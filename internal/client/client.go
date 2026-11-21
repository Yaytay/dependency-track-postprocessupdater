package client

import (
	"bytes"
	"context"
	"dependency-track-postprocessupdater/internal/config"
	"dependency-track-postprocessupdater/internal/model"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	logger     *config.Logger
}

func NewClient(baseURL, apiKey string, timeout time.Duration, logger *config.Logger) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		logger: logger,
	}
}

type Project struct {
	Authors                   []ProjectAuthor   `json:"authors,omitempty"`
	Name                      string            `json:"name"`
	Version                   string            `json:"version"`
	Classifier                string            `json:"classifier"`
	CollectionLogic           string            `json:"collectionLogic"`
	UUID                      string            `json:"uuid"`
	Properties                []ProjectProperty `json:"properties,omitempty"`
	Tags                      []ProjectTag      `json:"tags,omitempty"`
	LastBomImport             int64             `json:"lastBomImport"`
	LastBomImportFormat       string            `json:"lastBomImportFormat"`
	LastInheritedRiskScore    float64           `json:"lastInheritedRiskScore"`
	LastVulnerabilityAnalysis int64             `json:"lastVulnerabilityAnalysis"`
	Active                    bool              `json:"active"`
	IsLatest                  bool              `json:"isLatest"`
	Metrics                   ProjectMetrics    `json:"metrics"`
}

type ProjectAuthor struct {
	Name string `json:"name"`
}

type ProjectProperty struct {
	GroupName     string `json:"groupName"`
	PropertyName  string `json:"propertyName"`
	PropertyValue string `json:"propertyValue"`
	PropertyType  string `json:"propertyType"`
	Description   string `json:"description"`
}

type ProjectTag struct {
	Name string `json:"name"`
}

type TagRequest struct {
	Name string `json:"name"`
}

type PropertyRequest struct {
	GroupName     string `json:"groupName"`
	PropertyName  string `json:"propertyName"`
	PropertyValue string `json:"propertyValue"`
	PropertyType  string `json:"propertyType,omitempty"`
	Description   string `json:"description,omitempty"`
}

type ProjectMetrics struct {
	Critical                             int     `json:"critical"`
	High                                 int     `json:"high"`
	Medium                               int     `json:"medium"`
	Low                                  int     `json:"low"`
	Unassigned                           int     `json:"unassigned"`
	Vulnerabilities                      int     `json:"vulnerabilities"`
	VulnerableComponents                 int     `json:"vulnerableComponents"`
	Components                           int     `json:"components"`
	Suppressed                           int     `json:"suppressed"`
	FindingsTotal                        int     `json:"findingsTotal"`
	FindingsAudited                      int     `json:"findingsAudited"`
	FindingsUnaudited                    int     `json:"findingsUnaudited"`
	InheritedRiskScore                   float64 `json:"inheritedRiskScore"`
	PolicyViolationsFail                 int     `json:"policyViolationsFail"`
	PolicyViolationsWarn                 int     `json:"policyViolationsWarn"`
	PolicyViolationsInfo                 int     `json:"policyViolationsInfo"`
	PolicyViolationsTotal                int     `json:"policyViolationsTotal"`
	PolicyViolationsAudited              int     `json:"policyViolationsAudited"`
	PolicyViolationsUnaudited            int     `json:"policyViolationsUnaudited"`
	PolicyViolationsSecurityTotal        int     `json:"policyViolationsSecurityTotal"`
	PolicyViolationsSecurityAudited      int     `json:"policyViolationsSecurityAudited"`
	PolicyViolationsSecurityUnaudited    int     `json:"policyViolationsSecurityUnaudited"`
	PolicyViolationsLicenseTotal         int     `json:"policyViolationsLicenseTotal"`
	PolicyViolationsLicenseAudited       int     `json:"policyViolationsLicenseAudited"`
	PolicyViolationsLicenseUnaudited     int     `json:"policyViolationsLicenseUnaudited"`
	PolicyViolationsOperationalTotal     int     `json:"policyViolationsOperationalTotal"`
	PolicyViolationsOperationalAudited   int     `json:"policyViolationsOperationalAudited"`
	PolicyViolationsOperationalUnaudited int     `json:"policyViolationsOperationalUnaudited"`
	CollectionLogic                      string  `json:"collectionLogic"`
	CollectionLogicChanged               bool    `json:"collectionLogicChanged"`
	FirstOccurrence                      int64   `json:"firstOccurrence"`
	LastOccurrence                       int64   `json:"lastOccurrence"`
}

type VulnerabilityCounts struct {
	Critical   int
	High       int
	Medium     int
	Low        int
	Unassigned int
}

type ProjectSnapshot struct {
	Project Project
	Counts  VulnerabilityCounts
}

func (c *Client) ReadyProject(ctx context.Context, name, version string) (string, error) {
	u, err := url.Parse(c.baseURL + "/api/v1/project/lookup")
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("name", name)
	q.Set("version", version)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var project Project
	if err := json.NewDecoder(resp.Body).Decode(&project); err != nil {
		return "", err
	}
	if project.LastBomImport <= 0 {
		return "", nil
	}
	if strings.TrimSpace(project.UUID) == "" {
		return "", fmt.Errorf("project UUID missing from lookup response")
	}
	return project.UUID, nil
}

func (c *Client) FetchProjectSnapshots(ctx context.Context) ([]ProjectSnapshot, error) {
	projects, err := c.fetchProjects(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]ProjectSnapshot, 0, len(projects))
	for _, p := range projects {
		out = append(out, ProjectSnapshot{
			Project: p,
			Counts: VulnerabilityCounts{
				Critical:   p.Metrics.Critical,
				High:       p.Metrics.High,
				Medium:     p.Metrics.Medium,
				Low:        p.Metrics.Low,
				Unassigned: p.Metrics.Unassigned,
			},
		})
	}
	return out, nil
}

func (c *Client) fetchProjects(ctx context.Context) ([]Project, error) {
	const pageSize = 100

	projects := make([]Project, 0, pageSize)
	for pageNumber := 1; ; pageNumber++ {
		u, err := url.Parse(c.baseURL + "/api/v1/project")
		if err != nil {
			return nil, err
		}

		q := u.Query()
		q.Set("pageNumber", strconv.Itoa(pageNumber))
		q.Set("pageSize", strconv.Itoa(pageSize))
		u.RawQuery = q.Encode()

		c.logger.Debug("fetching projects page", "page_number", pageNumber, "page_size", pageSize)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-Api-Key", c.apiKey)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}

		var page []Project
		err = json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		projects = append(projects, page...)

		if len(page) < pageSize {
			break
		}
	}

	c.logger.Info("fetched all projects", "projects", len(projects))

	return projects, nil
}

func (c *Client) fetchProjectVulnerabilityCounts(ctx context.Context, projectUUID string) (VulnerabilityCounts, error) {
	u, err := url.Parse(c.baseURL + "/api/v1/finding/project/" + projectUUID)
	if err != nil {
		return VulnerabilityCounts{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return VulnerabilityCounts{}, err
	}
	req.Header.Set("X-Api-Key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return VulnerabilityCounts{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return VulnerabilityCounts{}, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var findings []struct {
		Vulnerability struct {
			Severity string `json:"severity"`
		} `json:"vulnerability"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&findings); err != nil {
		return VulnerabilityCounts{}, err
	}

	var counts VulnerabilityCounts
	for _, f := range findings {
		switch strings.ToLower(f.Vulnerability.Severity) {
		case "critical":
			counts.Critical++
		case "high":
			counts.High++
		case "medium":
			counts.Medium++
		case "low":
			counts.Low++
		default:
			counts.Unassigned++
		}
	}
	return counts, nil
}

func (c *Client) updateProjectMetadata(ctx context.Context, projectUUID string, tags []string, description *string) error {
	newTags := make([]ProjectTag, 0, len(tags))
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t != "" {
			newTags = append(newTags, ProjectTag{Name: t})
		}
	}
	if len(newTags) == 0 && description == nil {
		return nil
	}

	projectJSON, err := c.fetchProjectJSON(ctx, projectUUID)
	if err != nil {
		return err
	}

	updatedJSON := projectJSON
	if len(newTags) > 0 {
		updatedJSON, err = replaceProjectTags(projectJSON, newTags)
		if err != nil {
			return err
		}
	}
	if description != nil {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(updatedJSON, &fields); err != nil {
			return err
		}
		fields["description"], err = json.Marshal(*description)
		if err != nil {
			return err
		}
		updatedJSON, err = json.Marshal(fields)
		if err != nil {
			return err
		}
	}

	return c.updateProjectJSON(ctx, updatedJSON)
}

func (c *Client) fetchProjectJSON(ctx context.Context, projectUUID string) (json.RawMessage, error) {
	u, err := url.Parse(c.baseURL + "/api/v1/project/" + projectUUID)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return io.ReadAll(resp.Body)
}

func replaceProjectTags(projectJSON json.RawMessage, newTags []ProjectTag) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(projectJSON, &fields); err != nil {
		return nil, err
	}

	var existingTags []ProjectTag
	if rawTags, ok := fields["tags"]; ok && len(rawTags) > 0 && string(rawTags) != "null" {
		if err := json.Unmarshal(rawTags, &existingTags); err != nil {
			return nil, err
		}
	}

	mergedTags := mergeProjectTags(existingTags, newTags)

	tagBytes, err := json.Marshal(mergedTags)
	if err != nil {
		return nil, err
	}
	fields["tags"] = tagBytes

	return json.Marshal(fields)
}

func mergeProjectTags(existing, additions []ProjectTag) []ProjectTag {
	seen := make(map[string]struct{}, len(existing)+len(additions))
	out := make([]ProjectTag, 0, len(existing)+len(additions))

	addOne := func(tag ProjectTag) {
		name := strings.TrimSpace(tag.Name)
		if name == "" {
			return
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, ProjectTag{Name: name})
	}

	for _, tag := range existing {
		addOne(tag)
	}
	for _, tag := range additions {
		addOne(tag)
	}
	return out
}

func (c *Client) updateProjectJSON(ctx context.Context, projectJSON json.RawMessage) error {
	u, err := url.Parse(c.baseURL + "/api/v1/project")
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(projectJSON))
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

type bomResponse struct {
	Components []bomComponent `json:"components"`
}

type bomComponent struct {
	UUID            string             `json:"uuid"`
	Vulnerabilities []bomVulnerability `json:"vulnerabilities"`
}

type bomVulnerability struct {
	UUID string `json:"uuid"`
	ID   string `json:"id"`
}

type AnalysisRequest struct {
	Project       string                      `json:"project"`
	Component     string                      `json:"component"`
	Vulnerability string                      `json:"vulnerability"`
	State         model.AnalysisState         `json:"state"`
	Justification model.AnalysisJustification `json:"justification"`
	Response      model.AnalysisResponse      `json:"response"`
	Details       string                      `json:"details,omitempty"`
}

func (c *Client) ApplyPostProcessing(ctx context.Context, projectUUID string, tags []string, suppressions []model.Suppression, description *string, properties []model.Property, teams []string) error {
	if len(tags) > 0 || description != nil {
		if err := c.updateProjectMetadata(ctx, projectUUID, tags, description); err != nil {
			return err
		}
	}
	if len(properties) > 0 {
		if err := c.applyProperties(ctx, projectUUID, properties); err != nil {
			return err
		}
	}
	for _, team := range teams {
		team = strings.TrimSpace(team)
		if team == "" {
			return fmt.Errorf("team UUID must not be empty")
		}
		if _, err := c.requestJSON(ctx, http.MethodPut, "/api/v1/acl/mapping", map[string]string{"project": projectUUID, "team": team}, http.StatusCreated, http.StatusOK, http.StatusConflict); err != nil {
			return fmt.Errorf("assign team %s: %w", team, err)
		}
	}
	if len(suppressions) > 0 {
		if err := c.applySuppressionsAsAnalyses(ctx, projectUUID, suppressions); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) applyProperties(ctx context.Context, projectUUID string, properties []model.Property) error {
	path := "/api/v1/project/" + url.PathEscape(projectUUID) + "/property"
	body, err := c.requestJSON(ctx, http.MethodGet, path, nil, http.StatusOK)
	if err != nil {
		return err
	}
	var existing []model.Property
	if err := json.Unmarshal(body, &existing); err != nil {
		return err
	}
	keys := make(map[[2]string]bool, len(existing))
	for _, property := range existing {
		keys[[2]string{property.GroupName, property.PropertyName}] = true
	}
	for _, property := range properties {
		if strings.TrimSpace(property.GroupName) == "" || strings.TrimSpace(property.PropertyName) == "" {
			return fmt.Errorf("property groupName and propertyName are required")
		}
		key := [2]string{property.GroupName, property.PropertyName}
		method := http.MethodPut
		var payload any = property
		if keys[key] {
			method = http.MethodPost
			payload = struct {
				GroupName     string `json:"groupName"`
				PropertyName  string `json:"propertyName"`
				PropertyValue string `json:"propertyValue"`
			}{property.GroupName, property.PropertyName, property.PropertyValue}
		} else if property.PropertyType == "" {
			property.PropertyType = "STRING"
			payload = property
		}
		if _, err := c.requestJSON(ctx, method, path, payload, http.StatusOK, http.StatusCreated, http.StatusNoContent); err != nil {
			return fmt.Errorf("apply property %s/%s: %w", property.GroupName, property.PropertyName, err)
		}
		keys[key] = true
	}
	return nil
}

func (c *Client) requestJSON(ctx context.Context, method, path string, payload any, success ...int) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	for _, status := range success {
		if resp.StatusCode == status {
			return io.ReadAll(resp.Body)
		}
	}
	message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(message)))
}

func (c *Client) fetchProjectBomWithVulnerabilities(ctx context.Context, projectUUID string) (*bomResponse, error) {
	u, err := url.Parse(c.baseURL + "/api/v1/bom/cyclonedx/project/" + projectUUID)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("format", "json")
	q.Set("variant", "withVulnerabilities")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out bomResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) applySuppressionsAsAnalyses(ctx context.Context, projectUUID string, suppressions []model.Suppression) error {
	bom, err := c.fetchProjectBomWithVulnerabilities(ctx, projectUUID)
	if err != nil {
		return err
	}

	for _, suppression := range suppressions {
		vulnName := strings.TrimSpace(suppression.VulnerabilityName)
		if vulnName == "" {
			continue
		}

		state := suppression.State
		if strings.TrimSpace(string(state)) == "" {
			state = model.AnalysisStateNotSet
		}

		justification := suppression.Justification
		if strings.TrimSpace(string(justification)) == "" {
			justification = model.AnalysisJustificationNotSet
		}

		response := suppression.Response
		if strings.TrimSpace(string(response)) == "" {
			response = model.AnalysisResponseNotSet
		}

		for _, component := range bom.Components {
			for _, vuln := range component.Vulnerabilities {
				if strings.TrimSpace(vuln.ID) != vulnName {
					continue
				}

				logPayload := struct {
					Component     bomComponent      `json:"component"`
					Vulnerability bomVulnerability  `json:"vulnerability"`
					Suppression   model.Suppression `json:"suppression"`
				}{
					Component:     component,
					Vulnerability: vuln,
					Suppression:   suppression,
				}
				if b, err := json.Marshal(logPayload); err == nil {
					c.logger.Info("suppressing vulnerability", "details", string(b))
				} else {
					c.logger.Info("suppressing vulnerability", "component", component.UUID, "vulnerability", vuln.ID, "suppression", vulnName)
				}

				reqBody := AnalysisRequest{
					Project:       projectUUID,
					Component:     component.UUID,
					Vulnerability: vuln.UUID,
					State:         state,
					Justification: justification,
					Response:      response,
					Details:       suppression.Details,
				}

				if err := c.putAnalysis(ctx, reqBody); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (c *Client) putAnalysis(ctx context.Context, reqBody AnalysisRequest) error {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	u, err := url.Parse(c.baseURL + "/api/v1/analysis")
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}
