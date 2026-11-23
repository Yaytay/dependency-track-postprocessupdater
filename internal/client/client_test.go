package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dependency-track-postprocessupdater/internal/config"
	"dependency-track-postprocessupdater/internal/model"
)

func TestApplyPostProcessingMetadata(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Header.Get("X-Api-Key") != "key" {
			t.Error("missing API key")
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/project/project-id":
			io.WriteString(w, `{"uuid":"project-id","description":"old","tags":[{"name":"existing"}],"other":"preserved"}`)
		case "POST /api/v1/project":
			var project map[string]any
			if err := json.NewDecoder(r.Body).Decode(&project); err != nil {
				t.Error(err)
			}
			if project["description"] != "" || project["other"] != "preserved" || len(project["tags"].([]any)) != 2 {
				t.Errorf("unexpected project: %v", project)
			}
		case "GET /api/v1/project/project-id/property":
			io.WriteString(w, `[{"groupName":"g","propertyName":"existing"}]`)
		case "GET /api/v1/acl/team/team-id":
			io.WriteString(w, `[]`)
		case "POST /api/v1/project/project-id/property", "PUT /api/v1/project/project-id/property":
			var property model.Property
			if err := json.NewDecoder(r.Body).Decode(&property); err != nil {
				t.Error(err)
			}
			if r.Method == http.MethodPost && (property.PropertyName != "existing" || property.PropertyValue != "new") {
				t.Errorf("unexpected update: %+v", property)
			}
			if r.Method == http.MethodPut && (property.PropertyName != "added" || property.PropertyType != "STRING") {
				t.Errorf("unexpected creation: %+v", property)
			}
		case "PUT /api/v1/acl/mapping":
			var mapping map[string]string
			if err := json.NewDecoder(r.Body).Decode(&mapping); err != nil {
				t.Error(err)
			}
			if mapping["project"] != "project-id" || mapping["team"] != "team-id" {
				t.Errorf("unexpected mapping: %v", mapping)
			}
			w.WriteHeader(http.StatusConflict)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	c := NewClient(server.URL, "key", time.Second, config.NewLogger("logfmt", "error", io.Discard))
	description := ""
	err := c.ApplyPostProcessing(context.Background(), "project-id", []string{"new"}, nil, &description, []model.Property{
		{GroupName: "g", PropertyName: "existing", PropertyValue: "new"},
		{GroupName: "g", PropertyName: "added", PropertyValue: "value"},
	}, []string{"team-id"})
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 7 {
		t.Fatalf("unexpected calls: %v", calls)
	}
}

func TestApplyPostProcessingFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer server.Close()
	c := NewClient(server.URL, "key", time.Second, config.NewLogger("logfmt", "error", io.Discard))
	err := c.ApplyPostProcessing(context.Background(), "project-id", nil, nil, nil, nil, []string{"team-id"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected API error, got %v", err)
	}
	if err := c.ApplyPostProcessing(context.Background(), "project-id", nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("empty registration: %v", err)
	}
}

func TestHTTPStatusErrorsIncludeMethodAndPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer server.Close()
	c := NewClient(server.URL, "key", time.Second, config.NewLogger("logfmt", "error", io.Discard))
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		want string
		call func() error
	}{
		{"lookup", "GET /api/v1/project/lookup", func() error { _, err := c.ReadyProject(ctx, "name", "version"); return err }},
		{"projects", "GET /api/v1/project", func() error { _, err := c.fetchProjects(ctx); return err }},
		{"findings", "GET /api/v1/finding/project/id", func() error { _, err := c.fetchProjectVulnerabilityCounts(ctx, "id"); return err }},
		{"project", "GET /api/v1/project/id", func() error { _, err := c.fetchProjectJSON(ctx, "id"); return err }},
		{"update project", "POST /api/v1/project", func() error { return c.updateProjectJSON(ctx, json.RawMessage(`{}`)) }},
		{"request JSON", "PUT /api/v1/acl/mapping", func() error { _, err := c.requestJSON(ctx, http.MethodPut, "/api/v1/acl/mapping?secret=value", nil, http.StatusOK); return err }},
		{"bom", "GET /api/v1/bom/cyclonedx/project/id", func() error { _, err := c.fetchProjectBomWithVulnerabilities(ctx, "id"); return err }},
		{"analysis lookup", "GET /api/v1/analysis", func() error { _, err := c.analysisMatches(ctx, AnalysisRequest{}); return err }},
		{"analysis update", "PUT /api/v1/analysis", func() error { return c.putAnalysis(ctx, AnalysisRequest{}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "unexpected status 403: denied") || strings.Contains(err.Error(), "?secret=") {
				t.Fatalf("expected method, path and status without query, got %v", err)
			}
		})
	}
}

func TestReadyProject(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		want    string
		wantErr bool
	}{
		{"ready", 200, `{"uuid":"project-id","lastBomImport":123}`, "project-id", false},
		{"no import", 200, `{"uuid":"project-id"}`, "", false},
		{"not found", 404, ``, "", false},
		{"forbidden", 403, `denied`, "", true},
		{"missing uuid", 200, `{"lastBomImport":123}`, "", true},
		{"invalid response", 200, `{`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/project/lookup" || r.URL.Query().Get("name") != "a & b" || r.URL.Query().Get("version") != "1+2" || r.Header.Get("X-Api-Key") != "key" {
					t.Errorf("unexpected request: %s", r.URL.String())
				}
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer server.Close()
			c := NewClient(server.URL, "key", time.Second, config.NewLogger("logfmt", "error", io.Discard))
			got, err := c.ReadyProject(context.Background(), "a & b", "1+2")
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}

func TestSuppressionsSkipMatchingAnalysis(t *testing.T) {
	for _, tc := range []struct {
		name     string
		analysis string
		status   int
		wantPut  bool
		wantErr  bool
	}{
		{"matching", `{"analysisState":"FALSE_POSITIVE","analysisJustification":"CODE_NOT_PRESENT","analysisResponse":"UPDATE","analysisDetails":"reason"}`, 200, false, false},
		{"state differs", `{"analysisState":"IN_TRIAGE","analysisJustification":"CODE_NOT_PRESENT","analysisResponse":"UPDATE","analysisDetails":"reason"}`, 200, true, false},
		{"justification differs", `{"analysisState":"FALSE_POSITIVE","analysisJustification":"NOT_SET","analysisResponse":"UPDATE","analysisDetails":"reason"}`, 200, true, false},
		{"response differs", `{"analysisState":"FALSE_POSITIVE","analysisJustification":"CODE_NOT_PRESENT","analysisResponse":"NOT_SET","analysisDetails":"reason"}`, 200, true, false},
		{"details differ", `{"analysisState":"FALSE_POSITIVE","analysisJustification":"CODE_NOT_PRESENT","analysisResponse":"UPDATE","analysisDetails":"other"}`, 200, true, false},
		{"lookup error", `denied`, 403, false, true},
		{"invalid response", `{`, 200, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gets, puts := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method + " " + r.URL.Path {
				case "GET /api/v1/bom/cyclonedx/project/project-id":
					io.WriteString(w, `{"components":[{"uuid":"component-id","vulnerabilities":[{"uuid":"vuln-id","id":"CVE-1"}]}]}`)
				case "GET /api/v1/analysis":
					gets++
					if r.URL.Query().Get("project") != "project-id" || r.URL.Query().Get("component") != "component-id" || r.URL.Query().Get("vulnerability") != "vuln-id" || r.Header.Get("X-Api-Key") != "key" {
						t.Errorf("unexpected lookup: %s", r.URL.String())
					}
					w.WriteHeader(tc.status)
					io.WriteString(w, tc.analysis)
				case "PUT /api/v1/analysis":
					puts++
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			c := NewClient(server.URL, "key", time.Second, config.NewLogger("logfmt", "error", io.Discard))
			err := c.applySuppressionsAsAnalyses(context.Background(), "project-id", []model.Suppression{{VulnerabilityName: "CVE-1", State: model.AnalysisStateFalsePositive, Justification: model.AnalysisJustificationCodeNotPresent, Response: model.AnalysisResponseUpdate, Details: "reason"}})
			if (err != nil) != tc.wantErr || gets != 1 || (puts == 1) != tc.wantPut {
				t.Fatalf("got error %v, %d lookups, %d updates", err, gets, puts)
			}
		})
	}
}
