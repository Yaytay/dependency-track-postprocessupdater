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
	if len(calls) != 6 {
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
