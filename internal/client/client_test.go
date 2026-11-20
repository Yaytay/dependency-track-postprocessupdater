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
