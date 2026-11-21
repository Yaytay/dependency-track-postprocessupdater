package client

import (
	"context"
	"dependency-track-postprocessupdater/internal/config"
	"dependency-track-postprocessupdater/internal/model"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMatchingSettingsDoNotWrite(t *testing.T) {
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writes++
			w.WriteHeader(http.StatusOK)
			return
		}
		switch r.URL.Path {
		case "/api/v1/project/project":
			fmt.Fprint(w, `{"uuid":"project","description":"same","tags":[{"name":"Existing"}]}`)
		case "/api/v1/project/project/property":
			fmt.Fprint(w, `[{"groupName":"g","propertyName":"n","propertyValue":"v"}]`)
		case "/api/v1/acl/team/team":
			fmt.Fprint(w, `[{"uuid":"project"}]`)
		default:
			t.Errorf("unexpected request: %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	c := NewClient(server.URL, "key", time.Second, config.NewLogger("logfmt", "error", io.Discard))
	description := "same"
	err := c.ApplyPostProcessing(context.Background(), "project", []string{"existing"}, nil, &description, []model.Property{{GroupName: "g", PropertyName: "n", PropertyValue: "v"}}, []string{"team"})
	if err != nil || writes != 0 {
		t.Fatalf("error = %v, writes = %d; want no error and no writes", err, writes)
	}
}

func TestTeamLookupPaginates(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Query().Get("pageNumber") == "1" {
			fmt.Fprint(w, "[")
			for i := 0; i < 100; i++ {
				if i > 0 {
					fmt.Fprint(w, ",")
				}
				fmt.Fprint(w, `{"uuid":"other"}`)
			}
			fmt.Fprint(w, "]")
		} else {
			fmt.Fprint(w, `[{"uuid":"project"}]`)
		}
	}))
	defer server.Close()
	c := NewClient(server.URL, "key", time.Second, config.NewLogger("logfmt", "error", io.Discard))
	assigned, err := c.teamHasProject(context.Background(), "team", "project")
	if err != nil || !assigned || requests != 2 {
		t.Fatalf("assigned = %v, error = %v, requests = %d", assigned, err, requests)
	}
}
