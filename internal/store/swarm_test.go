package store

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"dependency-track-postprocessupdater/internal/config"
	"dependency-track-postprocessupdater/internal/model"
)

func TestSwarmValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{"alpha", true}, {"A-1.example", true}, {strings.Repeat("a", 63), true},
		{"", false}, {"..", false}, {"a/b", false}, {"-a", false}, {"a-", false},
		{"a..b", false}, {"é", false}, {"a_b", false}, {strings.Repeat("a", 64), false},
	} {
		if got := validSwarm(tc.name); got != tc.valid {
			t.Errorf("validSwarm(%q) = %v", tc.name, got)
		}
	}
}

func TestSwarmMergeAndDelete(t *testing.T) {
	s := newTestFileStore(t)
	baseDescription, firstDescription, secondDescription := "", "first", "second"
	base := Registration{Name: "app", Version: "1", Description: &baseDescription, Tags: []string{"base"}, Teams: []string{"base"}, Properties: []model.Property{{PropertyName: "base"}}, Suppressions: []model.Suppression{{VulnerabilityName: "base"}}}
	a := Registration{Name: "app", Version: "1", Description: &firstDescription, Tags: []string{"a"}, Teams: []string{"a"}, Properties: []model.Property{{PropertyName: "a"}}, Suppressions: []model.Suppression{{VulnerabilityName: "a"}}}
	b := Registration{Name: "app", Version: "1", Description: &secondDescription, Tags: []string{"b"}}
	if err := s.Put(base); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSwarm("b", b); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSwarm("a", a); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.dir, "a", registrationKey("app", "1"), "registration.json")); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetMerged("app", "1")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Tags, []string{"base", "a", "b"}) || len(got.Teams) != 2 || len(got.Properties) != 2 || len(got.Suppressions) != 2 || got.Description == nil || *got.Description != "" {
		t.Fatalf("unexpected merge: %+v", got)
	}
	if err := s.Delete("app", "1"); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetMerged("app", "1")
	if err != nil || got.Description == nil || *got.Description != "first" {
		t.Fatalf("swarm description: %+v %v", got, err)
	}
	if err := s.DeleteSwarm("a"); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetMerged("app", "1")
	if err != nil || !reflect.DeepEqual(got.Tags, []string{"b"}) {
		t.Fatalf("after delete: %+v %v", got, err)
	}
	if err := s.DeleteSwarm("b"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMerged("app", "1"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing registration: %v", err)
	}
}

func TestSwarmEndpointsAndProcessing(t *testing.T) {
	s := newTestFileStore(t)
	logger := config.NewLogger("logfmt", "error", io.Discard)
	p := &fakePostProcessor{readyUUID: "id"}
	request := func(method, path, body string) int {
		rr := httptest.NewRecorder()
		HandleRegister(logger, s, p, rr, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rr.Code
	}
	if code := request("POST", "/register", `{"name":"app","version":"1","tags":["base"]}`); code != 202 {
		t.Fatal(code)
	}
	if code := request("POST", "/register/swarm", `{"name":"app","version":"1","tags":["swarm"]}`); code != 202 {
		t.Fatal(code)
	}
	if !reflect.DeepEqual(p.want.tags, []string{"base", "swarm"}) {
		t.Fatal(p.want.tags)
	}
	rr := httptest.NewRecorder()
	HandleWebhook(context.Background(), logger, p, s, NewStore(), rr, httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(webhookPayload(t, "id", "app", "1"))))
	if rr.Code != 200 || !reflect.DeepEqual(p.want.tags, []string{"base", "swarm"}) {
		t.Fatalf("webhook: %d %v", rr.Code, p.want.tags)
	}
	if code := request("DELETE", "/register/swarm", ""); code != 204 {
		t.Fatal(code)
	}
	if code := request("POST", "/register/bad_name", `{}`); code != 400 {
		t.Fatal(code)
	}
	if code := request("DELETE", "/register", ""); code != 405 {
		t.Fatal(code)
	}
	if code := request("GET", "/register/swarm", ""); code != 405 {
		t.Fatal(code)
	}
}
