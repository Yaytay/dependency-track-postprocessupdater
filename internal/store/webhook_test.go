package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dependency-track-postprocessupdater/internal/config"
	"dependency-track-postprocessupdater/internal/model"
)

type fakePostProcessor struct {
	calls int
	want  struct {
		projectUUID  string
		tags         []string
		suppressions []model.Suppression
	}
	err error
}

func (f *fakePostProcessor) ApplyPostProcessing(ctx context.Context, projectUUID string, tags []string, suppressions []model.Suppression) error {
	f.calls++
	f.want.projectUUID = projectUUID
	f.want.tags = append([]string(nil), tags...)
	f.want.suppressions = append([]model.Suppression(nil), suppressions...)
	return f.err
}

func newWebhookTestStore(t *testing.T) *FileStore {
	t.Helper()

	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore() error = %v", err)
	}
	return store
}

func writeRegistration(t *testing.T, store *FileStore, name, version string) Registration {
	t.Helper()

	reg := Registration{
		Name:    name,
		Version: version,
		Tags:    []string{"tag-a", "tag-b"},
		Suppressions: []model.Suppression{
			{VulnerabilityName: "CVE-1234-5678"},
		},
	}
	store.clock = func() time.Time { return time.Date(2026, time.April, 14, 16, 10, 19, 0, time.UTC) }

	if err := store.Put(reg); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	return reg
}

func webhookPayload(t *testing.T, uuid, name, version string) []byte {
	t.Helper()

	payload := map[string]any{
		"notification": map[string]any{
			"level":     "INFORMATIONAL",
			"scope":     "PORTFOLIO",
			"group":     "BOM_PROCESSED",
			"timestamp": "2026-04-14T16:10:19.164035639",
			"title":     "Bill of Materials Processed",
			"content":   "A CycloneDX BOM was processed",
			"subject": map[string]any{
				"project": map[string]any{
					"uuid":    uuid,
					"name":    name,
					"version": version,
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return body
}

func TestHandleWebhookProcessesMatchingRegistration(t *testing.T) {
	store := newWebhookTestStore(t)
	writeRegistration(t, store, "artefact-a", "1.2.3")

	fake := &fakePostProcessor{}
	metrics := NewStore()

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(webhookPayload(t, "uuid-123", "artefact-a", "1.2.3")))
	rr := httptest.NewRecorder()

	logger := config.NewLogger("logfmt", "error", io.Discard)
	HandleWebhook(context.Background(), logger, fake, store, metrics, rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if fake.calls != 1 {
		t.Fatalf("ApplyPostProcessing calls = %d, want 1", fake.calls)
	}
	if fake.want.projectUUID != "uuid-123" {
		t.Fatalf("projectUUID = %q, want %q", fake.want.projectUUID, "uuid-123")
	}
	if got := metrics.Snapshot().Processed; got != 1 {
		t.Fatalf("metrics.Processed = %d, want 1", got)
	}

	if _, err := store.Get("artefact-a", "1.2.3"); err != nil {
		t.Fatalf("registration unexpectedly missing after webhook: %v", err)
	}
	if _, err := store.GetState("artefact-a", "1.2.3"); err != nil {
		t.Fatalf("state missing after webhook: %v", err)
	}
}

func TestHandleWebhookIgnoresMissingRegistration(t *testing.T) {
	store := newWebhookTestStore(t)
	fake := &fakePostProcessor{}
	metrics := NewStore()

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(webhookPayload(t, "uuid-123", "missing", "1.0.0")))
	rr := httptest.NewRecorder()

	logger := config.NewLogger("logfmt", "error", io.Discard)
	HandleWebhook(context.Background(), logger, fake, store, metrics, rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if fake.calls != 0 {
		t.Fatalf("ApplyPostProcessing calls = %d, want 0", fake.calls)
	}
	if got := metrics.Snapshot().Processed; got != 0 {
		t.Fatalf("metrics.Processed = %d, want 0", got)
	}
}

func TestHandleWebhookUpdatesLastNotifiedAt(t *testing.T) {
	store := newWebhookTestStore(t)
	writeRegistration(t, store, "artefact-a", "1.2.3")

	fake := &fakePostProcessor{}
	metrics := NewStore()

	wantNow := time.Date(2026, time.April, 15, 9, 30, 0, 0, time.UTC)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(webhookPayload(t, "uuid-123", "artefact-a", "1.2.3")))
	rr := httptest.NewRecorder()

	logger := config.NewLogger("logfmt", "error", io.Discard)
	HandleWebhook(context.Background(), logger, fake, store, metrics, rr, req)

	state, err := store.GetState("artefact-a", "1.2.3")
	if err != nil {
		t.Fatalf("GetState() error = %v", err)
	}
	if state.LastNotifiedAt.IsZero() {
		t.Fatal("LastNotifiedAt is zero, want set")
	}
	if state.LastNotifiedAt.Before(wantNow.Add(-24 * time.Hour)) {
		t.Fatalf("LastNotifiedAt = %v, want recent value", state.LastNotifiedAt)
	}
}

func TestHandleWebhookRejectsInvalidJSON(t *testing.T) {
	store := newWebhookTestStore(t)
	fake := &fakePostProcessor{}
	metrics := NewStore()

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader([]byte("{not-json")))
	rr := httptest.NewRecorder()

	logger := config.NewLogger("logfmt", "error", io.Discard)
	HandleWebhook(context.Background(), logger, fake, store, metrics, rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if fake.calls != 0 {
		t.Fatalf("ApplyPostProcessing calls = %d, want 0", fake.calls)
	}
}

func TestHandleWebhookPropagatesProcessingError(t *testing.T) {
	store := newWebhookTestStore(t)
	writeRegistration(t, store, "artefact-a", "1.2.3")

	fake := &fakePostProcessor{err: errors.New("boom")}
	metrics := NewStore()

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(webhookPayload(t, "uuid-123", "artefact-a", "1.2.3")))
	rr := httptest.NewRecorder()

	logger := config.NewLogger("logfmt", "error", io.Discard)
	HandleWebhook(context.Background(), logger, fake, store, metrics, rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
	if got := metrics.Snapshot().Processed; got != 0 {
		t.Fatalf("metrics.Processed = %d, want 0", got)
	}
}
