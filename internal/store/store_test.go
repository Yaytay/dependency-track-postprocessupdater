package store

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dependency-track-postprocessupdater/internal/config"
)

func TestHandleRegisterThenWebhookProcessesBOMProcessedNotification(t *testing.T) {
	store := newTestFileStore(t)
	metrics := NewStore()
	fake := &fakePostProcessor{}

	logger := config.NewLogger("logfmt", "error", io.Discard)

	store.clock = func() time.Time {
		return fixedTime(2026, time.April, 20, 13, 23, 42)
	}

	registerPayload := []byte(`{
  "name": "fileconverter",
  "version": "1.3.27-7-main",
  "updatedAt": "2026-04-20T13:23:42.999662+00:00",
  "suppressions": [{
      "notes": "CVE relates to pki-core, it's just picking up zipkin as a false positive.",
      "packageUrlRegex": "^pkg:maven/io.zipkin..*/.*$",
      "vulnerabilityName": "CVE-2022-2393"
    }, {
      "notes": "The CVE relates to SnakeYamls construction of Java objects, our use of Snakeyaml is always through Jackson, which only uses it for parsing the yaml.",
      "packageUrlRegex": "^pkg:maven/org.yaml/snakeyaml.*$",
      "vulnerabilityName": "CVE-2022-1471"
    }
  ]
}`)

	regReq := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(registerPayload))
	regRR := httptest.NewRecorder()

	HandleRegister(logger, store, nil, regRR, regReq)

	if regRR.Code != http.StatusAccepted {
		t.Fatalf("register status = %d, want %d", regRR.Code, http.StatusAccepted)
	}

	gotReg, err := store.Get("fileconverter", "1.3.27-7-main")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if gotReg.Name != "fileconverter" {
		t.Fatalf("stored name = %q, want %q", gotReg.Name, "fileconverter")
	}
	if gotReg.Version != "1.3.27-7-main" {
		t.Fatalf("stored version = %q, want %q", gotReg.Version, "1.3.27-7-main")
	}
	if len(gotReg.Suppressions) != 2 {
		t.Fatalf("stored suppressions = %d, want 2", len(gotReg.Suppressions))
	}

	evt := WebhookEvent{}
	evt.Notification.Level = "INFORMATIONAL"
	evt.Notification.Scope = "PORTFOLIO"
	evt.Notification.Group = "BOM_PROCESSED"
	evt.Notification.Timestamp = "2026-04-20T13:23:43.000000000"
	evt.Notification.Title = "Bill of Materials Processed"
	evt.Notification.Content = "A CycloneDX BOM was processed"
	evt.Notification.Subject.Project.UUID = "uuid-123"
	evt.Notification.Subject.Project.Name = "fileconverter"
	evt.Notification.Subject.Project.Version = "1.3.27-7-main"

	webhookBody, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	webhookReq := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(webhookBody))
	webhookRR := httptest.NewRecorder()
	HandleWebhook(context.Background(), logger, fake, store, metrics, webhookRR, webhookReq)

	if webhookRR.Code != http.StatusOK {
		t.Fatalf("webhook status = %d, want %d", webhookRR.Code, http.StatusOK)
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
	if len(fake.want.suppressions) != 2 {
		t.Fatalf("suppressions length = %d, want 2", len(fake.want.suppressions))
	}
}
