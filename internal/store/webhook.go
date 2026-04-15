package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"dependency-track-postprocessupdater/internal/config"
	"dependency-track-postprocessupdater/internal/model"
)

type PostProcessor interface {
	ApplyPostProcessing(ctx context.Context, projectUUID string, tags []string, suppressions []model.Suppression) error
}

type WebhookEvent struct {
	Notification struct {
		Level     string `json:"level"`
		Scope     string `json:"scope"`
		Group     string `json:"group"`
		Timestamp string `json:"timestamp"`
		Title     string `json:"title"`
		Content   string `json:"content"`
		Subject   struct {
			Project struct {
				UUID    string `json:"uuid"`
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"project"`
		} `json:"subject"`
	} `json:"notification"`
}

func HandleWebhook(ctx context.Context, logger *config.Logger, dtrack PostProcessor, store *FileStore, metrics *Store, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if logger.DebugEnabled() {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "unable to read body", http.StatusBadRequest)
			return
		}
		logger.Debug("received webhook", "method", r.Method, "url", r.URL, "body", string(body))
		r.Body = io.NopCloser(bytes.NewReader(body))
	} else {
		logger.Info("received webhook", "method", r.Method, "url", r.URL)
	}

	var evt WebhookEvent
	if err := json.NewDecoder(r.Body).Decode(&evt); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if evtJSON, err := json.Marshal(evt); err == nil {
		logger.Info("received webhook event", "event", string(evtJSON))
	} else {
		logger.Warn("received webhook event; failed to marshal for logging", "err", err)
	}

	projectUUID := strings.TrimSpace(evt.Notification.Subject.Project.UUID)
	name := strings.TrimSpace(evt.Notification.Subject.Project.Name)
	version := strings.TrimSpace(evt.Notification.Subject.Project.Version)

	if evt.Notification.Group != "BOM_PROCESSED" {
		logger.Info("webhook ignored; not BOM_PROCESSED", "name", name, "version", version, "project_uuid", projectUUID, "group", evt.Notification.Group)
		return
	}

	if projectUUID == "" {
		http.Error(w, "project uuid missing", http.StatusBadRequest)
		return
	}
	if name == "" || version == "" {
		http.Error(w, "project name/version missing", http.StatusBadRequest)
		return
	}

	reg, err := store.Get(name, version)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Info("webhook ignored; no registration", "name", name, "version", version, "project_uuid", projectUUID)
			w.WriteHeader(http.StatusOK)
			return
		}
		logger.Error("registration lookup failed", "name", name, "version", version, "err", err)
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}

	if err := dtrack.ApplyPostProcessing(ctx, projectUUID, reg.Tags, reg.Suppressions); err != nil {
		logger.Error("post-processing failed", "project_uuid", projectUUID, "name", name, "version", version, "err", err)
		http.Error(w, fmt.Sprintf("processing failed: %v", err), http.StatusInternalServerError)
		return
	}

	if err := store.UpdateLastNotifiedAt(name, version, time.Now().UTC()); err != nil {
		logger.Warn("failed to update lastNotifiedAt", "name", name, "version", version, "err", err)
	}

	metrics.IncrementProcessed()
	logger.Info("registration processed", "name", name, "version", version, "project_uuid", projectUUID)
	w.WriteHeader(http.StatusOK)
}
