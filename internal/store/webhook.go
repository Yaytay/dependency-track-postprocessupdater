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

	"dependency-track-postprocessupdater/internal/client"
	"dependency-track-postprocessupdater/internal/config"
)

type WebhookEvent struct {
	Project struct {
		UUID    string `json:"uuid"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"project"`
	ProjectUUID string `json:"projectUuid"`
}

func HandleWebhook(ctx context.Context, logger *config.Logger, dtrack *client.Client, store *FileStore, metrics *Store, w http.ResponseWriter, r *http.Request) {
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
		logger.Debug("received webhook", "method", r.Method, "url", r.URL)
	}

	var evt WebhookEvent
	if err := json.NewDecoder(r.Body).Decode(&evt); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	projectUUID := strings.TrimSpace(evt.ProjectUUID)
	if projectUUID == "" {
		projectUUID = strings.TrimSpace(evt.Project.UUID)
	}
	name := strings.TrimSpace(evt.Project.Name)
	version := strings.TrimSpace(evt.Project.Version)

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
