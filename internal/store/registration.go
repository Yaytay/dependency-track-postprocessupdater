package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"dependency-track-postprocessupdater/internal/model"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"dependency-track-postprocessupdater/internal/config"
)

type Registration struct {
	Name         string              `json:"name"`
	Version      string              `json:"version"`
	Description  *string             `json:"description,omitempty"`
	Properties   []model.Property    `json:"properties,omitempty"`
	Teams        []string            `json:"teams,omitempty"`
	Tags         []string            `json:"tags,omitempty"`
	Suppressions []model.Suppression `json:"suppressions,omitempty"`
	UpdatedAt    time.Time           `json:"updatedAt"`
}

type RegistrationState struct {
	LastNotifiedAt time.Time `json:"lastNotifiedAt,omitempty"`
}

type FileStore struct {
	dir   string
	mu    sync.Mutex
	clock func() time.Time
}

func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &FileStore{
		dir: dir,
		clock: func() time.Time {
			return time.Now().UTC()
		},
	}, nil
}

func registrationKey(name, version string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(name) + "\n" + strings.TrimSpace(version)))
	return hex.EncodeToString(sum[:])
}

func (s *FileStore) now() time.Time {
	if s != nil && s.clock != nil {
		return s.clock().UTC()
	}
	return time.Now().UTC()
}

func (s *FileStore) registrationDir(name, version string) string {
	return filepath.Join(s.dir, registrationKey(name, version))
}

func (s *FileStore) registrationPath(name, version string) string {
	return filepath.Join(s.registrationDir(name, version), "registration.json")
}

func (s *FileStore) statePath(name, version string) string {
	return filepath.Join(s.registrationDir(name, version), "state.json")
}

func (s *FileStore) Put(reg Registration) error {
	return s.put("", reg)
}

func validSwarm(swarm string) bool {
	if len(swarm) == 0 || len(swarm) > 253 {
		return false
	}
	for _, label := range strings.Split(swarm, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func (s *FileStore) PutSwarm(swarm string, reg Registration) error {
	if !validSwarm(swarm) {
		return errors.New("invalid swarm name")
	}
	return s.put(swarm, reg)
}

func (s *FileStore) put(swarm string, reg Registration) error {
	if strings.TrimSpace(reg.Name) == "" {
		return errors.New("name is required")
	}
	if strings.TrimSpace(reg.Version) == "" {
		return errors.New("version is required")
	}
	reg.UpdatedAt = s.now()

	dir := s.registrationDir(reg.Name, reg.Version)
	regPath := s.registrationPath(reg.Name, reg.Version)
	if swarm != "" {
		dir = filepath.Join(s.dir, swarm, registrationKey(reg.Name, reg.Version))
		regPath = filepath.Join(dir, "registration.json")
	}

	body, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp := regPath + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, regPath)
}

func (s *FileStore) Get(name, version string) (Registration, error) {
	var reg Registration
	body, err := os.ReadFile(s.registrationPath(name, version))
	if err != nil {
		return reg, err
	}
	if err := json.Unmarshal(body, &reg); err != nil {
		return reg, err
	}
	return reg, nil
}

func (s *FileStore) GetMerged(name, version string) (Registration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	merged, err := s.Get(name, version)
	found := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Registration{}, err
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return Registration{}, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !validSwarm(entry.Name()) {
			continue
		}
		path := filepath.Join(s.dir, entry.Name(), registrationKey(name, version), "registration.json")
		body, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return Registration{}, err
		}
		var reg Registration
		if err := json.Unmarshal(body, &reg); err != nil {
			return Registration{}, err
		}
		if !found {
			merged = reg
			found = true
			continue
		}
		if merged.Description == nil {
			merged.Description = reg.Description
		}
		merged.Properties = append(merged.Properties, reg.Properties...)
		merged.Teams = append(merged.Teams, reg.Teams...)
		merged.Tags = append(merged.Tags, reg.Tags...)
		merged.Suppressions = append(merged.Suppressions, reg.Suppressions...)
	}
	if !found {
		return Registration{}, os.ErrNotExist
	}
	return merged, nil
}

func (s *FileStore) DeleteSwarm(swarm string) error {
	if !validSwarm(swarm) {
		return errors.New("invalid swarm name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.RemoveAll(filepath.Join(s.dir, swarm))
}

func (s *FileStore) UpdateLastNotifiedAt(name, version string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.registrationDir(name, version), 0o755); err != nil {
		return err
	}

	state := RegistrationState{LastNotifiedAt: at.UTC()}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')

	tmp := s.statePath(name, version) + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.statePath(name, version))
}

func (s *FileStore) GetState(name, version string) (RegistrationState, error) {
	var state RegistrationState
	body, err := os.ReadFile(s.statePath(name, version))
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(body, &state); err != nil {
		return state, err
	}
	return state, nil
}

func (s *FileStore) Delete(name, version string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := os.RemoveAll(s.registrationDir(name, version))
	if err != nil {
		return err
	}
	return nil
}

func (s *FileStore) LastContact(name, version string) (time.Time, error) {
	reg, err := s.Get(name, version)
	if err != nil {
		return time.Time{}, err
	}

	lastContact := reg.UpdatedAt
	state, err := s.GetState(name, version)
	if err == nil && state.LastNotifiedAt.After(lastContact) {
		lastContact = state.LastNotifiedAt
	}
	return lastContact, nil
}

func (s *FileStore) PurgeOlderThan(cutoff time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		dir := filepath.Join(s.dir, entry.Name())
		regPath := filepath.Join(dir, "registration.json")

		body, err := os.ReadFile(regPath)
		if err != nil {
			continue
		}

		var reg Registration
		if err := json.Unmarshal(body, &reg); err != nil {
			continue
		}

		lastContact := reg.UpdatedAt
		statePath := filepath.Join(dir, "state.json")
		if stateBody, err := os.ReadFile(statePath); err == nil {
			var state RegistrationState
			if json.Unmarshal(stateBody, &state) == nil && state.LastNotifiedAt.After(lastContact) {
				lastContact = state.LastNotifiedAt
			}
		}

		if lastContact.Before(cutoff) {
			_ = os.RemoveAll(dir)
		}
	}

	return nil
}

type RegistrationProcessor interface {
	PostProcessor
	ReadyProject(ctx context.Context, name, version string) (string, error)
}

func HandleRegister(logger *config.Logger, store *FileStore, dtrack RegistrationProcessor, w http.ResponseWriter, r *http.Request) {
	logger.Info("received registration", "method", r.Method, "url", r.URL)
	swarm := ""
	if r.URL.Path != "/register" {
		swarm = strings.TrimPrefix(r.URL.Path, "/register/")
		if !validSwarm(swarm) {
			http.Error(w, "invalid swarm name", http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodDelete {
			if err := store.DeleteSwarm(swarm); err != nil {
				http.Error(w, "delete failed", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

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
		logger.Debug("received registration", "method", r.Method, "url", r.URL, "body", string(body))
		r.Body = io.NopCloser(bytes.NewReader(body))
	} else {
		logger.Info("received registration", "method", r.Method, "url", r.URL)
	}

	var reg Registration
	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(reg.Name) == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(reg.Version) == "" {
		http.Error(w, "version is required", http.StatusBadRequest)
		return
	}

	var err error
	if swarm == "" {
		err = store.Put(reg)
	} else {
		err = store.PutSwarm(swarm, reg)
	}
	if err != nil {
		logger.Error("registration failed", "name", reg.Name, "version", reg.Version, "err", err)
		http.Error(w, fmt.Sprintf("store failed: %v", err), http.StatusInternalServerError)
		return
	}

	logger.Info("registration stored", "name", reg.Name, "version", reg.Version, "tags", len(reg.Tags), "suppressions", len(reg.Suppressions))
	projectUUID, err := dtrack.ReadyProject(r.Context(), strings.TrimSpace(reg.Name), strings.TrimSpace(reg.Version))
	if err != nil {
		logger.Error("project lookup failed", "name", reg.Name, "version", reg.Version, "err", err)
		http.Error(w, fmt.Sprintf("registration stored; project lookup failed: %v", err), http.StatusInternalServerError)
		return
	}
	if projectUUID != "" {
		reg, err = store.GetMerged(reg.Name, reg.Version)
		if err != nil {
			logger.Error("registration lookup failed", "err", err)
			http.Error(w, "registration stored; lookup failed", http.StatusInternalServerError)
			return
		}
		if err := dtrack.ApplyPostProcessing(r.Context(), projectUUID, reg.Tags, reg.Suppressions, reg.Description, reg.Properties, reg.Teams); err != nil {
			logger.Error("post-processing failed", "project_uuid", projectUUID, "err", err)
			http.Error(w, fmt.Sprintf("registration stored; processing failed: %v", err), http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusAccepted)
}
