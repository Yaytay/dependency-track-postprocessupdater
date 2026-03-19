package store

import (
	"dependency-track-postprocessupdater/internal/model"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"dependency-track-postprocessupdater/internal/config"
)

type Registration struct {
	ProjectUUID  string              `json:"projectUuid"`
	Tags         []string            `json:"tags,omitempty"`
	Suppressions []model.Suppression `json:"suppressions,omitempty"`
	UpdatedAt    time.Time           `json:"updatedAt"`
}

type FileStore struct {
	dir string
	mu  sync.Mutex
}

func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &FileStore{dir: dir}, nil
}

func (s *FileStore) path(projectUUID string) string {
	return filepath.Join(s.dir, projectUUID+".json")
}

func (s *FileStore) Put(reg Registration) error {
	if strings.TrimSpace(reg.ProjectUUID) == "" {
		return errors.New("projectUUID is required")
	}
	reg.UpdatedAt = time.Now().UTC()

	body, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	tmp := s.path(reg.ProjectUUID) + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path(reg.ProjectUUID))
}

func (s *FileStore) Get(projectUUID string) (Registration, error) {
	var reg Registration
	body, err := os.ReadFile(s.path(projectUUID))
	if err != nil {
		return reg, err
	}
	if err := json.Unmarshal(body, &reg); err != nil {
		return reg, err
	}
	return reg, nil
}

func (s *FileStore) Delete(projectUUID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.path(projectUUID))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func HandleRegister(logger *config.Logger, store *FileStore, _ *Store, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logger.Debug("received registration", "method", r.Method, "url", r.URL, "body", r.Body)

	var reg Registration
	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(reg.ProjectUUID) == "" {
		http.Error(w, "projectUuid is required", http.StatusBadRequest)
		return
	}

	if err := store.Put(reg); err != nil {
		logger.Error("registration failed", "project_uuid", reg.ProjectUUID, "err", err)
		http.Error(w, fmt.Sprintf("store failed: %v", err), http.StatusInternalServerError)
		return
	}

	logger.Info("registration stored", "project_uuid", reg.ProjectUUID, "tags", len(reg.Tags), "suppressions", len(reg.Suppressions))
	w.WriteHeader(http.StatusAccepted)
}
