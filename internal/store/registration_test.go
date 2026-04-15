package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"dependency-track-postprocessupdater/internal/model"
)

func newTestFileStore(t *testing.T) *FileStore {
	t.Helper()

	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore() error = %v", err)
	}
	return store
}

func fixedTime(y int, m time.Month, d, hh, mm, ss int) time.Time {
	return time.Date(y, m, d, hh, mm, ss, 0, time.UTC)
}

func TestFileStorePutAndGet(t *testing.T) {
	store := newTestFileStore(t)
	wantNow := fixedTime(2026, time.April, 14, 16, 10, 19)

	store.clock = func() time.Time { return wantNow }

	reg := Registration{
		Name:    "artefact-a",
		Version: "1.2.3",
		Tags:    []string{"tag1", "tag2"},
		Suppressions: []model.Suppression{
			{
				VulnerabilityName: "CVE-1234-5678",
				Reason:            "test",
			},
		},
	}

	if err := store.Put(reg); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	got, err := store.Get("artefact-a", "1.2.3")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if got.Name != reg.Name {
		t.Fatalf("Name = %q, want %q", got.Name, reg.Name)
	}
	if got.Version != reg.Version {
		t.Fatalf("Version = %q, want %q", got.Version, reg.Version)
	}
	if len(got.Tags) != len(reg.Tags) {
		t.Fatalf("Tags length = %d, want %d", len(got.Tags), len(reg.Tags))
	}
	if len(got.Suppressions) != len(reg.Suppressions) {
		t.Fatalf("Suppressions length = %d, want %d", len(got.Suppressions), len(reg.Suppressions))
	}
	if !got.UpdatedAt.Equal(wantNow) {
		t.Fatalf("UpdatedAt = %v, want %v", got.UpdatedAt, wantNow)
	}
}

func TestFileStorePutRejectsMissingName(t *testing.T) {
	store := newTestFileStore(t)

	err := store.Put(Registration{Version: "1.2.3"})
	if err == nil {
		t.Fatal("Put() error = nil, want error")
	}
}

func TestFileStorePutRejectsMissingVersion(t *testing.T) {
	store := newTestFileStore(t)

	err := store.Put(Registration{Name: "artefact-a"})
	if err == nil {
		t.Fatal("Put() error = nil, want error")
	}
}

func TestFileStoreUpdateLastNotifiedAt(t *testing.T) {
	store := newTestFileStore(t)

	at := fixedTime(2026, time.April, 14, 17, 0, 0)
	if err := store.UpdateLastNotifiedAt("artefact-a", "1.2.3", at); err != nil {
		t.Fatalf("UpdateLastNotifiedAt() error = %v", err)
	}

	got, err := store.GetState("artefact-a", "1.2.3")
	if err != nil {
		t.Fatalf("GetState() error = %v", err)
	}

	if !got.LastNotifiedAt.Equal(at) {
		t.Fatalf("LastNotifiedAt = %v, want %v", got.LastNotifiedAt, at)
	}
}

func TestFileStoreLastContactUsesUpdatedAtWhenNoState(t *testing.T) {
	store := newTestFileStore(t)
	wantUpdatedAt := fixedTime(2026, time.April, 14, 16, 10, 19)

	store.clock = func() time.Time { return wantUpdatedAt }

	if err := store.Put(Registration{Name: "artefact-a", Version: "1.2.3"}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	got, err := store.LastContact("artefact-a", "1.2.3")
	if err != nil {
		t.Fatalf("LastContact() error = %v", err)
	}

	if !got.Equal(wantUpdatedAt) {
		t.Fatalf("LastContact = %v, want %v", got, wantUpdatedAt)
	}
}

func TestFileStoreLastContactUsesLastNotifiedAtWhenNewer(t *testing.T) {
	store := newTestFileStore(t)

	updatedAt := fixedTime(2026, time.April, 14, 16, 10, 19)
	lastNotifiedAt := fixedTime(2026, time.April, 15, 9, 30, 0)

	store.clock = func() time.Time { return updatedAt }

	if err := store.Put(Registration{Name: "artefact-a", Version: "1.2.3"}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if err := store.UpdateLastNotifiedAt("artefact-a", "1.2.3", lastNotifiedAt); err != nil {
		t.Fatalf("UpdateLastNotifiedAt() error = %v", err)
	}

	got, err := store.LastContact("artefact-a", "1.2.3")
	if err != nil {
		t.Fatalf("LastContact() error = %v", err)
	}

	if !got.Equal(lastNotifiedAt) {
		t.Fatalf("LastContact = %v, want %v", got, lastNotifiedAt)
	}
}

func TestFileStorePurgeOlderThan(t *testing.T) {
	store := newTestFileStore(t)

	oldUpdatedAt := fixedTime(2025, time.January, 1, 0, 0, 0)
	newUpdatedAt := fixedTime(2026, time.January, 1, 0, 0, 0)
	newLastNotifiedAt := fixedTime(2026, time.March, 1, 0, 0, 0)

	store.clock = func() time.Time { return oldUpdatedAt }
	if err := store.Put(Registration{Name: "old-artefact", Version: "1.0.0"}); err != nil {
		t.Fatalf("Put(old) error = %v", err)
	}

	store.clock = func() time.Time { return newUpdatedAt }
	if err := store.Put(Registration{Name: "new-artefact", Version: "2.0.0"}); err != nil {
		t.Fatalf("Put(new) error = %v", err)
	}
	if err := store.UpdateLastNotifiedAt("new-artefact", "2.0.0", newLastNotifiedAt); err != nil {
		t.Fatalf("UpdateLastNotifiedAt(new) error = %v", err)
	}

	cutoff := fixedTime(2025, time.June, 1, 0, 0, 0)
	if err := store.PurgeOlderThan(cutoff); err != nil {
		t.Fatalf("PurgeOlderThan() error = %v", err)
	}

	if _, err := store.Get("old-artefact", "1.0.0"); !os.IsNotExist(err) {
		t.Fatalf("Get(old) error = %v, want os.IsNotExist", err)
	}

	if _, err := store.Get("new-artefact", "2.0.0"); err != nil {
		t.Fatalf("Get(new) error = %v, want nil", err)
	}
}

func TestFileStoreDeleteRemovesDirectory(t *testing.T) {
	store := newTestFileStore(t)

	store.clock = func() time.Time {
		return fixedTime(2026, time.April, 14, 16, 10, 19)
	}

	if err := store.Put(Registration{Name: "artefact-a", Version: "1.2.3"}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	if err := store.Delete("artefact-a", "1.2.3"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	dir := filepath.Join(store.dir, registrationKey("artefact-a", "1.2.3"))
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("directory exists after Delete: err=%v", err)
	}
}
