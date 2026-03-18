package store

import "sync"

type Snapshot struct {
	Processed int64
}

type Store struct {
	mu        sync.Mutex
	processed int64
}

func NewStore() *Store { return &Store{} }

func (s *Store) IncrementProcessed() {
	s.mu.Lock()
	s.processed++
	s.mu.Unlock()
}

func (s *Store) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Snapshot{Processed: s.processed}
}
