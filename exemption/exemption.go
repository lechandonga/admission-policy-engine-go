// Package exemption 提供带作用范围与过期时间的豁免存储，支持撤销与并发读写。
package exemption

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lechandonga/admission-policy-engine-go/policy"
)

// ErrNotFound 表示目标豁免不存在。
var ErrNotFound = errors.New("exemption not found")

// Exemption 描述一条豁免：在作用范围内、过期时间之前且未撤销时，
// 指定策略（或全部策略）的违规不阻塞请求。
type Exemption struct {
	ID        string
	PolicyID  string // "*" 表示所有策略
	Scope     policy.Scope
	ExpiresAt time.Time
	Revoked   bool
}

// active 报告豁免在指定时刻是否生效。
func (e *Exemption) active(now time.Time) bool {
	return !e.Revoked && now.Before(e.ExpiresAt)
}

// Store 是并发安全的豁免存储。
type Store struct {
	mu    sync.RWMutex
	items map[string]*Exemption
}

// NewStore 创建空豁免存储。
func NewStore() *Store {
	return &Store{items: map[string]*Exemption{}}
}

// Add 新增豁免；ID 冲突或字段非法时报错。
func (s *Store) Add(e Exemption) error {
	if e.ID == "" {
		return fmt.Errorf("exemption id is required")
	}
	if e.PolicyID == "" {
		return fmt.Errorf("exemption %q: policy id is required (use \"*\" for all)", e.ID)
	}
	if e.ExpiresAt.IsZero() {
		return fmt.Errorf("exemption %q: expires_at is required", e.ID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[e.ID]; ok {
		return fmt.Errorf("exemption %q already exists", e.ID)
	}
	cp := e
	s.items[e.ID] = &cp
	return nil
}

// Revoke 撤销豁免，立即生效。
func (s *Store) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.items[id]
	if !ok {
		return ErrNotFound
	}
	e.Revoked = true
	return nil
}

// Covers 判断在指定时刻，是否存在覆盖 (policyID, kind, namespace, operation) 的有效豁免。
func (s *Store) Covers(policyID, kind, namespace, operation string, now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.items {
		if !e.active(now) {
			continue
		}
		if e.PolicyID != "*" && e.PolicyID != policyID {
			continue
		}
		if e.Scope.Matches(kind, namespace, operation) {
			return true
		}
	}
	return false
}

// Snapshot 返回当前全部豁免的副本，用于审计与调试。
func (s *Store) Snapshot() []Exemption {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Exemption, 0, len(s.items))
	for _, e := range s.items {
		out = append(out, *e)
	}
	return out
}
