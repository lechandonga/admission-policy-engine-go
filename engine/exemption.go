package engine

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lechandonga/admission-policy-engine-go/policy"
)

// Exemption 是一条带作用范围和过期时间的豁免。
type Exemption struct {
	ID        string
	RuleNames []string // 豁免的规则名；["*"] 表示全部规则
	Scope     policy.Scope
	ExpiresAt time.Time
	Revoked   bool
}

// active 判断豁免在当前时刻是否有效（未过期且未撤销）。
func (e *Exemption) active(now time.Time) bool {
	return !e.Revoked && now.Before(e.ExpiresAt)
}

// covers 判断豁免是否覆盖指定规则与请求。
func (e *Exemption) covers(ruleName string, req Request) bool {
	matched := false
	for _, n := range e.RuleNames {
		if n == "*" || n == ruleName {
			matched = true
			break
		}
	}
	return matched && e.Scope.Matches(req.Namespace, req.Resource, req.Operation)
}

// ExemptionRegistry 管理豁免的生命周期；内部加锁，可并发使用。
// 状态变化（新增/撤销/过期）在下一次评估立即生效。
type ExemptionRegistry struct {
	mu    sync.RWMutex
	items map[string]*Exemption
	now   func() time.Time // 可注入时钟，便于测试过期语义
}

func NewExemptionRegistry() *ExemptionRegistry {
	return &ExemptionRegistry{items: map[string]*Exemption{}, now: time.Now}
}

// SetClock 注入时钟（仅用于测试）。
func (r *ExemptionRegistry) SetClock(now func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = now
}

// Grant 注册一条豁免；ID 重复或过期时间非法将被拒绝。
func (r *ExemptionRegistry) Grant(e Exemption) error {
	if e.ID == "" {
		return errors.New("豁免缺少 ID")
	}
	if len(e.RuleNames) == 0 {
		return errors.New("豁免缺少规则范围 RuleNames")
	}
	if e.ExpiresAt.IsZero() {
		return errors.New("豁免必须带过期时间")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.items[e.ID]; dup {
		return fmt.Errorf("豁免 %q 已存在", e.ID)
	}
	cp := e
	r.items[e.ID] = &cp
	return nil
}

// Revoke 撤销豁免；撤销立即生效，幂等。
func (r *ExemptionRegistry) Revoke(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.items[id]; ok {
		e.Revoked = true
	}
}

// activeFor 返回当前对 (ruleName, req) 有效的豁免 ID 快照。
func (r *ExemptionRegistry) activeFor(ruleName string, req Request) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	now := r.now()
	var ids []string
	for _, e := range r.items {
		if e.active(now) && e.covers(ruleName, req) {
			ids = append(ids, e.ID)
		}
	}
	return ids
}
