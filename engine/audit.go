package engine

import (
	"sync"
	"time"
)

// AuditRecord 是一条可追溯的审计记录（仅告警命中或被豁免的拒绝会产生）。
type AuditRecord struct {
	RequestUID string
	Version    string
	Rule       string
	Message    string
	Exempted   bool
	RecordedAt time.Time
}

// AuditRecorder 记录审计事件；同一请求 UID 的重复评估不会产生重复记录。
type AuditRecorder struct {
	mu      sync.Mutex
	seen    map[string]struct{} // key: UID + 规则 + 是否豁免
	records []AuditRecord
}

func NewAuditRecorder() *AuditRecorder {
	return &AuditRecorder{seen: map[string]struct{}{}}
}

// record 去重追加审计记录；返回是否为新记录。
func (a *AuditRecorder) record(rec AuditRecord) bool {
	key := rec.RequestUID + "|" + rec.Rule + "|" + map[bool]string{true: "exempt", false: "warn"}[rec.Exempted]
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, dup := a.seen[key]; dup {
		return false
	}
	a.seen[key] = struct{}{}
	a.records = append(a.records, rec)
	return true
}

// Records 返回全部审计记录快照。
func (a *AuditRecorder) Records() []AuditRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AuditRecord, len(a.records))
	copy(out, a.records)
	return out
}
