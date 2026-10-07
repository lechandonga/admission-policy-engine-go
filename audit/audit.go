// Package audit 记录仅告警模式命中的审计事件，同一请求指纹去重。
package audit

import (
	"sync"
	"time"
)

// Record 是一条可追溯的审计记录。
type Record struct {
	Fingerprint string // 请求指纹，用于去重
	Version     string // 产生记录时的策略集合版本
	PolicyID    string
	RuleID      string
	Kind        string
	Namespace   string
	Name        string
	Operation   string
	Message     string
	RecordedAt  time.Time
}

// Recorder 是并发安全、按 (指纹, 策略版本, 策略, 规则) 去重的审计记录器。
type Recorder struct {
	mu      sync.Mutex
	seen    map[string]bool
	records []Record
}

// NewRecorder 创建空记录器。
func NewRecorder() *Recorder {
	return &Recorder{seen: map[string]bool{}}
}

// Record 写入一条审计记录；重复评估同一请求不会产生重复记录。
// 返回 true 表示本次写入了新记录。
func (r *Recorder) Record(rec Record) bool {
	key := rec.Fingerprint + "|" + rec.Version + "|" + rec.PolicyID + "|" + rec.RuleID
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen[key] {
		return false
	}
	r.seen[key] = true
	r.records = append(r.records, rec)
	return true
}

// Records 返回全部审计记录副本。
func (r *Recorder) Records() []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Record, len(r.records))
	copy(out, r.records)
	return out
}

// Len 返回审计记录条数。
func (r *Recorder) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.records)
}
