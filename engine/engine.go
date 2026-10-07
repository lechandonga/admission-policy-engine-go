// Package engine 实现进程内准入策略评估引擎：原子热更新、版本注册、
// 确定性规则合并、豁免判定与审计产出。
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lechandonga/admission-policy-engine-go/audit"
	"github.com/lechandonga/admission-policy-engine-go/exemption"
	"github.com/lechandonga/admission-policy-engine-go/policy"
)

// Reason 是可区分的决策原因码。
type Reason string

const (
	ReasonAllowed        Reason = "ALLOWED"         // 命中策略且全部通过
	ReasonDenied         Reason = "DENIED"          // 命中 enforce 规则违规
	ReasonWarned         Reason = "WARNED"          // 仅告警命中，放行但有审计
	ReasonExempted       Reason = "EXEMPTED"        // 违规被有效豁免覆盖，放行
	ReasonNoCoverage     Reason = "NO_COVERAGE"     // 无任何策略覆盖该请求，拒绝
	ReasonMalformed      Reason = "MALFORMED_INPUT" // 请求输入畸形，拒绝
	ReasonVersionUnknown Reason = "VERSION_UNKNOWN" // 指定版本不存在
)

// Request 是一次准入请求。
type Request struct {
	Kind      string         `json:"kind"`
	Namespace string         `json:"namespace"`
	Name      string         `json:"name"`
	Operation string         `json:"operation"`
	Object    map[string]any `json:"object"`
}

// validate 检查请求是否畸形。
func (r *Request) validate() error {
	if r == nil {
		return fmt.Errorf("request is nil")
	}
	if strings.TrimSpace(r.Kind) == "" {
		return fmt.Errorf("kind is required")
	}
	if strings.TrimSpace(r.Operation) == "" {
		return fmt.Errorf("operation is required")
	}
	if r.Object == nil {
		return fmt.Errorf("object is required")
	}
	return nil
}

// Fingerprint 返回请求的稳定指纹，用于审计去重。
func (r *Request) Fingerprint() string {
	h := sha256.New()
	h.Write([]byte(r.Kind + "|" + r.Namespace + "|" + r.Name + "|" + r.Operation))
	keys := make([]string, 0, len(r.Object))
	for k := range r.Object {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b, _ := json.Marshal(r.Object[k])
		h.Write([]byte(k))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Violation 描述一次规则命中。
type Violation struct {
	PolicyID string
	RuleID   string
	Mode     policy.Mode
	Exempted bool
	Message  string
}

// Decision 是一次评估的唯一结论。
type Decision struct {
	Allowed    bool
	Reason     Reason
	Version    string      // 实际使用的策略集合版本
	Violations []Violation // 按 (PolicyID, RuleID) 排序，顺序确定
	DryRun     []Violation // 试算命中，仅供观察，不影响结论见证
}

// registry 是策略集合的不可变视图：当前版本 + 全部历史版本。
type registry struct {
	current  *policy.Set
	versions map[string]*policy.Set
}

// Engine 是并发安全的准入评估引擎。
type Engine struct {
	view   atomic.Pointer[registry]
	loadMu sync.Mutex // 串行化加载，保证原子生效
	exempt *exemption.Store
	audit  *audit.Recorder
	now    func() time.Time
}

// Option 用于注入测试钩子。
type Option func(*Engine)

// WithClock 注入时钟（测试豁免过期时使用）。
func WithClock(now func() time.Time) Option {
	return func(e *Engine) { e.now = now }
}

// New 创建引擎，必须随后成功 LoadSet 才能评估。
func New(ex *exemption.Store, rec *audit.Recorder, opts ...Option) *Engine {
	e := &Engine{exempt: ex, audit: rec, now: time.Now}
	for _, o := range opts {
		o(e)
	}
	e.view.Store(&registry{versions: map[string]*policy.Set{}})
	return e
}

// LoadSet 校验并原子加载新版本；非法集合整体拒绝且不影响当前版本。
func (e *Engine) LoadSet(set *policy.Set) error {
	if err := set.Validate(); err != nil {
		return err
	}
	e.loadMu.Lock()
	defer e.loadMu.Unlock()
	old := e.view.Load()
	if _, exists := old.versions[set.Version]; exists {
		return fmt.Errorf("policy set version %q already loaded", set.Version)
	}
	versions := make(map[string]*policy.Set, len(old.versions)+1)
	for v, s := range old.versions {
		versions[v] = s
	}
	versions[set.Version] = set
	e.view.Store(&registry{current: set, versions: versions})
	return nil
}

// CurrentVersion 返回当前生效版本号。
func (e *Engine) CurrentVersion() string {
	if c := e.view.Load().current; c != nil {
		return c.Version
	}
	return ""
}

// Versions 返回全部可查询的历史版本号（升序）。
func (e *Engine) Versions() []string {
	reg := e.view.Load()
	out := make([]string, 0, len(reg.versions))
	for v := range reg.versions {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// Evaluate 使用当前生效版本评估请求。
func (e *Engine) Evaluate(req *Request) Decision {
	return e.evaluate(req, "")
}

// EvaluateAt 使用指定历史版本评估请求，结论可复现。
func (e *Engine) EvaluateAt(req *Request, version string) Decision {
	return e.evaluate(req, version)
}

func (e *Engine) evaluate(req *Request, version string) Decision {
	reg := e.view.Load()
	set := reg.current
	if version != "" {
		s, ok := reg.versions[version]
		if !ok {
			return Decision{Allowed: false, Reason: ReasonVersionUnknown, Version: version}
		}
		set = s
	}
	if set == nil {
		return Decision{Allowed: false, Reason: ReasonNoCoverage}
	}
	d := Decision{Version: set.Version}
	if err := req.validate(); err != nil {
		d.Reason = ReasonMalformed
		d.Violations = []Violation{{Message: err.Error()}}
		return d
	}
	fp := req.Fingerprint()
	now := e.now()
	matched := false
	for _, p := range set.SortedPolicies() {
		if !p.Scope.Matches(req.Kind, req.Namespace, req.Operation) {
			continue
		}
		matched = true
		rules := make([]policy.Rule, len(p.Rules))
		copy(rules, p.Rules)
		sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
		for _, r := range rules {
			msg, violated := evalRule(r, req.Object)
			if !violated {
				continue
			}
			v := Violation{PolicyID: p.ID, RuleID: r.ID, Mode: p.Mode, Message: msg}
			switch p.Mode {
			case policy.ModeDryRun:
				d.DryRun = append(d.DryRun, v)
			case policy.ModeWarn:
				d.Violations = append(d.Violations, v)
				e.audit.Record(audit.Record{
					Fingerprint: fp, Version: set.Version,
					PolicyID: p.ID, RuleID: r.ID,
					Kind: req.Kind, Namespace: req.Namespace, Name: req.Name,
					Operation: req.Operation, Message: msg,
					RecordedAt: now,
				})
			case policy.ModeEnforce:
				if e.exempt.Covers(p.ID, req.Kind, req.Namespace, req.Operation, now) {
					v.Exempted = true
				}
				d.Violations = append(d.Violations, v)
			}
		}
	}
	if !matched {
		d.Allowed = false
		d.Reason = ReasonNoCoverage
		return d
	}
	denied, warned, exempted := false, false, false
	for _, v := range d.Violations {
		switch {
		case v.Mode == policy.ModeEnforce && !v.Exempted:
			denied = true
		case v.Mode == policy.ModeEnforce && v.Exempted:
			exempted = true
		case v.Mode == policy.ModeWarn:
			warned = true
		}
	}
	switch {
	case denied:
		d.Allowed, d.Reason = false, ReasonDenied
	case exempted:
		d.Allowed, d.Reason = true, ReasonExempted
	case warned:
		d.Allowed, d.Reason = true, ReasonWarned
	default:
		d.Allowed, d.Reason = true, ReasonAllowed
	}
	return d
}

// evalRule 评估单条规则，返回违规说明与是否违规。
func evalRule(r policy.Rule, obj map[string]any) (string, bool) {
	val, ok := lookup(obj, r.Field)
	if r.Op == policy.OpRequired {
		if !ok {
			return fmt.Sprintf("field %q is required but missing", r.Field), true
		}
		return "", false
	}
	if !ok {
		// 字段缺失不得默认放行。
		return fmt.Sprintf("field %q missing, cannot verify rule %q", r.Field, r.ID), true
	}
	switch r.Op {
	case policy.OpEq:
		if !reflect.DeepEqual(normalize(val), normalize(r.Value)) {
			return fmt.Sprintf("field %q=%v, expected %v", r.Field, val, r.Value), true
		}
	case policy.OpNeq:
		if reflect.DeepEqual(normalize(val), normalize(r.Value)) {
			return fmt.Sprintf("field %q must not equal %v", r.Field, r.Value), true
		}
	case policy.OpIn:
		list, ok := r.Value.([]any)
		if !ok {
			return fmt.Sprintf("rule %q in-op requires array value", r.ID), true
		}
		for _, item := range list {
			if reflect.DeepEqual(normalize(val), normalize(item)) {
				return "", false
			}
		}
		return fmt.Sprintf("field %q=%v not in %v", r.Field, val, list), true
	case policy.OpMatches:
		s, _ := val.(string)
		pat, _ := r.Value.(string)
		if !regexp.MustCompile(pat).MatchString(s) {
			return fmt.Sprintf("field %q=%q does not match %q", r.Field, s, pat), true
		}
	}
	return "", false
}

// normalize 把 JSON 数字统一为 float64 以便比较。
func normalize(v any) any {
	switch n := v.(type) {
	case int:
		return float64(n)
	case int64:
		return float64(n)
	default:
		return v
	}
}

// lookup 按点分路径取值。
func lookup(obj map[string]any, path string) (any, bool) {
	var cur any = obj
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}
