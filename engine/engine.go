package engine

import (
	"fmt"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lechandonga/admission-policy-engine-go/policy"
)

// Engine 是准入策略评估引擎。评估只读取原子快照，
// 并发热更新时只会看到旧版或新版的完整视图。
type Engine struct {
	current atomic.Pointer[policy.Set]

	mu       sync.RWMutex
	versions map[string]*policy.Set // 全部历史版本，供指定版本复现评估

	exemptions *ExemptionRegistry
	audit      *AuditRecorder
	now        func() time.Time
}

// New 创建一个引擎并加载初始策略集合；集合非法时返回错误。
func New(initial *policy.Set) (*Engine, error) {
	if err := initial.Validate(); err != nil {
		return nil, fmt.Errorf("初始策略集合非法: %w", err)
	}
	e := &Engine{
		versions:   map[string]*policy.Set{},
		exemptions: NewExemptionRegistry(),
		audit:      NewAuditRecorder(),
		now:        time.Now,
	}
	e.versions[initial.Version] = initial
	e.current.Store(initial)
	return e, nil
}

// Exemptions 返回豁免注册表。
func (e *Engine) Exemptions() *ExemptionRegistry { return e.exemptions }

// Audit 返回审计记录器。
func (e *Engine) Audit() *AuditRecorder { return e.audit }

// Load 热更新策略集合：先整体校验，通过后原子切换生效版本。
// 校验失败时当前生效版本不受任何影响。
func (e *Engine) Load(set *policy.Set) error {
	if err := set.Validate(); err != nil {
		return fmt.Errorf("策略集合 %q 被拒绝: %w", set.Version, err)
	}
	e.mu.Lock()
	if _, exists := e.versions[set.Version]; exists {
		e.mu.Unlock()
		return fmt.Errorf("策略集合版本 %q 已存在，拒绝覆盖历史版本", set.Version)
	}
	e.versions[set.Version] = set
	e.mu.Unlock()
	e.current.Store(set)
	return nil
}

// CurrentVersion 返回当前生效版本号。
func (e *Engine) CurrentVersion() string { return e.current.Load().Version }

// Versions 返回全部可查询的历史版本号（升序）。
func (e *Engine) Versions() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]string, 0, len(e.versions))
	for v := range e.versions {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// Evaluate 使用当前生效版本评估请求。
func (e *Engine) Evaluate(req Request) Decision {
	return e.evaluateWith(e.current.Load(), req)
}

// EvaluateAt 使用指定历史版本评估请求；同一输入在同一版本下结论可复现。
func (e *Engine) EvaluateAt(version string, req Request) (Decision, error) {
	e.mu.RLock()
	set, ok := e.versions[version]
	e.mu.RUnlock()
	if !ok {
		return Decision{}, fmt.Errorf("未知策略版本 %q", version)
	}
	return e.evaluateWith(set, req), nil
}

// evaluateWith 是评估主流程：畸形输入与未覆盖不放行，
// 多条命中规则按确定顺序合并为唯一结论。
func (e *Engine) evaluateWith(set *policy.Set, req Request) Decision {
	d := Decision{Version: set.Version}

	if err := req.validate(); err != nil {
		d.Reasons = append(d.Reasons, Reason{
			Code:    CodeMalformedInput,
			Message: "畸形输入: " + err.Error(),
		})
		return d
	}

	covered := false // 是否有规则的作用范围覆盖该请求
	for _, rule := range set.SortedRules() {
		if !rule.Scope.Matches(req.Namespace, req.Resource, req.Operation) {
			continue
		}
		if rule.Mode != policy.ModeDryRun {
			// 试算规则不构成覆盖，避免试算影响真实请求结论。
			covered = true
		}
		hit, missing := matchRule(rule, req)
		if missing != "" {
			// 字段缺失：失败关闭。拦截/告警模式均不得默认放行。
			reason := Reason{
				Code:    CodeFieldMissing,
				Rule:    rule.Name,
				Message: fmt.Sprintf("规则 %q 条件字段 %q 缺失，按失败关闭处理", rule.Name, missing),
			}
			e.applyMode(&d, req, rule, reason)
			continue
		}
		if !hit {
			continue
		}
		reason := Reason{Rule: rule.Name, Message: rule.Message}
		switch rule.Mode {
		case policy.ModeEnforce:
			reason.Code = CodeRuleDenied
		case policy.ModeWarn:
			reason.Code = CodeRuleWarned
		default:
			reason.Code = CodeRuleDryRun
		}
		e.applyMode(&d, req, rule, reason)
	}

	if !covered {
		d.Reasons = append(d.Reasons, Reason{
			Code:    CodeNoPolicyCoverage,
			Message: "无任何策略规则覆盖该请求，按失败关闭拒绝",
		})
	}

	// 豁免：仅抵消拦截类原因（RuleDenied / FieldMissing）。
	var denied, others []Reason
	for _, r := range d.Reasons {
		if r.Code == CodeRuleDenied || r.Code == CodeFieldMissing {
			denied = append(denied, r)
		} else {
			others = append(others, r)
		}
	}
	var surviving []Reason
	exemptedSet := map[string]bool{}
	for _, r := range denied {
		ids := e.exemptions.activeFor(r.Rule, req)
		if len(ids) > 0 {
			exemptedSet[r.Rule] = true
			d.ExemptedBy = append(d.ExemptedBy, ids...)
			others = append(others, Reason{
				Code:    CodeExempted,
				Rule:    r.Rule,
				Message: fmt.Sprintf("规则 %q 的拦截被豁免 %v 放行", r.Rule, ids),
			})
			e.recordAudit(req, set.Version, r, true)
			continue
		}
		surviving = append(surviving, r)
	}
	d.Reasons = append(surviving, others...)
	if len(d.Reasons) == 0 {
		code := CodeNoViolations
		msg := "所有覆盖规则均通过"
		if len(exemptedSet) > 0 {
			code = CodeExempted
			msg = "拦截项已被有效豁免放行"
		}
		d.Reasons = []Reason{{Code: code, Message: msg}}
	}

	d.Allowed = true
	for _, r := range d.Reasons {
		if r.Code == CodeRuleDenied || r.Code == CodeFieldMissing ||
			r.Code == CodeMalformedInput || r.Code == CodeNoPolicyCoverage {
			d.Allowed = false
			break
		}
	}
	sort.Strings(d.ExemptedBy)
	return d
}

// applyMode 按规则模式把命中结果并入结论：拦截/告警进入 Reasons，
// 试算只进入 DryRun 列表；告警命中同时产出审计记录。
func (e *Engine) applyMode(d *Decision, req Request, rule policy.Rule, reason Reason) {
	switch rule.Mode {
	case policy.ModeDryRun:
		d.DryRun = append(d.DryRun, reason)
	case policy.ModeWarn:
		d.Reasons = append(d.Reasons, reason)
		e.recordAudit(req, d.Version, reason, false)
	default:
		d.Reasons = append(d.Reasons, reason)
	}
}

func (e *Engine) recordAudit(req Request, version string, reason Reason, exempted bool) {
	e.audit.record(AuditRecord{
		RequestUID: req.UID,
		Version:    version,
		Rule:       reason.Rule,
		Message:    reason.Message,
		Exempted:   exempted,
		RecordedAt: e.now(),
	})
}

// matchRule 判断规则是否命中；返回缺失字段名（若有）。
func matchRule(rule policy.Rule, req Request) (hit bool, missingField string) {
	for _, c := range rule.Conditions {
		val, ok := resolveField(req, c.Field)
		if !ok {
			if c.Operator == policy.OpMissing {
				continue
			}
			return false, c.Field
		}
		if !evalCondition(c, val) {
			return false, ""
		}
	}
	return true, ""
}

// resolveField 支持对象点分路径，以及 namespace/resource/operation 内置字段。
func resolveField(req Request, field string) (string, bool) {
	switch field {
	case "namespace":
		return req.Namespace, true
	case "resource":
		return req.Resource, true
	case "operation":
		return req.Operation, true
	}
	return fieldValue(req.Object, field)
}

func evalCondition(c policy.Condition, val string) bool {
	switch c.Operator {
	case policy.OpEquals:
		return val == c.Value
	case policy.OpNotEquals:
		return val != c.Value
	case policy.OpIn:
		for _, v := range c.Values {
			if v == val {
				return true
			}
		}
		return false
	case policy.OpExists:
		return true
	case policy.OpMatch:
		re, err := regexp.Compile(c.Value)
		return err == nil && re.MatchString(val)
	default:
		return false
	}
}
