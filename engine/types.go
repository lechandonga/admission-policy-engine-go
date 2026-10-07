// Package engine 提供进程内的准入策略评估引擎：版本化策略集合的原子热更新、
// 确定性的多规则合并、审计记录与带过期/撤销语义的豁免闭环。
package engine

import (
	"fmt"
	"strconv"
)

// Request 是一次准入评估请求，模拟真实准入链路中的 AdmissionReview。
type Request struct {
	// UID 唯一标识一次请求；同一 UID 的重复评估用于审计去重。
	UID       string
	Namespace string
	Resource  string
	Operation string // CREATE / UPDATE / DELETE 等
	// Object 是资源清单（如解码后的 Pod spec），规则条件在其上取字段。
	Object map[string]any
}

// validate 校验请求基本结构；畸形输入不允许默认放行。
func (r Request) validate() error {
	if r.UID == "" {
		return fmt.Errorf("缺少 UID")
	}
	if r.Namespace == "" || r.Resource == "" || r.Operation == "" {
		return fmt.Errorf("缺少 namespace/resource/operation")
	}
	if r.Object == nil {
		return fmt.Errorf("缺少资源清单 object")
	}
	return nil
}

// ReasonCode 区分结论来源，保证“未覆盖 / 字段缺失 / 输入畸形 / 命中规则”可区分。
type ReasonCode string

const (
	CodeMalformedInput   ReasonCode = "MalformedInput"   // 请求结构非法
	CodeNoPolicyCoverage ReasonCode = "NoPolicyCoverage" // 无任何规则覆盖该请求
	CodeRuleDenied       ReasonCode = "RuleDenied"       // 拦截规则命中
	CodeRuleWarned       ReasonCode = "RuleWarned"       // 仅告警规则命中
	CodeRuleDryRun       ReasonCode = "RuleDryRun"       // 试算规则命中（不影响结论）
	CodeFieldMissing     ReasonCode = "FieldMissing"     // 条件字段缺失，按失败关闭处理
	CodeExempted         ReasonCode = "Exempted"         // 被有效豁免放行
	CodeNoViolations     ReasonCode = "NoViolations"     // 有规则覆盖且全部通过
)

// Reason 是一条可解释的命中/放行原因。
type Reason struct {
	Code    ReasonCode
	Rule    string // 命中规则名；非规则类原因为空
	Message string
}

// Decision 是一次评估的唯一结论。
type Decision struct {
	Allowed bool
	Version string   // 评估所用的策略集合版本
	Reasons []Reason // 按确定顺序排列的合并原因
	// DryRun 列出试算规则的命中情况，仅作提示，不影响 Allowed。
	DryRun []Reason
	// ExemptedBy 列出本次生效的豁免 ID。
	ExemptedBy []string
}

// fieldValue 按点分路径从资源清单取值；路径缺失或类型不符时返回 ok=false。
func fieldValue(obj map[string]any, path string) (string, bool) {
	var cur any = obj
	for _, seg := range splitPath(path) {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		cur, ok = m[seg]
		if !ok {
			return "", false
		}
	}
	switch v := cur.(type) {
	case string:
		return v, true
	case fmt.Stringer:
		return v.String(), true
	case int:
		return strconv.Itoa(v), true
	case int64:
		return strconv.FormatInt(v, 10), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(v), true
	default:
		return "", false
	}
}

func splitPath(path string) []string {
	var segs []string
	start := 0
	for i := 0; i < len(path); i++ {
		if path[i] == '.' {
			segs = append(segs, path[start:i])
			start = i + 1
		}
	}
	return append(segs, path[start:])
}
