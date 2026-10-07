package policy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// APIVersion 是当前引擎唯一支持的策略集合结构版本。
const APIVersion = "admission.local/v1"

// Mode 表示规则的生效模式。
type Mode string

const (
	// ModeEnforce 拦截模式：命中即拒绝请求。
	ModeEnforce Mode = "enforce"
	// ModeWarn 仅告警模式：不阻塞请求，但产出审计记录。
	ModeWarn Mode = "warn"
	// ModeDryRun 试算模式：只在结论中标注，不影响放行也不产生审计。
	ModeDryRun Mode = "dryrun"
)

var validModes = map[Mode]bool{
	ModeEnforce: true,
	ModeWarn:    true,
	ModeDryRun:  true,
}

// Operator 是条件比较运算符。
type Operator string

const (
	OpEquals    Operator = "Equals"
	OpNotEquals Operator = "NotEquals"
	OpIn        Operator = "In"
	OpExists    Operator = "Exists"
	OpMissing   Operator = "Missing"
	OpMatch     Operator = "Match" // 正则匹配
)

var validOperators = map[Operator]bool{
	OpEquals:    true,
	OpNotEquals: true,
	OpIn:        true,
	OpExists:    true,
	OpMissing:   true,
	OpMatch:     true,
}

// Scope 声明规则或豁免的作用范围；空切片表示匹配全部。
// 同一维度内为“或”，不同维度之间为“与”。
type Scope struct {
	Namespaces []string `json:"namespaces,omitempty"`
	Resources  []string `json:"resources,omitempty"`
	Operations []string `json:"operations,omitempty"`
}

// Matches 判断请求是否落在作用范围内。
func (s Scope) Matches(namespace, resource, operation string) bool {
	return containsOrEmpty(s.Namespaces, namespace) &&
		containsOrEmpty(s.Resources, resource) &&
		containsOrEmpty(s.Operations, operation)
}

func containsOrEmpty(set []string, v string) bool {
	if len(set) == 0 {
		return true
	}
	for _, item := range set {
		if item == "*" || item == v {
			return true
		}
	}
	return false
}

// Condition 是针对请求对象字段的一条断言，字段使用点分路径（如 spec.replicas）。
type Condition struct {
	Field    string   `json:"field"`
	Operator Operator `json:"operator"`
	Value    string   `json:"value,omitempty"`
	Values   []string `json:"values,omitempty"`
}

// Rule 是一条准入规则。
type Rule struct {
	Name       string      `json:"name"`
	Mode       Mode        `json:"mode"`
	Scope      Scope       `json:"scope"`
	Conditions []Condition `json:"conditions"`
	Message    string      `json:"message"`
}

// Set 是一个不可变的策略集合版本。加载校验通过后即视为只读。
type Set struct {
	APIVersion string `json:"apiVersion"`
	Version    string `json:"version"`
	Rules      []Rule `json:"rules"`
}

// Validate 对策略集合做整体校验；任何一处非法都返回错误，调用方应整体拒绝。
func (s *Set) Validate() error {
	if s.APIVersion != APIVersion {
		return fmt.Errorf("不支持的结构版本 %q（仅支持 %q）", s.APIVersion, APIVersion)
	}
	if strings.TrimSpace(s.Version) == "" {
		return fmt.Errorf("策略集合缺少 version")
	}
	if len(s.Rules) == 0 {
		return fmt.Errorf("策略集合至少包含一条规则")
	}
	seen := make(map[string]struct{}, len(s.Rules))
	for i, r := range s.Rules {
		if strings.TrimSpace(r.Name) == "" {
			return fmt.Errorf("第 %d 条规则缺少 name", i)
		}
		if _, dup := seen[r.Name]; dup {
			return fmt.Errorf("规则名 %q 声明冲突（重复定义）", r.Name)
		}
		seen[r.Name] = struct{}{}
		if !validModes[r.Mode] {
			return fmt.Errorf("规则 %q 的生效模式 %q 非法", r.Name, r.Mode)
		}
		if strings.TrimSpace(r.Message) == "" {
			return fmt.Errorf("规则 %q 缺少 message", r.Name)
		}
		for j, c := range r.Conditions {
			if err := validateCondition(c); err != nil {
				return fmt.Errorf("规则 %q 第 %d 个条件非法: %w", r.Name, j, err)
			}
		}
	}
	return nil
}

func validateCondition(c Condition) error {
	if strings.TrimSpace(c.Field) == "" {
		return fmt.Errorf("条件缺少 field")
	}
	if !validOperators[c.Operator] {
		return fmt.Errorf("未知运算符 %q", c.Operator)
	}
	switch c.Operator {
	case OpIn:
		if len(c.Values) == 0 {
			return fmt.Errorf("In 运算符要求非空 values")
		}
	case OpExists, OpMissing:
	default:
		if c.Value == "" {
			return fmt.Errorf("%s 运算符要求非空 value", c.Operator)
		}
	}
	if c.Operator == OpMatch {
		if _, err := regexp.Compile(c.Value); err != nil {
			return fmt.Errorf("Match 正则非法: %v", err)
		}
	}
	return nil
}

// SortedRules 返回按确定顺序（模式优先级 + 名称字典序）排列的规则副本，
// 保证多条规则命中时合并结论的顺序可复现。
func (s *Set) SortedRules() []Rule {
	rules := make([]Rule, len(s.Rules))
	copy(rules, s.Rules)
	sort.SliceStable(rules, func(i, j int) bool {
		pi, pj := modePriority(rules[i].Mode), modePriority(rules[j].Mode)
		if pi != pj {
			return pi < pj
		}
		return rules[i].Name < rules[j].Name
	})
	return rules
}

// modePriority 决定合并顺序：拦截 > 告警 > 试算。
func modePriority(m Mode) int {
	switch m {
	case ModeEnforce:
		return 0
	case ModeWarn:
		return 1
	default:
		return 2
	}
}
