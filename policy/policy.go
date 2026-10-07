// Package policy 定义准入策略模型、作用范围匹配与策略集合的合法性校验。
package policy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Mode 表示策略的生效模式。
type Mode string

const (
	// ModeEnforce 拦截模式：命中违规即拒绝请求。
	ModeEnforce Mode = "enforce"
	// ModeWarn 仅告警模式：不阻塞请求，但产出审计记录。
	ModeWarn Mode = "warn"
	// ModeDryRun 试算模式：仅记录试算结果，不影响请求结论。
	ModeDryRun Mode = "dryrun"
)

var validModes = map[Mode]bool{ModeEnforce: true, ModeWarn: true, ModeDryRun: true}

// Op 是规则比较操作符。
type Op string

const (
	OpEq       Op = "eq"       // 字段值等于期望值
	OpNeq      Op = "neq"      // 字段值不等于期望值
	OpIn       Op = "in"       // 字段值在期望值集合内
	OpRequired Op = "required" // 字段必须存在
	OpMatches  Op = "matches"  // 字段值匹配正则
)

var validOps = map[Op]bool{OpEq: true, OpNeq: true, OpIn: true, OpRequired: true, OpMatches: true}

// Scope 声明策略的作用范围，空切片表示通配。
type Scope struct {
	Kinds      []string `json:"kinds"`
	Namespaces []string `json:"namespaces"`
	Operations []string `json:"operations"`
}

// Matches 判断请求是否落在作用范围内。
func (s Scope) Matches(kind, namespace, operation string) bool {
	return matchAny(s.Kinds, kind) && matchAny(s.Namespaces, namespace) && matchAny(s.Operations, operation)
}

func matchAny(patterns []string, v string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if p == "*" || strings.EqualFold(p, v) {
			return true
		}
	}
	return false
}

// Rule 描述对资源对象某一字段的约束。
type Rule struct {
	ID    string `json:"id"`
	Field string `json:"field"` // 点分路径，如 spec.replicas
	Op    Op     `json:"op"`
	Value any    `json:"value,omitempty"`
}

// Policy 是一条准入策略。
type Policy struct {
	ID    string `json:"id"`
	Mode  Mode   `json:"mode"`
	Scope Scope  `json:"scope"`
	Rules []Rule `json:"rules"`
}

// Set 是一个不可变的策略集合版本。
type Set struct {
	Version  string   `json:"version"`
	Policies []Policy `json:"policies"`
}

// Validate 对策略集合做整体合法性校验；任何一处非法都导致整体拒绝。
func (s *Set) Validate() error {
	if s == nil {
		return fmt.Errorf("policy set is nil")
	}
	if strings.TrimSpace(s.Version) == "" {
		return fmt.Errorf("policy set version is required")
	}
	if len(s.Policies) == 0 {
		return fmt.Errorf("policy set %q must contain at least one policy", s.Version)
	}
	seenPolicy := map[string]bool{}
	for i, p := range s.Policies {
		if p.ID == "" {
			return fmt.Errorf("policy set %q: policy #%d missing id", s.Version, i)
		}
		if seenPolicy[p.ID] {
			return fmt.Errorf("policy set %q: duplicate policy id %q", s.Version, p.ID)
		}
		seenPolicy[p.ID] = true
		if !validModes[p.Mode] {
			return fmt.Errorf("policy set %q: policy %q has unsupported mode %q", s.Version, p.ID, p.Mode)
		}
		if len(p.Rules) == 0 {
			return fmt.Errorf("policy set %q: policy %q must declare at least one rule", s.Version, p.ID)
		}
		seenRule := map[string]bool{}
		for _, r := range p.Rules {
			if r.ID == "" {
				return fmt.Errorf("policy set %q: policy %q has rule with empty id", s.Version, p.ID)
			}
			if seenRule[r.ID] {
				return fmt.Errorf("policy set %q: policy %q duplicate rule id %q", s.Version, p.ID, r.ID)
			}
			seenRule[r.ID] = true
			if strings.TrimSpace(r.Field) == "" {
				return fmt.Errorf("policy set %q: rule %q missing field", s.Version, r.ID)
			}
			if !validOps[r.Op] {
				return fmt.Errorf("policy set %q: rule %q has unsupported op %q", s.Version, r.ID, r.Op)
			}
			if r.Op == OpMatches {
				pat, ok := r.Value.(string)
				if !ok {
					return fmt.Errorf("policy set %q: rule %q matches op requires string pattern", s.Version, r.ID)
				}
				if _, err := regexp.Compile(pat); err != nil {
					return fmt.Errorf("policy set %q: rule %q invalid regex: %w", s.Version, r.ID, err)
				}
			}
		}
	}
	return nil
}

// SortedPolicies 返回按 ID 排序的策略副本，保证合并顺序确定。
func (s *Set) SortedPolicies() []Policy {
	out := make([]Policy, len(s.Policies))
	copy(out, s.Policies)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
