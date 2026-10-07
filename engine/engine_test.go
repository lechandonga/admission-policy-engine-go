package engine

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/admission-policy-engine-go/policy"
)

// ---------- 测试辅助 ----------

func baseSet(version string) *policy.Set {
	return &policy.Set{
		APIVersion: policy.APIVersion,
		Version:    version,
		Rules: []policy.Rule{
			{
				Name:  "deny-privileged",
				Mode:  policy.ModeEnforce,
				Scope: policy.Scope{Resources: []string{"pods"}},
				Conditions: []policy.Condition{
					{Field: "spec.securityContext.privileged", Operator: policy.OpEquals, Value: "true"},
				},
				Message: "禁止特权容器",
			},
			{
				Name:  "warn-no-probes",
				Mode:  policy.ModeWarn,
				Scope: policy.Scope{Resources: []string{"pods"}},
				Conditions: []policy.Condition{
					{Field: "spec.readinessProbe", Operator: policy.OpMissing},
				},
				Message: "缺少就绪探针",
			},
			{
				Name:  "dryrun-require-team-label",
				Mode:  policy.ModeDryRun,
				Scope: policy.Scope{Resources: []string{"pods"}},
				Conditions: []policy.Condition{
					{Field: "metadata.labels.team", Operator: policy.OpMissing},
				},
				Message: "建议补充 team 标签",
			},
		},
	}
}

func podReq(uid string, privileged bool) Request {
	return Request{
		UID:       uid,
		Namespace: "default",
		Resource:  "pods",
		Operation: "CREATE",
		Object: map[string]any{
			"spec": map[string]any{
				"securityContext": map[string]any{"privileged": fmt.Sprintf("%t", privileged)},
			},
		},
	}
}

func newEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(baseSet("v1"))
	if err != nil {
		t.Fatalf("初始化引擎失败: %v", err)
	}
	return e
}

func hasCode(d Decision, code ReasonCode) bool {
	for _, r := range d.Reasons {
		if r.Code == code {
			return true
		}
	}
	return false
}

// ---------- 业务一：准入决策与多规则合并 ----------

func TestDecisionEnforceDeny(t *testing.T) {
	t.Log("业务: 拦截模式 —— 特权容器命中 enforce 规则必须被拒绝并给出命中规则")
	e := newEngine(t)
	d := e.Evaluate(podReq("req-deny", true))
	if d.Allowed {
		t.Fatalf("特权容器应被拒绝")
	}
	if !hasCode(d, CodeRuleDenied) {
		t.Fatalf("结论应包含 RuleDenied 原因: %+v", d.Reasons)
	}
	if d.Reasons[0].Rule != "deny-privileged" {
		t.Fatalf("首条原因应为拦截规则 deny-privileged，实际 %q", d.Reasons[0].Rule)
	}
}

func TestDecisionWarnNotBlockingWithAudit(t *testing.T) {
	t.Log("业务: 仅告警模式 —— 不阻塞请求但产出审计记录，重复评估不重复记录")
	e := newEngine(t)
	req := podReq("req-warn", false) // 缺少 readinessProbe -> 命中 warn
	d := e.Evaluate(req)
	if !d.Allowed {
		t.Fatalf("warn 模式不得阻塞请求: %+v", d.Reasons)
	}
	if !hasCode(d, CodeRuleWarned) {
		t.Fatalf("结论应包含 RuleWarned: %+v", d.Reasons)
	}
	// 试算命中只标注不影响结论
	if len(d.DryRun) != 1 || d.DryRun[0].Rule != "dryrun-require-team-label" {
		t.Fatalf("试算命中应只出现在 DryRun 列表: %+v", d.DryRun)
	}
	// 重复评估同一请求：结论一致且审计不重复
	d2 := e.Evaluate(req)
	if d2.Allowed != d.Allowed || len(d2.Reasons) != len(d.Reasons) {
		t.Fatalf("同一请求重复评估结论应一致")
	}
	records := e.Audit().Records()
	if len(records) != 1 || records[0].Rule != "warn-no-probes" || records[0].RequestUID != "req-warn" {
		t.Fatalf("审计记录应去重且可追溯，实际: %+v", records)
	}
}

func TestDecisionNoCoverageAndMalformed(t *testing.T) {
	t.Log("业务: 失败关闭 —— 策略未覆盖与畸形输入均不得默认放行，且原因可区分")
	e := newEngine(t)

	noCov := e.Evaluate(Request{UID: "r1", Namespace: "default", Resource: "configmaps", Operation: "CREATE", Object: map[string]any{}})
	if noCov.Allowed || !hasCode(noCov, CodeNoPolicyCoverage) {
		t.Fatalf("未覆盖请求应拒绝且原因为 NoPolicyCoverage: %+v", noCov)
	}

	malformed := e.Evaluate(Request{UID: "", Namespace: "default", Resource: "pods", Operation: "CREATE"})
	if malformed.Allowed || !hasCode(malformed, CodeMalformedInput) {
		t.Fatalf("畸形输入应拒绝且原因为 MalformedInput: %+v", malformed)
	}
}

func TestDecisionMissingFieldFailClosed(t *testing.T) {
	t.Log("业务: 字段缺失 —— 拦截规则条件字段缺失时失败关闭，不得放行")
	e := newEngine(t)
	req := podReq("req-missing", false)
	delete(req.Object["spec"].(map[string]any), "securityContext")
	d := e.Evaluate(req)
	if d.Allowed || !hasCode(d, CodeFieldMissing) {
		t.Fatalf("字段缺失应失败关闭: %+v", d)
	}
}

func TestDecisionDeterministicMerge(t *testing.T) {
	t.Log("业务: 确定顺序合并 —— 多条规则命中时结论顺序可复现")
	e := newEngine(t)
	first := e.Evaluate(podReq("req-merge", true))
	for i := 0; i < 50; i++ {
		d := e.Evaluate(podReq(fmt.Sprintf("req-merge-%d", i), true))
		if len(d.Reasons) != len(first.Reasons) {
			t.Fatalf("合并后的原因数量不稳定")
		}
		for j := range d.Reasons {
			if d.Reasons[j].Rule != first.Reasons[j].Rule || d.Reasons[j].Code != first.Reasons[j].Code {
				t.Fatalf("第 %d 次评估原因顺序不一致: %+v vs %+v", i, d.Reasons, first.Reasons)
			}
		}
	}
}

// ---------- 业务二：热更新与版本兼容 ----------

func TestLoadRejectsIncompatibleSet(t *testing.T) {
	t.Log("业务: 版本兼容 —— 结构不支持/声明冲突/内容非法的集合整体拒绝，生效版本不变")
	e := newEngine(t)

	cases := map[string]*policy.Set{
		"结构版本不支持": {APIVersion: "admission.local/v9", Version: "v2", Rules: baseSet("v2").Rules},
		"规则名声明冲突": func() *policy.Set {
			s := baseSet("v2")
			s.Rules = append(s.Rules, s.Rules[0])
			return s
		}(),
		"生效模式非法": func() *policy.Set {
			s := baseSet("v2")
			s.Rules[0].Mode = "block"
			return s
		}(),
		"条件运算符非法": func() *policy.Set {
			s := baseSet("v2")
			s.Rules[0].Conditions[0].Operator = "Like"
			return s
		}(),
	}
	for name, set := range cases {
		if err := e.Load(set); err == nil {
			t.Fatalf("用例[%s]应被拒绝", name)
		}
		if e.CurrentVersion() != "v1" {
			t.Fatalf("用例[%s]失败后生效版本应仍为 v1，实际 %s", name, e.CurrentVersion())
		}
	}
	t.Logf("4 类非法集合均被整体拒绝，生效版本保持 %s", e.CurrentVersion())
}

func TestHotUpdateAtomicAndHistoryReproducible(t *testing.T) {
	t.Log("业务: 热更新 —— 并发加载与评估时只能看到完整旧版或新版，历史版本结论可复现")
	e := newEngine(t)

	// v2 起特权判断字段改名（模拟策略演进）
	v2 := baseSet("v2")
	v2.Rules[0].Conditions[0].Field = "spec.privileged"

	req := podReq("req-hot", true)

	const versions = 20
	var wg sync.WaitGroup
	errs := make(chan error, versions*8)

	// 加载方：顺序热更新 v2..vN
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 2; i <= versions; i++ {
			set := baseSet(fmt.Sprintf("v%d", i))
			if i >= 2 {
				set.Rules[0].Conditions[0].Field = "spec.privileged"
			}
			if err := e.Load(set); err != nil {
				errs <- fmt.Errorf("加载 v%d 失败: %w", i, err)
			}
		}
	}()

	// 评估方：每次结论必须能在其声明的版本下完整复现
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				d := e.Evaluate(req)
				replay, err := e.EvaluateAt(d.Version, req)
				if err != nil {
					errs <- fmt.Errorf("版本 %s 不可查询: %w", d.Version, err)
					return
				}
				if replay.Allowed != d.Allowed || len(replay.Reasons) != len(d.Reasons) {
					errs <- fmt.Errorf("版本 %s 下结论不可复现: %+v vs %+v", d.Version, d, replay)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if got := e.CurrentVersion(); got != fmt.Sprintf("v%d", versions) {
		t.Fatalf("热更新后生效版本应为 v%d，实际 %s", versions, got)
	}
	if len(e.Versions()) != versions {
		t.Fatalf("历史版本应全部可查询，实际 %v", e.Versions())
	}
	t.Logf("并发热更新至 %s，%d 个历史版本可查询，并发评估结论全部可复现", e.CurrentVersion(), len(e.Versions()))
}

// ---------- 业务三：审计与豁免闭环 ----------

func TestExemptionGrantExpireRevoke(t *testing.T) {
	t.Log("业务: 豁免闭环 —— 生效中放行，过期/撤销立即恢复拦截")
	e := newEngine(t)

	now := time.Now()
	clock := &now
	e.Exemptions().SetClock(func() time.Time { return *clock })

	err := e.Exemptions().Grant(Exemption{
		ID:        "ex-1",
		RuleNames: []string{"deny-privileged"},
		Scope:     policy.Scope{Namespaces: []string{"default"}},
		ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("注册豁免失败: %v", err)
	}

	d := e.Evaluate(podReq("req-exempt", true))
	if !d.Allowed || !hasCode(d, CodeExempted) || len(d.ExemptedBy) != 1 {
		t.Fatalf("有效豁免应放行并标注: %+v", d)
	}

	// 过期后立即失效
	*clock = now.Add(2 * time.Hour)
	d = e.Evaluate(podReq("req-expired", true))
	if d.Allowed || !hasCode(d, CodeRuleDenied) {
		t.Fatalf("豁免过期后应恢复拦截: %+v", d)
	}

	// 未过期但撤销，立即失效
	*clock = now
	if err := e.Exemptions().Grant(Exemption{
		ID: "ex-2", RuleNames: []string{"*"},
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("注册豁免 ex-2 失败: %v", err)
	}
	e.Exemptions().Revoke("ex-2")
	d = e.Evaluate(podReq("req-revoked", true))
	if d.Allowed || !hasCode(d, CodeRuleDenied) {
		t.Fatalf("豁免撤销后应恢复拦截: %+v", d)
	}
	t.Log("豁免的放行/过期/撤销三种状态均即时反映到结论")
}

func TestConcurrentEvaluateAuditExemption(t *testing.T) {
	t.Log("业务: 并发一致性 —— 评估、审计与豁免更新并发时结论与记录不矛盾")
	e := newEngine(t)

	now := time.Now()
	clock := &now
	e.Exemptions().SetClock(func() time.Time { return *clock })

	var wg sync.WaitGroup
	errs := make(chan error, 4096)

	// 豁免更新方：周期性授权/撤销
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			id := fmt.Sprintf("ex-c-%d", i)
			_ = e.Exemptions().Grant(Exemption{
				ID: id, RuleNames: []string{"deny-privileged"},
				ExpiresAt: now.Add(time.Hour),
			})
			if i%2 == 0 {
				e.Exemptions().Revoke(id)
			}
		}
	}()

	// 评估方：特权请求（拒绝或豁免）与告警请求（放行+审计）混合
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				deny := e.Evaluate(podReq(fmt.Sprintf("deny-%d-%d", g, i), true))
				if !deny.Allowed && len(deny.ExemptedBy) > 0 {
					errs <- fmt.Errorf("矛盾: 被拒绝却标注豁免 %+v", deny)
				}
				if deny.Allowed && !hasCode(deny, CodeExempted) && hasCode(deny, CodeRuleDenied) {
					errs <- fmt.Errorf("矛盾: 放行但仍含拦截原因 %+v", deny)
				}
				warn := e.Evaluate(podReq(fmt.Sprintf("warn-%d-%d", g, i), false))
				if !warn.Allowed {
					errs <- fmt.Errorf("矛盾: warn 请求被阻塞 %+v", warn)
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	// 审计去重不变量：同一 (UID, 规则, 类别) 不得出现重复记录
	seen := map[string]int{}
	for _, rec := range e.Audit().Records() {
		key := fmt.Sprintf("%s|%s|%t", rec.RequestUID, rec.Rule, rec.Exempted)
		seen[key]++
		if seen[key] > 1 {
			t.Fatalf("审计记录重复: %+v", rec)
		}
	}
	t.Logf("并发结束：审计记录 %d 条且按 (UID,规则,类别) 全部唯一，无结论/记录矛盾", len(e.Audit().Records()))
}
