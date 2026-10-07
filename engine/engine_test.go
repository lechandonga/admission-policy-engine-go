package engine_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/admission-policy-engine-go/audit"
	"github.com/lechandonga/admission-policy-engine-go/engine"
	"github.com/lechandonga/admission-policy-engine-go/exemption"
	"github.com/lechandonga/admission-policy-engine-go/policy"
)

func setV1() *policy.Set {
	return &policy.Set{
		Version: "v1",
		Policies: []policy.Policy{
			{
				ID:    "require-replicas",
				Mode:  policy.ModeEnforce,
				Scope: policy.Scope{Kinds: []string{"Deployment"}},
				Rules: []policy.Rule{
					{ID: "r1", Field: "spec.replicas", Op: policy.OpRequired},
				},
			},
			{
				ID:    "image-registry",
				Mode:  policy.ModeWarn,
				Scope: policy.Scope{Kinds: []string{"Deployment"}},
				Rules: []policy.Rule{
					{ID: "r1", Field: "spec.image", Op: policy.OpMatches, Value: "^registry\\.internal/"},
				},
			},
		},
	}
}

func setV2() *policy.Set {
	return &policy.Set{
		Version: "v2",
		Policies: []policy.Policy{
			{
				ID:    "require-replicas",
				Mode:  policy.ModeEnforce,
				Scope: policy.Scope{Kinds: []string{"Deployment"}},
				Rules: []policy.Rule{
					{ID: "r1", Field: "spec.replicas", Op: policy.OpEq, Value: 3},
				},
			},
		},
	}
}

func deployReq(replicas any) *engine.Request {
	obj := map[string]any{"spec": map[string]any{"image": "registry.internal/app:1.0"}}
	if replicas != nil {
		obj["spec"].(map[string]any)["replicas"] = replicas
	}
	return &engine.Request{Kind: "Deployment", Namespace: "prod", Name: "app", Operation: "CREATE", Object: obj}
}

func newEngine(t *testing.T, opts ...engine.Option) (*engine.Engine, *exemption.Store, *audit.Recorder) {
	t.Helper()
	ex := exemption.NewStore()
	rec := audit.NewRecorder()
	e := engine.New(ex, rec, opts...)
	if err := e.LoadSet(setV1()); err != nil {
		t.Fatalf("load v1: %v", err)
	}
	return e, ex, rec
}

func TestDecisionMergingAndReasons(t *testing.T) {
	t.Log("业务: 准入决策合并 —— enforce 拒绝 / warn 放行+审计 / 无覆盖拒绝 / 畸形输入拒绝")
	e, _, rec := newEngine(t)

	d := e.Evaluate(deployReq(nil))
	if d.Allowed || d.Reason != engine.ReasonDenied {
		t.Fatalf("missing replicas: got %+v, want DENIED", d)
	}
	t.Logf("用例[缺失必填字段拒绝]: reason=%s violations=%v", d.Reason, d.Violations)

	d = e.Evaluate(deployReq(2))
	if !d.Allowed || d.Reason != engine.ReasonAllowed {
		t.Fatalf("valid request: got %+v, want ALLOWED", d)
	}
	t.Logf("用例[合规请求放行]: reason=%s", d.Reason)

	bad := deployReq(2)
	bad.Object["spec"].(map[string]any)["image"] = "docker.io/app:latest"
	d = e.Evaluate(bad)
	if !d.Allowed || d.Reason != engine.ReasonWarned {
		t.Fatalf("warn hit: got %+v, want WARNED+allowed", d)
	}
	if rec.Len() != 1 {
		t.Fatalf("warn should produce 1 audit record, got %d", rec.Len())
	}
	t.Logf("用例[仅告警放行并审计]: reason=%s audit=%d", d.Reason, rec.Len())

	uncovered := &engine.Request{Kind: "ConfigMap", Namespace: "prod", Name: "cm", Operation: "CREATE", Object: map[string]any{}}
	if d = e.Evaluate(uncovered); d.Allowed || d.Reason != engine.ReasonNoCoverage {
		t.Fatalf("uncovered: got %+v, want NO_COVERAGE", d)
	}
	t.Logf("用例[策略未覆盖拒绝]: reason=%s", d.Reason)

	for i, malformed := range []*engine.Request{
		nil,
		{Kind: "", Operation: "CREATE", Object: map[string]any{}},
		{Kind: "Pod", Operation: "", Object: map[string]any{}},
		{Kind: "Pod", Operation: "CREATE", Object: nil},
	} {
		if d = e.Evaluate(malformed); d.Allowed || d.Reason != engine.ReasonMalformed {
			t.Fatalf("malformed #%d: got %+v, want MALFORMED_INPUT", i, d)
		}
	}
	t.Log("用例[畸形输入拒绝]: 4 个子用例全部拒绝")
}

func TestAuditDeduplication(t *testing.T) {
	t.Log("业务: 审计闭环 —— 同一请求重复评估不产生重复记录")
	e, _, rec := newEngine(t)
	bad := deployReq(2)
	bad.Object["spec"].(map[string]any)["image"] = "evil.io/x:1"
	for i := 0; i < 5; i++ {
		if d := e.Evaluate(bad); d.Reason != engine.ReasonWarned {
			t.Fatalf("eval #%d: %+v", i, d)
		}
	}
	if rec.Len() != 1 {
		t.Fatalf("duplicate evaluations produced %d records, want 1", rec.Len())
	}
	t.Logf("用例[重复评估去重]: 5 次评估 -> %d 条审计", rec.Len())
}

func TestDryRunIsolation(t *testing.T) {
	t.Log("业务: 试算模式 —— 试算命中不影响真实请求结论")
	ex, rec := exemption.NewStore(), audit.NewRecorder()
	e := engine.New(ex, rec)
	dry := &policy.Set{
		Version: "v1",
		Policies: []policy.Policy{{
			ID:    "dry-only",
			Mode:  policy.ModeDryRun,
			Scope: policy.Scope{Kinds: []string{"Deployment"}},
			Rules: []policy.Rule{{ID: "r1", Field: "spec.replicas", Op: policy.OpEq, Value: 3}},
		}},
	}
	if err := e.LoadSet(dry); err != nil {
		t.Fatal(err)
	}
	d := e.Evaluate(deployReq(2))
	if !d.Allowed || d.Reason != engine.ReasonAllowed || len(d.DryRun) != 1 {
		t.Fatalf("dryrun hit must not block: %+v", d)
	}
	if rec.Len() != 0 {
		t.Fatalf("dryrun must not produce audit records, got %d", rec.Len())
	}
	t.Logf("用例[试算不阻塞]: allowed=%v dryrun_hits=%d audit=%d", d.Allowed, len(d.DryRun), rec.Len())
}

func TestIncompatibleSetRejected(t *testing.T) {
	t.Log("业务: 版本兼容 —— 非法/冲突集合整体拒绝且不影响当前版本")
	e, _, _ := newEngine(t)
	cases := map[string]*policy.Set{
		"空版本号":   {Version: "", Policies: setV1().Policies},
		"空策略集合":  {Version: "v2"},
		"重复策略ID": {Version: "v2", Policies: []policy.Policy{setV1().Policies[0], setV1().Policies[0]}},
		"非法模式": {Version: "v2", Policies: []policy.Policy{{
			ID: "p", Mode: "block", Rules: []policy.Rule{{ID: "r", Field: "a", Op: policy.OpEq}},
		}}},
		"非法操作符": {Version: "v2", Policies: []policy.Policy{{
			ID: "p", Mode: policy.ModeEnforce, Rules: []policy.Rule{{ID: "r", Field: "a", Op: "contains"}},
		}}},
		"非法正则": {Version: "v2", Policies: []policy.Policy{{
			ID: "p", Mode: policy.ModeEnforce, Rules: []policy.Rule{{ID: "r", Field: "a", Op: policy.OpMatches, Value: "([["}},
		}}},
		"重复版本号": setV1(),
	}
	for name, bad := range cases {
		if err := e.LoadSet(bad); err == nil {
			t.Fatalf("case %q: expected rejection", name)
		} else {
			t.Logf("用例[%s]: 已拒绝 (%v)", name, err)
		}
	}
	if got := e.CurrentVersion(); got != "v1" {
		t.Fatalf("current version changed to %q after rejections", got)
	}
	d := e.Evaluate(deployReq(2))
	if !d.Allowed {
		t.Fatalf("current version must stay effective after rejections: %+v", d)
	}
	t.Log("用例[拒绝后当前版本不受影响]: 通过")
}

func TestConcurrentReloadAndEvaluate(t *testing.T) {
	t.Log("业务: 热更新 —— 并发评估只能看到旧版或新版的完整视图")
	e, _, _ := newEngine(t)
	const workers = 16
	const rounds = 200
	var wg sync.WaitGroup
	errCh := make(chan string, workers*rounds)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				d := e.Evaluate(deployReq(3))
				// 所有版本下 replicas=3 均合规；任何版本视图都必须给出一致放行结论。
				if d.Version == "" || !d.Allowed || len(d.Violations) != 0 {
					errCh <- fmt.Sprintf("inconsistent view: %+v", d)
				}
			}
		}(w)
	}
	// 交替热更新 v2/v3/v4...，每个版本都要求 replicas==3。
	for i := 2; i < 12; i++ {
		s := setV2()
		s.Version = fmt.Sprintf("v%d", i)
		if err := e.LoadSet(s); err != nil {
			t.Fatalf("load %s: %v", s.Version, err)
		}
	}
	wg.Wait()
	close(errCh)
	for msg := range errCh {
		t.Fatal(msg)
	}
	t.Logf("用例[并发热更新+评估]: %d workers x %d rounds, 视图始终一致", workers, rounds)

	// 历史版本可查询且结论可复现。
	versions := e.Versions()
	if len(versions) != 11 {
		t.Fatalf("versions=%v, want 11 entries", versions)
	}
	d1 := e.EvaluateAt(deployReq(2), "v2")
	d2 := e.EvaluateAt(deployReq(2), "v2")
	if d1.Allowed != d2.Allowed || d1.Reason != d2.Reason {
		t.Fatalf("EvaluateAt not reproducible: %+v vs %+v", d1, d2)
	}
	if d1.Allowed || d1.Reason != engine.ReasonDenied {
		t.Fatalf("v2 requires replicas==3, replicas=2 must be denied: %+v", d1)
	}
	if d := e.EvaluateAt(deployReq(2), "v1"); !d.Allowed {
		t.Fatalf("v1 only requires replicas present, replicas=2 must be allowed: %+v", d)
	}
	if d := e.EvaluateAt(deployReq(2), "v999"); d.Reason != engine.ReasonVersionUnknown {
		t.Fatalf("unknown version: %+v", d)
	}
	t.Logf("用例[历史版本查询与复现]: versions=%d, 结论可复现", len(versions))
}

func TestExemptionExpiryAndRevoke(t *testing.T) {
	t.Log("业务: 豁免闭环 —— 过期/撤销立即失效，状态变化即时反映到结论")
	now := time.Now()
	clock := &now
	e, ex, _ := newEngine(t, engine.WithClock(func() time.Time { return *clock }))

	req := deployReq(nil) // 缺 replicas，v1 enforce 拒绝
	if err := ex.Add(exemption.Exemption{
		ID: "ex-1", PolicyID: "require-replicas",
		Scope:     policy.Scope{Kinds: []string{"Deployment"}, Namespaces: []string{"prod"}},
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(req); !d.Allowed || d.Reason != engine.ReasonExempted {
		t.Fatalf("active exemption should allow: %+v", d)
	}
	t.Log("用例[有效豁免放行]: 通过")

	*clock = now.Add(2 * time.Hour) // 过期
	if d := e.Evaluate(req); d.Allowed || d.Reason != engine.ReasonDenied {
		t.Fatalf("expired exemption must not apply: %+v", d)
	}
	t.Log("用例[过期豁免失效]: 通过")

	*clock = now // 回到有效期内
	if err := ex.Revoke("ex-1"); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(req); d.Allowed || d.Reason != engine.ReasonDenied {
		t.Fatalf("revoked exemption must not apply: %+v", d)
	}
	t.Log("用例[撤销豁免立即失效]: 通过")

	// 作用范围不匹配的豁免不生效。
	if err := ex.Add(exemption.Exemption{
		ID: "ex-2", PolicyID: "require-replicas",
		Scope:     policy.Scope{Namespaces: []string{"staging"}},
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(req); d.Allowed {
		t.Fatalf("out-of-scope exemption must not apply: %+v", d)
	}
	t.Log("用例[作用范围外豁免不生效]: 通过")
}

func TestConcurrentExemptionAuditConsistency(t *testing.T) {
	t.Log("业务: 并发一致性 —— 评估/审计/豁免更新同时进行时结论与记录不矛盾")
	e, ex, rec := newEngine(t)
	bad := deployReq(2)
	bad.Object["spec"].(map[string]any)["image"] = "evil.io/x:1"

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				d := e.Evaluate(bad)
				if d.Reason != engine.ReasonWarned || !d.Allowed {
					t.Errorf("unexpected decision: %+v", d)
					return
				}
			}
		}(i)
	}
	// 并发添加/撤销豁免（warn 模式不受豁免影响，但存储需并发安全）。
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("ex-%d", i)
			_ = ex.Add(exemption.Exemption{
				ID: id, PolicyID: "*",
				Scope:     policy.Scope{Kinds: []string{"Deployment"}},
				ExpiresAt: time.Now().Add(time.Minute),
			})
			_ = ex.Revoke(id)
		}(i)
	}
	wg.Wait()
	if rec.Len() != 1 {
		t.Fatalf("concurrent duplicate evaluations must yield 1 audit record, got %d", rec.Len())
	}
	t.Logf("用例[并发评估审计去重]: audit=%d, 结论一致", rec.Len())
}
