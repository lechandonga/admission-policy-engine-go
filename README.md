# admission-policy-engine-go

一套纯进程内运行的准入策略评估引擎：用内存中的资源清单与准入请求模拟真实策略校验链路，
支持策略热更新、版本兼容、审计与豁免闭环，并发场景下结论一致且可解释。不依赖任何外部服务或真实凭据。

## 模块划分

| 包 | 职责 |
| --- | --- |
| `policy` | 策略模型（策略/规则/作用范围/生效模式）与集合整体合法性校验 |
| `engine` | 评估引擎：原子热更新、版本注册、确定性规则合并、决策产出 |
| `exemption` | 豁免存储：作用范围 + 过期时间 + 撤销，并发安全 |
| `audit` | 审计记录器：按请求指纹去重，并发安全 |

## 策略模型

```go
policy.Set{
    Version: "v1",
    Policies: []policy.Policy{{
        ID:   "require-replicas",
        Mode: policy.ModeEnforce, // enforce | warn | dryrun
        Scope: policy.Scope{     // 空切片表示通配
            Kinds: []string{"Deployment"}, Namespaces: []string{"prod"}, Operations: []string{"CREATE"},
        },
        Rules: []policy.Rule{
            {ID: "r1", Field: "spec.replicas", Op: policy.OpRequired},           // 字段必须存在
            {ID: "r2", Field: "spec.image", Op: policy.OpMatches, Value: "^registry\\.internal/"},
        },
    }},
}
```

- 规则操作符：`eq` / `neq` / `in` / `required` / `matches`（正则）。
- 字段用点分路径定位（如 `spec.replicas`）；**字段缺失一律视为违规，不默认放行**。

## 决策合并与生效规则

同一请求命中的多条规则按 `(PolicyID, RuleID)` 字典序合并为唯一结论：

| 原因码 | 含义 | 是否放行 |
| --- | --- | --- |
| `ALLOWED` | 命中策略且全部通过 | 是 |
| `DENIED` | enforce 规则违规且无有效豁免 | 否 |
| `WARNED` | 仅告警命中，放行并产出审计记录 | 是 |
| `EXEMPTED` | enforce 违规被有效豁免覆盖 | 是 |
| `NO_COVERAGE` | 无任何策略覆盖该请求（fail-closed） | 否 |
| `MALFORMED_INPUT` | 请求畸形（缺 kind/operation/object 等） | 否 |
| `VERSION_UNKNOWN` | 指定的历史版本不存在 | 否 |

优先级：`DENIED` > `EXEMPTED` > `WARNED` > `ALLOWED`。
`dryrun` 模式的命中只进入 `Decision.DryRun`，不影响结论、不产生审计，也不会污染后续真实请求。

## 版本兼容与热更新

- `Engine.LoadSet` 先整体校验（结构、声明冲突、非法模式/操作符/正则、版本号重复），
  任一非法即**整体拒绝**，当前生效版本不受影响。
- 加载通过写锁串行化、以 `atomic.Pointer` 整体替换不可变视图，并发评估只会看到旧版或新版的**完整视图**。
- `Engine.Versions()` 查询全部历史版本；`Engine.EvaluateAt(req, version)` 在指定版本下评估，结论可复现。

## 审计与豁免语义

- `warn` 模式命中不阻塞请求，但写入 `audit.Recorder`；记录以
  `(请求指纹, 策略版本, 策略, 规则)` 去重，**同一请求重复评估不产生重复记录**。
- 豁免必须声明 `PolicyID`（`"*"` 表示全部）、`Scope` 与 `ExpiresAt`；
  过期或 `Revoke` 撤销后立即失效，评估时实时判定，状态变化即时反映到结论。
- 豁免仅作用于 `enforce` 模式的违规；`warn`/`dryrun` 本就不阻塞，无需豁免。

## 本地验证

```bash
go test ./... -v          # 运行全部单测，日志标注各业务与用例
CGO_ENABLED=1 go test ./... -race   # 并发场景 race 检测
```

测试覆盖：决策合并与原因码、审计去重、试算隔离、非法集合整体拒绝、
并发热更新与评估一致性、历史版本复现、豁免过期/撤销/作用范围、并发评估+审计+豁免更新一致性。
