# admission-policy-engine-go

一套纯进程内运行的准入策略评估引擎：用内存中的资源清单与准入请求模拟真实策略校验链路，
覆盖策略加载与决策、原子热更新与版本兼容、审计与豁免闭环，全程不依赖外部服务或真实凭据。

## 工程结构

```
policy/   策略集合数据模型、作用范围/生效模式定义、加载前整体校验
engine/   评估引擎：版本化存储与原子切换、确定性规则合并、审计记录器、豁免注册表
```

对外接口入口：

- `engine.New(set)` / `(*Engine).Load(set)`：加载初始集合 / 热更新
- `(*Engine).Evaluate(req)` / `EvaluateAt(version, req)`：按当前版 / 指定历史版评估
- `(*Engine).Exemptions()`：豁免注册（`Grant` / `Revoke`）
- `(*Engine).Audit()`：审计记录查询

## 策略模型

策略集合（`policy.Set`）是不可变的版本单元：

```json
{
  "apiVersion": "admission.local/v1",
  "version": "v1",
  "rules": [
    {
      "name": "deny-privileged",
      "mode": "enforce",
      "scope": {"namespaces": ["default"], "resources": ["pods"], "operations": ["CREATE"]},
      "conditions": [{"field": "spec.securityContext.privileged", "operator": "Equals", "value": "true"}],
      "message": "禁止特权容器"
    }
  ]
}
```

- **作用范围 Scope**：`namespaces` / `resources` / `operations` 三个维度，空表示全部，
  支持 `*` 通配；同维度内为“或”，跨维度为“与”。
- **生效模式 Mode**：
  - `enforce` 拦截：命中即拒绝；
  - `warn` 仅告警：不阻塞请求，但产出可追溯的审计记录；
  - `dryrun` 试算：只写入结论的 `DryRun` 列表，不影响放行、不构成“覆盖”、不产生审计。
- **条件 Condition**：`field` 为资源清单上的点分路径（另支持内置字段
  `namespace` / `resource` / `operation`），运算符支持
  `Equals` / `NotEquals` / `In` / `Exists` / `Missing` / `Match`（正则）。

### 结论合并与失败关闭

同一请求命中的多条规则按确定顺序合并：**拦截 > 告警 > 试算，同模式按规则名字典序**，
因此同一输入的结论可复现。以下情况一律不默认放行，且原因码可区分：

| 场景 | 原因码 |
| --- | --- |
| 请求结构非法（缺 UID/对象等） | `MalformedInput` |
| 无任何非试算规则覆盖 | `NoPolicyCoverage` |
| 条件字段缺失 | `FieldMissing` |
| 拦截规则命中 | `RuleDenied` |
| 告警规则命中（不阻塞） | `RuleWarned` |
| 拦截被豁免放行 | `Exempted` |

## 版本兼容与热更新

- 加载前对集合做**整体校验**：`apiVersion` 不支持、规则名重复（声明冲突）、
  模式/运算符非法、条件缺值、正则不可编译等任一问题都会让**整个集合被拒绝**，
  当前生效版本不受任何影响。
- 校验通过后通过原子指针切换生效版本；并发评估只会看到**旧版或新版的完整视图**，
  不存在半更新状态。版本号不可重复加载，历史版本全部保留。
- `Versions()` 查询历史版本，`EvaluateAt(version, req)` 在指定版本下复现结论。

## 审计与豁免语义

- **审计**：`warn` 命中与被豁免的拦截都会产出 `AuditRecord`
  （含请求 UID、策略版本、规则、是否豁免）。同一请求 UID 的重复评估按
  `(UID, 规则, 类别)` 去重，不会产生重复记录。
- **豁免**：必须携带作用范围（规则名列表 + Scope）与过期时间，缺一不可。
  过期或调用 `Revoke` 撤销后立即失效，下一次评估即恢复拦截。
  豁免只抵消拦截类原因（`RuleDenied` / `FieldMissing`），并在结论中标注
  `ExemptedBy` 与 `Exempted` 原因，保证结论与审计记录一致。

## 并发一致性

- 生效版本用 `atomic.Pointer` 发布，评估全程只读快照，无需加锁；
- 豁免注册表与审计记录器各自内置互斥锁，授权/撤销/过期判断与评估并发安全；
- 结论中的豁免标注与审计记录在同一次评估内生成，不会互相矛盾。

## 本地验证

```bash
go build ./...
go test -v ./...          # 日志按业务分组，可见各链路用例与结果
CGO_ENABLED=1 go test -race ./...   # 并发竞态检测
```

测试覆盖：拦截/告警/试算合并、失败关闭（未覆盖/字段缺失/畸形输入）、
非法集合整体拒绝、并发热更新与历史版本复现、豁免过期与撤销、
审计去重、并发评估+审计+豁免更新的一致性。
