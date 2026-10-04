# 冻结 1x 基线并建立独立 evaluator gate

## Goal

建立一个只读、低判断量、机器可检查的 evaluator，冻结当前 UrProtect checkout 的兼容性与 Scheme-A 测量协议，并输出可供后续 analysis agent 消费的 `gate.json` 与 `analysis-input.json`。

## Requirements

- 兼容性只计完整端到端单元：Protector → Protected Image → rehydration → Native Image → target native loader → frozen behavioral oracle。
- 当前没有 Protected Image/rehydration 产品阶段时，输出 `baseline-zero`/`not-ready`，不伪造正分母。
- Scheme A 使用六个版本化攻击族；每个 required 族使用三次 replica、固定工具/seed/budget/oracle，并独立计算成本因子。
- 没有三次有限、可复现的 baseline attack success 时输出 `baseline-not-calibrated`。
- 评估器验证 corpus、protocol、baseline、工具、环境、raw evidence、哈希、路径和 anti-gaming invariants。
- evaluator 不修改源代码、产品配置、manifest、任务状态或冻结 baseline，只写自己的 evidence tree。
- 保留现有 fixture、real-sample、benchmark、test、fuzz、runtime 和 CI 证据；新 evaluator 只增加独立 gate。

## Acceptance Criteria

- [ ] 存在兼容性 corpus、Scheme-A manifest、oracle/protocol schema 和不可变 baseline reference。
- [ ] evaluator 能生成完整的 `environment.json`、`protocol.json`、`baseline-reference.json`、逐单元/逐攻击记录、`gate.json`、`analysis-input.json` 和闭合 `SHA256SUMS`。
- [ ] 当前 checkout 的严格链路状态为 `baseline-zero`/`not-ready`，而不是把既有 wrapper 或 direct protected ELF 计为 strict unit。
- [ ] 缺失工具、native capability、raw evidence、required row、manifest digest 或 anti-gaming 条件时，结果明确失败或 environment-unavailable 并保留证据。
- [ ] compatibility fixed/growth view、distinct identity、防重复计数和 Scheme-A 每族 `>=100x` conjunction 有自动化测试。
- [ ] existing CI contracts remain green and evaluator artifacts upload on pass/failure.

## Out of Scope

- Protected Image ABI、rehydrator 或保护器 materializer 的实现。
- 任何新的 loader 语义或保护算法。
- 以 prose 结论替代机器 gate。
