# 分析 evaluator 结果并定义 Protected Image local gate

## Goal

消费父任务冻结的独立 evaluator 结果，客观分析当前首个失败层级和 Scheme-A 未校准原因，定义下一实施切片的局部 gate，并把它转化为可执行的 Protected Image ABI/rehydration 子任务输入。

## Requirements

- 以 `.artifacts/evaluator/pr/gate.json` 和 `analysis-input.json` 为唯一规范测量输入；保留 `baseline-zero`、`baseline-not-calibrated` 和 environment-unavailable 语义。
- 不重新解释 evaluator 分数，不删除 required corpus/family，不改变 100x 协议、威胁模型、oracle、样本分母或基线。
- 分析 `protector` 首失败、缺失 Protected Image/rehydration/native-loader stage、现有保护器布局约束和 Scheme-A 工具缺口。
- 给出 Protected Image ABI v1、通用 rehydration、Native Image handoff 的最小可验证 local gate，以及后续 Scheme-A calibration gate。
- 明确哪些工作是当前切片范围、哪些需要后续子任务；给出风险、回滚点、CI/benchmark/test/fuzz 增量要求。
- 不修改产品代码；输出持久化分析报告和下一实施子任务建议。

## Acceptance Criteria

- [ ] 报告绑定 evaluator gate、analysis-input、baseline、protocol 和 commit/artifact hashes。
- [ ] 报告明确结论：当前 strict compatibility 为 baseline-zero，首失败为 protector/缺失 Protected Image stage，Scheme-A 为 baseline-not-calibrated。
- [ ] 定义 `protected-image-emission-v1`、`rehydration-native-handoff-v1` 和 `scheme-a-baseline-calibration-v1` 的机器可检查输入、输出、失败条件和证据路径。
- [ ] 给出下一实现子任务的 PRD 范围、设计边界、验证命令、回滚策略和 CI 接入点。
- [ ] 分析文件通过 Trellis context validation；不包含未经证据支持的兼容性或强度宣称。

## Out of Scope

- Protected Image、rehydrator、materializer、攻击工具或 native loader 的实现。
- 修改 evaluator 协议、基线、样本分母、CI gate 语义或现有产品代码。
