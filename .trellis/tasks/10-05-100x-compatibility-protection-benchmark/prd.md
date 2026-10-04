# 建立 100x 兼容性与保护强度基准

## Goal

把当前 UrProtect 的兼容性与保护强度建立成可复现、可审计、由 CI 执行的量化基准：把当前实现冻结为 `1x`，由尽量少做判断的独立评估 agent 只执行 gate 评定；再把评定结果交给分析 agent，形成带局部 gate 的 Trellis 子任务，并通过持续扩充样本、benchmark、测试、fuzzing 和 CI 驱动的实现迭代，使兼容性和保护强度两个维度分别达到当前基线的 `100x`。

项目最终必须体现真实架构收益，而不是只新增名词或清单：保护器可以产生复杂的 Protected Image，通用保护壳能够理解并展开它，展开结果能够被目标原生 loader 消化；同时，发布物不应只是一个完整的、静态可直接恢复的最终 protected ELF 外加压缩层。

## Confirmed Repository Context

- 当前仓库已有 AArch64 ELF parser/validator、`PayloadFrame`、native launcher、HostContext adapter、函数保护服务、fixture manifest、real-sample corpus、benchmark 项目、回归测试、coverage fuzzing 和多层 ARM64 CI。
- 当前保护服务主要直接生成 protected ELF bytes；当前 frame 主要对 payload 做压缩、完整性校验和 launcher/dispatch 封装。
- 当前 CI 已经执行保护 E2E、real-sample matrix、runtime matrix、stress、benchmark/test 和 fuzzing，但还没有一个同时约束兼容性增长与保护强度增长的独立双维 100x gate。
- 当前兼容性文档和 manifest 详细记录了特性/证据边界；本任务必须保留既有样本、benchmark、测试、fuzz corpus 和负例，不能用扩大范围的名义删除或弱化它们。

## Requirements

### R1. 冻结并发布 1x 基线

建立一次带版本、提交、工具链、运行环境、样本清单和原始 artifact hash 的基线快照。基线至少分别包含：

- 兼容性：在固定样本集和固定 oracle 下，哪些输入能被验证、保护、展开并交给原生 loader 成功运行；失败层级和原因必须可区分。
- 保护强度：发布 artifact 中最终 native image、符号/调试信息、CFG/代码结构暴露程度，以及静态恢复和直接反汇编的客观成本。

`1x` 是冻结的测量结果，不得用事后改变分母、样本筛选或评分权重来移动基线。

### R2. 使用独立、低判断量的 evaluator gate

独立 evaluator agent 只负责执行固定协议并输出机器可读评定，不负责提出架构方案、不负责实现、不修改产品代码。评定必须引用保留的 raw evidence，至少包含：

- baseline 与当前候选的兼容性分数，以及逐攻击族的保护强度向量；
- 每个分数的分子、分母、单位、样本版本、工具版本和置信/缺失状态；
- 通过/失败/环境不可用/未测的区分；
- 防止通过减少样本、降低 oracle 强度或改变威胁模型获得虚假提升的检查结果。

评定次数应尽量少：以固定 release/CI gate 为主，不把主观 agent 讨论作为持续循环。

### R3. 将评定反馈交给独立分析 agent

分析 agent 接收 evaluator 的原始结果和差距，不直接继承 evaluator 的结论作为产品事实。它必须：

- 按兼容性和保护强度分别分析当前距离 100x 的主要原因；
- 提出可验证的优先级、实现路径、风险和回滚点；
- 为每个局部改进定义一个独立、机器可检查的 local gate；
- 把分析结果和 local gate 持久化为 Trellis 子任务要求，子任务应有独立 PRD/设计/实施/检查证据。

### R4. 建立真正体现新架构的保护产物链

实现并验证以下可观察的产物边界：

```text
Source Image
  -> Protector
  -> Protected Image ABI
  -> Generic Rehydration / Shell
  -> Native-loader-consumable Image
  -> Native loader
```

保护壳必须能够通用理解所有合法的 Protected Image ABI 输出，而不是按样本、依赖组合或单个保护 pass 建立孤立白名单。原生 loader 仍负责最终 Native Image 的依赖、重定位、TLS、构造/析构和平台运行时语义。

### R5. 兼容性必须产生实际覆盖增长

兼容性主 gate 以端到端完整单元计分：输入经过保护器生成 Protected Image，经通用展开得到 Native Image，交给目标原生 loader 后完成预期运行并通过行为 oracle。parser-only、pack-only 和 handoff-only 结果保留为分层诊断与辅助覆盖，不替代主兼容性 100x。兼容性分数必须基于预注册、分层且可追加的挑战集；独立样本身份、生产者/构建链、ELF 结构、保护变换和原生运行环境都要被记录，避免重复生成近似 fixture 虚增覆盖。固定 corpus、增量 corpus 和真实 native-loader oracle 必须证明该结果。至少要能观察到：

- 当前保护器因自身布局、重写或展开能力拒绝的输入中，有一批在新链路下成功保护、展开并运行；
- 新增外部依赖或 loader 特性不再要求为每个具体依赖组合新增 UrProtect loader 白名单条目；
- 失败仍按 parser、protection analysis、Protected Image encoding、rehydration、native handoff 和环境层次区分。

### R6. 保护强度必须产生实际提升

保护强度不是一个静态、单一的“混淆分”，而是一个持续扩充的攻击向量。评估必须由可重复的红队自动化攻击和蓝队运行时/产物防线共同组成；每个攻击族都必须保存原始输入、攻击脚本版本、工具版本、结果、耗时/资源和恢复产物。

至少建立并持续扩充以下攻击族：

- **运行时 dump 与重新组装**：尝试从运行过程取得 image/code/data，并重新构造可被原生 loader 消化的可运行 artifact；记录 dump 完整度、重组成功率、耗时、所需观测和人工步骤。
- **修补与重新打包**：尝试修改受保护逻辑、绕过完整性/版本/入口约束并重新打包；记录修改是否生效、是否被蓝队 gate 阻断、可运行性和最小修改成本。
- **函数逻辑恢复**：尝试恢复函数边界、语义、调用关系、状态机和关键常量；记录自动恢复率、误恢复率、人工介入、CPU/内存成本和时间。
- **静态拆解**：使用固定且可复现的工具链直接解析、反汇编、反混淆和 CFG 恢复；记录可见代码比例、符号/调试信息泄露、CFG 恢复质量、工具失败点和资源成本。
- **动态观察与插桩**：尝试通过 trace、断点、事件和受控 instrumentation 恢复关键路径或替换执行；记录可观测性、绕过成功率和蓝队检测/拒绝结果。
- **完整性与 handoff 攻击**：执行截断、替换、重放、版本错配、局部篡改、延迟篡改和最终 image 劫持；要求在规定边界前拒绝且保留证据。

每个攻击族都要区分：攻击成功、攻击失败、环境不可用、工具不适用和结果未知。压缩率、哈希校验或“代码看起来更复杂”单独不能作为保护强度提升证据；哈希只证明完整性，不证明抗分析能力。

保护强度报告必须是版本化向量，例如：

```text
StrengthVector = {
  runtime_dump_reassembly,
  patch_repack,
  function_logic_recovery,
  static_decomposition,
  dynamic_instrumentation,
  integrity_handoff
}
```

每个分量都冻结当前 `1x` 基线、攻击协议和原始证据。红队攻击族可以持续新增，但既有 gate、威胁模型和历史结果不能被删除或静默改写；新增攻击族必须先建立基线，再进入相应的 required gate。
### R7. 样本、benchmark、测试和 fuzzing 只能扩充不能退化

实现迭代期间：

- 新样本、负例、变形样本、benchmark、单元/集成测试和 fuzz corpus 必须追加并有 provenance；
- 既有样本和 gate 不能因不利结果被删除、降级、改名规避或移出 required tier；
- fuzzing 必须持续覆盖 Protected Image codec、rehydration、最终 Native Image 验证和现有 ELF/payload 路径；
- benchmark 必须同时追踪兼容性吞吐/成功率、展开成本、启动成本、体积和保护分析成本。

### R8. CI 是开发驱动而非发布后补验

CI 必须在候选实现进入主分支前执行：

- evaluator gate；
- 兼容性固定 corpus 和增量 corpus；
- 保护强度测量；
- benchmark regression；
- unit/integration/native runtime tests；
- fuzz smoke 和保留 crash/timeout corpus 检查；
- evidence schema、样本 provenance 和防退化检查。

门禁失败必须阻止宣称达到目标，并保留可供分析 agent 使用的 artifact。

### R9. 两个维度和保护子维度必须按明确 gate 达标

最终成功不能用兼容性和保护强度的加权平均、单一综合分或一项提升抵销另一项退化。兼容性是独立维度，按 R5 的端到端挑战单元分数相对冻结基线达到 `>=100x`；保护强度是由红队/蓝队攻击族组成的版本化向量。每个已进入 required 的保护攻击族必须有独立的基线、分数和 non-regression gate，且均须相对各自冻结基线达到 `>=100x`；任何攻击族不得回归。如果攻击族只适用于特定 profile，则仅在该 profile 的 gate 中生效。所有既有正确性、安全边界和失败关闭契约必须继续通过。

## Acceptance Criteria

- [ ] 存在带提交、工具链、环境、样本版本和 raw evidence hash 的不可变 `1x` 基线报告。
- [ ] 存在独立 evaluator 协议和机器可读 gate；evaluator 不修改产品代码且评定次数受控。
- [ ] 存在 evaluator 输出到分析 agent 的持久化交接格式，以及由分析意见和 local gate 生成的 Trellis 子任务模板/流程。
- [ ] Protected Image ABI、通用 rehydration 和 Native Image handoff 在 managed/native 两侧有一致的版本、完整性、失败和回滚契约。
- [ ] 至少一个垂直切片证明新链路同时提升真实兼容性覆盖和客观保护强度，而不是只增加封装层。
- [ ] 固定 corpus、增量样本、benchmark、测试、fuzzing 和 CI gate 均持续保留并扩充；既有 required evidence 无退化。
- [ ] 兼容性主 gate 只计完整端到端成功单元（保护 → Protected Image → 通用展开 → Native Image → 目标原生 loader → 行为 oracle），并拥有独立、可审计的 `100x` 结果；保护强度拥有逐攻击族的向量结果和明确的 `100x` gate，未达标前不得标记任务完成。
- [ ] `COMPATIBILITY.md`、manifest、用户文档和 CI 报告能区分规则、证据、运行时环境、红队/蓝队攻击结果和产品 gate，且不再把孤立样本条目当作唯一支持定义。

## Out of Scope Until Explicitly Gated

- 以统计样本通过替代原生 loader handoff 或 Protected Image ABI 的证明。
- 通过删除既有负例、降低测试 tier、减少 fuzz 预算或更换威胁模型来制造 100x。
- 在没有独立 local gate 的情况下把 evaluator 的主观建议直接当作实现完成。
- 将 HostContext 预检逐步扩展为另一个未定义边界的通用 ELF loader。
