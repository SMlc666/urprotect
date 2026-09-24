# 建立公开真实 AArch64 样本 CI 语料库

## Goal

为 20 个彼此不同的公开真实 AArch64 软件项目建立隔离、可审计、CI 驱动的兼容性回归流程，并把后续 ELF/包装/runtime 兼容性开发绑定到真实样本证据。

本任务的目标不是把 20 个二进制放进开发者工作树，而是把公开来源、精确版本、哈希、样本属性和预期结果登记在仓库中，在隔离的 ARM64 CI 中按需获取和运行样本。本机开发流程默认只处理 manifest、静态计划、源码 fixture 和报告契约，不获取或启动真实样本。

## Background and confirmed repository facts

- `fixtures/manifest.json` 当前维护受控 feature/case 矩阵；现有 cases 主要由仓库源码和固定工具链构建，不等同于真实软件生态语料库。
- `scripts/run-fixture-matrix.sh` 要求 AArch64 runner，并已经为 glibc、musl、bionic 和多个语言/工具链保留分层证据。
- `.github/workflows/ci.yml` 已有 ARM64 native runner、bionic 容器、scheduled/release tier、artifact 上传和 `scripts/check-evidence.py` 证据门禁，可作为真实样本 CI 的基础。
- 当前兼容性 contract 要求区分 parser/model、outer wrapper、HostContext 和 runtime-specific evidence；loader 偶然接受某个 ELF 特征不自动形成产品支持声明。
- 当前产品处于 0.x 阶段，兼容性 contract、report、fixture schema 和 CI 选择逻辑可以进行一致的 breaking change，但跨层契约必须同步更新所有 producer、consumer、test、文档和证据。

## Product decisions

1. **20 个样本按项目名计数。** 同一个上游项目的 glibc、musl、bionic 或不同构建版本属于同一个样本的对照属性，不得用来增加样本数量。
2. **只使用公开来源。** 不引入私有样本作为正式 corpus；候选来源必须有公开 URL、版本/tag/commit 或发行包标识、归档/文件 SHA-256、内部路径和可审计的再分发信息。
3. **样本二进制不进入开发者工作树。** 仓库提交公开样本 registry 和筛选规则；CI 在 runner 临时目录下载、校验、运行和销毁样本，生成的结果进入 CI artifact。
4. **真实样本发现问题，contract 决定声明。** 真实样本用于发现特征、验证生态分布和锁定回归；新增支持仍需要明确不变量、受控正向 fixture、最近邻负向边界和适用层级的 oracle。
5. **执行只发生在隔离 CI。** 真实样本默认在临时 ARM64 runner 的隔离执行环境中运行；执行阶段关闭网络，限制权限、进程数、CPU、内存、文件系统写入和时间，并记录隔离环境事实。静态采集和执行结果必须区分。
6. **未来兼容性任务采用 CI-first。** 影响 ELF parser/validator、pack、launcher、native runtime、fixture contract 或 compatibility evidence 的任务，必须在计划阶段声明受影响的真实样本、CI tier、oracle 和证据路径；本机通过不代表兼容性任务完成。
7. **每个 PR 全量执行 20 样本套件。** 不按文件路径、标签或受影响样本分析缩减 PR 样本集合；全量 PR 成本由用户接受。Nightly/release 可以增加重复次数、环境覆盖或证据保留强度，但不得替代 PR 全量 required gate。

## Requirements

### R1 — Public sample registry

- 新增独立的真实样本 registry，不改变现有 `fixtures/manifest.json` 的 feature contract 语义。
- 每个样本记录唯一项目名、公开来源、精确版本、归档和/或解压文件 SHA-256、内部文件路径、许可证/再分发信息、目标架构、运行时/loader、样本类型和获取方式。
- registry 同时记录预期层级结果：静态 validator、outer wrapper、HostContext；`not-applicable`、预期拒绝、环境缺失和实际失败必须有不同状态。
- registry 允许同一项目挂载 runtime/build 对照变体，但变体不能产生新的样本计数。

### R2 — Candidate discovery and final 20 selection

- 候选筛选先从公开发行包、官方 release asset 或可复现的公开构建中收集候选，不先凭程序名冻结名单。
- 候选扫描至少提取 ELF class/data/machine/type、interpreter、PT_LOAD 布局、DT_NEEDED、RELA/RELR/PLT relocation、symbol version、TLS、GNU property、RELRO、GNU_STACK、stripped 状态和文件大小。
- 最终 corpus 恰好包含 20 个不同项目，并同时覆盖真实 producer、glibc/musl/bionic 生态、复杂依赖、常见 hardening、不同语言/运行时和明确的 rejected/deferred 边界。
- 选择报告必须说明每个项目为何入选、覆盖了哪些 feature、与其他样本的差异，以及被淘汰候选的重复或缺口原因。

### R3 — CI-only acquisition and execution

- 本机命令不得以默认路径下载或启动真实样本；本机只可验证 registry、生成候选计划、检查 schema 和运行不依赖真实样本的 contract tests。
- CI job 在固定的 AArch64 runner 上运行，先校验来源/版本/归档 hash，再从临时目录提取样本。
- 真实样本执行使用明确的隔离策略：无网络、最小权限、只读或临时文件系统、资源/时间上限和失败后清理；动态 loader、依赖库和 rootfs 也必须有固定来源与 hash。
- 静态分析默认覆盖全部 20 个项目；运行原始程序、outer packed 程序或 HostContext image 由样本 policy 显式选择。
- 所有样本都必须在执行前经过 ELF/UrProtect 静态报告采集；执行失败不得被记录为“跳过”或整体 CI 成功。
- 每一个 pull request 都必须运行并通过完整的 20 样本 suite，包含各样本 policy 声明的全部适用 oracle；不得按 diff 路径、标签或受影响样本选择缩减集合。
- PR job 的样本集合、来源 hash、隔离约束和关键 oracle 必须与 nightly/release 共用同一 registry 和 runner 实现，避免不同 tier 出现不同语义。

### R4 — Layered oracle and evidence

- 每个样本输出 normalized metadata、原始 `readelf`/等价工具报告、UrProtect JSON report、诊断码、baseline/packed 状态、stdout/stderr、信号/退出状态和环境记录（适用时）。
- 结果至少区分 `accepted-and-runs`、`expected-rejected`、`unexpected-rejection`、`unexpected-acceptance`、`runtime-failure`、`environment-unavailable` 和 `not-applicable`。
- outer wrapper 样本需要比较 baseline 与 packed 的可观察行为；HostContext 只对满足声明入口和 ABI contract 的样本执行，不把普通 shared object 自动当作 HostContext image。
- 生成的证据放在 `.artifacts/real-samples/<tier>/<sample-id>/` 或等价的 CI artifact 根下，并由证据脚本验证非空、来源和 schema。
- 报告提供按项目、producer、runtime、feature 和结果状态的聚合，明确列出首次出现的 ELF 特征和当前边界外最常见的样本。

### R5 — CI-first compatibility development contract

- 对 parser/validator、pack、launcher、native runtime、fixture schema 或 compatibility docs 的改动，PR 计划必须列出影响的真实样本和对应 oracle。
- 新增支持前必须同时拥有：真实样本观察、受控正向 fixture、最近邻负向 fixture、稳定诊断/结果和文档中的支持边界。
- 新增拒绝边界前必须证明拒绝发生在 loader handoff 或执行副作用之前，并将真实样本作为稳定 rejection regression。
- 样本结果出现 unexpected rejection/acceptance 时，相关兼容性任务保持未完成，直到结果被分类、修复或明确写入 contract。
- synthetic fixture matrix、real sample corpus 和 runtime-specific evidence 必须在报告中分层，不得用样本数量替代 feature 语义证明。

## Out of scope

- 在本机启动、调试或长期保存这 20 个真实样本二进制。
- 引入私有、不可审计来源或没有稳定 hash/provenance 的样本作为正式 corpus。
- 用同一项目的不同 libc、发行版或版本重复计算 20 个样本。
- 通过真实样本结果自动扩大 ELF/HostContext 支持范围。
- 本任务内实现新的 relocation、dependency、TLS、GNU property 或加密/代码变换能力；这些属于后续由 corpus 结果驱动的独立兼容性任务。
- 宣称通用 Android 设备、OEM、SELinux、物理设备或任意 ARM64 用户空间兼容性。

## Acceptance Criteria

- [x] 仓库包含独立的公开样本 registry、schema validator 和候选扫描/筛选工具；registry 不包含需要开发者本机执行的真实样本二进制。
- [x] 候选筛选报告冻结恰好 20 个不同上游项目，并给出每个样本的公开 provenance、精确版本、hash、目标运行时、feature fingerprint、入选理由和预期层级结果。
- [x] CI 能在固定 AArch64 runner 上下载并验证样本，且本机默认路径不会下载或启动真实样本。
- [x] 每个 PR 的 required gate 对全部 20 个样本完成静态分析，并对 policy 允许的样本完成隔离的 baseline/pack 或 HostContext oracle；不因 diff 路径、标签或 affected-sample 选择缩减集合。
- [x] Nightly 和 release 重用同一份 20 样本 registry 与 oracle contract；额外 tier 只增加重复/环境/证据强度，不将 PR 全量 gate 降级为局部样本测试。
- [x] 真实样本执行阶段具有可审计的网络关闭、权限、资源、文件系统和清理证据；执行失败、环境缺失和预期拒绝不会被混为成功。
- [x] CI 产出逐样本证据和聚合覆盖报告，`check-evidence.py` 或等价门禁能验证其完整性。
- [x] 至少有一个后续兼容性变更流程示例证明：计划声明受影响样本，CI 产生结果，unexpected outcome 阻断完成，contract/fixture/docs/evidence 同步后才可通过。
- [x] 项目 spec 或 workflow 文档记录 CI-first 兼容性开发规则，并明确 PR、nightly、release 三类 tier 的职责。

## CI tier contract

- **PR:** required full run for all 20 unique projects: provenance/hash verification, static fingerprint, UrProtect validation, and every sample-policy-applicable isolated baseline/outer-pack/HostContext oracle. Any unexpected result or missing evidence fails the gate.
- **Nightly:** rerun the same locked 20-project corpus and may add repeat/stability runs or additional approved runtime environments. This adds signal and does not replace PR coverage.
- **Release:** rerun the same locked corpus and retain release-grade provenance, environment, per-sample, and aggregate artifacts. This adds a release gate.
- A sample not applicable to an execution layer receives an explicit `not-applicable` result with a reason; it is never silently omitted.
