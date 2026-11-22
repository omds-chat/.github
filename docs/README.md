# 文档索引

本文件是 `.github` 仓库全部文档的索引入口。它只说明每份文档负责什么、写到哪里、什么时候读、给谁读,不复制文档正文;具体的结论以各文档本身为准。

## 文档一览

| 文档 | 职责一句话 | 主要内容 | 什么时候需要读 | 主要读者 |
|:---:|:---:|:---:|:---:|:---:|
| [README.md](../README.md) | 仓库入口,把读者导向组织主页与权利声明 | 仓库定位、两份入口链接、版权行 | 第一次进入本仓库时 | 用户、贡献者、Agent |
| [profile/README.md](../profile/README.md) | 组织主页(简体中文) | 组织定位、开始入口、仓库矩阵、生态与角色、签名与信任、组织原则、参与方式与联系 | 想了解组织是什么、该从哪个仓库入手时 | 用户、贡献者 |
| [profile/README.en-US.md](../profile/README.en-US.md) | 组织主页的英文版本 | 与中文版逐节对应的英文表述 | 读者使用英文,或需要核对中英表述是否一致时 | 用户、贡献者 |
| [profile/NOTICE.md](../profile/NOTICE.md) | 权利、署名与免责声明(中英双语) | 非官方声明、商标与权利归属、各项目的权利、收录即托管、浏览器运行与凭证风险、许可事实、异议与联系 | 引用组织名义、分发产物、处理署名与侵权异议、评估使用风险时 | 用户、贡献者、维护者 |
| [tools/Auth-Sign/README.md](../tools/Auth-Sign/README.md) | 证书与签名工具集的完整说明 | 前置环境、算法约定、逐个脚本的用法与占位符、命名与后缀约定、使用限制、角色视角流程、常见问题(含 OpenSSH 与 PEM 互转、带口令私钥的处理) | 生成密钥与证书、签发与校验签名、在 OpenSSH 与 PEM 之间转换密钥时 | 用户、维护者、Agent |
| [tools/dev-local-npmjs/README.md](../tools/dev-local-npmjs/README.md) | 本地 npm registry 模拟器(联调用具) | 端点语义、启动方式、与各合集收录校验的配合、边界 | 离线联调 npm 包名强校验、模拟包发布与下架时序时 | 维护者、Agent |
| [public/certs/README.md](../public/certs/README.md) | 公开证书材料的查阅说明 | 证书体系列表(类型、/O、/CN、颁发者、到期时间)、两棵互不隶属的信任层级树、每个来源目录放什么与不放什么、用 openssl 校验一张证书与一条链的只读命令 | 核对产物出自哪个签名渠道、验证证书链、判断某张证书属于哪条链时 | 用户、插件与资产作者、Agent |
| [docs/essays/trust-system.md](essays/trust-system.md) | CA-EEC-Sign 信任体系的论证 | 「是什么—为什么—怎么办」:纯前端无后端形态下信任的必要性、X.509/CMS 复用与两层根域、三层清单与作者签名定位的可行性,以及发布可追溯、收录可审计、出事可撤回、用户只面对一个开关的现实意义 | 需要向他人解释或评估签名与信任体系为什么这样设计时 | 用户、贡献者、维护者 |
| [docs/essays/plugin-ecosystem.md](essays/plugin-ecosystem.md) | 宿主—内部插件—社区插件三层生态的论证 | 「是什么—为什么—怎么办」:三层各自职责、内置所有需求不可能与底线承诺、丰富度与 npm 包名一致,能力/挂载点契约与市场渠道的可行性,上架路径与统一安装体验的现实意义 | 需要向他人解释或评估插件生态为什么分层时 | 用户、贡献者、维护者 |
| [docs/essays/asset-ecosystem.md](essays/asset-ecosystem.md) | 插件—内部资产—社区资产体系的论证 | 「是什么—为什么—怎么办」:内核与资产的边界、内容生产门槛必须远低于代码、格式 1.0.0 与两合集共用格式与信任域的可行性,安装即导入不覆盖与低门槛贡献的现实意义 | 需要向他人解释或评估资产生态为什么这样组织时 | 用户、贡献者、维护者 |
| [docs/repo-spec/asset-download-capability.md](repo-spec/asset-download-capability.md) | `assets:download` 能力与「受信来源插件」层级的规范 | 「是什么—为什么—怎么办」:能力语义及与 `assets:read` 的分工、受信来源的认定、清单 `assets` 块字段草案、引擎侧下载与校验与进度取消、插件侧自存与降级,以及边界与未定项 | 设计或改动大体积资产下载、判断某插件能否申请该能力、写清单 `assets` 块时 | 维护者、Agent |
| [docs/repo-spec/extensibility.md](repo-spec/extensibility.md) | 开发期与运行期两类扩展的划分 | 两类扩展的定义与判定、各仓库逐项归类、容易混的边界、新设计的自检问题 | 设计新能力、判断某物该不该给用户运行期入口、排查"为什么改了没生效"时 | 维护者、Agent |
| [docs/repo-spec/side-branches.md](repo-spec/side-branches.md) | 旁支分支的职责与命名约定 | 术语、通用规则、四个旁支分支的职责与内容、与主干 `certs/` 的区别、各仓库使用情况、扩展流程 | 新建或改名旁支分支、判断某类内容该放哪个分支、排查流水线读不到某份数据时 | 维护者、Agent |
| [docs/README.md](README.md) | 本索引 | 文档一览、冲突时的优先级、文档分层、维护约定 | 想找某份文档,或要新增、删除、改名文档时 | 贡献者、维护者、Agent |

`LICENSE`、`COPYRIGHT` 与 `public/certs/` 下的证书文件本身是许可与信任材料,不是文档,不列入上表;[public/certs/README.md](../public/certs/README.md) 是这批材料的查阅说明,已列入上表。它们与文档的关系见下一节。

## 冲突时以谁为准

同一件事在多处出现时,按下面的顺序判断,序号靠前者优先:

| 顺序 | 依据 | 说明 |
|:---:|:---:|:---:|
| 1 | [profile/NOTICE.md](../profile/NOTICE.md)、[LICENSE](../LICENSE)、[COPYRIGHT](../COPYRIGHT) | 法律声明与许可事实。任何文档、说明或注释与之冲突,一律以声明为准 |
| 2 | `tools/Auth-Sign/tool/` 下脚本与配置文件的实际行为 | 它决定真正产出的密钥与签名。README 里的步骤、参数、文件名与脚本不一致时,以脚本为准,并在当轮修正文档 |
| 3 | [tools/Auth-Sign/README.md](../tools/Auth-Sign/README.md) 中的算法约定、命名与后缀约定、使用限制 | 解释工具集为什么这样实现、什么能做什么不能做。与脚本冲突时先按"文档过时"处理并修正文档;确认是脚本偏离约定时,改脚本并同步文档 |
| 4 | [README.md](../README.md)、[profile/README.md](../profile/README.md)、[profile/README.en-US.md](../profile/README.en-US.md) | 只描述用途、入口与组织信息,不定义技术细节;与上面三层冲突时以上面三层为准 |

本索引只负责导航,不承载结论:索引里的"职责一句话"与"主要内容"若与文档实际内容不符,以文档为准,并在当轮修正索引。

## 文档分层

| 层次 | 面向谁 | 包含文档 | 写作要求 |
|:---:|:---:|:---:|:---:|
| 对外文档 | 组织外的用户、插件作者、资产作者与贡献者 | README.md、profile/README.md、profile/README.en-US.md、profile/NOTICE.md、public/certs/README.md | 说明能做什么、从哪里进、边界与免责,不写内部实现细节 |
| 维护者文档 | 改动工具集与流程的维护者 | tools/Auth-Sign/README.md 中的算法约定、使用限制、常见问题等章节、docs/repo-spec/side-branches.md、docs/repo-spec/asset-download-capability.md | 写清取舍理由、失败路径与兼容边界,脚本与流水线改动时同轮更新 |
| Agent 执行文档 | 按步骤执行命令的自动化流程或 Agent | tools/Auth-Sign/README.md 中的命令块与占位符约定、本索引的维护约定 | 只依赖可执行的命令与明确占位符,结论以退出码与实际输出为准 |

本仓库的设计论证类文档集中在 docs/essays/(各仓库的技术口径仍以各仓库自身文档为准);目前没有独立的 Agent 专用文档。新增这类文档时,在上表登记并归入对应层次,不要混写进现有文档。

## 维护约定

- 新增、删除、改名或移动文档时,在同一次改动里更新上面的文档一览表,并核对"什么时候需要读"与"主要读者"两列。
- 机制变更(脚本参数、退出码、算法、命名约定、目录约定)当轮更新对应文档:先改 `tools/Auth-Sign/README.md` 或相应脚本的用法说明,再复核本索引的描述是否仍然成立。
- 中英成对的文档([profile/README.md](../profile/README.md) 与 [profile/README.en-US.md](../profile/README.en-US.md))内容变更需成对更新,不保留只有单侧的新结论。
- 本索引不写时间戳、不写进度、不复制正文;它只回答"有哪些文档、各自负责什么、什么时候读、给谁读"。
- 文档分层发生变化(例如某份文档从对外转为仅维护者)时,同步修改分层表与上表对应行的读者列。
- 冲突无法按上一节判断时,先按第 1 层(法律声明)处理,其余按脚本的实际行为执行,并在同一次改动中把差异记入相应文档。
