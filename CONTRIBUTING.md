# 参与指南

感谢关注 omds-chat。本文说明参与各仓库的路径与规则;权利、署名与免责声明见 [NOTICE.md](NOTICE.md)。

## 一、入口选择

| 你想做什么 | 去哪个仓库 | 怎么开始 |
|:---:|:---:|:---|
| 使用产品或反馈问题 | [DeepSeek-Chat-Enhanced](https://github.com/omds-chat/DeepSeek-Chat-Enhanced) | 阅读 README,问题与建议提交 Issue |
| 开发插件 | [dsc-plugin-template](https://github.com/omds-chat/dsc-plugin-template) | 复制模板起步,规范在仓库 specs/ 内 |
| 提交插件收录 | [awesome-dsc-plugin](https://github.com/omds-chat/awesome-dsc-plugin) | 按 README 收录条件准备材料,提交 PR |
| 编写人性化资产包 | [dsc-humanize-asset-template](https://github.com/omds-chat/dsc-humanize-asset-template) | 复制资产模板,校验脚本随附 |
| 提交资产收录 | [awesome-dsc-humanize-asset](https://github.com/omds-chat/awesome-dsc-humanize-asset) | 按该仓库 CONTRIBUTING.md 准备材料 |

## 二、通用规则

1. **仓库自治:** 各仓库的技术决定由其维护者负责,组织提供发现与协作的空间;贡献前先读目标仓库自己的说明。
2. **收录不等于认证:** 收录与托管只说明可被找到,不构成安全、兼容或持续维护的保证。
3. **作者所有:** 你提交的内容权利仍属于你;收录即授权组织按对应许可证分发,许可证在贡献前确认。
4. **纯前端约束:** 插件与资产运行在浏览器内,不允许要求后端服务、原生模块或无法在 CI 中重建的产物。
5. **用户凭证边界:** 插件不得收集、转存或外传用户凭证与浏览器存储中的数据;违反此条的收录申请会被直接拒绝。

## 三、提交与评审

1. Issue 用途:问题反馈、收录咨询、规范讨论。PR 用途:代码、文档、收录材料。
2. 提交收录 PR 时,CI 会自动运行收录预检并把结果评论到 PR;预检通过不代表合并,维护者仍会复核内容。
3. 中文与英文文档成对维护;改中文时同步英文,反之亦然。
4. 提交信息用一行标题说明变化,正文只在需要时补充动机;不把仓库外信息写进提交。
5. 行为规范:对事不对人;评审意见聚焦内容;被拒的收录会给出理由,可修改后重新提交。

## 四、安全与凭证

发现安全问题不要开公开 Issue,按 [SECURITY.md](SECURITY.md) 的渠道报告;涉及用户凭证泄露的问题按最高优先级处理。

## 五、联系

- 组织 Owner 与联系人: JularDepick (JularDepick@gmail.com)
- 组织仓库列表: [github.com/omds-chat](https://github.com/omds-chat)
