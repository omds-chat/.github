<div align="center">

# omds-chat

**简体中文** · [English](README.en-US.md)

纯前端静态页面 · 无后端 · 插件化扩展

[主线仓库](https://github.com/omds-chat/DeepSeek-Chat-Enhanced) · [插件开发模板](https://github.com/omds-chat/dsc-plugin-template) · [同源插件仓库](https://github.com/omds-chat/dsc-inner-plugin) · [人性化插件](https://github.com/omds-chat/dsc-humanize)

</div>

一个主要服务于DeepSeek生态的开源社区组织，致力于通过二次开发，为终端用户打造更多易于使用的AI产品，以助力推进“AI普惠全人类”这一愿景的最后一公里。

---

## 从这里开始

| 我想…… | 入口 |
|:---:|:---:|
| 了解主线产品做了什么 | **[主线仓库说明](https://github.com/omds-chat/DeepSeek-Chat-Enhanced/blob/main/README.md)** · [English](https://github.com/omds-chat/DeepSeek-Chat-Enhanced/blob/main/README.en-US.md) |
| 获取可用的静态包 | **[主线仓库 Releases](https://github.com/omds-chat/DeepSeek-Chat-Enhanced/releases)** |
| 开发一个插件 | **[插件开发模板](https://github.com/omds-chat/dsc-plugin-template)** |
| 浏览插件索引与收录范围 | **[社区精选插件合集](https://github.com/omds-chat/awesome-dsc-plugin)** · [同源插件索引仓库](https://github.com/omds-chat/dsc-inner-plugin) |
| 反馈问题或申请收录 | **[社区精选插件合集](https://github.com/omds-chat/awesome-dsc-plugin)** · [组织仓库](https://github.com/omds-chat) |

## 仓库矩阵

| 仓库 | 能做什么 |
|:---:|:---:|
| **[DeepSeek-Chat-Enhanced](https://github.com/omds-chat/DeepSeek-Chat-Enhanced)** | 解压即用的社区增强聊天网页,基于官方 deepseek-ai/chat-demo 增强 |
| **[omds-chat.github.io](https://github.com/omds-chat/omds-chat.github.io)** | 组织站点的在线入口,可由此进入主线的在线页面 |
| **[dsc-plugin-template](https://github.com/omds-chat/dsc-plugin-template)** | 插件开发模板,提供示例与起步骨架,帮你快速写出可用的插件 |
| **[dsc-plugin-set-template](https://github.com/omds-chat/dsc-plugin-set-template)** | 插件合集模板,复制即得一套带分发规范、Schema 与签名校验的合集骨架 |
| **[dsc-inner-plugin](https://github.com/omds-chat/dsc-inner-plugin)** | 同源插件索引,收录承诺不泄露用户凭证与数据的插件 |
| **[awesome-dsc-plugin](https://github.com/omds-chat/awesome-dsc-plugin)** | 社区精选插件合集,收录社区插件并提供索引与收录申请入口 |
| **[dsc-humanize](https://github.com/omds-chat/dsc-humanize)** | 内部插件,让助手更接近你期望的样子,具体形态由你定义,并自带默认的人性化资产来源 |
| **[dsc-llm-tune](https://github.com/omds-chat/dsc-llm-tune)** | 内部插件,把请求采样参数(温度、`top_p`、最大长度、停止词)直接交给你调,与 dsc-humanize 互补但不并存 |
| **[dsc-provider-switch](https://github.com/omds-chat/dsc-provider-switch)** | 内部插件,按能力为每项模型能力挑选供应端点,内置 DeepSeek 并支持自定义 OpenAI 兼容、Anthropic 兼容端点 |
| **[dsc-humanize-asset-template](https://github.com/omds-chat/dsc-humanize-asset-template)** | 人性化资产的规范与骨架,帮助作者写出可被收录的资产包 |
| **[dsc-humanize-inner-asset](https://github.com/omds-chat/dsc-humanize-inner-asset)** | dsc-humanize 自带的默认人性化资产合集,每个资产都是一个可安装的包 |
| **[awesome-dsc-humanize-asset](https://github.com/omds-chat/awesome-dsc-humanize-asset)** | 社区贡献的人性化资产合集,提供索引与收录入口 |
| **[dsc-humanize-assistant](https://github.com/omds-chat/dsc-humanize-assistant)** | 官方首个人性化资产包,预设一组人设、标签、策略与注入文本,可直接安装体验 |
| **[.github](https://github.com/omds-chat/.github)** | 你现在浏览的组织主页,以及权利、署名与免责声明 |

## 生态与角色

| 角色 | 从哪里进入 | 能得到什么 |
|:---:|:---:|:---:|
| 普通用户 | [DeepSeek-Chat-Enhanced](https://github.com/omds-chat/DeepSeek-Chat-Enhanced) | 了解使用方式与资费前提,取得可直接使用的静态包 |
| 插件开发者 | [dsc-plugin-template](https://github.com/omds-chat/dsc-plugin-template) | 模板与示例,从零写出可用的插件 |
| 社区贡献者 | [awesome-dsc-plugin](https://github.com/omds-chat/awesome-dsc-plugin) | 提交插件收录,让作品被更多用户找到 |
| 资产作者 | [dsc-humanize-asset-template](https://github.com/omds-chat/dsc-humanize-asset-template) | 模板与规范,从零写出可被 [awesome-dsc-humanize-asset](https://github.com/omds-chat/awesome-dsc-humanize-asset) 收录的资产包,供 dsc-humanize 用户安装使用 |

## 签名与信任

组织用一套证书体系来说明内容的来源。

- **组织维护自己的根证书机构:** 用来认定哪些插件合集是受信任的发布方,并为它们签发证书。
- **受信任的合集为收录的插件签名:** 合集用组织签发的证书为收录的插件签名,你从合集拿到的插件因此可以追溯到组织认可的发布方。
- **插件作者也可以自签名:** 作者用自己的密钥为插件签名,这代表作者本人的承诺,不是组织的认定。
- **签名只证明来源未被篡改:** 签名说明内容确实来自所声称的发布者,并且发布之后没有被改动;它不证明插件安全、无害或会持续维护,挑选插件时仍请自行核对来源与风险。

## 组织原则

- **项目自治:** 各仓库的技术决定由其维护者负责,组织提供的是发现与协作的空间。
- **作者所有:** 代码、文档与设计的权利属于各自的开发者或权利人,组织不因收录而获得这些权利。
- **收录不等于认证:** 收录与托管只说明可被找到,不构成安全、兼容或持续维护的保证,请自行核对来源与风险。
- **开放参与:** 参与不需要组织成员身份;权限随明确的责任授予,不随热情授予。
- **轻量治理:** 常规协作直接推进,影响面大的改动保留审阅、记录与撤回的余地。

## 参与方式与联系

- 组织仓库列表: [github.com/omds-chat](https://github.com/omds-chat)
- 插件收录申请与问题反馈: 在 [awesome-dsc-plugin](https://github.com/omds-chat/awesome-dsc-plugin) 中提交 Issue
- 人性化资产收录申请与问题反馈: 在 [awesome-dsc-humanize-asset](https://github.com/omds-chat/awesome-dsc-humanize-asset) 中提交 Issue
- 主线产品的问题与建议: 在 [DeepSeek-Chat-Enhanced](https://github.com/omds-chat/DeepSeek-Chat-Enhanced) 中提交 Issue
- 组织资料与声明: [本仓库](https://github.com/omds-chat/.github) · [权利与免责声明](NOTICE.md)
- 组织 Owner 与联系人: JularDepick (JularDepick@gmail.com)

---

<sub>omds-chat 是非官方的社区组织,与 DeepSeek 及其关联主体不存在隶属、授权、合作、赞助或背书关系。插件运行在浏览器中,可以接触到保存在浏览器存储里的 API Key,请只启用你信任来源的插件。完整说明见[权利、署名与免责声明](NOTICE.md)。</sub>
