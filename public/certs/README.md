# 公开证书材料

本目录是 omds-chat 面向公众的证书与公钥存放处。任何人都可以用它核对一份产物的来源渠道，也可以自行验证一条信任链，而不必依赖任何私有材料。

目录内只有两类文件：

| 文件 | 内容 | 是否公开 |
|:---:|:---:|:---:|
| `<名称>.crt` | X.509 证书，PEM 编码 | 公开 |
| `<名称>.pub` | 与该证书配对密钥对的公钥，PEM 编码 | 公开 |

文件名的判定只认后缀：以 `.pub` 结尾的是公钥；文件名中出现的 `secret` 字样是历史命名习惯，不代表内容。不带 `.pub` 后缀的同名文件是私钥，不在本仓库，也不会对外提供。

## 证书体系列表

下表的 /O 与 /CN 均取自证书实际字段，到期时间取自证书的 `notAfter`。

| 目录 | 证书类型 | /O 组织主体 | /CN 名称主体 | 颁发者 | 到期时间（UTC+08:00） |
|:---:|:---:|:---:|:---:|:---:|:---:|
| `ds-chat/` | CA（根） | omds-chat | DeepSeek-Chat-Enhanced ROOT CA | 自签 | 2036-11-17 13:43:45 |
| `ds-chat-pages/` | EEC | omds-chat | DeepSeek-Chat-Enhanced Pages | DeepSeek-Chat-Enhanced ROOT CA | 2036-11-17 15:17:10 |
| `dsc-inner-plugin/` | EEC | omds-chat | dsc-inner-plugin | DeepSeek-Chat-Enhanced ROOT CA | 2036-11-17 15:19:26 |
| `awesome-dsc-plugin/` | EEC | omds-chat | awesome-dsc-plugin | DeepSeek-Chat-Enhanced ROOT CA | 2036-11-17 15:21:50 |
| `dsc-humanize/` | CA（根） | omds-chat | dsc-humanize ROOT CA | 自签 | 2036-11-17 22:24:05 |
| `dsc-humanize-inner-asset/` | EEC | omds-chat | dsc-humanize-inner-asset | dsc-humanize ROOT CA | 2036-11-17 22:29:09 |
| `awesome-dsc-humanize-asset/` | EEC | omds-chat | awesome-dsc-humanize-asset | dsc-humanize ROOT CA | 2036-11-17 22:31:50 |

证书里存的是 UTC 时间，上表已换算为 UTC+08:00。`openssl x509 -enddate` 直接输出 UTC，例如根证书为 `Nov 17 05:43:45 2036 GMT`，与上表的 13:43:45 是同一时刻。

证书用 ECDSA P-256 签发，签名算法 `ecdsa-with-SHA256`。两个根证书是自签的 CA 证书（`CA:TRUE`、`pathlen:0`，密钥用途 `Certificate Sign, CRL Sign`），因此只能签发末端证书、不能签发下级 CA；末端证书均为 `CA:FALSE`，密钥用途只有 `Digital Signature`，不能用来签发任何东西。

/O 固定为 `omds-chat`，是 PKI 材料的执行主体；/CN 是各渠道的名称主体。二者分开，是为了让绑定了 /CN 的分发渠道不必随执行主体变动而重签。

## 信任层级

本目录有两条互相独立的信任链。它们是两个互不隶属的体系，任一条链的根都不签发另一条链下的任何证书。

第一棵树，ds-chat 根及其下游：

```plaintext
ds-chat/ds-chat-root-ca.crt                 自签 CA，CA:TRUE，pathlen:0
├── ds-chat-pages/ds-chat-pages-eec.crt                     CN=DeepSeek-Chat-Enhanced Pages
├── dsc-inner-plugin/dsc-inner-plugin-eec.crt               CN=dsc-inner-plugin
└── awesome-dsc-plugin/awesome-dsc-plugin-eec.crt           CN=awesome-dsc-plugin
```

第二棵树，dsc-humanize 独立根及其下游：

```plaintext
dsc-humanize/dsc-humanize-root-ca.crt      自签 CA，CA:TRUE，pathlen:0
├── dsc-humanize-inner-asset/dsc-humanize-inner-asset-eec.crt      CN=dsc-humanize-inner-asset
└── awesome-dsc-humanize-asset/awesome-dsc-humanize-asset-eec.crt  CN=awesome-dsc-humanize-asset
```

两棵树的独立是结构上的，不是约定上的：拿 dsc-humanize 的根去校验 ds-chat 名下的证书会失败，反之亦然。要验证一张证书，必须用与它同一棵树的根。两个根证书都不会签发对方的末端证书，也不会跨树签发。

作者身份不出证书，因此不在任何一棵树里，见下一节。

## 作者身份

`author-omds-chat/` 放一对 Ed25519 密钥中的公钥，不是 X.509 证书。它对应的是 omds-chat 作为社区生态作者的署名身份，与上面两条证书链没有上下游关系：作者签名用公钥直接验证，不经过任何根证书，也没有吊销机制，公钥的真实性由验签方自行确认。

公钥随插件产物分发，验签方只需要这一把公钥。签名文件的命名、签名与验签命令见 [tools/Auth-Sign/README.md](../../tools/Auth-Sign/README.md) 的「角色三：作者」。

## 每个来源目录放什么

| 目录 | 证书 | 公钥 | 角色与绑定对象 |
|:---:|:---:|:---:|:---:|
| `ds-chat/` | `ds-chat-root-ca.crt` | `ds-chat-root-ca-secret.pub` | 根 CA，本树唯一的签发方 |
| `ds-chat-pages/` | `ds-chat-pages-eec.crt` | `ds-chat-pages-eec-secret.pub` | EEC，DeepSeek-Chat-Enhanced 的 Pages 分发 |
| `dsc-inner-plugin/` | `dsc-inner-plugin-eec.crt` | `dsc-inner-plugin-eec-secret.pub` | EEC，dsc-inner-plugin 仓库的插件索引 |
| `awesome-dsc-plugin/` | `awesome-dsc-plugin-eec.crt` | `awesome-dsc-plugin-eec-secret.pub` | EEC，awesome-dsc-plugin 合集及其收录插件 |
| `dsc-humanize/` | `dsc-humanize-root-ca.crt` | `dsc-humanize-root-ca-secret.pub` | 根 CA，humanize 资产生态的独立签发方 |
| `dsc-humanize-inner-asset/` | `dsc-humanize-inner-asset-eec.crt` | `dsc-humanize-inner-asset-eec-secret.pub` | EEC，内部默认资产合集 |
| `awesome-dsc-humanize-asset/` | `awesome-dsc-humanize-asset-eec.crt` | `awesome-dsc-humanize-asset-eec-secret.pub` | EEC，社区资产合集 |
| `author-omds-chat/` | 无（不出证书） | `author-omds-chat-secret.pub` | 作者署名身份，Ed25519 |

每个末端证书所在的目录只放该证书与它的公钥，不放根证书副本。验证时请直接引用同树根目录下的根证书，见下一节。

## 不放什么

以下材料一律不在本目录，也不要向任何渠道索取：

| 材料 | 原因 |
|:---:|:---:|
| 私钥 | 只在持有方本地保管，仅用于签名操作，任何情况下不对外 |
| CSR（证书签名请求） | 属于签发流程的中间件，供签发方使用，与验证无关 |
| 序列号记录（`.srl`、序列号清单） | 属于签发方的内部记录 |
| 扩展模板等签发配置 | 属于签发方的内部实现 |
| 已签发材料的存档副本 | 属于签发方的内部归档 |
| 仅用于本地临时验证的测试证书 | 只在本地使用，不随任何仓库分发 |

本目录只回答“这张证书是谁、由谁签发、何时到期”，不承担吊销列表、签发流程与私钥操作的说明。这些内容见 [tools/Auth-Sign/README.md](../../tools/Auth-Sign/README.md)。

## 如何校验一张证书

以下命令都是只读的：不生成、不签发、不改动任何文件。请在仓库根目录执行，路径均相对于仓库根。

查看一张证书的主体、颁发者、有效期与扩展：

```bash
openssl x509 -in public/certs/ds-chat-pages/ds-chat-pages-eec.crt \
  -noout -subject -issuer -dates -ext basicConstraints,keyUsage
```

输出中 `issuer` 是 `CN=DeepSeek-Chat-Enhanced ROOT CA`，`CA:FALSE`，密钥用途只有 `Digital Signature`。要看全部字段，把 `-noout -subject -issuer -dates -ext ...` 换成 `-text`。

核对证书与公钥是否配对（证书里的公钥应与 `.pub` 文件逐字节一致，`diff` 无输出即匹配）：

```bash
openssl x509 -in public/certs/ds-chat-pages/ds-chat-pages-eec.crt -noout -pubkey \
  | diff - public/certs/ds-chat-pages/ds-chat-pages-eec-secret.pub
```

查询到期时间，输出为 UTC：

```bash
openssl x509 -in public/certs/ds-chat/ds-chat-root-ca.crt -noout -enddate
```

## 如何校验一条链

先确认根证书自签有效。输出 `OK` 表示根证书的签名与自身公钥吻合：

```bash
openssl verify -CAfile public/certs/ds-chat/ds-chat-root-ca.crt \
  public/certs/ds-chat/ds-chat-root-ca.crt
```

再用根校验同树的末端证书。三张 ds-chat 名下的末端证书都应输出 `OK`：

```bash
openssl verify -CAfile public/certs/ds-chat/ds-chat-root-ca.crt \
  public/certs/ds-chat-pages/ds-chat-pages-eec.crt

openssl verify -CAfile public/certs/ds-chat/ds-chat-root-ca.crt \
  public/certs/dsc-inner-plugin/dsc-inner-plugin-eec.crt

openssl verify -CAfile public/certs/ds-chat/ds-chat-root-ca.crt \
  public/certs/awesome-dsc-plugin/awesome-dsc-plugin-eec.crt
```

humanize 一侧同理，换成该树的根：

```bash
openssl verify -CAfile public/certs/dsc-humanize/dsc-humanize-root-ca.crt \
  public/certs/dsc-humanize-inner-asset/dsc-humanize-inner-asset-eec.crt

openssl verify -CAfile public/certs/dsc-humanize/dsc-humanize-root-ca.crt \
  public/certs/awesome-dsc-humanize-asset/awesome-dsc-humanize-asset-eec.crt
```

验一条链失败，最需要先排除的不是证书坏了，而是用错了根。用错树时 `openssl verify` 退出码为 2，并报告：

```plaintext
error 20 at 0 depth lookup: unable to get local issuer certificate
```

这条失败正是两棵树互不隶属的证据。反过来，如果把两个根证书拼进同一个 `-CAfile` 再验证，输出会变成 `OK`：这只说明“任一根都能验”，不说明两条链有共同的上级。

作者身份不走链式校验：它的公钥直接参与签名验证，与上面两条链无关，也没有需要拼进 `-CAfile` 的根。
