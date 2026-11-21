# OpenSSL 极简 PKI 工具集

## 使用约定

本文件就是命令手册:每个角色的每一步都直接给出可执行的 `openssl` 命令,复制即可运行。

- **建议在与证书材料同一目录下执行。** 命令里用的全是相对路径(`-extfile eec_ext.cnf`、`-CAfile root_ca.crt`、`-out crl.pem`、`-in plugin.zip`),当前目录就是这些路径的基准目录;换到别处执行,相对路径就找不到文件。
- **先把两份配置模板放到该目录。** 签发 EEC 与生成 CRL 各需要一份模板,它们在 `tool/` 里:[eec_ext.cnf](tool/eec_ext.cnf)、[crl.conf](tool/crl.conf)。复制到证书材料目录后,下文命令才能原样执行。
- **必须在特定目录执行的命令,已在命令处标注**「该命令必须在 <目录> 下执行」。目前是签发 EEC(要求当前目录能找到 `eec_ext.cnf`)与吊销并生成 CRL(要求当前目录能找到 `crl.conf`)两步。
- **占位符** 形如 `_XXX_`,执行前替换为真实值;下文命令已按「命名与后缀约定」里的标准文件名填好,例如 `root_ca_secret`、`root_ca.crt`、`eec_secret`、`eec.crt`。
- **运行环境。** Windows 请在 Git Bash、MSYS2 等 bash 环境中执行;原生 cmd 与 PowerShell 不能直接跑 `> /dev/null`、`printf`、`[ -f … ]` 这类 bash 写法。

## 概述

这是一套基于 **OpenSSL 3.0+** 的轻量级通用 PKI 工具集,覆盖自签根证书、证书申请、终端签名证书签发、CMS 分离签名、签名验签、证书吊销列表(CRL)生成与吊销校验全流程;同时额外提供**无证书裸公钥分离签名**模式,不依赖 CA 体系即可完成数据签名与完整性校验。

内容按三组角色划分:

- **CA 与 EEC 流程**:只使用 `openssl` 命令,证书算法为 ECDSA P-256。
- **作者裸公钥流程**:以 `openssl` 命令为主,作者密钥为 Ed25519,交付格式统一为 PEM;另有两个 Python 转换脚本,用于把作者已有的 OpenSSH 密钥转成 PEM 或反向转回。
- **通用查询**:只使用 `openssl` 命令,用于在本地查看任意 x509 证书与任意私钥的信息。

全链路摘要算法统一为 SHA-512,不依赖 OpenSSL 默认值:CMS 签名与验签在每条 `openssl cms` 命令里显式写出 `-md sha512`,CRL 的摘要则由生成 CRL 时写出的 `openssl.cnf` 里显式的 `default_md = sha512` 决定。CRL 的验签方按 CRL 自身声明的签名算法验证,已发布的旧 CRL 仍可正常校验。

所有命令为通用工具,不绑定任何具体业务场景;所有带下划线的标识符为占位符,使用前替换为真实文件路径或名称。

## 前置环境

| 依赖 | 版本要求 | 检查命令 | 适用范围 |
|:---:|:---:|:---:|:---:|
| `openssl` | 3.0 及以上 | `openssl version` | 全部命令,必需 |
| `python` | 3.8 及以上 | `python --version` | 仅 `tool/` 下两个 `author_convert_*.py` 转换脚本需要 |
| `openssh` | 8.0 及以上 | `ssh -V` | 仅作者本地自验与转换脚本自校验可选使用,不是分发必需 |

- **全部 openssl 命令只依赖 openssl**:不额外安装任何工具。
- **openssh 不是分发必需**:本工具集只用 `openssh` 做作者本地自验,不作为签名与交付格式。
- **两个转换脚本只依赖 Python 标准库**:[author_convert_openssh_to_openssl.py](tool/author_convert_openssh_to_openssl.py)、[author_convert_openssl_to_openssh.py](tool/author_convert_openssl_to_openssh.py) 不需要 `cryptography` 等第三方模块,但要求 `python >= 3.8`;转换后的自校验会调用 `openssl`,环境里存在 `ssh-keygen` 时还会额外用 `ssh-keygen -y`、`ssh-keygen -l` 复核。带口令私钥的解密与加密都由脚本自带的 bcrypt_pbkdf、AES 实现完成,不需要先用 `ssh-keygen -p` 去掉口令。

> OpenSSL 版本低于 3.0 时,`openssl genpkey`、`openssl cms`、`openssl ca -gencrl` 的行为与本工具集不符,请先升级。

## 算法约定

| 角色 | 密钥算法 | 摘要算法 | 说明 |
|:---:|:---:|:---:|:---:|
| 根 CA | ECDSA P-256 | SHA-512 | 生成根密钥时固定曲线 |
| EEC | ECDSA P-256 | SHA-512 | `openssl cms -sign` 不支持 Ed25519 证书 |
| 作者 | Ed25519 | SHA-512 | `openssl pkeyutl -rawin` 直接对文件做纯 Ed25519 签名 |
| CRL | ECDSA P-256 | SHA-512 | 由根 CA 私钥签名,摘要取 `openssl.cnf` 里显式的 `default_md = sha512` |

摘要算法在 EEC 签名与两条验签命令中均以 `-md sha512` 显式指定,CRL 的摘要也由生成 CRL 时写出的 `openssl.cnf` 里 `default_md = sha512` 显式指定,全链路都不依赖 OpenSSL 默认值,避免默认值随 OpenSSL 版本或密钥类型漂移。

## 目录内容

| 文件 | 使用者 | 用途 |
|:---:|:---:|:---:|
| [README.md](README.md) | 全部 | 本文件,按角色给出全部命令 |
| [tool/eec_ext.cnf](tool/eec_ext.cnf) | 根证书机构 | EEC 扩展配置,签发 EEC 时通过 `-extfile` 引用 |
| [tool/crl.conf](tool/crl.conf) | 根证书机构 | CRL 扩展配置,生成 CRL 用的 `openssl.cnf` 通过 `.include` 引用 |
| [tool/author_convert_openssh_to_openssl.py](tool/author_convert_openssh_to_openssl.py) | 已有 OpenSSH 密钥的作者 | OpenSSH 密钥转 PEM |
| [tool/author_convert_openssl_to_openssh.py](tool/author_convert_openssl_to_openssh.py) | 已有 PEM 密钥的作者 | PEM 转 OpenSSH 密钥 |

## 命令速查

| 角色 | 步骤 | 命令要点 | 产出物 |
|:---:|:---:|:---:|:---:|
| CA | 生成根密钥对 | `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256` | `root_ca_secret`、`root_ca_secret.pub` |
| CA | 生成根证书 | `openssl req -x509 … -addext basicConstraints=critical,CA:TRUE,pathlen:0` | `root_ca.crt` |
| CA | 签发 EEC | `openssl x509 -req … -extfile eec_ext.cnf -extensions eec_ext` | `eec.crt`、`root_ca.srl` |
| CA | 吊销并生成 CRL | `openssl ca -revoke …` 与 `openssl ca -gencrl …` | `crl.pem`、`ca_work/` |
| EEC | 生成密钥对 | `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256` | `eec_secret`、`eec_secret.pub` |
| EEC | 生成 CSR | `openssl req -new -key eec_secret …` | `eec.csr` |
| EEC | 生成签名 | `openssl cms -sign -binary -outform DER -md sha512` | `plugin.zip.sig` |
| EEC | 校验签名 | `openssl cms -verify -binary -inform DER -CAfile root_ca.crt` | 退出码 0 或 1 |
| 作者 | 生成密钥对 | `openssl genpkey -algorithm ed25519` | `author_secret`、`author_secret.pub` |
| 作者 | 生成签名 | `openssl pkeyutl -sign -rawin` | `plugin.zip.sig` |
| 作者 | 校验签名 | `openssl pkeyutl -verify -pubin -rawin` | 控制台输出与退出码 |
| 作者 | 密钥格式互转 | `python author_convert_*.py` | PEM 或 OpenSSH 密钥 |
| 任意一方 | 查看证书与私钥 | `openssl x509 -text`、`openssl pkey -text` | 控制台输出 |

---

## 角色一:CA(根证书机构)

作为整个体系的信任锚,你持有根 CA 私钥与根证书,负责为可信主体签发终端签名证书,并在必要时对证书执行吊销管理。

### 第一步:生成根 CA 密钥对

```bash
# 根 CA 私钥:ECDSA P-256
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out root_ca_secret
# 由私钥导出公钥:公钥是公开材料,可随仓库分发;私钥不得入库
openssl pkey -in root_ca_secret -pubout -out root_ca_secret.pub
```

根私钥由 `openssl genpkey` 直接产出 PEM 编码的 PKCS#8,需严格安全保管;公钥 `root_ca_secret.pub` 可以公开分发。

### 第二步:生成自签名根证书

```bash
openssl req -x509 -new -key root_ca_secret -days 3650 -out root_ca.crt \
  -subj "/O=_YOUR_ORG_NAME_/CN=_YOUR_CA_NAME_" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"
```

`pathlen:0` 表示这张根证书只能签发终端证书、不能再签发下级 CA;`keyUsage` 限定为签发证书与签发 CRL。根证书作为全局信任锚公开分发,根私钥需严格安全保管。

### 第三步:签发 EEC

**该命令必须在 `eec_ext.cnf` 所在目录(即证书材料目录)下执行。**

```bash
# -extfile 用的是相对路径,当前目录找不到 eec_ext.cnf 会直接报错
# openssl x509 -req 不支持 -addext,证书扩展必须通过 -extfile 传入
openssl x509 -req -in eec.csr -CA root_ca.crt -CAkey root_ca_secret -CAcreateserial \
  -out eec.crt -days 365 -extfile eec_ext.cnf -extensions eec_ext
```

`-CAcreateserial` 会在当前目录生成 `root_ca.srl`,用来记录下一个序列号;后续签发沿用同一目录即可连续编号。证书扩展由 [eec_ext.cnf](tool/eec_ext.cnf) 限定为「仅数字签名、不可签发下级证书」,并写入 `subjectKeyIdentifier` 与 `authorityKeyIdentifier`。签发完成后把 `eec.crt` 返回给申请方。

### 第四步:吊销 EEC 并生成 CRL

**该命令必须在 `crl.conf` 所在目录(即证书材料目录)下执行。**

`openssl crl -gen` 在 OpenSSL 3.x 不可用,必须用 `openssl ca -gencrl`,因此需要一套最小 CA 目录。以下命令块按 1) 到 4) 的顺序执行,整段照抄即可。

```bash
# 1) 初始化最小 CA 目录:index.txt 吊销库、serial、crlnumber
mkdir -p ./ca_work
[ -f ./ca_work/index.txt ] || : > ./ca_work/index.txt
[ -f ./ca_work/serial ] || printf '01\n' > ./ca_work/serial
[ -f ./ca_work/crlnumber ] || printf '01\n' > ./ca_work/crlnumber

# 2) 生成该目录专用的 openssl.cnf,并通过 .include 引入 crl.conf 的 crl_ext 扩展
printf '%s\n' \
  '[ ca ]' \
  'default_ca = CA_default' \
  '' \
  '[ CA_default ]' \
  'dir = ./ca_work' \
  'database = $dir/index.txt' \
  'serial = $dir/serial' \
  'crlnumber = $dir/crlnumber' \
  'certificate = root_ca.crt' \
  'private_key = root_ca_secret' \
  '# default_md 显式写 sha512:不写则 openssl ca 取默认摘要,会随 OpenSSL 版本或密钥类型漂移' \
  'default_md = sha512' \
  'default_crl_days = 30' \
  'policy = policy_any' \
  'crl_extensions = crl_ext' \
  '' \
  '[ policy_any ]' \
  'commonName = optional' \
  'organizationName = optional' \
  'organizationalUnitName = optional' \
  'countryName = optional' \
  'stateOrProvinceName = optional' \
  'localityName = optional' \
  'emailAddress = optional' \
  '' \
  '.include = crl.conf' \
  > ./ca_work/openssl.cnf

# 3) 吊销证书;-revoke 可重复写多行;同一证书重复吊销会提示 Already revoked,不影响后续生成
openssl ca -config ./ca_work/openssl.cnf -revoke eec.crt -crl_reason keyCompromise -batch

# 4) 生成 CRL;-crldays 覆盖配置里的 default_crl_days
openssl ca -config ./ca_work/openssl.cnf -gencrl -out crl.pem -crldays 30
```

第 2 段的 `.include = crl.conf` 按当前目录解析,所以这条命令必须在放有 `crl.conf` 的目录下执行;`dir = ./ca_work`、`certificate`、`private_key` 也都是相对路径,分别指向 CA 工作目录、根证书与根私钥。

第 3 段的 `-crl_reason` 可选值:

| 取值 | 含义 |
|:---:|:---:|
| `unspecified` | 不透露原因 |
| `keyCompromise` | 私钥泄露或怀疑泄露 |
| `affiliationChanged` | 组织变更 |
| `superseded` | 已更换新证书 |
| `cessationOfOperation` | 关系终止 |
| `certificateHold` | 暂停使用 |

出现私钥泄露、权限终止、证书替换等情况时,把对应证书纳入吊销库并生成新版 CRL。CA 工作目录(`./ca_work`)保持不变即可累积吊销条目;需要吊销多张证书时重复执行第 3 段,或把 `-revoke` 行复制多份。

---

## 角色二:EEC(终端签名证书)

作为经根证书机构授权的签名主体,你持有自身私钥与根 CA 签发的 EEC(终端实体证书),负责对业务文件生成可通过信任链核验的数字签名。

### 第一步:生成 EEC 密钥对

```bash
# 必须是 ECDSA P-256,否则 openssl cms -sign 会失败
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out eec_secret
# 由私钥导出公钥:公钥是公开材料,可随 CSR 一并提交或单独分发
openssl pkey -in eec_secret -pubout -out eec_secret.pub
```

密钥类型固定为 ECDSA P-256,私钥由己方严格保密,不得对外提供;公钥 `eec_secret.pub` 属于公开材料。

### 第二步:生成证书签名请求(CSR)

```bash
openssl req -new -key eec_secret -out eec.csr -subj "/O=_YOUR_ORG_NAME_/CN=_YOUR_SIGNER_NAME_"
```

CSR 仅包含公钥与身份信息,不含私钥,提交给根证书机构。收到 `eec.crt` 后与本地 `eec_secret` 配套保存:证书可公开出示,私钥仅限签名操作使用。

### 第三步:对文件生成 CMS 分离签名

```bash
# 必须 -binary -outform DER,默认的 S/MIME 包装浏览器无法解析
# -md sha512:显式指定摘要算法,避免默认值随 OpenSSL 版本或密钥类型漂移
# -noattr:不写入签名属性,签名内容更确定
openssl cms -sign -binary -in plugin.zip -out plugin.zip.sig \
  -signer eec.crt -inkey eec_secret -outform DER -noattr -md sha512
```

签名内嵌 EEC 证书(没有加 `-nocerts`),验签方只需根证书即可完成链路校验。生成 `plugin.zip.sig` 后与原始文件一并提交给验签方。

### 第四步:校验签名

不检查吊销:

```bash
# -md sha512:显式指定摘要算法;验签侧实际以 SignerInfo 中的摘要为准,此参数仅作声明
# stdout 被丢弃后 openssl 自身的成功提示也看不到了,所以这里显式回显结论
# 验签通过退出码 0,验签失败退出码 1
if openssl cms -verify -binary -inform DER -in plugin.zip.sig -content plugin.zip \
     -CAfile root_ca.crt -md sha512 > /dev/null; then
  echo "验签通过:plugin.zip.sig 与 plugin.zip 内容匹配,且 EEC 可链到 root_ca.crt"
else
  echo "验签失败:plugin.zip.sig 与 plugin.zip 不匹配,或 EEC 证书链校验未通过" >&2
  exit 1
fi
```

同时检查吊销:

```bash
# openssl cms -verify 没有 -CRLfile 参数,需先把 CRL 与根证书拼进同一个 PEM 文件
cat root_ca.crt crl.pem > root_ca_with_crl.pem
if openssl cms -verify -binary -inform DER -in plugin.zip.sig -content plugin.zip \
     -CAfile root_ca_with_crl.pem -crl_check -md sha512 > /dev/null; then
  echo "验签通过:内容匹配,EEC 可链到 root_ca.crt 且未被吊销"
else
  echo "验签失败:内容不匹配,或 EEC 证书链/吊销校验未通过" >&2
  exit 1
fi
```

CA 方与验签方使用同一组命令:确认 EEC 由本 CA 签发、未过期、用途合规,同时确认签名与文件内容匹配。

---

## 角色三:作者(无证书裸公钥)

你不接入证书体系,不向根证书机构申请证书,仅通过自身持有的密钥对完成裸公钥签名;公钥的真实性由验签方自行确认,签名仅用于证明数据来源与完整性。

### 第一步:生成作者密钥对

```bash
# 仅用 openssl:Ed25519,与产品侧校验算法保持一致
openssl genpkey -algorithm ed25519 -out author_secret
openssl pkey -in author_secret -pubout -out author_secret.pub
```

作者密钥为 Ed25519:私钥是 PEM 编码的 PKCS#8,公钥是 PEM 编码的 SPKI。作者需选定这一套工具链并一直使用,不要与 OpenSSH 混用;手上已有 OpenSSH 密钥(含带口令的私钥)的作者可以先用第四个步骤里的转换脚本转成 PEM,再走这套流程。

### 第二步:对目标文件签名

```bash
openssl pkeyutl -sign -inkey author_secret -in plugin.zip -out plugin.zip.sig -rawin
```

`openssl pkeyutl -sign -rawin` 对 Ed25519 是把整个文件送入纯 Ed25519 签名(PureEdDSA,内部摘要固定 SHA-512),不额外做外部摘要,签名固定 64 字节。

### 第三步:交付校验材料并验证

把原始文件、签名文件、自身公钥一并交给验签方。验签方确认公钥归属后用同一条命令校验:

```bash
openssl pkeyutl -verify -pubin -inkey author_secret.pub -in plugin.zip -sigfile plugin.zip.sig -rawin
```

> 裸公钥签名体系不依赖 CA、无证书、无标准吊销机制。作者公钥的真实性由验签方自行确认,签名仅用于证明数据来源与完整性。

### 第四步:密钥格式互转(两个 Python 转换脚本)

`tool/` 下保留两个转换脚本,只处理 Ed25519 密钥的容器格式:

| 脚本 | 方向 | 支持的口令 |
|:---:|:---:|:---:|
| [author_convert_openssh_to_openssl.py](tool/author_convert_openssh_to_openssl.py) | OpenSSH 到 PEM | 输入私钥可带口令,解密后输出不带口令的 PKCS#8 |
| [author_convert_openssl_to_openssh.py](tool/author_convert_openssl_to_openssh.py) | PEM 到 OpenSSH | 输入私钥可带口令;输出是否带口令由参数决定 |

```bash
python tool/author_convert_openssh_to_openssl.py id_ed25519 -o author_secret            # 私钥:OpenSSH -> PKCS#8
python tool/author_convert_openssh_to_openssl.py id_ed25519.pub -o author_secret.pub    # 公钥:OpenSSH -> SPKI
python tool/author_convert_openssl_to_openssh.py author_secret -o id_ed25519            # 私钥:PKCS#8 -> OpenSSH
python tool/author_convert_openssl_to_openssh.py author_secret.pub -o id_ed25519.pub    # 公钥:SPKI -> ssh-ed25519

# 带口令的 PEM 私钥:优先交互提示或环境变量,避免口令进入 shell 历史与进程列表
python tool/author_convert_openssl_to_openssh.py author_secret -o id_ed25519                     # 交互提示,不回显
OPENSSH_KEY_PASSPHRASE=... python tool/author_convert_openssl_to_openssh.py author_secret -o id_ed25519
python tool/author_convert_openssl_to_openssh.py author_secret -o id_ed25519 --passphrase '...'  # 仅当上面两种都不便使用时

# 需要输出带口令的 OpenSSH 私钥时加 --encrypt-output
python tool/author_convert_openssl_to_openssh.py author_secret -o id_ed25519 --encrypt-output
python tool/author_convert_openssl_to_openssh.py author_secret -o id_ed25519 --encrypt-output --cipher aes256-ctr --rounds 16

# 带口令的 OpenSSH 私钥:优先交互提示或环境变量
python tool/author_convert_openssh_to_openssl.py id_ed25519 -o author_secret                          # 交互提示,不回显
OPENSSH_KEY_PASSPHRASE=... python tool/author_convert_openssh_to_openssl.py id_ed25519 -o author_secret
python tool/author_convert_openssh_to_openssl.py id_ed25519 -o author_secret --passphrase '...'      # 仅当上面两种都不便使用时
```

不给 `-o` 时输出到 `<输入文件>.converted`。

#### 为什么 ssh-keygen 转不了 Ed25519,为什么用标准库 Python,为什么口令处理也要自己写

**`ssh-keygen` 的格式转换对 Ed25519 完全不可用。** 两条命令都拿不到 PEM,已实测:

```console
$ ssh-keygen -e -m PKCS8 -f id_ed25519.pub
do_convert_to_pkcs8: unsupported key type ED25519

$ ssh-keygen -p -m PKCS8 -f id_ed25519
(命令报告成功,但文件仍是 -----BEGIN OPENSSH PRIVATE KEY-----,openssl 依然读不了)
```

`ssh-keygen -m` 只接受 `RFC4716`、`PKCS8`、`PEM`(部分版本还有 `hexdump`),不存在 `-m OPENSSH` 选项,反向同样没有入口。既然工具链不给路,就按格式规范自己写:`openssh-key-v1` 与 RFC 8410 的 PKCS#8、SPKI 都是结构固定的公开二进制格式,转换只是重排容器、搬运同一串 32 字节种子与公钥,不涉及任何密码学运算。

**用标准库 Python 而不是 `cryptography`。** 转换本身不需要密码学运算,真正需要判断的地方直接调用环境里已有的 `openssl`;不引入 pip 依赖与编译轮子,只用标准库的脚本可以原样复制到任何一台有 Python 的机器上运行。

**口令的处理同样在脚本里完成。** OpenSSH 私有段用 `bcrypt_pbkdf` 派生密钥、再用 `aes256-ctr` 之类的分组密码加密;PKCS#8 则用 PBES2(`PBKDF2` 加 AES-CBC)。标准库没有 `bcrypt_pbkdf`,也没有 AES,脚本因此自带一份标准库实现的 Blowfish、bcrypt_pbkdf、AES-CTR 与 AES-CBC。这样环境里只要有 `python` 与 `openssl`,带口令私钥两个方向都能转,既不用先手工执行 `ssh-keygen -p -N ""` 去掉口令,也不引入任何第三方模块。

两个脚本都带自校验,任何一步不通过就以非零退出码结束,且不留半成品文件:OpenSSH 转 PEM 时,产出的 PEM 必须能被 `openssl pkey -in <文件> -noout` 读通,且由它派生的公钥与 OpenSSH 私钥内嵌的公钥一致;PEM 转 OpenSSH 时,产出的私钥会被回读比对种子与公钥,环境里有 `ssh-keygen` 时再用 `ssh-keygen -y` 反推公钥比一次(带口令输出需要交互输入口令,这一步自动跳过,改用同一口令回读自校验)。

#### OpenSSH 私钥带口令(正向:OpenSSH 到 PEM)

`openssh-key-v1` 容器的头部字段顺序固定,脚本先只解析头部,再据此决定走哪条路径:

| 头部字段 | 类型 | 无口令时的值 | 在脚本里的作用 |
|:---:|:---:|:---:|:---:|
| `magic` | 固定字节 | `openssh-key-v1` 加 NUL | 标识容器格式,不匹配即报「不是 openssh-key-v1 结构」 |
| `ciphername` | string | `none` | 私有段的加密算法;不是 `none` 就表示私有段是密文 |
| `kdfname` | string | `none` | 口令派生函数,带口令时为 `bcrypt` |
| `kdfoptions` | string | 空 | `string salt` 加 `uint32 rounds`,供 bcrypt_pbkdf 使用 |
| `nkeys` | uint32 | `1` | 密钥数量,脚本只接受 1 |
| `publickey` | string | 外层公钥 blob | 与私有段内的公钥交叉校验 |
| `private` | string | 明文私有段 | 带口令时是密文,长度是 16 的整数倍 |

判断依据只有一条:**`ciphername` 是不是 `none`**。为 `none` 时私有段是明文,同时要求 `kdfname` 也是 `none` 且 `kdfoptions` 为空,否则按「头部自相矛盾」报私钥损坏;不是 `none` 时私有段是密文,必须用 `kdfname` 与 `kdfoptions` 解密。不能改用「能不能解析出私钥」来判断:密文的随机字节同样可能凑出合法的 checkint 与填充。

支持的加密算法只有 CTR 系列:`aes128-ctr`、`aes192-ctr`、`aes256-ctr`,密钥 16/24/32 字节,IV 固定 16 字节,与 `bcrypt_pbkdf` 的派生结果按「key 在前、iv 在后」切分。`aes256-cbc`、`chacha20-poly1305@openssh.com` 等其它 cipher 一律按「不支持」报错,不做猜测式解密。

密文被改动与口令错误在密码学上不可区分:改动落在第一个分组时 checkint 对不上,脚本按口令错误(退出码 2)提示,并在提示里写明「口令无误则私钥可能已损坏」;改动落在后面的分组时 checkint 仍然通过,脚本会按填充或公钥不一致报私钥损坏(退出码 5)。

正向转换的输出始终是不带口令的 PKCS#8 私钥,转换结束时脚本会明确提示这一点,并提醒自行保管。`rounds` 决定 bcrypt_pbkdf 的工作量,`ssh-keygen` 一般取 16 上下,纯 Python 实现一次需要十几秒,`rounds` 越大越慢;派生开始前会在 stderr 打出进度提示,避免让人误以为脚本卡住。

#### PEM 私钥带口令(反向:PEM 到 OpenSSH)

带口令的 PKCS#8 私钥是 **EncryptedPrivateKeyInfo**,外层只声明加密方案,内层才是真正的私钥。脚本先只解析外层算法字段,据此决定解密方式,不靠试解:

| 参数 | 本脚本支持 | 不在范围内时的处理 |
|:---:|:---:|:---:|
| 加密方案 | `PBES2` | 其它方案按「只支持 PBES2」报错,退出码 3 |
| 口令派生函数 | `PBKDF2` | 其它 KDF 报错,退出码 3 |
| PBKDF2 伪随机函数 | HMAC-SHA1、SHA-224、SHA-256、SHA-384、SHA-512 | 其它 PRF 报错,退出码 3 |
| 分组加密算法 | `aes128-cbc`、`aes192-cbc`、`aes256-cbc` | `des-ede3-cbc` 等报错,退出码 3 |

OpenSSL 3.x 的 `openssl pkey -aes-256-cbc`、`openssl genpkey -aes-256-cbc` 产出的正是 PBES2 加 PBKDF2-HMAC-SHA256 加 AES-256-CBC,可直接转换。

解密流程:按 PBES2 里的 salt 与 `iterationCount` 用 `hashlib.pbkdf2_hmac` 派生密钥,再用自带的 AES-CBC 解密,最后校验 PKCS#7 填充与 PKCS#8 结构。口令错误绝大多数表现为填充不合法,脚本按口令错误(退出码 2)提示,并写明「口令无误则私钥可能已损坏」。

输出私钥是否带口令由参数决定,**默认输出与历史行为一致,不带口令**:

| 参数 | 默认值 | 说明 |
|:---:|:---:|:---:|
| `--encrypt-output` | 关闭 | 打开后输出带口令的 `openssh-key-v1` 私钥;不加该参数时输出明文私钥 |
| `--cipher` | `aes256-ctr` | 输出私钥的加密算法,可选 `aes128-ctr`、`aes192-ctr`、`aes256-ctr` |
| `--rounds` | `16` | 输出私钥 bcrypt_pbkdf 的轮数,越大越慢 |

带口令输出的容器与 `ssh-keygen` 一致:`ciphername` 为所选算法、`kdfname` 为 `bcrypt`、`kdfoptions` 为 16 字节 salt 加轮数,私有段用派生出的 key 与 iv 走 AES-CTR 加密,填充按 16 字节分组。转换结束后脚本会用同一口令回读自校验,并提示使用该私钥时需要输入口令。

#### 口令来源与退出码(两个脚本通用)

口令按下面的优先级取得,只有确实需要时才会用到:

| 顺序 | 来源 | 适用场景与注意点 |
|:---:|:---:|:---:|
| 1 | `--passphrase`、`--output-passphrase` 参数 | 直接给出;会留在 shell 历史与进程列表里,只建议在环境变量不便时临时使用 |
| 2 | 环境变量 `OPENSSH_KEY_PASSPHRASE`(输入口令)、`OPENSSH_OUTPUT_PASSPHRASE`(输出口令) | 本地脚本、CI 之外的一次性使用,不进入命令行参数 |
| 3 | 交互提示 | 仅当上面都没有、且标准输入是真正的控制台时用 `getpass` 提示,不回显,最多 3 次;设置输出口令时要求连续两次输入一致。不是控制台就直接报错退出,不会卡在提示上 |

| 退出码 | 含义 | 典型提示 |
|:---:|:---:|:---:|
| 0 | 成功 | `已写入 …` 与自校验通过 |
| 1 | 普通错误 | 输入不存在、格式无法识别、参数冲突、`openssl` 自校验失败 |
| 2 | 口令错误或口令缺失 | 解密后填充或 checkint 不一致;非交互终端且没有提供口令;空口令 |
| 3 | KDF 或加密参数不支持 | `ciphername=aes256-cbc`、`des-ede3-cbc`、`kdfname=scrypt`、`rounds` 非法 |
| 4 | 不是 Ed25519 | 私钥类型是 `ssh-rsa` 等 |
| 5 | 私钥结构损坏 | 结构截断、填充不符、外层公钥与私有段不一致 |
| 130 | 用户中断 | 按下 Ctrl+C |

**交付格式仍然是 PEM。** `ssh-keygen -Y sign` 产出的 `SSHSIG` 宿主侧用 `openssl pkeyutl -verify` 校验不了,所以 OpenSSH 只用于作者本地自验,不作为分发格式;转换脚本只解决「作者手上已有另一种格式密钥」的兼容问题,交付给验签方的依然是 PEM 密钥与 PEM 签名。

---

## 通用查询

```bash
# 查看任意 x509 证书的基础信息(序列号、签发者、主体、有效期)
openssl x509 -in root_ca.crt -noout -serial -issuer -subject -dates

# 查看任意 x509 证书的完整信息
openssl x509 -in root_ca.crt -noout -text

# 查看任意私钥的信息(输出含私钥内容,仅限本地自查)
openssl pkey -in root_ca_secret -noout -text
```

---

## 命名与后缀约定

| 占位符 | 标准文件名 | 说明 |
|:---:|:---:|:---:|
| `_CA_PRIVATE_KEY_` | `root_ca_secret` | 根 CA 私钥,无后缀,仅本人可读 |
| `_CA_PRIVATE_KEY_.pub` | `root_ca_secret.pub` | 根 CA 公钥,PEM 编码,可公开分发 |
| `_CA_CERT_` | `root_ca.crt` | 根证书,PEM 编码,可公开分发 |
| `_EEC_PRIVATE_KEY_` | `eec_secret` | EEC 私钥,无后缀,仅本人可读 |
| `_EEC_PRIVATE_KEY_.pub` | `eec_secret.pub` | EEC 公钥,PEM 编码,可公开分发 |
| `_EEC_CERT_` | `eec.crt` | EEC 证书,PEM 编码 |
| `_EEC_CSR_` | `eec.csr` | 证书签名请求 |
| `_THE_FILENAME_`、`_DATA_FILE_` | 任意业务文件 | 待签名文件 |
| `_THE_SIGN_FILENAME_` | `<文件名>.sig` | 分离签名文件,与待签名文件同名加 `.sig` |
| `_THE_CA_CERT_FILENAME_` | 任意 x509 证书文件 | 待查看的证书,建议 `root_ca.crt` |
| `_THE_PRIVATE_KEY_FILENAME_` | 任意私钥文件 | 待查看的私钥,建议 `root_ca_secret`,仅限本地自查 |
| `_CRL_FILENAME_` | `crl.pem` | 吊销列表,PEM 编码 |
| `_CA_CRL_BUNDLE_` | `root_ca_with_crl.pem` | 根证书与 CRL 拼接后的中间文件 |
| `_CA_WORK_DIR_` | `./ca_work` | 最小 CA 目录,含 `index.txt`、`serial`、`crlnumber`、`openssl.cnf` |
| `_CRL_CONF_FILENAME_` | `crl.conf` | CRL 扩展配置,由生成的 `openssl.cnf` 通过 `.include` 引用 |
| `_THE_REASON_VALUE_` | `keyCompromise` 等 | 吊销原因,取值见 CA 角色第四步的表格 |
| `_HOW_LONG_` | `30` | CRL 有效期(天),对应 `-crldays` |
| `_AUTHOR_PRIVATE_KEY_` | `author_secret` | 作者私钥,无后缀 |
| `_AUTHOR_PUBLIC_KEY_` | `author_secret.pub` | 作者公钥,PEM 编码 |
| `_OPENSSH_PRIVATE_KEY_` | `id_ed25519` | OpenSSH 格式作者私钥,无后缀,仅本人可读 |
| `_OPENSSH_PUBLIC_KEY_` | `id_ed25519.pub` | OpenSSH 格式作者公钥,`ssh-ed25519` 一行,可公开分发 |

---

## 使用限制

以下限制决定你能用什么密钥、能产出什么签名,自己动手改命令时尤其要注意。

**1. 证书签名方(EEC)必须用 ECDSA P-256,不能用 Ed25519。**
`openssl cms -sign` 对 Ed25519 证书会报 `provider signature failure`,无法完成 CMS 签名。根 CA 同样统一用 ECDSA P-256:浏览器 WebCrypto 与 CMS 链路对 P-256 的兼容性最好,全链路同曲线也让验签方只需维护一套代码。

**2. 签名产物是裸 CMS 的 DER 结构,不是 S/MIME 文本。**
自己生成签名时要用 `-binary -outform DER`,验签要用 `-binary -inform DER`。`openssl cms` 默认输出 S/MIME 文本包装,浏览器侧无法解析;改成二进制 DER 后,浏览器侧与通用工具链都能直接解析。

**3. 签名必须内嵌 EEC 证书,不要加 `-nocerts`。**
不带证书时验签方只有根证书,会报 `signer certificate not found`。EEC 角色的签名命令保留内嵌证书,验签命令因此只需要根证书即可完成链路校验。

**4. 签发 EEC 时证书扩展要通过 `eec_ext.cnf` 传入。**
[eec_ext.cnf](tool/eec_ext.cnf) 提供 `basicConstraints`、`keyUsage`、`subjectKeyIdentifier`、`authorityKeyIdentifier`。自行签发时扩展也必须走 `-extfile`,因为 `openssl x509 -req` 不支持 `-addext`;这也决定了签发命令必须在能找得到该文件的目录下执行。

**5. 吊销要沿用同一个 CA 工作目录。**
CRL 由 `openssl ca -gencrl` 生成(`openssl crl -gen` 在 OpenSSL 3.x 不可用),因此吊销步骤会在 `./ca_work` 下初始化一套最小 CA 目录(`index.txt`、`serial`、`crlnumber`、`openssl.cnf`)。该目录同时是吊销数据库,重复执行会累积吊销条目。生成的 `openssl.cnf` 里显式写 `default_md = sha512`,CRL 的签名摘要固定为 SHA-512,不随 OpenSSL 默认值漂移。

**6. 作者密钥是 Ed25519,`ssh-keygen` 没有可用的格式互转。**
`ssh-keygen` 的转换只覆盖 RSA、DSA、ECDSA:`ssh-keygen -e -m PKCS8` 对 Ed25519 报 `unsupported key type`,`ssh-keygen -p -m PEM` 对 Ed25519 静默保持 OpenSSH 私有格式,并且 `ssh-keygen -m` 没有 `OPENSSH` 选项。

**7. 作者签名统一用 PEM 交付,不用 OpenSSH 签名格式。**
`ssh-keygen -Y sign` 产出的 `SSHSIG` 格式宿主侧用 `openssl pkeyutl -verify` 校验不了。OpenSSH 仅可用于作者本地自验,不作为分发格式。

**8. 摘要算法显式指定 SHA-512。**
EEC 签名命令与两条验签命令都带 `-md sha512`,生成 CRL 用的 `openssl.cnf` 也显式写 `default_md = sha512`,因此证书、CMS 与 CRL 全链路统一为 SHA-512。省略这两类参数时,摘要算法会随 OpenSSL 版本与密钥类型取默认值,不同环境可能不一致。CRL 的验签方按 CRL 自身声明的签名算法验证,旧 CRL 不需要重签,升级无兼容问题。

**9. Ed25519 在 OpenSSH 与 PEM 之间没有原生互转,本工具集用自建脚本补齐。**
`ssh-keygen` 与 `openssl` 都没有提供这条通道,转换能力由两个 `author_convert_*.py` 自己维护:只支持 Ed25519,私钥带口令时先解密再转换,转换后自动自校验;反向脚本还可以按参数输出带口令的 OpenSSH 私钥。交付给验签方的密钥与签名仍然是 PEM。

**10. 查看私钥的命令会打印私钥内容,只能在本地自查时使用。**
`openssl pkey -noout -text` 会把私钥的各个组成部分直接打到终端,Ed25519 私钥表现为种子与公钥的十六进制。不要在共享终端、录屏、CI 日志、聊天记录或任何会被留存的环境里运行它;只想确认密钥类型与长度时改用 `openssl pkey -in <私钥> -noout -text_pub`,需要公开材料时用 `openssl pkey -in <私钥> -pubout`。

**11. 禁止把空设备写进 openssl 参数,丢弃输出统一用 bash 重定向。**

MSYS / Git Bash 下,argv 里的 `/dev/null` 会被解析成相对名 `nul`,Git 自带的 openssl 把 `nul` 当作当前目录的普通文件;因此 `openssl … -out /dev/null` 会在工作目录留下 `nul` 垃圾文件,验签还可能直接失败。实测(`openssl 3.5.6`):

```console
$ openssl dgst -sha512 /dev/null
nul: No such file or directory
100000000A000000:error:80000002:system library:file_ctrl:No such file or directory:crypto/bio/bss_file.c:299:calling fopen(nul, rb)
```

需要丢弃输出时,只允许把 `/dev/null` 写在 bash 自己的重定向位置,即命令末尾的 `> /dev/null`(`[ -c /dev/null ]` 为真,是字符设备,不产生任何文件);同时禁止 `>nul` 与 `2>nul`,那是 cmd 语义,bash 会生成名为 `nul` 的普通文件。EEC 角色的两条验签命令均按此约定书写并显式回显结论,验签结论一律以退出码为准。

---

## 常见问题

**重复吊销同一张证书。**
`openssl ca -revoke` 会提示 `Already revoked`,这是预期行为;命令不会中断,随后仍会用现有吊销库生成 CRL。

**CRL 条目是否会丢失。**
不会。吊销步骤以 `./ca_work` 下的 `index.txt` 为吊销数据库,只要沿用同一个工作目录,历次吊销都会保留。更换工作目录等于新建一张空白吊销库。

**带吊销检查的验签报 `certificate revoked`。**
说明该 EEC 已在 CRL 中。这是吊销生效的预期结果,不是命令写错。

**签发 EEC 时报找不到 `eec_ext.cnf`。**
说明当前目录不是放有该模板的证书材料目录。`-extfile` 走相对路径,要么切到该目录执行,要么把 `-extfile` 改成绝对路径。

**带口令的私钥转换为什么比较慢。**
OpenSSH 方向要按私钥头部记录的 `rounds` 现算 `bcrypt_pbkdf`,PEM 方向要按 `iterationCount` 现算 `PBKDF2`;脚本里的实现是纯 Python,`rounds` 为 16 上下时一次转换约十几秒,`rounds` 上百时会到分钟级。派生开始前脚本会在 stderr 打出进度提示,期间没有输出是正常的,不要中断进程。

**OpenSSH 与 OpenSSL 的签名能否互验。**
不能。`ssh-keygen -Y sign` 的 `SSHSIG` 与 `openssl pkeyutl -sign` 的裸签名格式不同;Ed25519 密钥本身可以用两个 `author_convert_*.py` 在 OpenSSH 与 PEM 之间互转,但签名格式仍然不通用,所以交付统一使用 OpenSSL PEM 方案。
