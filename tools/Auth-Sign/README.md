# OpenSSL 极简 PKI 工具集

## 概述

这是一套基于 **OpenSSL 3.0+** 的轻量级通用 PKI 工具集,由若干 Shell 脚本与配置文件组成,覆盖自签根证书、证书申请、终端签名证书签发、CMS 分离签名、签名验签、证书吊销列表(CRL)生成与吊销校验全流程;同时额外提供**无证书裸公钥分离签名**模式,不依赖 CA 体系即可完成数据签名与完整性校验。

脚本与配置文件位于本文件同级的 `tool/` 目录,按三组划分:

- **CA 与 EEC 流程**:只使用 `openssl`,证书算法为 ECDSA P-256。
- **作者裸公钥流程**:以 `openssl` 为主,作者密钥为 Ed25519,交付格式统一为 PEM;另有两个 Python 转换脚本,用于把作者已有的 OpenSSH 密钥转成 PEM 或反向转回。
- **通用查询脚本**:只使用 `openssl`,用于在本地查看任意 x509 证书与任意私钥的信息。

全链路摘要算法统一为 SHA-512,不依赖 OpenSSL 默认值:CMS 签名与验签在每条 `openssl cms` 命令里显式写出 `-md sha512`,CRL 的摘要则由 `ca_revoke_and_gen_crl.sh` 生成的 `openssl.cnf` 里显式的 `default_md = sha512` 决定。CRL 的验签方按 CRL 自身声明的签名算法验证,已发布的旧 CRL 仍可正常校验,本次升级不产生兼容问题。

所有脚本为通用工具,不绑定任何具体业务场景;所有带下划线的标识符为占位符,使用前替换为真实文件路径或名称。每个 `.sh` 都可以逐行阅读后按需复制其中的命令;`ca_revoke_and_gen_crl.sh` 含目录初始化与多行配置生成,需要整段执行。

Shell 脚本以 `bash 脚本名` 方式执行,两个 Python 转换脚本以 `python 脚本名` 方式执行。Windows 请在 Git Bash、MSYS2 等 bash 环境中运行,原生 cmd 与 PowerShell 不能直接执行这些 Shell 脚本。

## 前置环境

| 依赖 | 版本要求 | 检查命令 | 适用范围 |
|:---:|:---:|:---:|:---:|
| `openssl` | 3.0 及以上 | `openssl version` | 全部脚本,必需 |
| `openssh` | 8.0 及以上 | `ssh -V` | 仅作者本地自验可选使用,不是分发必需 |
| `python` | 3.8 及以上 | `python --version` | 仅两个 `author_convert_*.py` 转换脚本需要 |

- **全部脚本只依赖 openssl**:`ca_gen_keypair.sh`、`ca_gen_root_cert.sh`、`eec_gen_keypair.sh`、`eec_gen_csr.sh`、`ca_issue_eec.sh`、`eec_sign_file.sh`、`verify_sign_by_eec.sh`、`verify_sign_by_eec_with_crl.sh`、`ca_revoke_and_gen_crl.sh`、`author_openssl_gen_keypair.sh`、`author_openssl_sign_file.sh`、`author_openssl_verify_file.sh`、`see_a_cert_info.sh`、`see_a_pkey_info.sh`。
- **openssh 不是分发必需**:本工具集不提供任何 `ssh-keygen` 脚本。作者若要用 OpenSSH 做本地自验,可自行用 `ssh-keygen` 生成与查看公钥,但交付给验签方的一律是 OpenSSL PEM 格式的密钥与签名。
- **两个转换脚本只依赖 Python 标准库**:`author_convert_openssh_to_openssl.py`、`author_convert_openssl_to_openssh.py` 不需要 `cryptography` 等第三方模块,但要求 `python >= 3.8`;转换后的自校验会调用 `openssl`,环境里存在 `ssh-keygen` 时还会额外用 `ssh-keygen -y`、`ssh-keygen -l` 复核。

> OpenSSL 版本低于 3.0 时,`openssl genpkey`、`openssl cms`、`openssl ca -gencrl` 的行为与本工具集不符,请先升级。

## 算法约定

| 角色 | 密钥算法 | 摘要算法 | 说明 |
|:---:|:---:|:---:|:---:|
| 根 CA | ECDSA P-256 | SHA-512 | `ca_gen_keypair.sh` 固定曲线 |
| EEC | ECDSA P-256 | SHA-512 | `openssl cms -sign` 不支持 Ed25519 证书 |
| 作者 | Ed25519 | SHA-512 | `openssl pkeyutl -rawin` 直接对文件做纯 Ed25519 签名 |
| CRL | ECDSA P-256 | SHA-512 | 由根 CA 私钥签名,摘要取 `openssl.cnf` 里显式的 `default_md = sha512` |

摘要算法在 `eec_sign_file.sh`、`verify_sign_by_eec.sh`、`verify_sign_by_eec_with_crl.sh` 中均以 `-md sha512` 显式指定,CRL 的摘要也由 `ca_revoke_and_gen_crl.sh` 生成的 `openssl.cnf` 里 `default_md = sha512` 显式指定,全链路都不依赖 OpenSSL 默认值,避免默认值随 OpenSSL 版本或密钥类型漂移。

---

## 脚本与文件说明

### 一、CA 与 EEC 流程(只用 openssl)

| 文件 | 使用者 | 用途 | 前置文件 | 占位符与标准后缀 | 产出物 |
|:---:|:---:|:---:|:---:|:---:|:---:|
| `ca_gen_keypair.sh` | 根证书机构 | 生成根 CA 密钥对(ECDSA P-256) | 无 | `_CA_PRIVATE_KEY_` 根私钥,建议 `root_ca_secret`<br>`_CA_PRIVATE_KEY_.pub` 根公钥,建议 `root_ca_secret.pub` | 私钥 `root_ca_secret`、公钥 `root_ca_secret.pub` |
| `ca_gen_root_cert.sh` | 根证书机构 | 生成自签名根证书 | 根 CA 私钥 | `_CA_PRIVATE_KEY_` 根私钥<br>`_CA_CERT_` 根证书,建议 `root_ca.crt`<br>`_YOUR_ORG_NAME_` 组织名称<br>`_YOUR_CA_NAME_` 根 CA 标识名 | 根证书 `root_ca.crt` |
| `eec_gen_keypair.sh` | 证书签名方 | 生成 EEC 密钥对(必须是 ECDSA P-256) | 无 | `_EEC_PRIVATE_KEY_` EEC 私钥,建议 `eec_secret`<br>`_EEC_PRIVATE_KEY_.pub` EEC 公钥,建议 `eec_secret.pub` | 私钥 `eec_secret`、公钥 `eec_secret.pub` |
| `eec_gen_csr.sh` | 证书签名方 | 生成证书签名请求(CSR) | EEC 私钥 | `_EEC_PRIVATE_KEY_` EEC 私钥<br>`_EEC_CSR_` 输出 CSR,建议 `eec.csr`<br>`_YOUR_ORG_NAME_` 组织名称<br>`_YOUR_SIGNER_NAME_` 签名方标识名 | CSR `eec.csr` |
| `ca_issue_eec.sh` | 根证书机构 | 用根证书签发 EEC(扩展走 `-extfile`) | 根证书、根私钥、对方提交的 CSR、`eec_ext.cnf` | `_EEC_CSR_` 输入 CSR<br>`_CA_CERT_` 根证书<br>`_CA_PRIVATE_KEY_` 根私钥<br>`_EEC_CERT_` 输出证书,建议 `eec.crt` | EEC 证书 `eec.crt`、根签发序列号 `root_ca.srl` |
| `eec_sign_file.sh` | 证书签名方 | 对文件生成 CMS 分离签名 | EEC 证书、EEC 私钥、待签名文件 | `_THE_FILENAME_` 待签名文件<br>`_EEC_CERT_` EEC 证书,建议 `eec.crt`<br>`_EEC_PRIVATE_KEY_` EEC 私钥,建议 `eec_secret` | 签名 `<文件名>.sig` |
| `verify_sign_by_eec.sh` | 验签方 | 校验 CMS 证书签名(不检查吊销) | 根证书、签名文件、原始文件 | `_THE_SIGN_FILENAME_` 签名文件,建议 `<文件名>.sig`<br>`_THE_SIGNED_FILENAME_` 原始文件<br>`_CA_CERT_` 根证书,建议 `root_ca.crt` | 验签结果以退出码为准,验签内容被丢弃 |
| `verify_sign_by_eec_with_crl.sh` | 验签方 | 校验 CMS 证书签名并强制检查 CRL 吊销 | 根证书、CRL、签名文件、原始文件 | `_THE_SIGN_FILENAME_` 签名文件<br>`_THE_SIGNED_FILENAME_` 原始文件<br>`_CA_CERT_` 根证书<br>`_CRL_FILENAME_` CRL,建议 `crl.pem`<br>`_CA_CRL_BUNDLE_` 拼接文件,建议 `root_ca_with_crl.pem` | 验签结果以退出码为准(验签内容被丢弃)、拼接文件 `root_ca_with_crl.pem` |
| `ca_revoke_and_gen_crl.sh` | 根证书机构 | 吊销证书并生成 CRL(基于最小 CA 目录) | 根证书、根私钥、待吊销证书、`crl.conf` | `_CA_WORK_DIR_` CA 工作目录,建议 `./ca_work`<br>`_CA_CERT_` 根证书<br>`_CA_PRIVATE_KEY_` 根私钥<br>`_CRL_CONF_FILENAME_` CRL 扩展配置,建议 `crl.conf`<br>`_EEC_CERT_` 待吊销证书,建议 `eec.crt`<br>`_THE_REASON_VALUE_` 吊销原因<br>`_CRL_FILENAME_` 输出 CRL,建议 `crl.pem`<br>`_HOW_LONG_` CRL 有效期(天) | CRL `crl.pem`、CA 工作目录 `ca_work/`(含 `index.txt`、`serial`、`crlnumber`、`openssl.cnf`) |

`_THE_REASON_VALUE_` 可选值:`unspecified`(不透露原因)、`keyCompromise`(私钥泄露或怀疑泄露)、`affiliationChanged`(组织变更)、`superseded`(已更换新证书)、`cessationOfOperation`(关系终止)、`certificateHold`。

### 二、作者裸公钥流程(openssl 与 Python 标准库,Ed25519)

| 文件 | 使用者 | 依赖 | 用途 | 前置文件 | 占位符与标准后缀 | 产出物 |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `author_openssl_gen_keypair.sh` | 独立签名方 | openssl | 生成作者密钥对(Ed25519) | 无 | `_AUTHOR_PRIVATE_KEY_` 作者私钥,建议 `author_secret` | 私钥 `author_secret`、公钥 `author_secret.pub` |
| `author_openssl_sign_file.sh` | 独立签名方 | openssl | 用私钥对文件生成裸公钥签名 | 作者私钥、待签名文件 | `_AUTHOR_PRIVATE_KEY_` 作者私钥<br>`_DATA_FILE_` 待签名文件 | 签名 `<文件名>.sig` |
| `author_openssl_verify_file.sh` | 验签方 | openssl | 用公钥校验裸公钥签名 | 作者公钥、原始文件、签名文件 | `_AUTHOR_PUBLIC_KEY_` 作者公钥,建议 `author_secret.pub`<br>`_DATA_FILE_` 原始文件 | 控制台验签结果 |
| `author_convert_openssh_to_openssl.py` | 已有 OpenSSH 密钥的作者 | python >= 3.8<br>openssl | 把 OpenSSH 格式的 Ed25519 私钥或公钥转成 OpenSSL PEM | 无 | `_OPENSSH_PRIVATE_KEY_` OpenSSH 私钥,建议 `id_ed25519`<br>`_OPENSSH_PUBLIC_KEY_` OpenSSH 公钥,建议 `id_ed25519.pub`<br>`_AUTHOR_PRIVATE_KEY_` 输出私钥,建议 `author_secret`<br>`_AUTHOR_PUBLIC_KEY_` 输出公钥,建议 `author_secret.pub` | PKCS#8 私钥 `author_secret`、SPKI 公钥 `author_secret.pub` |
| `author_convert_openssl_to_openssh.py` | 已有 PEM 密钥的作者 | python >= 3.8<br>openssl<br>openssh(仅自校验) | 把 OpenSSL PEM 格式的 Ed25519 私钥或公钥转成 OpenSSH | 无 | `_AUTHOR_PRIVATE_KEY_` PEM 私钥,建议 `author_secret`<br>`_AUTHOR_PUBLIC_KEY_` PEM 公钥,建议 `author_secret.pub`<br>`_OPENSSH_PRIVATE_KEY_` 输出私钥,建议 `id_ed25519`<br>`_OPENSSH_PUBLIC_KEY_` 输出公钥,建议 `id_ed25519.pub` | openssh-key-v1 私钥 `id_ed25519`、`ssh-ed25519` 公钥 `id_ed25519.pub` |

#### 为什么 ssh-keygen 转不了 Ed25519,为什么用标准库 Python,为什么只支持无口令密钥

**`ssh-keygen` 的格式转换对 Ed25519 完全不可用。** 两条命令都拿不到 PEM,已实测:

```console
$ ssh-keygen -e -m PKCS8 -f id_ed25519.pub
do_convert_to_pkcs8: unsupported key type ED25519

$ ssh-keygen -p -m PKCS8 -f id_ed25519
(命令报告成功,但文件仍是 -----BEGIN OPENSSH PRIVATE KEY-----,openssl 依然读不了)
```

`ssh-keygen -m` 只接受 `RFC4716`、`PKCS8`、`PEM`(部分版本还有 `hexdump`),不存在 `-m OPENSSH` 选项,反向同样没有入口。既然工具链不给路,就按格式规范自己写:`openssh-key-v1` 与 RFC 8410 的 PKCS#8、SPKI 都是结构固定的公开二进制格式,转换只是重排容器、搬运同一串 32 字节种子与公钥,不涉及任何密码学运算。

**用标准库 Python 而不是 `cryptography`。** 转换本身不需要密码学运算,真正需要判断的地方直接调用环境里已有的 `openssl`;不引入 pip 依赖与编译轮子,只用标准库的脚本可以原样复制到任何一台有 Python 的机器上运行,与本工具集"每个脚本可独立复制使用"的风格一致。

**只支持无口令私钥。** 带口令的 OpenSSH 私钥用 `bcrypt_pbkdf` 派生密钥、再用 `aes256-ctr` 等分组密码加密,标准库没有 `bcrypt_pbkdf`,自己实现既不划算也容易出错。遇到 `cipher` 不是 `none` 的私钥,转换脚本直接报错并提示先用 `ssh-keygen -p -N ""` 去掉口令,不会静默产出错误结果。

转换脚本都带自校验,任何一步不通过就以非零退出码结束,且不留半成品文件:OpenSSH 转 PEM 时,产出的 PEM 必须能被 `openssl pkey -in <文件> -noout` 读通,且由它派生的公钥与 OpenSSH 私钥内嵌的公钥一致;PEM 转 OpenSSH 时,产出的私钥会被回读比对种子与公钥,环境里有 `ssh-keygen` 时再用 `ssh-keygen -y` 反推公钥比一次。

```bash
python author_convert_openssh_to_openssl.py id_ed25519 -o author_secret            # 私钥:OpenSSH -> PKCS#8
python author_convert_openssh_to_openssl.py id_ed25519.pub -o author_secret.pub    # 公钥:OpenSSH -> SPKI
python author_convert_openssl_to_openssh.py author_secret -o id_ed25519            # 私钥:PKCS#8 -> OpenSSH
python author_convert_openssl_to_openssh.py author_secret.pub -o id_ed25519.pub    # 公钥:SPKI -> ssh-ed25519
```

不给 `-o` 时输出到 `<输入文件>.converted`。

**交付格式仍然是 PEM。** `ssh-keygen -Y sign` 产出的 `SSHSIG` 宿主侧用 `openssl pkeyutl -verify` 校验不了,所以 OpenSSH 只用于作者本地自验,不作为分发格式;转换脚本只解决"作者手上已有 OpenSSH 密钥"的兼容问题,交付给验签方的依然是 PEM 密钥与 PEM 签名。

### 三、通用查询脚本(只用 openssl)

| 文件 | 使用者 | 依赖 | 用途 | 前置文件 | 占位符与标准后缀 | 产出物 |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `see_a_cert_info.sh` | 任意一方 | openssl | 查看任意 x509 证书的基础信息(序列号、签发者、主体、有效期)与完整信息 | 待查看的证书 | `_THE_CA_CERT_FILENAME_` 证书文件,建议 `root_ca.crt` | 控制台输出 |
| `see_a_pkey_info.sh` | 任意一方 | openssl | 查看任意私钥的信息(输出含私钥内容,仅限本地自查) | 待查看的私钥 | `_THE_PRIVATE_KEY_FILENAME_` 私钥文件,建议 `root_ca_secret` | 控制台输出 |

### 四、配置文件

| 文件 | 使用者 | 用途 | 占位符 |
|:---:|:---:|:---:|:---:|
| `crl.conf` | 根证书机构 | CRL 扩展配置,`ca_revoke_and_gen_crl.sh` 生成的 `openssl.cnf` 通过 `.include` 引用 | 无 |
| `eec_ext.cnf` | 根证书机构 | EEC 扩展配置,`ca_issue_eec.sh` 通过 `-extfile` 引用 | 无 |

> `eec_ext.cnf` 由脚本按 `$(dirname "$0")` 定位,与脚本放在同一目录即可;`crl.conf` 的路径由 `_CRL_CONF_FILENAME_` 指定,不放在工作目录下时请写绝对路径。

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
不带证书时验签方只有根证书,会报 `signer certificate not found`。`eec_sign_file.sh` 保留内嵌证书,`verify_sign_by_eec.sh` 因此只需要根证书即可完成链路校验。

**4. 签发 EEC 时证书扩展要通过 `eec_ext.cnf` 传入。**
`eec_ext.cnf` 提供 `basicConstraints`、`keyUsage`、`subjectKeyIdentifier`、`authorityKeyIdentifier`。自行签发时扩展也必须走 `-extfile`,因为 `openssl x509 -req` 不支持 `-addext`。

**5. 吊销要沿用同一个 CA 工作目录。**
CRL 由 `openssl ca -gencrl` 生成(`openssl crl -gen` 在 OpenSSL 3.x 不可用),因此 `ca_revoke_and_gen_crl.sh` 会在 `_CA_WORK_DIR_` 下初始化一套最小 CA 目录(`index.txt`、`serial`、`crlnumber`、`openssl.cnf`)。该目录同时是吊销数据库,重复执行会累积吊销条目。生成的 `openssl.cnf` 里显式写 `default_md = sha512`,CRL 的签名摘要固定为 SHA-512,不随 OpenSSL 默认值漂移。

**6. 作者密钥是 Ed25519,`ssh-keygen` 没有可用的格式互转。**
`ssh-keygen` 的转换只覆盖 RSA、DSA、ECDSA:`ssh-keygen -e -m PKCS8` 对 Ed25519 报 `unsupported key type`,`ssh-keygen -p -m PEM` 对 Ed25519 静默保持 OpenSSH 私有格式,并且 `ssh-keygen -m` 没有 `OPENSSH` 选项。

**7. 作者签名统一用 PEM 交付,不用 OpenSSH 签名格式。**
`ssh-keygen -Y sign` 产出的 `SSHSIG` 格式宿主侧用 `openssl pkeyutl -verify` 校验不了。OpenSSH 仅可用于作者本地自验,不作为分发格式。

**8. 摘要算法显式指定 SHA-512。**
`eec_sign_file.sh`、`verify_sign_by_eec.sh`、`verify_sign_by_eec_with_crl.sh` 都带 `-md sha512`,`ca_revoke_and_gen_crl.sh` 生成的 `openssl.cnf` 也显式写 `default_md = sha512`,因此证书、CMS 与 CRL 全链路统一为 SHA-512。省略这两类参数时,摘要算法会随 OpenSSL 版本与密钥类型取默认值,不同环境可能不一致。CRL 的验签方按 CRL 自身声明的签名算法验证,旧 CRL 不需要重签,升级无兼容问题。

**9. Ed25519 在 OpenSSH 与 PEM 之间没有原生互转,本工具集用自建脚本补齐。**
`ssh-keygen` 与 `openssl` 都没有提供这条通道,转换能力由 `author_convert_openssh_to_openssl.py` 与 `author_convert_openssl_to_openssh.py` 自己维护:只支持 Ed25519、只支持无口令私钥,转换后自动自校验。交付给验签方的密钥与签名仍然是 PEM。

**10. `see_a_pkey_info.sh` 会打印私钥内容,只能在本地自查时使用。**
`openssl pkey -noout -text` 会把私钥的各个组成部分直接打到终端,Ed25519 私钥表现为种子与公钥的十六进制。不要在共享终端、录屏、CI 日志、聊天记录或任何会被留存的环境里运行它;只想确认密钥类型与长度时改用 `openssl pkey -in <私钥> -noout -text_pub`,需要公开材料时用 `openssl pkey -in <私钥> -pubout`。

**11. 禁止把空设备写进 openssl 参数,丢弃输出统一用 bash 重定向。**

MSYS / Git Bash 下,argv 里的 `/dev/null` 会被解析成相对名 `nul`,Git 自带的 openssl 把 `nul` 当作当前目录的普通文件;因此 `openssl ... -out /dev/null` 会在工作目录留下 `nul` 垃圾文件,验签还可能直接失败。实测(`openssl 3.5.6`):

```console
$ openssl dgst -sha512 /dev/null
nul: No such file or directory
100000000A000000:error:80000002:system library:file_ctrl:No such file or directory:crypto/bio/bss_file.c:299:calling fopen(nul, rb)
```

需要丢弃输出时,只允许把 `/dev/null` 写在 bash 自己的重定向位置,即命令末尾的 `> /dev/null`(`[ -c /dev/null ]` 为真,是字符设备,不产生任何文件);同时禁止 `>nul` 与 `2>nul`,那是 cmd 语义,bash 会生成名为 `nul` 的普通文件。`verify_sign_by_eec.sh` 与 `verify_sign_by_eec_with_crl.sh` 均按此约定书写并显式回显结论,验签结论一律以退出码为准。

---

## 角色视角流程

### 根证书机构视角

作为整个体系的信任锚,你持有根 CA 私钥与根证书,负责为可信主体签发终端签名证书,校验基于证书的数字签名,并在必要时对证书执行吊销管理。以下步骤只用 `openssl`。

**第一步:搭建根信任锚**

```bash
bash ca_gen_keypair.sh      # _CA_PRIVATE_KEY_ = root_ca_secret,_CA_PRIVATE_KEY_.pub = root_ca_secret.pub
bash ca_gen_root_cert.sh    # _CA_PRIVATE_KEY_ = root_ca_secret,_CA_CERT_ = root_ca.crt
```

根证书作为全局信任锚公开分发,根私钥需严格安全保管。

**第二步:签发终端签名证书**

```bash
bash ca_issue_eec.sh        # _EEC_CSR_ = eec.csr,_CA_CERT_ = root_ca.crt,_CA_PRIVATE_KEY_ = root_ca_secret,_EEC_CERT_ = eec.crt
```

接收申请方提交的 CSR,用根私钥签发 EEC。证书扩展由 `eec_ext.cnf` 限定为 "仅数字签名、不可签发下级证书"。签发完成后把 `eec.crt` 返回给申请方。

**第三步:校验证书签名**

```bash
bash verify_sign_by_eec.sh  # _THE_SIGN_FILENAME_ = plugin.zip.sig,_THE_SIGNED_FILENAME_ = plugin.zip,_CA_CERT_ = root_ca.crt
```

确认 EEC 由本 CA 签发、未过期、用途合规,同时确认签名与文件内容匹配。需要吊销校验时改用 `verify_sign_by_eec_with_crl.sh`,额外加载最新 `crl.pem`。

**第四步:证书吊销管理**

```bash
bash ca_revoke_and_gen_crl.sh   # _EEC_CERT_ = eec.crt,_CRL_FILENAME_ = crl.pem,_CA_WORK_DIR_ = ./ca_work
```

出现私钥泄露、权限终止、证书替换等情况时,把对应证书纳入吊销库并生成新版 CRL。CA 工作目录保持不变即可累积吊销条目;需要吊销多张证书时重复执行,或把 `-revoke` 行复制多份。

### 证书签名方视角

作为经根证书机构授权的签名主体,你持有自身私钥与根 CA 签发的 EEC,负责对业务文件生成可通过信任链核验的数字签名。

**第一步:生成自身密钥对**

```bash
bash eec_gen_keypair.sh     # _EEC_PRIVATE_KEY_ = eec_secret,_EEC_PRIVATE_KEY_.pub = eec_secret.pub
```

密钥类型固定为 ECDSA P-256,私钥由己方严格保密,不得对外提供;公钥 `eec_secret.pub` 属于公开材料,可随 CSR 一并提交或单独分发。

**第二步:申请签名证书**

```bash
bash eec_gen_csr.sh         # _EEC_PRIVATE_KEY_ = eec_secret,_EEC_CSR_ = eec.csr
```

CSR 仅包含公钥与身份信息,不含私钥,提交给根证书机构。

**第三步:接收并保存证书**

收到 `eec.crt` 后与本地 `eec_secret` 配套保存。证书可公开出示,私钥仅限签名操作使用。

**第四步:对文件生成签名**

```bash
bash eec_sign_file.sh       # _THE_FILENAME_ = plugin.zip,_EEC_CERT_ = eec.crt,_EEC_PRIVATE_KEY_ = eec_secret
```

生成 `plugin.zip.sig` 后与原始文件一并提交给验签方。签名内嵌 EEC 证书,验签方只需根证书即可完成校验。

### 独立签名方视角

你不接入证书体系,不向根证书机构申请证书,仅通过自身持有的密钥对完成裸公钥签名;公钥的真实性由验签方自行确认,签名仅用于证明数据来源与完整性。

**第一步:生成独立密钥对**

```bash
bash author_openssl_gen_keypair.sh   # _AUTHOR_PRIVATE_KEY_ = author_secret
```

作者密钥为 Ed25519:私钥是 PEM 编码的 PKCS#8,公钥是 PEM 编码的 SPKI。作者需选定这一套工具链并一直使用,不要与 OpenSSH 混用;手上已有 OpenSSH 密钥的作者可以先用 `author_convert_openssh_to_openssl.py` 转成 PEM,再走这套流程。

**第二步:对目标文件签名**

```bash
bash author_openssl_sign_file.sh    # _AUTHOR_PRIVATE_KEY_ = author_secret,_DATA_FILE_ = plugin.zip
```

`openssl pkeyutl -sign -rawin` 对 Ed25519 是把整个文件送入纯 Ed25519 签名(PureEdDSA,内部摘要固定 SHA-512),不额外做外部摘要,签名固定 64 字节。

**第三步:交付校验材料**

把原始文件、签名文件、自身公钥一并交给验签方。验签方确认公钥归属后校验:

```bash
bash author_openssl_verify_file.sh  # _AUTHOR_PUBLIC_KEY_ = author_secret.pub,_DATA_FILE_ = plugin.zip
```

> 裸公钥签名体系不依赖 CA、无证书、无标准吊销机制。作者公钥的真实性由验签方自行确认,签名仅用于证明数据来源与完整性。

---

## 常见问题

**重复吊销同一张证书。**
`openssl ca -revoke` 会提示 `Already revoked`,这是预期行为;脚本不会中断,随后仍会用现有吊销库生成 CRL。

**CRL 条目是否会丢失。**
不会。`ca_revoke_and_gen_crl.sh` 以 `_CA_WORK_DIR_` 下的 `index.txt` 为吊销数据库,只要沿用同一个工作目录,历次吊销都会保留。更换工作目录等于新建一张空白吊销库。

**`verify_sign_by_eec_with_crl.sh` 报 `certificate revoked`。**
说明该 EEC 已在 CRL 中。这是吊销生效的预期结果,不是脚本错误。

**OpenSSH 与 OpenSSL 的签名能否互验。**
不能。`ssh-keygen -Y sign` 的 `SSHSIG` 与 `openssl pkeyutl -sign` 的裸签名格式不同;Ed25519 密钥本身可以用 `author_convert_*` 两个脚本在 OpenSSH 与 PEM 之间互转,但签名格式仍然不通用,所以交付统一使用 OpenSSL PEM 方案。
