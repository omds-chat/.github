# 本地 npm registry 模拟器

联调用具:零依赖 Node http 服务器,在本地回环模拟 npm registry 的查询、发布与下架,供各合集仓库的收录校验(npm 包名强校验)离线走通。它不是 npm registry 的实现,不实现 tarball 与认证,不对外监听(只绑 127.0.0.1)。

## 一、启动

| 命令 | 说明 |
|:---:|:---|
| `node tools/npm-registry-mock/npm-registry-mock.mjs` | 默认端口 61123 |
| `node tools/npm-registry-mock/npm-registry-mock.mjs --port <端口>` | 自定端口 |

## 二、端点

| 端点 | 语义 |
|:---:|:---|
| `GET /<包名>` | 返回 registry 元数据文档(name、versions、dist-tags);无记录返回 npm 风格 404 |
| `PUT /<包名>` | 模拟发布,body 为 `{version, shasum?}`;shasum 缺省按包名与版本计算,重复版本覆盖更新 |
| `DELETE /<包名>/<版本>` | 模拟下架;最后一版下架后整包回到 404 |
| `GET /__health` | 健康检查,返回已登记包数 |

数据存 `packages/` 目录(不入库)。

## 三、与收录校验的配合

各合集仓库的 `NPM_REGISTRY_URL` 环境变量(或 `.env`)指向本模拟器(默认 `http://127.0.0.1:61123/`),`verify-catalog`、`verify-collection` 与 `preflight` 即离线查询;变量缺省时脚本回落官方源。收录时序的两种联调场景(先收录后发布、先发布后收录)与完整命令见 awesome-dsc-plugin README 的「离线联调 npm 校验」节。

## 四、边界

本模拟器属联调用具:CI 不使用,生产校验不经它,哈希只作占位比对不作安全承诺。
