# 本地静态服务器

联调用具：把某个目录按原样发布到本地回环，供各仓库产物在联调时互相取件。只监听回环，不参与 CI 与生产。

## 启动

| 命令 | 说明 |
|:---:|:---|
| `node tools/dev-static-server/dev-static-server.mjs --dir <目录> --port <端口>` | 默认端口 61118、默认监听 127.0.0.1 |
| `node tools/dev-static-server/dev-static-server.mjs --dir <目录> --host 0.0.0.0 --port <端口>` | 需要局域网访问时显式指定主机 |

## 行为

- 请求路径相对服务根目录解析，越出根目录一律 403。
- 目录请求回落 `index.html`。
- 所有响应带 `Access-Control-Allow-Origin: *`，插件与资产市场按跨源取件。
- 响应不缓存（`no-store`），改完产物刷新即可看到。

## 联调端口

| 端口 | 服务内容 |
|:---:|:---|
| 61116 | 本地 npm registry 模拟器（见 tools/dev-local-npmjs） |
| 61117 | 主线开发服务器（由主线自己的 `pnpm dev` 提供，不用本工具） |
| 61118 | 内部插件合集 `dist/` |
| 61119 | 社区插件合集 `dist/pages/` |
| 61120 | 内部资产合集 `dist/` |
| 61121 | 社区资产合集 `dist/` |
| 61122 | 资产作者站点（社区资产合集 site 产物） |
