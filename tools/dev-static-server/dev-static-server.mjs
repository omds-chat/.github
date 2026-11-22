/**
 * 本地静态服务器：把某个目录按原样发布到本地回环，供联调时各仓库产物互相取件。
 * 只监听 127.0.0.1，不做目录遍历防护之外的处理，不参与 CI 与生产。
 */
import { createServer } from 'node:http'
import { stat, readFile } from 'node:fs/promises'
import { extname, join, normalize, resolve } from 'node:path'

const DEFAULT_PORT = 61118
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.crt': 'application/x-pem-file',
  '.pem': 'application/x-pem-file',
  '.sig': 'application/octet-stream',
  '.txt': 'text/plain; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
}

const args = process.argv.slice(2)
const readArg = (name, fallback) => {
  const i = args.indexOf(name)
  return i >= 0 && args[i + 1] !== undefined ? args[i + 1] : fallback
}

const root = resolve(readArg('--dir', '.'))
const port = Number(readArg('--port', String(DEFAULT_PORT)))
const host = readArg('--host', '127.0.0.1')

const safePath = (urlPath) => {
  const decoded = decodeURIComponent(urlPath.split('?')[0].split('#')[0])
  const target = normalize(join(root, decoded))
  return target.startsWith(root) ? target : null
}

const server = createServer(async (req, res) => {
  const send = (status, body, headers = {}) => {
    res.writeHead(status, { 'Access-Control-Allow-Origin': '*', ...headers })
    res.end(body)
  }
  try {
    let target = safePath(req.url || '/')
    if (target === null) {
      send(403, 'forbidden')
      return
    }
    let info = await stat(target).catch(() => null)
    if (info?.isDirectory()) {
      target = join(target, 'index.html')
      info = await stat(target).catch(() => null)
    }
    if (!info?.isFile()) {
      send(404, 'not found')
      return
    }
    const body = await readFile(target)
    send(200, body, {
      'Content-Type': MIME[extname(target).toLowerCase()] || 'application/octet-stream',
      'Cache-Control': 'no-store',
      'Content-Length': String(body.byteLength),
    })
  } catch (error) {
    send(500, 'internal error: ' + (error instanceof Error ? error.message : String(error)))
  }
})

server.listen(port, host, () => {
  process.stdout.write('静态服务器 http://' + host + ':' + port + '/ -> ' + root + '\n')
})
