// Local dev server: serves ./public and runs the /api functions, with the same
// headers as vercel.json. No dependencies. Usage: npm run dev
import http from 'node:http';
import { existsSync, readFileSync } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const publicDir = path.join(root, 'public');
loadEnv(path.join(root, '.env'));

const PORT = Number(process.env.PORT) || 3000;
const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};
const vercelHeaders = JSON.parse(readFileSync(path.join(root, 'vercel.json'), 'utf8')).headers?.[0]?.headers || [];

http
  .createServer(async (req, res) => {
    for (const { key, value } of vercelHeaders) res.setHeader(key, value);
    const url = new URL(req.url, 'http://localhost');
    try {
      if (url.pathname.startsWith('/api/')) {
        const name = url.pathname.slice('/api/'.length).replace(/[^a-z0-9-]/gi, '');
        const file = path.join(root, 'api', `${name}.js`);
        if (!name || !existsSync(file)) return notFound(res);
        const { default: handler } = await import(pathToFileURL(file).href);
        return await handler(req, res);
      }
      let file = path.normalize(path.join(publicDir, decodeURIComponent(url.pathname)));
      if (!file.startsWith(publicDir)) return notFound(res);
      if ((await stat(file).catch(() => null))?.isDirectory()) file = path.join(file, 'index.html');
      const body = await readFile(file).catch(() => null);
      if (!body) return notFound(res);
      res.setHeader('Content-Type', TYPES[path.extname(file)] || 'application/octet-stream');
      res.end(body);
    } catch (err) {
      console.error(err);
      res.statusCode = 500;
      res.end('Internal error');
    }
  })
  .listen(PORT, () => console.log(`Phish-Catch running at http://localhost:${PORT}`));

function notFound(res) {
  res.statusCode = 404;
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.end('Not found');
}

function loadEnv(file) {
  if (!existsSync(file)) return;
  for (const line of readFileSync(file, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/i);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^(['"])(.*)\1$/, '$2');
  }
}
