// Serves the built site (dist/site/) under /mailanalyzer/, the path it has on radmagelabs.com and GitHub Pages,
// so the tests catch any asset path that only works at the domain root. Everything else is a 404.
//
//   node tools/serve.mjs [--port 4174]
//
// SPDX-License-Identifier: MIT
import { createServer } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'site');
const PREFIX = '/mailanalyzer/';
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };
const i = process.argv.indexOf('--port'), PORT = i > 0 ? Number(process.argv[i + 1]) : 4174;

createServer((req, res) => {
  const path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (path === '/mailanalyzer') { res.writeHead(301, { location: PREFIX }); return res.end(); }
  const name = path === PREFIX ? 'index.html' : path.startsWith(PREFIX) ? path.slice(PREFIX.length) : '';
  const file = name && !name.includes('/') && !name.includes('..') ? join(ROOT, name) : '';
  const type = TYPES[name.slice(name.lastIndexOf('.'))];
  if (!file || !type || !existsSync(file)) { res.writeHead(404, { 'content-type': 'text/plain' }); return res.end('not found'); }
  res.writeHead(200, { 'content-type': type, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(readFileSync(file));
}).listen(PORT, '127.0.0.1', () => console.log(`MailAnalyzer at http://127.0.0.1:${PORT}${PREFIX}`));
