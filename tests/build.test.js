// The release build: reproducible bytes, and a zip that holds exactly the tested source files.
// SPDX-License-Identifier: MIT
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync, mkdtempSync, rmSync } = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');
const { createHash } = require('node:crypto');
const { pathToFileURL } = require('node:url');

const ROOT = join(__dirname, '..');
const load = () => import(pathToFileURL(join(ROOT, 'tools', 'build.mjs')).href);

test('two builds produce identical bytes, and the zip holds exactly the source files', async () => {
  const B = await load();
  const a = B.build(mkdtempSync(join(tmpdir(), 'ma-a-'))), b = B.build(mkdtempSync(join(tmpdir(), 'ma-b-')));
  try {
    assert.ok(a.zip.equals(b.zip));
    assert.deepEqual(a.manifest, b.manifest);
    assert.equal(B.verifyZip(a.zip), B.ZIP_FILES.length + 1);
    const entries = Object.keys(B.readZip(a.zip));
    assert.deepEqual(entries, [B.ZIP_DIR, ...B.ZIP_FILES.map(f => B.ZIP_DIR + f)]);
    for (const f of B.SITE_FILES) assert.ok(readFileSync(join(a.outDir, 'site', f)).equals(readFileSync(join(ROOT, f))), f);
    const sums = readFileSync(join(a.outDir, 'SHA256SUMS.txt'), 'utf8');
    assert.equal(sums, `${createHash('sha256').update(a.zip).digest('hex')}  ${B.ZIP_NAME}\n`);
  } finally { rmSync(a.outDir, { recursive: true, force: true }); rmSync(b.outDir, { recursive: true, force: true }); }
});

test('the zip is named for the version and holds only what is needed to run it', async () => {
  const B = await load();
  const { VERSION } = require('../mailanalyzer-core.js');
  assert.equal(B.ZIP_NAME, `MailAnalyzer-v${VERSION}.zip`);
  assert.deepEqual(B.ZIP_FILES, ['index.html', 'mailanalyzer-core.js', 'app.js', 'LICENSE', 'README.md']);
});

test('a changed byte in a packaged file is caught', async () => {
  const B = await load();
  const out = B.build(mkdtempSync(join(tmpdir(), 'ma-c-')));
  try {
    const zip = Buffer.from(out.zip);
    const at = zip.indexOf(Buffer.from('<!doctype html>'));
    zip[at + 2] = 'D'.charCodeAt(0);
    assert.throws(() => B.verifyZip(zip), /CRC mismatch|differs/);
  } finally { rmSync(out.outDir, { recursive: true, force: true }); }
});
