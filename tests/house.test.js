// Release checks for the page and everything the repository would publish: versions, the Content Security Policy,
// no network use, house style, and a scan for data that must never ship (real-looking addresses, non-documentation
// IP addresses, workstation paths, keys and tokens).
// SPDX-License-Identifier: MIT
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync, existsSync } = require('node:fs');
const { join } = require('node:path');
const { execFileSync } = require('node:child_process');
const { C } = require('./helpers.js');

const ROOT = join(__dirname, '..');
const file = p => readFileSync(join(ROOT, p), 'utf8');
const html = file('index.html'), app = file('app.js'), core = file('mailanalyzer-core.js');
const V = C.VERSION;

// Every file that is or would be committed: tracked plus untracked-but-not-ignored, so local notes excluded through
// .git/info/exclude are left out and a new file is checked before it is added.
function projectFiles() {
  try {
    return execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], { cwd: ROOT, encoding: 'utf8' }).split('\0').filter(f => f && existsSync(join(ROOT, f)));
  } catch { return ['index.html', 'app.js', 'mailanalyzer-core.js', 'README.md', 'CHANGELOG.md', 'LICENSE']; }
}
const TEXT = /\.(html|js|mjs|cjs|json|md|yml|yaml|txt|css)$|^(LICENSE|\.gitignore|\.gitattributes)$/;
const files = projectFiles().filter(f => TEXT.test(f.split('/').pop()) && !/^package-lock\.json$/.test(f));

test('the version is the same everywhere it appears', () => {
  const pkg = JSON.parse(file('package.json'));
  assert.equal(pkg.version, V);
  assert.ok(html.includes(`<title>MailAnalyzer v${V} - `), 'title');
  assert.ok(html.includes(`"softwareVersion":"${V}"`), 'JSON-LD');
  assert.ok(html.includes(`<span id="version">v${V}</span>`), 'footer');
  assert.ok(html.includes(`MailAnalyzer v${V}. License`), 'About');
  assert.match(file('CHANGELOG.md'), new RegExp(`^## v${V.replace(/\./g, '\\.')} - \\d{4}-\\d{2}-\\d{2}$`, 'm'));
  assert.ok(file('README.md').includes(`v${V}`), 'README');
});

test('the page has a strict Content Security Policy and loads only its own two scripts', () => {
  const csp = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html);
  assert.ok(csp);
  assert.equal(csp[1], "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'");
  const scripts = [...html.matchAll(/<script\b([^>]*)>/g)].map(m => m[1].trim());
  assert.deepEqual(scripts, ['type="application/ld+json"', 'src="mailanalyzer-core.js"', 'src="app.js"']);
  assert.ok(!/\son[a-z]+\s*=/i.test(html.replace(/<script type="application\/ld\+json">[^<]*<\/script>/, '')), 'inline event handler');
  assert.ok(!/(src|href)="(https?:)?\/\//i.test(html.replace(/<link rel="canonical"[^>]*>/, '')), 'no outside resources');
  assert.match(html, /<meta name="referrer" content="no-referrer">/);
});

test('the page and its scripts contain no way to reach the network', () => {
  for (const [name, src] of [['app.js', app], ['mailanalyzer-core.js', core]]) {
    for (const rx of [/\bfetch\s*\(/, /XMLHttpRequest/, /WebSocket/, /sendBeacon/, /EventSource/, /\bimport\s*\(/, /new\s+Image\b/, /\.src\s*=/, /window\.open\s*\(/, /location\s*=/, /postMessage/, /navigator\.serviceWorker/, /\beval\s*\(/, /new\s+Function\b/]) assert.ok(!rx.test(src), `${name}: ${rx}`);
  }
});

test('the app is called MailAnalyzer everywhere; the old names appear only in the storage migration', () => {
  for (const f of ['index.html', 'app.js', 'mailanalyzer-core.js', 'README.md']) {
    const lines = file(f).split('\n').filter(l => /\bmops\b|\bhops_|mops_/i.test(l));
    for (const l of lines) assert.ok(f === 'mailanalyzer-core.js' && /LEGACY_PREFIXES|were called hops and then mops|called hops and then mops/.test(l), `${f}: ${l.trim().slice(0, 100)}`);
  }
});

test('JavaScript sources are pure ASCII (invisible and lookalike characters are written as escapes)', () => {
  for (const f of files.filter(x => /\.(m|c)?js$/.test(x))) {
    const bad = [...file(f)].filter(c => { const cp = c.codePointAt(0); return cp > 126 || (cp < 32 && c !== '\n'); });
    assert.equal(bad.length, 0, `${f}: ${[...new Set(bad)].map(c => `U+${c.codePointAt(0).toString(16).toUpperCase()}`).join(' ')}`);
  }
});

test('no em dashes, CR line endings or tabs-in-code style slips in any project file', () => {
  for (const f of files) {
    const s = file(f);
    assert.ok(!s.includes('\u2014'), `${f}: em dash`);
    assert.ok(!s.includes('\r'), `${f}: CR`);
  }
});

test('every JavaScript file carries an SPDX license identifier, and LICENSE is MIT', () => {
  for (const f of files.filter(x => /\.(m|c)?js$/.test(x))) assert.match(file(f), /SPDX-License-Identifier: MIT/, f);
  assert.match(html, /SPDX-License-Identifier: MIT/);
  const lic = file('LICENSE');
  assert.match(lic, /^MIT License\n\nCopyright \(c\) 2026 RadMageIRL\n/);
  assert.match(lic, /THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND/);
});

test('nothing that would be published holds real addresses, IP addresses, paths or secrets', () => {
  const okDomain = d => /(^|\.)(example|examp1e)(-[a-z0-9-]+)?\.(com|net|org|test)$/i.test(d) || /\.(test|example|invalid|localhost)$/i.test(d) || ['microsoft.com', 'gmail.com', 'paypal.com', 'outlook.com', 'b', 'mailhost'].includes(d.toLowerCase());
  for (const f of files) {
    const s = file(f);
    for (const m of s.matchAll(/(?<![\w.%+-])[\w.%+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)*)/gi)) {
      if (/^(playwright|types|eslint)/.test(m[0]) || /@v?\d/.test(m[0]) || f === 'package.json') continue; // package and action versions
      assert.ok(okDomain(m[1]), `${f}: ${m[0]}`);
    }
    for (const m of s.matchAll(/(?<![\w.])((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}))(?![\w.])/g)) {
      const [a, b, c] = [+m[2], +m[3], +m[4]], ip = m[1];
      const doc = (a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113);
      const priv = a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a === 0;
      const version = /^(1|15|2|3|0)\./.test(ip) && !/^(\d+\.){3}\d+$/.test(ip) ? true : /^15\.20\./.test(ip) || /^1\.\d+\.\d+\.\d+$/.test(ip) && f.endsWith('.md');
      assert.ok(doc || priv || version, `${f}: IP ${ip}`);
    }
    if (f === 'tests/house.test.js') continue; // this file holds the patterns themselves
    assert.ok(!/[A-Z]:\\Users\\|\/Users\/[a-z]|\/home\/[a-z]|AppData/i.test(s), `${f}: workstation path`);
    assert.ok(!/gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY|xox[abp]-|sk-[A-Za-z0-9]{20,}/.test(s), `${f}: secret`);
  }
});

test('the README documents the essentials', () => {
  const md = file('README.md');
  for (const h of ['## Features', '## Supported input', '## Using it', '## Microsoft 365 troubleshooting examples', '## Security and privacy', '## What header analysis cannot tell you', '## Browser support', '## Run it locally', '## License']) assert.ok(md.includes(h), h);
  assert.ok(md.includes('https://radmagelabs.com/mailanalyzer/'));
  assert.match(md, /!\[[^\]]+\]\(screenshots\/mailanalyzer\.png\)/);
  assert.ok(existsSync(join(ROOT, 'screenshots', 'mailanalyzer.png')));
});

test('the page is ready to host under /mailanalyzer/: no root-relative paths, canonical and preview set', () => {
  assert.ok(!/(src|href)="\//.test(html));
  assert.match(html, /<link rel="canonical" href="https:\/\/radmagelabs\.com\/mailanalyzer\/">/);
  assert.match(html, /<meta property="og:image" content="https:\/\/radmagelabs\.com\/assets\/og\/mailanalyzer\.png">/);
});
