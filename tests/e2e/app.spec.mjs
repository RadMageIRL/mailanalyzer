// The page in a real browser: rendering, hostile input, files, the report, recent history, theme, shortcuts,
// storage migration and offline use. Every test also fails on any page error, console error, or request that is
// not one of the page's own files.
// SPDX-License-Identifier: MIT
import { test as base, expect } from '@playwright/test';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { join, dirname } from 'node:path';

const require = createRequire(import.meta.url);
const F = require('../fixtures.js');
const C = require('../../mailanalyzer-core.js');
const { msg } = require('../cfb.js');
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const OWN = ['index.html', 'mailanalyzer-core.js', 'app.js'];

// Replaces the share sheet and the clipboard with recorders before the page loads, so a test sees exactly what Share
// passes. share: 'ok', 'abort' (the sheet was closed), 'fail', 'cannot' (canShare says no) or 'none' (no Web Share);
// clip: 'ok', 'fail', 'none' (no async clipboard) or 'real'; legacy: what document.execCommand('copy') returns.
const mockShare = (page, { share = 'ok', clip = 'ok', legacy = false } = {}) => page.addInitScript(({ share, clip, legacy }) => {
  window.__shared = []; window.__copied = []; window.__legacy = [];
  const def = (o, k, v) => Object.defineProperty(o, k, { value: v, configurable: true, writable: true });
  if (share === 'none') { def(navigator, 'share', undefined); def(navigator, 'canShare', undefined); } else {
    def(navigator, 'canShare', () => share !== 'cannot');
    def(navigator, 'share', async data => {
      window.__shared.push(JSON.parse(JSON.stringify(data)));
      if (share === 'abort') throw new DOMException('Share canceled', 'AbortError');
      if (share === 'fail') throw new DOMException('Share denied', 'NotAllowedError');
    });
  }
  if (clip !== 'real') def(navigator, 'clipboard', clip === 'none' ? undefined : { writeText: async t => { window.__copied.push(t); if (clip === 'fail') throw new DOMException('Write blocked', 'NotAllowedError'); } });
  const exec = document.execCommand.bind(document);
  def(document, 'execCommand', (cmd, ...rest) => { if (cmd !== 'copy') return exec(cmd, ...rest); window.__legacy.push(document.activeElement && document.activeElement.value); return legacy; });
}, { share, clip, legacy });
const recorded = page => page.evaluate(() => ({ shared: window.__shared, copied: window.__copied, legacy: window.__legacy }));
const settle = page => page.evaluate(() => new Promise(r => setTimeout(r, 100)));

const test = base.extend({
  shareMock: [null, { option: true }],
  app: async ({ page, baseURL, shareMock }, use) => {
    const errors = [], requests = [];
    page.on('pageerror', e => errors.push(`pageerror: ${e.message}`));
    page.on('console', m => { if (m.type() === 'error') errors.push(`console: ${m.text()}`); });
    page.on('request', r => requests.push(r.url()));
    if (shareMock) await mockShare(page, shareMock);
    await page.goto(baseURL);
    await page.waitForSelector('html[data-ready="1"]');
    await use({ page, errors, requests });
    expect(errors, 'page errors').toEqual([]);
    const outside = requests.filter(u => !u.startsWith(baseURL) && !u.startsWith('data:') && !u.startsWith('blob:'));
    expect(outside, 'requests outside the page').toEqual([]);
  }
});

const analyzeText = async (page, text) => { await page.fill('#headers-input', text); await page.click('#analyze-button'); await expect(page.locator('#results')).toBeVisible(); };
const local = (page, key) => page.evaluate(k => localStorage.getItem(k), key);
const session = (page, key) => page.evaluate(k => sessionStorage.getItem(k), key);

test('loads under /mailanalyzer/ as MailAnalyzer, requesting only its own three files', async ({ app: { page, requests }, baseURL }) => {
  await expect(page).toHaveTitle('MailAnalyzer | Email Header Analyzer | RadMage Labs');
  await expect(page.locator('h1')).toHaveText('MailAnalyzer');
  await expect(page.locator('#version')).toHaveText(`v${C.VERSION}`);
  const names = requests.map(u => u.slice(baseURL.length) || 'index.html');
  expect(names.sort()).toEqual([...OWN].sort());
  expect(await page.content()).not.toMatch(/\bmops\b/i);
});

test('Sample shows the verdict, findings and every section', async ({ app: { page } }) => {
  await page.click('#sample-button');
  await expect(page.locator('#verdict h2')).toContainText('Possible impersonation');
  await expect(page.locator('#verdict')).toContainText('not re-verified');
  await expect(page.locator('#findings .finding').first()).toContainText('Reply-To uses a cousin of the From domain');
  await expect(page.locator('#auth .mech')).toHaveCount(4);
  await expect(page.locator('#m365-section')).toBeVisible();
  await expect(page.locator('#route .hop')).toHaveCount(5);
  await expect(page.locator('#route .hop.boundary')).toContainText('entered your systems');
  await expect(page.locator('#filters-section')).toBeVisible();
  await expect(page.locator('#header-table tr')).toHaveCount(C.analyze(C.SAMPLE).headers.length);
});

test('pasting a header block analyzes it straight away', async ({ app: { page } }) => {
  await page.fill('#headers-input', F.m365());
  await page.locator('#headers-input').dispatchEvent('paste');
  await expect(page.locator('#verdict h2')).toHaveText(/Looks clean/);
});

test('ctrl+enter analyzes; text that is not headers says so and analyzes nothing', async ({ app: { page } }) => {
  await page.fill('#headers-input', 'just some words');
  await page.locator('#headers-input').press('Control+Enter');
  await expect(page.locator('#toast')).toContainText('No headers found');
  await expect(page.locator('#results')).toBeHidden();
  await page.fill('#headers-input', F.m365());
  await page.locator('#headers-input').press('Control+Enter');
  await expect(page.locator('#results')).toBeVisible();
});

const PAYLOAD = '<img src=x onerror="window.__xss=1">';
const hostile = F.m365({
  subject: `${PAYLOAD} \u202Egnp.exe`,
  from: `From: "<script>window.__xss=2</script>" <billing@example-vendor.com>`,
  replyTo: [`Reply-To: "x" <a"onmouseover="window.__xss=3"@example.org>`],
  ar: `servid.example<svg/onload=window.__xss=4>; spf=pass (${PAYLOAD}) smtp.mailfrom=example-vendor.com; dkim=pass header.d=<b>example-vendor.com</b>;dmarc=pass action=none header.from=example-vendor.com`,
  forefront: `CIP:198.51.100.24;CTRY:<img src=x onerror=window.__xss=5>;SCL:1;SFV:NSPM;CAT:NONE;H:"><script>window.__xss=6</script>;DIR:INB;`,
  date: `Tue, 10 Nov 2026 09:00:00 +0000"><img src=x onerror=window.__xss=7>`,
  extra: [`X-<svg/onload=window.__xss=8>: ${PAYLOAD}`, `X-Spam-Status: Yes, score=9 required=5 tests=${PAYLOAD}`, 'X-Mailgun-Tag: </td></tr></table><script>window.__xss=9</script>'],
  msgid: `"><iframe src=javascript:window.__xss=10>@example.com`
});

test('hostile header values render as text: no script runs and no element is injected', async ({ app: { page } }) => {
  await analyzeText(page, hostile);
  await page.keyboard.press('Escape');
  await page.locator('body').click({ position: { x: 5, y: 5 } });
  await page.click('#report-button');
  await page.check('#opt-raw');
  await page.click('#report-close');
  await page.click('#recent-button');
  await page.click('#recent-close');
  await page.click('#about-button');
  await page.click('#about-close');
  await page.locator('#findings .finding').first().hover();
  expect(await page.evaluate(() => window.__xss)).toBeUndefined();
  expect(await page.locator('#results img, #results script, #results svg, #results iframe, #recent-panel img').count()).toBe(0);
  expect(await page.evaluate(() => [...document.querySelectorAll('*')].filter(el => [...el.attributes].some(a => /^on/i.test(a.name))).length)).toBe(0);
  await expect(page.locator('#summary')).toContainText(PAYLOAD);
  await expect(page.locator('#summary')).toContainText('[U+202E]gnp.exe');
  await expect(page.locator('#header-table')).toContainText('X-<svg/onload=window.__xss=8>');
});

test('a hostile file name is shown as text in the recent list', async ({ app: { page } }) => {
  await page.setInputFiles('#file-input', { name: '<img src=x onerror=window.__xss=11>.eml', mimeType: 'message/rfc822', buffer: Buffer.from(F.m365()) });
  await expect(page.locator('#results')).toBeVisible();
  await page.click('#edit-button');
  await expect(page.locator('#recent-inline')).toContainText('<img src=x onerror=window.__xss=11>.eml');
  expect(await page.evaluate(() => window.__xss)).toBeUndefined();
  expect(await page.locator('#recent-panel img').count()).toBe(0);
});

test('an .eml is read up to its first blank line: the body is neither shown nor stored', async ({ app: { page } }) => {
  const eml = `${F.m365().replace(/\n/g, '\r\n')}\r\n\r\nDear customer, the secret code is 4417.\r\nX-Looks-Like: a header in the body\r\n`;
  await page.setInputFiles('#file-input', { name: 'invoice.eml', mimeType: 'message/rfc822', buffer: Buffer.from(eml) });
  await expect(page.locator('#verdict h2')).toHaveText(/Looks clean/);
  expect(await page.inputValue('#headers-input')).not.toContain('secret code');
  expect(await session(page, C.KEYS.message)).not.toContain('secret code');
  const recent = JSON.parse(await local(page, C.KEYS.recent));
  expect(recent[0].source).toBe('eml');
  expect(recent[0].name).toBe('invoice.eml');
  expect(recent[0].text).not.toContain('secret code');
  await expect(page.locator('#header-table')).not.toContainText('X-Looks-Like');
});

test('a body pasted along with the headers is never stored', async ({ app: { page } }) => {
  await analyzeText(page, `${F.m365()}\n\nPlease wire the payment to account 0000 1111.`);
  expect(await session(page, C.KEYS.message)).not.toContain('wire the payment');
  expect(await local(page, C.KEYS.recent)).not.toContain('wire the payment');
  await page.reload();
  await page.waitForSelector('html[data-ready="1"]');
  await expect(page.locator('#results')).toBeVisible();
  expect(await page.inputValue('#headers-input')).not.toContain('wire the payment');
});

test('an Outlook .msg is read through its stored headers; a corrupt one is refused with a message', async ({ app: { page } }) => {
  await page.setInputFiles('#file-input', { name: 'message.msg', mimeType: 'application/vnd.ms-outlook', buffer: msg(F.m365().replace(/\n/g, '\r\n')) });
  await expect(page.locator('#verdict h2')).toHaveText(/Looks clean/);
  expect(JSON.parse(await local(page, C.KEYS.recent))[0].source).toBe('msg');
  const bad = Buffer.from(msg('From: a@example.com\r\n')); bad.writeUInt16LE(30, 30);
  await page.setInputFiles('#file-input', { name: 'broken.msg', mimeType: 'application/vnd.ms-outlook', buffer: bad });
  await expect(page.locator('#toast')).toContainText('Could not read that .msg file');
  const empty = msg('', { wide: true });
  await page.setInputFiles('#file-input', { name: 'draft.msg', mimeType: 'application/vnd.ms-outlook', buffer: empty });
  await expect(page.locator('#toast')).toContainText('has no internet headers');
});

test('dropping a file shows the overlay and analyzes it', async ({ app: { page } }) => {
  const text = F.m365();
  await page.evaluate(t => {
    const dt = new DataTransfer();
    dt.items.add(new File([t], 'dropped.eml', { type: 'message/rfc822' }));
    document.dispatchEvent(new DragEvent('dragenter', { dataTransfer: dt, bubbles: true }));
    window.__overlay = document.getElementById('drop-overlay').classList.contains('visible');
    document.dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true, cancelable: true }));
  }, text);
  expect(await page.evaluate(() => window.__overlay)).toBe(true);
  await expect(page.locator('#results')).toBeVisible();
  await expect(page.locator('#drop-overlay')).not.toHaveClass(/visible/);
  expect(JSON.parse(await local(page, C.KEYS.recent))[0].name).toBe('dropped.eml');
});

test('the report masks by default, explains that masking is partial, and its options work', async ({ app: { page } }) => {
  await page.click('#sample-button');
  await page.click('#report-button');
  const preview = page.locator('#report-preview');
  await expect(preview).toContainText('b***@example-vendor.com');
  await expect(preview).toContainText('Partially masked');
  await expect(page.locator('#report-dialog')).toContainText('Masking is partial, not anonymization');
  expect(await preview.textContent()).not.toContain('billing@example-vendor.com');
  await page.uncheck('#opt-redact');
  await expect(preview).toContainText('billing@example-vendor.com');
  await page.check('#opt-subject');
  await expect(preview).toContainText('Subject:      [hidden]');
  await page.check('#opt-raw');
  await expect(preview).toContainText('----- ORIGINAL HEADERS');
  expect(JSON.parse(await local(page, C.KEYS.report))).toEqual({ redact: false, subject: true, notes: true, raw: true });
});

test('report and header downloads are plain text files named for MailAnalyzer', async ({ app: { page } }) => {
  await page.click('#sample-button');
  await page.click('#report-button');
  const [report] = await Promise.all([page.waitForEvent('download'), page.click('#report-download')]);
  expect(report.suggestedFilename()).toMatch(/^mailanalyzer-report-\d{12}\.txt$/);
  const text = readFileSync(await report.path(), 'utf8');
  expect(text).toBe(await page.locator('#report-preview').textContent());
  expect(text).toContain('EMAIL HEADER ANALYSIS (MailAnalyzer');
  await page.click('#report-close');
  const [raw] = await Promise.all([page.waitForEvent('download'), page.click('#raw-download')]);
  expect(raw.suggestedFilename()).toMatch(/^mailanalyzer-headers-\d{12}\.txt$/);
  expect(readFileSync(await raw.path(), 'utf8')).toBe(`${C.headerBlock(C.SAMPLE)}\n`);
});

test('Copy report puts the report on the clipboard', async ({ app: { page }, browserName, context }) => {
  test.skip(browserName !== 'chromium', 'clipboard read-back is only scriptable in Chromium');
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.click('#sample-button');
  await page.click('#report-button');
  await page.click('#report-copy');
  await expect(page.locator('#toast')).toContainText('Report copied');
  // the system clipboard may hand text back with CRLF line endings (Windows)
  expect((await page.evaluate(() => navigator.clipboard.readText())).replace(/\r\n/g, '\n')).toBe(await page.locator('#report-preview').textContent());
});

test('recent history: entries appear, one can be removed, and Clear all needs a second click', async ({ app: { page } }) => {
  await analyzeText(page, F.m365({ subject: 'First message' }));
  await page.click('#new-button');
  await analyzeText(page, F.m365({ subject: 'Second message' }));
  await page.click('#new-button');
  await expect(page.locator('#recent-inline .recent-item')).toHaveCount(2);
  await expect(page.locator('#recent-inline .recent-item').first()).toContainText('Second message');
  await page.locator('#recent-inline [data-recent-remove]').first().click();
  await expect(page.locator('#recent-inline .recent-item')).toHaveCount(1);
  await page.locator('#recent-inline [data-recent-open]').first().click();
  await expect(page.locator('#collapsed-summary')).toContainText('First message');
  await page.click('#recent-button');
  await page.click('#recent-clear');
  await expect(page.locator('#recent-clear')).toHaveText('Click again to clear');
  expect(JSON.parse(await local(page, C.KEYS.recent))).toHaveLength(1);
  await page.click('#recent-clear');
  await expect(page.locator('#recent-list')).toContainText('Nothing yet');
  expect(await local(page, C.KEYS.recent)).toBeNull();
});

test('New forgets the message in this tab; a reload otherwise restores it', async ({ app: { page } }) => {
  await page.click('#sample-button');
  await page.reload();
  await page.waitForSelector('html[data-ready="1"]');
  await expect(page.locator('#verdict h2')).toContainText('Possible impersonation');
  await page.click('#new-button');
  expect(await session(page, C.KEYS.message)).toBeNull();
  await page.reload();
  await page.waitForSelector('html[data-ready="1"]');
  await expect(page.locator('#results')).toBeHidden();
});

test('the theme cycles system, light, dark and is remembered', async ({ app: { page } }) => {
  await expect(page.locator('#theme-toggle')).toHaveText('Theme: sys');
  await page.click('#theme-toggle');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await page.click('#theme-toggle');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  expect(await local(page, C.KEYS.theme)).toBe('dark');
  const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  await page.reload();
  await page.waitForSelector('html[data-ready="1"]');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  expect(await page.evaluate(() => getComputedStyle(document.body).backgroundColor)).toBe(bg);
  await page.click('#theme-toggle');
  expect(await page.evaluate(() => document.documentElement.hasAttribute('data-theme'))).toBe(false);
});

test('keyboard shortcuts: r, Escape, e, h, /, Shift+R and o', async ({ app: { page } }) => {
  // listening early: Playwright turns on file chooser interception asynchronously when the first listener is added
  const choosers = [];
  page.on('filechooser', c => choosers.push(c));
  await page.click('#sample-button');
  await page.locator('body').click({ position: { x: 2, y: 2 } });
  await page.keyboard.press('r');
  await expect(page.locator('#report-dialog')).toHaveAttribute('open', '');
  await page.keyboard.press('Escape');
  await expect(page.locator('#report-dialog')).not.toHaveAttribute('open', '');
  await page.keyboard.press('h');
  await expect(page.locator('#recent-dialog')).toHaveAttribute('open', '');
  await page.keyboard.press('Escape');
  await page.keyboard.press('/');
  await expect(page.locator('#header-filter')).toBeFocused();
  await page.keyboard.type('dkim-signature');
  await expect(page.locator('#header-table tr')).toHaveCount(1);
  await expect(page.locator('#header-table mark')).toHaveCount(1);
  await page.keyboard.press('Escape');
  await expect(page.locator('#header-table tr')).toHaveCount(C.analyze(C.SAMPLE).headers.length);
  await page.locator('body').click({ position: { x: 2, y: 2 } });
  await page.keyboard.press('Shift+R');
  await expect(page.locator('#toast')).toContainText('Re-analyzed');
  await page.keyboard.press('o');
  await expect.poll(() => choosers.length).toBe(1);
  expect(choosers[0].isMultiple()).toBe(false);
  await page.locator('body').click({ position: { x: 2, y: 2 } });
  await page.keyboard.press('e');
  await expect(page.locator('#input-panel')).toBeVisible();
});

test('settings from the old names carry over once; another page\'s look-alike keys are left alone', async ({ app: { page } }) => {
  await page.evaluate(() => {
    localStorage.clear();
    localStorage.setItem('mops_theme', 'dark');
    localStorage.setItem('mops_domains', 'example.com');
    localStorage.setItem('hops_report', '{"redact":false}');
    localStorage.setItem('mops_recent', JSON.stringify([{ id: 'x', source: 'eml', name: 'old.eml', at: 1790000000000, from: 'a@example.com', subject: 'Old one', text: 'From: a@example.com\nSubject: Old one\n\nold body text' }]));
    localStorage.setItem('hops_theme', 'neon-purple');
  });
  await page.reload();
  await page.waitForSelector('html[data-ready="1"]');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  expect(await local(page, C.KEYS.domains)).toBe('example.com');
  expect(JSON.parse(await local(page, C.KEYS.report)).redact).toBe(false);
  await expect(page.locator('#recent-inline')).toContainText('Old one');
  expect(await local(page, C.KEYS.recent)).not.toContain('old body text');
  for (const k of ['mops_theme', 'mops_domains', 'hops_report', 'mops_recent']) expect(await local(page, k)).toBeNull();
  expect(await local(page, 'hops_theme')).toBe('neon-purple');
});

test('your domains change the analysis when About closes', async ({ app: { page } }) => {
  await analyzeText(page, F.m365({ from: 'From: "IT Help Desk" <helpdesk@example-vendor.com>' }));
  await expect(page.locator('#findings')).not.toContainText('poses as IT');
  await page.click('#about-button');
  await page.fill('#domains-input', 'example.com');
  await page.click('#about-close');
  await expect(page.locator('#findings')).toContainText('Sender name poses as IT or mail support');
  expect(await local(page, C.KEYS.domains)).toBe('example.com');
});

test('forged verdicts are shown as claims, never as a clean result', async ({ app: { page } }) => {
  await analyzeText(page, F.m365({ ar: null, rspf: null, bottom: ['Authentication-Results: spf=pass smtp.mailfrom=example-vendor.com; dkim=pass header.d=example-vendor.com; dmarc=pass action=none header.from=example-vendor.com'] }));
  await expect(page.locator('#verdict h2')).toHaveText(/Suspicious/);
  await expect(page.locator('#auth-source')).toContainText('sender-controlled');
  await expect(page.locator('#findings .finding.bad').first()).toContainText('Authentication results sit below your gateway');
  await page.click('#new-button');
  await analyzeText(page, F.forgedMicrosoftAtBottom());
  await expect(page.locator('#findings')).toContainText('Your entry point is not the newest hop');
  await expect(page.locator('#m365')).toContainText('could not confirm that your tenant wrote these stamps');
});

test('keeps working offline once loaded', async ({ app: { page }, context }) => {
  await context.setOffline(true);
  await page.click('#sample-button');
  await page.click('#report-button');
  await expect(page.locator('#report-preview')).toContainText('EMAIL HEADER ANALYSIS');
  const [d] = await Promise.all([page.waitForEvent('download'), page.click('#report-download')]);
  expect(d.suggestedFilename()).toMatch(/^mailanalyzer-report-/);
  await context.setOffline(false);
});

base('runs from a file on disk with no network at all', async ({ page, context }) => {
  const errors = [], requests = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('request', r => requests.push(r.url()));
  await context.setOffline(true);
  await page.goto(pathToFileURL(join(ROOT, 'dist', 'site', 'index.html')).href);
  await page.waitForSelector('html[data-ready="1"]');
  await page.click('#sample-button');
  await expect(page.locator('#verdict h2')).toContainText('Possible impersonation');
  expect(errors).toEqual([]);
  expect(requests.filter(u => !u.startsWith('file:') && !u.startsWith('data:'))).toEqual([]);
});

// ---------- Share and Back to RadMage Labs ----------
const LINK = C.SHARE.url;
const SHARED = { title: C.SHARE.title, text: C.SHARE.text, url: LINK };
const shareButton = page => page.getByRole('button', { name: 'Share', exact: true });
const PRIVATE = F.m365({ subject: 'Quarterly payroll 7731', msgid: 'leak-check-7731@mail.example-vendor.com', from: 'From: "Payroll Desk" <payroll.desk@example-vendor.com>' });

test.describe('Share with a share sheet', () => {
  test.use({ shareMock: { share: 'ok' } });

  test('passes the public address, title and line, copies nothing, and says so', async ({ app: { page } }) => {
    await shareButton(page).click();
    await expect(page.locator('#toast')).toHaveText('Link shared');
    expect(await recorded(page)).toEqual({ shared: [SHARED], copied: [], legacy: [] });
  });

  test('is a labeled toolbar button that Enter and Space press', async ({ app: { page } }) => {
    const b = shareButton(page);
    await expect(b).toBeVisible();
    await expect(b).toHaveAttribute('title', `Share ${LINK}`);
    await expect(page.getByRole('navigation', { name: 'Analyzer controls' }).getByRole('button', { name: 'Share', exact: true })).toHaveCount(1);
    await b.focus();
    await expect(b).toBeFocused();
    await page.keyboard.press('Enter');
    await expect.poll(async () => (await recorded(page)).shared.length).toBe(1);
    await page.keyboard.press('Space');
    await expect.poll(async () => (await recorded(page)).shared.length).toBe(2);
    await expect(b).toBeFocused();
  });

  test('nothing from a message or the address bar goes with it, and analysis leaves the address alone', async ({ app: { page }, baseURL }) => {
    const opened = `${baseURL}?utm_source=test&from=payroll#payroll`;
    await page.goto(opened);
    await page.waitForSelector('html[data-ready="1"]');
    await analyzeText(page, PRIVATE);
    await expect(page.locator('#summary')).toContainText('Quarterly payroll 7731');
    await page.click('#report-button');
    await page.click('#report-close');
    await shareButton(page).click();
    await expect(page.locator('#toast')).toHaveText('Link shared');
    const r = await recorded(page);
    expect(r.shared).toEqual([SHARED]);
    const all = JSON.stringify(r).toLowerCase();
    for (const s of ['payroll', '7731', 'leak-check', 'example-vendor', '198.51.100', 'utm', '#', '?']) expect(all, s).not.toContain(s);
    expect(page.url()).toBe(opened);
  });

  test('analysis, the report and Share make no network requests at all', async ({ app: { page, requests } }) => {
    const before = requests.length;
    await analyzeText(page, PRIVATE);
    await page.click('#report-button');
    await page.click('#report-close');
    await shareButton(page).click();
    await expect(page.locator('#toast')).toHaveText('Link shared');
    await page.click('#sample-button');
    await expect(page.locator('#verdict h2')).toContainText('Possible impersonation');
    await settle(page);
    expect(requests.slice(before)).toEqual([]);
  });
});

test.describe('Share when the sheet is closed', () => {
  test.use({ shareMock: { share: 'abort' } });
  test('does nothing else', async ({ app: { page } }) => {
    await shareButton(page).click();
    await expect.poll(async () => (await recorded(page)).shared.length).toBe(1);
    await settle(page);
    expect((await recorded(page)).copied).toEqual([]);
    await expect(page.locator('#toast')).not.toHaveClass(/visible/);
  });
});

test.describe('Share when the sheet fails', () => {
  test.use({ shareMock: { share: 'fail' } });
  test('copies the link instead', async ({ app: { page } }) => {
    await shareButton(page).click();
    await expect(page.locator('#toast')).toHaveText(`Link copied: ${LINK}`);
    const r = await recorded(page);
    expect([r.shared.length, r.copied]).toEqual([1, [LINK]]);
  });
});

test.describe('Share when the page cannot share', () => {
  test.use({ shareMock: { share: 'cannot' } });
  test('copies the link without opening the sheet', async ({ app: { page } }) => {
    await shareButton(page).click();
    await expect(page.locator('#toast')).toHaveText(`Link copied: ${LINK}`);
    expect(await recorded(page)).toEqual({ shared: [], copied: [LINK], legacy: [] });
  });
});

test.describe('Share without Web Share', () => {
  test.use({ shareMock: { share: 'none' } });
  test('copies the link and says so', async ({ app: { page } }) => {
    await page.click('#sample-button');
    await shareButton(page).click();
    await expect(page.locator('#toast')).toHaveText(`Link copied: ${LINK}`);
    expect(await recorded(page)).toEqual({ shared: [], copied: [LINK], legacy: [] });
  });
});

test.describe('Share without Web Share or the async clipboard', () => {
  test.use({ shareMock: { share: 'none', clip: 'none', legacy: true } });
  test('copies the link with the older copy command and gives focus back', async ({ app: { page } }) => {
    await shareButton(page).focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('#toast')).toHaveText(`Link copied: ${LINK}`);
    expect(await recorded(page)).toEqual({ shared: [], copied: [], legacy: [LINK] });
    await expect(shareButton(page)).toBeFocused();
    await expect(page.locator('textarea')).toHaveCount(1);
  });
});

test.describe('Share when every way to copy is blocked', () => {
  test.use({ shareMock: { share: 'none', clip: 'fail', legacy: false } });
  test('shows the address with a clear message', async ({ app: { page } }) => {
    await shareButton(page).click();
    await expect(page.locator('#toast')).toHaveText(`Clipboard blocked; the link is ${LINK}`);
    expect(await recorded(page)).toEqual({ shared: [], copied: [LINK], legacy: [LINK] });
  });
});

test.describe('Share with the real clipboard', () => {
  test.use({ shareMock: { share: 'none', clip: 'real' } });
  test('puts the public address on the clipboard', async ({ app: { page }, browserName, context }) => {
    test.skip(browserName !== 'chromium', 'clipboard read-back is only scriptable in Chromium');
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await analyzeText(page, PRIVATE);
    await shareButton(page).click();
    await expect(page.locator('#toast')).toHaveText(`Link copied: ${LINK}`);
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(LINK);
  });
});

base('from a file on disk, Share still passes the public address', async ({ page, context }) => {
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await mockShare(page, { share: 'ok' });
  await context.setOffline(true);
  await page.goto(pathToFileURL(join(ROOT, 'dist', 'site', 'index.html')).href);
  await page.waitForSelector('html[data-ready="1"]');
  await page.click('#sample-button');
  await shareButton(page).click();
  await expect(page.locator('#toast')).toHaveText('Link shared');
  expect((await recorded(page)).shared).toEqual([SHARED]);
  expect(errors).toEqual([]);
});

test('Back to RadMage Labs is a plain link to radmagelabs.com above the title, in the same tab', async ({ app: { page } }) => {
  const link = page.getByRole('navigation', { name: 'RadMage Labs' }).getByRole('link', { name: 'Back to RadMage Labs', exact: true });
  await expect(link).toBeVisible();
  await expect(link).toHaveAttribute('href', 'https://radmagelabs.com/');
  expect(await link.evaluate(a => [a.target, a.rel, a.hasAttribute('download'), a.hasAttribute('ping')])).toEqual(['', '', false, false]);
  const [l, h] = [await link.boundingBox(), await page.locator('h1').boundingBox()];
  expect(l.y + l.height).toBeLessThanOrEqual(h.y);
  expect(l.height).toBeGreaterThanOrEqual(24);
});

base('Back to RadMage Labs opens radmagelabs.com from the keyboard and sends no referrer', async ({ page, baseURL }) => {
  const asked = [];
  await page.route('https://radmagelabs.com/**', route => {
    asked.push({ url: route.request().url(), referer: route.request().headers().referer });
    return route.fulfill({ status: 200, contentType: 'text/html', body: '<!doctype html><title>RadMage Labs</title>' });
  });
  await page.goto(baseURL);
  await page.waitForSelector('html[data-ready="1"]');
  await page.click('#sample-button');
  await page.getByRole('link', { name: 'Back to RadMage Labs' }).focus();
  await page.keyboard.press('Enter');
  await page.waitForURL('https://radmagelabs.com/');
  expect(asked).toEqual([{ url: 'https://radmagelabs.com/', referer: undefined }]);
});
