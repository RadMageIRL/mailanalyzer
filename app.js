/*
  MailAnalyzer page: input, rendering, the report dialog, recent history, theme and shortcuts.
  The analysis itself is in mailanalyzer-core.js. Nothing here touches the network.

  Copyright (c) 2026 RadMageIRL. Released under the MIT License; see LICENSE.
  Styling and interaction patterns derived from Kard, also by RadMageIRL.
  SPDX-License-Identifier: MIT
*/
(() => {
  'use strict';
  const C = window.MailAnalyzerCore;
  const { KEYS, THEMES, LIMITS, SYSTEMS, SFV, CAT, IPV, SFTY, DIR, ATP, MBX_DEST, KNOWN, CATEGORIES } = C;
  const $ = id => document.getElementById(id);
  let toastTimer = null, current = null;

  // ---------- helpers ----------
  function safeGet(key) { try { return localStorage.getItem(key); } catch { return null; } }
  function safeSet(key, value) { try { localStorage.setItem(key, value); return true; } catch { return false; } }
  function safeRemove(key) { try { localStorage.removeItem(key); } catch { /* blocked */ } }
  // the loaded header block lives in sessionStorage: it survives a reload but goes when the tab closes
  function sessionGet(key) { try { return sessionStorage.getItem(key); } catch { return null; } }
  function sessionSet(key, value) { try { if (value == null) sessionStorage.removeItem(key); else sessionStorage.setItem(key, value); } catch { /* blocked */ } }
  // Every string from a message goes through esc before it reaches innerHTML: invisible and direction-control
  // characters are spelled out first, then the HTML metacharacters are escaped.
  function esc(value) { return C.visible(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
  function flash(message, duration = 2400) { const toast = $('toast'); toast.textContent = message; toast.classList.add('visible'); clearTimeout(toastTimer); toastTimer = setTimeout(() => toast.classList.remove('visible'), duration); }
  const { fmtTime, fmtDur } = C;
  function download(name, text) { const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' })); const a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 2000); }
  function copy(text, what) { if (!navigator.clipboard) { flash('Clipboard not available here; use Download instead'); return; } navigator.clipboard.writeText(text).then(() => flash(what), () => flash('Clipboard blocked; use Download instead')); }
  function stamp() { return fmtTime(Date.now()).replace(/[-: ]/g, '').slice(0, 12); }
  function applyTheme(mode) {
    if (mode === 'system') delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = mode;
    const button = $('theme-toggle');
    button.textContent = `Theme: ${mode === 'system' ? 'sys' : mode}`;
    button.setAttribute('aria-label', `Color theme: ${mode}. Click to cycle system, light, dark.`);
    let meta = document.querySelector('meta[name="theme-color"]');
    if (!meta) { meta = document.createElement('meta'); meta.name = 'theme-color'; document.head.appendChild(meta); }
    meta.content = getComputedStyle(document.body).backgroundColor || '#101311';
  }

  // ---------- rendering ----------
  function tone(result) { const r = (result || 'none').toLowerCase(); return /^(pass|bestguesspass)$/.test(r) ? 'good' : /^(fail|hardfail|permerror)$/.test(r) ? 'bad' : /^(softfail|softpass|temperror|neutral|policy)$/.test(r) ? 'warn' : 'none'; }
  function pill(label, result, extra = '') { return `<span class="pill ${tone(result)}">${label ? `<b>${esc(label)}</b>` : ''}${esc((result || 'none').toLowerCase())}${extra ? ` <span class="dim">${esc(extra)}</span>` : ''}</span>`; }
  const BASIS_HELP = { reported: 'A mail server wrote this verdict into a header; MailAnalyzer is repeating it, not re-checking it.', observed: 'Read directly from header values. The sender controls most of these.', inferred: 'Worked out by MailAnalyzer from other headers; a heuristic.', untrusted: 'Comes from a header in a sender-controlled position (below your gateway). Treat as a claim.' };
  const BASES = Object.keys(BASIS_HELP);
  function basisTag(basis, by) { return BASES.includes(basis) ? `<span class="basis basis-${basis}" title="${esc(BASIS_HELP[basis])}">${basis === 'reported' && by ? `reported \u00B7 ${esc(by)}` : esc(basis)}</span>` : ''; }
  function sysTag(sys) { return sys ? `<span class="tag sys" style="--sys:${sys.color}">${esc(sys.label)}</span>` : ''; }
  function ipTag(ip) { return ip ? `<span class="tag" title="${C.isPrivateIp(ip) ? 'private / internal address' : 'public address'}">${esc(ip)}${C.isPrivateIp(ip) ? ' \u00B7 private' : ''}</span>` : ''; }
  function kvHtml(rows) { return `<dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>`; }
  const SEV = { bad: 'bad', warn: 'warn', info: 'info', good: 'good' };
  function catTag(key, text) { const c = CATEGORIES.find(x => x.key === key); return c ? `<span class="tag ${c.tone}">${esc(text || c.tag)}</span>` : ''; }
  function mechCard(name, result, rows, basis, by, extra = '') {
    return `<div class="mech ${tone(result) === 'none' ? '' : tone(result)}"><div class="mech-head"><h4>${esc(name)}</h4>${pill('', result, extra)}${basisTag(basis, by)}</div>${kvHtml(rows)}</div>`;
  }
  const trustTagFor = trust => trust === 'trusted' ? '<span class="tag good" title="Inferred from where the header sits relative to the Received chain">stamped after it reached you</span>' : trust === 'untrusted' ? '<span class="tag bad">below the sender-side hops: sender-controlled</span>' : '<span class="tag warn" title="MailAnalyzer could not tell from the header order whether your servers or the sender wrote this">writer not confirmed</span>';
  function render(r) {
    current = r;
    $('results').hidden = false;
    $('report-button').disabled = false;
    const worst = r.findings[0]?.sev || 'good';
    const bad = r.findings.filter(x => x.sev === 'bad').length, warn = r.findings.filter(x => x.sev === 'warn').length;
    const severity = C.verdictOf(r), top = r.categories[0];
    const because = top ? `<p class="because">because ${top.support.slice(0, 3).map(x => esc(x.title)).join(' \u00B7 ')}${r.categories.length > 1 ? ` \u00B7 also ${r.categories.slice(1).map(c => catTag(c.key, c.title)).join(' ')}` : ''}</p>` : '';
    $('verdict').className = `verdict panel ${worst === 'info' ? 'good' : SEV[worst]}`;
    $('verdict').innerHTML = `<div class="grow"><h2>${esc(top ? top.title : severity)}${top ? basisTag(top.basis, top.by) : ''}</h2><p>${top ? `${esc(severity)} \u00B7 ` : ''}${bad ? `${bad} serious \u00B7 ` : ''}${warn ? `${warn} warning${warn === 1 ? '' : 's'} \u00B7 ` : ''}${r.hops.length} hop${r.hops.length === 1 ? '' : 's'}${r.timed.length >= 2 ? ` \u00B7 ${fmtDur(r.timed[r.timed.length - 1].t - r.timed[0].t)} in transit` : ''} \u00B7 ${r.headers.length} headers \u00B7 based on what servers recorded, not re-verified</p>${because}</div><button class="button" type="button" id="verdict-report">Report</button>`;
    $('verdict-report').addEventListener('click', openReport);
    $('findings').innerHTML = r.findings.map(x => `<div class="finding ${SEV[x.sev]}"><span class="sev">${{ bad: 'serious', warn: 'warning', info: 'note', good: 'ok' }[x.sev]}</span><span class="body"><strong>${esc(x.title)}</strong> ${basisTag(x.basis, x.by)}${x.cat && x.basis !== 'untrusted' ? ` ${catTag(x.cat)}` : ''}${x.detail ? `<span class="detail">${esc(x.detail)}</span>` : ''}</span></div>`).join('');

    const addr = a => a ? `${a.name ? `${esc(a.name)} ` : ''}<span class="dim">&lt;</span>${esc(a.addr)}<span class="dim">&gt;</span>` : '<span class="dim">-</span>';
    const rows = [
      ['from', addr(r.from)], ['reply-to', r.replyTo ? addr(r.replyTo) : '<span class="dim">-</span>'], ['return-path', r.returnPath ? esc(r.returnPath) : '<span class="dim">-</span>'],
      ['to', esc(C.decodeWords(r.get('to')) || '-')], ...(r.get('cc') ? [['cc', esc(C.decodeWords(r.get('cc')))]] : []),
      ['subject', esc(r.subject || '-')], ['date', r.dateHeader != null ? `${fmtTime(r.dateHeader)} <span class="dim">local \u00B7 ${esc(r.get('date'))}</span>` : esc(r.get('date') || '-')],
      ['message-id', esc(r.get('message-id') || '-')]
    ];
    if (r.ms.networkId) rows.push(['network msg id', `${esc(r.ms.networkId)} <span class="dim">\u00B7 search this in Message trace / Explorer</span>`]);
    const bulkRow = [...r.bulkMarks, ...(r.mailgun.length ? ['sent via Mailgun'] : [])];
    if (bulkRow.length) rows.push(['bulk', esc(bulkRow.join(' \u00B7 '))]);
    if (r.autoMarks.length) rows.push(['automated', esc(r.autoMarks.join(' \u00B7 '))]);
    $('summary').innerHTML = rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join('') + `<dt></dt><dd><span class="basis basis-observed" title="${esc(BASIS_HELP.observed)}">observed</span> <span class="dim">the sender writes all of these</span></dd>`;

    renderAuth(r); renderM365(r); renderRoute(r); renderFilters(r); renderHeaders();
  }
  function renderAuth(r) {
    const basis = r.authTrust === 'untrusted' ? 'untrusted' : 'reported';
    $('auth-source').innerHTML = r.authSource ? `from ${esc(r.authSource)}${r.primary.servid ? ` \u00B7 ${esc(r.primary.servid)}` : ''} \u00B7 ${trustTagFor(r.authTrust)}` : 'no authentication results in these headers';
    let html = '';
    const spfB = r.spf?.viaReceivedSpf ? (r.spf.trust === 'untrusted' ? 'untrusted' : 'reported') : basis;
    if (r.spf) html += mechCard('spf', r.spf.result, C.spfExplain(r), spfB, r.spf.viaReceivedSpf ? 'Received-SPF' : r.reporter, r.spfDomain);
    else html += mechCard('spf', 'none', [['meaning', 'No SPF result was recorded.']], 'observed');
    const dk = C.dkimRows(r);
    if (dk.length) dk.forEach(d => { html += mechCard('dkim', d.result, d.rows, d.result === 'unverified' ? 'observed' : basis, r.reporter, d.domain); });
    else html += mechCard('dkim', 'none', [['meaning', 'No DKIM signature and no DKIM result in these headers.']], 'observed');
    html += mechCard('dmarc', r.dmarc ? r.dmarc.result : 'none', C.dmarcExplain(r), r.dmarc ? basis : 'inferred', r.reporter, r.dmarc?.props.action ? `action=${r.dmarc.props.action}` : '');
    if (r.compauth) html += mechCard('compauth', r.compauth.result, [['meaning', 'Microsoft\'s composite verdict: SPF, DKIM, DMARC, ARC and sender reputation combined. It can pass mail that fails DMARC, or fail mail with no DMARC policy.'], ['reason', `${r.compauth.props.reason || '-'}: ${C.compauthReason(r.compauth.props.reason)}`]], basis, 'Microsoft 365', r.compauth.props.reason ? `reason ${r.compauth.props.reason}` : '');
    if (r.arc) html += mechCard('arc', r.arc.result, [['meaning', r.arc.result === 'pass' ? 'The receiving server reports that the ARC chain verified: intermediaries (lists, forwarders) recorded the authentication results they saw before changing the message.' : 'The ARC chain did not verify.']], basis, r.reporter);
    if (r.primary.methods.length) html += `<details><summary>raw ${esc(r.authSource)}</summary><pre class="raw">${esc(r.primary.methods.map(m => `${m.method}=${m.result}${m.comment ? ` (${m.comment})` : ''} ${Object.entries(m.props).map(([k, v]) => `${k}=${v}`).join(' ')}`).join('\n'))}</pre></details>`;
    $('auth').innerHTML = html;
  }
  function renderM365(r) {
    const f = r.forefront || {}, ms = r.ms;
    $('m365').innerHTML = '';
    if (!ms.present) { $('m365-section').hidden = true; return; }
    $('m365-section').hidden = false;
    const basis = ms.ffTrust === 'untrusted' ? 'untrusted' : 'reported';
    const verdictRows = [
      ['SFV', f.SFV, SFV[f.SFV] || (f.SFV ? 'undocumented' : '')],
      ['SCL', ms.scl, C.sclMeaning(ms.scl)],
      ['CAT', f.CAT, CAT[f.CAT] || (f.CAT ? 'undocumented' : '')],
      ['BCL', ms.bcl, C.bclMeaning(ms.bcl)],
      ['PCL', ms.pcl, C.pclMeaning(ms.pcl)],
      ['SFTY', f.SFTY, SFTY[f.SFTY] || (f.SFTY ? 'undocumented safety tip' : '')],
      ['SRV', f.SRV, f.SRV === 'BULK' ? 'marked as bulk by spam filtering' : ''],
      ['IPV', f.IPV, IPV[f.IPV] || ''],
      ['compauth', r.compauth ? `${r.compauth.result} ${r.compauth.props.reason || ''}`.trim() : '', r.compauth ? C.compauthReason(r.compauth.props.reason) : '']
    ].filter(x => x[1] != null && x[1] !== '');
    const mbx = ms.mbx || {};
    const deliveryRows = [['dest', mbx.DEST, `${MBX_DEST[mbx.DEST] || 'a value MailAnalyzer does not recognize'}; Microsoft does not document this header`], ['OFR', mbx.OFR, 'the filter or setting that chose the folder (undocumented)'], ['RF', mbx.RF, 'routing folder (undocumented)']].filter(x => x[1]);
    const sourceRows = [
      ['CIP', f.CIP, 'connecting IP as seen by Exchange Online'], ['CTRY', f.CTRY, 'country of the connecting IP'], ['PTR', f.PTR, 'reverse DNS of the connecting IP'], ['H', f.H, 'HELO/EHLO name the sender gave'], ['LANG', f.LANG, 'language detected in the message'], ['DIR', f.DIR, DIR[f.DIR] || ''], ['SFS', f.SFS, 'spam rules matched (Microsoft-internal IDs)']
    ].filter(x => x[1] != null && x[1] !== '');
    const orgRows = [
      ['AuthAs', ms.authAs, /anonymous/i.test(ms.authAs) ? 'arrived from outside, unauthenticated (normal for inbound internet mail)' : /internal/i.test(ms.authAs) ? 'sent by your own organization' : /partner/i.test(ms.authAs) ? 'arrived over a partner connector' : ''],
      ['Directionality', ms.direction, /incoming/i.test(ms.direction) ? 'inbound to your tenant' : /originating/i.test(ms.direction) ? 'sent from your tenant' : ''],
      ['AuthSource', ms.authSource, 'server that authenticated or accepted it'],
      ['FromEntityHeader', ms.entity, /internet/i.test(ms.entity) ? 'came from the internet' : /hosted/i.test(ms.entity) ? 'came from a mailbox in Exchange Online' : ''],
      ['OriginalArrivalTime', ms.arrival, ''],
      ['ATP properties', ms.atp, ms.atp.split('|').map(x => ATP[x.trim()]).filter(Boolean).join(', ')],
      ['Network-Message-Id', ms.networkId, 'the ID Message trace and Threat Explorer search on'],
      ['Tenant', ms.tenantId, 'tenant ID Exchange stamped (the receiving tenant, or the sender\'s for mail between tenants)']
    ].filter(x => x[1]);
    const table = (title, list) => list.length ? `<div class="sub-head"><strong>${esc(title)}</strong></div><table class="table decode"><colgroup><col class="k"><col class="v"><col></colgroup><tbody>${list.map(([k, v, d]) => `<tr><td><code>${esc(k)}</code></td><td class="val">${esc(v).split(')(').join(')<wbr>(')}</td><td class="dim">${esc(d || '')}</td></tr>`).join('')}</tbody></table>` : '';
    const note = basis === 'untrusted' ? 'These stamps sit below your gateway, so the sender could have written them.' : ms.ffTrust === 'unknown' ? 'MailAnalyzer could not confirm that your tenant wrote these stamps: the Received chain does not show the message entering through Exchange Online\'s front door. Treat them as claims.' : 'Written by Exchange Online Protection when the message arrived; MailAnalyzer decodes them but cannot re-run the filters.';
    $('m365').innerHTML = `<p class="hint" style="margin:-6px 0 12px">${basisTag(basis, 'Microsoft 365')}${ms.ffTrust === 'unknown' ? ` ${trustTagFor('unknown')}` : ''} ${esc(note)}</p>`
      + table('verdicts', verdictRows) + table('mailbox delivery', deliveryRows) + table('connection', sourceRows) + table('organization stamps', orgRows);
  }
  function renderRoute(r) {
    const maxDelay = Math.max(1000, ...r.hops.map(h => h.delay || 0));
    $('route-sub').innerHTML = r.hops.length ? `${r.hops.length} received hop${r.hops.length === 1 ? '' : 's'}, oldest first${r.timed.length >= 2 ? ` \u00B7 ${fmtDur(r.timed[r.timed.length - 1].t - r.timed[0].t)} end to end` : ''} \u00B7 times are each server's own claim ${basisTag('observed')}${r.boundary >= 0 ? ` \u00B7 trust boundary ${basisTag('inferred')}` : ' \u00B7 no trust boundary found'}` : 'no Received headers';
    $('route').innerHTML = r.hops.length ? r.hops.map((h, i) => {
      const d = h.delay, cls = d == null ? '' : d < -5000 ? 'skew' : d >= 5 * 60e3 ? 'very-slow' : d >= 60e3 ? 'slow' : '';
      const outside = r.boundary > 0 && i < r.boundary, isBoundary = i === r.boundary, held = r.edge.held && i === r.boundary - 1;
      const fromLabel = h.from ? `<span class="host">${esc(h.from)}</span>` : '<span class="dim">(origin)</span>';
      const trust = held ? '<span class="tag warn" title="Names Exchange Online or one of your domains, but the hop above does not show it arriving from your side, so it is not trusted.">names your systems \u00B7 not confirmed</span>' : outside ? '<span class="tag" title="Written by a sender-side server. The sender can put anything here.">sender side \u00B7 unverifiable</span>' : isBoundary ? '<span class="tag good" title="The newest hop received by your own edge (Exchange Online or your domains). Inferred from the host names.">entered your systems</span>' : '';
      const meta = [trust, sysTag(h.bySys), h.fromSys && h.fromSys !== h.bySys ? `<span class="dim">from</span> ${sysTag(h.fromSys)}` : '', ipTag(h.ip), h.with ? `<span class="tag">${esc(h.with)}</span>` : '', h.tls ? `<span class="tag good">${esc(h.tlsVer || 'TLS')}</span>` : h.from ? '<span class="tag">no TLS noted</span>' : ''].filter(Boolean).join(' ');
      return `<div class="hop ${outside ? 'outside' : ''} ${isBoundary ? 'boundary' : ''}"><span class="hop-n">${i + 1}</span><div><div class="hop-route">${fromLabel}<span class="arrow">\u2192</span><span class="host">${esc(h.by || '?')}</span></div><div class="hop-meta">${meta}</div>${h.fromDetail ? `<div class="hop-meta">${esc(h.fromDetail)}</div>` : ''}<details><summary>raw</summary><pre>${esc(h.raw)}</pre></details></div><div class="hop-time">${h.t != null ? esc(fmtTime(h.t)) : `<span title="${esc(h.dateRaw)}">no timestamp</span>`}<span class="delay ${cls}">${d == null ? (i === 0 ? 'start' : '-') : d < 0 ? esc(fmtDur(d)) : `+${esc(fmtDur(d))}`}</span>${d != null && d > 0 ? `<div class="delay-bar"><span class="${cls}" style="width:${Math.max(2, d / maxDelay * 100).toFixed(1)}%"></span></div>` : ''}</div></div>`;
    }).join('') : '<p class="empty">No Received headers. Paste the full header block, not just the From/To lines.</p>';
  }
  function renderFilters(r) {
    const table = (sys, title, list) => list.length ? `<div class="sub-head">${sysTag(sys)} <strong>${esc(title)}</strong> ${basisTag(list.some(h => r.trustOf(h) === 'untrusted') ? 'untrusted' : 'reported', sys?.label || '')}</div><table class="table" style="margin-bottom:18px"><tbody>${list.map(h => `<tr class="${r.trustOf(h) === 'untrusted' ? 'untrusted' : ''}"><td class="code"><code>${esc(h.name)}</code></td><td>${esc(h.value)}</td></tr>`).join('')}</tbody></table>` : '';
    const html = table(SYSTEMS.find(s => s.key === 'mailgun'), 'Mailgun', r.mailgun) + table(null, 'Other', r.otherSpam);
    $('filters-section').hidden = !html;
    $('filters').innerHTML = html;
  }
  function renderHeaders() {
    if (!current) return;
    const q = $('header-filter').value.trim().toLowerCase();
    const list = q ? current.headers.filter(h => `${h.name}: ${h.value}`.toLowerCase().includes(q)) : current.headers;
    // highlights the first match; skipped when lower-casing changes the text's length (a few Unicode letters do)
    const hl = text => { if (!q) return esc(text); const low = text.toLowerCase(), i = low.indexOf(q); return i < 0 || low.length !== text.length ? esc(text) : `${esc(text.slice(0, i))}<mark>${esc(text.slice(i, i + q.length))}</mark>${esc(text.slice(i + q.length))}`; };
    $('header-count').textContent = q ? `${list.length} of ${current.headers.length} headers` : `${current.headers.length} headers, top to bottom as received \u00B7 rows shaded red were already present when the message reached you`;
    $('header-table').innerHTML = list.map(h => `<tr class="${current.trustOf(h) === 'untrusted' ? 'untrusted' : ''}"><td class="h-name ${KNOWN.has(h.name.toLowerCase()) ? 'known' : ''}">${hl(h.name)}</td><td>${hl(h.value)}${h.cut ? ' <span class="tag warn">cut short</span>' : ''}</td></tr>`).join('') || '<tr><td class="dim">no matching headers</td></tr>';
  }

  // ---------- troubleshooting report ----------
  function refreshReport() {
    const o = { redact: $('opt-redact').checked, subject: $('opt-subject').checked, notes: $('opt-notes').checked, raw: $('opt-raw').checked };
    safeSet(KEYS.report, JSON.stringify(o));
    $('report-preview').textContent = C.buildReport(current, o);
  }
  function openReport() {
    if (!current) return;
    const o = C.reportOptions(safeGet(KEYS.report));
    $('opt-redact').checked = o.redact; $('opt-subject').checked = o.subject; $('opt-notes').checked = o.notes; $('opt-raw').checked = o.raw;
    refreshReport();
    $('report-dialog').showModal();
  }

  // ---------- input handling ----------
  // Only the header block is ever kept: in this tab's session (for a reload) and in the recent list.
  function run(text, quiet = false, keepScroll = false) {
    const r = C.analyze(text);
    if (!r) { if (!quiet) flash('No headers found. Paste the full raw header block.'); return null; }
    render(r);
    sessionSet(KEYS.message, r.block);
    $('input-panel').hidden = true; $('collapsed-input').hidden = false;
    $('collapsed-summary').textContent = C.visible(`${r.headers.length} headers \u00B7 ${r.from.addr || 'no From'} \u00B7 ${r.subject || 'no subject'}`);
    if (!keepScroll) window.scrollTo({ top: 0 });
    return r;
  }
  function rerun() {
    if (!current) return;
    const y = window.scrollY;
    if (run(current.block, true, true)) { window.scrollTo({ top: y }); flash('Re-analyzed'); }
  }
  function editInput() { $('input-panel').hidden = false; $('collapsed-input').hidden = true; $('headers-input').focus(); }
  function reset() { $('headers-input').value = ''; $('results').hidden = true; current = null; $('report-button').disabled = true; sessionSet(KEYS.message, null); editInput(); }
  function analyzeInput(quiet = false) { const r = run($('headers-input').value, quiet); if (r) remember(r, 'pasted'); }
  async function loadFile(blob) {
    if (!blob) return;
    const isMsg = /\.msg$/i.test(blob.name || '');
    let text;
    if (isMsg) {
      if (blob.size > LIMITS.msgBytes) { flash(`That .msg is larger than ${LIMITS.msgBytes / 1048576} MB. Save the message as .eml, or copy the headers from File \u2192 Properties.`, 6000); return; }
      let h = null;
      try { h = C.msgHeaders(await blob.arrayBuffer()); } catch { h = null; }
      if (h === null) { flash('Could not read that .msg file. Save the message as .eml, or copy the headers from File \u2192 Properties.', 6000); return; }
      if (!h.trim()) { flash('That .msg has no internet headers. Drafts and some internal mail never get them; check File \u2192 Properties in Outlook.', 6000); return; }
      text = h;
    } else {
      // An .eml's headers end at its first blank line (RFC 5322); only the first 2 MB is read, and the body is dropped here.
      text = (await blob.slice(0, LIMITS.emlBytes).text()).replace(/\r\n?/g, '\n').replace(/^\s+/, '').split(/\n[ \t]*\n/)[0];
    }
    const r = run(text);
    if (r) { $('headers-input').value = r.block; remember(r, isMsg ? 'msg' : 'eml', blob.name); }
  }

  // ---------- recent ----------
  // header blocks only, newest first, in localStorage; saving drops the oldest until it fits
  function loadRecent() { try { return C.cleanRecent(JSON.parse(safeGet(KEYS.recent) || '[]')); } catch { return []; } }
  function saveRecent(list) {
    while (list.length && !safeSet(KEYS.recent, JSON.stringify(list))) list.pop();
    if (!list.length) safeRemove(KEYS.recent);
    renderRecent();
  }
  function remember(r, source, name = '', keep = null) {
    const block = r.block.slice(0, LIMITS.recentChars), id = C.hashText(block), list = loadRecent().filter(x => x.id !== id);
    list.unshift({ id, source: keep?.source || source, name: keep ? keep.name : name, at: Date.now(), from: r.from.addr || '', subject: r.subject || '', text: block });
    saveRecent(list.slice(0, LIMITS.recentMax));
  }
  function ago(t) {
    const s = (Date.now() - t) / 1000;
    return s < 60 ? 'just now' : s < 3600 ? `${Math.floor(s / 60)}m ago` : s < 86400 ? `${Math.floor(s / 3600)}h ago` : s < 7 * 86400 ? `${Math.floor(s / 86400)}d ago` : fmtTime(t).slice(0, 10);
  }
  function recentRows(list) {
    return list.map(x => `<li class="recent-item"><button class="recent-open" type="button" data-recent-open="${esc(x.id)}"><span class="recent-subject">${esc(x.subject || '(no subject)')}</span><span class="recent-meta"><span class="tag">${esc(x.source)}</span> ${esc(x.from || 'no From')}${x.name ? ` \u00B7 ${esc(x.name)}` : ''} \u00B7 <span title="${esc(fmtTime(x.at))}">${esc(ago(x.at))}</span></span></button><button class="button small recent-remove" type="button" data-recent-remove="${esc(x.id)}" aria-label="Remove from recent" title="Remove from recent">\u00D7</button></li>`).join('');
  }
  function renderRecent() {
    const list = loadRecent();
    $('recent-panel').hidden = !list.length;
    $('recent-inline').innerHTML = recentRows(list.slice(0, 6));
    $('recent-all').hidden = list.length <= 6;
    $('recent-list').innerHTML = list.length ? recentRows(list) : '<li class="empty">Nothing yet. Messages you open or paste show up here.</li>';
    $('recent-clear').disabled = !list.length;
  }
  function openRecent(id) {
    const item = loadRecent().find(x => x.id === id);
    if (!item) return;
    if ($('recent-dialog').open) $('recent-dialog').close();
    $('headers-input').value = item.text;
    const r = run(item.text);
    if (r) remember(r, item.source, item.name, item);
  }
  let clearArmed = null;
  function clearRecent() {
    if (!clearArmed) { $('recent-clear').textContent = 'Click again to clear'; clearArmed = setTimeout(() => { clearArmed = null; $('recent-clear').textContent = 'Clear all'; }, 3000); return; }
    clearTimeout(clearArmed); clearArmed = null; $('recent-clear').textContent = 'Clear all';
    saveRecent([]); flash('Recent list cleared');
  }

  // ---------- events ----------
  $('analyze-button').addEventListener('click', () => analyzeInput());
  $('clear-button').addEventListener('click', reset);
  $('new-button').addEventListener('click', reset);
  $('edit-button').addEventListener('click', editInput);
  $('refresh-button').addEventListener('click', rerun);
  $('sample-button').addEventListener('click', () => { $('headers-input').value = C.SAMPLE; run(C.SAMPLE); flash('Sample: a vendor invoice sent via Mailgun \u2192 Microsoft 365'); });
  $('headers-input').addEventListener('keydown', event => { if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) { event.preventDefault(); analyzeInput(); } });
  $('headers-input').addEventListener('paste', () => setTimeout(() => { if (/^received:/im.test($('headers-input').value)) analyzeInput(true); }, 0));
  $('open-button').addEventListener('click', () => $('file-input').click());
  $('file-input').addEventListener('change', event => { loadFile(event.target.files[0]); event.target.value = ''; });
  $('report-button').addEventListener('click', openReport);
  const openRecentDialog = () => { renderRecent(); $('recent-dialog').showModal(); };
  $('recent-button').addEventListener('click', openRecentDialog);
  $('recent-all').addEventListener('click', openRecentDialog);
  $('recent-close').addEventListener('click', () => $('recent-dialog').close());
  $('recent-clear').addEventListener('click', clearRecent);
  document.addEventListener('click', event => {
    const open = event.target.closest('[data-recent-open]'), remove = event.target.closest('[data-recent-remove]');
    if (open) openRecent(open.dataset.recentOpen);
    if (remove) { saveRecent(loadRecent().filter(x => x.id !== remove.dataset.recentRemove)); flash('Removed from recent'); }
  });
  window.addEventListener('storage', event => { if (event.key === KEYS.recent || event.key === null) renderRecent(); });
  ['opt-redact', 'opt-subject', 'opt-notes', 'opt-raw'].forEach(id => $(id).addEventListener('change', refreshReport));
  $('report-copy').addEventListener('click', () => copy($('report-preview').textContent, 'Report copied, ready to paste into a ticket'));
  $('report-download').addEventListener('click', () => download(`mailanalyzer-report-${stamp()}.txt`, $('report-preview').textContent));
  $('report-close').addEventListener('click', () => $('report-dialog').close());
  $('raw-copy').addEventListener('click', () => { if (current) copy(current.block, 'Original headers copied'); });
  $('raw-download').addEventListener('click', () => { if (current) download(`mailanalyzer-headers-${stamp()}.txt`, `${current.block}\n`); });
  $('header-filter').addEventListener('input', renderHeaders);
  $('header-filter').addEventListener('keydown', event => { if (event.key === 'Escape') { event.target.value = ''; renderHeaders(); event.target.blur(); } });
  $('theme-toggle').addEventListener('click', () => {
    const stored = safeGet(KEYS.theme), cur = THEMES.includes(stored) ? stored : 'system';
    const next = THEMES[(THEMES.indexOf(cur) + 1) % THEMES.length];
    applyTheme(next); safeSet(KEYS.theme, next); flash(`Theme: ${next}`);
  });
  // your domains apply as you type; the analysis re-runs once when About closes
  let domainsAtOpen = '';
  $('about-button').addEventListener('click', () => { domainsAtOpen = $('domains-input').value; $('about-dialog').showModal(); });
  $('about-close').addEventListener('click', () => $('about-dialog').close());
  $('about-dialog').addEventListener('close', () => { if ($('domains-input').value !== domainsAtOpen && current) rerun(); });
  $('domains-input').addEventListener('input', event => { const v = event.target.value; if (v.trim()) safeSet(KEYS.domains, v); else safeRemove(KEYS.domains); C.setDomains(v); });
  let dragDepth = 0;
  const hasFiles = event => [...(event.dataTransfer?.types || [])].includes('Files');
  document.addEventListener('dragenter', event => { if (hasFiles(event)) { dragDepth++; $('drop-overlay').classList.add('visible'); } });
  document.addEventListener('dragleave', event => { if (!hasFiles(event)) return; dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) $('drop-overlay').classList.remove('visible'); });
  document.addEventListener('dragover', event => event.preventDefault());
  document.addEventListener('drop', event => { event.preventDefault(); dragDepth = 0; $('drop-overlay').classList.remove('visible'); const file = event.dataTransfer?.files?.[0]; if (file) loadFile(file); });
  document.addEventListener('keydown', event => {
    // typing in a field is not a shortcut, but a field inside a dialog that just closed still holds focus in WebKit
    const typing = event.target.matches('input, textarea, select') && !event.target.closest('dialog:not([open])');
    if (typing || document.querySelector('dialog[open]') || event.ctrlKey || event.metaKey || event.altKey) return;
    if (event.key === '/' && current) { event.preventDefault(); $('header-filter').focus(); $('header-filter').scrollIntoView({ block: 'center' }); }
    if (event.key === 'r' && current) { event.preventDefault(); openReport(); }
    if (event.key === 'e') { event.preventDefault(); editInput(); }
    if (event.key === 'R' && current) { event.preventDefault(); rerun(); }
    if (event.key === 'h') { event.preventDefault(); openRecentDialog(); }
    if (event.key === 'o') { event.preventDefault(); $('file-input').click(); }
    if (event.key === 'Escape' && $('header-filter').value) { $('header-filter').value = ''; renderHeaders(); }
  });

  // ---------- start ----------
  try { C.migrateStorage(localStorage); } catch { /* storage blocked */ }
  $('version').textContent = `v${C.VERSION}`;
  $('domains-input').value = safeGet(KEYS.domains) || ''; C.setDomains($('domains-input').value);
  const storedTheme = safeGet(KEYS.theme); applyTheme(THEMES.includes(storedTheme) ? storedTheme : 'system');
  renderRecent();
  const restored = sessionGet(KEYS.message);
  if (restored) { $('headers-input').value = restored; run(restored, true, true); }
  if (!current) $('headers-input').focus();
  document.documentElement.dataset.ready = '1';
})();
