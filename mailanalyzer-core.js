/*
  MailAnalyzer core: header parsing, the trust boundary, authentication and Microsoft 365
  decoding, findings, categories, the text report, Outlook .msg header extraction and the
  browser storage migration. No DOM access, so the page and the Node tests share this file.

  Copyright (c) 2026 RadMageIRL. Released under the MIT License; see LICENSE.
  SPDX-License-Identifier: MIT
*/
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.MailAnalyzerCore = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const VERSION = '1.0.1';
  // What the page's Share button passes: the public page address and a fixed title and line, wherever the page was
  // opened. Nothing from a message, no query string, no fragment and no tracking parameters ever go with it.
  const SHARE = Object.freeze({
    title: 'MailAnalyzer | RadMage Labs',
    text: 'Analyze email headers, authentication results, and mail routing privately in your browser.',
    url: 'https://radmagelabs.com/mailanalyzer/'
  });
  // Hard limits. A real header block is a few dozen kilobytes; these keep a hostile file or paste
  // from tying up the page. Anything past them is left out and the analysis says so.
  const LIMITS = { blockChars: 1024 * 1024, headers: 5000, valueChars: 64 * 1024, emlBytes: 2 * 1024 * 1024, msgBytes: 100 * 1024 * 1024, recentChars: 256 * 1024, recentMax: 25 };
  const THEMES = ['system', 'light', 'dark'];

  // ---------- systems ----------
  const SYSTEMS = [
    { key: 'm365', label: 'Microsoft 365', color: '#a981d0', rx: /protection\.outlook\.com|\.outlook\.com|exchangelabs\.com|office365\.com|\.microsoft\.com|^[A-Z]{2,4}\d?P[A-Z0-9]{4,}\./ },
    { key: 'mailgun', label: 'Mailgun', color: '#e58a3e', rx: /mailgun\.(net|org|com|info)/i },
    { key: 'onprem', label: 'your domains', color: '#56a36e', rx: /(?!)/ }, // matches nothing until setDomains sets your domains
    { key: 'google', label: 'Google', color: '#d6a545', rx: /google\.com|googlemail\.com|gmail\.com/i },
    { key: 'ses', label: 'Amazon SES', color: '#d6a545', rx: /amazonses\.com/i },
    { key: 'sendgrid', label: 'SendGrid', color: '#4fb3b3', rx: /sendgrid\.net/i },
    { key: 'proofpoint', label: 'Proofpoint', color: '#c47ab0', rx: /pphosted\.com|proofpoint/i },
    { key: 'mimecast', label: 'Mimecast', color: '#c47ab0', rx: /mimecast/i }
  ];
  // Exchange Online's inbound front door. A hop received here means the message reached a Microsoft 365 tenant.
  const EOP = /\.mail\.protection\.outlook\.com$/i;
  // Microsoft 365's own internal servers, which handle a message after the front door. Anchored, so
  // "outlook.com.example.net" is not one of them.
  const M365_INTERNAL = /(^|\.)(outlook\.com|office365\.com|exchangelabs\.com|microsoft\.com)$|^[A-Z]{2,4}\d?P[A-Z0-9]{4,}$/i;
  let OUR_EDGE = EOP, OWN = /(?!)/, OWN_DOMAINS = [];
  // "example.com" matches that host and its subdomains; * matches any run of host characters ("mail*")
  function parseDomains(text) {
    return [...new Set(String(text || '').slice(0, 4096).toLowerCase().split(/[\s,;]+/).map(d => d.replace(/^@|^\*?\.|\.$/g, '')).filter(d => d.length <= 253 && /^[a-z0-9.*-]+$/.test(d) && /[a-z0-9]/.test(d)))].slice(0, 100);
  }
  function setDomains(text) {
    const list = parseDomains(text);
    const own = list.map(d => { const body = d.split('*').map(p => p.replace(/\./g, '\\.')).join('[\\w.-]*'); return d.includes('*') ? `^${body}\\.?$` : `(^|\\.)${body}\\.?$`; }).join('|');
    OWN = own ? new RegExp(own, 'i') : /(?!)/;
    SYSTEMS.find(s => s.key === 'onprem').rx = OWN;
    OUR_EDGE = own ? new RegExp(`${EOP.source}|${own}`, 'i') : EOP;
    OWN_DOMAINS = list;
    return list;
  }
  const getDomains = () => OWN_DOMAINS.slice();

  // ---------- Microsoft 365 code books ----------
  const SFV = { NSPM: 'not spam; delivered to the inbox', SPM: 'spam', SKS: 'marked as spam before filtering, usually by a mail flow rule', SKA: 'filtering skipped: sender on an allow list in the anti-spam policy', SKB: 'marked as spam: sender on a block list in the anti-spam policy', SKI: 'filtering skipped: intra-org mail', SKN: 'marked as non-spam before filtering, usually by a mail flow rule', SKQ: 'released from quarantine', SFE: "filtering skipped: sender is in the recipient's Safe Senders", BLK: "blocked: sender is in the recipient's Blocked Senders" };
  const CAT = { NONE: 'no threat category', BULK: 'bulk', DIMP: 'domain impersonation', GIMP: 'mailbox intelligence impersonation', HPHSH: 'high-confidence phishing', HPHISH: 'high-confidence phishing', HSPM: 'high-confidence spam', MALW: 'malware', PHSH: 'phishing', SPM: 'spam', SPOOF: 'spoofing', UIMP: 'user impersonation', BIMP: 'brand impersonation', AMP: 'malware (anti-malware policy)', SAP: 'malicious attachment (Safe Attachments)', OSPM: 'outbound spam', INTOS: 'intra-org phishing', FTBP: 'filetype block (common attachment filter)' };
  const BAD_CAT = new Set(['DIMP', 'GIMP', 'BIMP', 'HPHSH', 'HPHISH', 'HSPM', 'MALW', 'AMP', 'SAP', 'PHSH', 'SPM', 'SPOOF', 'UIMP', 'INTOS', 'FTBP']);
  const IPV = { CAL: 'allowed by the connection filter (IP Allow List)', NLI: 'not listed on any IP reputation list' };
  const SFTY = { '9.1': 'default phishing protection: phishing URL, suspicious content or a known phishing source', '9.11': 'intra-org spoofing safety tip', '9.19': 'domain impersonation (anti-phishing policy)', '9.20': 'user impersonation (anti-phishing policy)', '9.21': 'spoof intelligence: sender failed authentication (unverified sender tag "?")', '9.22': 'as 9.21, but a user Safe Sender entry was overridden', '9.23': 'as 9.22, but an organization allow entry was overridden', '9.24': 'as 9.23, but a user mail flow rule was overridden', '9.25': 'first contact safety tip' };
  const DIR = { INB: 'inbound', OUT: 'outbound', INT: 'intra-org' };
  const ATP = { SA: 'scanned by Safe Attachments', SL: 'scanned by Safe Links' };
  function sclMeaning(scl) { if (scl === '' || scl == null) return ''; const n = Number(scl); if (Number.isNaN(n)) return ''; return n === -1 ? 'filtering skipped (trusted sender or bypass)' : n <= 1 ? 'not spam' : n <= 4 ? 'not spam (unusual value)' : n <= 6 ? 'spam: junk folder by default' : 'high-confidence spam'; }
  function bclMeaning(bcl) { if (bcl === '' || bcl == null) return ''; const n = Number(bcl); if (Number.isNaN(n)) return ''; return n === 0 ? 'not from a bulk sender' : n <= 3 ? 'bulk sender with few complaints' : n <= 7 ? 'bulk sender with mixed complaints (default threshold is 7)' : 'bulk sender with many complaints'; }
  function pclMeaning(pcl) { if (pcl === '' || pcl == null) return ''; const n = Number(pcl); if (Number.isNaN(n)) return ''; return n <= 3 ? 'content unlikely to be phishing' : 'content likely to be phishing'; }
  function compauthReason(code) {
    if (!code) return 'Microsoft combines SPF, DKIM, DMARC, ARC and its own sender intelligence into this verdict.';
    const exact = { '000': 'Explicit fail: the From domain publishes DMARC p=reject or p=quarantine and the message failed it.', '001': 'Implicit fail: the From domain has no enforcing DMARC policy, and Microsoft\'s own evaluation failed it.', '002': 'Your organization\'s spoof settings explicitly block this sender/domain pair.', '010': 'DMARC reject/quarantine failure for a domain that is one of your accepted domains (someone spoofing your own domain).' };
    if (exact[code]) return exact[code];
    if (!/^\d{3}$/.test(code)) return `Reason code ${code}; not in Microsoft's published ranges.`;
    return ({ 1: 'Pass. The last two digits are Microsoft-internal.', 7: 'Pass. The last two digits are Microsoft-internal.', 2: 'Soft pass: some evidence of authenticity, not enough for a pass.', 3: 'Not checked: composite authentication did not run.', 4: 'Bypassed, for example by an allow entry or connector.', 9: 'Bypassed, for example by an allow entry or connector.', 6: 'Implicit fail for a message claiming one of your accepted domains.' })[code[0]] || `Reason code ${code}; not in Microsoft's published ranges.`;
  }

  // ---------- authentication code books ----------
  // These say what a result MEANS. MailAnalyzer never re-checks one: every result shown is what a server wrote.
  const SPF_MEANING = { pass: "The receiving server reports that the sending IP is listed in the evaluated domain's SPF record, so that domain authorized this server.", fail: "The receiving server reports that the evaluated domain's SPF record says this IP may NOT send for it (-all).", softfail: 'The SPF record says this IP is probably not allowed (~all). Usually accepted, but counts against the message.', neutral: 'The SPF record makes no statement about this IP (?all).', none: 'No SPF record was found for the evaluated domain, or there was no domain to check.', temperror: 'A temporary DNS error stopped the check; a retry might pass.', permerror: 'The SPF record is broken (a syntax error or more than 10 DNS lookups) and could not be evaluated.' };
  const DKIM_MEANING = { pass: 'The receiving server reports that the signature verified: the signing domain (d=) vouches that the signed headers and body were not changed after signing.', fail: 'The signature did not verify. The message was changed after signing (an added footer, a gateway rewriting links or the subject) or the signature is forged.', none: 'There was no DKIM signature to check.', neutral: 'The signature could not be evaluated (unsupported algorithm or similar).', temperror: 'The public key could not be fetched from DNS; temporary.', permerror: 'The signature or the published key is malformed or missing.', policy: 'The signature is valid but rejected by local policy (for example too weak a key).' };
  const DMARC_MEANING = { pass: 'The receiving server reports that at least one of SPF or DKIM passed AND used a domain aligned with the visible From domain.', fail: 'Neither SPF nor DKIM passed with a domain aligned to the visible From. The receiver applies the From domain\'s policy (see action).', none: 'The From domain publishes no DMARC record, so there is no policy to apply.', bestguesspass: 'The From domain has no DMARC record; Microsoft estimated it would have passed.', temperror: 'A temporary DNS error stopped the DMARC lookup.', permerror: 'The From domain\'s DMARC record is malformed.' };
  const DMARC_ACTION = { none: 'none: deliver normally (p=none, or the message passed)', quarantine: 'quarantine: junk or quarantine (p=quarantine)', reject: 'reject: refuse the message (p=reject)', oreject: 'override: the domain asked for reject, Microsoft 365 junked or quarantined it instead', 'pct.quarantine': 'quarantine applied under a pct= sampling rule', 'pct.reject': 'reject applied under a pct= sampling rule' };
  const KNOWN = new Set(['from', 'to', 'cc', 'subject', 'date', 'message-id', 'reply-to', 'return-path', 'received', 'authentication-results', 'received-spf', 'dkim-signature', 'arc-authentication-results', 'x-forefront-antispam-report', 'x-microsoft-antispam', 'x-microsoft-antispam-mailbox-delivery', 'x-ms-exchange-organization-scl', 'x-ms-exchange-organization-network-message-id', 'x-mailgun-sending-ip', 'sender', 'list-unsubscribe', 'list-unsubscribe-post', 'list-id', 'precedence', 'feedback-id', 'auto-submitted', 'x-spam-status', 'x-spam-flag', 'x-spamd-result', 'x-rspamd-action', 'x-virus-status']);

  // ---------- categories ----------
  // A finding can support one category. The headline names the first category in this order that a finding
  // supports at warning level or worse, from a header not in a sender-controlled position. Bulk and automated
  // are not threats, so a note is enough for them.
  const CATEGORIES = [
    { key: 'malware', label: 'Malware', tag: 'malware', tone: 'bad' },
    { key: 'phish', label: 'Phishing', tag: 'phishing', tone: 'bad' },
    { key: 'impersonation', label: 'Impersonation', tag: 'impersonation', tone: 'bad' },
    { key: 'spam', label: 'Spam', tag: 'spam', tone: 'warn' },
    { key: 'bulk', label: 'Bulk mail', tag: 'bulk', tone: 'info', benign: true },
    { key: 'automated', label: 'Automated message', tag: 'automated', tone: 'info', benign: true }
  ];
  const CAT_OF_MS = { AMP: 'malware', MALW: 'malware', SAP: 'malware', FTBP: 'malware', PHSH: 'phish', HPHSH: 'phish', HPHISH: 'phish', INTOS: 'phish', BIMP: 'impersonation', DIMP: 'impersonation', GIMP: 'impersonation', UIMP: 'impersonation', SPOOF: 'impersonation', SPM: 'spam', HSPM: 'spam' };
  // X-Microsoft-Antispam-Mailbox-Delivery is not documented by Microsoft; these are the folder values seen on delivered mail.
  const MBX_DEST = { I: 'Inbox', J: 'Junk Email folder' };

  // ---------- sender identity ----------
  // Brands often named in phishing display names, and the organizational domains they send from. Consumer mailbox
  // domains (outlook.com, gmail.com, icloud.com) are left out on purpose: anyone can sign up for one.
  const BRANDS = [
    { name: 'Microsoft', home: 'microsoft.com', rx: /\bmicrosoft\b|\boffice ?365\b|\bm365\b|\bonedrive\b|\bsharepoint\b/i, domains: /^(microsoft|office|office365|microsoft365|microsoftonline|sharepointonline|onedrive)\.com$/ },
    { name: 'Google', home: 'google.com', rx: /\bgoogle\b|\bgmail\b/i, domains: /^(google|youtube)\.com$/ },
    { name: 'Apple', home: 'apple.com', rx: /\bapple ?(id|support|pay|account)\b|\bicloud\b|\bitunes\b|\bapp store\b/i, domains: /^apple\.com$/ },
    { name: 'Amazon', home: 'amazon.com', rx: /\bamazon\b|\baws\b/i, domains: /^amazon(\.com?)?\.[a-z]{2,3}$|^(aws|amazonaws)\.com$/ },
    { name: 'PayPal', home: 'paypal.com', rx: /\bpaypal\b/i, domains: /^paypal(\.com?)?\.[a-z]{2,3}$/ },
    { name: 'DocuSign', home: 'docusign.com', rx: /\bdocu ?sign\b/i, domains: /^docusign\.(com|net)$/ },
    { name: 'Adobe', home: 'adobe.com', rx: /\badobe\b|\bacrobat\b/i, domains: /^(adobe|adobesign|echosign)\.com$/ },
    { name: 'Dropbox', home: 'dropbox.com', rx: /\bdropbox\b/i, domains: /^dropbox(mail)?\.com$/ },
    { name: 'DHL', home: 'dhl.com', rx: /\bDHL\b/, domains: /^dhl(\.com?)?\.[a-z]{2,3}$/ },
    { name: 'FedEx', home: 'fedex.com', rx: /\bfed ?ex\b/i, domains: /^fedex\.com$/ },
    { name: 'UPS', home: 'ups.com', rx: /\bUPS\b/, domains: /^ups\.com$/ },
    { name: 'USPS', home: 'usps.com', rx: /\bUSPS\b|\bpostal service\b/i, domains: /^usps\.(com|gov)$/ },
    { name: 'IRS', home: 'irs.gov', rx: /\bIRS\b|\binternal revenue service\b/i, domains: /^irs\.gov$/ },
    { name: 'Netflix', home: 'netflix.com', rx: /\bnetflix\b/i, domains: /^netflix\.com$/ },
    { name: 'LinkedIn', home: 'linkedin.com', rx: /\blinkedin\b/i, domains: /^linkedin\.com$/ },
    { name: 'Facebook', home: 'facebook.com', rx: /\bfacebook\b|\binstagram\b/i, domains: /^(facebook|facebookmail|instagram|meta)\.com$/ },
    { name: 'Zoom', home: 'zoom.us', rx: /\bzoom\b/i, domains: /^zoom\.(us|com)$/ },
    { name: 'Wells Fargo', home: 'wellsfargo.com', rx: /\bwells ?fargo\b/i, domains: /^wellsfargo\.com$/ },
    { name: 'Bank of America', home: 'bankofamerica.com', rx: /\bbank of america\b/i, domains: /^(bankofamerica|bofa)\.com$/ },
    { name: 'Chase', home: 'chase.com', rx: /\bchase ?(bank|alerts?|online)\b|\bjp ?morgan chase\b/i, domains: /^(chase|jpmchase|jpmorgan)\.com$/ },
    { name: 'Norton', home: 'norton.com', rx: /\bnorton ?(360|antivirus|lifelock|security)\b/i, domains: /^(norton|nortonlifelock)\.com$/ },
    { name: 'McAfee', home: 'mcafee.com', rx: /\bmcafee\b/i, domains: /^mcafee\.com$/ },
    { name: 'Geek Squad', home: 'bestbuy.com', rx: /\bgeek ?squad\b/i, domains: /^(bestbuy|geeksquad)\.com$/ }
  ];
  const FREEMAIL = new Set(['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'hotmail.co.uk', 'hotmail.fr', 'live.com', 'msn.com', 'yahoo.com', 'yahoo.co.uk', 'yahoo.ca', 'ymail.com', 'rocketmail.com', 'aol.com', 'icloud.com', 'me.com', 'mac.com', 'proton.me', 'protonmail.com', 'pm.me', 'gmx.com', 'gmx.net', 'gmx.de', 'web.de', 'mail.com', 'zoho.com', 'yandex.com', 'yandex.ru', 'mail.ru', 'tutanota.com', 'tuta.io', 'fastmail.com', 'qq.com', '163.com', '126.com', 'comcast.net', 'att.net', 'sbcglobal.net', 'verizon.net']);
  // Company and finance-role names that a consumer mailbox has no business using
  const ROLE_WORDS = /\b(accounts? (payable|receivable)|billing|invoic(e|es|ing)|payroll|finance|accounting|treasury|ceo|cfo|coo|president|human resources|hr (department|team|dept)|procurement|purchasing (department|dept)|bank|inc|llc|ltd|corp(oration)?|gmbh)\b/i;
  const IT_ROLE = /\b(it ?(support|help ?desk|department|team|service ?desk|security)|help ?desk|service ?desk|system administrator|sys ?admin|mail(box)? ?(admin(istrator)?|support|team|server)|e-?mail ?(admin(istrator)?|support|team)|webmail|postmaster)\b/i;
  // Characters that do not show on screen: soft hyphen, zero-width space, word joiners, byte-order mark and the
  // bidirectional controls that change how text reads. ZWJ/ZWNJ and the LRM/RLM marks are left alone: emoji and
  // right-to-left scripts use them legitimately.
  const HIDDEN = /[\u00AD\u200B\u2060-\u2064\uFEFF\u202A-\u202E\u2066-\u2069]/g;
  const HIDDEN_NAME = { '00AD': 'soft hyphen', '200B': 'zero-width space', 'FEFF': 'zero-width no-break space', '2060': 'word joiner' };
  // What visible() spells out: the hidden characters above plus C0 controls (except tab), DEL and the C1 controls.
  // On screen and in reports they become [U+XXXX], so a direction override cannot reorder what is shown.
  const CONTROL = /[\u0000-\u0008\u000A-\u001F\u007F-\u009F\u00AD\u200B\u2060-\u2064\uFEFF\u202A-\u202E\u2066-\u2069]/g;
  // Cyrillic, Greek and Armenian letters that render like Latin ones; NFKC already folds fullwidth letters.
  const CONFUSABLE = { '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p', '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j', '\u04CF': 'l', '\u0501': 'd', '\u0455': 's', '\u051B': 'q', '\u051D': 'w', '\u04BB': 'h', '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041A': 'K', '\u041C': 'M', '\u041D': 'H', '\u041E': 'O', '\u0420': 'P', '\u0421': 'C', '\u0422': 'T', '\u0425': 'X', '\u0406': 'I', '\u0408': 'J', '\u0405': 'S', '\u03B1': 'a', '\u03BF': 'o', '\u03C1': 'p', '\u03BD': 'v', '\u03BA': 'k', '\u03B9': 'i', '\u03C5': 'u', '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0396': 'Z', '\u0397': 'H', '\u0399': 'I', '\u039A': 'K', '\u039C': 'M', '\u039D': 'N', '\u039F': 'O', '\u03A1': 'P', '\u03A4': 'T', '\u03A5': 'Y', '\u03A7': 'X', '\u0578': 'n', '\u0585': 'o', '\u0131': 'i', '\u0251': 'a' };
  const SCRIPTS = [['Latin', /\p{Script=Latin}/u], ['Cyrillic', /\p{Script=Cyrillic}/u], ['Greek', /\p{Script=Greek}/u], ['Armenian', /\p{Script=Armenian}/u]];

  // ---------- small helpers ----------
  const pad = n => String(n).padStart(2, '0');
  function fmtTime(t) { const d = new Date(t); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; }
  function fmtDur(ms) { const neg = ms < 0, s = Math.abs(ms) / 1000; let out; if (s < 1) out = '<1s'; else if (s < 90) out = `${Math.round(s)}s`; else if (s < 3600) out = `${Math.floor(s / 60)}m ${pad(Math.round(s % 60))}s`; else if (s < 172800) out = `${Math.floor(s / 3600)}h ${pad(Math.round(s % 3600 / 60))}m`; else out = `${(s / 86400).toFixed(1)}d`; return neg ? `\u2212${out}` : out; }
  function utcOffset(t) { const off = -new Date(t).getTimezoneOffset(), a = Math.abs(off); return `UTC${off < 0 ? '-' : '+'}${pad(Math.floor(a / 60))}:${pad(a % 60)}`; }
  function hashText(s) { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); } return (h >>> 0).toString(36); }
  // Spells out invisible and direction-control characters as [U+XXXX] (see CONTROL). Newlines are kept.
  const visible = s => String(s ?? '').replace(CONTROL, c => c === '\n' ? c : `[U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}]`);
  // The text around the first @ in s, out to the nearest separator. Linear time, unlike a regex on a long run.
  function firstAddr(s) {
    const str = String(s || ''), at = str.indexOf('@');
    if (at < 0) return '';
    const stop = /[\s<>"'(),;]/;
    let a = at, b = at + 1;
    while (a > 0 && !stop.test(str[a - 1])) a--;
    while (b < str.length && !stop.test(str[b])) b++;
    return at > a && b > at + 1 ? str.slice(a, b) : '';
  }

  // ---------- header parsing ----------
  const HEADER_LINE = /^([\x21-\x39\x3b-\x7e]+):[ \t]?(.*)$/;
  const GAP_TOLERANT = /^(received|received-spf|authentication-results|arc-[\w-]+|dkim-signature|return-path|delivered-to|x-[\w-]+|message-id|mime-version):/i;
  // Reads the header block at the start of text. Returns the headers, the raw block they came from (so only
  // headers are ever stored or copied, never a body that was pasted along with them) and whether a limit cut it short.
  function splitHeaders(text) {
    const src = String(text ?? '').replace(/\r\n?/g, '\n').replace(/^\s+/, '');
    const lines = src.split('\n'), headers = [];
    // next[i]: the first non-blank line after line i, worked out once from the end (a blank-line run stays linear)
    const next = new Int32Array(lines.length + 1).fill(-1);
    for (let i = lines.length - 1, nf = -1; i >= 0; i--) { next[i] = nf; if (lines[i].trim()) nf = i; }
    let end = lines.length, chars = 0, truncated = false, gap = null;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      chars += line.length + 1;
      if (chars > LIMITS.blockChars || headers.length > LIMITS.headers) { truncated = true; end = i; break; }
      if (/^[ \t]/.test(line) && headers.length) { if (line.trim()) appendValue(headers[headers.length - 1], line.trim()); continue; }
      const m = HEADER_LINE.exec(line);
      if (m) { headers.push({ name: m[1], value: '', idx: headers.length, cut: false }); appendValue(headers[headers.length - 1], m[2].trim(), true); continue; }
      if (!line.trim()) {
        // A blank line ends the header block, unless a well-known transport header follows
        // (some copy-paste sources leave gaps). Body text like "Note: ..." still ends it.
        const n = next[i];
        if (n >= 0 && GAP_TOLERANT.test(lines[n])) { if (!gap) gap = { line: i, count: headers.length }; continue; }
        end = i;
        break;
      }
      // A line that is neither a header nor indented: pasted headers sometimes wrap like this, but after a blank line
      // it means the "header" was the start of a body, so everything from that blank line on is left out.
      if (gap) { headers.length = gap.count; end = gap.line; break; }
      if (headers.length) appendValue(headers[headers.length - 1], line.trim());
      else { end = i; break; }
    }
    if (headers.length > LIMITS.headers) { headers.length = LIMITS.headers; truncated = true; }
    const block = headers.length ? lines.slice(0, end).join('\n').trimEnd() : ''; // not /\s+$/: quadratic on long blanks
    return { headers, block, truncated };
  }
  function appendValue(h, text, first = false) {
    if (h.cut) return;
    const v = first ? text : `${h.value} ${text}`;
    if (v.length > LIMITS.valueChars) { h.value = v.slice(0, LIMITS.valueChars); h.cut = true; } else h.value = v;
  }
  const headerBlock = text => splitHeaders(text).block;
  function decodeWords(s) {
    return String(s || '').replace(/=\?([^?\s]+)\?([bBqQ])\?([^?\s]*)\?=(?:\s+(?==\?))?/g, (match, charset, enc, text) => {
      try {
        let bytes;
        if (enc.toUpperCase() === 'B') bytes = Uint8Array.from(atob(text), c => c.charCodeAt(0));
        else {
          const t = text.replace(/_/g, ' '), arr = [];
          for (let i = 0; i < t.length; i++) { if (t[i] === '=' && /^[0-9a-f]{2}$/i.test(t.substr(i + 1, 2))) { arr.push(parseInt(t.substr(i + 1, 2), 16)); i += 2; } else arr.push(t.charCodeAt(i) & 0xff); }
          bytes = new Uint8Array(arr);
        }
        return new TextDecoder(charset.replace(/\*.*$/, '')).decode(bytes);
      } catch { return match; }
    });
  }
  // RFC 5322 mailbox list. The structure is read from the raw value first and only the display name is decoded
  // afterwards, so a quoted or encoded display name containing "<someone@example.org>" can never become the address.
  function parseMailboxes(value) {
    const s = String(value ?? ''), list = [];
    let raw = '', cmt = '', angle = null, q = false, depth = 0, inAngle = false;
    const unquote = t => t.replace(/"((?:[^"\\]|\\.)*)"?/g, (m, inner) => inner.replace(/\\(.)/g, '$1'));
    const end = () => {
      let name, addr;
      if (angle != null) { addr = angle.trim(); name = raw; }
      else { const t = raw.trim(); addr = addrSpecIn(t); name = addr ? t.replace(addr, ' ') : raw; }
      name = decodeWords(unquote(name)).replace(/\s+/g, ' ').trim();
      if (!name && cmt.trim()) name = decodeWords(cmt).replace(/\s+/g, ' ').trim();
      if (addr || name) list.push({ name, addr: addr.replace(/^<|>$/g, '') });
      raw = ''; cmt = ''; angle = null;
    };
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (inAngle) { if (c === '>') inAngle = false; else angle += c; continue; }
      if (q) { raw += c; if (c === '\\' && i + 1 < s.length) raw += s[++i]; else if (c === '"') q = false; continue; }
      if (depth) { if (c === '\\' && i + 1 < s.length) { cmt += s[++i]; continue; } if (c === '(') depth++; else if (c === ')' && --depth === 0) { cmt += ' '; continue; } cmt += c; continue; }
      if (c === '"') { q = true; raw += c; continue; }
      if (c === '(') { depth = 1; continue; }
      if (c === '=' && s[i + 1] === '?') { const m = /^=\?[^?\s]+\?[bBqQ]\?[^?\s]*\?=/.exec(s.slice(i, i + 1024)); if (m) { raw += m[0]; i += m[0].length - 1; continue; } }
      if (c === '<' && angle == null) { angle = ''; inAngle = true; continue; }
      if (c === ',' && (angle != null || raw.includes('@'))) { end(); continue; }
      raw += c;
    }
    end();
    return list;
  }
  // The addr-spec in t: the first @ outside a quoted string, with its local part (which may itself be quoted, as in
  // "service@paypal.com"@example.net, whose domain is example.net) and its domain. Linear time.
  function addrSpecIn(t) {
    let q = false, at = -1;
    for (let i = 0; i < t.length; i++) { const c = t[i]; if (q) { if (c === '\\') i++; else if (c === '"') q = false; continue; } if (c === '"') q = true; else if (c === '@') { at = i; break; } }
    if (at < 1) return '';
    const stop = /[\s<>"(),;:]/;
    let a = at;
    if (t[at - 1] === '"') { a = at - 2; while (a >= 0 && !(t[a] === '"' && t[a - 1] !== '\\')) a--; if (a < 0) return ''; }
    while (a > 0 && !stop.test(t[a - 1])) a--;
    let b = at + 1;
    while (b < t.length && !/[\s<>"(),;]/.test(t[b])) b++;
    return b > at + 1 ? t.slice(a, b) : '';
  }
  function parseAddress(value) { return parseMailboxes(value)[0] || { name: '', addr: '' }; }
  const domainOf = addr => (String(addr || '').split('@').pop() || '').toLowerCase().replace(/[<>\s]/g, '').replace(/\.$/, '');
  // Hosting suffixes where every customer gets a subdomain: two of them are different organizations. A short
  // stand-in for the Public Suffix List, which this page does not download.
  const SHARED_SUFFIXES = new Set(['github.io', 'gitlab.io', 'herokuapp.com', 'azurewebsites.net', 'cloudfront.net', 'blogspot.com', 'firebaseapp.com', 'web.app', 'pages.dev', 'workers.dev', 'netlify.app', 'vercel.app', 'appspot.com', 'onrender.com', 'glitch.me', 'repl.co', 'ngrok.io', 'ngrok-free.app']);
  function orgDomain(domain) {
    const parts = String(domain || '').toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
    if (parts.length <= 2) return parts.join('.');
    if (SHARED_SUFFIXES.has(parts.slice(-2).join('.'))) return parts.slice(-3).join('.');
    const tld = parts[parts.length - 1], sld = parts[parts.length - 2];
    if (tld.length === 2 && ['co', 'com', 'net', 'org', 'gov', 'ac', 'edu', 'ltd', 'plc', 'or', 'ne', 'go'].includes(sld)) return parts.slice(-3).join('.');
    return parts.slice(-2).join('.');
  }
  // RFC 5322 section 3.3 dates, read the same way in every browser (Date.parse differs between engines and reads
  // a date with no zone as the viewer's local time). No zone means -0000, as section 4.3 says.
  const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
  const ZONES = { UT: 0, UTC: 0, GMT: 0, Z: 0, EST: -300, EDT: -240, CST: -360, CDT: -300, MST: -420, MDT: -360, PST: -480, PDT: -420 };
  function parseMailDate(s) {
    if (!s) return null;
    const v = String(s).slice(0, 200).replace(/\([^()]*\)/g, ' ').replace(/\s+/g, ' ').trim();
    const m = /^(?:[A-Za-z]{3,9},?\s*)?(\d{1,2})[\s-]+([A-Za-z]{3})[A-Za-z]*\.?[\s-]+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,]\d+)?)?\s*(?:([+-])(\d{2}):?(\d{2})|([A-Za-z]{1,5}))?(?:\s|$)/.exec(v);
    if (m) {
      const mon = MONTHS[m[2].toLowerCase()];
      let year = +m[3];
      if (m[3].length === 2) year += year < 50 ? 2000 : 1900; else if (m[3].length === 3) year += 1900;
      const day = +m[1], h = +m[4], mi = +m[5], sec = m[6] ? +m[6] : 0;
      if (mon === undefined || day < 1 || day > 31 || h > 23 || mi > 59 || sec > 60) return null;
      let off = 0;
      if (m[7]) { if (+m[9] > 59) return null; off = (m[7] === '-' ? -1 : 1) * (+m[8] * 60 + +m[9]); } else if (m[10]) off = ZONES[m[10].toUpperCase()] ?? 0;
      const t = Date.UTC(year, mon, day, h, mi, Math.min(sec, 59));
      if (new Date(t).getUTCDate() !== day) return null; // 31 Feb and the like
      return t - off * 60e3;
    }
    const iso = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?\s*(Z|[+-]\d{2}:?\d{2})$/i.exec(v);
    if (iso) {
      const z = iso[7].toUpperCase(), off = z === 'Z' ? 0 : (z[0] === '-' ? -1 : 1) * (+z.slice(1, 3) * 60 + +z.slice(-2));
      const t = Date.UTC(+iso[1], +iso[2] - 1, +iso[3], +iso[4], +iso[5], iso[6] ? +iso[6] : 0);
      return Number.isNaN(t) ? null : t - off * 60e3;
    }
    return null;
  }
  function isPrivateIp(ip) {
    if (!ip) return false;
    const s = String(ip).replace(/^\[|\]$/g, '').replace(/^ipv6:/i, '');
    if (/^(10\.|127\.|192\.168\.|169\.254\.)/.test(s)) return true;
    let m = /^172\.(\d+)\./.exec(s); if (m && +m[1] >= 16 && +m[1] <= 31) return true;
    m = /^100\.(\d+)\./.exec(s); if (m && +m[1] >= 64 && +m[1] <= 127) return true;
    return /^(::1$|fe80:|f[cd][0-9a-f]{0,2}:)/i.test(s);
  }
  function systemOf(text) { return SYSTEMS.find(s => s.rx.test(text || '')) || null; }
  const hostOf = h => String(h || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  function parseReceived(header) {
    const value = header.value;
    const semi = value.lastIndexOf(';');
    const datePart = semi >= 0 ? value.slice(semi + 1).trim() : '';
    const body = semi >= 0 ? value.slice(0, semi) : value;
    const by = /\bby\s+([^\s;()]+)/i.exec(body);
    const fromSection = by ? body.slice(0, by.index) : body;
    const from = /\bfrom\s+([^\s;()]+)(?:\s+\(([^()]{0,512})\))?/i.exec(fromSection);
    // the protocol: the words after "with", up to id/for/via (a plain scan; a lookahead here was slow on long blanks)
    const wi = /\bwith\s+/i.exec(body);
    let withText = '';
    if (wi) { const rest = body.slice(wi.index + wi[0].length, wi.index + wi[0].length + 200), stopAt = /\s(?:id|for|via)\s/i.exec(rest); withText = (stopAt ? rest.slice(0, stopAt.index) : rest).trim(); }
    const id = /\bid\s+<?([^\s;>]+)/i.exec(body);
    const forAddr = /\bfor\s+<?([^\s;<>]+@[^\s;<>]+)>?/i.exec(body);
    // The connecting IP comes from the receiving server's own note in parentheses after the sender's name
    // ("from helo (rdns [192.0.2.1])", or Exchange's "from host (192.0.2.1)"). The name before it is whatever the
    // sender said in HELO, so an address there counts only when the whole name is an address literal.
    const detailIp = from && from[2] ? /\[(?:IPv6:)?([0-9a-f.:]+)\]/i.exec(from[2]) || /^\s*((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})\s*$/i.exec(from[2]) : null;
    const ip = detailIp || (from ? /^\[(?:IPv6:)?([0-9a-f.:]+)\]$/i.exec(from[1]) : null);
    const tlsVer = /TLS\s?v?1[._]?([0-3])/i.exec(body);
    const tls = !!tlsVer || /\b(ESMTPS|ESMTPSA|UTF8SMTPS|HTTPS)\b|cipher=/i.test(body);
    const fromHost = from ? from[1] : '', byHost = by ? by[1] : '';
    const detail = from && from[2] ? from[2] : '';
    return {
      raw: value, idx: header.idx, t: parseMailDate(datePart), dateRaw: datePart,
      from: fromHost, fromDetail: ip && detail.replace(/[[\]()]/g, '').trim() === ip[1] ? '' : detail, by: byHost,
      with: withText.replace(/\s*\(.*$/, '').trim(), id: id ? id[1] : '', for: forAddr ? forAddr[1] : '',
      ip: ip ? ip[1] : '', tls, tlsVer: tlsVer ? `TLS 1.${tlsVer[1]}` : '',
      fromSys: systemOf(`${fromHost} ${detail}`), bySys: systemOf(byHost)
    };
  }
  // Splits an Authentication-Results value on the semicolons that separate results, skipping any inside
  // comments or quoted strings, and returns each part with its comments taken out (one linear pass).
  function authParts(value) {
    const parts = [];
    let text = '', comment = '', firstComment = null, depth = 0, q = false;
    const push = () => { parts.push({ text: text.trim(), comment: (firstComment ?? '').trim() }); text = ''; comment = ''; firstComment = null; };
    for (let i = 0; i < value.length; i++) {
      const c = value[i];
      if (depth) { if (c === '\\') { comment += value[++i] ?? ''; continue; } if (c === '(') depth++; else if (c === ')' && --depth === 0) { if (firstComment == null) firstComment = comment; comment = ''; text += ' '; continue; } comment += c; continue; }
      if (q) { text += c; if (c === '\\') text += value[++i] ?? ''; else if (c === '"') q = false; continue; }
      if (c === '"') { q = true; text += c; continue; }
      if (c === '(') { depth = 1; comment = ''; continue; }
      if (c === ';') { push(); continue; }
      text += c;
    }
    if (depth && firstComment == null) firstComment = comment;
    push();
    return parts.filter(p => p.text || p.comment);
  }
  function parseAuthResults(value) {
    const v = String(value || '').replace(/^\s*i=\d+\s*;\s*/i, '');
    const out = { servid: '', methods: [] };
    authParts(v).forEach((part, index) => {
      const m = /^(spf|dkim|dmarc|compauth|arc|bimi|dkim-atps|iprev|auth|smime)\s*=\s*([\w-]+)/i.exec(part.text);
      if (!m) { if (index === 0) out.servid = part.text.split(/\s+/)[0] || ''; return; }
      const props = {};
      part.text.replace(/(?<![\w.-])([\w.-]+)=("[^"]*"|[^\s;]+)/g, (mm, k, val) => { const key = k.toLowerCase(); if (!(key in props)) props[key] = val.replace(/^"|"$/g, ''); return mm; });
      out.methods.push({ method: m[1].toLowerCase(), result: m[2].toLowerCase(), props, comment: part.comment });
    });
    return out;
  }
  function parseKv(value, pairSep = ';', kvSep = ':') {
    const out = {};
    value.split(pairSep).forEach(part => { const i = part.indexOf(kvSep); if (i > 0) { const k = part.slice(0, i).trim().toUpperCase(); if (!(k in out)) out[k] = part.slice(i + 1).trim(); } });
    return out;
  }
  function tagsOf(dkimSig) { const out = {}; dkimSig.replace(/\s+/g, '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) out[p.slice(0, i).toLowerCase()] = p.slice(i + 1); }); return out; }

  // ---------- lookalikes ----------
  // Punycode (RFC 3492): turns an xn-- label back into the characters a mail client shows.
  function punyDecode(s) {
    if (s.length > 253) throw new Error('bad punycode');
    const out = [], basic = s.lastIndexOf('-');
    for (let j = 0; j < basic; j++) out.push(s.charCodeAt(j));
    let n = 128, bias = 72, i = 0;
    for (let idx = basic > 0 ? basic + 1 : 0; idx < s.length;) {
      const oldi = i;
      for (let w = 1, k = 36; ; k += 36) {
        if (idx >= s.length) throw new Error('bad punycode');
        const c = s.charCodeAt(idx++), digit = c >= 48 && c <= 57 ? c - 22 : c >= 97 && c <= 122 ? c - 97 : c >= 65 && c <= 90 ? c - 65 : 36;
        if (digit >= 36) throw new Error('bad punycode');
        i += digit * w;
        const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
        if (digit < t) break;
        w *= 36 - t;
        if (w > 0x7fffffff) throw new Error('bad punycode');
      }
      let delta = oldi === 0 ? Math.floor((i - oldi) / 700) : Math.floor((i - oldi) / 2), k = 0;
      delta += Math.floor(delta / (out.length + 1));
      for (; delta > 455; k += 36) delta = Math.floor(delta / 35);
      bias = k + Math.floor(36 * delta / (delta + 38));
      n += Math.floor(i / (out.length + 1)); i %= out.length + 1;
      if (n > 0x10ffff) throw new Error('bad punycode');
      out.splice(i++, 0, n);
    }
    return String.fromCodePoint(...out);
  }
  const toUnicode = domain => String(domain || '').split('.').map(l => { if (!/^xn--/i.test(l)) return l; try { return punyDecode(l.slice(4).toLowerCase()); } catch { return l; } }).join('.');
  const skeleton = s => String(s || '').normalize('NFKC').replace(/./gsu, c => CONFUSABLE[c] || c);
  const scriptsOf = s => SCRIPTS.filter(([, rx]) => rx.test(s)).map(([name]) => name);
  // A further fold for comparing domains: digits and letter pairs that pass for other letters at a glance.
  const looksAs = s => skeleton(s).toLowerCase().replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/cl/g, 'd').replace(/0/g, 'o').replace(/[1i]/g, 'l').replace(/5/g, 's');
  function oneEdit(a, b) {
    if (a === b || Math.abs(a.length - b.length) > 1) return false;
    let i = 0; while (i < a.length && a[i] === b[i]) i++;
    if (a.length === b.length) return a.slice(i + 1) === b.slice(i + 1) || (a[i] === b[i + 1] && a[i + 1] === b[i] && a.slice(i + 2) === b.slice(i + 2));
    return a.length > b.length ? a.slice(i + 1) === b.slice(i) : a.slice(i) === b.slice(i + 1);
  }
  // How domain d imitates domain t, or '' when it does not. d may be punycode.
  function lookalike(d, t, tldSwap = true) {
    const shown = toUnicode(d).toLowerCase(), dOrg = orgDomain(shown), tOrg = orgDomain(t);
    if (!dOrg || !tOrg || dOrg === tOrg) return '';
    const [dName, ...dEnd] = dOrg.split('.'), [tName] = tOrg.split('.');
    if (shown.startsWith(`${tOrg}.`) || shown.includes(`.${tOrg}.`)) return `puts ${tOrg} in front of another domain`;
    if (dName === tName) return tldSwap && tName.length >= 4 ? `has the same name with a different ending (.${dEnd.join('.')})` : '';
    if (tName.length >= 4 && looksAs(dName) === looksAs(tName)) return 'swaps in lookalike characters';
    if (tName.length >= 6 && oneEdit(dName, tName)) return 'is one character off';
    return '';
  }
  // A different domain that reuses t's name with extra words: example-billing.com, pay-example.net
  function cousin(d, t) {
    const a = orgDomain(d).split('.')[0], b = orgDomain(t).split('.')[0];
    return b.length >= 5 && a !== b && `-${a}-`.includes(`-${b}-`);
  }
  function hiddenIn(s) {
    return [...new Set(String(s || '').match(HIDDEN) || [])].map(c => { const hex = c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0'); return `U+${hex} ${HIDDEN_NAME[hex] || (/^(202|206[6-9])/.test(hex) ? 'text direction control' : 'invisible operator')}`; });
  }

  // ---------- the trust boundary ----------
  // Where the message entered your systems, worked out from the newest Received line down. Every server
  // prepends its own Received line, so only the top of the chain was certainly written by your side.
  //  - Walk down past Microsoft 365's internal servers to the first hop received by your edge: Exchange Online's
  //    front door or a host on your domains. A hop newer than that, written by anyone else, means the edge below
  //    it is not where this copy arrived (forwarded mail, or a forged Received line), so there is no boundary.
  //  - From a hop on your domains, keep going down only while the newer hop says it came from your domains over a
  //    private address. That is the one thing a sender cannot fake: the address your own server saw.
  //  - Exchange Online's front door ends the walk. Below it is the internet.
  // Only a named Microsoft 365 server is passed over on the way down. A hop with no name, or named only by an IP
  // address (Gmail's top hops are), cannot be shown to be yours, so it ends the walk like any other server.
  function findBoundary(hops) {
    let b = -1, foreign = '', held = '';
    for (let i = hops.length - 1; i >= 0; i--) {
      const by = hostOf(hops[i].by);
      if (b < 0) {
        if (OUR_EDGE.test(by)) { b = i; if (EOP.test(by)) break; continue; }
        if (by && M365_INTERNAL.test(by)) continue;
        foreign = by || 'a server that gave no name';
        break;
      }
      const newer = hops[i + 1];
      if (OWN.test(by) && OWN.test(hostOf(newer.from)) && (!newer.ip || isPrivateIp(newer.ip))) { b = i; continue; }
      if (OUR_EDGE.test(by)) held = by;
      break;
    }
    const buried = foreign ? hops.findIndex(h => OUR_EDGE.test(hostOf(h.by))) : -1;
    return { boundary: foreign ? -1 : b, foreign, held, buried };
  }

  // ---------- analysis ----------
  function analyze(text) {
    const { headers, block, truncated } = splitHeaders(text);
    if (!headers.length) return null;
    const all = name => headers.filter(h => h.name.toLowerCase() === name);
    const first = name => all(name)[0] || null;
    const get = name => first(name)?.value || '';
    const fromList = parseMailboxes(get('from'));
    const from = fromList[0] || { name: '', addr: '' }, replyTo = get('reply-to') ? parseAddress(get('reply-to')) : null;
    const returnPath = parseAddress(get('return-path')).addr.replace(/^<|>$/g, '');
    const sender = get('sender') ? parseAddress(get('sender')) : null;
    const fromDomain = domainOf(from.addr);
    const hops = all('received').map(parseReceived).reverse();
    hops.forEach((h, i) => { const prev = hops[i - 1]; h.delay = prev && prev.t != null && h.t != null ? h.t - prev.t : null; });
    const timed = hops.filter(h => h.t != null);
    const dateHeader = parseMailDate(get('date'));

    // Trust boundary (inferred, see findBoundary). Headers above our first Received line were added after the
    // message reached us; headers below the last sender-side one were already there when it arrived. Between the
    // two is the sender's last server. Exchange Online appends its own X-MS-Exchange-* / X-Forefront-* stamps at the
    // bottom and renames copies that arrive from outside to "...-Untrusted", so those are judged by name, and only
    // when the boundary is Exchange Online's front door.
    const edge = findBoundary(hops), boundary = edge.boundary;
    const firstOurs = boundary >= 0 ? hops[boundary].idx : null, lastOutside = boundary > 0 ? hops[boundary - 1].idx : null;
    const viaM365 = boundary >= 0 && EOP.test(hostOf(hops[boundary].by));
    const MS_STAMP = /^x-(ms-exchange-|forefront-antispam-report$|microsoft-antispam)/i;
    // strict: a verdict header the entry server writes itself (Authentication-Results, Received-SPF). Exchange Online
    // writes those above its Received line, so under it they are sender-side. Other servers (Gmail, for one) write
    // them just below their own Received line, so there the position between the two hops cannot say who wrote it.
    const trustOf = (header, strict = false) => {
      if (!header) return 'absent';
      if (MS_STAMP.test(header.name) && !/-untrusted$/i.test(header.name)) return viaM365 ? 'trusted' : 'unknown';
      if (boundary < 0) return 'unknown';
      if (header.idx < firstOurs) return 'trusted';
      if (boundary > 0 && header.idx > lastOutside) return 'untrusted';
      return viaM365 && (strict || boundary === 0) ? 'untrusted' : 'unknown';
    };
    const msUntrusted = headers.filter(h => /^x-(forefront-antispam-report|microsoft-antispam[\w-]*)-untrusted$/i.test(h.name));

    // Authentication: prefer the topmost Authentication-Results in a trusted position.
    const arHeaders = all('authentication-results'), arcHeaders = all('arc-authentication-results');
    const arHeader = arHeaders.find(h => trustOf(h, true) === 'trusted') || arHeaders.find(h => trustOf(h, true) !== 'untrusted') || arHeaders[0] || arcHeaders.find(h => trustOf(h, true) === 'trusted') || arcHeaders[0] || null;
    const primary = arHeader ? parseAuthResults(arHeader.value) : { servid: '', methods: [] };
    const authSource = !arHeader ? '' : arHeader.name.toLowerCase() === 'authentication-results' ? 'Authentication-Results' : 'ARC-Authentication-Results';
    const authTrust = trustOf(arHeader, true);
    const method = name => primary.methods.filter(m => m.method === name);
    let spf = method('spf')[0] || null;
    // Received-SPF counts only from a position the sender could not have written, unless it is all there is.
    const rspfAll = all('received-spf'), rspfHeader = rspfAll.find(h => trustOf(h, true) !== 'untrusted') || rspfAll[0] || null;
    const receivedSpf = rspfHeader?.value || '', rspfTrust = trustOf(rspfHeader, true);
    if (!spf && receivedSpf) { const r = /^\s*(\w+)/.exec(receivedSpf); spf = { method: 'spf', result: (r ? r[1] : 'none').toLowerCase(), props: { 'smtp.mailfrom': (/envelope-from=["<]?([^\s;">]+)/i.exec(receivedSpf) || [])[1] || '' }, comment: (/\(([^()]{0,1000})\)/.exec(receivedSpf) || [])[1] || '', viaReceivedSpf: true, trust: rspfTrust }; }
    // a real message carries one to three DKIM signatures; 50 of each keeps the matching below cheap
    const dkims = method('dkim').slice(0, 50), dmarc = method('dmarc')[0] || null, compauth = method('compauth')[0] || null, arc = method('arc')[0] || null;
    const signatures = all('dkim-signature').slice(0, 50).map(h => tagsOf(h.value));
    const spfDomainRaw = spf?.props['smtp.mailfrom'] || spf?.props['envelope-from'] || returnPath || '';
    const spfDomain = spfDomainRaw.includes('@') ? domainOf(spfDomainRaw) : spfDomainRaw.toLowerCase();
    const spfAlignedDomain = !!fromDomain && !!spfDomain && orgDomain(spfDomain) === orgDomain(fromDomain);
    const spfAligned = !!spf && spf.result === 'pass' && spfAlignedDomain;
    const dkimPassDomains = dkims.filter(d => d.result === 'pass').map(d => (d.props['header.d'] || domainOf(d.props['header.i'] || '')).toLowerCase()).filter(Boolean);
    const dkimAligned = !!fromDomain && dkimPassDomains.some(d => orgDomain(d) === orgDomain(fromDomain));
    const heloSpf = rspfTrust === 'untrusted' ? '' : (/helo=([^\s;]+)/i.exec(receivedSpf) || [])[1] || '';

    // Microsoft 365
    const ffHeader = first('x-forefront-antispam-report');
    const forefront = ffHeader ? parseKv(ffHeader.value) : null;
    const msAntispamHeader = first('x-microsoft-antispam');
    const msAntispam = msAntispamHeader ? parseKv(msAntispamHeader.value) : null;
    const mbxHeader = first('x-microsoft-antispam-mailbox-delivery'), mbx = mbxHeader ? parseKv(mbxHeader.value) : null;
    const ms = {
      scl: get('x-ms-exchange-organization-scl') || forefront?.SCL || '',
      bcl: msAntispam?.BCL ?? '', pcl: get('x-ms-exchange-organization-pcl') || msAntispam?.PCL || '',
      authAs: get('x-ms-exchange-organization-authas'), authSource: get('x-ms-exchange-organization-authsource'),
      direction: get('x-ms-exchange-organization-messagedirectionality'), networkId: get('x-ms-exchange-organization-network-message-id'),
      tenantId: get('x-ms-exchange-crosstenant-id'), arrival: get('x-ms-exchange-crosstenant-originalarrivaltime'), entity: get('x-ms-exchange-crosstenant-fromentityheader'),
      atp: get('x-ms-exchange-atpmessageproperties'), ffTrust: trustOf(ffHeader || msAntispamHeader || mbxHeader || headers.find(h => /^x-ms-exchange-organization-/i.test(h.name))), present: !!(ffHeader || msAntispamHeader || mbxHeader || headers.some(h => /^x-ms-exchange-/i.test(h.name))),
      verdicts: !!(ffHeader || msAntispamHeader || mbxHeader || get('x-ms-exchange-organization-scl')),
      mbx, mbxTrust: trustOf(mbxHeader), viaM365
    };

    // Sending IP: prefer what the receiver reported, then fall back to the trust-boundary hop.
    const ipCandidates = [
      [(/sender IP is ([0-9a-f.:]+)/i.exec(spf?.comment || '') || [])[1], `${authSource || 'Authentication-Results'} (SPF comment)`],
      [rspfTrust === 'untrusted' ? '' : (/client-ip=([0-9a-f.:]+)/i.exec(receivedSpf) || [])[1], 'Received-SPF client-ip'],
      [forefront?.CIP, 'X-Forefront-Antispam-Report CIP'],
      [boundary >= 0 ? hops[boundary].ip : '', `Received header of hop ${boundary + 1}`]
    ];
    const ipHit = ipCandidates.find(([ip]) => ip);
    const sendingIp = ipHit ? { ip: ipHit[0], source: ipHit[1], inferred: ipHit === ipCandidates[3] } : null;

    // Other gateways
    const mailgun = headers.filter(h => /^x-mailgun-/i.test(h.name));
    const otherSpam = headers.filter(h => /^x-(spam|proofpoint|mimecast|rspamd|virus|amavis)/i.test(h.name));

    // Open-source filter and scanner stamps (SpamAssassin, rspamd, ClamAV / amavis), read when present
    const filterHits = [], hit = (header, verdict, note = '') => filterHits.push({ header, verdict, note });
    const phishRules = v => [...new Set(v.match(/\b\w*PHISH\w*/gi) || [])].slice(0, 12).join(', ');
    const sa = first('x-spam-status'), saScore = sa && /score=(-?[\d.]+)/i.exec(sa.value), saNeed = sa && /required=(-?[\d.]+)/i.exec(sa.value);
    if (sa && /^\s*yes\b/i.test(sa.value)) hit(sa, 'spam', saScore ? `score ${saScore[1]}${saNeed ? ` of ${saNeed[1]} needed` : ''}` : '');
    const saTests = sa && /tests=([^;]*)/i.exec(sa.value);
    if (saTests && /phish/i.test(saTests[1])) hit(sa, 'phish', `phishing rules matched: ${phishRules(saTests[1])}`);
    const flag = first('x-spam-flag') || first('x-spam');
    if (flag && /^\s*(yes|true)\b/i.test(flag.value)) hit(flag, 'spam');
    const spamd = first('x-spamd-result'), spamdScore = spamd && /default:\s*(true|false)\s*\[\s*(-?[\d.]+)\s*\/\s*(-?[\d.]+)/i.exec(spamd.value);
    if (spamdScore && /^true$/i.test(spamdScore[1])) hit(spamd, 'spam', `score ${spamdScore[2]} of ${spamdScore[3]} needed`);
    if (spamd && /phish/i.test(spamd.value)) hit(spamd, 'phish', `phishing rules matched: ${phishRules(spamd.value)}`);
    const action = first('x-rspamd-action');
    if (action && /reject|add header|rewrite subject/i.test(action.value)) hit(action, 'spam', `action: ${action.value.trim()}`);
    const scan = first('x-virus-status') || first('x-amavis-alert');
    if (scan && /infected|banned/i.test(scan.value)) hit(scan, 'malware', scan.value.trim().slice(0, 300));

    // Bulk and automated markers: RFC 2369 / 8058 list headers, RFC 3834 Auto-Submitted, null-sender bounces
    const oneClick = /list-unsubscribe=one-click/i.test(get('list-unsubscribe-post'));
    const precedence = get('precedence').trim().toLowerCase(), autoSubmitted = get('auto-submitted').trim().toLowerCase();
    const bulkMarks = [get('list-unsubscribe') && 'List-Unsubscribe', oneClick && 'one-click unsubscribe', get('list-id') && 'List-Id', /^(bulk|list|junk)$/.test(precedence) && `Precedence: ${precedence}`, get('feedback-id') && 'Feedback-ID'].filter(Boolean);
    const autoMarks = [autoSubmitted && autoSubmitted !== 'no' && `Auto-Submitted: ${autoSubmitted.slice(0, 60)}`, /^\s*<\s*>\s*$/.test(get('return-path')) && 'empty Return-Path (a bounce)', /^(mailer-daemon|postmaster)@/i.test(from.addr) && `sent by ${from.addr.split('@')[0]}`, /report-type="?delivery-status/i.test(get('content-type')) && 'delivery status report', all('x-ms-exchange-message-is-ndr').length && 'Exchange non-delivery report', /^(yes|true)$/i.test(get('x-autoreply').trim()) && 'X-Autoreply'].filter(Boolean);

    const r = { text: block, block, truncated, headers, all, get, from, fromList, replyTo, returnPath, sender, fromDomain, hops, timed, dateHeader, boundary, edge, trustOf, msUntrusted, arHeaders, primary, authSource, authTrust, spf, dkims, dmarc, compauth, arc, signatures, spfDomain, spfAlignedDomain, spfAligned, dkimPassDomains, dkimAligned, heloSpf, forefront, msAntispam, ms, sendingIp, mailgun, otherSpam, filterHits, oneClick, bulkMarks, autoMarks, subject: decodeWords(get('subject')) };
    r.reporter = reporterLabel(r);
    r.findings = buildFindings(r);
    r.categories = categorize(r.findings);
    return r;
  }
  function reporterLabel(r) {
    if (!r.authSource) return '';
    const sys = r.primary.servid ? systemOf(r.primary.servid) : null;
    if (sys) return sys.label;
    if (r.primary.servid) return r.primary.servid;
    if (r.ms.viaM365 && r.authTrust === 'trusted') return 'Microsoft 365';
    return 'an unnamed server';
  }
  // The basis of SPF: Received-SPF has its own position; everything else comes from the chosen results header.
  const spfBasis = r => (r.spf?.viaReceivedSpf ? r.spf.trust : r.authTrust) === 'untrusted' ? 'untrusted' : 'reported';

  // ---------- explanations (shared by the cards, the findings and the report) ----------
  function spfExplain(r) {
    const s = r.spf; if (!s) return null;
    const rows = [
      ['domain evaluated', `${r.spfDomain || '(none)'} - the envelope sender (smtp.mailfrom / Return-Path), not the From address people see`],
      ['sending IP', r.sendingIp ? `${r.sendingIp.ip} (${r.sendingIp.inferred ? 'inferred from the ' : 'reported in '}${r.sendingIp.source})` : 'not recorded'],
      ...(r.heloSpf ? [['helo', r.heloSpf]] : []),
      ['meaning', SPF_MEANING[s.result] || `Result "${s.result}".`],
      ['alignment', !r.fromDomain || !r.spfDomain ? 'cannot tell, a domain is missing' : r.spfAlignedDomain ? `${r.spfDomain} shares the organizational domain of From ${r.fromDomain} (relaxed alignment)` : `${r.spfDomain} is a different organization from From ${r.fromDomain}, so SPF cannot vouch for the From address`],
      ['for DMARC', r.spfAligned ? `SPF passed and aligned, which is enough for DMARC on its own${r.dkimAligned ? '; DKIM passed and aligned too' : ''}.` : s.result === 'pass' ? `SPF passed for a different domain, so it does not count for DMARC.${r.dkimAligned ? ' DKIM passed and aligned, which carries DMARC instead.' : ' No aligned DKIM pass either, so DMARC has nothing to pass on.'}` : r.dkimAligned ? 'SPF did not pass, but DKIM passed and aligned, so DMARC can still pass.' : 'SPF did not pass and no aligned DKIM pass exists, so DMARC fails.']
    ];
    if (s.comment) rows.push(['server note', s.comment]);
    return rows;
  }
  function dkimRows(r) {
    if (r.dkimRowsCache) return r.dkimRowsCache;
    return (r.dkimRowsCache = dkimRowsOf(r));
  }
  function dkimRowsOf(r) {
    const out = r.dkims.map(d => {
      const domain = d.props['header.d'] || domainOf(d.props['header.i'] || '');
      const aligned = domain && r.fromDomain && orgDomain(domain) === orgDomain(r.fromDomain);
      return { result: d.result, domain, selector: d.props['header.s'] || r.signatures.find(s => (s.d || '').toLowerCase() === domain.toLowerCase())?.s || '', comment: d.comment, rows: [
        ['signing domain', `${domain || '(not stated)'}${d.props['header.s'] ? ` \u00B7 selector ${d.props['header.s']}` : ''}`],
        ['meaning', DKIM_MEANING[d.result] || `Result "${d.result}".`],
        ['alignment', !domain ? 'cannot tell' : aligned ? `${domain} shares the organizational domain of From ${r.fromDomain}` : `${domain} is a different organization from From ${r.fromDomain || '?'} (normal for some ESPs, but it cannot carry DMARC)`],
        ['for DMARC', d.result === 'pass' && aligned ? 'Passed and aligned, which is enough for DMARC on its own.' : r.spfAligned ? 'Does not carry DMARC, but SPF passed and aligned, so DMARC can still pass.' : r.dkimAligned ? 'Another DKIM signature passed and aligned, which carries DMARC.' : 'No aligned SPF or DKIM pass exists, so DMARC fails.'],
        ...(d.comment ? [['server note', d.comment]] : [])
      ] };
    });
    // Signatures present but with no verdict recorded: the header only proves a signature was attached.
    r.signatures.filter(s => !out.some(o => o.domain.toLowerCase() === (s.d || '').toLowerCase())).forEach(s => out.push({ result: 'unverified', domain: s.d || '', selector: s.s || '', rows: [
      ['signing domain', `${s.d || '?'} \u00B7 selector ${s.s || '?'}`],
      ['meaning', 'A DKIM-Signature header is present, but no server recorded a verdict for it. MailAnalyzer does not verify signatures, so treat it as unchecked.']
    ] }));
    return out;
  }
  function dmarcExplain(r) {
    const d = r.dmarc;
    const carried = r.spfAligned && r.dkimAligned ? 'both SPF and DKIM (aligned passes)' : r.spfAligned ? 'SPF (aligned pass)' : r.dkimAligned ? 'DKIM (aligned pass)' : 'neither: no aligned SPF or DKIM pass';
    if (!d) return [['meaning', 'No server recorded a DMARC verdict in these headers.'], ['computed', `From ${r.fromDomain || '?'}: an aligned pass came from ${carried}, so DMARC ${r.spfAligned || r.dkimAligned ? 'would pass' : 'would fail'} if the domain publishes a policy. MailAnalyzer cannot see the policy without DNS.`]];
    return [
      ['From domain', d.props['header.from'] || r.fromDomain || '?'],
      ['meaning', DMARC_MEANING[d.result] || `Result "${d.result}".`],
      ...(d.props.action ? [['action', DMARC_ACTION[d.props.action] || d.props.action]] : []),
      ...(d.props.p || d.props.policy ? [['policy', d.props.p || d.props.policy]] : []),
      ['carried by', `${carried}, according to the SPF and DKIM results reported alongside it`]
    ];
  }

  function buildFindings(r) {
    const f = [], add = (sev, title, detail, basis, by = '', cat = '') => f.push({ sev, title, detail: detail || '', basis, by, cat });
    const rep = r.reporter || 'the receiving server', untrustedAuth = r.authTrust === 'untrusted';
    // Input and trust
    if (r.truncated) add('info', 'Only part of the input was read', `MailAnalyzer reads at most ${LIMITS.headers} headers, ${LIMITS.blockChars / 1024} KB of header text and ${LIMITS.valueChars / 1024} KB per header. The rest was left out.`, 'observed');
    else if (r.headers.some(h => h.cut)) add('info', 'A very long header was cut short', `${r.headers.filter(h => h.cut).map(h => h.name).slice(0, 5).join(', ')}: only the first ${LIMITS.valueChars / 1024} KB of each was read.`, 'observed');
    if (r.boundary < 0 && r.hops.length) {
      if (r.edge.foreign && r.edge.buried >= 0) add('warn', 'Your entry point is not the newest hop', `A hop received by ${r.hops[r.edge.buried].by} sits below newer hops written by ${r.edge.foreign}, which is not Exchange Online or one of your domains. That happens when mail is forwarded out of your systems, or when a sender forges a Received line, so MailAnalyzer does not treat it as where this copy arrived. Every verdict below is a claim.`, 'inferred');
      else add('info', 'Could not find where the message entered your systems', `${r.edge.foreign ? `The newest hop was received by ${r.edge.foreign}, which is not Exchange Online or one of your domains (set them in About)` : 'No hop was received by Exchange Online\'s inbound front door or a host on your domains (set them in About)'}, so MailAnalyzer cannot tell which verdict headers your own servers wrote. Every verdict below is a claim.`, 'inferred');
    }
    if (r.edge.held) add('info', 'A hop below your entry point also names your systems', `${r.edge.held} received the message before your entry point, but the hop above it does not show it arriving from your domains over a private address, so MailAnalyzer does not extend trust to it. Headers between the two are treated as claims.`, 'inferred');
    if (untrustedAuth) add('bad', 'Authentication results sit below your gateway', `The ${r.authSource} header used here appears below the Received line of your entry point, so the sender could have written it. Do not rely on these SPF/DKIM/DMARC values.`, 'inferred');
    else if (r.authSource && r.authTrust === 'unknown') add('warn', 'Could not confirm who wrote the authentication results', `MailAnalyzer could not place the ${r.authSource} header relative to your own servers, so the SPF/DKIM/DMARC values below are claims, not confirmed verdicts from your gateway.`, 'inferred');
    if (r.arHeaders.length > 1) { const bad = r.arHeaders.filter(h => r.trustOf(h, true) === 'untrusted').length; if (bad) add('info', `${bad} Authentication-Results header${bad === 1 ? '' : 's'} from before your gateway ignored`, 'Sender-side servers (or the sender) added them; only results stamped after the message reached you are used.', 'inferred'); }
    if (r.spf?.viaReceivedSpf && r.spf.trust === 'untrusted') add('warn', 'The only Received-SPF header sits below your gateway', 'The sender could have written it, so its SPF result is a claim.', 'inferred');
    // DMARC / auth
    if (r.dmarc) {
      const action = r.dmarc.props.action ? ` \u00B7 action ${r.dmarc.props.action}` : '';
      if (/fail/.test(r.dmarc.result)) add('bad', `DMARC ${r.dmarc.result} for ${r.dmarc.props['header.from'] || r.fromDomain}${action}`, `${DMARC_MEANING.fail} SPF ${r.spf?.result || 'none'} (${r.spfDomain || 'no domain'}, ${r.spfAlignedDomain ? 'aligned' : 'not aligned'}); DKIM ${r.dkims.map(d => `${d.result} ${d.props['header.d'] || ''}`.trim()).join(', ') || 'none'}.`, untrustedAuth ? 'untrusted' : 'reported', rep, 'impersonation');
      else if (r.dmarc.result === 'pass') add(untrustedAuth ? 'warn' : r.authTrust === 'trusted' ? 'good' : 'info', `DMARC pass${untrustedAuth ? ' claimed' : r.authTrust === 'trusted' ? '' : ' (writer not confirmed)'} for ${r.dmarc.props['header.from'] || r.fromDomain}`, `Carried by ${r.spfAligned && r.dkimAligned ? 'SPF and DKIM' : r.spfAligned ? 'SPF' : r.dkimAligned ? 'DKIM' : 'a mechanism MailAnalyzer could not match from the other results'}.`, untrustedAuth ? 'untrusted' : 'reported', rep);
      else if (r.dmarc.result === 'bestguesspass') add('info', 'DMARC best-guess pass', DMARC_MEANING.bestguesspass, untrustedAuth ? 'untrusted' : 'reported', rep);
      else add('warn', `DMARC ${r.dmarc.result}`, DMARC_MEANING[r.dmarc.result] || 'DMARC did not produce a pass.', untrustedAuth ? 'untrusted' : 'reported', rep);
    } else if (r.authSource) add('warn', 'No DMARC verdict recorded', `MailAnalyzer computed alignment from the reported SPF/DKIM results: DMARC ${r.spfAligned || r.dkimAligned ? 'would pass' : 'would fail'} if ${r.fromDomain || 'the From domain'} publishes a policy.`, 'inferred');
    else add('warn', 'No Authentication-Results header', 'These headers carry no SPF/DKIM/DMARC verdict. They may be trimmed, or were captured before the receiving gateway.', 'observed');
    if (r.compauth) {
      const code = r.compauth.props.reason || '';
      if (r.compauth.result === 'fail') add('bad', `Microsoft composite authentication failed${code ? ` (reason ${code})` : ''}`, compauthReason(code), untrustedAuth ? 'untrusted' : 'reported', 'Microsoft 365', 'impersonation');
      else if (r.compauth.result === 'softpass') add('warn', `Microsoft composite authentication soft-pass${code ? ` (reason ${code})` : ''}`, compauthReason(code), untrustedAuth ? 'untrusted' : 'reported', 'Microsoft 365');
    }
    if (r.spf && /^(fail|softfail|permerror|temperror)$/.test(r.spf.result)) {
      const rows = Object.fromEntries(spfExplain(r));
      add(r.spf.result === 'fail' && !r.dkimAligned ? 'bad' : 'warn', `SPF ${r.spf.result} for ${r.spfDomain || 'the envelope sender'}`, `Sending IP ${r.sendingIp?.ip || 'not recorded'}. ${rows.meaning} ${rows['for DMARC']}`, spfBasis(r), r.spf.viaReceivedSpf ? 'Received-SPF' : rep);
    }
    dkimRows(r).filter(d => /fail|permerror|temperror/.test(d.result)).forEach(d => add(r.spfAligned || r.dkimAligned ? 'warn' : 'bad', `DKIM ${d.result} for ${d.domain || 'a signature'}`, `${DKIM_MEANING[d.result] || ''} ${Object.fromEntries(d.rows)['for DMARC']}`, untrustedAuth ? 'untrusted' : 'reported', rep));
    if (r.authSource && !r.dkims.length && !r.signatures.length) add('info', 'Message is not DKIM-signed', 'Only SPF can authenticate it, and SPF breaks when mail is forwarded.', 'observed');

    // DKIM signatures that cover less than they appear to
    r.signatures.slice(0, 20).forEach(s => {
      const d = (s.d || '?').toLowerCase(), passed = r.dkimPassDomains.includes(d);
      if (s.l) add(passed ? 'warn' : 'info', `DKIM signature for ${d} covers only part of the body (l=${s.l.slice(0, 20)})`, 'Anything after that many bytes is outside the signature, so text can be added to a signed message and it still verifies.', 'observed');
      if (s.h && !s.h.toLowerCase().split(':').includes('from')) add(passed ? 'warn' : 'info', `DKIM signature for ${d} does not cover the From header`, 'RFC 6376 requires the From header to be signed; without it the signature vouches for nothing about the sender people see.', 'observed');
    });

    // Header structure: fields that may appear only once (RFC 5322 3.6). Mail programs disagree on which copy
    // they show, so a second From is a known way to display one sender while another is checked.
    const repeated = ['from', 'sender', 'reply-to', 'to', 'cc', 'subject', 'date', 'message-id'].map(n => [n, r.all(n)]).filter(([, hs]) => hs.length > 1);
    repeated.filter(([, hs]) => new Set(hs.map(h => h.value.trim())).size > 1).forEach(([n, hs]) => {
      const identity = /^(from|sender|reply-to)$/.test(n);
      add(identity ? 'bad' : 'warn', `${hs[0].name} header appears ${hs.length} times with different values`, `${hs.slice(0, 4).map(h => `"${h.value.slice(0, 300)}"`).join(' and ')}. This field may appear only once, and mail programs differ on which copy they show.`, 'observed', '', identity ? 'impersonation' : '');
    });
    const same = repeated.filter(([, hs]) => new Set(hs.map(h => h.value.trim())).size === 1);
    if (same.length) add('info', 'Headers repeated with identical values', `${same.map(([, hs]) => hs[0].name).join(', ')}. Usually a copy-paste artifact.`, 'observed');
    const fromAddrs = new Set(r.fromList.map(m => m.addr.toLowerCase()).filter(a => a.includes('@')));
    if (fromAddrs.size > 1) add('warn', 'From lists more than one address', `${[...fromAddrs].slice(0, 5).join(', ')}. Mail programs show one of them; authentication may have checked another.`, 'observed', '', 'impersonation');

    // Identity mismatches (read straight from sender-controlled headers)
    const fromOrg = orgDomain(r.fromDomain);
    if (r.from.name && r.from.name.includes('@')) {
      const shown = firstAddr(r.from.name).toLowerCase();
      if (shown && shown !== r.from.addr.toLowerCase()) add('bad', 'Display name shows a different address', `Shown as "${r.from.name.slice(0, 300)}" but the actual From address is ${r.from.addr}.`, 'observed', '', 'impersonation');
    }
    if (/^"[^"]*@[^"]*"@/.test(r.from.addr)) add('bad', 'The From mailbox name contains another address', `${r.from.addr.slice(0, 300)}: some mail programs show only the quoted part, but the message is from ${r.fromDomain}.`, 'observed', '', 'impersonation');
    // Lookalike and international domains, against your domains (About) and commonly impersonated brands
    const own = OWN_DOMAINS.filter(d => d.includes('.') && !d.includes('*')), isOwn = d => own.some(o => orgDomain(o) === orgDomain(d));
    const flagged = new Set();
    [['From', r.fromDomain], ['Reply-To', domainOf(r.replyTo?.addr)], ['Sender', domainOf(r.sender?.addr)]].forEach(([field, d]) => {
      if (!d || d.length > 253 || flagged.has(d) || isOwn(d)) return;
      const shown = toUnicode(d), sent = shown !== d ? ` (sent as ${d})` : '';
      const mine = own.map(o => [o, lookalike(d, o)]).find(([, how]) => how);
      if (mine) { flagged.add(d); return add(/different ending/.test(mine[1]) ? 'warn' : 'bad', `${field} domain imitates your domain ${mine[0]}`, `${shown}${sent} ${mine[1]}. Check the spelling before you reply, click or pay.`, 'inferred', '', 'impersonation'); }
      const brand = BRANDS.filter(b => !b.domains.test(orgDomain(shown))).map(b => [b, lookalike(d, b.home, false)]).find(([, how]) => how);
      if (brand) { flagged.add(d); return add('bad', `${field} domain imitates ${brand[0].name} (${brand[0].home})`, `${shown}${sent} ${brand[1]}.`, 'inferred', '', 'phish'); }
      const kin = own.find(o => cousin(shown, o));
      if (kin) { flagged.add(d); return add('warn', `${field} domain borrows your name`, `${shown} is not ${kin} but reuses its name with extra words. Common in invoice and payment fraud.`, 'inferred', '', 'impersonation'); }
      if (shown === d && !/[^\x00-\x7f]/.test(d)) return;
      flagged.add(d);
      const scripts = scriptsOf(shown), reads = skeleton(shown);
      if (shown.split('.').some(l => { const s = scriptsOf(l); return s.length > 1 && s.includes('Latin'); })) add('bad', `${field} domain mixes alphabets`, `${shown}${sent} mixes ${scripts.join(' and ')} letters${reads !== shown ? ` and reads as ${reads}` : ''}.`, 'observed', '', 'impersonation');
      else if (reads !== shown && !/[^\x00-\x7f]/.test(reads)) add('bad', `${field} domain is spelled with lookalike letters`, `${shown}${sent} reads as ${reads} but uses ${scripts.join(' and ') || 'non-Latin'} letters.`, 'observed', '', 'impersonation');
      else add('info', `${field} domain uses international characters`, `${d} displays as ${shown}.`, 'observed');
    });
    // The display name: hidden characters, mixed alphabets, a brand or IT role from someone else's domain
    const name = r.from.name.slice(0, 1000), nameReads = skeleton(name);
    const hiddenSender = hiddenIn(`${name}${r.from.addr}`);
    if (hiddenSender.length) add('warn', 'Hidden characters in the sender', `${hiddenSender.join(', ')}. They do not show on screen; senders use them to dodge filters or disguise a name.`, 'observed', '', 'impersonation');
    const mixedWord = name.split(/\s+/).find(w => { const s = scriptsOf(w); return s.length > 1 && s.includes('Latin'); });
    if (mixedWord) add('warn', 'Sender name mixes alphabets', `"${mixedWord.slice(0, 100)}" mixes ${scriptsOf(mixedWord).join(' and ')} letters and reads as "${skeleton(mixedWord).slice(0, 100)}".`, 'observed', '', 'impersonation');
    const systemSender = /^(microsoftexchange[0-9a-f]{32}|postmaster|mailer-daemon)@/i.test(r.from.addr);
    if (name && r.fromDomain && !isOwn(r.fromDomain) && !systemSender) {
      const brand = BRANDS.find(b => b.rx.test(nameReads)), disguised = brand && !brand.rx.test(name);
      if (brand && !brand.domains.test(fromOrg)) add(disguised ? 'bad' : 'warn', `Sender name says ${brand.name}, but the address is not ${brand.name}'s`, `"${name.slice(0, 300)}" <${r.from.addr}>: ${fromOrg} is not one of ${brand.name}'s sending domains (${brand.home}). A brand in the sender name is the most common phishing disguise${disguised ? ', and here it is spelled with lookalike letters' : '; it can also be a service the brand really uses'}.`, 'inferred', '', 'phish');
      else if (own.length && IT_ROLE.test(nameReads)) add('warn', 'Sender name poses as IT or mail support', `"${name.slice(0, 300)}" <${r.from.addr}>, which is not one of your domains. Fake IT and mailbox notices are a common way to steal passwords.`, 'inferred', '', 'phish');
    }
    if (FREEMAIL.has(fromOrg) && ROLE_WORDS.test(nameReads)) add('warn', 'Free webmail account using a business or role name', `"${name.slice(0, 300)}" <${r.from.addr}>. A consumer mailbox presented as a company or a finance role is how business email compromise often starts; confirm through a contact you already know.`, 'inferred', '', 'impersonation');
    const hiddenSubject = hiddenIn(r.subject);
    if (hiddenSubject.length) add('warn', 'Hidden characters in the subject', `${hiddenSubject.join(', ')}. Invisible characters split words so keyword filters miss them.`, 'observed');
    // Reply-To: lookalike of From, free webmail, a cousin domain, or just a different domain (strongest one only)
    const replyDomain = domainOf(r.replyTo?.addr);
    if (r.replyTo && r.replyTo.addr && orgDomain(replyDomain) !== fromOrg && !flagged.has(replyDomain)) {
      const look = r.fromDomain && lookalike(replyDomain, r.fromDomain);
      if (look) add('bad', 'Reply-To imitates the From domain', `Replies go to ${r.replyTo.addr}: ${toUnicode(replyDomain)} ${look} (${r.fromDomain}).`, 'inferred', '', 'impersonation');
      else if (FREEMAIL.has(orgDomain(replyDomain)) && !FREEMAIL.has(fromOrg)) add('warn', 'Replies go to a free webmail account', `From ${r.fromDomain || '?'}, but replies go to ${r.replyTo.addr}. The classic business email compromise setup; small businesses invoicing through a platform do it too, so confirm through a contact you already know before paying.`, 'observed', '', 'impersonation');
      else if (r.fromDomain && cousin(replyDomain, r.fromDomain)) add('warn', 'Reply-To uses a cousin of the From domain', `Replies go to ${r.replyTo.addr}, a different domain built on the name ${fromOrg.split('.')[0]}. Common in invoice and payment fraud.`, 'inferred', '', 'impersonation');
      else add('warn', 'Reply-To goes to a different domain', `Replies go to ${r.replyTo.addr}, not ${r.fromDomain || 'the From domain'}. Normal for some ticketing and marketing tools; a red flag on invoices and payment requests.`, 'observed');
    }
    if (r.returnPath && fromOrg && orgDomain(domainOf(r.returnPath)) !== fromOrg) add('info', 'Envelope sender differs from From', `Return-Path ${domainOf(r.returnPath)} vs From ${r.fromDomain}. Expected for bulk senders (Mailgun, SendGrid, SES); DKIM then has to carry DMARC.`, 'observed');
    if (r.sender && r.sender.addr && orgDomain(domainOf(r.sender.addr)) !== fromOrg) add('info', 'Sent on behalf of', `Sender: ${r.sender.addr}`, 'observed');

    // Microsoft 365 verdicts
    const msBasis = r.ms.ffTrust === 'untrusted' ? 'untrusted' : 'reported';
    if (r.ms.verdicts && r.ms.ffTrust === 'unknown') add('warn', 'Could not confirm that your Microsoft 365 tenant wrote these stamps', 'Microsoft 365 verdict headers are present, but the message did not enter your systems through Exchange Online\'s front door as far as the Received chain shows (forwarded mail, a partial paste, or forged headers), so the decoded verdicts below are claims.', 'inferred');
    if (r.forefront) {
      const sfv = r.forefront.SFV, cat = r.forefront.CAT, scl = parseInt(r.ms.scl, 10), sfty = r.forefront.SFTY;
      if (cat && BAD_CAT.has(cat)) add('bad', `Microsoft classified it as ${CAT[cat] || cat}`, `CAT:${cat} \u00B7 SFV:${sfv || '?'} (${SFV[sfv] || 'unknown'}) \u00B7 SCL ${Number.isNaN(scl) ? '?' : scl}`, msBasis, 'Microsoft 365', CAT_OF_MS[cat]);
      else if (sfv === 'SPM' || scl >= 5) add('warn', 'Microsoft marked it as spam', `SFV:${sfv || '?'} (${SFV[sfv] || 'unknown'}) \u00B7 SCL ${Number.isNaN(scl) ? '?' : `${scl}: ${sclMeaning(scl)}`}`, msBasis, 'Microsoft 365', 'spam');
      else if (sfv && /^(SKA|SKN|SKS|SFE|SKQ)$/.test(sfv)) add('info', `Microsoft spam filtering was bypassed (${sfv})`, SFV[sfv], msBasis, 'Microsoft 365');
      if (sfty) { const tipCat = sfty === '9.1' ? 'phish' : /^9\.(11|19|20|21|22|23|24)$/.test(sfty) ? 'impersonation' : ''; add(tipCat ? 'warn' : 'info', `Safety tip SFTY:${sfty.slice(0, 10)}`, SFTY[sfty] || 'Undocumented safety tip code.', msBasis, 'Microsoft 365', tipCat); }
      if (r.forefront.SRV === 'BULK') add('info', 'Microsoft flagged it as bulk mail (SRV:BULK)', `BCL ${r.ms.bcl || '?'}: ${bclMeaning(r.ms.bcl)}`, msBasis, 'Microsoft 365', 'bulk');
    } else if (r.ms.scl && parseInt(r.ms.scl, 10) >= 5) add('warn', `Exchange SCL ${r.ms.scl}`, sclMeaning(r.ms.scl), msBasis, 'Exchange', 'spam');
    const bcl = parseInt(r.ms.bcl, 10), pcl = parseInt(r.ms.pcl, 10);
    if (bcl >= 7) add('warn', `High bulk complaint level (BCL ${bcl})`, bclMeaning(bcl), msBasis, 'Microsoft 365', 'bulk');
    if (pcl >= 4) add('warn', `Phishing confidence level ${pcl}`, pclMeaning(pcl), msBasis, 'Microsoft 365', 'phish');
    // Mailbox delivery: which folder Exchange filed it in (an undocumented header, decoded only as far as observed)
    if (r.ms.mbx?.DEST) {
      const dest = r.ms.mbx.DEST.slice(0, 20), basis = r.ms.mbxTrust === 'untrusted' ? 'untrusted' : 'reported', why = [r.ms.mbx.OFR && `OFR:${r.ms.mbx.OFR.slice(0, 60)}`, r.ms.mbx.RF && `RF:${r.ms.mbx.RF.slice(0, 60)}`].filter(Boolean).join(' \u00B7 ');
      if (dest === 'J') add('warn', 'Delivered to the Junk Email folder', `dest:J${why ? ` \u00B7 ${why}` : ''}. Microsoft does not document this header; dest:J is what Exchange records on mail it files in Junk Email.`, basis, 'Microsoft 365', 'spam');
      else add('info', MBX_DEST[dest] ? `Delivered to the ${MBX_DEST[dest]}` : `Delivered to folder code "${dest}"`, `dest:${dest}${why ? ` \u00B7 ${why}` : ''}. Microsoft does not document this header${MBX_DEST[dest] ? '' : ', and MailAnalyzer does not recognize this value'}.`, basis, 'Microsoft 365');
    }
    if (r.msUntrusted.length) add('info', 'Microsoft antispam headers from before your tenant were set aside', `${r.msUntrusted.map(h => h.name).slice(0, 6).join(', ')}: Exchange renames these when they arrive from outside (another tenant, or forged). They are not your tenant's verdict and are ignored here.`, 'observed');
    if (r.ms.authAs && /^anonymous$/i.test(r.ms.authAs) && r.fromDomain && OWN.test(r.fromDomain)) add('warn', 'Claims to be from your own domain but arrived unauthenticated', `From ${r.fromDomain}, but Exchange recorded AuthAs: Anonymous (external, not your own servers). Typical of spoofing your own domain unless a third-party sender is configured for it.`, msBasis, 'Microsoft 365', 'impersonation');

    // Open-source filter and scanner verdicts: one finding per verdict, however many stamps agree
    ['malware', 'phish', 'spam'].forEach(verdict => {
      const hits = r.filterHits.filter(x => x.verdict === verdict);
      if (!hits.length) return;
      const trusted = hits.filter(x => r.trustOf(x.header) !== 'untrusted'), use = trusted.length ? trusted : hits;
      const basis = trusted.length ? 'reported' : 'untrusted', by = [...new Set(use.map(x => x.header.name))].join(' / ');
      const detail = use.map(x => `${x.header.name}${x.note ? `: ${x.note}` : ''}`).join('; ');
      if (verdict === 'malware') add('bad', 'A virus scanner reported it infected', detail, basis, by, 'malware');
      else if (verdict === 'phish') add('warn', 'A spam filter matched phishing rules', detail, basis, by, 'phish');
      else add('warn', 'A spam filter marked it as spam', detail, basis, by, 'spam');
    });

    // Bulk and automated mail (not threats; they name what kind of mail it is)
    if (r.bulkMarks.length) add('info', 'Bulk or list mail', `${r.bulkMarks.join(' \u00B7 ')}.${r.get('list-unsubscribe') && !r.oneClick ? ' No one-click unsubscribe (RFC 8058), which Gmail and Yahoo require from bulk senders.' : ''}`, 'observed', '', 'bulk');
    if (r.autoMarks.length) add('info', 'Automated message', `${r.autoMarks.join(' \u00B7 ')}: an auto-reply, bounce or system notice rather than mail a person wrote.`, 'observed', '', 'automated');

    // Route (timestamps are server-claimed; the arithmetic is ours)
    if (r.timed.length >= 2) {
      const total = r.timed[r.timed.length - 1].t - r.timed[0].t;
      const worst = r.hops.reduce((w, h, i) => h.delay != null && (w == null || h.delay > r.hops[w].delay) ? i : w, null);
      const held = worst != null && worst > 0 && r.hops[worst].delay > 0 ? `Longest gap: ${fmtDur(r.hops[worst].delay)} sitting at ${r.hops[worst - 1].by || 'hop ' + worst}${r.hops[worst - 1].bySys ? ` (${r.hops[worst - 1].bySys.label})` : ''} before it reached ${r.hops[worst].by || 'the next hop'} (hop ${worst} \u2192 ${worst + 1}). Based on each server's own timestamp.` : '';
      if (total > 15 * 60e3) add('bad', `Delivery took ${fmtDur(total)}`, held, 'inferred');
      else if (total > 2 * 60e3) add('warn', `Delivery took ${fmtDur(total)}`, held, 'inferred');
      if (r.hops.some(h => h.delay != null && h.delay < -5000)) add('info', 'Clock skew between servers', 'At least one hop is stamped earlier than the hop before it, so the servers\' clocks disagree. Delays around that hop are unreliable.', 'inferred');
    }
    if (r.dateHeader != null && r.timed.length) {
      const lag = r.timed[0].t - r.dateHeader;
      if (lag > 60 * 60e3) add('warn', `First hop is ${fmtDur(lag)} after the Date header`, 'The message sat in an outbox or queue, or was resent. The Date header is written by the sender.', 'inferred');
      else if (lag < -60 * 60e3) add('info', 'Date header is later than the first hop', "The sender's clock is off, or the Date header was set deliberately.", 'inferred');
    }
    const plain = r.hops.filter((h, i) => i > 0 && h.from && !h.tls && h.ip && !isPrivateIp(h.ip));
    if (plain.length) add('info', `${plain.length} public hop${plain.length === 1 ? '' : 's'} with no TLS noted`, `${plain.slice(0, 6).map(h => `${h.from} \u2192 ${h.by}`).join('; ')}. Absence of a TLS marker is not proof it was unencrypted; formats vary.`, 'inferred');

    const order = { bad: 0, warn: 1, info: 2, good: 3 };
    if (!f.some(x => x.sev === 'bad' || x.sev === 'warn')) add('good', 'Nothing alarming', 'Reported authentication and gateway verdicts look normal.', 'inferred');
    return f.sort((a, b) => order[a.sev] - order[b.sev]);
  }
  // Categories in CATEGORIES order. A filter's own verdict makes one "reported"; otherwise it is MailAnalyzer's
  // reading, worded "likely" when a serious finding supports it and "possible" when only warnings do.
  function categorize(findings) {
    return CATEGORIES.map(c => {
      const support = findings.filter(x => x.cat === c.key && x.basis !== 'untrusted' && (c.benign || x.sev === 'bad' || x.sev === 'warn'))
        .sort((a, b) => (b.basis === 'reported') - (a.basis === 'reported'));
      if (!support.length) return null;
      const reported = support.find(x => x.basis === 'reported');
      const strength = reported || c.benign ? '' : support.some(x => x.sev === 'bad') ? 'Likely' : 'Possible';
      return { ...c, support, basis: reported ? 'reported' : c.benign ? 'observed' : 'inferred', by: reported?.by || '', title: strength ? `${strength} ${c.label.toLowerCase()}` : c.label };
    }).filter(Boolean);
  }
  const verdictOf = r => r.findings[0]?.sev === 'bad' ? 'Suspicious' : r.findings[0]?.sev === 'warn' ? 'Passed, with warnings' : 'Looks clean';

  // ---------- troubleshooting report ----------
  // Masks the mailbox part of anything shaped like an address: j***@example.com, a quoted mailbox name
  // ("j***"@example.com), every character RFC 5322 allows in one, and hosts with no dot. A match starts only at the
  // beginning of a run of mailbox characters (the lookbehind), so a long run without an @ costs linear time.
  const ATEXT = "\\p{L}\\p{N}!#$%&'*+/=?^_`{|}~.-";
  const EMAIL_RX = new RegExp(`(?<![${ATEXT}])([${ATEXT}]+)@([\\p{L}\\p{N}-]+(?:\\.[\\p{L}\\p{N}-]+)*)`, 'gu');
  const QUOTED_RX = /"((?:[^"\\\n]|\\.){1,256})"@([\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)*)/gu;
  const keepFirst = local => { const k = /[\p{L}\p{N}]/u.exec(local); return k ? local.slice(0, k.index + 1) : ''; };
  function mask(s) {
    return String(s ?? '').replace(QUOTED_RX, (m, local, domain) => `"${keepFirst(local)}***"@${domain}`).replace(EMAIL_RX, (m, local, domain) => `${keepFirst(local)}***@${domain}`);
  }
  const REPORT_DEFAULTS = { redact: true, subject: false, notes: true, raw: false };
  function reportOptions(json) { try { const o = JSON.parse(json || '{}'); const out = { ...REPORT_DEFAULTS }; if (o && typeof o === 'object') Object.keys(REPORT_DEFAULTS).forEach(k => { if (typeof o[k] === 'boolean') out[k] = o[k]; }); return out; } catch { return { ...REPORT_DEFAULTS }; } }
  function buildReport(r, o = REPORT_DEFAULTS, now = Date.now()) {
    const m = s => o.redact ? mask(s) : String(s ?? '');
    const addrLine = a => a ? `${a.name && !a.name.includes('@') ? `${a.name} ` : ''}<${m(a.addr)}>` : '-';
    const listAddrs = v => { const list = parseMailboxes(v).map(x => x.addr).filter(Boolean); return list.length ? list.map(m).join(', ') : '-'; };
    const pad2 = (s, n) => String(s).padEnd(n);
    const counts = ['bad', 'warn', 'info'].map(s => r.findings.filter(x => x.sev === s).length);
    const L = [];
    L.push(`EMAIL HEADER ANALYSIS (MailAnalyzer v${VERSION})`, `Generated ${fmtTime(now)} local time (${utcOffset(now)}); every time below is local too.`);
    L.push(o.redact ? 'Partially masked: only the mailbox names in addresses are hidden. Display names, domains, host names, IP addresses, message IDs and encoded values are left as they are, so this report is not anonymized.' : 'Not masked: addresses appear in full.');
    L.push('');
    L.push(`VERDICT: ${verdictOf(r).toUpperCase()} (${counts[0]} serious, ${counts[1]} warnings, ${counts[2]} notes)`);
    const top = r.categories[0];
    if (top) L.push(`CATEGORY: ${top.title} (${top.basis}${top.by ? `: ${top.by}` : ''})${r.categories.length > 1 ? `; also ${r.categories.slice(1).map(c => c.title).join(', ')}` : ''}`, `  because: ${top.support.slice(0, 3).map(x => m(x.title)).join('; ')}`);
    L.push('');
    L.push('MESSAGE  [observed: written by the sender]');
    L.push(`  From:         ${addrLine(r.from)}`);
    if (r.replyTo) L.push(`  Reply-To:     ${m(r.replyTo.addr)}`);
    L.push(`  Return-Path:  ${m(r.returnPath) || '-'}`, `  To:           ${listAddrs(r.get('to'))}`);
    if (r.get('cc')) L.push(`  Cc:           ${listAddrs(r.get('cc'))}`);
    L.push(`  Subject:      ${o.subject ? '[hidden]' : m(r.subject) || '-'}`, `  Date:         ${r.get('date') || '-'}`, `  Message-ID:   ${r.get('message-id') || '-'}`);
    if (r.ms.networkId) L.push(`  Network-Message-Id: ${r.ms.networkId}   (Message trace / Explorer)`);
    L.push('');
    L.push(`AUTHENTICATION  [${r.authTrust === 'untrusted' ? 'UNTRUSTED: header sits below your gateway' : r.authTrust === 'unknown' ? `writer not confirmed: ${r.reporter || 'no server'}` : `reported by ${r.reporter || 'no server'}`}${r.authSource ? `, ${r.authSource}` : ''}; not re-verified]`);
    if (r.spf) L.push(`  SPF    ${pad2(r.spf.result, 9)} domain ${r.spfDomain || '-'}, sending IP ${r.sendingIp?.ip || '-'}${r.sendingIp ? ` (${r.sendingIp.inferred ? 'inferred' : 'reported'}: ${r.sendingIp.source})` : ''}, ${r.spfAlignedDomain ? 'aligned' : 'NOT aligned'} with From${spfBasis(r) === 'untrusted' && r.spf.viaReceivedSpf ? ' (UNTRUSTED Received-SPF)' : ''}`);
    else L.push('  SPF    none recorded');
    const dk = dkimRows(r);
    if (dk.length) dk.forEach(d => L.push(`  DKIM   ${pad2(d.result, 9)} d=${d.domain || '-'}${d.selector ? ` s=${d.selector}` : ''}, ${d.domain && orgDomain(d.domain) === orgDomain(r.fromDomain) ? 'aligned' : 'NOT aligned'} with From`));
    else L.push('  DKIM   none (no signature)');
    if (r.dmarc) L.push(`  DMARC  ${pad2(r.dmarc.result, 9)} header.from=${r.dmarc.props['header.from'] || r.fromDomain}${r.dmarc.props.action ? `, action=${r.dmarc.props.action}` : ''}; carried by ${r.spfAligned && r.dkimAligned ? 'SPF+DKIM' : r.spfAligned ? 'SPF' : r.dkimAligned ? 'DKIM' : 'neither'}`);
    else L.push(`  DMARC  none recorded; inferred: would ${r.spfAligned || r.dkimAligned ? 'pass' : 'fail'} on alignment`);
    if (r.compauth) L.push(`  compauth ${r.compauth.result} reason ${r.compauth.props.reason || '-'}: ${compauthReason(r.compauth.props.reason)}`);
    L.push('');
    if (r.ms.present) {
      const f = r.forefront || {};
      L.push(`MICROSOFT 365  [${r.ms.ffTrust === 'untrusted' ? 'UNTRUSTED position' : r.ms.ffTrust === 'unknown' ? 'not confirmed as your tenant\'s stamps' : 'reported by Exchange Online'}]`);
      const rows = [['SFV', f.SFV, SFV[f.SFV]], ['SCL', r.ms.scl, sclMeaning(r.ms.scl)], ['CAT', f.CAT, CAT[f.CAT]], ['BCL', r.ms.bcl, bclMeaning(r.ms.bcl)], ['PCL', r.ms.pcl, pclMeaning(r.ms.pcl)], ['SFTY', f.SFTY, SFTY[f.SFTY]], ['IPV', f.IPV, IPV[f.IPV]], ['CIP', f.CIP, f.CTRY ? `country ${f.CTRY}` : ''], ['DIR', f.DIR, DIR[f.DIR]], ['AuthAs', r.ms.authAs, ''], ['dest', r.ms.mbx?.DEST, `${MBX_DEST[r.ms.mbx?.DEST] || 'unrecognized folder code'} (Mailbox-Delivery, undocumented)`]].filter(x => x[1]);
      rows.forEach(([k, v, d]) => L.push(`  ${pad2(k, 7)}${pad2(v, 10)} ${d || ''}`.trimEnd()));
      L.push('');
    }
    L.push(`ROUTE  [oldest first; times are each server's own timestamp${r.boundary >= 0 ? '; trust boundary inferred' : '; no trust boundary found'}]`);
    r.hops.forEach((h, i) => {
      const where = r.boundary > 0 && i < r.boundary ? 'sender side' : i === r.boundary ? 'ENTERED YOUR SYSTEMS' : '';
      L.push(`  ${String(i + 1).padStart(2)}. ${h.from || '(origin)'}${h.ip ? ` [${h.ip}]` : ''} -> ${h.by || '?'}${h.bySys ? ` (${h.bySys.label})` : ''}`);
      L.push(`      ${h.t != null ? fmtTime(h.t) : 'no timestamp'}${h.delay != null ? `  ${h.delay < 0 ? fmtDur(h.delay) : `+${fmtDur(h.delay)}`}` : ''}${h.tls ? `  ${h.tlsVer || 'TLS'}` : ''}${where ? `  <${where}>` : ''}`);
    });
    if (r.timed.length >= 2) L.push(`  Total transit: ${fmtDur(r.timed[r.timed.length - 1].t - r.timed[0].t)}`);
    L.push('');
    L.push('FINDINGS');
    r.findings.filter(x => o.notes || x.sev === 'bad' || x.sev === 'warn').forEach(x => {
      L.push(`  [${{ bad: 'SERIOUS', warn: 'WARNING', info: 'NOTE', good: 'OK' }[x.sev]}] (${x.basis}${x.by && x.basis === 'reported' ? `: ${x.by}` : ''}) ${x.cat && x.basis !== 'untrusted' ? `{${CATEGORIES.find(c => c.key === x.cat).tag}} ` : ''}${m(x.title)}`);
      if (x.detail) L.push(`      ${m(x.detail)}`);
    });
    L.push('', 'Basis: reported = verdict a mail server wrote into a header; observed = read directly from header values (sender-controlled);', '       inferred = worked out by MailAnalyzer; untrusted = verdict header in a sender-controlled position.', 'MailAnalyzer does not query DNS, verify DKIM signatures or check reputation; it reports what the servers recorded.', 'Invisible and text-direction characters are shown as [U+XXXX].');
    if (o.raw) {
      let raw = r.headers.map(h => `${h.name}: ${h.value}`).join('\n');
      if (o.redact) raw = raw.split('\n').map(line => /^message-id:|^x-ms-exchange-organization-network-message-id:/i.test(line) ? line : mask(line)).join('\n');
      if (o.subject) raw = raw.replace(/^(subject|thread-topic):.*$/gim, '$1: [hidden]');
      L.push('', '----- ORIGINAL HEADERS (unfolded, top = newest) -----', raw);
    }
    return visible(L.join('\n'));
  }

  // ---------- Outlook .msg (OLE compound file) ----------
  // Only the top-level PR_TRANSPORT_MESSAGE_HEADERS stream is read: 007D001F (UTF-16) or 007D001E (8-bit).
  // Returns null when the file is not a readable compound file, '' when it has no internet headers. Every size,
  // count and sector number comes from the file, so each is checked against the file's real size before use.
  function msgHeaders(input) {
    const buf = input instanceof ArrayBuffer ? input : input?.buffer instanceof ArrayBuffer ? input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength) : null;
    if (!buf || buf.byteLength < 512 || buf.byteLength > LIMITS.msgBytes) return null;
    const v = new DataView(buf), u8 = new Uint8Array(buf), END = 0xFFFFFFFA, NONE = 0xFFFFFFFF;
    if (v.getUint32(0, true) !== 0xE011CFD0 || v.getUint32(4, true) !== 0xE11AB1A1) return null;
    const shift = v.getUint16(30, true), miniShift = v.getUint16(32, true);
    if ((shift !== 9 && shift !== 12) || miniShift !== 6) return null;
    const ss = 1 << shift, ms = 64, cutoff = v.getUint32(56, true), per = ss / 4;
    if (cutoff !== 4096) return null;
    const sectorCount = Math.ceil((buf.byteLength - ss) / ss);
    if (sectorCount < 1) return null;
    const at = n => (n + 1) * ss;
    const ok = n => n < sectorCount;
    const u32 = off => off + 4 <= buf.byteLength ? v.getUint32(off, true) : NONE;
    const numFat = v.getUint32(44, true);
    if (numFat < 1 || numFat > sectorCount) return null;
    const fatSecs = [];
    for (let i = 0; i < 109 && fatSecs.length < numFat; i++) { const s = v.getUint32(76 + i * 4, true); if (s >= END) continue; if (!ok(s)) return null; fatSecs.push(s); }
    for (let d = v.getUint32(68, true), seen = new Set(); d < END && fatSecs.length < numFat;) {
      if (!ok(d) || seen.has(d)) return null;
      seen.add(d);
      for (let i = 0; i < per - 1 && fatSecs.length < numFat; i++) { const s = u32(at(d) + i * 4); if (s >= END) continue; if (!ok(s)) return null; fatSecs.push(s); }
      d = u32(at(d) + (per - 1) * 4);
    }
    const fat = new Uint32Array(fatSecs.length * per);
    fatSecs.forEach((s, i) => { for (let j = 0; j < per; j++) fat[i * per + j] = u32(at(s) + j * 4); });
    // A sector chain; null when it links outside the table or runs longer than limit (which is how a cycle ends).
    const chain = (start, table, limit) => {
      const out = [];
      for (let s = start; s < END; s = table[s]) { if (s >= table.length || out.length >= limit) return null; out.push(s); }
      return out;
    };
    const gather = (secs, size, src, unit, offset) => {
      if (!secs || secs.length * unit < size) return null;
      const out = new Uint8Array(size);
      let p = 0;
      for (const s of secs) { const n = Math.min(unit, size - p); if (n <= 0) break; const o = offset(s); if (o + n > src.length) return null; out.set(src.subarray(o, o + n), p); p += n; }
      return out;
    };
    // gather() refuses a size the chain cannot hold before it allocates anything, so a huge claimed size costs nothing
    const read = (start, size) => gather(chain(start, fat, sectorCount), size, u8, ss, at);
    const dirStart = v.getUint32(48, true), dirChain = chain(dirStart, fat, sectorCount);
    if (!dirChain || !dirChain.length) return null;
    const dir = gather(dirChain, dirChain.length * ss, u8, ss, at);
    if (!dir) return null;
    const dv = new DataView(dir.buffer), entries = [], utf16 = new TextDecoder('utf-16le');
    for (let o = 0; o + 128 <= dir.length; o += 128) {
      const len = Math.min(dv.getUint16(o + 64, true), 64);
      entries.push({ name: len >= 2 ? utf16.decode(dir.subarray(o, o + len - 2)) : '', type: dir[o + 66], left: dv.getUint32(o + 68, true), right: dv.getUint32(o + 72, true), child: dv.getUint32(o + 76, true), start: dv.getUint32(o + 116, true), size: dv.getUint32(o + 120, true) });
    }
    const root = entries[0];
    if (!root || root.type !== 5) return null;
    const top = [], stack = [root.child], seen = new Set();
    while (stack.length) { const i = stack.pop(); if (i >= entries.length || seen.has(i)) continue; seen.add(i); top.push(entries[i]); stack.push(entries[i].left, entries[i].right); }
    const stream = e => {
      if (e.size >= cutoff) return read(e.start, e.size);
      if (root.size > buf.byteLength) return null;
      const miniCount = v.getUint32(64, true);
      if (miniCount > sectorCount) return null;
      const miniBytes = read(v.getUint32(60, true), miniCount * ss), miniStream = read(root.start, root.size);
      if (!miniBytes || !miniStream) return null;
      const miniFat = new Uint32Array(miniBytes.buffer, miniBytes.byteOffset, miniBytes.length / 4);
      return gather(chain(e.start, miniFat, Math.ceil(root.size / ms) + 1), e.size, miniStream, ms, s => s * ms);
    };
    const wide = top.find(e => e.type === 2 && /^__substg1\.0_007D001F$/i.test(e.name));
    if (wide) { const b = stream(wide); return b ? utf16.decode(b).replace(/\0+$/, '') : null; }
    const narrow = top.find(e => e.type === 2 && /^__substg1\.0_007D001E$/i.test(e.name));
    if (narrow) { const b = stream(narrow); return b ? new TextDecoder('windows-1252').decode(b).replace(/\0+$/, '') : null; }
    return '';
  }

  // ---------- browser storage ----------
  // Everything this page keeps, all in this browser. The message being looked at lives in sessionStorage (it goes
  // when the tab closes); the rest in localStorage. The app was called hops and then mops; their settings carry
  // over once, but only values that look like this app's, so another page's data on the same site is left alone.
  const KEYS = { theme: 'mailanalyzer_theme', report: 'mailanalyzer_report', recent: 'mailanalyzer_recent', domains: 'mailanalyzer_domains', message: 'mailanalyzer_message' };
  const LEGACY_PREFIXES = ['mops_', 'hops_'];
  const SOURCES = ['pasted', 'eml', 'msg'];
  const str = (x, n) => typeof x === 'string' ? x.slice(0, n) : '';
  // One recent entry, rebuilt from its header block (an old entry could hold a pasted body; this drops it).
  function normalizeRecent(x) {
    if (!x || typeof x !== 'object' || typeof x.text !== 'string' || typeof x.id !== 'string' || !Number.isFinite(x.at)) return null;
    const block = headerBlock(x.text.slice(0, LIMITS.recentChars * 2)).slice(0, LIMITS.recentChars);
    if (!block) return null;
    return { id: hashText(block), source: SOURCES.includes(x.source) ? x.source : 'pasted', name: str(x.name, 260), at: x.at, from: str(x.from, 320), subject: str(x.subject, 500), text: block };
  }
  function cleanRecent(list) {
    if (!Array.isArray(list)) return [];
    const seen = new Set();
    return list.map(normalizeRecent).filter(x => x && !seen.has(x.id) && seen.add(x.id)).slice(0, LIMITS.recentMax);
  }
  const VALIDATE = {
    theme: v => THEMES.includes(v) ? v : null,
    report: v => { const o = JSON.parse(v); if (!o || typeof o !== 'object' || Array.isArray(o)) return null; const keys = Object.keys(o); return keys.length && keys.every(k => k in REPORT_DEFAULTS && typeof o[k] === 'boolean') ? JSON.stringify(reportOptions(v)) : null; },
    recent: v => { const list = JSON.parse(v); if (!Array.isArray(list)) return null; const clean = cleanRecent(list); return clean.length || !list.length ? JSON.stringify(clean) : null; },
    domains: v => v.length <= 4096 && /^[\w.*@,;\s-]*$/.test(v) ? v : null
  };
  function migrateStorage(store) {
    const moved = [];
    for (const k of Object.keys(VALIDATE)) {
      for (const prefix of LEGACY_PREFIXES) {
        const old = prefix + k;
        let value = null;
        try { value = store.getItem(old); } catch { value = null; }
        if (value == null) continue;
        let clean = null;
        try { clean = VALIDATE[k](value); } catch { clean = null; }
        if (clean == null) continue; // not this app's: leave it alone
        try { if (store.getItem(KEYS[k]) == null) { store.setItem(KEYS[k], clean); moved.push(old); } store.removeItem(old); } catch { /* storage full or blocked */ }
      }
    }
    return moved;
  }

  // A synthetic sample: a vendor invoice sent through Mailgun to a Microsoft 365 tenant (documentation addresses only).
  const SAMPLE = [
    'Received: from CH3PR12MB8000.namprd12.prod.outlook.com (2603:10b6:610:1::12) by DM6PR12MB4000.namprd12.prod.outlook.com with HTTPS; Mon, 26 Oct 2026 14:08:19 +0000',
    'Received: from BN9PR03CA0001.namprd03.prod.outlook.com (2603:10b6:408:fe::6) by CH3PR12MB8000.namprd12.prod.outlook.com (2603:10b6:610:1::12) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8000.10; Mon, 26 Oct 2026 14:08:18 +0000',
    'Received: from BN2PEPF00000001.namprd04.prod.outlook.com (2603:10b6:408:fe:cafe::1) by BN9PR03CA0001.outlook.office365.com (2603:10b6:408:fe::6) with Microsoft SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8000.12 via Frontend Transport; Mon, 26 Oct 2026 14:08:18 +0000',
    'Authentication-Results: spf=pass (sender IP is 198.51.100.24)',
    ' smtp.mailfrom=mg.example-vendor.com; dkim=pass (signature was verified)',
    ' header.d=example-vendor.com;dmarc=pass action=none',
    ' header.from=example-vendor.com;compauth=pass reason=100',
    'Received-SPF: Pass (protection.outlook.com: domain of mg.example-vendor.com designates 198.51.100.24 as permitted sender) receiver=protection.outlook.com; client-ip=198.51.100.24; helo=m228-12.mailgun.net; pr=C',
    'Received: from m228-12.mailgun.net (198.51.100.24) by BN2PEPF00000001.mail.protection.outlook.com (10.167.243.10) with Microsoft SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8000.10 via Frontend Transport; Mon, 26 Oct 2026 14:08:17 +0000',
    'DKIM-Signature: a=rsa-sha256; v=1; c=relaxed/relaxed; d=example-vendor.com; q=dns/txt; s=mg; t=1792850499;',
    ' h=Content-Type: MIME-Version: Subject: From: Reply-To: To: Date: Message-Id; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=ExampleSignatureValue',
    'X-Mailgun-Sending-Ip: 198.51.100.24',
    'X-Mailgun-Sid: WyI3ZjNhMSIsICJhcEBleGFtcGxlLmNvbSIsICIxMjM0Il0=',
    'X-Mailgun-Tag: invoices',
    'Received: by 7f3a1c2b9d8e with HTTP id 671cf2a3e1b2c3d4e5f60718; Mon, 26 Oct 2026 14:01:39 GMT',
    'From: "Example Vendor Billing" <billing@example-vendor.com>',
    'Reply-To: "Accounts" <accounts@example-vendor-payments.net>',
    'To: Accounts Payable <ap@example.com>',
    'Subject: =?UTF-8?Q?Invoice_10482_-_payment_due?=',
    'Date: Mon, 26 Oct 2026 14:01:39 +0000',
    'Message-Id: <20261026140139.ab12cd34ef56@mg.example-vendor.com>',
    'Return-Path: bounce+1a2b3c.ap=example.com@mg.example-vendor.com',
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset="utf-8"',
    'X-MS-Exchange-Organization-SCL: 1',
    'X-Forefront-Antispam-Report: CIP:198.51.100.24;CTRY:US;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:m228-12.mailgun.net;PTR:m228-12.mailgun.net;CAT:NONE;SFS:(13230040)(4636009);DIR:INB;',
    'X-Microsoft-Antispam: BCL:3;PCL:0;ARA:13230040;',
    'X-MS-Exchange-Organization-AuthAs: Anonymous',
    'X-MS-Exchange-Organization-AuthSource: BN2PEPF00000001.namprd04.prod.outlook.com',
    'X-MS-Exchange-Organization-MessageDirectionality: Incoming',
    'X-MS-Exchange-Organization-Network-Message-Id: 3f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b',
    'X-MS-Exchange-CrossTenant-OriginalArrivalTime: 26 Oct 2026 14:08:17.8123 (UTC)',
    'X-MS-Exchange-CrossTenant-FromEntityHeader: Internet',
    'X-MS-Exchange-AtpMessageProperties: SA|SL'
  ].join('\n');

  return {
    VERSION, SHARE, LIMITS, THEMES, KEYS, SYSTEMS, SFV, CAT, IPV, SFTY, DIR, ATP, MBX_DEST, KNOWN, CATEGORIES, BRANDS, SAMPLE, REPORT_DEFAULTS,
    setDomains, getDomains, parseDomains, sclMeaning, bclMeaning, pclMeaning, compauthReason,
    fmtTime, fmtDur, utcOffset, hashText, visible, firstAddr, isPrivateIp, systemOf,
    splitHeaders, headerBlock, decodeWords, parseMailboxes, parseAddress, domainOf, orgDomain, parseMailDate, parseReceived, parseAuthResults, parseKv, tagsOf,
    punyDecode, toUnicode, skeleton, lookalike, cousin, hiddenIn, findBoundary,
    analyze, spfExplain, dkimRows, dmarcExplain, categorize, verdictOf, mask, reportOptions, buildReport, msgHeaders,
    normalizeRecent, cleanRecent, migrateStorage
  };
});
