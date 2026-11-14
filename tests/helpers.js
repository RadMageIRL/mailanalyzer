// Shared by the unit tests. Times are checked in UTC. MAILANALYZER_CORE points the tests at another copy of the core
// (used to run the suite against deliberately broken copies and make sure it notices).
// SPDX-License-Identifier: MIT
'use strict';
process.env.TZ = 'UTC';
const path = require('node:path');
const C = require(process.env.MAILANALYZER_CORE || path.join(__dirname, '..', 'mailanalyzer-core.js'));
const F = require('./fixtures.js');

/** Analyzes text with "your domains" set to `domains` (empty by default), so no test leaks into the next. */
function analyze(text, domains = '') { C.setDomains(domains); return C.analyze(text); }
const titles = r => r.findings.map(f => f.title);
/** The first finding whose title matches rx, or undefined. */
const find = (r, rx) => r.findings.find(f => rx.test(f.title));
const has = (r, rx) => r.findings.some(f => rx.test(f.title));

module.exports = { C, F, analyze, titles, find, has };
