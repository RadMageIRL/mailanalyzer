// Synthetic header fixtures shared by the unit and browser tests. Every address, domain and IP address here is an
// example or documentation value (RFC 2606 domains, RFC 5737 and RFC 3849 ranges, private ranges); Microsoft 365
// server names follow the public naming pattern with made-up numbers. Nothing comes from a real message.
// SPDX-License-Identifier: MIT
'use strict';

const DAY = 'Tue, 10 Nov 2026';
const join = (...parts) => parts.flat().filter(x => x !== null && x !== undefined && x !== false).join('\n');

// A message from a sender's own server to a Microsoft 365 tenant. Top to bottom: two internal Microsoft hops, the
// tenant's Authentication-Results and Received-SPF, the Exchange Online front door hop, whatever the sender's last
// server added (`senderSide`), the sender's own submission hop, then whatever the sender wrote (`bottom`) and the
// message headers, with Exchange's own stamps at the end.
function m365(o = {}) {
  const ar = 'ar' in o ? o.ar : 'spf=pass (sender IP is 198.51.100.24) smtp.mailfrom=example-vendor.com; dkim=pass (signature was verified) header.d=example-vendor.com;dmarc=pass action=none header.from=example-vendor.com;compauth=pass reason=100';
  const ff = o.forefront ?? 'CIP:198.51.100.24;CTRY:US;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:mail.example-vendor.com;PTR:mail.example-vendor.com;CAT:NONE;SFS:(13230040);DIR:INB;';
  return join(
    o.top || [],
    `Received: from SA1PR10MB0001.namprd10.prod.outlook.com (2603:10b6:806:1::1) by SA1PR10MB0002.namprd10.prod.outlook.com with HTTPS; ${DAY} ${o.t4 || '09:00:05'} +0000`,
    `Received: from DS7PEPF00000002.namprd05.prod.outlook.com (2603:10b6:8:1::2) by SA1PR10MB0001.namprd10.prod.outlook.com (2603:10b6:806:1::1) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.1.1; ${DAY} ${o.t3 || '09:00:04'} +0000`,
    ar === null ? [] : `Authentication-Results: ${ar}`,
    o.rspf === null ? [] : `Received-SPF: ${o.rspf || 'Pass (protection.outlook.com: domain of example-vendor.com designates 198.51.100.24 as permitted sender) receiver=protection.outlook.com; client-ip=198.51.100.24; helo=mail.example-vendor.com; pr=C'}`,
    `Received: from ${o.helo || 'mail.example-vendor.com'} (${o.ip || '198.51.100.24'}) by DS7PEPF00000002.mail.protection.outlook.com (10.167.1.2) with Microsoft SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.1.1 via Frontend Transport; ${DAY} ${o.t2 || '09:00:03'} +0000`,
    o.senderSide || [],
    o.noSenderHop ? [] : `Received: from [192.0.2.10] (unknown [192.0.2.10]) by mail.example-vendor.com (Postfix) with ESMTPSA id 4ABC12; ${DAY} ${o.t1 || '09:00:01'} +0000`,
    o.bottom || [],
    o.from ?? 'From: "Example Vendor" <billing@example-vendor.com>',
    o.replyTo || [],
    o.to ?? 'To: Accounts Payable <ap@example.com>',
    `Subject: ${o.subject ?? 'Invoice 10482'}`,
    `Date: ${o.date || `${DAY} 09:00:00 +0000`}`,
    `Message-ID: <${o.msgid || '20261110090000.4abc12@mail.example-vendor.com'}>`,
    'MIME-Version: 1.0',
    o.extra || [],
    o.ms === false ? [] : [
      `X-MS-Exchange-Organization-SCL: ${o.scl ?? 1}`,
      `X-Forefront-Antispam-Report: ${ff}`,
      `X-Microsoft-Antispam: ${o.antispam || 'BCL:0;'}`,
      'X-MS-Exchange-Organization-AuthAs: Anonymous',
      'X-MS-Exchange-Organization-MessageDirectionality: Incoming',
      'X-MS-Exchange-Organization-Network-Message-Id: 0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b',
      o.mbx ? `X-Microsoft-Antispam-Mailbox-Delivery: ${o.mbx}` : []
    ]
  );
}

// A message delivered to a mailbox on another provider's servers: no Exchange Online hop anywhere. The newest hop is
// written by the receiving provider (mx.example.net), which is not one of "your domains" unless the test sets it.
function otherProvider(o = {}) {
  return join(
    `Received: by 2001:db8:100::1 with SMTP id a1b2c3; ${DAY} 09:00:05 -0800 (PST)`,
    `Received: from mail.example-shop.com (mail.example-shop.com. [203.0.113.5]) by mx.example.net with ESMTPS id x9y8z7 for <someone@example.org> (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128); ${DAY} 09:00:04 -0800 (PST)`,
    o.ar === null ? [] : `Authentication-Results: mx.example.net; ${o.ar || 'dkim=pass header.i=@example-shop.com header.s=s1; spf=pass (example.net: domain of bounce@example-shop.com designates 203.0.113.5 as permitted sender) smtp.mailfrom=bounce@example-shop.com; dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=example-shop.com'}`,
    o.bottom || [],
    `Received: from [192.0.2.44] by mail.example-shop.com with ESMTPSA id q1; ${DAY} 09:00:02 -0800`,
    o.from ?? 'From: Example Shop <news@example-shop.com>',
    'To: someone@example.org',
    `Subject: ${o.subject ?? 'Your order has shipped'}`,
    `Date: ${DAY} 09:00:01 -0800`,
    'Message-ID: <q1.20261110@example-shop.com>',
    o.extra || []
  );
}

// An attacker's message to a mailbox that is NOT on Microsoft 365, carrying forged Microsoft headers at the bottom:
// a fake Exchange Online hop and stamps saying it is clean, and an Authentication-Results claiming DMARC passed.
function forgedMicrosoftAtBottom() {
  return otherProvider({
    ar: 'dkim=none; spf=softfail (example.net: domain of transitioning x@example-bad.test does not designate 203.0.113.5 as permitted sender) smtp.mailfrom=x@example-bad.test; dmarc=fail (p=REJECT) header.from=example-bank.test',
    bottom: [
      'Authentication-Results: spf=pass (sender IP is 198.51.100.9) smtp.mailfrom=example-bank.test; dkim=pass header.d=example-bank.test;dmarc=pass action=none header.from=example-bank.test;compauth=pass reason=100',
      `Received: from x.example-bad.test (198.51.100.9) by FAKE01.mail.protection.outlook.com (10.0.0.1) with Microsoft SMTP Server; ${DAY} 08:59:59 +0000`,
      'X-Forefront-Antispam-Report: CIP:198.51.100.9;CTRY:US;SCL:-1;SFV:SKA;CAT:NONE;DIR:INB;',
      'X-MS-Exchange-Organization-SCL: -1'
    ],
    from: 'From: Example Bank <alerts@example-bank.test>'
  });
}

module.exports = { DAY, join, m365, otherProvider, forgedMicrosoftAtBottom };
