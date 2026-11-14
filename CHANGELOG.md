# Changelog

## v1.0.1 - 2026-11-14

### Added

- **Back to RadMage Labs**, a link above the title, at every page width.
- **Share** in the toolbar. It opens your device's share sheet with the page's public address, `https://radmagelabs.com/mailanalyzer/`, or copies that address where there is no share sheet (or the sheet fails), and says whether the copy worked; if the clipboard is blocked, it shows the address instead. Closing the sheet does nothing. It shares the same address whether the page was opened on radmagelabs.com, on GitHub Pages or from a file on disk, with no query string or tracking parameters, and never anything you analyzed.

### Changed

- A shorter page title (`MailAnalyzer | Email Header Analyzer | RadMage Labs`, 51 characters, down from 95) and a shorter description (134 characters, down from 178). The link-preview description and the structured data now use the same description as the page.

## v1.0.0 - 2026-11-14

The first public release. MailAnalyzer was a private tool of mine before this, under the name mops; settings saved by that version (theme, report options, your domains and the recent list) carry over the first time the page opens.

### Features

- SPF, DKIM, DMARC, ARC and alignment analysis, with what each result means and which mechanism carried DMARC.
- Microsoft 365 and Exchange Online Protection decoding: SFV, SCL, CAT, BCL, PCL, SFTY, SRV, IPV, composite authentication reason codes, `X-MS-Exchange-Organization-*` stamps, Network-Message-Id and the Mailbox-Delivery folder.
- A trust boundary, and a basis on every verdict: reported, observed, inferred or untrusted.
- Received chain routing with per-hop delays, total transit, the longest gap, clock skew and TLS notes.
- Mailgun, Proofpoint, Mimecast, SpamAssassin, rspamd and virus scanner stamps.
- A category headline and phishing, impersonation and sender identity checks: lookalike, punycode and mixed-alphabet domains, brand and IT-support sender names, free webmail business roles, Reply-To tricks, display names showing another address, repeated headers, hidden characters and weak DKIM signatures.
- Pasted headers, `.eml`, Outlook `.msg` and text files, by button, shortcut or drag and drop.
- A troubleshooting report with mailbox masking, a hidden-subject option and the original headers.
- Recent history, original-header filtering, light and dark themes, keyboard shortcuts and a responsive layout.

### Corrected while preparing the release

- **Trust boundary:** the entry point was the oldest hop received by Exchange Online or your domains, so a forged Received line at the bottom of a message could make every header count as trusted. It is now the newest such hop, and only when every newer hop belongs to Microsoft 365 or your domains; otherwise every verdict is shown as unconfirmed.
- **Forged results with no sender-side hop:** when your edge received the message directly from the sender, the headers the sender wrote below it counted as trusted, so a forged "DMARC pass" read as clean. They are now untrusted.
- **Microsoft 365 stamps** were trusted whenever any hop named Exchange Online's front door, even a forged one. They are now trusted only when the message entered through it, and a warning says when they cannot be tied to your tenant.
- **Unnamed hops:** a newer hop with no name, or named only by an IP address, was passed over on the way down to the entry point, so a forged Exchange Online hop below it could be trusted. Only named Microsoft 365 servers are passed over now.
- **Connecting IP:** the address was taken from the first bracket in the Received line, which can sit inside the name the sender gave in HELO; it now comes from the receiving server's own note, so a sender cannot pose as one of your internal relays.
- **Received-SPF** was used without checking where it sat; one written by the sender is now marked untrusted and no longer supplies the sending IP or HELO name.
- **Sender address:** a quoted or encoded display name containing `<someone@example.org>` could become the From address that every check used, and so could a quoted mailbox name such as `"service@example.com"@example.net`, whose real domain is the second one. Addresses are now read from the header's structure before the name is decoded, and a quoted mailbox name holding another address is flagged.
- **Authentication-Results** split on semicolons inside comments and quoted values.
- **Stored bodies:** a message body pasted along with the headers was kept in the recent list and the tab's session, although the page said bodies were never kept. Only the header block is stored now (a body that happens to start with an `X-` line included), and older recent entries are cleaned when they carry over.
- **Slow input:** some crafted inputs took seconds to minutes (a 60 KB From header with no @ took about 5 seconds, and longer ones grew with the square of the length; long runs of blanks did the same). Parsing is linear now, with limits of 1 MB and 5000 headers per block and 64 KB per header.
- **Outlook .msg:** sizes, counts and sector numbers from the file were used without checks, so a corrupt file could ask for gigabytes of memory or loop. Every one is now checked against the file.
- **Dates** with no time zone were read in the viewer's own time zone; they are now UTC, as RFC 5322 says, and dates are read the same way in every browser.
- **Display:** text-direction and invisible characters in headers could reorder what was shown; they are now spelled out as `[U+XXXX]` on screen and in reports.
- **Masking** now covers addresses with non-ASCII names, every character a mailbox name may hold, quoted mailbox names, hosts with no dot, and addresses in the subject line; the report and the dialog say plainly that masking is partial and not anonymization.
- **Organizational domains** on shared hosting suffixes (such as `github.io`) are now told apart.
- **Layout:** the page scrolled sideways on phones narrower than about 420 pixels (the title row and long header names did not wrap).
- The scripts moved out of the page so a strict Content Security Policy can forbid inline scripts and every outgoing connection.
