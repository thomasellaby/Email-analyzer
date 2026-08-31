# Email Security Analyzer

A standalone Python tool that inspects emails for phishing and malware
indicators and produces a scored, explainable verdict. It works on full
`.eml` files (headers + body + attachments) or on a raw headers-only text
capture, and depends only on the Python standard library.

Script: [`email_security_analyzer.py`](email_security_analyzer.py)

## Requirements

- Python 3.9+
- No third-party packages required for core functionality
- Optional: `requests` (only needed if you enable VirusTotal hash lookups)

## Usage

```bash
# Full analysis of an .eml file (headers, body, URLs, attachments)
python email_security_analyzer.py analyze --eml suspicious.eml

# Machine-readable output
python email_security_analyzer.py analyze --eml suspicious.eml --json

# Write the report to a file instead of stdout
python email_security_analyzer.py analyze --eml suspicious.eml --json --out report.json

# Analyze raw headers only (e.g. pasted from "show original")
python email_security_analyzer.py analyze --headers headers.txt

# Extract attachments to disk for further manual/AV inspection
python email_security_analyzer.py analyze --eml suspicious.eml --save-attachments ./extracted

# Enable optional VirusTotal SHA256 reputation lookups for attachments
python email_security_analyzer.py analyze --eml suspicious.eml --vt-api-key YOUR_KEY
# or set the key via environment variable:
export VT_API_KEY=YOUR_KEY
python email_security_analyzer.py analyze --eml suspicious.eml
```

`--headers` mode only runs the header checks (no body/URL/attachment
content available); `--eml` mode runs the full pipeline.

## What it checks

### Headers
- SPF / DKIM / DMARC results parsed from `Authentication-Results`
- `Reply-To`, `Return-Path`, `Sender`, and `Message-ID` domain mismatches
  against the visible `From` domain
- Display-name brand impersonation (e.g. `"PayPal Support"` sent from a
  non-PayPal domain), checked against a built-in list of commonly
  impersonated brands
- Corporate-sounding senders (`support@`, `billing@`, `security@`, etc.)
  originating from free webmail providers (Gmail, Outlook, Yahoo, ...)
- Suspicious/bulk-mailer `X-Mailer` / `User-Agent` signatures
- Missing `Authentication-Results` / `Received` headers (reduces
  confidence, flagged as informational)

### Body (plain text and HTML)
- Urgency and pressure language ("account suspended", "verify your
  account", "act now", ...)
- Credential- and financial-harvesting language ("enter your password",
  "wire transfer", "gift card", "social security number", ...)
- Generic greetings ("Dear Customer") typical of mass phishing
- Hidden/visually suppressed HTML text (`display:none`, zero font-size,
  same-color-as-background) used to evade filters
- Embedded `<input type="password">` fields (credential harvesting forms
  should never appear inside an email body)
- `<script>` tags and `meta http-equiv="refresh"` redirects
- Long Base64 blobs in plaintext that decode to a URL or an executable
  signature (obfuscation technique)

### URLs (plaintext links and HTML anchors)
- Raw IP-address links
- URL-shortener usage (bit.ly, tinyurl, t.co, etc.)
- High-abuse top-level domains (`.zip`, `.top`, `.xyz`, `.click`, ...)
- Punycode / IDN domains (`xn--...`), a common homograph-attack technique
- Typosquatting of known brand domains via Levenshtein distance
  (e.g. `paypa1-secure.xyz` vs. `paypal.com`)
- Brand names embedded in an unrelated domain
- **Anchor text vs. actual href mismatch** — the displayed link text
  points to one domain while the real `href` goes elsewhere, a hallmark
  phishing deception

### Attachments
- Dangerous executable/script extensions (`.exe`, `.scr`, `.js`, `.vbs`,
  `.ps1`, `.hta`, `.lnk`, `.jar`, ...)
- Double extensions used to disguise executables as documents
  (`invoice.pdf.exe`)
- Macro-enabled Office formats (`.docm`, `.xlsm`, `.pptm`) and hidden
  macros inside non-macro OOXML files (`vbaProject.bin` detection)
- Password-protected ZIP archives (common AV-evasion technique)
- File signature ("magic bytes") vs. declared extension mismatches
  (e.g. a `.pdf` that is actually a Windows PE executable)
- Missing file extensions
- MD5/SHA256 hash inventory for every attachment
- Optional VirusTotal reputation lookup by SHA256 hash (opt-in; only the
  hash is transmitted, never file contents)

## Scoring and verdict

Every finding carries a severity (`info` / `low` / `medium` / `high` /
`critical`) and a weighted point value. Points are summed into a total
risk score, which maps to a verdict band:

| Score range | Verdict                     |
|-------------|------------------------------|
| 0–14        | CLEAN                        |
| 15–34       | LOW                           |
| 35–59       | SUSPICIOUS                    |
| 60–84       | LIKELY PHISHING/MALICIOUS     |
| 85+         | MALICIOUS                     |

The text report lists findings from most to least severe, each with a
plain-language explanation of *why* it was flagged, so a human analyst
can quickly verify the reasoning rather than trust a black-box score.

## Output formats

- **Human-readable text** (default): summary block (subject, from,
  reply-to, attachment count, SPF/DKIM/DMARC results, total score,
  verdict) followed by findings sorted by severity.
- **JSON** (`--json`): same data as a structured object —
  `meta`, `total_score`, `verdict`, `verdict_description`, `findings[]`
  — suitable for piping into other tooling or a SIEM.

## Limitations

- Brand/typosquat detection relies on a small built-in brand list —
  extend `KNOWN_BRANDS` in the script for organization-specific needs.
- No sandboxed detonation of attachments; static/heuristic checks only.
  VirusTotal lookup is opt-in and hash-based (no upload of file content).
- SPF/DKIM/DMARC verification relies on the `Authentication-Results`
  header already present in the source (the tool does not perform its
  own DNS-based SPF/DKIM validation).
- Heuristic scoring is a decision aid, not a guarantee — always apply
  analyst judgment before acting on the verdict (e.g. blocking a sender
  or deleting mail).

## Intended use

This is a defensive analysis tool for security analysts, IT admins, and
incident responders triaging suspicious email. It does not send, modify,
or delete any mail; it only reads and reports on files you provide it.
