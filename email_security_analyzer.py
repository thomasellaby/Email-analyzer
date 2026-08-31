#!/usr/bin/env python3
"""
Email Security Analyzer
========================
A defensive security tool that inspects .eml files, raw headers, or attachments
and reports phishing / malware indicators with a weighted risk score.

Usage:
    python email_security_analyzer.py analyze --eml suspicious.eml
    python email_security_analyzer.py analyze --eml suspicious.eml --json
    python email_security_analyzer.py analyze --eml suspicious.eml --json --out report.json
    python email_security_analyzer.py analyze --headers headers.txt
    python email_security_analyzer.py analyze --eml suspicious.eml --save-attachments ./extracted
    python email_security_analyzer.py analyze --eml suspicious.eml --vt-api-key $VT_API_KEY

Only the Python standard library is required. VirusTotal hash lookups are an
optional enhancement that activates automatically if the `requests` package
is importable and an API key is supplied (via --vt-api-key or VT_API_KEY env
var). No file contents are ever uploaded anywhere -- only SHA256 hashes are
sent to VirusTotal's lookup endpoint, and only when explicitly requested.
"""

from __future__ import annotations

import argparse
import base64
import email
import hashlib
import ipaddress
import json
import os
import re
import sys
import zipfile
from dataclasses import dataclass, field
from email.message import Message
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from io import BytesIO
from typing import Any, Optional
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# Reference data
# --------------------------------------------------------------------------

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "icloud.com", "mail.com", "gmx.com", "yandex.com", "protonmail.com",
    "zoho.com", "live.com", "msn.com",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "rebrand.ly", "cutt.ly", "shorte.st", "s.id", "tiny.cc",
    "rb.gy", "shorturl.at", "lnkd.in", "snip.ly", "v.gd", "qr.ae",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "country", "kim", "gq", "cf", "tk", "ml",
    "ga", "work", "click", "link", "loan", "download", "review", "rest",
    "quest", "cam", "icu", "buzz", "surf", "monster",
}

# Commonly impersonated brands -> canonical domain, used for typosquat /
# display-name-spoof detection. Not exhaustive -- extend as needed.
KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "office365": "office.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "linkedin": "linkedin.com",
    "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com",
    "chase": "chase.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "ups": "ups.com",
    "docusign": "docusign.com",
    "dropbox": "dropbox.com",
    "adobe": "adobe.com",
    "irs": "irs.gov",
    "usps": "usps.com",
    "hmrc": "gov.uk",
    "coinbase": "coinbase.com",
    "americanexpress": "americanexpress.com",
    "steamcommunity": "steampowered.com",
}

URGENCY_PHRASES = [
    "verify your account", "account suspended", "confirm your identity",
    "unusual activity", "unauthorized access", "click here immediately",
    "act now", "urgent action required", "your account will be closed",
    "limited time", "final notice", "password will expire",
    "update your billing", "suspended due to", "security alert",
    "immediate attention", "failure to comply", "restricted access",
    "reactivate your account", "confirm your password", "validate your account",
]

CREDENTIAL_HARVEST_PHRASES = [
    "enter your password", "confirm your password", "social security number",
    "credit card number", "wire transfer", "gift card", "bitcoin", "crypto wallet",
    "banking details", "login credentials", "ssn", "routing number",
    "one time password", "otp code", "cvv", "pin number", "account number",
]

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".msi", ".msp", ".jar",
    ".lnk", ".cpl", ".reg", ".dll", ".iso", ".img", ".vhd", ".chm", ".gadget",
    ".application", ".scf", ".inf", ".ws",
}

MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam", ".sldm"}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".ace", ".tar", ".gz", ".iso"}

OOXML_EXTENSIONS = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}

# Magic bytes for quick file-type sniffing (extension-vs-content mismatch check)
MAGIC_SIGNATURES = [
    (b"MZ", "Windows PE executable (.exe/.dll)"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP/OOXML archive"),
    (b"\xd0\xcf\x11\xe0", "Legacy OLE document (.doc/.xls/.ppt)"),
    (b"\x7fELF", "Linux ELF executable"),
    (b"\xca\xfe\xba\xbe", "Java class/Mach-O fat binary"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x89PNG", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"),
]

RISK_BANDS = [
    (0, 14, "CLEAN", "No significant phishing/malware indicators detected."),
    (15, 34, "LOW", "Minor indicators present; likely benign but worth a glance."),
    (35, 59, "SUSPICIOUS", "Multiple indicators present; treat with caution."),
    (60, 84, "LIKELY PHISHING/MALICIOUS", "Strong evidence of malicious intent."),
    (85, 10_000, "MALICIOUS", "Overwhelming evidence of malicious intent."),
]


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class Finding:
    category: str
    severity: str  # info | low | medium | high | critical
    score: int
    title: str
    detail: str

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "score": self.score,
            "title": self.title,
            "detail": self.detail,
        }


@dataclass
class Report:
    findings: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def add(self, category: str, severity: str, score: int, title: str, detail: str) -> None:
        self.findings.append(Finding(category, severity, score, title, detail))

    @property
    def total_score(self) -> int:
        return sum(f.score for f in self.findings)

    @property
    def verdict(self) -> tuple:
        score = self.total_score
        for low, high, label, desc in RISK_BANDS:
            if low <= score <= high:
                return label, desc
        return "UNKNOWN", ""

    def to_dict(self) -> dict:
        label, desc = self.verdict
        return {
            "meta": self.meta,
            "total_score": self.total_score,
            "verdict": label,
            "verdict_description": desc,
            "findings": [f.to_dict() for f in sorted(self.findings, key=lambda x: -x.score)],
        }


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def domain_of(address: str) -> str:
    addr = parseaddr(address)[1]
    if "@" in addr:
        return addr.rsplit("@", 1)[1].lower().strip(">").strip()
    return ""


def is_ip_literal(host: str) -> bool:
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


def registrable_domain(host: str) -> str:
    """Best-effort second-level+TLD extraction without an external PSL dependency."""
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return host.lower()
    two_part_tlds = {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "co.jp", "com.br"}
    last_two = ".".join(parts[-2:])
    if last_two in two_part_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


class LinkExtractor(HTMLParser):
    """Pulls out <a href> pairs plus visible text, and flags hidden/suspicious styling."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list = []  # (href, visible_text)
        self.has_password_field = False
        self.hidden_text_hits = 0
        self._current_href: Optional[str] = None
        self._current_text: list = []
        self._in_style_hidden = False

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attrs_d = dict(attrs)
        if tag == "a" and "href" in attrs_d:
            self._current_href = attrs_d["href"]
            self._current_text = []
        if tag == "input" and attrs_d.get("type", "").lower() == "password":
            self.has_password_field = True
        style = attrs_d.get("style", "")
        if style and re.search(
            r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*#?fff(?:fff)?\s*;?\s*background(?:-color)?\s*:\s*#?fff)",
            style, re.I,
        ):
            self.hidden_text_hits += 1

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._current_href is not None:
            self.links.append((self._current_href, "".join(self._current_text).strip()))
            self._current_href = None
            self._current_text = []


URL_RE = re.compile(r"""(?xi)
    \b((?:https?://|www\.)
    [^\s<>"'\)\]]+)
""")


def extract_plain_urls(text: str) -> list:
    return [m.group(1) for m in URL_RE.finditer(text or "")]


# --------------------------------------------------------------------------
# Header analysis
# --------------------------------------------------------------------------

AUTH_RESULT_MECHS = ("spf", "dkim", "dmarc")


def _parse_auth_results_header(value: str) -> tuple:
    """Split one Authentication-Results header into (authserv-id, {mech: result})."""
    authserv_id = value.split(";", 1)[0].strip()
    results = {}
    for mech in AUTH_RESULT_MECHS:
        m = re.search(rf"{mech}=(\w+)", value, re.I)
        if m:
            results[mech] = m.group(1).lower()
    return authserv_id, results


def analyze_headers(msg: Message, report: Report, trusted_authserv: Optional[list] = None) -> None:
    from_hdr = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    sender_hdr = msg.get("Sender", "")
    message_id = msg.get("Message-ID", "")
    subject = msg.get("Subject", "")
    display_name, from_addr = parseaddr(from_hdr)

    report.meta["from"] = from_hdr
    report.meta["subject"] = subject
    report.meta["reply_to"] = reply_to
    report.meta["return_path"] = return_path

    from_domain = domain_of(from_addr)

    # --- Reply-To mismatch ---
    if reply_to:
        reply_domain = domain_of(reply_to)
        if reply_domain and from_domain and registrable_domain(reply_domain) != registrable_domain(from_domain):
            report.add(
                "headers", "high", 15, "Reply-To domain differs from From domain",
                f"From domain '{from_domain}' but replies are routed to '{reply_domain}'. "
                "This is a very common phishing pattern used to redirect victim replies "
                "to an attacker-controlled mailbox.",
            )

    # --- Return-Path / envelope sender mismatch ---
    if return_path:
        rp_addr = return_path.strip("<>")
        rp_domain = domain_of(rp_addr)
        if rp_domain and from_domain and registrable_domain(rp_domain) != registrable_domain(from_domain):
            report.add(
                "headers", "medium", 10, "Return-Path domain differs from From domain",
                f"Envelope sender domain '{rp_domain}' does not match the visible From domain "
                f"'{from_domain}'. Legitimate mail can do this (mailing lists, ESPs) but it is "
                "also used to bypass casual inspection.",
            )

    # --- Sender header mismatch ---
    if sender_hdr:
        sender_domain = domain_of(sender_hdr)
        if sender_domain and from_domain and registrable_domain(sender_domain) != registrable_domain(from_domain):
            report.add(
                "headers", "low", 6, "Sender header differs from From domain",
                f"Sender: domain '{sender_domain}' differs from From domain '{from_domain}'.",
            )

    # --- Message-ID domain check ---
    if message_id:
        mid_match = re.search(r"@([\w.\-]+)>?$", message_id.strip())
        if mid_match:
            mid_domain = mid_match.group(1).lower()
            if from_domain and registrable_domain(mid_domain) != registrable_domain(from_domain) \
                    and mid_domain not in FREE_EMAIL_PROVIDERS:
                report.add(
                    "headers", "info", 3, "Message-ID domain differs from From domain",
                    f"Message-ID host '{mid_domain}' does not match From domain '{from_domain}'. "
                    "Often benign (relays/ESPs) but adds to the overall picture.",
                )

    # --- Display-name brand spoofing ---
    if display_name:
        dn_lower = re.sub(r"[^a-z0-9]", "", display_name.lower())
        for brand, brand_domain in KNOWN_BRANDS.items():
            if brand in dn_lower:
                if from_domain and registrable_domain(from_domain) != registrable_domain(brand_domain):
                    report.add(
                        "headers", "critical", 25, "Display name impersonates a known brand",
                        f"Display name '{display_name}' references '{brand}' but the sending address "
                        f"'{from_addr}' resolves to domain '{from_domain}', not the legitimate "
                        f"'{brand_domain}'. Classic brand-impersonation phishing.",
                    )
                break

    # --- Free webmail claiming to be a company / no-reply corporate sender ---
    if from_domain in FREE_EMAIL_PROVIDERS and any(
        kw in display_name.lower() for kw in ["support", "security", "billing", "admin",
                                                "helpdesk", "service", "team", "notification",
                                                "accounts", "bank"]
    ):
        report.add(
            "headers", "medium", 12, "Corporate-sounding sender using free webmail",
            f"Display name '{display_name}' suggests an official/corporate sender, but the "
            f"message originates from the free provider '{from_domain}'.",
        )

    # --- Authentication-Results (SPF/DKIM/DMARC) ---
    # NOTE: Authentication-Results is only trustworthy when it was stamped by the
    # receiving organization's own boundary MTA (RFC 8601 "authserv-id"). Anyone who
    # controls the raw message -- including the attacker's own sending infrastructure,
    # or an analyst hand-editing a .eml/headers.txt -- can prepend a header of this
    # exact same name claiming spf=pass/dkim=pass/dmarc=pass. Without an allowlist of
    # authserv-id values that belong to a trusted receiving system, a "pass" here is
    # self-reported, not verified, and must not be allowed to silently cancel out a
    # forged/failing result added elsewhere in the same header block.
    auth_results = msg.get_all("Authentication-Results", []) or []
    trusted_authserv = [t.lower().strip() for t in (trusted_authserv or []) if t.strip()]

    def _is_trusted(authserv_id: str) -> bool:
        aid = authserv_id.lower().strip()
        return any(aid == t or aid.endswith("." + t) for t in trusted_authserv)

    if auth_results:
        parsed = [_parse_auth_results_header(v) for v in auth_results]
        trusted_blocks = [p for p in parsed if trusted_authserv and _is_trusted(p[0])]

        if trusted_authserv and not trusted_blocks:
            report.add(
                "headers", "medium", 8, "No Authentication-Results from a trusted mail server",
                f"Found {len(parsed)} Authentication-Results header(s), but none carry an "
                f"authserv-id matching the configured trusted list ({', '.join(trusted_authserv)}). "
                "Results in an untrusted header can be forged by anyone who controls the raw "
                "message and should not be relied upon.",
            )

        # A forged block sitting alongside the genuine one is itself a strong signal --
        # flag disagreement regardless of which block ends up being used for scoring.
        by_mech: dict = {}
        for authserv_id, results in parsed:
            for mech, result in results.items():
                by_mech.setdefault(mech, set()).add(result)
        for mech, result_set in by_mech.items():
            if len(result_set) > 1:
                report.add(
                    "headers", "high", 16,
                    f"Conflicting {mech.upper()} results across Authentication-Results headers",
                    f"Message carries multiple Authentication-Results headers reporting different "
                    f"{mech}= outcomes ({', '.join(sorted(result_set))}). This is consistent with "
                    "an attacker injecting a forged 'pass' block alongside, or in place of, the "
                    "genuine result added by the receiving server.",
                )

        if trusted_blocks:
            authserv_id, results = trusted_blocks[0]
            confidence = "high"
        else:
            authserv_id, results = parsed[0]
            confidence = "low"

        report.meta["authserv_id"] = authserv_id
        report.meta["authserv_trusted"] = bool(trusted_blocks)

        for mech in AUTH_RESULT_MECHS:
            result = results.get(mech)
            if not result:
                continue
            report.meta[f"{mech}_result"] = result
            if result in ("fail", "softfail"):
                if confidence == "high":
                    report.add(
                        "headers", "high", 14, f"{mech.upper()} authentication failed",
                        f"Authentication-Results ({authserv_id}) reports {mech}={result}. The "
                        "sending server failed to authenticate for this domain, a strong "
                        "spoofing signal.",
                    )
                else:
                    report.add(
                        "headers", "medium", 7, f"{mech.upper()} authentication failed (unverified source)",
                        f"Authentication-Results ({authserv_id}) reports {mech}={result}, but this "
                        "header's authserv-id is not on the trusted list, so it cannot be tied to "
                        "a real mail server -- treated as a weaker signal.",
                    )
            elif result in ("none", "neutral", "temperror", "permerror"):
                report.add(
                    "headers", "low", 5, f"{mech.upper()} authentication inconclusive ({result})",
                    f"Authentication-Results ({authserv_id}) reports {mech}={result}. Not conclusive "
                    "on its own.",
                )
            elif result == "pass" and confidence == "low":
                report.add(
                    "headers", "info", 0, f"{mech.upper()}=pass reported by unverified source",
                    f"Authentication-Results ({authserv_id}) reports {mech}=pass, but no trusted "
                    "authserv-id was configured for comparison, so this cannot be treated as proof "
                    "of legitimacy -- it may have been forged by whoever supplied this message.",
                )
    else:
        report.add(
            "headers", "info", 4, "No Authentication-Results header found",
            "Could not verify SPF/DKIM/DMARC because the header is missing (may have been "
            "stripped, or the analyzed source is a forwarded/raw copy).",
        )

    # --- Received chain sanity check ---
    received = msg.get_all("Received", []) or []
    report.meta["hop_count"] = len(received)
    if len(received) == 0:
        report.add(
            "headers", "info", 3, "No Received headers present",
            "File may be a partial export or headers-only capture; routing history unavailable.",
        )

    # --- Suspicious X-Mailer / User-Agent ---
    mailer = msg.get("X-Mailer", "") or msg.get("User-Agent", "")
    if mailer and re.search(r"(mass\s*mailer|bulk|spam|phish)", mailer, re.I):
        report.add(
            "headers", "medium", 10, "Suspicious mail client signature",
            f"X-Mailer/User-Agent value looks automated/bulk-oriented: '{mailer}'.",
        )

    # --- Subject line urgency scoring reused from body scan is applied separately ---


# --------------------------------------------------------------------------
# Body / URL analysis
# --------------------------------------------------------------------------

def get_bodies(msg: Message) -> tuple:
    plain_parts, html_parts = [], []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            if "attachment" in disp.lower():
                continue
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except (LookupError, TypeError):
                text = payload.decode("utf-8", errors="replace")
            if ctype == "text/plain":
                plain_parts.append(text)
            elif ctype == "text/html":
                html_parts.append(text)
    else:
        try:
            payload = msg.get_payload(decode=True)
        except Exception:
            payload = None
        if payload is not None:
            charset = msg.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except (LookupError, TypeError):
                text = payload.decode("utf-8", errors="replace")
            if msg.get_content_type() == "text/html":
                html_parts.append(text)
            else:
                plain_parts.append(text)
    return plain_parts, html_parts


def analyze_urls(url: str, anchor_text: Optional[str], report: Report, seen: set) -> None:
    key = (url, anchor_text)
    if key in seen:
        return
    seen.add(key)

    normalized = url if "://" in url else "http://" + url
    try:
        parsed = urlparse(normalized)
    except ValueError:
        return
    host = parsed.hostname or ""
    if not host:
        return

    reg_domain = registrable_domain(host)

    if is_ip_literal(host):
        report.add(
            "url", "high", 14, "URL uses a raw IP address",
            f"Link points directly to IP address '{host}' instead of a domain name: {url}",
        )

    if reg_domain in URL_SHORTENERS or host in URL_SHORTENERS:
        report.add(
            "url", "medium", 8, "URL shortener detected",
            f"Link uses a shortening service ('{host}') that obscures the true destination: {url}",
        )

    tld = host.rsplit(".", 1)[-1].lower() if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        report.add(
            "url", "low", 5, "Uncommon/high-abuse TLD in URL",
            f"Link uses top-level domain '.{tld}', which sees disproportionate phishing abuse: {url}",
        )

    if host.startswith("xn--") or ".xn--" in host:
        report.add(
            "url", "high", 12, "Punycode (internationalized) domain in URL",
            f"Domain '{host}' is IDN-encoded, a technique used for homograph/lookalike domain "
            f"attacks: {url}",
        )

    # Typosquat check against known brands
    core_label = reg_domain.split(".")[0]
    for brand, brand_domain in KNOWN_BRANDS.items():
        brand_label = brand_domain.split(".")[0]
        if reg_domain == brand_domain:
            continue
        dist = levenshtein(core_label, brand_label)
        if 0 < dist <= 2 and abs(len(core_label) - len(brand_label)) <= 2:
            report.add(
                "url", "critical", 20, "Possible typosquat of a known brand domain",
                f"Domain '{host}' is suspiciously similar to legitimate brand domain "
                f"'{brand_domain}' (edit distance {dist}): {url}",
            )
            break
        if brand_label in core_label and core_label != brand_label:
            report.add(
                "url", "medium", 10, "Brand name embedded in unrelated domain",
                f"Domain '{host}' contains brand name '{brand}' but is not the official domain "
                f"'{brand_domain}': {url}",
            )
            break

    # Anchor text vs actual href mismatch (classic HTML phishing trick)
    if anchor_text:
        text_urls = extract_plain_urls(anchor_text)
        for tu in text_urls:
            tu_norm = tu if "://" in tu else "http://" + tu
            try:
                tu_host = urlparse(tu_norm).hostname or ""
            except ValueError:
                continue
            if tu_host and registrable_domain(tu_host) != reg_domain:
                report.add(
                    "url", "critical", 22, "Link text does not match link destination",
                    f"Displayed link text points to '{tu_host}' but the actual href goes to "
                    f"'{host}'. This is a hallmark phishing deception: text='{anchor_text.strip()}' "
                    f"href={url}",
                )


def analyze_body(msg: Message, report: Report) -> None:
    plain_parts, html_parts = get_bodies(msg)
    full_plain = "\n".join(plain_parts)
    full_html = "\n".join(html_parts)
    combined_lower = (full_plain + " " + re.sub(r"<[^>]+>", " ", full_html)).lower()

    if not plain_parts and not html_parts:
        report.add("body", "info", 0, "No readable body content found",
                    "Message has no text/plain or text/html parts (or is headers-only input).")
        return

    # --- Urgency / social-engineering language ---
    hits = [p for p in URGENCY_PHRASES if p in combined_lower]
    if hits:
        severity = "high" if len(hits) >= 3 else "medium"
        score = min(20, 6 * len(hits))
        report.add(
            "body", severity, score, "Urgency / pressure language detected",
            f"Found {len(hits)} phrase(s) commonly used to induce panic or urgency: "
            f"{', '.join(hits[:6])}{'...' if len(hits) > 6 else ''}",
        )

    # --- Credential / financial harvesting language ---
    cred_hits = [p for p in CREDENTIAL_HARVEST_PHRASES if p in combined_lower]
    if cred_hits:
        score = min(22, 7 * len(cred_hits))
        report.add(
            "body", "high", score, "Credential/financial-harvesting language detected",
            f"Found {len(cred_hits)} phrase(s) associated with requests for sensitive data: "
            f"{', '.join(cred_hits[:6])}{'...' if len(cred_hits) > 6 else ''}",
        )

    # --- HTML-specific checks ---
    seen_urls: set = set()
    if full_html:
        parser = LinkExtractor()
        try:
            parser.feed(full_html)
        except Exception:
            pass

        if parser.has_password_field:
            report.add(
                "body", "critical", 25, "Embedded HTML login form requesting a password",
                "The email body contains an HTML <input type=password> field -- emails should "
                "never embed credential-harvesting forms directly.",
            )

        if parser.hidden_text_hits:
            report.add(
                "body", "medium", 10, "Hidden or visually suppressed text detected",
                f"Found {parser.hidden_text_hits} element(s) styled to be invisible "
                "(display:none, zero font-size, or same-color-as-background text), often used "
                "to evade spam filters or hide payload text from the reader.",
            )

        for href, text in parser.links:
            analyze_urls(href, text, report, seen_urls)

        if re.search(r"<script", full_html, re.I):
            report.add(
                "body", "high", 15, "Embedded <script> in HTML email body",
                "Active scripting content in an email body is highly unusual and frequently "
                "malicious (most mail clients block it, but webmail rendering bugs exist).",
            )

        if re.search(r"<meta[^>]+http-equiv=[\"']?refresh", full_html, re.I):
            report.add(
                "body", "medium", 10, "Auto-redirect meta refresh in HTML body",
                "Body uses a meta-refresh redirect, sometimes used to bounce victims through "
                "intermediate tracking/cloaking pages before the final phishing site.",
            )

    for plain_url in extract_plain_urls(full_plain):
        analyze_urls(plain_url, None, report, seen_urls)

    if len(seen_urls) == 0 and not html_parts:
        pass  # no links found, nothing more to say

    # --- Generic greeting (mass-phishing indicator) ---
    if re.search(r"^\s*(dear (customer|user|valued customer|member)|hello customer)\b", combined_lower, re.I | re.M):
        report.add(
            "body", "low", 6, "Generic greeting instead of personalized name",
            "Message opens with a generic greeting ('Dear Customer', etc.), typical of "
            "mass-distributed phishing rather than legitimate account-specific correspondence.",
        )

    # --- Base64 blob hidden in plain text (obfuscated payload / link) ---
    b64_blobs = re.findall(r"[A-Za-z0-9+/]{80,}={0,2}", full_plain)
    for blob in b64_blobs[:5]:
        try:
            decoded = base64.b64decode(blob, validate=True)
            if b"http" in decoded.lower() or decoded[:2] == b"MZ":
                report.add(
                    "body", "high", 14, "Obfuscated Base64 content in message body",
                    "Found a long Base64-encoded blob in the plaintext body that decodes to a "
                    "URL or executable signature -- a common evasion technique.",
                )
                break
        except Exception:
            continue


# --------------------------------------------------------------------------
# Attachment analysis
# --------------------------------------------------------------------------

def sniff_magic(data: bytes) -> Optional[str]:
    for sig, label in MAGIC_SIGNATURES:
        if data.startswith(sig):
            return label
    return None


def zip_is_encrypted(data: bytes) -> bool:
    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.flag_bits & 0x1:
                    return True
    except Exception:
        return False
    return False


def ooxml_has_macro(data: bytes) -> bool:
    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            return any("vbaProject.bin" in n for n in zf.namelist())
    except Exception:
        return False


def vt_lookup(sha256: str, api_key: str) -> Optional[dict]:
    try:
        import requests  # type: ignore
    except ImportError:
        return None
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": api_key},
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        return {"error": str(exc)}


def analyze_attachments(msg: Message, report: Report, save_dir: Optional[str], vt_api_key: Optional[str]) -> None:
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disp = str(part.get("Content-Disposition", ""))
        if not filename and "attachment" not in disp.lower():
            continue
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            payload = None
        if payload is None:
            continue
        attachments.append((filename or "unnamed_attachment", payload, part.get_content_type()))

    report.meta["attachment_count"] = len(attachments)
    if not attachments:
        return

    if save_dir:
        os.makedirs(save_dir, exist_ok=True)

    for filename, data, declared_ctype in attachments:
        safe_name = re.sub(r"[^\w.\-]", "_", filename)
        ext = os.path.splitext(safe_name)[1].lower()
        size = len(data)
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()

        detail_base = f"Filename: '{filename}' | Size: {size} bytes | SHA256: {sha256}"

        if save_dir:
            with open(os.path.join(save_dir, safe_name), "wb") as fh:
                fh.write(data)

        # Double extension check, e.g. invoice.pdf.exe
        name_no_ext = os.path.splitext(safe_name)[0]
        if re.search(r"\.\w{2,5}$", name_no_ext) and ext in DANGEROUS_EXTENSIONS:
            report.add(
                "attachment", "critical", 22, "Double file extension on attachment",
                f"'{filename}' uses a double extension pattern to disguise an executable as a "
                f"document (e.g. name.pdf.exe). {detail_base}",
            )
        elif ext in DANGEROUS_EXTENSIONS:
            report.add(
                "attachment", "critical", 20, "Dangerous executable/script attachment",
                f"'{filename}' has a high-risk extension ('{ext}') commonly used to deliver "
                f"malware. {detail_base}",
            )

        if ext in MACRO_EXTENSIONS:
            report.add(
                "attachment", "high", 15, "Macro-enabled Office document attached",
                f"'{filename}' is a macro-enabled Office format ('{ext}'), frequently used to "
                f"deliver malicious VBA payloads. {detail_base}",
            )
        elif ext in OOXML_EXTENSIONS and ooxml_has_macro(data):
            report.add(
                "attachment", "high", 15, "Office document contains embedded VBA macro",
                f"'{filename}' has a non-macro extension but its OOXML package contains "
                f"vbaProject.bin -- a mismatch sometimes used to sneak macros past filters. "
                f"{detail_base}",
            )

        if ext in ARCHIVE_EXTENSIONS:
            if ext == ".zip" and zip_is_encrypted(data):
                report.add(
                    "attachment", "high", 14, "Password-protected ZIP attachment",
                    f"'{filename}' is an encrypted ZIP archive. Attackers commonly password-"
                    f"protect malicious archives to evade automated antivirus/email scanning "
                    f"(the password is usually given in the email body). {detail_base}",
                )
            else:
                report.add(
                    "attachment", "low", 6, "Archive attachment present",
                    f"'{filename}' is an archive file; contents could not be fully inspected "
                    f"without extraction. {detail_base}",
                )

        # Magic-byte vs extension mismatch
        magic_label = sniff_magic(data)
        if magic_label:
            if "PE executable" in magic_label and ext not in (".exe", ".dll", ".scr", ".com"):
                report.add(
                    "attachment", "critical", 22, "File content is an executable disguised by its extension",
                    f"'{filename}' has extension '{ext}' but its actual file signature indicates: "
                    f"{magic_label}. {detail_base}",
                )
            elif "PDF" in magic_label and ext not in (".pdf",):
                report.add(
                    "attachment", "medium", 8, "File extension does not match content (PDF)",
                    f"'{filename}' claims extension '{ext}' but content signature is: {magic_label}. "
                    f"{detail_base}",
                )

        if not ext:
            report.add(
                "attachment", "low", 5, "Attachment has no file extension",
                f"'{filename}' lacks a file extension, which can be used to slip past naive "
                f"extension-based filters. {detail_base}",
            )

        report.findings.append(Finding(
            "attachment", "info", 0, f"Attachment inventory: {filename}",
            f"{detail_base} | MD5: {md5} | Declared Content-Type: {declared_ctype}",
        ))

        if vt_api_key:
            vt_result = vt_lookup(sha256, vt_api_key)
            if vt_result is None:
                report.add(
                    "attachment", "info", 0, "VirusTotal lookup skipped",
                    "The 'requests' package is not installed; install it to enable VT hash lookups.",
                )
            elif "error" in vt_result:
                report.add(
                    "attachment", "info", 0, f"VirusTotal lookup failed for {filename}",
                    str(vt_result["error"]),
                )
            else:
                stats = vt_result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                if malicious > 0:
                    report.add(
                        "attachment", "critical", min(40, 20 + malicious), "VirusTotal flags this attachment as malicious",
                        f"'{filename}' (SHA256 {sha256}): {malicious} vendor(s) flagged malicious, "
                        f"{suspicious} flagged suspicious.",
                    )
                elif suspicious > 0:
                    report.add(
                        "attachment", "medium", 10, "VirusTotal flags this attachment as suspicious",
                        f"'{filename}' (SHA256 {sha256}): {suspicious} vendor(s) flagged suspicious, 0 malicious.",
                    )
                else:
                    report.add(
                        "attachment", "info", 0, "VirusTotal reports no detections",
                        f"'{filename}' (SHA256 {sha256}): 0 detections across reporting vendors.",
                    )


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def analyze_message(
    msg: Message,
    save_dir: Optional[str] = None,
    vt_api_key: Optional[str] = None,
    trusted_authserv: Optional[list] = None,
) -> Report:
    report = Report()
    analyze_headers(msg, report, trusted_authserv=trusted_authserv)
    analyze_body(msg, report)
    analyze_attachments(msg, report, save_dir, vt_api_key)
    return report


def load_eml(path: str) -> Message:
    with open(path, "rb") as fh:
        return email.message_from_binary_file(fh)


def load_headers_only(path: str) -> Message:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    if "\n\n" not in text:
        text += "\n\n"
    return email.message_from_string(text)


# --------------------------------------------------------------------------
# Reporting output
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def print_human_report(report: Report) -> None:
    label, desc = report.verdict
    bar = "=" * 70
    print(bar)
    print(" EMAIL SECURITY ANALYSIS REPORT")
    print(bar)
    if report.meta.get("subject"):
        print(f"Subject     : {report.meta.get('subject')}")
    if report.meta.get("from"):
        print(f"From        : {report.meta.get('from')}")
    if report.meta.get("reply_to"):
        print(f"Reply-To    : {report.meta.get('reply_to')}")
    print(f"Attachments : {report.meta.get('attachment_count', 0)}")
    for mech in ("spf", "dkim", "dmarc"):
        if f"{mech}_result" in report.meta:
            print(f"{mech.upper():<12}: {report.meta[f'{mech}_result']}")
    if "authserv_id" in report.meta:
        trust_note = "trusted" if report.meta.get("authserv_trusted") else "UNVERIFIED"
        print(f"AuthServID  : {report.meta['authserv_id']} ({trust_note})")
    print(bar)
    print(f"RISK SCORE  : {report.total_score}")
    print(f"VERDICT     : {label}  -  {desc}")
    print(bar)

    findings = [f for f in report.findings if f.score > 0]
    inventory = [f for f in report.findings if f.score == 0]
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -f.score))

    if findings:
        print("\nFINDINGS (highest severity first):\n")
        for f in findings:
            print(f"[{f.severity.upper():<8}] (+{f.score:>2}) {f.title}")
            print(f"           {f.detail}\n")
    else:
        print("\nNo scored findings triggered.\n")

    if inventory:
        print("-" * 70)
        print("ADDITIONAL INFO:\n")
        for f in inventory:
            print(f"  - {f.title}: {f.detail}")

    print(bar)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="email_security_analyzer",
        description="Analyze .eml files or raw headers for phishing/malware indicators.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze_p = sub.add_parser("analyze", help="Analyze an email source")
    src = analyze_p.add_mutually_exclusive_group(required=True)
    src.add_argument("--eml", metavar="FILE", help="Path to a .eml file (headers + body + attachments)")
    src.add_argument("--headers", metavar="FILE", help="Path to a text file containing raw email headers only")

    analyze_p.add_argument("--json", action="store_true", help="Output machine-readable JSON instead of a text report")
    analyze_p.add_argument("--out", metavar="FILE", help="Write report to this file instead of stdout")
    analyze_p.add_argument("--save-attachments", metavar="DIR", help="Extract attachments to this directory for further inspection")
    analyze_p.add_argument(
        "--vt-api-key", metavar="KEY",
        default=os.environ.get("VT_API_KEY"),
        help="VirusTotal API key for optional attachment hash reputation lookups "
             "(defaults to VT_API_KEY env var). Only SHA256 hashes are sent, never file contents.",
    )
    analyze_p.add_argument(
        "--trusted-authserv", metavar="HOSTNAME", action="append",
        default=[h for h in os.environ.get("TRUSTED_AUTHSERV", "").split(",") if h.strip()],
        help="Hostname (authserv-id) of a mail server you trust to have genuinely performed "
             "SPF/DKIM/DMARC checks, e.g. mx.google.com. Repeatable. Without this, "
             "Authentication-Results is self-reported by the message source and can be forged "
             "by an attacker, so pass/fail results are treated with reduced confidence. Can "
             "also be set via the comma-separated TRUSTED_AUTHSERV env var.",
    )
    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        if args.eml:
            if not os.path.isfile(args.eml):
                print(f"error: file not found: {args.eml}", file=sys.stderr)
                return 1
            msg = load_eml(args.eml)
            report = analyze_message(
                msg, save_dir=args.save_attachments, vt_api_key=args.vt_api_key,
                trusted_authserv=args.trusted_authserv,
            )
        else:
            if not os.path.isfile(args.headers):
                print(f"error: file not found: {args.headers}", file=sys.stderr)
                return 1
            msg = load_headers_only(args.headers)
            report = Report()
            analyze_headers(msg, report, trusted_authserv=args.trusted_authserv)
            report.add("body", "info", 0, "Body/attachment scan skipped",
                       "Only headers were supplied (--headers mode); body and attachment "
                       "checks require --eml.")

        if args.json:
            output = json.dumps(report.to_dict(), indent=2)
        else:
            import io
            buf = io.StringIO()
            _stdout = sys.stdout
            sys.stdout = buf
            try:
                print_human_report(report)
            finally:
                sys.stdout = _stdout
            output = buf.getvalue()

        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(output)
            print(f"Report written to {args.out}")
        else:
            print(output)

        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
