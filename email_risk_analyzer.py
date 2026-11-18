#!/usr/bin/env python3
"""
Email Risk Analyzer
-------------------
Scans email content and flags potentially unsafe messages based on:
  * Urgent / pressure language
  * Requests for sensitive data (passwords, SSN, card numbers, etc.)
  * Suspicious links (IP hosts, shorteners, lookalike/punycode domains,
    mismatched link text, odd TLDs, "@" tricks, non-HTTPS)
  * Sender spoofing signs (display-name mismatch, Reply-To mismatch,
    failed SPF/DKIM/DMARC)
  * Risky attachments (executables, scripts, macro documents, archives)

Usage:
  python email_risk_analyzer.py message.eml          # analyze an .eml file
  python email_risk_analyzer.py -t "plain text body" # analyze raw text
  cat message.txt | python email_risk_analyzer.py -  # read from stdin
  python email_risk_analyzer.py --demo               # run built-in samples
  python email_risk_analyzer.py message.eml --json   # machine-readable output

Only the Python standard library is required.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# Configuration: tweak these lists/weights to tune sensitivity
# --------------------------------------------------------------------------

URGENCY_PATTERNS = [
    r"\burgent(ly)?\b", r"\bimmediate(ly)?\b", r"\basap\b", r"\bact now\b",
    r"\bwithin \d+ ?(hours?|hrs?|minutes?|mins?)\b", r"\bfinal (notice|warning)\b",
    r"\blast (chance|warning)\b", r"\baccount (will be )?(suspended|locked|closed|terminated)\b",
    r"\bverify (your|now)\b", r"\bexpires? (today|soon|in)\b", r"\bfailure to (comply|respond)\b",
    r"\bimmediate action required\b", r"\blimited time\b", r"\bunauthori[sz]ed (login|access|activity)\b",
]

SENSITIVE_PATTERNS = [
    r"\bpassword\b", r"\bpasscode\b", r"\bpin( number)?\b", r"\bone[- ]time (code|password)\b",
    r"\b(otp|2fa|verification) code\b", r"\bsocial security\b", r"\bssn\b",
    r"\bcredit card\b", r"\bcard number\b", r"\bcvv\b", r"\bsecurity code\b",
    r"\bbank account\b", r"\brouting number\b", r"\biban\b", r"\bseed phrase\b",
    r"\brecovery phrase\b", r"\bprivate key\b", r"\bdate of birth\b", r"\bmother'?s maiden name\b",
    r"\blog ?in (to|credentials)\b", r"\bconfirm your (identity|account|details)\b",
]

MONEY_SCAM_PATTERNS = [
    r"\bwire transfer\b", r"\bgift cards?\b", r"\bbitcoin\b", r"\bcrypto(currency)?\b",
    r"\blottery\b", r"\byou('ve| have) won\b", r"\binheritance\b", r"\bprize\b",
    r"\bkindly (send|transfer|pay)\b", r"\bpayment (is )?(overdue|pending|failed)\b",
    r"\brefund\b", r"\binvoice attached\b",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf",
    "ga", "work", "loan", "support", "download", "review", "stream", "icu", "cam",
}

# Brands commonly impersonated, used to spot lookalike domains
BRAND_DOMAINS = {
    "paypal": "paypal.com", "microsoft": "microsoft.com", "apple": "apple.com",
    "google": "google.com", "amazon": "amazon.com", "netflix": "netflix.com",
    "facebook": "facebook.com", "instagram": "instagram.com", "dhl": "dhl.com",
    "fedex": "fedex.com", "chase": "chase.com", "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com", "docusign": "docusign.com",
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".js", ".jse",
    ".vbs", ".vbe", ".wsf", ".ps1", ".jar", ".lnk", ".hta", ".dll", ".iso", ".img",
}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".xlsb"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar"}

URL_REGEX = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)

# Risk thresholds (total score -> level)
LEVELS = [(0, "LOW"), (25, "MEDIUM"), (50, "HIGH"), (80, "CRITICAL")]


# --------------------------------------------------------------------------
# Data structures
# --------------------------------------------------------------------------

@dataclass
class Finding:
    category: str
    detail: str
    score: int


@dataclass
class Report:
    score: int = 0
    level: str = "LOW"
    findings: list[Finding] = field(default_factory=list)

    def add(self, category: str, detail: str, score: int) -> None:
        self.findings.append(Finding(category, detail, score))

    def finalize(self) -> None:
        self.score = min(100, sum(f.score for f in self.findings))
        for threshold, name in LEVELS:
            if self.score >= threshold:
                self.level = name


@dataclass
class ParsedEmail:
    sender: str = ""
    reply_to: str = ""
    subject: str = ""
    text: str = ""
    html: str = ""
    auth_results: str = ""
    attachments: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------

class LinkExtractor(HTMLParser):
    """Collects (href, visible text) pairs from HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def parse_eml(data: bytes) -> ParsedEmail:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(data)
    parsed = ParsedEmail(
        sender=str(msg.get("From", "")),
        reply_to=str(msg.get("Reply-To", "")),
        subject=str(msg.get("Subject", "")),
        auth_results=" ".join(str(v) for v in msg.get_all("Authentication-Results", [])),
    )
    body = msg.get_body(preferencelist=("plain",))
    if body:
        parsed.text = body.get_content()
    body = msg.get_body(preferencelist=("html",))
    if body:
        parsed.html = body.get_content()
    for part in msg.iter_attachments():
        name = part.get_filename()
        if name:
            parsed.attachments.append(name)
    return parsed


def parse_plain(text: str) -> ParsedEmail:
    """Parse simple 'Header: value' text followed by a body, or just a body."""
    parsed = ParsedEmail()
    head, sep, rest = text.partition("\n\n")
    if sep and re.match(r"^(From|Subject|Reply-To):", head, re.I | re.M):
        for line in head.splitlines():
            key, _, val = line.partition(":")
            key = key.strip().lower()
            if key == "from":
                parsed.sender = val.strip()
            elif key == "reply-to":
                parsed.reply_to = val.strip()
            elif key == "subject":
                parsed.subject = val.strip()
        parsed.text = rest
    else:
        parsed.text = text
    if "<a " in parsed.text.lower() or "<html" in parsed.text.lower():
        parsed.html = parsed.text
    return parsed


# --------------------------------------------------------------------------
# Detection logic
# --------------------------------------------------------------------------

def registered_domain(host: str) -> str:
    """Rough registrable domain (last two labels). Good enough without a PSL."""
    parts = host.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def count_matches(patterns: list[str], text: str) -> list[str]:
    hits = []
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            hits.append(m.group(0).lower())
    return hits


def check_language(report: Report, subject: str, text: str) -> None:
    combined = f"{subject}\n{text}"

    urgent = count_matches(URGENCY_PATTERNS, combined)
    if urgent:
        report.add("Urgency", f"Pressure language: {', '.join(urgent[:5])}",
                   min(30, 10 * len(urgent)))

    sensitive = count_matches(SENSITIVE_PATTERNS, combined)
    if sensitive:
        report.add("Sensitive data", f"Asks for or mentions: {', '.join(sensitive[:5])}",
                   min(35, 12 * len(sensitive)))

    money = count_matches(MONEY_SCAM_PATTERNS, combined)
    if money:
        report.add("Financial lure", f"Money/scam wording: {', '.join(money[:5])}",
                   min(20, 7 * len(money)))

    letters = [c for c in subject if c.isalpha()]
    if len(letters) >= 8 and sum(c.isupper() for c in letters) / len(letters) > 0.7:
        report.add("Urgency", "Subject line is mostly capital letters", 5)

    if combined.count("!") >= 4:
        report.add("Urgency", "Excessive exclamation marks", 4)


def check_url(report: Report, url: str, link_text: str = "") -> None:
    try:
        parsed = urlparse(url)
    except ValueError:
        report.add("Link", f"Malformed URL: {url[:60]}", 8)
        return

    host = (parsed.hostname or "").lower()
    if not host:
        return
    short = url if len(url) <= 70 else url[:67] + "..."

    # IP address instead of domain
    try:
        ipaddress.ip_address(host)
        report.add("Link", f"Link points to a raw IP address: {short}", 20)
        return
    except ValueError:
        pass

    if parsed.scheme == "http":
        report.add("Link", f"Unencrypted (HTTP) link: {short}", 6)

    if "@" in (parsed.netloc or "").split("]")[0] and "@" in parsed.netloc:
        report.add("Link", f"URL contains '@' (hides real destination): {short}", 18)

    if host in URL_SHORTENERS:
        report.add("Link", f"URL shortener hides destination: {short}", 10)

    if host.startswith("xn--") or ".xn--" in host:
        report.add("Link", f"Punycode / lookalike (IDN) domain: {host}", 18)

    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        report.add("Link", f"Suspicious top-level domain '.{tld}': {host}", 10)

    if host.count(".") >= 4:
        report.add("Link", f"Excessive subdomains: {host}", 8)

    if host.count("-") >= 3:
        report.add("Link", f"Many hyphens in domain: {host}", 6)

    # Brand impersonation: brand name appears in host but domain isn't the brand's
    reg = registered_domain(host)
    for brand, real in BRAND_DOMAINS.items():
        if brand in host and reg != real:
            report.add("Link", f"Possible '{brand}' impersonation: {host}", 22)
            break

    # Displayed text looks like a URL but goes somewhere else
    shown = re.search(r"(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})", link_text.lower())
    if shown and registered_domain(shown.group(1)) != reg:
        report.add("Link", f"Link text shows '{shown.group(1)}' but goes to '{host}'", 25)


def check_links(report: Report, parsed: ParsedEmail) -> None:
    seen: set[str] = set()

    if parsed.html:
        extractor = LinkExtractor()
        extractor.feed(parsed.html)
        for href, text in extractor.links:
            if href.lower().startswith(("http://", "https://")) and href not in seen:
                seen.add(href)
                check_url(report, href, text)

    for url in URL_REGEX.findall(parsed.text):
        url = url.rstrip(".,;")
        if url not in seen:
            seen.add(url)
            check_url(report, url)

    if len(seen) >= 8:
        report.add("Link", f"Unusually high number of links ({len(seen)})", 5)


def check_sender(report: Report, parsed: ParsedEmail) -> None:
    name, addr = parseaddr(parsed.sender)
    sender_domain = addr.split("@")[-1].lower() if "@" in addr else ""

    if parsed.sender and not addr:
        report.add("Sender", "Sender address is missing or malformed", 10)

    # Display name claims a brand but domain doesn't match
    for brand, real in BRAND_DOMAINS.items():
        if brand in name.lower().replace(" ", "") and sender_domain and \
                registered_domain(sender_domain) != real:
            report.add("Sender", f"Display name mentions '{brand}' but sender domain is '{sender_domain}'", 25)
            break

    # Display name contains a different email address
    m = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", name)
    if m and sender_domain and registered_domain(m.group(1)) != registered_domain(sender_domain):
        report.add("Sender", "Display name contains an email address that differs from the real sender", 20)

    # Reply-To differs from From
    _, reply_addr = parseaddr(parsed.reply_to)
    if reply_addr and addr and \
            registered_domain(reply_addr.split("@")[-1]) != registered_domain(sender_domain):
        report.add("Sender", f"Reply-To domain differs from sender ({reply_addr})", 15)

    if sender_domain.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        report.add("Sender", f"Sender uses a suspicious TLD: {sender_domain}", 10)

    # Email authentication results, when present
    auth = parsed.auth_results.lower()
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", auth)
        if m and m.group(1) in {"fail", "softfail", "none", "permerror", "temperror"}:
            report.add("Authentication", f"{mech.upper()} result: {m.group(1)}",
                       15 if m.group(1) == "fail" else 8)


def check_attachments(report: Report, attachments: list[str]) -> None:
    for name in attachments:
        lower = name.lower()
        ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""
        if re.search(r"\.\w{2,4}\.(exe|scr|bat|cmd|js|vbs|ps1|jar|lnk)$", lower):
            report.add("Attachment", f"Double extension (disguised executable): {name}", 30)
        elif ext in DANGEROUS_EXTENSIONS:
            report.add("Attachment", f"Executable/script attachment: {name}", 30)
        elif ext in MACRO_EXTENSIONS:
            report.add("Attachment", f"Macro-enabled document: {name}", 20)
        elif ext in ARCHIVE_EXTENSIONS:
            report.add("Attachment", f"Archive may hide malicious files: {name}", 8)


def analyze(parsed: ParsedEmail) -> Report:
    report = Report()
    plain_text = parsed.text
    if parsed.html and not plain_text:
        plain_text = re.sub(r"<[^>]+>", " ", parsed.html)

    check_language(report, parsed.subject, plain_text)
    check_links(report, parsed)
    check_sender(report, parsed)
    check_attachments(report, parsed.attachments)

    # Combo bonus: urgency + sensitive data request is the classic phishing pattern
    cats = {f.category for f in report.findings}
    if {"Urgency", "Sensitive data", "Link"} <= cats:
        report.add("Combination", "Urgency + sensitive data request + link (classic phishing pattern)", 15)

    report.finalize()
    return report


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

ICONS = {"LOW": "[ OK ]", "MEDIUM": "[WARN]", "HIGH": "[RISK]", "CRITICAL": "[STOP]"}
ADVICE = {
    "LOW": "No strong warning signs found. Stay cautious with unexpected requests.",
    "MEDIUM": "Some suspicious traits. Verify the sender through a separate channel before acting.",
    "HIGH": "Likely unsafe. Do not click links, open attachments, or share information.",
    "CRITICAL": "Very likely phishing/malware. Do not interact; report it and delete.",
}


def print_report(parsed: ParsedEmail, report: Report) -> None:
    print("=" * 64)
    print(f"From:    {parsed.sender or '(unknown)'}")
    print(f"Subject: {parsed.subject or '(none)'}")
    print("-" * 64)
    print(f"{ICONS[report.level]}  Risk level: {report.level}   Score: {report.score}/100")
    print(f"        {ADVICE[report.level]}")
    if report.findings:
        print("\nFindings:")
        for f in sorted(report.findings, key=lambda x: -x.score):
            print(f"  +{f.score:<3} [{f.category}] {f.detail}")
    print("=" * 64)


# --------------------------------------------------------------------------
# Demo samples
# --------------------------------------------------------------------------

DEMO_EMAILS = [
    ("Legitimate-looking", """From: Sam Rivera <sam@company.com>
Subject: Lunch on Thursday?

Hi team,

Are we still meeting Thursday at noon? Here's the menu: https://www.example.com/menu

Thanks,
Sam"""),
    ("Classic phishing", """From: PayPal Support <security@paypa1-verify.xyz>
Reply-To: help@gmail-collect.top
Subject: URGENT: Your account will be suspended!!!

Dear customer,

We detected unauthorized activity. Verify your password and credit card number
within 24 hours or your account will be suspended.

Log in now: http://192.168.4.20/paypal/login
Or: <a href="http://secure-paypal.verify-now.xyz/login">https://www.paypal.com/signin</a>

Failure to respond will result in permanent closure."""),
]


def run_demo() -> None:
    for title, raw in DEMO_EMAILS:
        print(f"\n### Sample: {title}")
        parsed = parse_plain(raw)
        print_report(parsed, analyze(parsed))


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Scan emails for phishing and other risks.")
    ap.add_argument("file", nargs="?", help="Path to .eml/.txt file, or '-' for stdin")
    ap.add_argument("-t", "--text", help="Analyze raw text instead of a file")
    ap.add_argument("--json", action="store_true", help="Output JSON")
    ap.add_argument("--demo", action="store_true", help="Run built-in sample emails")
    args = ap.parse_args()

    if args.demo:
        run_demo()
        return 0

    if args.text:
        parsed = parse_plain(args.text)
    elif args.file == "-":
        parsed = parse_plain(sys.stdin.read())
    elif args.file:
        with open(args.file, "rb") as fh:
            data = fh.read()
        if args.file.lower().endswith(".eml"):
            parsed = parse_eml(data)
        else:
            parsed = parse_plain(data.decode("utf-8", errors="replace"))
    else:
        ap.print_help()
        return 1

    report = analyze(parsed)
    if args.json:
        print(json.dumps({
            "sender": parsed.sender, "subject": parsed.subject,
            "score": report.score, "level": report.level,
            "findings": [asdict(f) for f in report.findings],
        }, indent=2))
    else:
        print_report(parsed, report)

    # Exit code reflects risk, handy for scripts/pipelines
    return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[report.level]


if __name__ == "__main__":
    sys.exit(main())
