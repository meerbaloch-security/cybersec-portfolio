#!/usr/bin/env python3
"""phish-analyzer: triage a suspicious email (.eml) and produce a risk report.

Pure Python standard library. No network calls, so it is safe to run on live
phishing samples: links are never opened and attachments are never executed.

Usage:
    python3 phish_analyzer.py samples/invoice_phish.eml
    python3 phish_analyzer.py samples/*.eml --format json
    python3 phish_analyzer.py email.eml --format markdown -o report.md
"""

from __future__ import annotations

import argparse
import email
import hashlib
import ipaddress
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from email import policy
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

# --------------------------------------------------------------------------- #
# Reference data
# --------------------------------------------------------------------------- #
BRANDS = {
    "paypal.com", "microsoft.com", "office.com", "outlook.com", "apple.com",
    "icloud.com", "google.com", "gmail.com", "amazon.com", "netflix.com",
    "dhl.com", "fedex.com", "ups.com", "linkedin.com", "facebook.com",
    "instagram.com", "dropbox.com", "docusign.com", "adobe.com", "chase.com",
    "wellsfargo.com", "bankofamerica.com", "commbank.com.au", "anz.com",
    "westpac.com.au", "emiratesnbd.com", "adcb.com", "auspost.com.au",
}
BRAND_KEYWORDS = {b.split(".")[0] for b in BRANDS}

FREEMAIL = {
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com",
    "aol.com", "proton.me", "protonmail.com", "gmx.com", "mail.com", "yandex.com",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "rb.gy", "shorturl.at", "tiny.cc",
}

RISKY_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "work", "rest", "cam"}

DANGEROUS_EXT = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".bat", ".cmd",
    ".ps1", ".lnk", ".iso", ".img", ".msi", ".jar", ".cpl", ".one", ".html", ".htm", ".svg",
}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".xlam", ".dotm"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".gz", ".tar", ".cab"}

URGENCY = [
    r"\burgent\b", r"\bimmediately\b", r"\bwithin 24 hours\b", r"\bsuspend(ed)?\b",
    r"\bverify your (account|identity)\b", r"\bunusual (sign-?in|activity)\b",
    r"\bpassword (will )?expire", r"\bfinal (notice|warning)\b", r"\bact now\b",
    r"\blocked\b", r"\bconfirm your (details|payment)\b", r"\bgift ?cards?\b",
    r"\bwire transfer\b", r"\binvoice (attached|overdue)\b", r"\bpayment (failed|declined)\b",
]
FINANCIAL_ASK = [r"\bgift ?cards?\b", r"\bwire (transfer|the funds)\b", r"\b(change|update)d? (of )?bank (details|account)\b",
                 r"\breply with the codes?\b", r"\bdon'?t call\b", r"\bkeep this (confidential|between us)\b"]
EXEC_ROLES = re.compile(r"\b(ceo|cfo|coo|director|president|chairman|payroll|hr|it support|helpdesk|accounts)\b", re.I)

CREDENTIAL_ASK = [r"\b(log ?in|sign ?in)\b.*\b(here|below|now)\b", r"\bupdate your (payment|billing)\b",
                  r"\benter your (password|credentials)\b"]

INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]

URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'()\[\]]+)""")


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    category: str
    severity: str  # info | low | medium | high
    message: str
    points: int


@dataclass
class Report:
    file: str
    subject: str
    from_address: str
    from_display: str
    reply_to: str
    return_path: str
    sender_ip: str | None
    auth: dict
    urls: list[dict] = field(default_factory=list)
    attachments: list[dict] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    verdict: str = "clean"

    def add(self, category: str, severity: str, message: str, points: int) -> None:
        self.findings.append(Finding(category, severity, message, points))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
class _LinkParser(HTMLParser):
    """Collect (href, visible text) pairs and form actions from HTML bodies."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self.forms: list[str] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self._href, self._text = a["href"], []
        elif tag == "form":
            self.forms.append(a.get("action") or "")

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(">").strip() if "@" in addr else ""


def registrable(host: str) -> str:
    """Approximate registrable domain (handles common two-level suffixes)."""
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "net", "org", "gov", "edu", "ac"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# Single-character look-alikes; multi-character tricks (rn -> m, vv -> w) are handled in lookalike_of
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a"})


def lookalike_of(domain: str) -> str | None:
    """Return the brand a domain imitates, or None."""
    reg = registrable(domain)
    if reg in BRANDS:
        return None
    label = reg.split(".")[0]
    normalized = label.translate(HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
    for brand in BRANDS:
        b_label = brand.split(".")[0]
        if len(b_label) < 4:
            continue
        if normalized == b_label or (len(label) >= 5 and levenshtein(label, b_label) == 1):
            return brand
    # brand keyword buried in a different domain: paypal-secure-login.com, microsoft.account-verify.xyz
    whole = domain.lower().translate(HOMOGLYPHS)
    for kw in BRAND_KEYWORDS:
        if len(kw) >= 5 and kw in whole and not reg.startswith(kw + "."):
            return next(b for b in BRANDS if b.startswith(kw + "."))
    return None


def defang(url: str) -> str:
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def parse_auth_results(msg: EmailMessage) -> dict:
    """Read SPF/DKIM/DMARC verdicts that the receiving server recorded."""
    raw = " ".join(str(h) for h in (msg.get_all("Authentication-Results") or []))
    raw += " " + " ".join(str(h) for h in (msg.get_all("Received-SPF") or []))
    result = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}\s*=\s*(\w+)", raw, re.I)
        if not m and mech == "spf":
            m = re.search(r"^\s*(pass|fail|softfail|neutral|none|permerror|temperror)\b", raw.strip(), re.I)
        result[mech] = m.group(1).lower() if m else "missing"
    return result


def first_external_ip(msg: EmailMessage) -> str | None:
    """Originating IP from the oldest Received header that has a public IP."""
    for hdr in reversed(msg.get_all("Received") or []):
        for candidate in re.findall(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?", str(hdr)):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            # Skip internal hops (RFC 1918, loopback, link-local, CGNAT)
            if not (ip.is_loopback or ip.is_link_local or ip.is_unspecified
                    or any(ip in n for n in INTERNAL_NETS)):
                return candidate
    return None


def body_parts(msg: EmailMessage) -> tuple[str, str]:
    text, html = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except (LookupError, KeyError, ValueError):
            content = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        if not isinstance(content, str):
            continue
        if ctype == "text/plain":
            text.append(content)
        elif ctype == "text/html":
            html.append(content)
    return "\n".join(text), "\n".join(html)


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def check_headers(msg: EmailMessage, r: Report) -> None:
    from_dom = domain_of(r.from_address)

    for mech, verdict in r.auth.items():
        if verdict in {"fail", "softfail", "permerror"}:
            pts = 25 if mech == "dmarc" else 15
            r.add("authentication", "high", f"{mech.upper()} {verdict}: sender domain not verified", pts)
        elif verdict == "missing":
            r.add("authentication", "low", f"No {mech.upper()} result recorded", 3)

    if r.reply_to and domain_of(r.reply_to) and domain_of(r.reply_to) != from_dom:
        sev, pts = ("high", 20) if domain_of(r.reply_to) in FREEMAIL else ("medium", 12)
        r.add("spoofing", sev, f"Reply-To ({r.reply_to}) differs from From domain ({from_dom})", pts)

    rp_dom = domain_of(r.return_path)
    if rp_dom and registrable(rp_dom) != registrable(from_dom):
        r.add("spoofing", "low", f"Return-Path domain ({rp_dom}) differs from From domain", 5)

    # Display-name impersonation: "PayPal Support" <random@gmail.com>
    display = r.from_display.lower()
    for kw in BRAND_KEYWORDS:
        if len(kw) >= 4 and kw in display and kw not in from_dom:
            r.add("spoofing", "high", f"Display name mentions '{kw}' but address is {r.from_address}", 20)
            break
    if from_dom in FREEMAIL and EXEC_ROLES.search(r.from_display):
        r.add("bec", "medium", f"Executive/role title in display name sent from free webmail ({from_dom})", 12)
    if "@" in r.from_display and domain_of(r.from_display) != from_dom:
        r.add("spoofing", "high", "Display name contains a different email address", 15)

    brand = lookalike_of(from_dom) if from_dom else None
    if brand:
        r.add("lookalike", "high", f"Sender domain {from_dom} imitates {brand}", 25)
    if from_dom.startswith("xn--") or ".xn--" in from_dom:
        r.add("lookalike", "high", f"Sender domain uses punycode (IDN): {from_dom}", 15)


def check_body(text: str, html: str, r: Report) -> None:
    combined = (text + " " + re.sub(r"<[^>]+>", " ", html)).lower()
    hits = sorted({m.group(0) for p in URGENCY for m in re.finditer(p, combined)})
    if hits:
        r.add("social-engineering", "medium" if len(hits) >= 2 else "low",
              f"Urgency/pressure language: {', '.join(hits[:5])}", min(5 * len(hits), 20))
    money = sorted({m.group(0) for p in FINANCIAL_ASK for m in re.finditer(p, combined)})
    if money:
        r.add("bec", "high" if len(money) >= 2 else "medium",
              f"Business email compromise pattern (money/secrecy request): {', '.join(money)}", 10 + 5 * len(money))
    if any(re.search(p, combined) for p in CREDENTIAL_ASK):
        r.add("social-engineering", "medium", "Asks the recipient to log in or update payment details", 10)

    parser = _LinkParser()
    if html:
        parser.feed(html)
    seen: set[str] = set()
    pairs = list(parser.links) + [(u, "") for u in URL_RE.findall(text + " " + html)]
    for href, shown in pairs:
        href = href.strip().rstrip(".,;")
        if href.lower().startswith("mailto:") or href.startswith("#"):
            continue
        if href.lower().startswith("www."):
            href = "http://" + href
        key = href + "|" + shown
        if href in seen and not shown:
            continue
        seen.add(href)
        seen.add(key)
        analyze_url(href, shown, r)

    for action in parser.forms:
        r.add("credential-harvesting", "high", f"HTML form inside the email (posts to: {action or 'same page'})", 20)


def analyze_url(href: str, shown: str, r: Report) -> None:
    parsed = urlparse(href)
    host = (parsed.hostname or "").lower()
    if not host:
        return
    flags: list[str] = []

    try:
        ipaddress.ip_address(host)
        flags.append("raw IP address")
        r.add("url", "high", f"Link points to a raw IP: {defang(href)}", 15)
    except ValueError:
        pass

    if parsed.scheme == "http":
        flags.append("no HTTPS")
    if registrable(host) in SHORTENERS:
        flags.append("URL shortener")
        r.add("url", "medium", f"Shortened link hides destination: {defang(href)}", 8)
    if host.rsplit(".", 1)[-1] in RISKY_TLDS:
        flags.append("high-abuse TLD")
        r.add("url", "medium", f"High-abuse TLD .{host.rsplit('.', 1)[-1]}: {defang(href)}", 8)
    if host.startswith("xn--") or ".xn--" in host:
        flags.append("punycode")
        r.add("url", "high", f"Punycode domain (possible homograph): {host}", 15)
    if "@" in parsed.netloc:
        flags.append("userinfo trick")
        r.add("url", "high", f"'@' in URL hides the real host: {defang(href)}", 15)
    brand = lookalike_of(host)
    if brand:
        flags.append(f"imitates {brand}")
        r.add("lookalike", "high", f"Link domain {host} imitates {brand}", 20)

    shown_host = ""
    m = re.search(r"([a-z0-9-]+(?:\.[a-z0-9-]+)+)", shown.lower())
    if m and "." in m.group(1):
        shown_host = m.group(1)
        if registrable(shown_host) != registrable(host):
            flags.append("text/href mismatch")
            r.add("url", "high", f"Link text shows '{shown_host}' but goes to {host}", 20)

    r.urls.append({"url": href, "defanged": defang(href), "host": host, "shown_as": shown or None, "flags": flags})


def check_attachments(msg: EmailMessage, r: Report) -> None:
    for part in msg.iter_attachments():
        name = part.get_filename() or "(unnamed)"
        data = part.get_payload(decode=True) or b""
        lower = name.lower()
        suffixes = re.findall(r"\.[a-z0-9]{1,5}", lower)
        ext = suffixes[-1] if suffixes else ""
        flags: list[str] = []

        if ext in DANGEROUS_EXT:
            flags.append("executable/script type")
            r.add("attachment", "high", f"Dangerous attachment type: {name}", 25)
        elif ext in MACRO_EXT:
            flags.append("macro-enabled Office file")
            r.add("attachment", "high", f"Macro-enabled document: {name}", 20)
        elif ext in ARCHIVE_EXT:
            flags.append("archive")
            r.add("attachment", "medium", f"Archive attachment (may hide payloads): {name}", 8)
        if len(suffixes) >= 2 and suffixes[-2] in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"}:
            flags.append("double extension")
            r.add("attachment", "high", f"Double extension disguises file type: {name}", 20)
        if data[:2] == b"MZ" and ext not in {".exe", ".dll", ".scr"}:
            flags.append("Windows executable content")
            r.add("attachment", "high", f"{name} contains a Windows executable (MZ header)", 25)

        r.attachments.append({
            "filename": name,
            "content_type": part.get_content_type(),
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "flags": flags,
        })


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def analyze(path: Path) -> Report:
    with path.open("rb") as fh:
        msg = email.message_from_binary_file(fh, policy=policy.default)

    display, addr = parseaddr(str(msg.get("From", "")))
    reply_to = getaddresses([str(msg.get("Reply-To", ""))])
    r = Report(
        file=str(path),
        subject=str(msg.get("Subject", "")),
        from_address=addr.lower(),
        from_display=display,
        reply_to=(reply_to[0][1].lower() if reply_to and reply_to[0][1] else ""),
        return_path=parseaddr(str(msg.get("Return-Path", "")))[1].lower(),
        sender_ip=first_external_ip(msg),
        auth=parse_auth_results(msg),
    )

    check_headers(msg, r)
    text, html = body_parts(msg)
    check_body(text, html, r)
    check_attachments(msg, r)

    r.score = min(100, sum(f.points for f in r.findings))
    r.verdict = "malicious" if r.score >= 60 else "suspicious" if r.score >= 30 else "likely safe"
    return r


SEV_ICON = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "⚪"}


def to_markdown(r: Report) -> str:
    out = [
        f"# Phishing analysis: {Path(r.file).name}",
        "",
        f"**Verdict:** {r.verdict.upper()}  |  **Risk score:** {r.score}/100",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Subject | {r.subject} |",
        f"| From | {r.from_display} &lt;{r.from_address}&gt; |",
        f"| Reply-To | {r.reply_to or '-'} |",
        f"| Return-Path | {r.return_path or '-'} |",
        f"| Originating IP | {r.sender_ip or '-'} |",
        f"| SPF / DKIM / DMARC | {r.auth['spf']} / {r.auth['dkim']} / {r.auth['dmarc']} |",
        "",
        "## Findings",
        "",
    ]
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    for f in sorted(r.findings, key=lambda f: order[f.severity]) or []:
        out.append(f"- {SEV_ICON[f.severity]} **{f.severity}** [{f.category}] {f.message} (+{f.points})")
    if not r.findings:
        out.append("- No indicators found.")
    if r.urls:
        out += ["", "## URLs (defanged)", "", "| URL | Flags |", "|---|---|"]
        out += [f"| `{u['defanged']}` | {', '.join(u['flags']) or '-'} |" for u in r.urls]
    if r.attachments:
        out += ["", "## Attachments", "", "| File | Type | SHA-256 | Flags |", "|---|---|---|---|"]
        out += [f"| {a['filename']} | {a['content_type']} | `{a['sha256'][:16]}…` | {', '.join(a['flags']) or '-'} |"
                for a in r.attachments]
    out += ["", "## Recommended actions", ""]
    if r.verdict == "likely safe":
        out.append("- No action needed beyond normal caution.")
    else:
        out += [
            "- Do not click links or open attachments.",
            "- Block the sender domain and listed URLs at the mail gateway / proxy.",
            "- Search mailboxes for the same subject or sender and purge copies.",
            "- If anyone clicked or entered credentials: reset password, revoke sessions, check MFA.",
            "- Submit hashes and URLs to your threat-intel platform.",
        ]
    return "\n".join(out) + "\n"


def to_text(r: Report) -> str:
    lines = [f"\n=== {r.file} ===", f"Verdict: {r.verdict.upper()}   Score: {r.score}/100",
             f"From: {r.from_display} <{r.from_address}>   Subject: {r.subject}",
             f"SPF/DKIM/DMARC: {r.auth['spf']}/{r.auth['dkim']}/{r.auth['dmarc']}   Origin IP: {r.sender_ip or '-'}"]
    for f in r.findings:
        lines.append(f"  [{f.severity:<6}] {f.category:<22} {f.message}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Triage suspicious .eml files offline.")
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    ap.add_argument("-o", "--output", type=Path, help="Write to file instead of stdout")
    args = ap.parse_args(argv)

    reports = [analyze(p) for p in args.files]
    if args.format == "json":
        rendered = json.dumps([asdict(r) for r in reports], indent=2)
    elif args.format == "markdown":
        rendered = "\n---\n\n".join(to_markdown(r) for r in reports)
    else:
        rendered = "\n".join(to_text(r) for r in reports)

    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
        print(f"Wrote {args.output}")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
