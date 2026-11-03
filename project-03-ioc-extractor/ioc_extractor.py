#!/usr/bin/env python3
"""ioc-extractor: pull indicators of compromise out of threat reports.

Reads threat-intel reports, blog posts, alerts or analyst notes (.txt, .md,
.html, or stdin), "refangs" obfuscated indicators such as hxxp:// and
evil[.]com, removes noise (private IPs, well-known benign domains, file names
that look like domains), and exports the result for security tools.

Pure Python standard library. No network calls.

Usage:
    python3 ioc_extractor.py samples/sandfox_report.md
    python3 ioc_extractor.py report.html --format stix -o bundle.json
    python3 ioc_extractor.py report.txt --format csv -o iocs.csv
    python3 ioc_extractor.py report.txt --format defanged    # safe to paste in chat/email
    cat alert.txt | python3 ioc_extractor.py -
"""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import re
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

# --------------------------------------------------------------------------- #
# Reference data
# --------------------------------------------------------------------------- #
# Common TLDs. A candidate domain must end in one of these, which stops version
# strings and most file names (loader.ps1, report.pdf) being reported as domains.
TLDS = set("""
com net org info biz io co ai app dev cloud online site xyz top club shop store tech live link click
icu buzz rest work fun space website cyou sbs bond lat cam today world life email services support
ly ru cn uk de fr nl it es pl ua by kz ir kp in pk ae sa qa om kw bh eg tr il jp kr tw hk sg my id th vn
ph au nz ca us mx br ar cl za ng ke ch at be se no fi dk cz ro hu gr pt ie su ws tk ml ga cf gq to cc
tv me eu asia mobi pro name gov edu mil int onion zip mov sh py pl rs md so
""".split())

# Real TLDs that are also common file extensions. Only accept these when the
# text clearly marks them as indicators (inside a URL, or written defanged).
FILE_LIKE_TLDS = {"zip", "mov", "sh", "py", "pl", "rs", "md", "so"}

# Benign infrastructure that shows up in almost every report as references.
BENIGN_DOMAINS = {
    "microsoft.com", "windows.com", "office.com", "live.com", "google.com", "gstatic.com",
    "googleapis.com", "github.com", "githubusercontent.com", "mitre.org", "cisa.gov", "nist.gov",
    "virustotal.com", "abuseipdb.com", "shodan.io", "twitter.com", "x.com", "linkedin.com",
    "youtube.com", "wikipedia.org", "apple.com", "amazon.com", "amazonaws.com", "cloudflare.com",
    "example.com", "example.org", "example.net", "w3.org", "schema.org", "mozilla.org",
}

TYPES = ["ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "cve", "attack_technique"]

# --------------------------------------------------------------------------- #
# Refanging
# --------------------------------------------------------------------------- #
REFANG_RULES = [
    (re.compile(r"(?i)\bhxxp(s?)"), r"http\1"),
    (re.compile(r"(?i)\bh\[tt\]p(s?)"), r"http\1"),
    (re.compile(r"(?i)\bfxp\b"), "ftp"),
    (re.compile(r"\[:\]//|\[://\]"), "://"),
    (re.compile(r"\s*(\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\})\s*", re.I), "."),
    (re.compile(r"\s+\[?dot\]?\s+(?=[a-z0-9])", re.I), "."),
    (re.compile(r"\s*(\[@\]|\(@\)|\[at\]|\(at\)|\{at\})\s*", re.I), "@"),
    (re.compile(r"\[/\]"), "/"),
]
DEFANG_MARKERS = r"(?:hxxp|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\[at\]|\(at\)|\[@\]|\[:\])"


def refang(text: str) -> str:
    for rx, repl in REFANG_RULES:
        text = rx.sub(repl, text)
    return text


def defang(value: str, kind: str) -> str:
    if kind in {"md5", "sha1", "sha256", "cve", "attack_technique"}:
        return value
    out = re.sub(r"(?i)^http", "hxxp", value)
    out = out.replace("://", "[://]") if kind == "url" else out
    if kind == "email":
        out = out.replace("@", "[@]")
    return out.replace(".", "[.]") if kind != "ipv6" else out.replace(":", "[:]")


# --------------------------------------------------------------------------- #
# Patterns
# --------------------------------------------------------------------------- #
LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
DOMAIN_RE = re.compile(rf"(?i)(?<![\w@.-])((?:{LABEL}\.)+[a-z]{{2,24}})(?![\w-])")
URL_RE = re.compile(r"""(?i)\b((?:https?|ftp)://[^\s<>"'`\])}]+)""")
EMAIL_RE = re.compile(rf"(?i)\b([a-z0-9._%+-]+@(?:{LABEL}\.)+[a-z]{{2,24}})\b")
IPV4_RE = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.]|\.\d)")
IPV6_RE = re.compile(r"(?i)(?<![\w:])((?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4})?)(?![\w:])")
HASH_RES = {
    "sha256": re.compile(r"(?i)\b([a-f0-9]{64})\b"),
    "sha1": re.compile(r"(?i)\b([a-f0-9]{40})\b"),
    "md5": re.compile(r"(?i)\b([a-f0-9]{32})\b"),
}
CVE_RE = re.compile(r"(?i)\b(CVE-\d{4}-\d{4,7})\b")
VERSION_HINT = re.compile(r"(?i)(version|ver\.?|build|release|\bv)\s*$")
ATTACK_RE = re.compile(r"\b(T1\d{3}(?:\.\d{3})?)\b")


@dataclass(frozen=True)
class IOC:
    type: str
    value: str
    context: str  # the sentence it came from, trimmed


class _TextOnly(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts: list[str] = []
        self._skip = False

    def handle_starttag(self, tag, attrs):
        self._skip = tag in {"script", "style"}
        if tag in {"p", "br", "div", "li", "tr", "h1", "h2", "h3", "pre"}:
            self.parts.append("\n")
        for name, val in attrs:
            if name == "href" and val and not val.startswith(("#", "mailto:", "javascript:")):
                self.parts.append(f" {val} ")

    def handle_endtag(self, tag):
        self._skip = False

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def html_to_text(raw: str) -> str:
    p = _TextOnly()
    p.feed(raw)
    return "".join(p.parts)


def _context(text: str, start: int, end: int) -> str:
    left = max(text.rfind("\n", 0, start), text.rfind(". ", 0, start))
    right_candidates = [i for i in (text.find("\n", end), text.find(". ", end)) if i != -1]
    right = min(right_candidates) if right_candidates else len(text)
    snippet = " ".join(text[left + 1:right].split())
    return snippet[:200]


def _registrable(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "net", "org", "gov", "ac", "edu"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _ip_is_noise(ip: ipaddress._BaseAddress) -> bool:
    # Documentation ranges (192.0.2.0/24 etc.) are kept so sample reports work.
    doc = any(ip in n for n in DOC_NETS)
    if doc:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved


DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #
def extract(raw: str, *, keep_private: bool = False, keep_benign: bool = False) -> dict[str, list[IOC]]:
    """Return IOCs grouped by type, de-duplicated, in order of first appearance."""
    # Remember which defanged tokens the author marked on purpose, before refanging.
    marked = {refang(m.group(0)).lower().strip(".,;:")
              for m in re.finditer(r"\S*" + DEFANG_MARKERS + r"\S*", raw, re.I)}
    text = refang(raw)
    found: dict[str, dict[str, IOC]] = {t: {} for t in TYPES}

    def add(kind: str, value: str, start: int, end: int) -> None:
        key = value.lower() if kind not in {"cve", "attack_technique"} else value.upper()
        if kind in {"cve"}:
            value = value.upper()
        if key not in found[kind]:
            found[kind][key] = IOC(kind, value, _context(text, start, end))

    url_spans: list[tuple[int, int]] = []
    url_hosts: set[str] = set()
    for m in URL_RE.finditer(text):
        url = m.group(1).rstrip(".,;:!?'\"")
        host = re.sub(r"^[a-z]+://", "", url, flags=re.I).split("/")[0].split(":")[0].split("@")[-1].lower()
        if not keep_benign and _registrable(host) in BENIGN_DOMAINS:
            continue
        add("url", url, m.start(), m.end())
        url_spans.append((m.start(), m.end()))
        url_hosts.add(host)

    for m in EMAIL_RE.finditer(text):
        dom = m.group(1).split("@")[1].lower()
        if not keep_benign and _registrable(dom) in BENIGN_DOMAINS:
            continue
        add("email", m.group(1), m.start(), m.end())

    for m in IPV4_RE.finditer(text):
        if VERSION_HINT.search(text[max(0, m.start() - 12):m.start()]):
            continue  # "version 2.4.1.9" or "v10.0.0.1" is a version number, not an IP
        ip = ipaddress.ip_address(m.group(1))
        if keep_private or not _ip_is_noise(ip):
            add("ipv4", m.group(1), m.start(), m.end())

    for m in IPV6_RE.finditer(text):
        try:
            ip = ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        if keep_private or not _ip_is_noise(ip):
            add("ipv6", str(ip), m.start(), m.end())

    for m in DOMAIN_RE.finditer(text):
        dom = m.group(1).lower().rstrip(".")
        tld = dom.rsplit(".", 1)[-1]
        if tld not in TLDS:
            continue
        in_url = any(s <= m.start() < e for s, e in url_spans)
        if in_url and dom not in url_hosts:
            continue  # a file name in a URL path, e.g. /dl/payload.zip
        if tld in FILE_LIKE_TLDS and not (dom in marked or dom in url_hosts):
            continue  # "payload.zip" is a file name unless the author defanged it
        if not keep_benign and _registrable(dom) in BENIGN_DOMAINS:
            continue
        add("domain", dom, m.start(), m.end())

    # Hashes: longest first so a SHA-256 is never also reported as something shorter.
    for kind in ("sha256", "sha1", "md5"):
        for m in HASH_RES[kind].finditer(text):
            v = m.group(1).lower()
            if len(set(v)) <= 2:  # 000000... placeholders
                continue
            add(kind, v, m.start(), m.end())

    for m in CVE_RE.finditer(text):
        add("cve", m.group(1), m.start(), m.end())
    for m in ATTACK_RE.finditer(text):
        add("attack_technique", m.group(1), m.start(), m.end())

    return {k: list(v.values()) for k, v in found.items()}


# --------------------------------------------------------------------------- #
# Output formats
# --------------------------------------------------------------------------- #
NAMESPACE = uuid.UUID("6f1e1d2c-3b4a-4c5d-8e9f-0a1b2c3d4e5f")
STIX_PATTERN = {
    "ipv4": "ipv4-addr:value", "ipv6": "ipv6-addr:value", "domain": "domain-name:value",
    "url": "url:value", "email": "email-addr:value",
    "md5": "file:hashes.MD5", "sha1": "file:hashes.'SHA-1'", "sha256": "file:hashes.'SHA-256'",
}


def _stix_id(kind: str, value: str) -> str:
    # Deterministic IDs: re-running on the same report produces the same objects.
    return f"{kind}--{uuid.uuid5(NAMESPACE, kind + ':' + value)}"


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'")


def to_stix(iocs: dict[str, list[IOC]], source: str) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    identity_id = _stix_id("identity", "ioc-extractor")
    objects: list[dict] = [{
        "type": "identity", "spec_version": "2.1", "id": identity_id, "created": now, "modified": now,
        "name": "ioc-extractor", "identity_class": "system",
    }]
    for kind, items in iocs.items():
        for ioc in items:
            if kind in STIX_PATTERN:
                objects.append({
                    "type": "indicator", "spec_version": "2.1", "id": _stix_id("indicator", f"{kind}:{ioc.value}"),
                    "created": now, "modified": now, "created_by_ref": identity_id,
                    "name": f"{kind}: {ioc.value}", "description": ioc.context,
                    "indicator_types": ["malicious-activity"],
                    "pattern": f"[{STIX_PATTERN[kind]} = '{_esc(ioc.value)}']",
                    "pattern_type": "stix", "valid_from": now,
                    "external_references": [{"source_name": "source-report", "description": source}],
                })
            elif kind == "cve":
                objects.append({
                    "type": "vulnerability", "spec_version": "2.1", "id": _stix_id("vulnerability", ioc.value),
                    "created": now, "modified": now, "created_by_ref": identity_id, "name": ioc.value,
                    "external_references": [{"source_name": "cve", "external_id": ioc.value}],
                })
            elif kind == "attack_technique":
                objects.append({
                    "type": "attack-pattern", "spec_version": "2.1", "id": _stix_id("attack-pattern", ioc.value),
                    "created": now, "modified": now, "created_by_ref": identity_id, "name": ioc.value,
                    "external_references": [{
                        "source_name": "mitre-attack", "external_id": ioc.value,
                        "url": f"https://attack.mitre.org/techniques/{ioc.value.replace('.', '/')}/",
                    }],
                })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def to_csv(iocs: dict[str, list[IOC]]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "defanged", "context"])
    for kind, items in iocs.items():
        for i in items:
            w.writerow([kind, i.value, defang(i.value, kind), i.context])
    return buf.getvalue()


def to_json(iocs: dict[str, list[IOC]]) -> str:
    return json.dumps({k: [{"value": i.value, "context": i.context} for i in v] for k, v in iocs.items() if v}, indent=2)


LABELS = {"ipv4": "IPv4 addresses", "ipv6": "IPv6 addresses", "domain": "Domains", "url": "URLs",
          "email": "Email addresses", "md5": "MD5 hashes", "sha1": "SHA-1 hashes", "sha256": "SHA-256 hashes",
          "cve": "CVEs", "attack_technique": "MITRE ATT&CK techniques"}


def to_defanged(iocs: dict[str, list[IOC]], source: str) -> str:
    out = [f"# IOCs extracted from {source}", "", "_Network indicators are defanged and safe to paste._", ""]
    for kind in TYPES:
        if iocs[kind]:
            out += [f"## {LABELS[kind]} ({len(iocs[kind])})", ""]
            out += [f"- `{defang(i.value, kind)}`" for i in iocs[kind]]
            out.append("")
    return "\n".join(out)


def to_text(iocs: dict[str, list[IOC]]) -> str:
    total = sum(len(v) for v in iocs.values())
    out = [f"Extracted {total} unique indicators", ""]
    for kind in TYPES:
        if iocs[kind]:
            out.append(f"{LABELS[kind]} ({len(iocs[kind])})")
            out += [f"  {i.value}" for i in iocs[kind]]
            out.append("")
    return "\n".join(out)


def read_input(path: str) -> tuple[str, str]:
    if path == "-":
        return sys.stdin.read(), "stdin"
    p = Path(path)
    raw = p.read_text(encoding="utf-8", errors="replace")
    if p.suffix.lower() in {".html", ".htm"}:
        raw = html_to_text(raw)
    return raw, p.name


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Extract and refang IOCs from threat reports.")
    ap.add_argument("input", help="Report file (.txt, .md, .html) or - for stdin")
    ap.add_argument("--format", choices=["text", "json", "csv", "stix", "defanged"], default="text")
    ap.add_argument("-o", "--output", type=Path)
    ap.add_argument("--keep-private", action="store_true", help="Keep private/internal IP addresses")
    ap.add_argument("--keep-benign", action="store_true", help="Keep well-known benign domains")
    args = ap.parse_args(argv)

    raw, source = read_input(args.input)
    iocs = extract(raw, keep_private=args.keep_private, keep_benign=args.keep_benign)

    if args.format == "stix":
        rendered = json.dumps(to_stix(iocs, source), indent=2)
    elif args.format == "json":
        rendered = to_json(iocs)
    elif args.format == "csv":
        rendered = to_csv(iocs)
    elif args.format == "defanged":
        rendered = to_defanged(iocs, source)
    else:
        rendered = to_text(iocs)

    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
        print(f"Wrote {sum(len(v) for v in iocs.values())} indicators to {args.output}")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
