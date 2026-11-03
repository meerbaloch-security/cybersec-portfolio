# Project 02 — Phishing Email Analyzer (phish-analyzer)

An offline triage tool for suspicious emails. Give it a `.eml` file and it
returns a verdict, a 0-100 risk score, and an analyst-style report explaining
each indicator, plus recommended actions.

It makes **no network calls**: links are never opened and attachments are
never executed, so it is safe to run on real phishing samples. It needs only
the Python standard library.

See an example output in [`reports/credential_phish_report.md`](reports/credential_phish_report.md).

## What it checks

| Area | Checks |
|---|---|
| **Authentication** | SPF, DKIM and DMARC results from `Authentication-Results` |
| **Spoofing** | Reply-To and Return-Path mismatch, brand name in the display name, a hidden second address in the display name |
| **Look-alike domains** | Typosquats (`paypa1`, `rnicrosoft`), brand keywords in unrelated domains, punycode / IDN homographs |
| **URLs** | Link text that differs from the real destination, raw IP links, URL shorteners, high-abuse TLDs, `@` userinfo tricks, plain HTTP |
| **Attachments** | Executables and scripts, double extensions (`invoice.pdf.exe`), macro-enabled Office files, archives, `MZ` headers, SHA-256 hashes for threat-intel lookups |
| **Social engineering** | Urgency language, requests to log in or update payment details |
| **BEC (business email compromise)** | Gift-card, wire-transfer and secrecy requests; an executive title in the display name sent from free webmail |
| **Credential harvesting** | HTML forms embedded in the email |

Every finding adds weighted points. A total of 60 or more is **malicious**,
30-59 is **suspicious**, and below 30 is **likely safe**.

## Quick start

```bash
python3 samples/make_samples.py            # create 4 fake sample emails
python3 phish_analyzer.py samples/*.eml    # text summary
python3 phish_analyzer.py samples/credential_phish.eml --format markdown -o report.md
python3 phish_analyzer.py samples/*.eml --format json > results.json
python3 -m unittest discover -s tests -v   # run the tests
```

To analyse a real email, use your mail client's "Download message" or "Show
original" option to save it as `.eml`.

## Results on the samples

| Sample | Scenario | Verdict | Score |
|---|---|---|---|
| `credential_phish.eml` | PayPal look-alike, link-text mismatch, raw IP link | Malicious | 100 |
| `malware_invoice.eml` | Fake DHL invoice, `pdf.exe` double extension, `.xlsm` macro file | Malicious | 100 |
| `bec_giftcard.eml` | Fake CEO on Outlook.com asking for gift cards (passes SPF/DKIM/DMARC) | Malicious | 62 |
| `legit_newsletter.eml` | Normal newsletter | Likely safe | 0 |

The BEC sample shows why email authentication alone isn't enough: it passes
SPF, DKIM and DMARC because it really was sent from Outlook.com, so only the
content and display-name checks catch it.

An example report is in [`reports/credential_phish_report.md`](reports/credential_phish_report.md).

## Design decisions

- **Offline by design.** Analysts often triage live samples; the tool never
  makes a network request.
- **Explainable scoring.** Each point added is tied to a readable finding, so
  an analyst can see why the tool reached its verdict.
- **Defanged output.** URLs in reports are written as `hxxp://evil[.]com` so
  nobody clicks them by mistake.

## Limitations and next steps

- It trusts the `Authentication-Results` header written by the receiving
  server rather than re-verifying DKIM signatures itself.
- The look-alike detection is heuristic. A next step would be comparing
  against a larger brand list, with a confusables table for Unicode.
- Optional enrichment: look up the attachment hashes and URLs on VirusTotal or
  urlscan.io using an API key.
- Extract and scan QR codes in image attachments ("quishing").
