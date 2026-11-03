# Phishing analysis: credential_phish.eml

**Verdict:** MALICIOUS  |  **Risk score:** 100/100

| Field | Value |
|---|---|
| Subject | Urgent: unusual sign-in activity - account suspended |
| From | PayPal Security &lt;service@paypa1-secure.xyz&gt; |
| Reply-To | paypal.helpdesk.team@gmail.com |
| Return-Path | bounce@mailer-77.xyz |
| Originating IP | 203.0.113.45 |
| SPF / DKIM / DMARC | fail / none / fail |

## Findings

- 🔴 **high** [authentication] SPF fail: sender domain not verified (+15)
- 🔴 **high** [authentication] DMARC fail: sender domain not verified (+25)
- 🔴 **high** [spoofing] Reply-To (paypal.helpdesk.team@gmail.com) differs from From domain (paypa1-secure.xyz) (+20)
- 🔴 **high** [spoofing] Display name mentions 'paypal' but address is service@paypa1-secure.xyz (+20)
- 🔴 **high** [lookalike] Sender domain paypa1-secure.xyz imitates paypal.com (+25)
- 🔴 **high** [lookalike] Link domain paypa1-secure.xyz imitates paypal.com (+20)
- 🔴 **high** [url] Link text shows 'www.paypal.com' but goes to paypa1-secure.xyz (+20)
- 🔴 **high** [url] Link points to a raw IP: hxxp://203[.]0[.]113[.]45/paypal/login (+15)
- 🟠 **medium** [social-engineering] Urgency/pressure language: immediately, suspended, unusual sign-in, verify your account, within 24 hours (+20)
- 🟠 **medium** [social-engineering] Asks the recipient to log in or update payment details (+10)
- 🟠 **medium** [url] High-abuse TLD .xyz: hxxps://paypa1-secure[.]xyz/verify?id=8812 (+8)
- 🟠 **medium** [url] Shortened link hides destination: hxxps://bit[.]ly/3xAmPle (+8)
- 🟡 **low** [spoofing] Return-Path domain (mailer-77.xyz) differs from From domain (+5)

## URLs (defanged)

| URL | Flags |
|---|---|
| `hxxps://paypa1-secure[.]xyz/verify?id=8812` | high-abuse TLD, imitates paypal.com, text/href mismatch |
| `hxxps://bit[.]ly/3xAmPle` | URL shortener |
| `hxxp://203[.]0[.]113[.]45/paypal/login` | raw IP address, no HTTPS |
| `hxxps://www[.]paypal[.]com/security` | - |

## Recommended actions

- Do not click links or open attachments.
- Block the sender domain and listed URLs at the mail gateway / proxy.
- Search mailboxes for the same subject or sender and purge copies.
- If anyone clicked or entered credentials: reset password, revoke sessions, check MFA.
- Submit hashes and URLs to your threat-intel platform.
