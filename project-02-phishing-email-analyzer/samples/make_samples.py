#!/usr/bin/env python3
"""Generate the fake sample emails used for demos and tests.

All sample messages are fabricated. Domains such as paypa1-secure.xyz are
invented for illustration and the attachments are harmless placeholder bytes.
"""

from email.message import EmailMessage
from pathlib import Path

HERE = Path(__file__).parent


def save(name: str, msg: EmailMessage) -> None:
    (HERE / name).write_bytes(bytes(msg))


def credential_phish() -> EmailMessage:
    m = EmailMessage()
    m["Return-Path"] = "<bounce@mailer-77.xyz>"
    m["Received"] = "from mailer-77.xyz (mailer-77.xyz [203.0.113.45]) by mx.example.com; Mon, 2 Nov 2026 09:14:02 +0000"
    m["Authentication-Results"] = "mx.example.com; spf=fail smtp.mailfrom=mailer-77.xyz; dkim=none; dmarc=fail header.from=paypa1-secure.xyz"
    m["From"] = '"PayPal Security" <service@paypa1-secure.xyz>'
    m["Reply-To"] = "paypal.helpdesk.team@gmail.com"
    m["To"] = "victim@example.com"
    m["Subject"] = "Urgent: unusual sign-in activity - account suspended"
    m.set_content("We detected unusual sign-in activity. Verify your account within 24 hours or it will be suspended.\n"
                  "Login here: http://203.0.113.45/paypal/login\n")
    m.add_alternative("""<html><body>
<p>We detected <b>unusual sign-in activity</b>. Your account is <b>suspended</b>.</p>
<p>Verify your account <b>immediately</b>: <a href="https://paypa1-secure.xyz/verify?id=8812">https://www.paypal.com/security</a></p>
<p>Or use this short link: <a href="https://bit.ly/3xAmPle">Restore access</a></p>
</body></html>""", subtype="html")
    return m


def malware_phish() -> EmailMessage:
    m = EmailMessage()
    m["Return-Path"] = "<accounts@quick-freight-billing.top>"
    m["Received"] = "from smtp.quick-freight-billing.top ([198.51.100.23]) by mx.example.com; Mon, 2 Nov 2026 11:40:10 +0000"
    m["Authentication-Results"] = "mx.example.com; spf=softfail smtp.mailfrom=quick-freight-billing.top; dkim=fail; dmarc=fail"
    m["From"] = '"DHL Express Billing" <invoice@quick-freight-billing.top>'
    m["To"] = "finance@example.com"
    m["Subject"] = "Invoice overdue - final notice"
    m.set_content("Final notice: your invoice attached is overdue. Open the document and enable content to view.\n")
    m.add_attachment(b"MZ\x90\x00 placeholder bytes - not a real executable", maintype="application",
                     subtype="octet-stream", filename="Invoice_88231.pdf.exe")
    m.add_attachment(b"PK\x03\x04 placeholder", maintype="application",
                     subtype="vnd.ms-excel.sheet.macroEnabled.12", filename="statement.xlsm")
    return m


def bec_phish() -> EmailMessage:
    m = EmailMessage()
    m["Return-Path"] = "<ceo.office.private@outlook.com>"
    m["Received"] = "from outlook.com ([192.0.2.77]) by mx.example.com; Mon, 2 Nov 2026 13:02:44 +0000"
    m["Authentication-Results"] = "mx.example.com; spf=pass smtp.mailfrom=outlook.com; dkim=pass header.d=outlook.com; dmarc=pass"
    m["From"] = '"Sarah Chen (CEO) sarah.chen@example.com" <ceo.office.private@outlook.com>'
    m["Reply-To"] = "ceo.office.private@outlook.com"
    m["To"] = "assistant@example.com"
    m["Subject"] = "Quick favour - confidential"
    m.set_content("Are you at your desk? I need you to buy 5 gift cards for a client today, it's urgent. "
                  "Reply with the codes. Don't call, I'm in a meeting.\n")
    return m


def legit_newsletter() -> EmailMessage:
    m = EmailMessage()
    m["Return-Path"] = "<news@example.org>"
    m["Received"] = "from mail.example.org ([192.0.2.10]) by mx.example.com; Mon, 2 Nov 2026 08:00:00 +0000"
    m["Authentication-Results"] = "mx.example.com; spf=pass smtp.mailfrom=example.org; dkim=pass header.d=example.org; dmarc=pass"
    m["From"] = '"Example Org Newsletter" <news@example.org>'
    m["To"] = "reader@example.com"
    m["Subject"] = "November community update"
    m.set_content("Hi! Here is our monthly update. Read more at https://www.example.org/blog/november\n")
    m.add_alternative('<p>Hi! Read our <a href="https://www.example.org/blog/november">November update</a>.</p>',
                      subtype="html")
    return m


if __name__ == "__main__":
    save("credential_phish.eml", credential_phish())
    save("malware_invoice.eml", malware_phish())
    save("bec_giftcard.eml", bec_phish())
    save("legit_newsletter.eml", legit_newsletter())
    print("Samples written to", HERE)
