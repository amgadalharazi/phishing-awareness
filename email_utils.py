"""Email sending helpers. Falls back to console logging in TEST_MODE."""

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import config


def send_email(to_email, subject, html_body):
    """Send (or, in TEST_MODE, log) a single email. Returns True on success."""
    if config.TEST_MODE:
        print(f"[TEST MODE] Would send to {to_email!r} — subject: {subject!r}")
        return True
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{config.SENDER_NAME} <{config.SENDER_EMAIL}>"
        msg["To"] = to_email
        msg.attach(MIMEText(html_body, "html"))
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15) as server:
            server.starttls()
            server.login(config.SMTP_USER, config.SMTP_PASSWORD)
            server.sendmail(config.SENDER_EMAIL, [to_email], msg.as_string())
        return True
    except Exception as exc:  # noqa: BLE001 - report any send failure, keep going
        print(f"[SEND ERROR] {to_email}: {exc}")
        return False
