"""
Configuration for the Phishing Awareness Simulation Tool.

All values can be overridden via environment variables. See README.md
for the full list and setup instructions.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "phishing_sim.db")

SECRET_KEY = os.environ.get("SECRET_KEY")  # generated at runtime in app.py if unset

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")  # change in production

SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "security-training@yourcompany.com")
SENDER_NAME = os.environ.get("SENDER_NAME", "Security Awareness Team")
BASE_URL = os.environ.get("BASE_URL", "http://localhost:3000")

TEST_MODE = not (SMTP_HOST and SMTP_USER and SMTP_PASSWORD)

RISK_LOW, RISK_MED, RISK_HIGH = "Low", "Medium", "High"

DEFAULT_TEMPLATES = [
    {
        "name": "Password Expiry Notice",
        "subject": "Action required: your password expires today",
        "difficulty": "Medium",
        "body_html": (
            "<p>Hi {{name}},</p>"
            "<p>Your network password expires <strong>today</strong>. "
            "To avoid losing access to your account, please confirm your "
            "credentials now.</p>"
            "<p><a href=\"{{tracking_link}}\">Confirm my password</a></p>"
            "<p>IT Support Team</p>"
        ),
        "red_flags": (
            "Urgent, fear-based subject line demanding immediate action.\n"
            "Generic greeting instead of your real name/role.\n"
            "Link text hides the real destination URL - hover before clicking.\n"
            "Legitimate IT requests rarely ask you to 're-confirm' a password by "
            "clicking a link in an email."
        ),
    },
    {
        "name": "Shared Document Notification",
        "subject": "A file has been shared with you: Q3_Budget_Final.xlsx",
        "difficulty": "Easy",
        "body_html": (
            "<p>Hello {{name}},</p>"
            "<p>A colleague has shared a document with you. Click below to "
            "view it.</p>"
            "<p><a href=\"{{tracking_link}}\">View document</a></p>"
        ),
        "red_flags": (
            "You weren't told who specifically shared the file.\n"
            "No context about what the document is for.\n"
            "Hovering the link shows a domain that doesn't match your normal "
            "file-sharing tool."
        ),
    },
    {
        "name": "IT Helpdesk Ticket",
        "subject": "Re: Your support ticket #48213 - response needed",
        "difficulty": "Hard",
        "body_html": (
            "<p>Hi {{name}},</p>"
            "<p>Following up on the support ticket you opened. We need you to "
            "verify your identity to continue troubleshooting.</p>"
            "<p><a href=\"{{tracking_link}}\">Verify and continue</a></p>"
            "<p>Thanks,<br>IT Helpdesk</p>"
        ),
        "red_flags": (
            "References a ticket you never actually opened.\n"
            "Asks you to 'verify identity' via a link rather than an internal "
            "system you already know.\n"
            "Reply-to address doesn't match your real helpdesk domain."
        ),
    },
]
