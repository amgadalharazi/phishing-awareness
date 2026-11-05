# Phishing Awareness Simulation Tool

A Flask app for running internal phishing-awareness campaigns: create email
templates, send them to a target list, track who clicks / "submits" on the
simulated landing page, and see per-user awareness scores with basic
recommendations.

**Intended use:** internal security-awareness training within an
organization that has authorized the exercise (e.g. via IT/security/HR
sign-off). It is not intended to send email that impersonates a specific
real outside company.

## Project layout

```
phishing_awareness_tool/
├── app.py              # Flask routes only
├── config.py           # Env-driven settings + default email templates
├── database.py         # SQLite connection handling + schema init
├── email_utils.py       # send_email() — logs in TEST MODE, SMTP otherwise
├── scoring.py           # score/risk/recommendation logic
├── requirements.txt
├── static/
│   └── style.css        # extracted from the original inline <style>
└── templates/
    ├── base.html         # shared layout (sidebar, topbar, flash messages)
    ├── login.html
    ├── dashboard.html
    ├── templates_list.html
    ├── template_new.html
    ├── campaigns_list.html
    ├── campaign_new.html
    ├── campaign_detail.html
    ├── landing_form.html   # public: simulated fake login page
    ├── reveal.html         # public: "this was a simulation" reveal page
    ├── users_list.html
    └── user_detail.html
```

## Setup

```bash
pip install -r requirements.txt
python app.py
```

Then open http://localhost:3000 (default login: `admin` / `admin123` — change this).

## Email sending

By default the app runs in **TEST MODE**: "sending" an email just logs it to
the console and records it as sent, so you can try the whole flow with no
mail server. To actually send mail, set these environment variables before
running:

```
SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SENDER_EMAIL, SENDER_NAME
```

and optionally:

```
BASE_URL            # the address people will click, e.g. http://phishtraining.yourcompany.internal
ADMIN_USERNAME
ADMIN_PASSWORD
SECRET_KEY
```

## Notes on behavior preserved from the original single-file version

- The fake landing page never stores what someone typed — only that a
  submission happened.
- The "reveal" page shown after submitting explains it was a training
  exercise and lists the red flags for that template.
- `TEST_MODE` is derived automatically: it's on unless `SMTP_HOST`,
  `SMTP_USER`, and `SMTP_PASSWORD` are all set.
