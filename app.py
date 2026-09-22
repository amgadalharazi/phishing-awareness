"""
Phishing Awareness Simulation Tool
-----------------------------------
A single-file Flask app for running internal phishing-awareness campaigns:
create email templates, send them to a target list, track who clicks /
"submits" on the simulated landing page, and see per-user awareness scores
with basic recommendations.

INTENDED USE: internal security-awareness training within an organization
that has authorized the exercise (e.g. via IT/security/HR sign-off). It is
not intended to send email that impersonates a specific real outside company.

SETUP
  pip install -r requirements.txt
  python app.py
  -> open http://localhost:5000  (default login: admin / admin123 - CHANGE THIS)

EMAIL SENDING
  By default the app runs in TEST MODE: "sending" an email just logs it to
  the console and records it as sent, so you can try the whole flow with no
  mail server. To actually send mail, set these environment variables before
  running:
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SENDER_EMAIL, SENDER_NAME
  and optionally BASE_URL (the address people will click, e.g.
  http://phishtraining.yourcompany.internal) and ADMIN_USERNAME /
  ADMIN_PASSWORD / SECRET_KEY.
"""

import os
import sqlite3
import smtplib
import secrets
import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import (
    Flask, request, redirect, url_for, session, g,
    render_template_string, flash, abort
)

# ------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "phishing_sim.db")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(16))

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

# ------------------------------------------------------------------------
# Database
# ------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    first_run = not os.path.exists(DB_PATH)
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            subject TEXT NOT NULL,
            body_html TEXT NOT NULL,
            difficulty TEXT DEFAULT 'Medium',
            red_flags TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS campaigns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            template_id INTEGER NOT NULL,
            status TEXT DEFAULT 'draft',
            created_at TEXT DEFAULT (datetime('now')),
            sent_at TEXT,
            FOREIGN KEY (template_id) REFERENCES templates(id)
        );

        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id INTEGER NOT NULL,
            name TEXT,
            email TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            sent_at TEXT,
            clicked_at TEXT,
            submitted_at TEXT,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
        );
        """
    )
    db.commit()
    if first_run:
        for t in DEFAULT_TEMPLATES:
            db.execute(
                "INSERT INTO templates (name, subject, body_html, difficulty, red_flags) "
                "VALUES (?, ?, ?, ?, ?)",
                (t["name"], t["subject"], t["body_html"], t["difficulty"], t["red_flags"]),
            )
        db.commit()
    db.close()


# ------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------

def now_iso():
    return datetime.datetime.utcnow().isoformat(timespec="seconds")


def new_token():
    return secrets.token_urlsafe(16)


def send_email(to_email, subject, html_body):
    """Send (or, in TEST_MODE, log) a single email. Returns True on success."""
    if TEST_MODE:
        print(f"[TEST MODE] Would send to {to_email!r} — subject: {subject!r}")
        return True
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{SENDER_NAME} <{SENDER_EMAIL}>"
        msg["To"] = to_email
        msg.attach(MIMEText(html_body, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SENDER_EMAIL, [to_email], msg.as_string())
        return True
    except Exception as exc:  # noqa: BLE001 - report any send failure, keep going
        print(f"[SEND ERROR] {to_email}: {exc}")
        return False


def compute_score(sent, clicked, submitted):
    """0-100 awareness score. Clicking costs more than nothing; submitting
    the fake form costs the most, since it's the highest-risk behaviour."""
    if sent == 0:
        return 100
    click_rate = clicked / sent
    submit_rate = submitted / sent
    score = 100 - (click_rate * 60) - (submit_rate * 40)
    return max(0, min(100, round(score)))


def risk_level(score):
    if score >= 80:
        return RISK_LOW
    if score >= 50:
        return RISK_MED
    return RISK_HIGH


def recommendations_for(score, sent, clicked, submitted):
    level = risk_level(score)
    recs = []
    if submitted > 0:
        recs.append("Complete the mandatory phishing-response training module.")
        recs.append("Turn on multi-factor authentication if it isn't already required.")
        recs.append("Review the steps to report a suspicious email to IT/security.")
    if clicked > 0:
        recs.append("Practice hovering over links to preview the real destination before clicking.")
        recs.append("Check sender addresses closely — look-alike domains are a common trick.")
    if level == RISK_LOW and submitted == 0 and clicked == 0 and sent > 0:
        recs.append("Strong track record — consider volunteering as a phishing-awareness champion for your team.")
    if not recs:
        recs.append("No activity yet — recommendations will appear once this person has been included in a campaign.")
    return level, recs


def user_stats():
    """Aggregate target rows by email across all campaigns."""
    db = get_db()
    rows = db.execute(
        """
        SELECT email,
               MAX(name) AS name,
               COUNT(*) AS sent,
               SUM(CASE WHEN clicked_at IS NOT NULL THEN 1 ELSE 0 END) AS clicked,
               SUM(CASE WHEN submitted_at IS NOT NULL THEN 1 ELSE 0 END) AS submitted
        FROM targets
        WHERE sent_at IS NOT NULL
        GROUP BY email
        ORDER BY email
        """
    ).fetchall()
    result = []
    for r in rows:
        score = compute_score(r["sent"], r["clicked"], r["submitted"])
        result.append({**dict(r), "score": score, "risk": risk_level(score)})
    result.sort(key=lambda x: x["score"])
    return result


# ------------------------------------------------------------------------
# Auth
# ------------------------------------------------------------------------

PUBLIC_ENDPOINTS = {"login", "static", "track_click", "track_submit"}


@app.before_request
def require_login():
    if request.endpoint in PUBLIC_ENDPOINTS or request.endpoint is None:
        return None
    if not session.get("admin"):
        return redirect(url_for("login"))
    return None


@app.context_processor
def inject_globals():
    return {"test_mode": TEST_MODE, "smtp_host": SMTP_HOST or "-"}


# ------------------------------------------------------------------------
# HTML (base layout + small shared bits)
# ------------------------------------------------------------------------

BASE_LAYOUT = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} · Phishing Awareness</title>
<style>
  :root {
    --bg: #0f1419; --panel: #161d27; --panel-2: #1c2531; --border: #26313f;
    --text: #e7ecf2; --muted: #8b97a5; --accent: #4c8bf5; --accent-dim: #2a3f63;
    --low: #3dd68c; --med: #f2a93b; --high: #e5484d;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 15px; line-height: 1.5;
  }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .shell { display: flex; min-height: 100vh; }
  nav.side {
    width: 220px; flex-shrink: 0; background: var(--panel);
    border-right: 1px solid var(--border); padding: 20px 14px;
  }
  nav.side .brand { font-weight: 600; font-size: 16px; padding: 0 10px 18px; }
  nav.side .brand span { color: var(--accent); }
  nav.side a {
    display: block; padding: 9px 10px; border-radius: 6px; color: var(--muted);
    font-size: 14px; margin-bottom: 2px;
  }
  nav.side a:hover { background: var(--panel-2); text-decoration: none; color: var(--text); }
  nav.side a.active { background: var(--accent-dim); color: var(--text); }
  main { flex: 1; padding: 28px 36px; max-width: 1080px; }
  .topbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 22px; }
  .topbar h1 { font-size: 20px; margin: 0; font-weight: 600; }
  .badge {
    font-size: 12px; padding: 3px 9px; border-radius: 20px; border: 1px solid var(--border);
    color: var(--muted);
  }
  .badge.test { color: var(--med); border-color: var(--med); }
  .badge.live { color: var(--low); border-color: var(--low); }
  .card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 18px 20px; margin-bottom: 18px;
  }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; }
  .stat .num { font-size: 28px; font-weight: 600; }
  .stat .label { color: var(--muted); font-size: 13px; margin-top: 2px; }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 500; font-size: 13px; }
  tr:last-child td { border-bottom: none; }
  .pill { display: inline-block; padding: 2px 9px; border-radius: 20px; font-size: 12px; font-weight: 500; }
  .pill.Low { background: rgba(61,214,140,.15); color: var(--low); }
  .pill.Medium { background: rgba(242,169,59,.15); color: var(--med); }
  .pill.High { background: rgba(229,72,77,.15); color: var(--high); }
  .pill.status { background: var(--panel-2); color: var(--muted); }
  label { display: block; font-size: 13px; color: var(--muted); margin: 14px 0 5px; }
  input[type=text], input[type=email], input[type=password], select, textarea {
    width: 100%; background: var(--panel-2); border: 1px solid var(--border); color: var(--text);
    padding: 9px 11px; border-radius: 6px; font-size: 14px; font-family: inherit;
  }
  textarea { min-height: 120px; resize: vertical; }
  button, .btn {
    background: var(--accent); color: #fff; border: none; padding: 9px 16px;
    border-radius: 6px; font-size: 14px; cursor: pointer; font-weight: 500; display: inline-block;
  }
  button:hover, .btn:hover { opacity: .9; text-decoration: none; }
  .btn.secondary { background: var(--panel-2); color: var(--text); border: 1px solid var(--border); }
  .flash { padding: 10px 14px; border-radius: 6px; margin-bottom: 16px; font-size: 14px; }
  .flash.ok { background: rgba(61,214,140,.12); color: var(--low); border: 1px solid var(--low); }
  .flash.err { background: rgba(229,72,77,.12); color: var(--high); border: 1px solid var(--high); }
  .muted { color: var(--muted); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
  .section-title { font-size: 14px; color: var(--muted); margin: 26px 0 10px; }
  code.tag { background: var(--panel-2); padding: 1px 6px; border-radius: 4px; font-family: ui-monospace, monospace; }
</style>
</head>
<body>
<div class="shell">
  {% if session.get('admin') %}
  <nav class="side">
    <div class="brand">Phish<span>Aware</span></div>
    <a href="{{ url_for('dashboard') }}" class="{{ 'active' if active=='dashboard' else '' }}">Dashboard</a>
    <a href="{{ url_for('list_templates') }}" class="{{ 'active' if active=='templates' else '' }}">Email templates</a>
    <a href="{{ url_for('list_campaigns') }}" class="{{ 'active' if active=='campaigns' else '' }}">Campaigns</a>
    <a href="{{ url_for('list_users') }}" class="{{ 'active' if active=='users' else '' }}">People &amp; scores</a>
    <a href="{{ url_for('logout') }}" style="margin-top:16px;">Log out</a>
  </nav>
  {% endif %}
  <main>
    <div class="topbar">
      <h1>{{ title }}</h1>
      {% if session.get('admin') %}
        <span class="badge {{ 'test' if test_mode else 'live' }}">
          {{ 'Test mode — emails are logged, not sent' if test_mode else 'Live — sending via ' + smtp_host }}
        </span>
      {% endif %}
    </div>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for category, message in messages %}
        <div class="flash {{ 'err' if category=='error' else 'ok' }}">{{ message }}</div>
      {% endfor %}
    {% endwith %}
    {{ content|safe }}
  </main>
</div>
</body>
</html>
"""


def render_page(title, active, template_str, **ctx):
    inner = render_template_string(template_str, **ctx)
    return render_template_string(BASE_LAYOUT, title=title, active=active, content=inner)


# ------------------------------------------------------------------------
# Auth routes
# ------------------------------------------------------------------------

LOGIN_TMPL = """
<div class="card" style="max-width:360px; margin: 40px auto;">
  <form method="post">
    <label>Username</label>
    <input type="text" name="username" required autofocus>
    <label>Password</label>
    <input type="password" name="password" required>
    <button type="submit" style="margin-top:18px; width:100%;">Log in</button>
  </form>
</div>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("username") == ADMIN_USERNAME and request.form.get("password") == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect(url_for("dashboard"))
        flash("Incorrect username or password.", "error")
    return render_page("Log in", "login", LOGIN_TMPL)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------------------
# Dashboard
# ------------------------------------------------------------------------

DASHBOARD_TMPL = """
<div class="grid">
  <div class="card stat"><div class="num">{{ campaign_count }}</div><div class="label">Campaigns</div></div>
  <div class="card stat"><div class="num">{{ sent_count }}</div><div class="label">Emails sent</div></div>
  <div class="card stat"><div class="num">{{ click_rate }}%</div><div class="label">Click rate</div></div>
  <div class="card stat"><div class="num">{{ submit_rate }}%</div><div class="label">Submitted "credentials"</div></div>
</div>

<div class="section-title">Highest-risk people right now</div>
<div class="card">
  {% if top_risk %}
  <table>
    <tr><th>Name</th><th>Email</th><th>Score</th><th>Risk</th><th>Sent / Clicked / Submitted</th></tr>
    {% for u in top_risk %}
    <tr>
      <td>{{ u.name or '—' }}</td>
      <td>{{ u.email }}</td>
      <td>{{ u.score }}</td>
      <td><span class="pill {{ u.risk }}">{{ u.risk }}</span></td>
      <td class="muted">{{ u.sent }} / {{ u.clicked }} / {{ u.submitted }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p class="muted">No campaigns sent yet. <a href="{{ url_for('new_campaign') }}">Create your first campaign</a>.</p>
  {% endif %}
</div>

<div class="section-title">Recent campaigns</div>
<div class="card">
  {% if campaigns %}
  <table>
    <tr><th>Campaign</th><th>Template</th><th>Status</th><th>Sent</th><th>Clicked</th></tr>
    {% for c in campaigns %}
    <tr>
      <td><a href="{{ url_for('view_campaign', campaign_id=c.id) }}">{{ c.name }}</a></td>
      <td class="muted">{{ c.template_name }}</td>
      <td><span class="pill status">{{ c.status }}</span></td>
      <td>{{ c.sent }}</td>
      <td>{{ c.clicked }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p class="muted">Nothing here yet.</p>
  {% endif %}
</div>
"""


@app.route("/")
def dashboard():
    db = get_db()
    campaign_count = db.execute("SELECT COUNT(*) c FROM campaigns").fetchone()["c"]
    sent_count = db.execute("SELECT COUNT(*) c FROM targets WHERE sent_at IS NOT NULL").fetchone()["c"]
    clicked_count = db.execute("SELECT COUNT(*) c FROM targets WHERE clicked_at IS NOT NULL").fetchone()["c"]
    submitted_count = db.execute("SELECT COUNT(*) c FROM targets WHERE submitted_at IS NOT NULL").fetchone()["c"]
    click_rate = round(100 * clicked_count / sent_count) if sent_count else 0
    submit_rate = round(100 * submitted_count / sent_count) if sent_count else 0

    top_risk = [u for u in user_stats() if u["risk"] != RISK_LOW][:8]

    rows = db.execute(
        """
        SELECT c.id, c.name, c.status, t.name AS template_name,
               COUNT(tg.id) AS sent,
               SUM(CASE WHEN tg.clicked_at IS NOT NULL THEN 1 ELSE 0 END) AS clicked
        FROM campaigns c
        JOIN templates t ON t.id = c.template_id
        LEFT JOIN targets tg ON tg.campaign_id = c.id AND tg.sent_at IS NOT NULL
        GROUP BY c.id ORDER BY c.id DESC LIMIT 10
        """
    ).fetchall()

    return render_page(
        "Dashboard", "dashboard", DASHBOARD_TMPL,
        campaign_count=campaign_count, sent_count=sent_count,
        click_rate=click_rate, submit_rate=submit_rate,
        top_risk=top_risk, campaigns=[dict(r) for r in rows],
    )


# ------------------------------------------------------------------------
# Templates
# ------------------------------------------------------------------------

TEMPLATES_LIST_TMPL = """
<p><a href="{{ url_for('new_template') }}" class="btn">+ New template</a></p>
<div class="card">
  <table>
    <tr><th>Name</th><th>Subject</th><th>Difficulty</th><th>Created</th></tr>
    {% for t in templates %}
    <tr>
      <td>{{ t.name }}</td>
      <td class="muted">{{ t.subject }}</td>
      <td>{{ t.difficulty }}</td>
      <td class="muted">{{ t.created_at }}</td>
    </tr>
    {% endfor %}
  </table>
</div>
"""

NEW_TEMPLATE_TMPL = """
<div class="card" style="max-width:640px;">
  <form method="post">
    <label>Template name</label>
    <input type="text" name="name" required placeholder="e.g. Password Expiry Notice">

    <label>Email subject</label>
    <input type="text" name="subject" required>

    <label>Difficulty</label>
    <select name="difficulty">
      <option>Easy</option><option selected>Medium</option><option>Hard</option>
    </select>

    <label>Email body (HTML)</label>
    <textarea name="body_html" required placeholder="Use {{ '{{name}}' }} and {{ '{{tracking_link}}' }} as placeholders"></textarea>
    <p class="muted" style="font-size:12px;">
      Use <code class="tag">{{ '{{name}}' }}</code> for the recipient's name and
      <code class="tag">{{ '{{tracking_link}}' }}</code> where the phishing link should go.
    </p>

    <label>Red flags to reveal after someone clicks (one per line)</label>
    <textarea name="red_flags" placeholder="Urgent tone, mismatched sender domain, ..."></textarea>

    <button type="submit" style="margin-top:18px;">Save template</button>
  </form>
</div>
"""


@app.route("/templates")
def list_templates():
    db = get_db()
    rows = db.execute("SELECT * FROM templates ORDER BY id DESC").fetchall()
    return render_page("Email templates", "templates", TEMPLATES_LIST_TMPL, templates=rows)


@app.route("/templates/new", methods=["GET", "POST"])
def new_template():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        subject = request.form.get("subject", "").strip()
        body_html = request.form.get("body_html", "").strip()
        difficulty = request.form.get("difficulty", "Medium")
        red_flags = request.form.get("red_flags", "").strip()
        if not (name and subject and body_html):
            flash("Name, subject and body are all required.", "error")
        else:
            db = get_db()
            db.execute(
                "INSERT INTO templates (name, subject, body_html, difficulty, red_flags) VALUES (?,?,?,?,?)",
                (name, subject, body_html, difficulty, red_flags),
            )
            db.commit()
            flash(f'Template "{name}" saved.')
            return redirect(url_for("list_templates"))
    return render_page("New template", "templates", NEW_TEMPLATE_TMPL)


# ------------------------------------------------------------------------
# Campaigns
# ------------------------------------------------------------------------

CAMPAIGNS_LIST_TMPL = """
<p><a href="{{ url_for('new_campaign') }}" class="btn">+ New campaign</a></p>
<div class="card">
  <table>
    <tr><th>Campaign</th><th>Template</th><th>Status</th><th>Targets</th><th>Clicked</th><th></th></tr>
    {% for c in campaigns %}
    <tr>
      <td>{{ c.name }}</td>
      <td class="muted">{{ c.template_name }}</td>
      <td><span class="pill status">{{ c.status }}</span></td>
      <td>{{ c.target_count }}</td>
      <td>{{ c.clicked }}</td>
      <td><a href="{{ url_for('view_campaign', campaign_id=c.id) }}">View →</a></td>
    </tr>
    {% endfor %}
  </table>
</div>
"""

NEW_CAMPAIGN_TMPL = """
<div class="card" style="max-width:640px;">
  <form method="post">
    <label>Campaign name</label>
    <input type="text" name="name" required placeholder="e.g. Q4 Finance team test">

    <label>Email template</label>
    <select name="template_id" required>
      {% for t in templates %}
      <option value="{{ t.id }}">{{ t.name }} ({{ t.difficulty }})</option>
      {% endfor %}
    </select>

    <label>Targets — one "Name, email" per line</label>
    <textarea name="targets" required placeholder="Jane Doe, jane@example.com&#10;John Smith, john@example.com"></textarea>

    <button type="submit" style="margin-top:18px;">Create campaign (draft)</button>
  </form>
</div>
"""

CAMPAIGN_DETAIL_TMPL = """
<div class="grid" style="margin-bottom:20px;">
  <div class="card stat"><div class="num">{{ targets|length }}</div><div class="label">Targets</div></div>
  <div class="card stat"><div class="num">{{ clicked }}</div><div class="label">Clicked</div></div>
  <div class="card stat"><div class="num">{{ submitted }}</div><div class="label">Submitted</div></div>
  <div class="card stat"><div class="num">{{ campaign.status }}</div><div class="label">Status</div></div>
</div>

{% if campaign.status == 'draft' %}
<form method="post" action="{{ url_for('send_campaign', campaign_id=campaign.id) }}">
  <button type="submit">Send {{ targets|length }} emails now</button>
</form>
{% endif %}

<div class="section-title">Recipients</div>
<div class="card">
  <table>
    <tr><th>Name</th><th>Email</th><th>Sent</th><th>Clicked</th><th>Submitted</th></tr>
    {% for t in targets %}
    <tr>
      <td>{{ t.name or '—' }}</td>
      <td>{{ t.email }}</td>
      <td class="muted">{{ t.sent_at or '—' }}</td>
      <td class="muted">{{ t.clicked_at or '—' }}</td>
      <td class="muted">{{ t.submitted_at or '—' }}</td>
    </tr>
    {% endfor %}
  </table>
</div>
"""


@app.route("/campaigns")
def list_campaigns():
    db = get_db()
    rows = db.execute(
        """
        SELECT c.id, c.name, c.status, t.name AS template_name,
               COUNT(tg.id) AS target_count,
               SUM(CASE WHEN tg.clicked_at IS NOT NULL THEN 1 ELSE 0 END) AS clicked
        FROM campaigns c
        JOIN templates t ON t.id = c.template_id
        LEFT JOIN targets tg ON tg.campaign_id = c.id
        GROUP BY c.id ORDER BY c.id DESC
        """
    ).fetchall()
    return render_page("Campaigns", "campaigns", CAMPAIGNS_LIST_TMPL, campaigns=rows)


@app.route("/campaigns/new", methods=["GET", "POST"])
def new_campaign():
    db = get_db()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        template_id = request.form.get("template_id")
        raw_targets = request.form.get("targets", "")

        parsed = []
        for line in raw_targets.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(",", 1)]
            if len(parts) == 2 and "@" in parts[1]:
                parsed.append((parts[0], parts[1]))
            elif "@" in parts[0]:
                parsed.append(("", parts[0]))

        if not (name and template_id and parsed):
            flash("Campaign name, a template, and at least one valid target are required.", "error")
        else:
            cur = db.execute(
                "INSERT INTO campaigns (name, template_id) VALUES (?, ?)", (name, template_id)
            )
            campaign_id = cur.lastrowid
            for tname, temail in parsed:
                db.execute(
                    "INSERT INTO targets (campaign_id, name, email, token) VALUES (?,?,?,?)",
                    (campaign_id, tname, temail, new_token()),
                )
            db.commit()
            flash(f'Campaign "{name}" created with {len(parsed)} target(s). Review it, then send.')
            return redirect(url_for("view_campaign", campaign_id=campaign_id))

    templates = db.execute("SELECT * FROM templates ORDER BY name").fetchall()
    return render_page("New campaign", "campaigns", NEW_CAMPAIGN_TMPL, templates=templates)


@app.route("/campaigns/<int:campaign_id>")
def view_campaign(campaign_id):
    db = get_db()
    campaign = db.execute("SELECT * FROM campaigns WHERE id=?", (campaign_id,)).fetchone()
    if not campaign:
        abort(404)
    targets = db.execute(
        "SELECT * FROM targets WHERE campaign_id=? ORDER BY email", (campaign_id,)
    ).fetchall()
    clicked = sum(1 for t in targets if t["clicked_at"])
    submitted = sum(1 for t in targets if t["submitted_at"])
    return render_page(
        f"Campaign: {campaign['name']}", "campaigns", CAMPAIGN_DETAIL_TMPL,
        campaign=campaign, targets=targets, clicked=clicked, submitted=submitted,
    )


@app.route("/campaigns/<int:campaign_id>/send", methods=["POST"])
def send_campaign(campaign_id):
    db = get_db()
    campaign = db.execute("SELECT * FROM campaigns WHERE id=?", (campaign_id,)).fetchone()
    if not campaign:
        abort(404)
    template = db.execute("SELECT * FROM templates WHERE id=?", (campaign["template_id"],)).fetchone()
    targets = db.execute(
        "SELECT * FROM targets WHERE campaign_id=? AND sent_at IS NULL", (campaign_id,)
    ).fetchall()

    ok, failed = 0, 0
    for t in targets:
        tracking_link = f"{BASE_URL}{url_for('track_click', token=t['token'])}"
        body = template["body_html"].replace("{{name}}", t["name"] or "there").replace(
            "{{tracking_link}}", tracking_link
        )
        if send_email(t["email"], template["subject"], body):
            db.execute("UPDATE targets SET sent_at=? WHERE id=?", (now_iso(), t["id"]))
            ok += 1
        else:
            failed += 1
    db.execute("UPDATE campaigns SET status='sent', sent_at=? WHERE id=?", (now_iso(), campaign_id))
    db.commit()

    msg = f"Sent {ok} email(s)."
    if failed:
        msg += f" {failed} failed to send."
    flash(msg)
    return redirect(url_for("view_campaign", campaign_id=campaign_id))


# ------------------------------------------------------------------------
# Public tracking + simulated landing page (no login required)
# ------------------------------------------------------------------------

LANDING_FORM_TMPL = """
<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<style>
  body { font-family: -apple-system, "Segoe UI", sans-serif; background:#eef1f5; display:flex;
         align-items:center; justify-content:center; min-height:100vh; margin:0; }
  .box { background:#fff; padding:34px; border-radius:10px; width:320px; box-shadow:0 2px 16px rgba(0,0,0,.08); }
  .box h2 { margin:0 0 4px; font-size:19px; }
  .box p.sub { color:#667; font-size:13px; margin:0 0 20px; }
  label { display:block; font-size:13px; color:#556; margin:14px 0 5px; }
  input { width:100%; padding:9px 10px; border:1px solid #ccd2da; border-radius:6px; font-size:14px; box-sizing:border-box; }
  button { margin-top:20px; width:100%; background:#2f6fed; color:#fff; border:none; padding:10px;
           border-radius:6px; font-size:14px; cursor:pointer; }
</style></head>
<body>
  <div class="box">
    <h2>Company Portal</h2>
    <p class="sub">Please sign in to continue</p>
    <form method="post" action="{{ url_for('track_submit', token=token) }}">
      <label>Email</label>
      <input type="email" name="u" required>
      <label>Password</label>
      <input type="password" name="p" required>
      <button type="submit">Sign in</button>
    </form>
  </div>
</body></html>
"""

REVEAL_TMPL = """
<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phishing simulation</title>
<style>
  body { font-family: -apple-system, "Segoe UI", sans-serif; background:#0f1419; color:#e7ecf2;
         display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; padding:20px; }
  .box { background:#161d27; border:1px solid #26313f; padding:32px; border-radius:10px; max-width:480px; }
  h2 { margin-top:0; color:#f2a93b; }
  ul { padding-left:20px; }
  li { margin-bottom:8px; color:#c3ccd6; }
  .note { color:#8b97a5; font-size:13px; margin-top:18px; }
</style></head>
<body>
  <div class="box">
    <h2>⚠ This was a simulated phishing email</h2>
    <p>{{ note }}</p>
    {% if red_flags %}
    <p><strong>What gave it away:</strong></p>
    <ul>
      {% for flag in red_flags %}<li>{{ flag }}</li>{% endfor %}
    </ul>
    {% endif %}
    <p class="note">No password was recorded — this page is part of your organization's security-awareness training. If you have questions, contact your security team.</p>
  </div>
</body></html>
"""


def _red_flags_for_token(token):
    db = get_db()
    row = db.execute(
        """
        SELECT tmpl.red_flags FROM targets tg
        JOIN campaigns c ON c.id = tg.campaign_id
        JOIN templates tmpl ON tmpl.id = c.template_id
        WHERE tg.token = ?
        """,
        (token,),
    ).fetchone()
    if not row or not row["red_flags"]:
        return []
    return [line.strip() for line in row["red_flags"].splitlines() if line.strip()]


@app.route("/t/<token>")
def track_click(token):
    db = get_db()
    target = db.execute("SELECT * FROM targets WHERE token=?", (token,)).fetchone()
    if not target:
        abort(404)
    if not target["clicked_at"]:
        db.execute(
            "UPDATE targets SET clicked_at=?, ip_address=?, user_agent=? WHERE id=?",
            (now_iso(), request.remote_addr, request.headers.get("User-Agent", ""), target["id"]),
        )
        db.commit()
    return render_template_string(LANDING_FORM_TMPL, token=token)


@app.route("/t/<token>/submit", methods=["POST"])
def track_submit(token):
    db = get_db()
    target = db.execute("SELECT * FROM targets WHERE token=?", (token,)).fetchone()
    if not target:
        abort(404)
    # Deliberately not storing whatever was typed — only that a submission happened.
    if not target["submitted_at"]:
        db.execute("UPDATE targets SET submitted_at=? WHERE id=?", (now_iso(), target["id"]))
        db.commit()
    flags = _red_flags_for_token(token)
    return render_template_string(
        REVEAL_TMPL,
        note="You just entered information into a fake login form during a security-awareness exercise.",
        red_flags=flags,
    )


# ------------------------------------------------------------------------
# People & scores
# ------------------------------------------------------------------------

USERS_LIST_TMPL = """
<div class="card">
  <table>
    <tr><th>Name</th><th>Email</th><th>Sent</th><th>Clicked</th><th>Submitted</th><th>Score</th><th>Risk</th></tr>
    {% for u in users %}
    <tr>
      <td><a href="{{ url_for('view_user', email=u.email) }}">{{ u.name or '—' }}</a></td>
      <td>{{ u.email }}</td>
      <td>{{ u.sent }}</td>
      <td>{{ u.clicked }}</td>
      <td>{{ u.submitted }}</td>
      <td>{{ u.score }}</td>
      <td><span class="pill {{ u.risk }}">{{ u.risk }}</span></td>
    </tr>
    {% endfor %}
  </table>
  {% if not users %}<p class="muted">No one has been sent a campaign yet.</p>{% endif %}
</div>
"""

USER_DETAIL_TMPL = """
<div class="grid" style="margin-bottom:20px;">
  <div class="card stat"><div class="num">{{ u.score }}</div><div class="label">Awareness score</div></div>
  <div class="card stat"><div class="num"><span class="pill {{ u.risk }}">{{ u.risk }}</span></div><div class="label">Risk level</div></div>
  <div class="card stat"><div class="num">{{ u.sent }}</div><div class="label">Campaigns sent</div></div>
  <div class="card stat"><div class="num">{{ u.clicked }} / {{ u.submitted }}</div><div class="label">Clicked / submitted</div></div>
</div>

<div class="section-title">Recommendations</div>
<div class="card">
  <ul>{% for r in recs %}<li style="margin-bottom:8px;">{{ r }}</li>{% endfor %}</ul>
</div>

<div class="section-title">Campaign history</div>
<div class="card">
  <table>
    <tr><th>Campaign</th><th>Sent</th><th>Clicked</th><th>Submitted</th></tr>
    {% for h in history %}
    <tr>
      <td>{{ h.campaign_name }}</td>
      <td class="muted">{{ h.sent_at }}</td>
      <td class="muted">{{ h.clicked_at or '—' }}</td>
      <td class="muted">{{ h.submitted_at or '—' }}</td>
    </tr>
    {% endfor %}
  </table>
</div>
"""


@app.route("/users")
def list_users():
    return render_page("People & scores", "users", USERS_LIST_TMPL, users=user_stats())


@app.route("/users/<email>")
def view_user(email):
    all_users = {u["email"]: u for u in user_stats()}
    u = all_users.get(email)
    if not u:
        abort(404)
    level, recs = recommendations_for(u["score"], u["sent"], u["clicked"], u["submitted"])
    db = get_db()
    history = db.execute(
        """
        SELECT c.name AS campaign_name, tg.sent_at, tg.clicked_at, tg.submitted_at
        FROM targets tg JOIN campaigns c ON c.id = tg.campaign_id
        WHERE tg.email=? AND tg.sent_at IS NOT NULL
        ORDER BY tg.sent_at DESC
        """,
        (email,),
    ).fetchall()
    return render_page(f"{u['name'] or email}", "users", USER_DETAIL_TMPL, u=u, recs=recs, history=history)


# ------------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------------

init_db()

if __name__ == "__main__":
    if TEST_MODE:
        print("Running in TEST MODE — emails will be logged to the console, not actually sent.")
        print("Set SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASSWORD / SENDER_EMAIL to send real mail.\n")
    print(f"Admin login: {ADMIN_USERNAME} / {ADMIN_PASSWORD} (change via env vars for real use)\n")
    app.run(debug=True, host="0.0.0.0", port=3000)