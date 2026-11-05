"""
Phishing Awareness Simulation Tool
-----------------------------------
A Flask app for running internal phishing-awareness campaigns: create email
templates, send them to a target list, track who clicks / "submits" on the
simulated landing page, and see per-user awareness scores with basic
recommendations.

INTENDED USE: internal security-awareness training within an organization
that has authorized the exercise (e.g. via IT/security/HR sign-off). It is
not intended to send email that impersonates a specific real outside company.

SETUP
  pip install -r requirements.txt
  python app.py
  -> open http://localhost:3000  (default login: admin / admin123 - CHANGE THIS)

EMAIL SENDING
  By default the app runs in TEST MODE: "sending" an email just logs it to
  the console and records it as sent, so you can try the whole flow with no
  mail server. To actually send mail, set these environment variables before
  running:
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SENDER_EMAIL, SENDER_NAME
  and optionally BASE_URL (the address people will click, e.g.
  http://phishtraining.yourcompany.internal) and ADMIN_USERNAME /
  ADMIN_PASSWORD / SECRET_KEY.

To see all of the available configuration options, run `python app.py --help` or see config.py.
See README.md for the full project layout.
"""

import secrets

from flask import (
    Flask, request, redirect, url_for, session,
    render_template, flash, abort
)

import config
from database import get_db, close_db, init_db
from email_utils import send_email
from scoring import compute_score, risk_level, recommendations_for, user_stats

# ------------------------------------------------------------------------
# App setup
# ------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = config.SECRET_KEY or secrets.token_hex(16)

app.teardown_appcontext(close_db)


def now_iso():
    import datetime
    return datetime.datetime.utcnow().isoformat(timespec="seconds")


def new_token():
    return secrets.token_urlsafe(16)


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
    return {"test_mode": config.TEST_MODE, "smtp_host": config.SMTP_HOST or "-"}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if (
            request.form.get("username") == config.ADMIN_USERNAME
            and request.form.get("password") == config.ADMIN_PASSWORD
        ):
            session["admin"] = True
            return redirect(url_for("dashboard"))
        flash("Incorrect username or password.", "error")
    return render_template("login.html", title="Log in", active="login")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------------------
# Dashboard
# ------------------------------------------------------------------------

@app.route("/")
def dashboard():
    db = get_db()
    campaign_count = db.execute("SELECT COUNT(*) c FROM campaigns").fetchone()["c"]
    sent_count = db.execute("SELECT COUNT(*) c FROM targets WHERE sent_at IS NOT NULL").fetchone()["c"]
    clicked_count = db.execute("SELECT COUNT(*) c FROM targets WHERE clicked_at IS NOT NULL").fetchone()["c"]
    submitted_count = db.execute("SELECT COUNT(*) c FROM targets WHERE submitted_at IS NOT NULL").fetchone()["c"]
    click_rate = round(100 * clicked_count / sent_count) if sent_count else 0
    submit_rate = round(100 * submitted_count / sent_count) if sent_count else 0

    top_risk = [u for u in user_stats() if u["risk"] != config.RISK_LOW][:8]

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

    return render_template(
        "dashboard.html", title="Dashboard", active="dashboard",
        campaign_count=campaign_count, sent_count=sent_count,
        click_rate=click_rate, submit_rate=submit_rate,
        top_risk=top_risk, campaigns=[dict(r) for r in rows],
    )


# ------------------------------------------------------------------------
# Templates
# ------------------------------------------------------------------------

@app.route("/templates")
def list_templates():
    db = get_db()
    rows = db.execute("SELECT * FROM templates ORDER BY id DESC").fetchall()
    return render_template("templates_list.html", title="Email templates", active="templates", templates=rows)


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
    return render_template("template_new.html", title="New template", active="templates")


# ------------------------------------------------------------------------
# Campaigns
# ------------------------------------------------------------------------

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
    return render_template("campaigns_list.html", title="Campaigns", active="campaigns", campaigns=rows)


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
    return render_template("campaign_new.html", title="New campaign", active="campaigns", templates=templates)


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
    return render_template(
        "campaign_detail.html", title=f"Campaign: {campaign['name']}", active="campaigns",
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
        tracking_link = f"{config.BASE_URL}{url_for('track_click', token=t['token'])}"
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
    return render_template("landing_form.html", token=token)


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
    return render_template(
        "reveal.html",
        note="You just entered information into a fake login form during a security-awareness exercise.",
        red_flags=flags,
    )


# ------------------------------------------------------------------------
# People & scores
# ------------------------------------------------------------------------

@app.route("/users")
def list_users():
    return render_template("users_list.html", title="People & scores", active="users", users=user_stats())


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
    return render_template(
        "user_detail.html", title=u["name"] or email, active="users", u=u, recs=recs, history=history
    )


# ------------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------------

init_db()

if __name__ == "__main__":
    if config.TEST_MODE:
        print("Running in TEST MODE — emails will be logged to the console, not actually sent.")
        print("Set SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASSWORD / SENDER_EMAIL to send real mail.\n")
    print(f"Admin login: {config.ADMIN_USERNAME} / {config.ADMIN_PASSWORD} (change via env vars for real use)\n")
    app.run(debug=True, host="0.0.0.0", port=3000)
