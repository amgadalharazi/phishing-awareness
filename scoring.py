"""Awareness-score computation, risk levels, recommendations, and user stats."""

from database import get_db
import config


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
        return config.RISK_LOW
    if score >= 50:
        return config.RISK_MED
    return config.RISK_HIGH


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
    if level == config.RISK_LOW and submitted == 0 and clicked == 0 and sent > 0:
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
