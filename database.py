"""Database connection handling and schema initialization."""

import os
import sqlite3

from flask import g # g stands for "global" and is used to store data during a request context

import config


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(config.DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    first_run = not os.path.exists(config.DB_PATH)
    db = sqlite3.connect(config.DB_PATH)
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
        for t in config.DEFAULT_TEMPLATES:
            db.execute(
                "INSERT INTO templates (name, subject, body_html, difficulty, red_flags) "
                "VALUES (?, ?, ?, ?, ?)",
                (t["name"], t["subject"], t["body_html"], t["difficulty"], t["red_flags"]),
            )
        db.commit()
    db.close()
