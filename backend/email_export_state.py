import os
import sqlite3
from collections.abc import Callable
from contextlib import closing
from pathlib import Path


def _database_path() -> Path:
    return Path(
        os.getenv(
            "PHISHING_EXPORT_STATE_DB",
            str(Path(__file__).with_name("phishing_export_state.sqlite3")),
        )
    )


def _connect():
    database_path = _database_path()
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path, timeout=30)
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS exported_emails (
            email_id TEXT PRIMARY KEY,
            exported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS processed_emails (
            email_id TEXT PRIMARY KEY,
            classification TEXT NOT NULL,
            reason TEXT NOT NULL,
            processed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    return connection


def get_processed_email(email_id: str) -> dict[str, str] | None:
    with closing(_connect()) as connection:
        row = connection.execute(
            """
            SELECT classification, reason
            FROM processed_emails
            WHERE email_id = ?
            """,
            (email_id,),
        ).fetchone()
    if row is None:
        return None
    return {"classification": row[0], "reason": row[1]}


def record_processed_email(email_id: str, result: dict[str, str]) -> None:
    with closing(_connect()) as connection:
        with connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO processed_emails
                    (email_id, classification, reason)
                VALUES (?, ?, ?)
                """,
                (email_id, result["classification"], result["reason"]),
            )


def export_email_once(email_id: str, export: Callable[[], None]) -> bool:
    with closing(_connect()) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT 1 FROM exported_emails WHERE email_id = ?",
                (email_id,),
            ).fetchone()
            if existing:
                return False

            export()
            connection.execute(
                "INSERT INTO exported_emails (email_id) VALUES (?)",
                (email_id,),
            )
    return True
