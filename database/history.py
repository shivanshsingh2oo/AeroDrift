import sqlite3
from datetime import datetime


def create_database():
    connection = sqlite3.connect("aerodrift.db")

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS drift_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            drift_detected INTEGER,
            message TEXT,
            path TEXT,
            remediation TEXT
        )
    """)

    connection.commit()
    connection.close()


def save_drift(result, remediation):
    connection = sqlite3.connect("aerodrift.db")

    cursor = connection.cursor()

    path = " → ".join(result["path"])

    cursor.execute("""
        INSERT INTO drift_history
        (timestamp, drift_detected, message, path, remediation)
        VALUES (?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        int(result["drift_detected"]),
        result["message"],
        path,
        remediation["action"]
    ))

    connection.commit()
    connection.close()


def get_drift_history():
    connection = sqlite3.connect("aerodrift.db")

    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, timestamp, drift_detected, message, path, remediation
        FROM drift_history
        ORDER BY id DESC
    """)

    records = cursor.fetchall()

    connection.close()

    return records