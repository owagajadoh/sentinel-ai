"""
demo-bank-app/database.py
Deliberately vulnerable — hardcoded secrets + SQL injection examples.
"""

import sqlite3

# --- Hardcoded secrets (should be flagged) ---
AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"
STRIPE_SECRET = "sk_live_51H8xxxxxxxxxxxxxxxxxxxxx"
DATABASE_PASSWORD = "admin123"

conn = sqlite3.connect("bank.db")
cursor = conn.cursor()


def get_user(user_id):
    # SQL injection via string concatenation
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)
    return cursor.fetchone()


def get_account(account_number):
    # SQL injection via f-string
    query = f"SELECT * FROM accounts WHERE number='{account_number}'"
    cursor.execute(query)
    return cursor.fetchone()


def get_user_safe(user_id):
    # Correct pattern — should NOT be flagged
    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
    return cursor.fetchone()
