"""
auth/passwords.py
─────────────────
Mickey — Password hashing for firm users  (Chunk 1)

Mirrors the bcrypt approach already used in server.py so both
systems use identical hashing. If server.py is ever merged with
the auth module this file becomes the single source of truth.
"""

import hashlib
import re


def hash_pw(pw: str) -> str:
    """
    bcrypt hash.  SHA-256 pre-hash avoids bcrypt's 72-byte limit.
    Identical to the implementation in server.py.
    """
    import bcrypt
    pre = hashlib.sha256(pw.encode()).hexdigest().encode()
    return bcrypt.hashpw(pre, bcrypt.gensalt(rounds=12)).decode()


def verify_pw(pw: str, stored: str) -> bool:
    import bcrypt
    try:
        pre = hashlib.sha256(pw.encode()).hexdigest().encode()
        return bcrypt.checkpw(pre, stored.encode())
    except Exception:
        return False


def validate_pw(pw: str) -> tuple[bool, list[str]]:
    """
    Returns (is_valid, list_of_unmet_rules).
    Rules match server.py so UX is consistent across both login systems.
    """
    rules = []
    if len(pw) < 8:
        rules.append("at least 8 characters")
    if not re.search(r"\d", pw):
        rules.append("a number")
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>/?`~\\|]", pw):
        rules.append("a special character")
    if not re.search(r"[A-Z]", pw):
        rules.append("an uppercase letter")
    return len(rules) == 0, rules
