"""
auth/data.py
────────────
Mickey — Firm & Auth Data Layer  (Chunk 1)

New directory layout under AUTH_PATH (default: /opt/mickey/auth/):

  firms/
    {firm_id}.json              ← one record per firm
  invites/
    {token}.json                ← one record per pending invite
  tokens/
    {token}.json                ← email verification tokens
  indexes/
    domain_to_firm.json         ← {email_domain: firm_id}
    email_to_user.json          ← {email: firm_id}

Existing /opt/mickey/users.json and /opt/mickey/data/ are
NOT touched by this module — they continue to work as-is.
Firm users are stored inside the firm record until Chunk 9
integrates the two systems.

Multi-user safety note (1–5 person legal teams):
  JSON + atomic rename is safe for this scale. We use a
  write-to-tmp-then-rename pattern so a crash during write
  never corrupts the live file. If Mickey ever scales beyond
  ~50 concurrent users, migrate to SQLite.
"""

import json
import os
import secrets
import datetime
import tempfile
from pathlib import Path

# ── Path setup ────────────────────────────────────────────────
# Mirrors the pattern in server.py: respects MICKEY_DATA env var
_BASE       = Path(os.environ.get("MICKEY_DATA", "/opt/mickey"))
AUTH_PATH   = _BASE / "auth"
FIRMS_DIR   = AUTH_PATH / "firms"
INVITES_DIR = AUTH_PATH / "invites"
TOKENS_DIR  = AUTH_PATH / "tokens"
INDEX_DIR   = AUTH_PATH / "indexes"

for _d in [FIRMS_DIR, INVITES_DIR, TOKENS_DIR, INDEX_DIR]:
    _d.mkdir(parents=True, exist_ok=True)


# ════════════════════════════════════════════════════════════════
# ATOMIC FILE I/O
# ════════════════════════════════════════════════════════════════

def _atomic_write(path: Path, data: dict) -> None:
    """
    Write JSON to a temp file in the same directory, then rename.
    Rename is atomic on Linux (same filesystem), so a crash during
    write never leaves a half-written file.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, path)          # atomic on Linux
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _read_json(path: Path, default=None):
    """Read JSON file, return default if missing or corrupt."""
    if default is None:
        default = {}
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


# ════════════════════════════════════════════════════════════════
# FIRM RECORDS
# ════════════════════════════════════════════════════════════════
#
# Firm record schema:
# {
#   "firm_id":        "f_<16 hex chars>",
#   "firm_name":      "De Backer Law",
#   "email_domain":   "debacker-law.be",       ← used for domain blocking
#   "billing_email":  "mathias@debacker-law.be",
#   "vat":            "BE0123456789",           ← optional
#   "country":        "BE",
#   "status":         "pending_approval" | "trial" | "active" | "suspended",
#   "seats":          10,
#   "created_at":     "2026-02-20T21:00:00",
#   "approved_at":    null | "2026-02-20T21:05:00",
#   "approved_by":    null | "platform_admin",
#   "tc_version":     "1.0",
#   "trial_ends_at":  "2026-03-22T21:00:00",
#   "users": {
#     "user_<id>": {
#       "user_id":          "user_<16 hex>",
#       "email":            "mathias@debacker-law.be",
#       "display_name":     "Mathias De Backer",
#       "role":             "admin" | "member" | "knowledge_curator",
#       "hashed":           "<bcrypt hash>",
#       "email_verified":   true | false,
#       "tc_accepted_at":   "2026-02-20T21:00:00" | null,
#       "tc_version":       "1.0" | null,
#       "tc_ip":            "1.2.3.4" | null,
#       "tc_pdf_sent":      true | false,
#       "cookie_accepted":  true | false,
#       "created_at":       "2026-02-20T21:00:00",
#       "last_login":       "2026-02-20T21:00:00" | null,
#       "invited_by":       "user_<id>" | null
#     }
#   }
# }

TRIAL_DAYS   = 30
DEFAULT_SEATS = 10


def new_firm_id() -> str:
    return "f_" + secrets.token_hex(8)


def new_user_id() -> str:
    return "user_" + secrets.token_hex(8)


def _firm_path(firm_id: str) -> Path:
    return FIRMS_DIR / f"{firm_id}.json"


def load_firm(firm_id: str) -> dict | None:
    """Load a single firm record. Returns None if not found."""
    data = _read_json(_firm_path(firm_id), default=None)
    return data


def save_firm(firm: dict) -> None:
    """Atomically save a firm record."""
    _atomic_write(_firm_path(firm["firm_id"]), firm)


def list_firms() -> list[dict]:
    """Return all firm records, newest first."""
    firms = []
    for p in FIRMS_DIR.glob("*.json"):
        rec = _read_json(p)
        if rec:
            firms.append(rec)
    firms.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return firms


def create_firm(
    firm_name: str,
    email_domain: str,
    billing_email: str,
    vat: str = "",
    country: str = "BE",
) -> dict:
    """
    Create a new firm in pending_approval status.
    Does NOT create any users — call create_firm_user() after.
    """
    now = datetime.datetime.utcnow().isoformat()
    trial_end = (
        datetime.datetime.utcnow() + datetime.timedelta(days=TRIAL_DAYS)
    ).isoformat()

    firm = {
        "firm_id":       new_firm_id(),
        "firm_name":     firm_name.strip(),
        "email_domain":  email_domain.lower().strip(),
        "billing_email": billing_email.lower().strip(),
        "vat":           vat.strip(),
        "country":       country.upper().strip(),
        "status":        "pending_approval",
        "seats":         DEFAULT_SEATS,
        "created_at":    now,
        "approved_at":   None,
        "approved_by":   None,
        "rejected_at":   None,
        "rejected_by":   None,
        "tc_version":    "1.0",
        "trial_ends_at": trial_end,
        "users":         {},
    }
    save_firm(firm)
    return firm


def approve_firm(firm_id: str, approved_by: str = "platform_admin") -> dict | None:
    """Set firm status to trial and record approval timestamp."""
    firm = load_firm(firm_id)
    if not firm:
        return None
    now = datetime.datetime.utcnow().isoformat()
    firm["status"]      = "trial"
    firm["approved_at"] = now
    firm["approved_by"] = approved_by
    save_firm(firm)
    return firm


def reject_firm(firm_id: str, rejected_by: str = "platform_admin") -> dict | None:
    """Set firm status to rejected."""
    firm = load_firm(firm_id)
    if not firm:
        return None
    now = datetime.datetime.utcnow().isoformat()
    firm["status"]      = "rejected"
    firm["rejected_at"] = now
    firm["rejected_by"] = rejected_by
    save_firm(firm)
    return firm


def suspend_firm(firm_id: str) -> dict | None:
    firm = load_firm(firm_id)
    if not firm:
        return None
    firm["status"] = "suspended"
    save_firm(firm)
    return firm


# ════════════════════════════════════════════════════════════════
# FIRM USERS
# ════════════════════════════════════════════════════════════════

def create_firm_user(
    firm: dict,
    email: str,
    display_name: str,
    hashed_password: str,
    role: str = "admin",
    invited_by: str | None = None,
    email_verified: bool = False,
) -> dict:
    """
    Add a user to a firm record and save.
    Returns the new user dict.
    Role: "admin" | "member" | "knowledge_curator"
    """
    import hashlib
    user_id = new_user_id()
    now = datetime.datetime.utcnow().isoformat()

    user = {
        "user_id":         user_id,
        "email":           email.lower().strip(),
        "display_name":    display_name.strip(),
        "role":            role,
        "hashed":          hashed_password,
        "email_verified":  email_verified,
        "tc_accepted_at":  None,
        "tc_version":      None,
        "tc_ip":           None,
        "tc_pdf_sent":     False,
        "cookie_accepted": False,
        "created_at":      now,
        "last_login":      None,
        "invited_by":      invited_by,
    }
    firm["users"][user_id] = user
    save_firm(firm)
    return user


def find_user_by_email(email: str) -> tuple[dict | None, dict | None]:
    """
    Search all firms for a user with this email.
    Returns (firm, user) or (None, None).
    """
    email = email.lower().strip()
    for firm in list_firms():
        for user in firm.get("users", {}).values():
            if user.get("email") == email:
                return firm, user
    return None, None


def get_firm_user_count(firm: dict) -> int:
    return len(firm.get("users", {}))


def update_user_field(firm: dict, user_id: str, **fields) -> None:
    """Update specific fields on a user and save the firm atomically."""
    if user_id not in firm["users"]:
        return
    firm["users"][user_id].update(fields)
    save_firm(firm)


def record_login(firm: dict, user_id: str) -> None:
    update_user_field(
        firm, user_id,
        last_login=datetime.datetime.utcnow().isoformat()
    )


def accept_tc(firm: dict, user_id: str, ip: str, version: str = "1.0") -> None:
    update_user_field(
        firm, user_id,
        tc_accepted_at=datetime.datetime.utcnow().isoformat(),
        tc_version=version,
        tc_ip=ip,
    )


# ════════════════════════════════════════════════════════════════
# EMAIL VERIFICATION TOKENS
# ════════════════════════════════════════════════════════════════
#
# Token record:
# {
#   "token":      "<64 hex chars>",
#   "type":       "email_verify" | "invite",
#   "email":      "user@firm.be",
#   "firm_id":    "f_...",
#   "user_id":    "user_...",    ← null for invite (user not yet created)
#   "role":       null | "member" | "knowledge_curator",
#   "created_at": "...",
#   "expires_at": "...",
#   "used":       false
# }

TOKEN_EXPIRY_HOURS = 24


def new_token() -> str:
    return secrets.token_hex(32)   # 64 chars, URL-safe


def _token_path(token: str) -> Path:
    return TOKENS_DIR / f"{token}.json"


def create_email_token(
    email: str,
    firm_id: str,
    user_id: str,
    token_type: str = "email_verify",
) -> str:
    """Create and save an email verification token. Returns the token string."""
    token = new_token()
    now   = datetime.datetime.utcnow()
    rec   = {
        "token":      token,
        "type":       token_type,
        "email":      email.lower().strip(),
        "firm_id":    firm_id,
        "user_id":    user_id,
        "role":       None,
        "created_at": now.isoformat(),
        "expires_at": (now + datetime.timedelta(hours=TOKEN_EXPIRY_HOURS)).isoformat(),
        "used":       False,
    }
    _atomic_write(_token_path(token), rec)
    return token


def create_invite_token(
    email: str,
    firm_id: str,
    role: str,
    invited_by_user_id: str,
) -> str:
    """Create a team invite token (user doesn't exist yet). Returns token."""
    token = new_token()
    now   = datetime.datetime.utcnow()
    rec   = {
        "token":      token,
        "type":       "invite",
        "email":      email.lower().strip(),
        "firm_id":    firm_id,
        "user_id":    None,
        "role":       role,
        "invited_by": invited_by_user_id,
        "created_at": now.isoformat(),
        "expires_at": (now + datetime.timedelta(hours=TOKEN_EXPIRY_HOURS * 7)).isoformat(),  # 7 days for invites
        "used":       False,
    }
    _atomic_write(_token_path(token), rec)
    return token


def load_token(token: str) -> dict | None:
    """Load token record. Returns None if not found."""
    return _read_json(_token_path(token), default=None)


def consume_token(token: str) -> dict | None:
    """
    Mark token as used and return it.
    Returns None if token not found, already used, or expired.
    """
    rec = load_token(token)
    if not rec:
        return None
    if rec.get("used"):
        return None
    expires = datetime.datetime.fromisoformat(rec["expires_at"])
    if datetime.datetime.utcnow() > expires:
        return None
    rec["used"] = True
    rec["used_at"] = datetime.datetime.utcnow().isoformat()
    _atomic_write(_token_path(token), rec)
    return rec


def list_pending_invites(firm_id: str) -> list[dict]:
    """Return all unused, non-expired invite tokens for a firm."""
    now = datetime.datetime.utcnow()
    result = []
    for p in TOKENS_DIR.glob("*.json"):
        rec = _read_json(p)
        if (
            rec
            and rec.get("type") == "invite"
            and rec.get("firm_id") == firm_id
            and not rec.get("used")
            and datetime.datetime.fromisoformat(rec["expires_at"]) > now
        ):
            result.append(rec)
    return result


def revoke_invite(token: str) -> bool:
    """Mark an invite token as used (effectively revoked)."""
    rec = load_token(token)
    if not rec:
        return False
    rec["used"] = True
    rec["revoked"] = True
    rec["revoked_at"] = datetime.datetime.utcnow().isoformat()
    _atomic_write(_token_path(token), rec)
    return True


# ════════════════════════════════════════════════════════════════
# INDEXES  (fast lookups without scanning all firms)
# ════════════════════════════════════════════════════════════════
#
# These are derived/cached data — rebuilt from firms if lost.
# Always update indexes when creating firms or users.

def _index_path(name: str) -> Path:
    return INDEX_DIR / f"{name}.json"


def _load_index(name: str) -> dict:
    return _read_json(_index_path(name), default={})


def _save_index(name: str, data: dict) -> None:
    _atomic_write(_index_path(name), data)


# ── Domain → firm_id ─────────────────────────────────────────

def register_domain(email_domain: str, firm_id: str) -> None:
    idx = _load_index("domain_to_firm")
    idx[email_domain.lower().strip()] = firm_id
    _save_index("domain_to_firm", idx)


def domain_is_taken(email_domain: str) -> bool:
    """True if any firm has already registered this email domain."""
    idx = _load_index("domain_to_firm")
    fid = idx.get(email_domain.lower().strip())
    if not fid:
        return False
    # Verify the firm still exists (defensive — handles deleted firms)
    return load_firm(fid) is not None


def get_firm_by_domain(email_domain: str) -> dict | None:
    idx = _load_index("domain_to_firm")
    fid = idx.get(email_domain.lower().strip())
    return load_firm(fid) if fid else None


def unregister_domain(email_domain: str) -> None:
    idx = _load_index("domain_to_firm")
    idx.pop(email_domain.lower().strip(), None)
    _save_index("domain_to_firm", idx)


# ── Email → firm_id (for fast login lookup) ──────────────────

def register_email(email: str, firm_id: str) -> None:
    idx = _load_index("email_to_firm")
    idx[email.lower().strip()] = firm_id
    _save_index("email_to_firm", idx)


def get_firm_id_by_email(email: str) -> str | None:
    idx = _load_index("email_to_firm")
    return idx.get(email.lower().strip())


def unregister_email(email: str) -> None:
    idx = _load_index("email_to_firm")
    idx.pop(email.lower().strip(), None)
    _save_index("email_to_firm", idx)


# ════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════

def email_to_domain(email: str) -> str:
    """Extract domain from email address."""
    parts = email.lower().strip().split("@")
    return parts[-1] if len(parts) == 2 else ""


def rebuild_indexes() -> None:
    """
    Rebuild all indexes from scratch by scanning firm files.
    Run this if indexes get out of sync (e.g. after manual edits).
    """
    domain_idx: dict = {}
    email_idx:  dict = {}

    for firm in list_firms():
        fid    = firm["firm_id"]
        domain = firm.get("email_domain", "")
        if domain:
            domain_idx[domain] = fid
        for user in firm.get("users", {}).values():
            email = user.get("email", "")
            if email:
                email_idx[email] = fid

    _save_index("domain_to_firm", domain_idx)
    _save_index("email_to_firm",  email_idx)

def create_password_reset_token(email: str, firm_id: str, user_id: str) -> str:
    """
    Create a password reset token.
    Principle 1: expires after 1 hour, single-use.
    Any existing unused reset tokens for this user are invalidated first.
    """
    # Invalidate any existing reset tokens for this user (principle 1)
    for p in TOKENS_DIR.glob("*.json"):
        rec = _read_json(p)
        if (rec
            and rec.get("type") == "password_reset"
            and rec.get("user_id") == user_id
            and not rec.get("used")):
            rec["used"] = True
            rec["invalidated"] = True
            _atomic_write(p, rec)

    token = new_token()
    now   = datetime.datetime.utcnow()
    rec   = {
        "token":      token,
        "type":       "password_reset",
        "email":      email.lower().strip(),
        "firm_id":    firm_id,
        "user_id":    user_id,
        "role":       None,
        "created_at": now.isoformat(),
        "expires_at": (now + datetime.timedelta(hours=1)).isoformat(),  # Principle 1: 1 hour
        "used":       False,
    }
    _atomic_write(_token_path(token), rec)
    return token

def list_all_firms() -> list:
    """Return summary of all registered firms for the back office."""
    firms = []
    if not FIRMS_DIR.exists():
        return firms
    for p in FIRMS_DIR.glob("f_*.json"):
        rec = _read_json(p)
        if rec:
            firms.append({
                "firm_id":     rec.get("firm_id", ""),
                "firm_name":   rec.get("firm_name", ""),
                "email_domain":rec.get("email_domain", ""),
                "status":      rec.get("status", ""),
                "created_at":  rec.get("created_at", ""),
                "approved_at": rec.get("approved_at", ""),
                "user_count":  len(rec.get("users", {})),
                "country":     rec.get("country", ""),
            })
    return sorted(firms, key=lambda x: x.get("created_at", ""), reverse=True)


def _firm_path(firm_id: str):
    return FIRMS_DIR / f"{firm_id}.json"

def save_firm(firm: dict) -> None:
    """Save firm data atomically."""
    firm_id = firm.get("firm_id", "")
    if not firm_id:
        return
    path = FIRMS_DIR / f"{firm_id}.json"
    _atomic_write(path, firm)


def create_invite_token(firm_id: str, email: str, display_name: str,
                        role: str, invited_by: str) -> str:
    """Create a secure invite token for a new team member."""
    token    = _random_token()
    expires  = (datetime.datetime.utcnow() + datetime.timedelta(days=7)).isoformat()
    rec = {
        "token":        token,
        "type":         "invite",
        "firm_id":      firm_id,
        "email":        email,
        "display_name": display_name,
        "role":         role,
        "invited_by":   invited_by,
        "created_at":   datetime.datetime.utcnow().isoformat(),
        "expires_at":   expires,
        "used":         False,
    }
    _atomic_write(TOKENS_DIR / f"{token}.json", rec)
    return token


def update_user_field(firm: dict, user_id: str, **kwargs) -> None:
    """Update fields on a user record and save the firm."""
    if user_id not in firm.get("users", {}):
        return
    firm["users"][user_id].update(kwargs)
    firm["updated_at"] = datetime.datetime.utcnow().isoformat()
    save_firm(firm)

def get_trial_status(firm: dict) -> dict:
    """Return trial status info for a firm."""
    import datetime as _dt
    status     = firm.get("status", "pending_approval")
    created_at = firm.get("created_at", "")
    approved_at= firm.get("approved_at", "")

    if status not in ("trial", "active"):
        return {"status": status, "days_left": 0, "expired": False}

    if status == "active":
        return {"status": "active", "days_left": 999, "expired": False}

    # Calculate trial days remaining
    start_str = approved_at or created_at
    try:
        start = _dt.datetime.fromisoformat(start_str)
        trial_days = int(firm.get("trial_days", 30))
        expires    = start + _dt.timedelta(days=trial_days)
        now        = _dt.datetime.utcnow()
        days_left  = (expires - now).days
        expired    = days_left < 0
        return {
            "status":    "expired" if expired else "trial",
            "days_left": max(0, days_left),
            "expires_at": expires.isoformat(),
            "expired":   expired,
        }
    except Exception:
        return {"status": "trial", "days_left": 30, "expired": False}


def extend_trial(firm_id: str, extra_days: int = 30) -> bool:
    """Platform admin: extend a firm's trial."""
    firm = load_firm(firm_id)
    if not firm:
        return False
    firm["trial_days"] = int(firm.get("trial_days", 30)) + extra_days
    save_firm(firm)
    return True

# ════════════════════════════════════════════════════════════════
# T&C VERSIONING
# ════════════════════════════════════════════════════════════════

CURRENT_TC_VERSION = "1.0"  # Bump this when T&Cs change

def needs_tc_reaccept(user: dict) -> bool:
    """Returns True if user needs to re-accept updated T&Cs."""
    accepted_version = user.get("tc_version_accepted", "")
    return accepted_version != CURRENT_TC_VERSION


def record_tc_acceptance(firm: dict, user_id: str) -> None:
    """Record T&C acceptance with version and timestamp."""
    import datetime as _dt
    if user_id not in firm.get("users", {}):
        return
    firm["users"][user_id]["tc_accepted_at"]       = _dt.datetime.utcnow().isoformat()
    firm["users"][user_id]["tc_version_accepted"]  = CURRENT_TC_VERSION
    save_firm(firm)
