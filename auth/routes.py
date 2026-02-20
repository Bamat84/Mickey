"""
auth/routes.py
──────────────
Mickey — Public Auth Routes  (Chunk 2)

Registered as a Blueprint in server.py (Chunk 9).
Until Chunk 9, these routes are standalone and don't
touch the existing Mickey session system.

Routes:
  GET  /                          → landing page
  GET  /signin                    → sign in page
  POST /auth/signin               → sign in logic
  GET  /register                  → registration form
  POST /auth/register             → registration logic
  GET  /auth/check-domain         → domain availability check (AJAX)
  POST /auth/send-tc-email        → send T&C PDF to email
  GET  /verify-email/<token>      → email verification
  GET  /verify-pending            → "check your email" holding page
  GET  /pending                   → "awaiting approval" holding page
  GET  /invite/<token>            → invite acceptance form
  POST /auth/invite/accept        → invite acceptance logic
  POST /auth/signout              → sign out
  POST /auth/resend-verification  → resend verification email
"""

import datetime
import time
import json
from collections import defaultdict
from pathlib import Path
from flask import (
    Blueprint, render_template, request, jsonify,
    session, redirect, url_for
)

# ── Auth-specific rate limiting ───────────────────────────────
# Stricter than the AI rate limiter in server.py.
# Principle 1: Rate limiting on all auth endpoints.
# Principle 1: Failed login attempts logged with IP.

_auth_attempts: dict = defaultdict(list)  # ip → [timestamps]

_MAX_ATTEMPTS  = 5    # per _WINDOW_SECS
_WINDOW_SECS   = 300  # 5-minute sliding window
_LOCKOUT_SECS  = 900  # 15-minute lockout

def _rate_key() -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "unknown")

def _check_auth_rate(key: str) -> tuple:
    """Returns (allowed: bool, seconds_to_wait: int)."""
    now   = time.time()
    calls = [t for t in _auth_attempts[key] if now - t < _WINDOW_SECS]
    _auth_attempts[key] = calls
    if len(calls) >= _MAX_ATTEMPTS:
        wait = int(_LOCKOUT_SECS - (now - min(calls)))
        return False, max(wait, 0)
    return True, 0

def _record_auth_attempt(key: str) -> None:
    _auth_attempts[key].append(time.time())

def _clear_auth_attempts(key: str) -> None:
    _auth_attempts.pop(key, None)

def _log_auth_event(event: str, email: str, success: bool) -> None:
    """Append to audit log. Never logs passwords or tokens."""
    try:
        import os
        base     = Path(os.environ.get("MICKEY_DATA", "/opt/mickey"))
        log_path = base / "auth" / "auth_audit.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "ts":      datetime.datetime.utcnow().isoformat(),
            "event":   event,
            "email":   email,
            "ip":      _rate_key(),
            "success": success,
        }
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        pass  # logging must never crash the auth flow

from auth.data import (
    domain_is_taken, email_to_domain,
    create_firm, create_firm_user, approve_firm,
    create_email_token, consume_token, load_token,
    create_invite_token, list_pending_invites,
    get_firm_id_by_email, load_firm, find_user_by_email,
    register_domain, register_email, update_user_field,
    get_firm_user_count, record_login, accept_tc,
)
from auth.passwords import hash_pw, verify_pw, validate_pw
from auth.email import (
    send_verification_email,
    send_approval_email,
    send_new_firm_notification,
    send_invite_email,
)

auth_bp = Blueprint("auth", __name__)

# ── Current T&C version ───────────────────────────────────────
TC_VERSION = "1.0"


# ════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════

def _client_ip() -> str:
    """Best-effort real IP (handles reverse proxy)."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _firm_session(firm, user) -> None:
    """Write firm+user into Flask session."""
    session.clear()
    session["firm_id"]      = firm["firm_id"]
    session["user_id"]      = user["user_id"]
    session["email"]        = user["email"]
    session["display_name"] = user["display_name"]
    session["role"]         = user["role"]
    session["firm_name"]    = firm["firm_name"]
    session["firm_status"]  = firm["status"]
    session.permanent       = True


def _role_label(role: str) -> str:
    return {
        "admin":             "Admin",
        "member":            "Member",
        "knowledge_curator": "Knowledge Curator",
    }.get(role, role.capitalize())


# ════════════════════════════════════════════════════════════════
# PUBLIC PAGES
# ════════════════════════════════════════════════════════════════

@auth_bp.route("/")
def landing():
    # If already signed in send them to the app
    if session.get("firm_id"):
        return redirect("/app")
    return render_template("auth/landing.html")


@auth_bp.route("/signin")
def signin_page():
    if session.get("firm_id"):
        return redirect("/app")
    return render_template("auth/signin.html")


@auth_bp.route("/register")
def register_page():
    if session.get("firm_id"):
        return redirect("/app")
    return render_template("auth/register.html")


@auth_bp.route("/verify-pending")
def verify_pending():
    email = session.get("pending_email", "")
    return render_template("auth/verify_pending.html", email=email)


@auth_bp.route("/pending")
def pending_page():
    firm_name = session.get("pending_firm_name", "")
    email     = session.get("pending_email", "")
    return render_template("auth/pending.html", firm_name=firm_name, email=email)


@auth_bp.route("/invite/<token>")
def invite_page(token):
    rec = load_token(token)
    if not rec or rec.get("used") or rec.get("type") != "invite":
        return render_template("auth/invite.html", invalid=True, token=token)

    # Check not expired
    expires = datetime.datetime.fromisoformat(rec["expires_at"])
    if datetime.datetime.utcnow() > expires:
        return render_template("auth/invite.html", invalid=True, token=token)

    firm = load_firm(rec["firm_id"])
    if not firm:
        return render_template("auth/invite.html", invalid=True, token=token)

    # Find invited_by name
    invited_by = ""
    if rec.get("invited_by"):
        inviter = firm.get("users", {}).get(rec["invited_by"], {})
        invited_by = inviter.get("display_name", "")

    return render_template(
        "auth/invite.html",
        invalid=False,
        token=token,
        email=rec["email"],
        firm_name=firm["firm_name"],
        role_label=_role_label(rec["role"]),
        invited_by=invited_by,
    )


# ════════════════════════════════════════════════════════════════
# AUTH API  (JSON endpoints called by the JS in templates)
# ════════════════════════════════════════════════════════════════

@auth_bp.route("/auth/check-domain")
def check_domain():
    """AJAX: is this email domain already registered?"""
    domain = request.args.get("domain", "").lower().strip()
    if not domain:
        return jsonify({"taken": False})
    return jsonify({"taken": domain_is_taken(domain)})


@auth_bp.route("/auth/send-tc-email", methods=["POST"])
def send_tc_email():
    """Send T&C PDF link to the given email (pre-registration)."""
    d     = request.get_json(force=True) or {}
    email = (d.get("email") or "").strip().lower()
    if not email:
        return jsonify({"ok": False})
    # Reuse the verification email template to send the T&C link
    from auth.email import _send, _base_template, _h1, _p, _btn, PLATFORM_URL
    content = (
        _h1("Mickey Terms of Service") +
        _p("You requested a copy of the Mickey Terms of Service and Privacy Policy.") +
        _btn(f"{PLATFORM_URL}/terms.pdf", "Download Terms of Service (PDF)")
    )
    _send(email, email, "Mickey — Terms of Service", _base_template(content))
    return jsonify({"ok": True})


@auth_bp.route("/auth/register", methods=["POST"])
def do_register():
    # Principle 1: rate limit registration by IP
    ip = _rate_key()
    allowed, wait = _check_auth_rate(ip)
    if not allowed:
        mins = (wait + 59) // 60
        return jsonify({"error": f"Too many attempts. Please wait {mins} minute(s) and try again."}), 429

    d = request.get_json(force=True) or {}

    firm_name    = (d.get("firm_name")    or "").strip()
    country      = (d.get("country")      or "BE").strip().upper()
    vat          = (d.get("vat")          or "").strip()
    display_name = (d.get("display_name") or "").strip()
    email        = (d.get("email")        or "").strip().lower()
    password     = d.get("password", "")
    confirm      = d.get("confirm", "")
    tc_accept    = d.get("tc_accept", False)
    cookie       = d.get("cookie_consent", "not_set")

    # ── Validation ────────────────────────────────────────────
    if not firm_name:    return jsonify({"error": "Firm name is required."}), 400
    if not display_name: return jsonify({"error": "Your name is required."}), 400
    if not email:        return jsonify({"error": "Email address is required."}), 400
    if "@" not in email: return jsonify({"error": "Please enter a valid email address."}), 400
    if not tc_accept:    return jsonify({"error": "You must accept the Terms of Service."}), 400
    if password != confirm:
        return jsonify({"error": "Passwords do not match."}), 400

    valid, rules = validate_pw(password)
    if not valid:
        return jsonify({"error": "Password needs: " + ", ".join(rules) + "."}), 400

    # ── Domain blocking ───────────────────────────────────────
    domain = email_to_domain(email)
    if domain_is_taken(domain):
        return jsonify({"error": "Your firm's email domain is already registered. Ask your admin to invite you."}), 409

    # ── Check email not already registered ────────────────────
    existing_fid = get_firm_id_by_email(email)
    if existing_fid:
        return jsonify({"error": "This email address is already registered. Please sign in."}), 409

    # ── Create firm ───────────────────────────────────────────
    firm = create_firm(firm_name, domain, email, vat, country)

    # ── Create admin user ─────────────────────────────────────
    hashed = hash_pw(password)
    user   = create_firm_user(
        firm, email, display_name, hashed,
        role="admin", email_verified=False
    )

    # Record T&C acceptance
    ip = _client_ip()
    accept_tc(firm, user["user_id"], ip, TC_VERSION)

    # Record cookie consent on the user
    update_user_field(firm, user["user_id"], cookie_accepted=(cookie == "accepted"))

    # Register indexes
    register_domain(domain, firm["firm_id"])
    register_email(email, firm["firm_id"])

    # ── Send verification email ───────────────────────────────
    # Reload firm (updated by create_firm_user + accept_tc)
    from auth.data import load_firm as _load
    firm = _load(firm["firm_id"])
    token = create_email_token(email, firm["firm_id"], user["user_id"])
    send_verification_email(email, display_name, firm_name, token)
    _log_auth_event("register", email, True)

    # Store in session for the holding page
    session["pending_email"]     = email
    session["pending_firm_name"] = firm_name

    return jsonify({"ok": True})


@auth_bp.route("/verify-email/<token>")
def verify_email(token):
    rec = consume_token(token)

    if not rec:
        # Expired or invalid — show a helpful error
        return render_template(
            "auth/verify_pending.html",
            email="",
            error="This verification link has expired or already been used. Please register again or request a new link."
        )

    firm = load_firm(rec["firm_id"])
    if not firm:
        return redirect("/register")

    # Mark user email as verified
    update_user_field(firm, rec["user_id"], email_verified=True)

    # Notify platform owner
    admin_user = firm["users"].get(rec["user_id"], {})
    send_new_firm_notification(
        firm_name=firm["firm_name"],
        firm_id=firm["firm_id"],
        admin_email=admin_user.get("email", ""),
        admin_name=admin_user.get("display_name", ""),
        email_domain=firm["email_domain"],
        country=firm["country"],
        vat=firm["vat"],
    )

    session["pending_firm_name"] = firm["firm_name"]
    session["pending_email"]     = admin_user.get("email", "")
    return redirect("/pending")


@auth_bp.route("/auth/resend-verification", methods=["POST"])
def resend_verification():
    email = session.get("pending_email", "")
    if not email:
        return jsonify({"ok": False})

    firm, user = find_user_by_email(email)
    if not firm or not user:
        return jsonify({"ok": False})

    token = create_email_token(email, firm["firm_id"], user["user_id"])
    send_verification_email(email, user["display_name"], firm["firm_name"], token)
    return jsonify({"ok": True})


@auth_bp.route("/auth/signin", methods=["POST"])
def do_signin():
    # Principle 1: rate limit auth endpoints by IP
    ip = _rate_key()
    allowed, wait = _check_auth_rate(ip)
    if not allowed:
        mins = (wait + 59) // 60
        return jsonify({"error": f"Too many attempts. Please wait {mins} minute(s) and try again."}), 429

    d        = request.get_json(force=True) or {}
    email    = (d.get("email") or "").strip().lower()
    password = d.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400

    firm, user = find_user_by_email(email)

    if not firm or not user:
        _record_auth_attempt(ip)
        _log_auth_event("signin_fail", email, False)
        # Security: don't reveal whether the email is registered
        return jsonify({"error": "Incorrect email or password."}), 401

    if not verify_pw(password, user.get("hashed", "")):
        _record_auth_attempt(ip)
        _log_auth_event("signin_fail", email, False)
        return jsonify({"error": "Incorrect email or password."}), 401

    if not user.get("email_verified"):
        session["pending_email"] = email
        return jsonify({"error": "Please verify your email address first.", "redirect": "/verify-pending"}), 403

    if firm["status"] == "pending_approval":
        session["pending_firm_name"] = firm["firm_name"]
        session["pending_email"]     = email
        return jsonify({"error": "Your account is pending approval.", "redirect": "/pending"}), 403

    if firm["status"] in ("rejected", "suspended"):
        return jsonify({"error": "This account has been suspended. Contact hello@askmickey.io."}), 403

    # ── Successful sign in ────────────────────────────────────
    _clear_auth_attempts(ip)
    _log_auth_event("signin_ok", email, True)
    _firm_session(firm, user)
    record_login(firm, user["user_id"])

    return jsonify({"ok": True, "redirect": "/app"})


@auth_bp.route("/auth/invite/accept", methods=["POST"])
def accept_invite():
    d            = request.get_json(force=True) or {}
    token        = d.get("token", "")
    display_name = (d.get("display_name") or "").strip()
    password     = d.get("password", "")
    confirm      = d.get("confirm", "")
    tc_accept    = d.get("tc_accept", False)

    if not display_name: return jsonify({"error": "Please enter your full name."}), 400
    if not tc_accept:    return jsonify({"error": "You must accept the Terms of Service."}), 400
    if password != confirm:
        return jsonify({"error": "Passwords do not match."}), 400

    valid, rules = validate_pw(password)
    if not valid:
        return jsonify({"error": "Password needs: " + ", ".join(rules) + "."}), 400

    rec = consume_token(token)
    if not rec or rec.get("type") != "invite":
        return jsonify({"error": "This invitation link has expired or already been used."}), 400

    firm = load_firm(rec["firm_id"])
    if not firm:
        return jsonify({"error": "Firm not found."}), 404

    # Check seats
    if get_firm_user_count(firm) >= firm.get("seats", 10):
        return jsonify({"error": "Your firm has reached its seat limit. Ask your admin to upgrade."}), 403

    hashed = hash_pw(password)
    user   = create_firm_user(
        firm, rec["email"], display_name, hashed,
        role=rec["role"], invited_by=rec.get("invited_by"),
        email_verified=True,  # invite email was already verified by clicking the link
    )

    # Record T&C
    accept_tc(firm, user["user_id"], _client_ip(), TC_VERSION)
    register_email(rec["email"], firm["firm_id"])

    # Reload firm then sign in
    from auth.data import load_firm as _load
    firm = _load(firm["firm_id"])
    _firm_session(firm, user)
    record_login(firm, user["user_id"])

    return jsonify({"ok": True, "redirect": "/app"})


@auth_bp.route("/auth/signout", methods=["POST"])
def signout():
    session.clear()
    return jsonify({"ok": True, "redirect": "/"})


@auth_bp.route("/terms")
def terms_page():
    return render_template("auth/terms.html")


@auth_bp.route("/privacy")
def privacy_page():
    return render_template("auth/privacy.html")


# ════════════════════════════════════════════════════════════════
# TEMPORARY RESET ROUTE — REMOVE AFTER USE
# ════════════════════════════════════════════════════════════════
# Access: /auth/reset-registration?code=MICKEYRESET2026
# Clears firm/index files so you can re-register.
# This route will be deleted in the next commit.

@auth_bp.route("/auth/reset-registration")
def temp_reset_registration():
    import os
    from pathlib import Path

    code = request.args.get("code", "")
    if code != "MICKEYRESET2026":
        return "Not found", 404

    base = Path(os.environ.get("MICKEY_DATA", "/opt/mickey"))
    auth_path = base / "auth"
    deleted = []

    # Delete all firm files
    for f in (auth_path / "firms").glob("f_*.json"):
        f.unlink()
        deleted.append(f.name)

    # Delete indexes
    for name in ["domain_to_firm.json", "email_to_firm.json"]:
        p = auth_path / "indexes" / name
        if p.exists():
            p.unlink()
            deleted.append(name)

    # Delete all tokens (verification + invites)
    for f in (auth_path / "tokens").glob("*.json"):
        f.unlink()
        deleted.append(f.name)

    return f"""
    <html><body style="font-family:sans-serif;padding:40px;background:#F5F3EE;">
    <h2 style="color:#1B4F40;">Registration reset complete</h2>
    <p>Deleted {len(deleted)} file(s).</p>
    <p style="margin-top:20px;">
        <a href="/register" style="background:#1B4F40;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;">
            Register now
        </a>
    </p>
    </body></html>
    """
