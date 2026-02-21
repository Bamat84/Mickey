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
    create_password_reset_token,
    list_all_firms,
)
from auth.passwords import hash_pw, verify_pw, validate_pw
from auth.email import (
    send_verification_email,
    send_approval_email,
    send_new_firm_notification,
    send_invite_email,
    send_password_reset_email,
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
    session["username"]     = user["email"]   # bridge: old Mickey app uses session["username"]
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
    return jsonify({"ok": True, "redirect": "/signin"})


@auth_bp.route("/terms")
def terms_page():
    return render_template("auth/terms.html")


@auth_bp.route("/privacy")
def privacy_page():
    return render_template("auth/privacy.html")


@auth_bp.route("/forgot-password")
def forgot_password_page():
    """Request password reset — shown when user clicks 'Forgot password'."""
    return render_template("auth/forgot_password.html")


@auth_bp.route("/auth/forgot-password", methods=["POST"])
def do_forgot_password():
    """
    Principle 1: Never reveal whether email exists.
    Always return the same response regardless.
    Rate limited by IP.
    """
    ip = _rate_key()
    allowed, wait = _check_auth_rate(ip)
    if not allowed:
        mins = (wait + 59) // 60
        return jsonify({"error": f"Too many attempts. Please wait {mins} minute(s)."}), 429

    d     = request.get_json(force=True) or {}
    email = (d.get("email") or "").strip().lower()

    _record_auth_attempt(ip)

    if email and "@" in email:
        firm, user = find_user_by_email(email)
        if firm and user and user.get("email_verified"):
            token = create_password_reset_token(email, firm["firm_id"], user["user_id"])
            send_password_reset_email(email, user["display_name"], token)
            _log_auth_event("password_reset_requested", email, True)

    # Always return success — principle 1: never reveal if email exists
    return jsonify({"ok": True})


@auth_bp.route("/reset-password/<token>")
def reset_password_page(token):
    """Password reset form — user arrives here from email link."""
    rec = load_token(token)

    # Validate token without consuming it yet
    if not rec or rec.get("used") or rec.get("type") != "password_reset":
        return render_template("auth/reset_password.html", invalid=True, token=token)

    expires = datetime.datetime.fromisoformat(rec["expires_at"])
    if datetime.datetime.utcnow() > expires:
        return render_template("auth/reset_password.html", expired=True, token=token)

    return render_template("auth/reset_password.html", invalid=False, expired=False, token=token)


@auth_bp.route("/auth/reset-password", methods=["POST"])
def do_reset_password():
    """
    Consume the reset token and update the password.
    Principle 1: token is single-use, expires after 1 hour.
    """
    d        = request.get_json(force=True) or {}
    token    = d.get("token", "")
    password = d.get("password", "")
    confirm  = d.get("confirm", "")

    if password != confirm:
        return jsonify({"error": "Passwords do not match."}), 400

    valid, rules = validate_pw(password)
    if not valid:
        return jsonify({"error": "Password needs: " + ", ".join(rules) + "."}), 400

    # consume_token validates expiry and single-use atomically
    rec = consume_token(token)
    if not rec or rec.get("type") != "password_reset":
        return jsonify({"error": "This reset link has expired or already been used. Please request a new one."}), 400

    firm = load_firm(rec["firm_id"])
    if not firm:
        return jsonify({"error": "Account not found."}), 404

    # Update password
    hashed = hash_pw(password)
    update_user_field(firm, rec["user_id"], hashed=hashed)
    _log_auth_event("password_reset_complete", rec["email"], True)

    return jsonify({"ok": True})








@auth_bp.route("/trial-expired")
def trial_expired():
    """Shown when a firm's trial has expired."""
    firm_name = session.get("firm_name", "your firm")
    return render_template("auth/trial_expired.html", firm_name=firm_name)







# ════════════════════════════════════════════════════════════════
# CHUNK 12 — T&C VERSIONING + AI DISCLAIMER
# ════════════════════════════════════════════════════════════════

@auth_bp.route("/accept-terms")
def accept_terms_page():
    """Shown when T&Cs have been updated and user needs to re-accept."""
    if not session.get("firm_id"):
        return redirect("/signin")
    from auth.data import needs_tc_reaccept, CURRENT_TC_VERSION
    firm = load_firm(session["firm_id"])
    user_id = session.get("user_id","")
    if not firm or user_id not in firm.get("users",{}):
        return redirect("/signin")
    user = firm["users"][user_id]
    if not needs_tc_reaccept(user):
        return redirect("/app")
    return render_template("auth/accept_terms.html",
        display_name=session.get("display_name",""),
        tc_version=CURRENT_TC_VERSION,
    )


@auth_bp.route("/api/accept-terms", methods=["POST"])
def api_accept_terms():
    """Record T&C acceptance."""
    if not session.get("firm_id"):
        return jsonify({"error": "Not authenticated"}), 401
    from auth.data import record_tc_acceptance
    firm    = load_firm(session["firm_id"])
    user_id = session.get("user_id","")
    if not firm or user_id not in firm.get("users",{}):
        return jsonify({"error": "User not found"}), 404
    record_tc_acceptance(firm, user_id)
    _log_auth_event("tc_accepted", session.get("email",""), True)
    return jsonify({"ok": True, "redirect": "/app"})



# ════════════════════════════════════════════════════════════════
# CHUNK 11 — GDPR DATA RIGHTS (export + deletion)
# ════════════════════════════════════════════════════════════════

@auth_bp.route("/settings/privacy")
def privacy_settings():
    """GDPR data rights page — export and deletion."""
    if not session.get("firm_id"):
        return redirect("/signin")
    return render_template("auth/privacy_settings.html",
        display_name=session.get("display_name",""),
        email=session.get("email",""),
        firm_name=session.get("firm_name",""),
    )


@auth_bp.route("/api/gdpr/export", methods=["POST"])
def gdpr_export():
    """GDPR Art. 20 — data portability. Export all user data as JSON."""
    if not session.get("firm_id"):
        return jsonify({"error": "Not authenticated"}), 401

    import json as _json, datetime as _dt
    firm    = load_firm(session["firm_id"])
    user_id = session.get("user_id","")

    if not firm or user_id not in firm.get("users",{}):
        return jsonify({"error": "User not found"}), 404

    user = firm["users"][user_id]

    export = {
        "export_date":    _dt.datetime.utcnow().isoformat(),
        "export_version": "1.0",
        "subject":        "Mickey personal data export (GDPR Art. 20)",
        "personal_data": {
            "display_name": user.get("display_name",""),
            "email":        user.get("email",""),
            "role":         user.get("role",""),
            "created_at":   user.get("created_at",""),
            "last_signin":  user.get("last_signin",""),
            "tc_accepted_at": user.get("tc_accepted_at",""),
        },
        "firm_data": {
            "firm_name":    firm.get("firm_name",""),
            "email_domain": firm.get("email_domain",""),
            "status":       firm.get("status",""),
            "created_at":   firm.get("created_at",""),
        },
        "note": "Document content, AI query content and usage logs are not included in this export as they are processed transiently and not stored persistently per Mickey's privacy policy."
    }

    _log_auth_event("gdpr_export", session.get("email",""), True)

    from flask import Response
    return Response(
        _json.dumps(export, indent=2, ensure_ascii=False),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=mickey-data-export-{_dt.date.today()}.json"}
    )


@auth_bp.route("/api/gdpr/request-deletion", methods=["POST"])
def gdpr_request_deletion():
    """GDPR Art. 17 — right to erasure. Flags account for deletion."""
    if not session.get("firm_id"):
        return jsonify({"error": "Not authenticated"}), 401

    import datetime as _dt
    firm    = load_firm(session["firm_id"])
    user_id = session.get("user_id","")
    email   = session.get("email","")

    if not firm or user_id not in firm.get("users",{}):
        return jsonify({"error": "User not found"}), 404

    # Mark user for deletion
    firm["users"][user_id]["deletion_requested_at"] = _dt.datetime.utcnow().isoformat()
    firm["users"][user_id]["deletion_requested"]    = True
    save_firm(firm)

    # Notify platform owner
    from auth.email import _send, _base_template, _h1, _p, PLATFORM_URL
    import os
    owner_email = os.environ.get("MICKEY_OWNER_EMAIL","")
    if owner_email:
        body = _base_template(
            _h1("Deletion request received") +
            _p(f"User {email} ({session.get('display_name','')}) has requested deletion of their account.") +
            _p(f"Firm: {firm.get('firm_name','')} ({session.get('firm_id','')})") +
            _p(f"To process: remove user from firm JSON file within 30 days (GDPR Art. 12).") +
            _p(f"User ID: {user_id}")
        )
        _send(owner_email, "Mickey Admin", "Mickey — account deletion request", body)

    _log_auth_event("gdpr_deletion_request", email, True)

    # Sign the user out
    session.clear()
    return jsonify({
        "ok": True,
        "message": "Your deletion request has been received. Your account will be deleted within 30 days in accordance with GDPR Art. 17. You have been signed out."
    })


@auth_bp.route("/api/gdpr/delete-firm", methods=["POST"])
def gdpr_delete_firm():
    """Admin only: delete entire firm and all its data."""
    if not session.get("firm_id") or session.get("role") != "admin":
        return jsonify({"error": "Not authorised"}), 403

    import datetime as _dt, shutil as _shutil
    data    = request.get_json(force=True) or {}
    confirm = data.get("confirm","")

    if confirm != "DELETE MY FIRM":
        return jsonify({"error": "Please type DELETE MY FIRM to confirm"}), 400

    firm_id = session.get("firm_id")
    email   = session.get("email","")
    firm    = load_firm(firm_id)
    if not firm:
        return jsonify({"error": "Firm not found"}), 404

    # Mark for deletion (actual deletion done by platform admin within 30 days)
    firm["deletion_requested_at"] = _dt.datetime.utcnow().isoformat()
    firm["deletion_requested"]    = True
    firm["deletion_requested_by"] = email
    firm["status"]                = "deletion_pending"
    save_firm(firm)

    # Notify platform owner
    from auth.email import _send, _base_template, _h1, _p
    import os
    owner_email = os.environ.get("MICKEY_OWNER_EMAIL","")
    if owner_email:
        body = _base_template(
            _h1("Firm deletion request") +
            _p(f"Firm {firm.get('firm_name','')} (ID: {firm_id}) has requested full account deletion.") +
            _p(f"Requested by: {email}") +
            _p(f"Action required: delete firm data directory within 30 days.")
        )
        _send(owner_email, "Mickey Admin", "Mickey — firm deletion request", body)

    _log_auth_event("gdpr_firm_deletion_request", email, True)
    session.clear()
    return jsonify({
        "ok": True,
        "message": "Your firm deletion request has been received. All data will be permanently deleted within 30 days."
    })



# ════════════════════════════════════════════════════════════════
# CHUNK 5 — SESSION BRIDGE & APP ACCESS
# ════════════════════════════════════════════════════════════════

def firm_login_required(f):
    """Decorator for routes that need firm auth session."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("firm_id"):
            return redirect("/signin")
        if session.get("firm_status") not in ("trial", "active"):
            return redirect("/pending")
        return f(*args, **kwargs)
    return decorated


@auth_bp.route("/api/firm/me")
def firm_me():
    """Current user info for new frontend."""
    if not session.get("firm_id"):
        return jsonify({"authenticated": False}), 401
    return jsonify({
        "authenticated": True,
        "email":         session.get("email"),
        "display_name":  session.get("display_name"),
        "role":          session.get("role"),
        "firm_id":       session.get("firm_id"),
        "firm_name":     session.get("firm_name"),
        "firm_status":   session.get("firm_status"),
    })


@auth_bp.route("/api/firm/logout", methods=["POST"])
def firm_logout():
    """Sign out — clears session server-side (principle 1)."""
    _log_auth_event("logout", session.get("email", ""), True)
    session.clear()
    return jsonify({"ok": True, "redirect": "/signin"})


# ════════════════════════════════════════════════════════════════
# CHUNK 6 — TEAM MANAGEMENT
# ════════════════════════════════════════════════════════════════

@auth_bp.route("/team")
def team_page():
    """Team management page — admin only."""
    if not session.get("firm_id"):
        return redirect("/signin")
    if session.get("role") != "admin":
        return redirect("/app")
    firm = load_firm(session["firm_id"])
    if not firm:
        return redirect("/signin")
    users = []
    for uid, u in firm.get("users", {}).items():
        users.append({
            "user_id":      uid,
            "display_name": u.get("display_name", ""),
            "email":        u.get("email", ""),
            "role":         u.get("role", "member"),
            "status":       u.get("status", "active"),
            "created_at":   u.get("created_at", ""),
        })
    users.sort(key=lambda x: x["created_at"])
    return render_template("auth/team.html",
        firm=firm,
        users=users,
        current_user_id=session.get("user_id"),
    )


@auth_bp.route("/api/team/invite", methods=["POST"])
def team_invite():
    """Admin: invite a new team member."""
    if not session.get("firm_id") or session.get("role") != "admin":
        return jsonify({"error": "Not authorised"}), 403

    data  = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    role  = data.get("role", "member")
    name  = (data.get("display_name") or "").strip()

    if not email:
        return jsonify({"error": "Email required"}), 400
    if role not in ("admin", "member", "knowledge_curator"):
        return jsonify({"error": "Invalid role"}), 400

    firm = load_firm(session["firm_id"])
    if not firm:
        return jsonify({"error": "Firm not found"}), 404

    # Check email domain matches firm domain
    email_domain = email.split("@")[-1].lower()
    if email_domain != firm.get("email_domain", ""):
        return jsonify({"error": f"Email must be from @{firm['email_domain']}"}), 400

    # Check not already a member
    for uid, u in firm.get("users", {}).items():
        if u.get("email", "").lower() == email:
            return jsonify({"error": "This email is already a team member"}), 400

    # Create invite token
    token = create_invite_token(
        firm_id      = firm["firm_id"],
        email        = email,
        display_name = name,
        role         = role,
        invited_by   = session.get("display_name", "your admin"),
    )

    # Send invite email
    ok = send_invite_email(
        to_email     = email,
        display_name = name or email,
        firm_name    = firm["firm_name"],
        invited_by   = session.get("display_name", "your admin"),
        token        = token,
    )

    _log_auth_event("team_invite", email, ok)
    if ok:
        return jsonify({"ok": True, "message": f"Invite sent to {email}"})
    else:
        return jsonify({"error": "Failed to send invite email — check Brevo config"}), 500


@auth_bp.route("/api/team/change-role", methods=["POST"])
def team_change_role():
    """Admin: change a team member's role."""
    if not session.get("firm_id") or session.get("role") != "admin":
        return jsonify({"error": "Not authorised"}), 403

    data    = request.get_json(force=True) or {}
    user_id = data.get("user_id", "")
    role    = data.get("role", "")

    if role not in ("admin", "member", "knowledge_curator"):
        return jsonify({"error": "Invalid role"}), 400

    # Can't demote yourself
    if user_id == session.get("user_id") and role != "admin":
        return jsonify({"error": "You cannot change your own role"}), 400

    firm = load_firm(session["firm_id"])
    if not firm or user_id not in firm.get("users", {}):
        return jsonify({"error": "User not found"}), 404

    firm["users"][user_id]["role"] = role
    save_firm(firm)
    _log_auth_event("role_change", firm["users"][user_id].get("email", ""), True)
    return jsonify({"ok": True})


@auth_bp.route("/api/team/remove", methods=["POST"])
def team_remove():
    """Admin: remove a team member."""
    if not session.get("firm_id") or session.get("role") != "admin":
        return jsonify({"error": "Not authorised"}), 403

    data    = request.get_json(force=True) or {}
    user_id = data.get("user_id", "")

    if user_id == session.get("user_id"):
        return jsonify({"error": "You cannot remove yourself"}), 400

    firm = load_firm(session["firm_id"])
    if not firm or user_id not in firm.get("users", {}):
        return jsonify({"error": "User not found"}), 404

    removed_email = firm["users"][user_id].get("email", "")
    del firm["users"][user_id]
    save_firm(firm)
    _log_auth_event("team_remove", removed_email, True)
    return jsonify({"ok": True})







# ════════════════════════════════════════════════════════════════
# CHUNK 9 — TRIAL MANAGEMENT
# ════════════════════════════════════════════════════════════════

@auth_bp.route("/api/firm/trial-status")
def firm_trial_status():
    """Return trial status for current firm — used by frontend banner."""
    if not session.get("firm_id"):
        return jsonify({"error": "Not authenticated"}), 401
    firm = load_firm(session["firm_id"])
    if not firm:
        return jsonify({"error": "Firm not found"}), 404
    from auth.data import get_trial_status
    trial = get_trial_status(firm)
    return jsonify({
        "firm_name":   firm.get("firm_name",""),
        "status":      trial.get("status",""),
        "days_left":   trial.get("days_left", 0),
        "expired":     trial.get("expired", False),
        "expires_at":  trial.get("expires_at",""),
        "show_banner": trial.get("status") == "trial" and trial.get("days_left", 99) <= 14,
    })


@auth_bp.route("/api/firm/usage")
def firm_usage():
    """Return usage summary for current firm."""
    if not session.get("firm_id"):
        return jsonify({"error": "Not authenticated"}), 401
    firm = load_firm(session["firm_id"])
    if not firm:
        return jsonify({"error": "Firm not found"}), 404
    users = firm.get("users", {})
    return jsonify({
        "firm_id":    firm.get("firm_id"),
        "firm_name":  firm.get("firm_name"),
        "user_count": len(users),
        "users": [
            {
                "display_name": u.get("display_name",""),
                "email":        u.get("email",""),
                "role":         u.get("role","member"),
                "last_signin":  u.get("last_signin",""),
            }
            for uid, u in users.items()
        ]
    })



# ════════════════════════════════════════════════════════════════
# CHUNK 8 — BACK OFFICE (proper platform admin dashboard)
# ════════════════════════════════════════════════════════════════

@auth_bp.route("/platform-admin")
def platform_admin():
    """Proper back office — replaces temporary platform-approve page."""
    import hashlib, os
    url_key   = request.args.get("key", "")
    valid_key = hashlib.sha256(b"MICKEYSETUP2026").hexdigest()
    if not url_key or hashlib.sha256(url_key.encode()).hexdigest() != valid_key:
        return "Not found", 404

    firms = list_all_firms()
    # Enrich with trial status
    from auth.data import get_trial_status
    for f in firms:
        t = get_trial_status(f)
        f["trial_info"] = t
        f["user_count"] = len(f.get("users", {}))

    # Sort: pending first, then trial, then active
    order = {"pending_approval": 0, "trial": 1, "active": 2, "rejected": 3, "suspended": 4}
    firms.sort(key=lambda x: (order.get(x.get("status",""), 9), x.get("firm_name","")))

    total_firms  = len(firms)
    trial_firms  = sum(1 for f in firms if f.get("status") == "trial")
    active_firms = sum(1 for f in firms if f.get("status") == "active")
    pending_firms= sum(1 for f in firms if f.get("status") == "pending_approval")
    total_users  = sum(f["user_count"] for f in firms)

    status_badge = {
        "pending_approval": ("<span style='background:#FEF3C7;color:#92400E;padding:2px 8px;border-radius:12px;font-size:10px;font-weight:700;letter-spacing:.06em;'>PENDING</span>"),
        "trial":    ("<span style='background:#D1FAE5;color:#065F46;padding:2px 8px;border-radius:12px;font-size:10px;font-weight:700;letter-spacing:.06em;'>TRIAL</span>"),
        "active":   ("<span style='background:#DBEAFE;color:#1E40AF;padding:2px 8px;border-radius:12px;font-size:10px;font-weight:700;letter-spacing:.06em;'>ACTIVE</span>"),
        "rejected": ("<span style='background:#FEE2E2;color:#991B1B;padding:2px 8px;border-radius:12px;font-size:10px;font-weight:700;letter-spacing:.06em;'>REJECTED</span>"),
        "suspended":("<span style='background:#F3F4F6;color:#6B7280;padding:2px 8px;border-radius:12px;font-size:10px;font-weight:700;letter-spacing:.06em;'>SUSPENDED</span>"),
    }

    rows = ""
    for f in firms:
        fid   = f.get("firm_id","")
        name  = f.get("firm_name","—")
        domain= f.get("email_domain","—")
        status= f.get("status","—")
        uc    = f["user_count"]
        ti    = f["trial_info"]
        days  = f"D{ti.get('days_left',0)}" if status == "trial" else "—"
        badge = status_badge.get(status, status)
        admin_email = ""
        for uid, u in f.get("users",{}).items():
            if u.get("role") == "admin":
                admin_email = u.get("email","")
                break

        actions = ""
        if status == "pending_approval":
            actions = f'''
                <button onclick="firmAction('{fid}','approve')" style="background:#1B4F40;color:#fff;border:none;padding:5px 12px;border-radius:6px;font-size:11px;font-weight:600;cursor:pointer;margin-right:4px;">Approve</button>
                <button onclick="firmAction('{fid}','reject')" style="background:#fff;color:#C0392B;border:1px solid #E8BCBC;padding:5px 12px;border-radius:6px;font-size:11px;cursor:pointer;">Reject</button>
            '''
        elif status == "trial":
            actions = f'''
                <button onclick="firmAction('{fid}','activate')" style="background:#1B4F40;color:#fff;border:none;padding:5px 12px;border-radius:6px;font-size:11px;font-weight:600;cursor:pointer;margin-right:4px;">Activate</button>
                <button onclick="firmExtend('{fid}')" style="background:#fff;color:#1B4F40;border:1px solid #C4DACE;padding:5px 12px;border-radius:6px;font-size:11px;cursor:pointer;">+30 days</button>
            '''
        elif status == "active":
            actions = f'''
                <button onclick="firmAction('{fid}','suspend')" style="background:#fff;color:#706C65;border:1px solid #D8D4CC;padding:5px 12px;border-radius:6px;font-size:11px;cursor:pointer;">Suspend</button>
            '''
        elif status in ("rejected","suspended"):
            actions = f'''
                <button onclick="firmAction('{fid}','approve')" style="background:#1B4F40;color:#fff;border:none;padding:5px 12px;border-radius:6px;font-size:11px;font-weight:600;cursor:pointer;">Re-approve</button>
            '''

        rows += f'''
        <tr style="border-bottom:1px solid #F0EDE8;">
          <td style="padding:12px 16px;">
            <div style="font-weight:500;color:#1A1916;font-size:13px;">{name}</div>
            <div style="font-size:11px;color:#A8A49D;">@{domain} · {admin_email}</div>
          </td>
          <td style="padding:12px 16px;text-align:center;">{badge}</td>
          <td style="padding:12px 16px;text-align:center;font-size:13px;color:#706C65;">{uc}</td>
          <td style="padding:12px 16px;text-align:center;font-size:12px;color:#706C65;">{days}</td>
          <td style="padding:12px 16px;">{actions}</td>
        </tr>
        '''

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mickey — Platform Admin</title>
<link href="https://fonts.googleapis.com/css2?family=Lora:ital,wght@0,500&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  *{{margin:0;padding:0;box-sizing:border-box;}}
  body{{font-family:'Inter',sans-serif;background:#F5F3EE;color:#1A1916;font-size:13px;}}
  .topbar{{background:#1B4F40;padding:0 32px;height:56px;display:flex;align-items:center;justify-content:space-between;}}
  .topbar-logo{{font-family:'Lora',serif;color:#fff;font-size:18px;}}
  .topbar-sub{{font-size:11px;color:rgba(255,255,255,.5);margin-left:12px;}}
  .topbar-links a{{color:rgba(255,255,255,.6);font-size:12px;text-decoration:none;margin-left:20px;}}
  .topbar-links a:hover{{color:#fff;}}
  .main{{max-width:1100px;margin:0 auto;padding:32px 24px;}}
  .stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:28px;}}
  .stat{{background:#fff;border:1px solid #EAE6DF;border-radius:10px;padding:16px 20px;}}
  .stat-val{{font-family:'Lora',serif;font-size:28px;color:#1B4F40;}}
  .stat-label{{font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#A8A49D;margin-top:2px;}}
  .card{{background:#fff;border:1px solid #EAE6DF;border-radius:12px;overflow:hidden;}}
  .card-header{{padding:16px 20px;border-bottom:1px solid #F0EDE8;display:flex;align-items:center;justify-content:space-between;}}
  .card-title{{font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#A8A49D;}}
  table{{width:100%;border-collapse:collapse;}}
  th{{padding:10px 16px;text-align:left;font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#A8A49D;background:#FAFAF8;border-bottom:1px solid #F0EDE8;}}
  th:nth-child(2),th:nth-child(3),th:nth-child(4){{text-align:center;}}
  #alert{{position:fixed;top:20px;right:20px;padding:12px 20px;border-radius:8px;font-size:13px;font-weight:500;display:none;z-index:100;}}
  .alert-ok{{background:#D1FAE5;border:1px solid #6EE7B7;color:#065F46;}}
  .alert-err{{background:#FEE2E2;border:1px solid #FCA5A5;color:#991B1B;}}
</style>
</head>
<body>
<div class="topbar">
  <div style="display:flex;align-items:center;">
    <div class="topbar-logo">Mickey</div>
    <span class="topbar-sub">Platform Admin</span>
  </div>
  <div class="topbar-links">
    <a href="/platform-setup?key={url_key}">Setup</a>
    <a href="/platform-admin?key={url_key}">↺ Refresh</a>
  </div>
</div>

<div class="main">
  <div class="stats">
    <div class="stat"><div class="stat-val">{total_firms}</div><div class="stat-label">Total firms</div></div>
    <div class="stat"><div class="stat-val">{pending_firms}</div><div class="stat-label">Pending</div></div>
    <div class="stat"><div class="stat-val">{trial_firms}</div><div class="stat-label">On trial</div></div>
    <div class="stat"><div class="stat-val">{active_firms}</div><div class="stat-label">Active</div></div>
    <div class="stat"><div class="stat-val">{total_users}</div><div class="stat-label">Total users</div></div>
  </div>

  <div class="card">
    <div class="card-header">
      <span class="card-title">Firms</span>
      <span style="font-size:12px;color:#A8A49D;">{total_firms} registered</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Firm</th>
          <th>Status</th>
          <th>Users</th>
          <th>Trial</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</div>

<div id="alert"></div>

<script>
const KEY = "{url_key}";

function showAlert(msg, ok=true) {{
  const el = document.getElementById("alert");
  el.textContent = msg;
  el.className = ok ? "alert-ok" : "alert-err";
  el.style.display = "block";
  setTimeout(() => el.style.display = "none", 3000);
}}

async function firmAction(firmId, action) {{
  if (!confirm(`${{action}} this firm?`)) return;
  const r = await fetch(`/api/platform/firm-action?key=${{KEY}}`, {{
    method: "POST",
    headers: {{"Content-Type":"application/json"}},
    body: JSON.stringify({{firm_id: firmId, action}})
  }});
  const d = await r.json();
  if (d.ok) {{ showAlert(d.message || "Done"); setTimeout(() => location.reload(), 1000); }}
  else showAlert(d.error || "Failed", false);
}}

async function firmExtend(firmId) {{
  const r = await fetch(`/api/platform/firm-extend?key=${{KEY}}`, {{
    method: "POST",
    headers: {{"Content-Type":"application/json"}},
    body: JSON.stringify({{firm_id: firmId, days: 30}})
  }});
  const d = await r.json();
  if (d.ok) {{ showAlert("Trial extended by 30 days"); setTimeout(() => location.reload(), 1000); }}
  else showAlert(d.error || "Failed", false);
}}
</script>
</body>
</html>"""


@auth_bp.route("/api/platform/firm-action")
def platform_firm_action():
    """Back office: approve/reject/activate/suspend a firm."""
    import hashlib
    url_key   = request.args.get("key", "")
    valid_key = hashlib.sha256(b"MICKEYSETUP2026").hexdigest()
    if not url_key or hashlib.sha256(url_key.encode()).hexdigest() != valid_key:
        return jsonify({"error": "Not authorised"}), 403

    data   = request.get_json(force=True) or {}
    firm_id= data.get("firm_id","")
    action = data.get("action","")

    firm = load_firm(firm_id)
    if not firm:
        return jsonify({"error": "Firm not found"}), 404

    status_map = {
        "approve":  "trial",
        "activate": "active",
        "reject":   "rejected",
        "suspend":  "suspended",
    }
    if action not in status_map:
        return jsonify({"error": "Invalid action"}), 400

    new_status = status_map[action]
    firm["status"] = new_status
    if action == "approve":
        import datetime as _dt
        firm["approved_at"] = _dt.datetime.utcnow().isoformat()
        firm.setdefault("trial_days", 30)
    save_firm(firm)

    # Send approval email if approving
    if action == "approve":
        admin_email = ""
        admin_name  = ""
        for uid, u in firm.get("users", {}).items():
            if u.get("role") == "admin":
                admin_email = u.get("email","")
                admin_name  = u.get("display_name","")
                break
        if admin_email:
            send_approval_email(admin_email, admin_name, firm["firm_name"])

    return jsonify({"ok": True, "message": f"Firm {action}d successfully"})


@auth_bp.route("/api/platform/firm-extend")
def platform_firm_extend():
    """Back office: extend a firm's trial."""
    import hashlib
    url_key   = request.args.get("key", "")
    valid_key = hashlib.sha256(b"MICKEYSETUP2026").hexdigest()
    if not url_key or hashlib.sha256(url_key.encode()).hexdigest() != valid_key:
        return jsonify({"error": "Not authorised"}), 403

    data    = request.get_json(force=True) or {}
    firm_id = data.get("firm_id","")
    days    = int(data.get("days", 30))

    from auth.data import extend_trial
    ok = extend_trial(firm_id, days)
    if ok:
        return jsonify({"ok": True})
    return jsonify({"error": "Firm not found"}), 404



# ════════════════════════════════════════════════════════════════
# PLATFORM CONFIG PAGE  (one-time setup, browser-based)
# ════════════════════════════════════════════════════════════════

@auth_bp.route("/platform-setup", methods=["GET", "POST"])
def platform_setup():
    import os
    from pathlib import Path

    # Protected by URL key (temporary) OR environment variable if set
    import hashlib
    url_key  = request.args.get("key", "") or request.form.get("setup_key", "")
    env_pw   = os.environ.get("MICKEY_ADMIN_PASSWORD", "")
    valid_key = hashlib.sha256(b"MICKEYSETUP2026").hexdigest()

    authed = (
        (url_key and hashlib.sha256(url_key.encode()).hexdigest() == valid_key) or
        (env_pw and request.form.get("admin_password", "") == env_pw)
    )

    # Pass key through form posts
    setup_key = url_key or ""

    error = success = test_result = ""

    base        = Path(os.environ.get("MICKEY_DATA", "/opt/mickey"))
    config_path = base / "config.env"
    existing    = {}
    if config_path.exists():
        for line in config_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                existing[k.strip()] = v.strip()

    if request.method == "POST":
        if not authed:
            error = "Incorrect password or invalid setup key."
        else:
            existing["BREVO_API_KEY"]      = request.form.get("brevo_api_key", "").strip()
            existing["MICKEY_OWNER_EMAIL"] = request.form.get("owner_email", "").strip()
            existing["MICKEY_URL"]         = request.form.get("mickey_url", "https://askmickey.io").strip()
            existing["MICKEY_FROM_EMAIL"]  = request.form.get("from_email", "noreply@askmickey.io").strip()
            existing["MICKEY_FROM_NAME"]   = "Mickey Legal"
            existing["MICKEY_HTTPS"]       = "true"

            lines = [f"{k}={v}" for k, v in existing.items() if v]
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            config_path.chmod(0o600)

            for k, v in existing.items():
                if v:
                    os.environ[k] = v

            # Hot-reload email module constants
            try:
                import auth.email as em
                em.BREVO_API_KEY = existing.get("BREVO_API_KEY", "")
                em.OWNER_EMAIL   = existing.get("MICKEY_OWNER_EMAIL", "")
                em.PLATFORM_URL  = existing.get("MICKEY_URL", "https://askmickey.io")
                em.FROM_EMAIL    = existing.get("MICKEY_FROM_EMAIL", "noreply@askmickey.io")
            except Exception:
                pass

            if request.form.get("send_test"):
                test_to = request.form.get("test_email", "").strip()
                if test_to:
                    from auth.email import _send, _base_template, _h1, _p
                    ok = _send(test_to, test_to, "Mickey — email test",
                        _base_template(
                            _h1("Email is working") +
                            _p("This is a test from your Mickey platform. Brevo is configured correctly.")
                        ))
                    test_result = "Email sent successfully." if ok else "Send failed — check your Brevo API key."
            else:
                success = "Configuration saved."

    brevo_set = bool(existing.get("BREVO_API_KEY"))

    alert = ""
    if error:
        alert = f'''<div style="background:#FAEAE8;border:1px solid #E8BCBC;color:#C0392B;padding:12px 14px;border-radius:8px;margin-bottom:20px;font-size:13px;">{error}</div>'''
    elif success:
        alert = f'''<div style="background:#EAF1ED;border:1px solid #C4DACE;color:#1B4F40;padding:12px 14px;border-radius:8px;margin-bottom:20px;font-size:13px;">{success}</div>'''
    elif test_result:
        col = "#EAF1ED" if "successfully" in test_result else "#FAEAE8"
        brd = "#C4DACE" if "successfully" in test_result else "#E8BCBC"
        txt = "#1B4F40" if "successfully" in test_result else "#C0392B"
        alert = f'''<div style="background:{col};border:1px solid {brd};color:{txt};padding:12px 14px;border-radius:8px;margin-bottom:20px;font-size:13px;">{test_result}</div>'''

    brevo_badge = ('<span style="color:#1B4F40;font-size:11px;font-weight:600;">&#10003; Configured</span>'
                   if brevo_set else
                   '<span style="color:#C8A030;font-size:11px;font-weight:600;">&#9675; Not set</span>')

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mickey — Platform Setup</title>
<link href="https://fonts.googleapis.com/css2?family=Lora:ital,wght@0,500&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  *{{margin:0;padding:0;box-sizing:border-box;}}
  body{{font-family:'Inter',sans-serif;background:#1B4F40;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:40px 20px;}}
  .card{{background:#fff;border-radius:16px;padding:44px 48px;width:100%;max-width:500px;}}
  h1{{font-family:'Lora',serif;font-size:22px;font-weight:500;color:#1B4F40;margin-bottom:4px;}}
  .sub{{font-size:11px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:#A8A49D;margin-bottom:32px;}}
  label{{display:block;font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#A8A49D;margin-bottom:6px;}}
  input{{width:100%;padding:9px 12px;border:1px solid #D8D4CC;border-radius:8px;font-family:'Inter',sans-serif;font-size:13px;color:#1A1916;background:#fff;outline:none;margin-bottom:16px;}}
  input:focus{{border-color:#1B4F40;}}
  .btn{{width:100%;padding:10px;background:#1B4F40;color:#fff;border:none;border-radius:8px;font-family:'Inter',sans-serif;font-size:13px;font-weight:600;cursor:pointer;margin-top:4px;}}
  .btn:hover{{background:#153D31;}}
  .btn-ghost{{background:transparent;color:#1B4F40;border:1.5px solid #C4DACE;margin-top:8px;}}
  .divider{{height:1px;background:#EAE6DF;margin:24px 0;}}
  .badge-row{{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;padding:10px 14px;background:#F5F3EE;border-radius:8px;font-size:13px;color:#706C65;}}
</style>
</head>
<body>
<div class="card">
  <h1>Mickey</h1>
  <div class="sub">Platform Setup</div>

  {alert}

  <div class="badge-row">
    Brevo email &nbsp; {brevo_badge}
  </div>

  <form method="POST" action="/platform-setup?key={setup_key}">
    <label>Admin password (or use the URL key)</label>
    <input type="password" name="admin_password" placeholder="Leave blank if using URL key">

    <label>Brevo API key</label>
    <input type="password" name="brevo_api_key" value="{existing.get("BREVO_API_KEY","")}" placeholder="xkeysib-...">

    <label>Your email (receives new registration alerts)</label>
    <input type="email" name="owner_email" value="{existing.get("MICKEY_OWNER_EMAIL","")}" placeholder="you@yourfirm.be">

    <label>Platform URL</label>
    <input type="text" name="mickey_url" value="{existing.get("MICKEY_URL","https://askmickey.io")}">

    <label>From email address</label>
    <input type="text" name="from_email" value="{existing.get("MICKEY_FROM_EMAIL","noreply@askmickey.io")}">

    <button type="submit" class="btn">Save configuration</button>

    <div class="divider"></div>

    <label>Send test email to</label>
    <input type="email" name="test_email" placeholder="your@email.com">
    <button type="submit" name="send_test" value="1" class="btn btn-ghost">Send test email</button>
  </form>
</div>
</body>
</html>"""




@auth_bp.route("/platform-approve", methods=["GET", "POST"])
def platform_approve():
    """Temporary firm approval page — until back office is built."""
    import os, hashlib
    from pathlib import Path

    url_key   = request.args.get("key", "")
    valid_key = hashlib.sha256(b"MICKEYSETUP2026").hexdigest()
    if not url_key or hashlib.sha256(url_key.encode()).hexdigest() != valid_key:
        return "Not found", 404

    message = ""
    firms_list = list_all_firms()

    if request.method == "POST":
        firm_id = request.form.get("firm_id", "")
        action  = request.form.get("action", "")
        if firm_id and action in ("approve", "reject"):
            firm = load_firm(firm_id)
            if firm:
                if action == "approve":
                    from auth.data import load_firm as _lf
                    firm["status"]      = "trial"
                    firm["approved_at"] = datetime.datetime.utcnow().isoformat()
                    from auth.data import _atomic_write, _firm_path
                    _atomic_write(_firm_path(firm_id), firm)
                    # Send approval email to admin user
                    for uid, u in firm.get("users", {}).items():
                        if u.get("role") == "admin":
                            send_approval_email(u["email"], u["display_name"], firm["firm_name"])
                    message = f"✓ {firm['firm_name']} approved — approval email sent."
                else:
                    firm["status"] = "rejected"
                    from auth.data import _atomic_write, _firm_path
                    _atomic_write(_firm_path(firm_id), firm)
                    message = f"✗ {firm['firm_name']} rejected."
            firms_list = list_all_firms()

    rows = ""
    for f in firms_list:
        status_colour = {
            "pending_approval": "#C8A030",
            "trial":            "#1B4F40",
            "active":           "#1B4F40",
            "rejected":         "#C0392B",
            "suspended":        "#C0392B",
        }.get(f["status"], "#706C65")

        approve_btn = ""
        if f["status"] == "pending_approval":
            approve_btn = f"""
            <form method="POST" style="display:inline;">
              <input type="hidden" name="firm_id" value="{f['firm_id']}">
              <button name="action" value="approve"
                style="background:#1B4F40;color:#fff;border:none;padding:6px 14px;border-radius:6px;font-size:12px;cursor:pointer;font-family:Inter,sans-serif;font-weight:600;margin-right:6px;">
                Approve
              </button>
              <button name="action" value="reject"
                style="background:#FAEAE8;color:#C0392B;border:1px solid #E8BCBC;padding:6px 14px;border-radius:6px;font-size:12px;cursor:pointer;font-family:Inter,sans-serif;">
                Reject
              </button>
            </form>"""

        rows += f"""<tr>
          <td style="padding:12px 16px;border-bottom:1px solid #EAE6DF;">{f['firm_name']}</td>
          <td style="padding:12px 16px;border-bottom:1px solid #EAE6DF;font-size:12px;color:#706C65;">{f['email_domain']}</td>
          <td style="padding:12px 16px;border-bottom:1px solid #EAE6DF;">
            <span style="color:{status_colour};font-size:12px;font-weight:600;">{f['status'].replace('_',' ').title()}</span>
          </td>
          <td style="padding:12px 16px;border-bottom:1px solid #EAE6DF;">{approve_btn}</td>
        </tr>"""

    msg_html = ""
    if message:
        col = "#EAF1ED" if "✓" in message else "#FAEAE8"
        brd = "#C4DACE" if "✓" in message else "#E8BCBC"
        txt = "#1B4F40" if "✓" in message else "#C0392B"
        msg_html = f'''<div style="background:{col};border:1px solid {brd};color:{txt};padding:12px 16px;border-radius:8px;margin-bottom:24px;font-size:13px;font-weight:500;">{message}</div>'''

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mickey — Firm Approvals</title>
<link href="https://fonts.googleapis.com/css2?family=Lora:ital,wght@0,500&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  *{{margin:0;padding:0;box-sizing:border-box;}}
  body{{font-family:'Inter',sans-serif;background:#1B4F40;min-height:100vh;padding:40px 20px;}}
  .card{{background:#fff;border-radius:16px;padding:36px 40px;max-width:760px;margin:0 auto;}}
  h1{{font-family:'Lora',serif;font-size:22px;font-weight:500;color:#1B4F40;margin-bottom:4px;}}
  .sub{{font-size:11px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:#A8A49D;margin-bottom:28px;}}
  table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #EAE6DF;border-radius:10px;overflow:hidden;}}
  th{{background:#F5F3EE;padding:10px 16px;text-align:left;font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#A8A49D;border-bottom:1px solid #EAE6DF;}}
  .empty{{padding:32px;text-align:center;color:#A8A49D;font-size:13px;}}
</style>
</head>
<body>
<div class="card">
  <h1>Mickey</h1>
  <div class="sub">Firm Approvals</div>
  {msg_html}
  <table>
    <thead><tr>
      <th>Firm</th><th>Domain</th><th>Status</th><th>Action</th>
    </tr></thead>
    <tbody>
      {rows if rows else '<tr><td colspan="4" class="empty">No firms registered yet.</td></tr>'}
    </tbody>
  </table>
  <p style="margin-top:16px;font-size:11px;color:#A8A49D;">
    <a href="/platform-setup?key=MICKEYSETUP2026" style="color:#1B4F40;">&#8592; Back to setup</a>
  </p>
</div>
</body>
</html>"""





@auth_bp.route("/platform-bootstrap")
def platform_bootstrap():
    """One-time route to install SSH public key on server."""
    import os, hashlib
    from pathlib import Path

    url_key   = request.args.get("key", "")
    valid_key = hashlib.sha256(b"MICKEYSETUP2026").hexdigest()
    if not url_key or hashlib.sha256(url_key.encode()).hexdigest() != valid_key:
        return "Not found", 404

    pub_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOKXcY6hJ+f1McWnzAWUMsP+fRmgI9qjDku5mS5BmidG mathiasmu@LAPTOP-AH952I21"

    try:
        ssh_dir        = Path("/root/.ssh")
        auth_keys_file = ssh_dir / "authorized_keys"
        ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

        # Only add if not already present
        existing = auth_keys_file.read_text(encoding="utf-8") if auth_keys_file.exists() else ""
        if pub_key not in existing:
            with open(auth_keys_file, "a", encoding="utf-8") as f:
                f.write("\n" + pub_key + "\n")
            auth_keys_file.chmod(0o600)
            result = "SSH key installed successfully. GitHub Actions can now connect."
        else:
            result = "SSH key was already installed."

        return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
<style>body{{font-family:Inter,sans-serif;background:#1B4F40;min-height:100vh;display:flex;align-items:center;justify-content:center;}}
.card{{background:#fff;border-radius:16px;padding:40px 48px;max-width:480px;width:100%;}}
h2{{color:#1B4F40;margin-bottom:12px;}}p{{color:#706C65;font-size:14px;line-height:1.6;margin-bottom:20px;}}
.btn{{display:inline-block;background:#1B4F40;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none;font-size:13px;font-weight:600;}}</style>
</head><body><div class="card">
<h2>&#10003; {result}</h2>
<p>You can now push to GitHub and the Deploy Mickey workflow will connect to your server automatically.</p>
<p>After your next push, check GitHub Actions to confirm the workflow succeeds.</p>
<a href="/platform-approve?key=MICKEYSETUP2026" class="btn">Go to firm approvals</a>
</div></body></html>"""

    except Exception as e:
        return f"Error: {e}", 500





@auth_bp.route("/platform-debug-reset")
def debug_reset():
    """Temporary: debug password reset flow."""
    import os, hashlib
    from pathlib import Path

    url_key   = request.args.get("key", "")
    valid_key = hashlib.sha256(b"MICKEYSETUP2026").hexdigest()
    if not url_key or hashlib.sha256(url_key.encode()).hexdigest() != valid_key:
        return "Not found", 404

    email = request.args.get("email", "").strip().lower()
    if not email:
        return "Add ?email=your@email.com to the URL", 400

    steps = []

    # Step 1: check env vars
    steps.append(f"BREVO_API_KEY set: {bool(os.environ.get('BREVO_API_KEY'))}")
    steps.append(f"MICKEY_URL: {os.environ.get('MICKEY_URL','not set')}")

    # Step 2: find user
    firm, user = find_user_by_email(email)
    steps.append(f"Firm found: {bool(firm)} — {firm.get('firm_name','') if firm else 'none'}")
    steps.append(f"User found: {bool(user)} — {user.get('display_name','') if user else 'none'}")
    if user:
        steps.append(f"Email verified: {user.get('email_verified')}")
        steps.append(f"Firm status: {firm.get('status') if firm else 'n/a'}")

    # Step 3: try sending
    if firm and user:
        token = create_password_reset_token(email, firm["firm_id"], user["user_id"])
        steps.append(f"Token created: {token[:12]}...")
        ok = send_password_reset_email(email, user["display_name"], token)
        steps.append(f"Email sent: {ok}")
    else:
        steps.append("Skipping email — user not found")

    rows = "".join(f"<tr><td style='padding:8px 12px;border-bottom:1px solid #eee;font-family:monospace;font-size:13px;'>{s}</td></tr>" for s in steps)
    return f"""<html><body style="font-family:sans-serif;padding:40px;background:#F5F3EE;">
    <h2 style="color:#1B4F40;">Password Reset Debug</h2>
    <p style="color:#706C65;margin-bottom:20px;">Email: {email}</p>
    <table style="background:#fff;border-radius:8px;border:1px solid #ddd;border-collapse:collapse;width:100%;max-width:600px;">{rows}</table>
    </body></html>"""





@auth_bp.route("/platform-reset-pw", methods=["GET", "POST"])
def platform_reset_pw():
    """Direct password reset — no email needed. Admin only."""
    import os, hashlib
    from pathlib import Path

    url_key   = request.args.get("key", "")
    valid_key = hashlib.sha256(b"MICKEYSETUP2026").hexdigest()
    if not url_key or hashlib.sha256(url_key.encode()).hexdigest() != valid_key:
        return "Not found", 404

    message = ""
    if request.method == "POST":
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")

        if password != confirm:
            message = "error:Passwords do not match."
        elif len(password) < 8:
            message = "error:Password must be at least 8 characters."
        else:
            firm, user = find_user_by_email(email)
            if not firm or not user:
                message = "error:Email not found."
            else:
                hashed = hash_pw(password)
                update_user_field(firm, user["user_id"], hashed=hashed)
                message = "ok:Password updated. You can now sign in."

    col = "#EAF1ED" if message.startswith("ok:") else "#FAEAE8"
    brd = "#C4DACE" if message.startswith("ok:") else "#E8BCBC"
    txt = "#1B4F40" if message.startswith("ok:") else "#C0392B"
    msg_html = f'''<div style="background:{col};border:1px solid {brd};color:{txt};padding:12px 14px;border-radius:8px;margin-bottom:20px;font-size:13px;font-weight:500;">{message.split(":",1)[1]}</div>''' if message else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mickey — Reset Password</title>
<link href="https://fonts.googleapis.com/css2?family=Lora:ital,wght@0,500&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  *{{margin:0;padding:0;box-sizing:border-box;}}
  body{{font-family:'Inter',sans-serif;background:#1B4F40;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:40px 20px;}}
  .card{{background:#fff;border-radius:16px;padding:44px 48px;width:100%;max-width:440px;}}
  h1{{font-family:'Lora',serif;font-size:22px;font-weight:500;color:#1B4F40;margin-bottom:4px;}}
  .sub{{font-size:11px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:#A8A49D;margin-bottom:28px;}}
  label{{display:block;font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#A8A49D;margin-bottom:6px;}}
  input{{width:100%;padding:9px 12px;border:1px solid #D8D4CC;border-radius:8px;font-family:'Inter',sans-serif;font-size:13px;color:#1A1916;outline:none;margin-bottom:16px;}}
  input:focus{{border-color:#1B4F40;}}
  .btn{{width:100%;padding:10px;background:#1B4F40;color:#fff;border:none;border-radius:8px;font-family:'Inter',sans-serif;font-size:13px;font-weight:600;cursor:pointer;margin-top:4px;}}
  .btn:hover{{background:#153D31;}}
  a{{color:#1B4F40;font-size:12px;}}
</style>
</head>
<body>
<div class="card">
  <h1>Mickey</h1>
  <div class="sub">Direct Password Reset</div>
  {msg_html}
  <form method="POST" action="/platform-reset-pw?key={url_key}">
    <label>Email address</label>
    <input type="email" name="email" required>
    <label>New password</label>
    <input type="password" name="password" required>
    <label>Confirm password</label>
    <input type="password" name="confirm" required>
    <button type="submit" class="btn">Set new password</button>
  </form>
  <p style="margin-top:16px;"><a href="/signin">Go to sign in</a></p>
</div>
</body>
</html>"""



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

