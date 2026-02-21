"""
auth/email.py
─────────────
Mickey — Transactional Email via Brevo  (Chunk 1)

Requires environment variable:
  BREVO_API_KEY=xkeysib-...

All email is sent via Brevo's v3 REST API (no SDK needed —
avoids an extra dependency).

If BREVO_API_KEY is not set, emails are logged to
/opt/mickey/auth/email_log.txt instead of sending.
This makes local development work without a Brevo account.

Templates:
  1. Email verification          → send_verification_email()
  2. Approval notification       → send_approval_email()
  3. Rejection notification      → send_rejection_email()
  4. Team invite                 → send_invite_email()
  5. Platform owner notification → send_new_firm_notification()
"""

import os
import json
import datetime
import urllib.request
import urllib.error
from pathlib import Path

# ── Config ────────────────────────────────────────────────────
BREVO_API_KEY   = os.environ.get("BREVO_API_KEY", "")
BREVO_SEND_URL  = "https://api.brevo.com/v3/smtp/email"

# Load config.env if env vars not set
from pathlib import Path as _Path
for _cp in [_Path("/opt/mickey/config.env"), _Path(__file__).parent.parent / "config.env"]:
    if _cp.exists():
        for _line in _cp.read_text(encoding="utf-8").splitlines():
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _, _v = _line.partition("=")
                os.environ.setdefault(_k.strip(), _v.strip())
        break

BREVO_API_KEY   = os.environ.get("BREVO_API_KEY", "")

FROM_EMAIL      = os.environ.get("MICKEY_FROM_EMAIL", "mathias.baert@lex-it.be")
FROM_NAME       = os.environ.get("MICKEY_FROM_NAME",  "Mickey Legal")
PLATFORM_URL    = os.environ.get("MICKEY_URL",        "https://askmickey.io")

# Platform owner — receives new firm notifications
OWNER_EMAIL     = os.environ.get("MICKEY_OWNER_EMAIL", "")

# Email log for dev / fallback
_BASE           = Path(os.environ.get("MICKEY_DATA", "/opt/mickey"))
EMAIL_LOG       = _BASE / "auth" / "email_log.txt"


# ════════════════════════════════════════════════════════════════
# CORE SEND FUNCTION
# ════════════════════════════════════════════════════════════════

def _send(to_email: str, to_name: str, subject: str, html: str) -> bool:
    """
    Send one email via Brevo API.
    Falls back to file log if BREVO_API_KEY is not configured.
    Returns True on success, False on failure.
    """
    if not BREVO_API_KEY:
        _log_email(to_email, subject, html)
        return True

    payload = {
        "sender":     {"name": FROM_NAME, "email": FROM_EMAIL},
        "to":         [{"email": to_email, "name": to_name}],
        "subject":    subject,
        "htmlContent": html,
    }

    data = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        BREVO_SEND_URL,
        data=data,
        headers={
            "api-key":      BREVO_API_KEY,
            "Content-Type": "application/json",
            "Accept":       "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 201)
    except urllib.error.HTTPError as e:
        _log_email(to_email, subject, html, error=str(e))
        return False
    except Exception as e:
        _log_email(to_email, subject, html, error=str(e))
        return False


def _log_email(to_email: str, subject: str, html: str, error: str = "") -> None:
    """Write email to log file (dev mode or on send failure)."""
    EMAIL_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(EMAIL_LOG, "a", encoding="utf-8") as f:
        f.write(f"\n{'─'*60}\n")
        f.write(f"[{datetime.datetime.utcnow().isoformat()}]\n")
        if error:
            f.write(f"SEND FAILED: {error}\n")
        else:
            f.write("(BREVO_API_KEY not set — logged only)\n")
        f.write(f"TO:      {to_email}\n")
        f.write(f"SUBJECT: {subject}\n")
        f.write(f"BODY:\n{html}\n")


# ════════════════════════════════════════════════════════════════
# SHARED STYLE
# ════════════════════════════════════════════════════════════════

def _base_template(content: str) -> str:
    """Wrap content in Mickey-branded email shell."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Mickey Legal</title>
</head>
<body style="margin:0;padding:0;background:#F5F3EE;font-family:'Helvetica Neue',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#F5F3EE;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="560" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;overflow:hidden;border:1px solid #E8E4DC;">

          <!-- Header -->
          <tr>
            <td style="background:#1B4F40;padding:28px 40px;">
              <p style="margin:0;font-family:Georgia,'Times New Roman',serif;font-size:22px;font-weight:700;color:#F5F3EE;letter-spacing:-0.3px;">
                Mickey
              </p>
              <p style="margin:4px 0 0;font-size:11px;color:#A8C4BD;letter-spacing:0.5px;text-transform:uppercase;">
                Legal Intelligence
              </p>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:36px 40px 32px;">
              {content}
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding:20px 40px 28px;border-top:1px solid #E8E4DC;">
              <p style="margin:0;font-size:11px;color:#9A9690;line-height:1.6;">
                Mickey Legal &mdash; <a href="{PLATFORM_URL}" style="color:#1B4F40;text-decoration:none;">{PLATFORM_URL}</a><br>
                This is an automated message. Please do not reply to this email.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def _btn(url: str, label: str) -> str:
    return f"""<p style="margin:28px 0 0;">
      <a href="{url}" style="display:inline-block;background:#1B4F40;color:#F5F3EE;
         text-decoration:none;padding:12px 28px;border-radius:6px;
         font-size:14px;font-weight:600;font-family:'Helvetica Neue',Arial,sans-serif;">
        {label}
      </a>
    </p>
    <p style="margin:12px 0 0;font-size:12px;color:#9A9690;">
      Or copy this link: <span style="color:#1B4F40;word-break:break-all;">{url}</span>
    </p>"""


def _h1(text: str) -> str:
    return f'<h1 style="margin:0 0 16px;font-family:Georgia,serif;font-size:24px;font-weight:700;color:#1B4F40;">{text}</h1>'


def _p(text: str) -> str:
    return f'<p style="margin:0 0 14px;font-size:15px;line-height:1.6;color:#2C2C2C;">{text}</p>'


# ════════════════════════════════════════════════════════════════
# EMAIL TEMPLATES
# ════════════════════════════════════════════════════════════════

def send_verification_email(
    to_email: str,
    display_name: str,
    firm_name: str,
    token: str,
) -> bool:
    """
    Sent immediately after registration.
    User must click to verify their email before the firm
    enters the approval queue.
    """
    verify_url = f"{PLATFORM_URL}/verify-email/{token}"

    content = (
        _h1("Please verify your email") +
        _p(f"Hi {display_name},") +
        _p(f"Thank you for registering <strong>{firm_name}</strong> on Mickey. "
           f"Please verify your email address to continue.") +
        _btn(verify_url, "Verify my email address") +
        _p("This link expires in 24 hours. If you didn't create this account, "
           "you can safely ignore this email.")
    )
    return _send(to_email, display_name, "Please verify your email — Mickey", _base_template(content))


def send_approval_email(
    to_email: str,
    display_name: str,
    firm_name: str,
) -> bool:
    """
    Sent to the firm admin when platform owner approves their registration.
    """
    login_url = f"{PLATFORM_URL}/signin"

    content = (
        _h1("Your account has been approved") +
        _p(f"Hi {display_name},") +
        _p(f"Great news — <strong>{firm_name}</strong>'s Mickey account has been approved "
           f"and is ready to use.") +
        _p("You can now sign in and start inviting your team.") +
        _btn(login_url, "Sign in to Mickey") +
        _p("If you have any questions, reply to this email or contact us at "
           "<a href='mailto:hello@askmickey.io' style='color:#1B4F40;'>hello@askmickey.io</a>.")
    )
    return _send(to_email, display_name, f"{firm_name} — your Mickey account is approved", _base_template(content))


def send_rejection_email(
    to_email: str,
    display_name: str,
    firm_name: str,
    reason: str = "",
) -> bool:
    """
    Sent if platform owner rejects the registration.
    """
    reason_block = f"<p style='margin:0 0 14px;font-size:15px;line-height:1.6;color:#2C2C2C;'><strong>Reason:</strong> {reason}</p>" if reason else ""

    content = (
        _h1("Registration not approved") +
        _p(f"Hi {display_name},") +
        _p(f"Thank you for your interest in Mickey. Unfortunately we are unable to "
           f"approve the registration for <strong>{firm_name}</strong> at this time.") +
        reason_block +
        _p("If you believe this is a mistake or would like to discuss further, please "
           "contact us at <a href='mailto:hello@askmickey.io' style='color:#1B4F40;'>hello@askmickey.io</a>.")
    )
    return _send(to_email, display_name, "Your Mickey registration — update", _base_template(content))


def send_invite_email(
    to_email: str,
    firm_name: str,
    invited_by_name: str,
    role: str,
    token: str,
) -> bool:
    """
    Sent to a team member invited by the firm admin.
    They click the link to set their password and accept T&Cs.
    """
    invite_url = f"{PLATFORM_URL}/invite/{token}"

    role_labels = {
        "admin":               "Admin",
        "member":              "Member",
        "knowledge_curator":   "Knowledge Curator",
    }
    role_label = role_labels.get(role, role.capitalize())

    content = (
        _h1(f"You've been invited to {firm_name} on Mickey") +
        _p(f"{invited_by_name} has invited you to join <strong>{firm_name}</strong> "
           f"on Mickey Legal as <strong>{role_label}</strong>.") +
        _p("Click the button below to set up your account. "
           "The invitation expires in 7 days.") +
        _btn(invite_url, "Accept invitation") +
        _p("If you weren't expecting this invitation, you can safely ignore this email.")
    )
    return _send(to_email, to_email, f"{invited_by_name} invited you to Mickey", _base_template(content))


def send_new_firm_notification(
    firm_name: str,
    firm_id: str,
    admin_email: str,
    admin_name: str,
    email_domain: str,
    country: str,
    vat: str,
) -> bool:
    """
    Sent to platform owner (MICKEY_OWNER_EMAIL) when a new firm
    registers and needs approval.
    """
    if not OWNER_EMAIL:
        return False   # owner email not configured — skip silently

    backoffice_url = f"{PLATFORM_URL}/backoffice"

    content = (
        _h1("New firm registration") +
        _p(f"<strong>{firm_name}</strong> has registered and is awaiting your approval.") +
        f"""<table style="border-collapse:collapse;width:100%;margin:16px 0;">
          <tr><td style="padding:8px 0;font-size:13px;color:#666;width:140px;">Firm</td>
              <td style="padding:8px 0;font-size:14px;color:#2C2C2C;"><strong>{firm_name}</strong></td></tr>
          <tr><td style="padding:8px 0;font-size:13px;color:#666;">Admin</td>
              <td style="padding:8px 0;font-size:14px;color:#2C2C2C;">{admin_name} &lt;{admin_email}&gt;</td></tr>
          <tr><td style="padding:8px 0;font-size:13px;color:#666;">Domain</td>
              <td style="padding:8px 0;font-size:14px;color:#2C2C2C;">@{email_domain}</td></tr>
          <tr><td style="padding:8px 0;font-size:13px;color:#666;">Country</td>
              <td style="padding:8px 0;font-size:14px;color:#2C2C2C;">{country}</td></tr>
          <tr><td style="padding:8px 0;font-size:13px;color:#666;">VAT</td>
              <td style="padding:8px 0;font-size:14px;color:#2C2C2C;">{vat or '—'}</td></tr>
          <tr><td style="padding:8px 0;font-size:13px;color:#666;">Firm ID</td>
              <td style="padding:8px 0;font-size:13px;color:#9A9690;font-family:monospace;">{firm_id}</td></tr>
        </table>""" +
        _btn(backoffice_url, "Review in back office")
    )
    return _send(OWNER_EMAIL, "Mickey Admin", f"New registration: {firm_name}", _base_template(content))

def send_password_reset_email(
    to_email: str,
    display_name: str,
    token: str,
) -> bool:
    """
    Sent when a user requests a password reset.
    Token expires in 1 hour (single-use — principle 1).
    """
    reset_url = f"{PLATFORM_URL}/reset-password/{token}"

    content = (
        _h1("Reset your password") +
        _p(f"Hi {display_name},") +
        _p("We received a request to reset your Mickey password. "
           "Click the button below to choose a new one.") +
        _btn(reset_url, "Reset my password") +
        _p("<strong>This link expires in 1 hour</strong> and can only be used once. "
           "If you did not request a password reset, you can safely ignore this email — "
           "your password has not been changed.")
    )
    return _send(to_email, display_name, "Reset your Mickey password", _base_template(content))

def send_invite_email(to_email: str, display_name: str, firm_name: str,
                      invited_by: str, token: str) -> bool:
    """Send team invite email."""
    invite_url = f"{PLATFORM_URL}/invite/{token}"
    body = _base_template(
        _h1(f"You\'re invited to join {firm_name} on Mickey") +
        _p(f"Hi {display_name or to_email},") +
        _p(f"{invited_by} has invited you to join <strong>{firm_name}</strong> on Mickey Legal Intelligence.") +
        _btn("Accept invitation", invite_url) +
        _p(f"This invitation expires in 7 days.") +
        _p("If you weren\'t expecting this invitation, you can safely ignore this email.")
    )
    return _send(to_email, display_name or to_email,
                 f"You\'re invited to join {firm_name} on Mickey", body)
