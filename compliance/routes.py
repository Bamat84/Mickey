"""
compliance/routes.py
Mickey Compliance Module — Flask Blueprint
All routes follow /api/compliance/{register}/{action} convention.
"""
import os
import json
from functools import wraps
from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for
from datetime import datetime
from werkzeug.utils import secure_filename

from . import data as cd

compliance_bp = Blueprint("compliance", __name__, template_folder="../templates/compliance")

UPLOAD_ROOT = "/opt/mickey/data/uploads"
ALLOWED_EXTENSIONS = {"pdf", "docx", "doc", "xlsx", "txt", "md"}
MAX_FILE_MB = 20

# ── Auth decorators ───────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "firm_id" not in session or "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated

def module_access_required(module_name):
    """Check user has access to this compliance module."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "firm_id" not in session:
                return jsonify({"error": "Authentication required"}), 401
            modules = session.get("modules", [])
            if module_name not in modules:
                return jsonify({"error": "Access denied to this module"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

def editor_required(f):
    """Require editor or admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        role = session.get("compliance_role", "viewer")
        if role not in ("admin", "editor"):
            return jsonify({"error": "Editor access required"}), 403
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Require admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        role = session.get("compliance_role", "viewer")
        if role != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated

def get_firm():
    return session.get("firm_id")

def ok(data=None):
    if data is None:
        return jsonify({"ok": True})
    return jsonify({"ok": True, "data": data})

def err(msg, code=400):
    return jsonify({"error": msg}), code

# ── Main compliance page ──────────────────────────────────────────────────────

@compliance_bp.route("/compliance")
@login_required
def index():
    return redirect("/app")

# ── Compliance settings ───────────────────────────────────────────────────────

@compliance_bp.route("/api/compliance/settings", methods=["GET"])
@login_required
@module_access_required("compliance")
def get_settings():
    return ok(cd.get_compliance_settings(get_firm()))

@compliance_bp.route("/api/compliance/settings", methods=["POST"])
@login_required
@module_access_required("compliance")
@admin_required
def save_settings():
    data = request.get_json(silent=True) or {}
    return ok(cd.save_compliance_settings(get_firm(), data))

# ── DPO ──────────────────────────────────────────────────────────────────────

@compliance_bp.route("/api/compliance/dpo", methods=["GET"])
@login_required
@module_access_required("compliance")
def get_dpo():
    return ok(cd.get_dpo(get_firm()))

@compliance_bp.route("/api/compliance/dpo", methods=["POST"])
@login_required
@module_access_required("compliance")
@editor_required
def save_dpo():
    data = request.get_json(silent=True) or {}
    return ok(cd.save_dpo(get_firm(), data))

# ── RoPA ─────────────────────────────────────────────────────────────────────

@compliance_bp.route("/api/compliance/ropa", methods=["GET"])
@login_required
@module_access_required("compliance")
def get_ropa():
    return ok(cd.get_ropa(get_firm()))

@compliance_bp.route("/api/compliance/ropa", methods=["POST"])
@login_required
@module_access_required("compliance")
@editor_required
def add_ropa():
    data = request.get_json(silent=True) or {}
    required = ["activity_name", "role"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return err(f"Missing required fields: {', '.join(missing)}")
    return ok(cd.add_ropa(get_firm(), data)), 201

@compliance_bp.route("/api/compliance/ropa/<record_id>", methods=["PUT"])
@login_required
@module_access_required("compliance")
@editor_required
def update_ropa(record_id):
    data = request.get_json(silent=True) or {}
    result = cd.update_ropa(get_firm(), record_id, data)
    if not result:
        return err("Record not found", 404)
    return ok(result)

@compliance_bp.route("/api/compliance/ropa/<record_id>", methods=["DELETE"])
@login_required
@module_access_required("compliance")
@editor_required
def delete_ropa(record_id):
    cd.delete_ropa(get_firm(), record_id)
    return ok()

# ── DSR ──────────────────────────────────────────────────────────────────────

@compliance_bp.route("/api/compliance/dsrs", methods=["GET"])
@login_required
@module_access_required("compliance")
def get_dsrs():
    return ok(cd.get_dsrs(get_firm()))

@compliance_bp.route("/api/compliance/dsrs", methods=["POST"])
@login_required
@module_access_required("compliance")
@editor_required
def add_dsr():
    data = request.get_json(silent=True) or {}
    required = ["requester_name", "right", "received_date", "role"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return err(f"Missing required fields: {', '.join(missing)}")
    return ok(cd.add_dsr(get_firm(), data)), 201

@compliance_bp.route("/api/compliance/dsrs/<record_id>", methods=["PUT"])
@login_required
@module_access_required("compliance")
@editor_required
def update_dsr(record_id):
    data = request.get_json(silent=True) or {}
    result = cd.update_dsr(get_firm(), record_id, data)
    if not result:
        return err("Record not found", 404)
    return ok(result)

@compliance_bp.route("/api/compliance/dsrs/<record_id>/close", methods=["POST"])
@login_required
@module_access_required("compliance")
@editor_required
def close_dsr(record_id):
    data = request.get_json(silent=True) or {}
    result = cd.close_dsr(get_firm(), record_id, data.get("outcome", ""))
    if not result:
        return err("Record not found", 404)
    return ok(result)

# ── Data Breach ───────────────────────────────────────────────────────────────

@compliance_bp.route("/api/compliance/breaches", methods=["GET"])
@login_required
@module_access_required("compliance")
def get_breaches():
    return ok(cd.get_breaches(get_firm()))

@compliance_bp.route("/api/compliance/breaches", methods=["POST"])
@login_required
@module_access_required("compliance")
@editor_required
def add_breach():
    data = request.get_json(silent=True) or {}
    required = ["description", "detected_at", "breach_type"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return err(f"Missing required fields: {', '.join(missing)}")
    return ok(cd.add_breach(get_firm(), data)), 201

@compliance_bp.route("/api/compliance/breaches/<record_id>", methods=["PUT"])
@login_required
@module_access_required("compliance")
@editor_required
def update_breach(record_id):
    data = request.get_json(silent=True) or {}
    result = cd.update_breach(get_firm(), record_id, data)
    if not result:
        return err("Record not found", 404)
    return ok(result)

# ── DPIA ─────────────────────────────────────────────────────────────────────

@compliance_bp.route("/api/compliance/dpias", methods=["GET"])
@login_required
@module_access_required("compliance")
def get_dpias():
    return ok(cd.get_dpias(get_firm()))

@compliance_bp.route("/api/compliance/dpias", methods=["POST"])
@login_required
@module_access_required("compliance")
@editor_required
def add_dpia():
    data = request.get_json(silent=True) or {}
    if not data.get("activity_name"):
        return err("Activity name required")
    return ok(cd.add_dpia(get_firm(), data)), 201

@compliance_bp.route("/api/compliance/dpias/<record_id>/advance", methods=["POST"])
@login_required
@module_access_required("compliance")
@editor_required
def advance_dpia(record_id):
    result = cd.advance_dpia(get_firm(), record_id)
    if not result:
        return err("Record not found", 404)
    return ok(result)

@compliance_bp.route("/api/compliance/dpias/<record_id>", methods=["PUT"])
@login_required
@module_access_required("compliance")
@editor_required
def update_dpia(record_id):
    data = request.get_json(silent=True) or {}
    result = cd.update_dpia(get_firm(), record_id, data)
    if not result:
        return err("Record not found", 404)
    return ok(result)

# ── TIA ──────────────────────────────────────────────────────────────────────

@compliance_bp.route("/api/compliance/tias", methods=["GET"])
@login_required
@module_access_required("compliance")
def get_tias():
    return ok(cd.get_tias(get_firm()))

@compliance_bp.route("/api/compliance/tias", methods=["POST"])
@login_required
@module_access_required("compliance")
@editor_required
def add_tia():
    data = request.get_json(silent=True) or {}
    required = ["importer_name", "destination_country", "transfer_mechanism"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return err(f"Missing required fields: {', '.join(missing)}")
    return ok(cd.add_tia(get_firm(), data)), 201

@compliance_bp.route("/api/compliance/tias/<record_id>", methods=["PUT"])
@login_required
@module_access_required("compliance")
@editor_required
def update_tia(record_id):
    data = request.get_json(silent=True) or {}
    result = cd.update_tia(get_firm(), record_id, data)
    if not result:
        return err("Record not found", 404)
    return ok(result)

@compliance_bp.route("/api/compliance/tias/<record_id>", methods=["DELETE"])
@login_required
@module_access_required("compliance")
@editor_required
def delete_tia(record_id):
    cd.delete_tia(get_firm(), record_id)
    return ok()

# ── DPA ──────────────────────────────────────────────────────────────────────

@compliance_bp.route("/api/compliance/dpas", methods=["GET"])
@login_required
@module_access_required("compliance")
def get_dpas():
    return ok(cd.get_dpas(get_firm()))

@compliance_bp.route("/api/compliance/dpas", methods=["POST"])
@login_required
@module_access_required("compliance")
@editor_required
def add_dpa():
    data = request.get_json(silent=True) or {}
    required = ["counterparty", "our_role"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return err(f"Missing required fields: {', '.join(missing)}")
    return ok(cd.add_dpa(get_firm(), data)), 201

@compliance_bp.route("/api/compliance/dpas/<record_id>", methods=["PUT"])
@login_required
@module_access_required("compliance")
@editor_required
def update_dpa(record_id):
    data = request.get_json(silent=True) or {}
    result = cd.update_dpa(get_firm(), record_id, data)
    if not result:
        return err("Record not found", 404)
    return ok(result)

@compliance_bp.route("/api/compliance/dpas/<record_id>", methods=["DELETE"])
@login_required
@module_access_required("compliance")
@editor_required
def delete_dpa(record_id):
    cd.delete_dpa(get_firm(), record_id)
    return ok()

# ── Gifts ─────────────────────────────────────────────────────────────────────

@compliance_bp.route("/api/compliance/gifts", methods=["GET"])
@login_required
@module_access_required("compliance")
def get_gifts():
    return ok(cd.get_gifts(get_firm()))

@compliance_bp.route("/api/compliance/gifts", methods=["POST"])
@login_required
@module_access_required("compliance")
@editor_required
def add_gift():
    data = request.get_json(silent=True) or {}
    required = ["employee_name", "direction", "gift_type", "third_party", "value", "gift_date"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return err(f"Missing required fields: {', '.join(missing)}")
    return ok(cd.add_gift(get_firm(), data)), 201

@compliance_bp.route("/api/compliance/gifts/<record_id>/approve", methods=["POST"])
@login_required
@module_access_required("compliance")
@editor_required
def approve_gift(record_id):
    data = request.get_json(silent=True) or {}
    result = cd.update_gift_status(get_firm(), record_id, "approved", data.get("note", ""))
    if not result:
        return err("Record not found", 404)
    return ok(result)

@compliance_bp.route("/api/compliance/gifts/<record_id>/decline", methods=["POST"])
@login_required
@module_access_required("compliance")
@editor_required
def decline_gift(record_id):
    data = request.get_json(silent=True) or {}
    result = cd.update_gift_status(get_firm(), record_id, "declined", data.get("note", ""))
    if not result:
        return err("Record not found", 404)
    return ok(result)

# ── COI ──────────────────────────────────────────────────────────────────────

@compliance_bp.route("/api/compliance/coi", methods=["GET"])
@login_required
@module_access_required("compliance")
def get_coi():
    return ok(cd.get_coi(get_firm()))

@compliance_bp.route("/api/compliance/coi", methods=["POST"])
@login_required
@module_access_required("compliance")
@editor_required
def add_coi():
    data = request.get_json(silent=True) or {}
    required = ["person_name", "person_role", "declaration_year"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return err(f"Missing required fields: {', '.join(missing)}")
    return ok(cd.add_coi(get_firm(), data)), 201

@compliance_bp.route("/api/compliance/coi/<record_id>", methods=["PUT"])
@login_required
@module_access_required("compliance")
@editor_required
def update_coi(record_id):
    data = request.get_json(silent=True) or {}
    result = cd.update_coi(get_firm(), record_id, data)
    if not result:
        return err("Record not found", 404)
    return ok(result)

# ── Third-Party DD ────────────────────────────────────────────────────────────

@compliance_bp.route("/api/compliance/tpdd", methods=["GET"])
@login_required
@module_access_required("compliance")
def get_tpdd():
    return ok(cd.get_tpdd(get_firm()))

@compliance_bp.route("/api/compliance/tpdd", methods=["POST"])
@login_required
@module_access_required("compliance")
@editor_required
def add_tpdd():
    data = request.get_json(silent=True) or {}
    required = ["company_name", "third_party_type", "country"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return err(f"Missing required fields: {', '.join(missing)}")
    return ok(cd.add_tpdd(get_firm(), data)), 201

@compliance_bp.route("/api/compliance/tpdd/<record_id>", methods=["PUT"])
@login_required
@module_access_required("compliance")
@editor_required
def update_tpdd(record_id):
    data = request.get_json(silent=True) or {}
    result = cd.update_tpdd(get_firm(), record_id, data)
    if not result:
        return err("Record not found", 404)
    return ok(result)

# ── Donations ─────────────────────────────────────────────────────────────────

@compliance_bp.route("/api/compliance/donations", methods=["GET"])
@login_required
@module_access_required("compliance")
def get_donations():
    return ok(cd.get_donations(get_firm()))

@compliance_bp.route("/api/compliance/donations", methods=["POST"])
@login_required
@module_access_required("compliance")
@editor_required
def add_donation():
    data = request.get_json(silent=True) or {}
    required = ["recipient", "donation_type", "amount", "donation_date"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return err(f"Missing required fields: {', '.join(missing)}")
    return ok(cd.add_donation(get_firm(), data)), 201

@compliance_bp.route("/api/compliance/donations/<record_id>", methods=["PUT"])
@login_required
@module_access_required("compliance")
@editor_required
def update_donation(record_id):
    data = request.get_json(silent=True) or {}
    result = cd.update_donation(get_firm(), record_id, data)
    if not result:
        return err("Record not found", 404)
    return ok(result)

# ── Red Flags ─────────────────────────────────────────────────────────────────

@compliance_bp.route("/api/compliance/flags", methods=["GET"])
@login_required
@module_access_required("compliance")
def get_flags():
    # Admin + editor only regardless of module setting
    role = session.get("compliance_role", "viewer")
    if role not in ("admin", "editor"):
        return err("Access restricted", 403)
    return ok(cd.get_flags(get_firm()))

@compliance_bp.route("/api/compliance/flags", methods=["POST"])
@login_required
@module_access_required("compliance")
@editor_required
def add_flag():
    data = request.get_json(silent=True) or {}
    required = ["description", "identified_date", "severity"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return err(f"Missing required fields: {', '.join(missing)}")
    return ok(cd.add_flag(get_firm(), data)), 201

@compliance_bp.route("/api/compliance/flags/<record_id>", methods=["PUT"])
@login_required
@module_access_required("compliance")
@editor_required
def update_flag(record_id):
    data = request.get_json(silent=True) or {}
    result = cd.update_flag(get_firm(), record_id, data)
    if not result:
        return err("Record not found", 404)
    return ok(result)

# ── Whistleblowing ────────────────────────────────────────────────────────────

@compliance_bp.route("/api/compliance/wb", methods=["GET"])
@login_required
@module_access_required("whistleblowing")
def get_wb():
    return ok(cd.get_wb_cases(get_firm()))

@compliance_bp.route("/api/compliance/wb", methods=["POST"])
@login_required
@module_access_required("whistleblowing")
@editor_required
def add_wb():
    data = request.get_json(silent=True) or {}
    required = ["category", "received_date", "channel", "summary"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return err(f"Missing required fields: {', '.join(missing)}")
    return ok(cd.add_wb_case(get_firm(), data)), 201

@compliance_bp.route("/api/compliance/wb/<record_id>/status", methods=["POST"])
@login_required
@module_access_required("whistleblowing")
@editor_required
def update_wb_status(record_id):
    data = request.get_json(silent=True) or {}
    if not data.get("status"):
        return err("Status required")
    result = cd.update_wb_status(get_firm(), record_id, data["status"], data.get("note", ""))
    if not result:
        return err("Record not found", 404)
    return ok(result)

@compliance_bp.route("/api/compliance/wb/stats", methods=["GET"])
@login_required
@module_access_required("whistleblowing")
def wb_stats():
    return ok(cd.get_wb_annual_stats(get_firm()))

# ── Policies & Advice ─────────────────────────────────────────────────────────

@compliance_bp.route("/api/compliance/policies", methods=["GET"])
@login_required
@module_access_required("compliance")
def get_policies():
    module = request.args.get("module")
    return ok(cd.get_policies(get_firm(), module))

@compliance_bp.route("/api/compliance/policies", methods=["POST"])
@login_required
@module_access_required("compliance")
@editor_required
def add_policy():
    data = request.get_json(silent=True) or {}
    required = ["title", "doc_type", "module"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return err(f"Missing required fields: {', '.join(missing)}")
    return ok(cd.add_policy(get_firm(), data)), 201

@compliance_bp.route("/api/compliance/policies/upload", methods=["POST"])
@login_required
@module_access_required("compliance")
@editor_required
def upload_policy():
    if "file" not in request.files:
        return err("No file provided")
    f = request.files["file"]
    if not f.filename:
        return err("No file selected")
    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        return err(f"File type not allowed. Use: {', '.join(ALLOWED_EXTENSIONS)}")
    firm_id = get_firm()
    upload_dir = os.path.join(UPLOAD_ROOT, firm_id, "compliance", "policies")
    os.makedirs(upload_dir, exist_ok=True)
    # Check size
    f.seek(0, 2)
    size = f.tell()
    f.seek(0)
    if size > MAX_FILE_MB * 1024 * 1024:
        return err(f"File too large. Maximum {MAX_FILE_MB}MB.")
    safe_name = secure_filename(f.filename)
    file_path = os.path.join(upload_dir, safe_name)
    f.save(file_path)
    meta = {
        "title": request.form.get("title", safe_name),
        "doc_type": request.form.get("doc_type", "policy"),
        "module": request.form.get("module", "gdpr"),
        "file_path": file_path,
        "file_name": safe_name,
        "file_ext": ext,
        "jurisdictions": request.form.get("jurisdictions", ""),
        "from_radar": request.form.get("from_radar", "false") == "true",
    }
    result = cd.add_policy(firm_id, meta)
    return ok(result), 201

@compliance_bp.route("/api/compliance/policies/<record_id>", methods=["PUT"])
@login_required
@module_access_required("compliance")
@editor_required
def update_policy(record_id):
    data = request.get_json(silent=True) or {}
    result = cd.update_policy(get_firm(), record_id, data)
    if not result:
        return err("Record not found", 404)
    return ok(result)

@compliance_bp.route("/api/compliance/policies/<record_id>", methods=["DELETE"])
@login_required
@module_access_required("compliance")
@editor_required
def delete_policy(record_id):
    cd.delete_policy(get_firm(), record_id)
    return ok()

# ── Dashboard ─────────────────────────────────────────────────────────────────

@compliance_bp.route("/api/compliance/dashboard", methods=["GET"])
@login_required
@module_access_required("compliance")
def get_dashboard():
    return ok(cd.get_dashboard(get_firm()))

# ── User role management (settings integration) ───────────────────────────────

@compliance_bp.route("/api/settings/users", methods=["GET"])
@login_required
@admin_required
def get_users():
    """Return all users in the firm with their compliance roles and modules."""
    from auth.data import get_firm_data
    firm = get_firm_data(get_firm())
    if not firm:
        return err("Firm not found", 404)
    users = []
    for uid, u in firm.get("users", {}).items():
        users.append({
            "user_id": uid,
            "display_name": u.get("display_name", ""),
            "email": u.get("email", ""),
            "status": u.get("status", "active"),
            "compliance_role": u.get("compliance_role", "viewer"),
            "modules": u.get("modules", []),
            "last_signin": u.get("last_signin", ""),
            "created_at": u.get("created_at", ""),
        })
    return ok(users)

@compliance_bp.route("/api/settings/users/<user_id>", methods=["PUT"])
@login_required
@admin_required
def update_user(user_id):
    """Update a user's compliance role and module access."""
    from auth.data import get_firm_data, save_firm_data
    data = request.get_json(silent=True) or {}
    firm = get_firm_data(get_firm())
    if not firm or user_id not in firm.get("users", {}):
        return err("User not found", 404)
    # Prevent admin from demoting themselves
    if user_id == session.get("user_id") and data.get("compliance_role") != "admin":
        return err("You cannot change your own role")
    allowed_roles = ("admin", "editor", "viewer")
    allowed_modules = ("compliance", "whistleblowing", "documents", "corporate", "radar", "knowledge")
    if "compliance_role" in data:
        if data["compliance_role"] not in allowed_roles:
            return err("Invalid role")
        firm["users"][user_id]["compliance_role"] = data["compliance_role"]
    if "modules" in data:
        modules = [m for m in data["modules"] if m in allowed_modules]
        firm["users"][user_id]["modules"] = modules
    if "status" in data:
        if data["status"] in ("active", "inactive"):
            firm["users"][user_id]["status"] = data["status"]
    save_firm_data(get_firm(), firm)
    return ok(firm["users"][user_id])

@compliance_bp.route("/api/settings/users/invite", methods=["POST"])
@login_required
@admin_required
def invite_user():
    """Invite a new user to the firm."""
    from auth.data import get_firm_data, save_firm_data
    import hashlib, secrets
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return err("Email required")
    firm = get_firm_data(get_firm())
    if not firm:
        return err("Firm not found")
    # Check user limit
    active_users = [u for u in firm.get("users", {}).values() if u.get("status") == "active"]
    if len(active_users) >= 5:
        return err("Maximum 5 users per firm. Deactivate a user before inviting another.")
    # Check not already a member
    for u in firm.get("users", {}).values():
        if u.get("email", "").lower() == email:
            return err("This email address is already a member of your firm.")
    # Create pending user record (they set password on first login)
    uid = "u_" + secrets.token_hex(4)
    invite_token = secrets.token_urlsafe(32)
    from datetime import datetime
    firm["users"][uid] = {
        "user_id": uid,
        "email": email,
        "display_name": data.get("display_name", ""),
        "hashed": "",  # Set on first login
        "compliance_role": data.get("compliance_role", "viewer"),
        "modules": data.get("modules", []),
        "status": "pending_invite",
        "invite_token": invite_token,
        "invite_sent_at": datetime.utcnow().isoformat(),
        "email_verified": False,
        "created_at": datetime.utcnow().isoformat(),
    }
    save_firm_data(get_firm(), firm)
    # TODO: Send invite email via Brevo
    return ok({"user_id": uid, "invite_token": invite_token})

@compliance_bp.route("/api/settings/users/<user_id>/deactivate", methods=["POST"])
@login_required
@admin_required
def deactivate_user(user_id):
    from auth.data import get_firm_data, save_firm_data
    if user_id == session.get("user_id"):
        return err("You cannot deactivate your own account")
    firm = get_firm_data(get_firm())
    if not firm or user_id not in firm.get("users", {}):
        return err("User not found", 404)
    firm["users"][user_id]["status"] = "inactive"
    save_firm_data(get_firm(), firm)
    return ok()
