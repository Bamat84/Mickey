"""
compliance/data.py
Mickey Compliance Module — Data layer
All reads/writes for compliance registers.
Data lives at /opt/mickey/data/firms/{firm_id}/compliance/
"""
import json
import os
import uuid
from datetime import datetime, date, timedelta
import shutil

DATA_ROOT = "/opt/mickey/data/firms"
UPLOAD_ROOT = "/opt/mickey/data/uploads"

# ── helpers ──────────────────────────────────────────────────────────────────

def _compliance_dir(firm_id):
    return os.path.join(DATA_ROOT, firm_id, "compliance")

def _ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def _reg_path(firm_id, register):
    """Path to a register JSON file."""
    return os.path.join(_compliance_dir(firm_id), f"{register}.json")

def _read(firm_id, register):
    path = _reg_path(firm_id, register)
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return json.load(f)

def _write(firm_id, register, data):
    _ensure_dir(_compliance_dir(firm_id))
    path = _reg_path(firm_id, register)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, default=str)
    os.replace(tmp, path)  # atomic

def _read_single(firm_id, key):
    """Read a single-record JSON (DPO, firm settings)."""
    path = os.path.join(_compliance_dir(firm_id), f"{key}.json")
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)

def _write_single(firm_id, key, data):
    _ensure_dir(_compliance_dir(firm_id))
    path = os.path.join(_compliance_dir(firm_id), f"{key}.json")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, default=str)
    os.replace(tmp, path)

def _new_id(prefix=""):
    return f"{prefix}{uuid.uuid4().hex[:10]}"

def _now():
    return datetime.utcnow().isoformat()

def _today():
    return date.today().isoformat()

# ── deadline engine ───────────────────────────────────────────────────────────

def days_until(deadline_str):
    """Returns int days until deadline. Negative = overdue."""
    if not deadline_str:
        return None
    try:
        dl = date.fromisoformat(deadline_str[:10])
        return (dl - date.today()).days
    except Exception:
        return None

def rag_from_days(days, warn_threshold=14):
    """Return 'red'/'amber'/'green' from days remaining."""
    if days is None:
        return "muted"
    if days < 0:
        return "red"
    if days <= warn_threshold:
        return "amber"
    return "green"

def add_deadline_fields(record, deadline_field="deadline", warn=14):
    """Enrich a record with days_remaining and rag fields."""
    dl = record.get(deadline_field)
    days = days_until(dl)
    record["_days_remaining"] = days
    record["_rag"] = rag_from_days(days, warn)
    return record

# ── supervisory authorities lookup ───────────────────────────────────────────

SUPERVISORY_AUTHORITIES = {
    "BE": {"name": "GBA / APD", "full": "Gegevensbeschermingsautoriteit / Autorité de protection des données", "url": "https://www.gegevensbeschermingsautoriteit.be"},
    "FR": {"name": "CNIL", "full": "Commission Nationale de l'Informatique et des Libertés", "url": "https://www.cnil.fr"},
    "DE": {"name": "BfDI / State DPAs", "full": "Federal Commissioner for Data Protection (BfDI) + 16 state authorities", "url": "https://www.bfdi.bund.de"},
    "NL": {"name": "AP", "full": "Autoriteit Persoonsgegevens", "url": "https://www.autoriteitpersoonsgegevens.nl"},
    "LU": {"name": "CNPD", "full": "Commission nationale pour la protection des données", "url": "https://cnpd.public.lu"},
    "GB": {"name": "ICO", "full": "Information Commissioner's Office", "url": "https://ico.org.uk"},
    "IE": {"name": "DPC", "full": "Data Protection Commission", "url": "https://www.dataprotection.ie"},
    "ES": {"name": "AEPD", "full": "Agencia Española de Protección de Datos", "url": "https://www.aepd.es"},
    "IT": {"name": "Garante", "full": "Garante per la protezione dei dati personali", "url": "https://www.garanteprivacy.it"},
    "PL": {"name": "UODO", "full": "Urząd Ochrony Danych Osobowych", "url": "https://uodo.gov.pl"},
    "OTHER": {"name": "National DPA", "full": "National Data Protection Authority", "url": ""},
}

def get_supervisory_authority(country_code):
    return SUPERVISORY_AUTHORITIES.get(country_code.upper(), SUPERVISORY_AUTHORITIES["OTHER"])

# ── country risk (TI CPI tiers) ───────────────────────────────────────────────

HIGH_RISK_COUNTRIES = {
    "AF","AO","BY","CF","CD","CG","CU","ER","GN","GQ","GW","HT","IQ",
    "KP","LB","LY","ML","MM","MZ","NI","NE","NG","PK","RU","SD","SS",
    "SY","TD","TJ","TM","UZ","VE","YE","ZW","CM","KH","MG","ZM",
}
MEDIUM_RISK_COUNTRIES = {
    "BD","BO","EC","EG","GH","GT","GY","HN","ID","KE","KG","KZ","LA",
    "LK","MX","MN","MR","MW","NA","NP","PH","PG","PY","RW","SL","SN",
    "TH","TZ","UA","UG","VN","ZA","BR","CO","MA","PER","TN","TR",
}

def country_risk(code):
    if not code:
        return "unknown"
    c = code.upper()
    if c in HIGH_RISK_COUNTRIES:
        return "high"
    if c in MEDIUM_RISK_COUNTRIES:
        return "medium"
    return "low"

# ── DPO ──────────────────────────────────────────────────────────────────────

def get_dpo(firm_id):
    return _read_single(firm_id, "dpo")

def save_dpo(firm_id, data):
    data["updated_at"] = _now()
    _write_single(firm_id, "dpo", data)
    return data

# ── RoPA ─────────────────────────────────────────────────────────────────────

def get_ropa(firm_id):
    records = _read(firm_id, "ropa")
    for r in records:
        add_deadline_fields(r, "review_date", warn=30)
    return records

def add_ropa(firm_id, data):
    records = _read(firm_id, "ropa")
    data["id"] = _new_id("ropa_")
    data["created_at"] = _now()
    data["updated_at"] = _now()
    data["firm_id"] = firm_id
    records.append(data)
    _write(firm_id, "ropa", records)
    return data

def update_ropa(firm_id, record_id, data):
    records = _read(firm_id, "ropa")
    for i, r in enumerate(records):
        if r["id"] == record_id:
            data["id"] = record_id
            data["created_at"] = r.get("created_at", _now())
            data["updated_at"] = _now()
            data["firm_id"] = firm_id
            records[i] = data
            _write(firm_id, "ropa", records)
            return data
    return None

def delete_ropa(firm_id, record_id):
    records = [r for r in _read(firm_id, "ropa") if r["id"] != record_id]
    _write(firm_id, "ropa", records)

# ── DSR ──────────────────────────────────────────────────────────────────────

def get_dsrs(firm_id):
    records = _read(firm_id, "dsrs")
    for r in records:
        add_deadline_fields(r, "deadline", warn=14)
        # Processor sub-deadline
        if r.get("role") == "processor" and r.get("controller_notify_by"):
            r["_ctrl_days"] = days_until(r["controller_notify_by"])
    return records

def add_dsr(firm_id, data):
    records = _read(firm_id, "dsrs")
    data["id"] = _new_id("dsr_")
    data["created_at"] = _now()
    data["updated_at"] = _now()
    data["firm_id"] = firm_id
    data["status"] = "open"
    # Calculate deadline
    received = data.get("received_date", _today())
    if data.get("clock_paused"):
        data["deadline"] = None
    else:
        dl = date.fromisoformat(received) + timedelta(days=30)
        data["deadline"] = dl.isoformat()
    # Processor: 5-business-day controller notification deadline
    if data.get("role") == "processor":
        notify_by = date.fromisoformat(received) + timedelta(days=7)  # 5 bd ≈ 7 calendar
        data["controller_notify_by"] = notify_by.isoformat()
    records.append(data)
    _write(firm_id, "dsrs", records)
    return data

def update_dsr(firm_id, record_id, data):
    records = _read(firm_id, "dsrs")
    for i, r in enumerate(records):
        if r["id"] == record_id:
            data["id"] = record_id
            data["created_at"] = r.get("created_at", _now())
            data["updated_at"] = _now()
            data["firm_id"] = firm_id
            records[i] = data
            _write(firm_id, "dsrs", records)
            return data
    return None

def close_dsr(firm_id, record_id, outcome):
    records = _read(firm_id, "dsrs")
    for i, r in enumerate(records):
        if r["id"] == record_id:
            records[i]["status"] = "closed"
            records[i]["outcome"] = outcome
            records[i]["closed_at"] = _now()
            records[i]["updated_at"] = _now()
            _write(firm_id, "dsrs", records)
            return records[i]
    return None

# ── Data Breach ───────────────────────────────────────────────────────────────

def get_breaches(firm_id):
    records = _read(firm_id, "breaches")
    for r in records:
        if r.get("status") == "open" and r.get("detected_at"):
            # 72h clock
            try:
                detected = datetime.fromisoformat(r["detected_at"])
                deadline_dt = detected + timedelta(hours=72)
                now = datetime.utcnow()
                hours_left = (deadline_dt - now).total_seconds() / 3600
                r["_hours_remaining"] = round(hours_left, 1)
                r["_72h_rag"] = "red" if hours_left < 12 else ("amber" if hours_left < 36 else "green")
            except Exception:
                pass
        add_deadline_fields(r, "sa_notified_deadline", warn=0)
    return records

def add_breach(firm_id, data):
    records = _read(firm_id, "breaches")
    data["id"] = _new_id("bre_")
    data["ref"] = f"BRE-{date.today().year}-{str(len(records)+1).zfill(3)}"
    data["created_at"] = _now()
    data["updated_at"] = _now()
    data["firm_id"] = firm_id
    data["status"] = "open"
    # 72h SA notification deadline
    if data.get("detected_at"):
        try:
            detected = datetime.fromisoformat(data["detected_at"])
            deadline_dt = detected + timedelta(hours=72)
            data["sa_notified_deadline"] = deadline_dt.isoformat()
        except Exception:
            pass
    records.append(data)
    _write(firm_id, "breaches", records)
    return data

def update_breach(firm_id, record_id, updates):
    records = _read(firm_id, "breaches")
    for i, r in enumerate(records):
        if r["id"] == record_id:
            records[i].update(updates)
            records[i]["updated_at"] = _now()
            _write(firm_id, "breaches", records)
            return records[i]
    return None

# ── DPIA ─────────────────────────────────────────────────────────────────────

DPIA_STAGES = [
    "Screening", "Necessity & Proportionality", "Risk Identification",
    "Risk Assessment", "Risk Mitigation", "DPO Consultation", "Final Review"
]

def get_dpias(firm_id):
    return _read(firm_id, "dpias")

def add_dpia(firm_id, data):
    records = _read(firm_id, "dpias")
    data["id"] = _new_id("dpia_")
    data["created_at"] = _now()
    data["updated_at"] = _now()
    data["firm_id"] = firm_id
    data["stage"] = 0  # 0-indexed, 7 stages total
    data["status"] = "in_progress"
    data["stage_history"] = [{"stage": 0, "entered_at": _now()}]
    records.append(data)
    _write(firm_id, "dpias", records)
    return data

def advance_dpia(firm_id, record_id):
    records = _read(firm_id, "dpias")
    for i, r in enumerate(records):
        if r["id"] == record_id:
            current = r.get("stage", 0)
            if current < 6:
                records[i]["stage"] = current + 1
                records[i]["stage_history"].append({"stage": current + 1, "entered_at": _now()})
                if current + 1 == 6:
                    records[i]["status"] = "final_review"
            else:
                records[i]["status"] = "completed"
                records[i]["completed_at"] = _now()
            records[i]["updated_at"] = _now()
            _write(firm_id, "dpias", records)
            return records[i]
    return None

def update_dpia(firm_id, record_id, updates):
    records = _read(firm_id, "dpias")
    for i, r in enumerate(records):
        if r["id"] == record_id:
            records[i].update(updates)
            records[i]["updated_at"] = _now()
            _write(firm_id, "dpias", records)
            return records[i]
    return None

# ── TIA ──────────────────────────────────────────────────────────────────────

def get_tias(firm_id):
    records = _read(firm_id, "tias")
    for r in records:
        add_deadline_fields(r, "reassess_by", warn=60)
    return records

def add_tia(firm_id, data):
    records = _read(firm_id, "tias")
    data["id"] = _new_id("tia_")
    data["created_at"] = _now()
    data["updated_at"] = _now()
    data["firm_id"] = firm_id
    records.append(data)
    _write(firm_id, "tias", records)
    return data

def update_tia(firm_id, record_id, updates):
    records = _read(firm_id, "tias")
    for i, r in enumerate(records):
        if r["id"] == record_id:
            records[i].update(updates)
            records[i]["updated_at"] = _now()
            _write(firm_id, "tias", records)
            return records[i]
    return None

def delete_tia(firm_id, record_id):
    records = [r for r in _read(firm_id, "tias") if r["id"] != record_id]
    _write(firm_id, "tias", records)

# ── DPA ──────────────────────────────────────────────────────────────────────

def get_dpas(firm_id):
    records = _read(firm_id, "dpas")
    for r in records:
        add_deadline_fields(r, "review_date", warn=60)
    return records

def add_dpa(firm_id, data):
    records = _read(firm_id, "dpas")
    data["id"] = _new_id("dpa_")
    data["created_at"] = _now()
    data["updated_at"] = _now()
    data["firm_id"] = firm_id
    records.append(data)
    _write(firm_id, "dpas", records)
    return data

def update_dpa(firm_id, record_id, updates):
    records = _read(firm_id, "dpas")
    for i, r in enumerate(records):
        if r["id"] == record_id:
            records[i].update(updates)
            records[i]["updated_at"] = _now()
            _write(firm_id, "dpas", records)
            return records[i]
    return None

def delete_dpa(firm_id, record_id):
    records = [r for r in _read(firm_id, "dpas") if r["id"] != record_id]
    _write(firm_id, "dpas", records)

# ── ABC: Gifts ────────────────────────────────────────────────────────────────

def get_gifts(firm_id):
    records = _read(firm_id, "gifts")
    for r in records:
        r["_country_risk"] = country_risk(r.get("country", ""))
    return records

def add_gift(firm_id, data):
    records = _read(firm_id, "gifts")
    data["id"] = _new_id("gift_")
    data["created_at"] = _now()
    data["updated_at"] = _now()
    data["firm_id"] = firm_id
    data["status"] = "pending"
    records.append(data)
    _write(firm_id, "gifts", records)
    return data

def update_gift_status(firm_id, record_id, status, note=""):
    records = _read(firm_id, "gifts")
    for i, r in enumerate(records):
        if r["id"] == record_id:
            records[i]["status"] = status
            records[i]["approval_note"] = note
            records[i]["decided_at"] = _now()
            records[i]["updated_at"] = _now()
            _write(firm_id, "gifts", records)
            return records[i]
    return None

# ── ABC: COI ─────────────────────────────────────────────────────────────────

def get_coi(firm_id):
    return _read(firm_id, "coi")

def add_coi(firm_id, data):
    records = _read(firm_id, "coi")
    data["id"] = _new_id("coi_")
    data["created_at"] = _now()
    data["updated_at"] = _now()
    data["firm_id"] = firm_id
    records.append(data)
    _write(firm_id, "coi", records)
    return data

def update_coi(firm_id, record_id, updates):
    records = _read(firm_id, "coi")
    for i, r in enumerate(records):
        if r["id"] == record_id:
            records[i].update(updates)
            records[i]["updated_at"] = _now()
            _write(firm_id, "coi", records)
            return records[i]
    return None

# ── ABC: Third-Party DD ────────────────────────────────────────────────────────

def get_tpdd(firm_id):
    records = _read(firm_id, "tpdd")
    for r in records:
        r["_country_risk"] = country_risk(r.get("country", ""))
        add_deadline_fields(r, "next_review", warn=60)
    return records

def add_tpdd(firm_id, data):
    records = _read(firm_id, "tpdd")
    data["id"] = _new_id("tpdd_")
    data["created_at"] = _now()
    data["updated_at"] = _now()
    data["firm_id"] = firm_id
    # Auto-flag enhanced DD for high-risk countries
    if country_risk(data.get("country", "")) == "high":
        data["dd_level"] = "enhanced"
    records.append(data)
    _write(firm_id, "tpdd", records)
    return data

def update_tpdd(firm_id, record_id, updates):
    records = _read(firm_id, "tpdd")
    for i, r in enumerate(records):
        if r["id"] == record_id:
            records[i].update(updates)
            records[i]["updated_at"] = _now()
            _write(firm_id, "tpdd", records)
            return records[i]
    return None

# ── ABC: Political Donations ──────────────────────────────────────────────────

def get_donations(firm_id):
    return _read(firm_id, "donations")

def add_donation(firm_id, data):
    records = _read(firm_id, "donations")
    data["id"] = _new_id("don_")
    data["created_at"] = _now()
    data["updated_at"] = _now()
    data["firm_id"] = firm_id
    data["status"] = "pending_board" if data.get("board_approval_required") else "approved"
    records.append(data)
    _write(firm_id, "donations", records)
    return data

def update_donation(firm_id, record_id, updates):
    records = _read(firm_id, "donations")
    for i, r in enumerate(records):
        if r["id"] == record_id:
            records[i].update(updates)
            records[i]["updated_at"] = _now()
            _write(firm_id, "donations", records)
            return records[i]
    return None

# ── ABC: Red Flags ────────────────────────────────────────────────────────────

def get_flags(firm_id):
    return _read(firm_id, "redflags")

def add_flag(firm_id, data):
    records = _read(firm_id, "redflags")
    data["id"] = _new_id("flag_")
    data["created_at"] = _now()
    data["updated_at"] = _now()
    data["firm_id"] = firm_id
    data["status"] = "open"
    records.append(data)
    _write(firm_id, "redflags", records)
    return data

def update_flag(firm_id, record_id, updates):
    records = _read(firm_id, "redflags")
    for i, r in enumerate(records):
        if r["id"] == record_id:
            records[i].update(updates)
            records[i]["updated_at"] = _now()
            _write(firm_id, "redflags", records)
            return records[i]
    return None

# ── Whistleblowing ────────────────────────────────────────────────────────────

def get_wb_cases(firm_id):
    records = _read(firm_id, "wb_cases")
    for r in records:
        add_deadline_fields(r, "acknowledge_by", warn=3)
        add_deadline_fields(r, "outcome_by", warn=14)
        # rename enriched fields to avoid clash
        r["_ack_days"] = days_until(r.get("acknowledge_by"))
        r["_outcome_days"] = days_until(r.get("outcome_by"))
    return records

def add_wb_case(firm_id, data):
    records = _read(firm_id, "wb_cases")
    year = date.today().year
    seq = len([r for r in records if str(year) in r.get("ref", "")]) + 1
    data["id"] = _new_id("wb_")
    data["ref"] = f"WB-{year}-{str(seq).zfill(3)}"
    data["created_at"] = _now()
    data["updated_at"] = _now()
    data["firm_id"] = firm_id
    data["status"] = "received"
    received = data.get("received_date", _today())
    # 7-day acknowledgement
    ack_by = date.fromisoformat(received) + timedelta(days=7)
    data["acknowledge_by"] = ack_by.isoformat()
    # 3-month outcome deadline
    outcome_by = date.fromisoformat(received) + timedelta(days=90)
    data["outcome_by"] = outcome_by.isoformat()
    # If anonymous, store identity separately (not in main record)
    if data.get("reporter_type") == "named" and data.get("reporter_name"):
        identity = {
            "case_id": data["id"],
            "name": data.pop("reporter_name", ""),
            "contact": data.pop("reporter_contact", ""),
            "stored_at": _now()
        }
        _write_single(firm_id, f"wb_identity_{data['id']}", identity)
    records.append(data)
    _write(firm_id, "wb_cases", records)
    return data

def update_wb_status(firm_id, record_id, status, note=""):
    records = _read(firm_id, "wb_cases")
    for i, r in enumerate(records):
        if r["id"] == record_id:
            records[i]["status"] = status
            if note:
                records[i].setdefault("notes", []).append({"note": note, "at": _now()})
            if status == "acknowledged":
                records[i]["acknowledged_at"] = _now()
            if status in ("closed", "no_action"):
                records[i]["closed_at"] = _now()
            records[i]["updated_at"] = _now()
            _write(firm_id, "wb_cases", records)
            return records[i]
    return None

def get_wb_annual_stats(firm_id):
    year = date.today().year
    records = _read(firm_id, "wb_cases")
    year_records = [r for r in records if str(year) in r.get("created_at", "")]
    stats = {
        "year": year,
        "total": len(year_records),
        "open": len([r for r in year_records if r.get("status") not in ("closed","no_action")]),
        "closed": len([r for r in year_records if r.get("status") in ("closed","no_action")]),
        "by_category": {},
        "anonymous": len([r for r in year_records if r.get("reporter_type") == "anonymous"]),
    }
    for r in year_records:
        cat = r.get("category", "other")
        stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
    return stats

# ── Policies & Advice ─────────────────────────────────────────────────────────

def get_policies(firm_id, module=None):
    records = _read(firm_id, "policies")
    if module:
        records = [r for r in records if r.get("module") == module]
    return records

def add_policy(firm_id, data):
    records = _read(firm_id, "policies")
    data["id"] = _new_id("pol_")
    data["created_at"] = _now()
    data["updated_at"] = _now()
    data["firm_id"] = firm_id
    records.append(data)
    _write(firm_id, "policies", records)
    return data

def update_policy(firm_id, record_id, updates):
    records = _read(firm_id, "policies")
    for i, r in enumerate(records):
        if r["id"] == record_id:
            records[i].update(updates)
            records[i]["updated_at"] = _now()
            _write(firm_id, "policies", records)
            return records[i]
    return None

def delete_policy(firm_id, record_id):
    records = _read(firm_id, "policies")
    to_delete = next((r for r in records if r["id"] == record_id), None)
    if to_delete and to_delete.get("file_path"):
        try:
            os.remove(to_delete["file_path"])
        except Exception:
            pass
    records = [r for r in records if r["id"] != record_id]
    _write(firm_id, "policies", records)

# ── Dashboard aggregates ───────────────────────────────────────────────────────

def get_dashboard(firm_id):
    """Aggregate RAG counts and top actions for dashboard widgets."""
    dsrs = get_dsrs(firm_id)
    breaches = get_breaches(firm_id)
    ropa = get_ropa(firm_id)
    gifts = get_gifts(firm_id)
    coi = get_coi(firm_id)
    tpdd = get_tpdd(firm_id)
    wb = get_wb_cases(firm_id)

    open_dsrs = [d for d in dsrs if d.get("status") == "open"]
    open_breaches = [b for b in breaches if b.get("status") == "open"]
    open_wb = [w for w in wb if w.get("status") not in ("closed","no_action")]

    return {
        "gdpr": {
            "ropa_overdue": len([r for r in ropa if r.get("_rag") == "red"]),
            "ropa_due_soon": len([r for r in ropa if r.get("_rag") == "amber"]),
            "ropa_ok": len([r for r in ropa if r.get("_rag") == "green"]),
            "dsr_overdue": len([d for d in open_dsrs if d.get("_rag") == "red"]),
            "dsr_due_soon": len([d for d in open_dsrs if d.get("_rag") == "amber"]),
            "dsr_ok": len([d for d in open_dsrs if d.get("_rag") == "green"]),
            "breach_active": len(open_breaches),
            "breach_urgent": next((b for b in open_breaches if b.get("_hours_remaining", 999) < 36), None),
        },
        "abc": {
            "gifts_pending": len([g for g in gifts if g.get("status") == "pending"]),
            "coi_missing": len([c for c in coi if c.get("conflict_status") == "not_submitted"]),
            "dd_high_risk": len([t for t in tpdd if t.get("_country_risk") == "high" and t.get("status") != "cleared"]),
        },
        "wb": {
            "open": len(open_wb),
            "closed_ytd": len([w for w in wb if w.get("status") in ("closed","no_action") and str(date.today().year) in w.get("closed_at","")]),
            "urgent": next((w for w in open_wb if w.get("_ack_days") is not None and w.get("_ack_days","") != "" and isinstance(w.get("_ack_days"),int) and w["_ack_days"] < 3), None),
        }
    }

# ── Firm settings (compliance-specific) ───────────────────────────────────────

def get_compliance_settings(firm_id):
    return _read_single(firm_id, "compliance_settings")

def save_compliance_settings(firm_id, data):
    data["updated_at"] = _now()
    _write_single(firm_id, "compliance_settings", data)
    return data


# ── Bulk import ────────────────────────────────────────────────────────────────

# Maps register name → file prefix for IDs
_REGISTER_PREFIX = {
    "ropa": "ropa_", "dsrs": "dsr_", "breaches": "breach_", "dpias": "dpia_",
    "tias": "tia_", "dpas": "dpa_", "gifts": "gift_", "coi": "coi_",
    "tpdd": "tpdd_", "donations": "don_", "flags": "flag_", "wb": "wb_",
}

def bulk_import(firm_id, register, records):
    """Append a list of pre-mapped records to a register. Returns count saved."""
    if register not in _REGISTER_PREFIX:
        raise ValueError(f"Unknown register: {register}")
    prefix = _REGISTER_PREFIX[register]
    existing = _read(firm_id, register)
    for rec in records:
        rec["id"] = _new_id(prefix)
        rec["firm_id"] = firm_id
        rec["created_at"] = _now()
        rec["updated_at"] = _now()
        # Remove any internal/computed fields from the import payload
        for k in list(rec.keys()):
            if k.startswith("_"):
                del rec[k]
        existing.append(rec)
    _write(firm_id, register, existing)
    return len(records)
