from flask import Flask, request, jsonify, session
from flask_cors import CORS
import psycopg2
from twilio.twiml.messaging_response import MessagingResponse
import hashlib
import os
import json
from datetime import datetime, timedelta
import requests
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

# Configuration
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'None'

and thsi will ibe like this:
CORS(app, supports_credentials=True,
     resources={r"/api/*": {"origins": "*"}},
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])?

# User conversation state (in-memory)
user_state = {}

# Import configuration
try:
    from config import MESSAGES, FRAUD_MEDIUMS, INCIDENT_TYPES, INDIAN_STATES
except ImportError:
    print("⚠️ Config not imported, using basic config")
    MESSAGES = {}
    FRAUD_MEDIUMS = {}
    INCIDENT_TYPES = {}
    INDIAN_STATES = []

# =============================================================================
# DATABASE
# =============================================================================

def get_db():
    """Get database connection"""
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise Exception("DATABASE_URL not set")
    
    # Fix for Render's postgres:// URL
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    
    return psycopg2.connect(database_url, cursor_factory=RealDictCursor)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def generate_reference_id():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    return f"I4C-{timestamp}"

def hash_evidence(text):
    return hashlib.sha256(text.encode()).hexdigest()

def get_message(lang, key, **kwargs):
    lang = lang if lang in MESSAGES else 'en'
    msg = MESSAGES.get(lang, {}).get(key, f"Message: {key}")
    return msg.format(**kwargs) if kwargs else msg

def save_report(data):
    """Save report to database"""
    conn = get_db()
    c = conn.cursor()
    
    reference_id = generate_reference_id()
    
    c.execute("""
        INSERT INTO cyber_reports (
            phone, location_city, location_state, language_preference,
            fraud_medium, incident_type, incident_description,
            suspect_phone, suspect_email, suspect_upi_id,
            suspect_other_details, amount_involved,
            evidence_text, evidence_hash, media_files,
            anonymous, reference_id, status, priority,
            consent_given, data_retention_date, created_at
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        RETURNING id
    """, (
        data.get("phone", "ANONYMOUS"),
        data.get("location_city"),
        data.get("location_state"),
        data.get("language", "en"),
        data.get("fraud_medium"),
        data.get("incident_type"),
        data.get("description"),
        data.get("suspect_phone"),
        data.get("suspect_email"),
        data.get("suspect_upi"),
        data.get("suspect_other"),
        data.get("amount", 0),
        data.get("evidence_text"),
        data.get("evidence_hash"),
        json.dumps(data.get("media_files", [])),
        data.get("anonymous", "NO"),
        reference_id,
        "NEW",
        "MEDIUM",
        1,
        (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d"),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    report_id = c.fetchone()['id']
    conn.commit()
    conn.close()
    
    return reference_id

# =============================================================================
# WHATSAPP BOT
# =============================================================================

@app.route("/whatsapp", methods=["POST"])
def whatsapp_bot():
    """WhatsApp webhook"""
    msg = request.values.get("Body", "").strip()
    phone = request.values.get("From", "")
    
    resp = MessagingResponse()
    reply = resp.message()
    
    if phone not in user_state:
        user_state[phone] = {"language": "en", "step": "welcome"}
    
    state = user_state[phone]
    lang = state.get("language", "en")
    
    try:
        # Welcome
        if state.get("step") == "welcome" or msg.lower() in ["start", "hi", "hello"]:
            print("DEBUG MESSAGE:", get_message("en", "welcome"))
            reply.body(get_message("en", "welcome"))
            state["step"] = "language"
        
        # Language
        elif state.get("step") == "language":
            lang_map = {"1": "en", "2": "hi", "3": "gu"}
            msg_clean = msg.strip()

            if msg_clean in lang_map:
                state["language"] = lang_map[msg_clean]
                lang = state["language"]
                reply.body(get_message(lang, "consent"))
                state["step"] = "consent"
            else:
                reply.body(get_message(lang, "invalid_input"))

        
        # Consent
        elif state.get("step") == "consent":
            if msg == "1":
                state["consent"] = True
                reply.body(get_message(lang, "fraud_medium"))
                state["step"] = "fraud_medium"
            elif msg == "2":
                reply.body("Thank you. Call 1930 for help.")
                user_state.pop(phone, None)
            else:
                reply.body(get_message(lang, "invalid_input"))
        
        # Fraud Medium
        elif state.get("step") == "fraud_medium":
            if msg in FRAUD_MEDIUMS.get(lang, {}):
                state["fraud_medium"] = FRAUD_MEDIUMS['en'][msg]
                reply.body(get_message(lang, "incident_type"))
                state["step"] = "incident_type"
            else:
                reply.body(get_message(lang, "invalid_input"))
        
        # Incident Type
        elif state.get("step") == "incident_type":
            if msg in INCIDENT_TYPES.get(lang, {}):
                state["incident_type"] = INCIDENT_TYPES['en'][msg]
                reply.body(get_message(lang, "location_state"))
                state["step"] = "location_state"
            else:
                reply.body(get_message(lang, "invalid_input"))
        
        # State
        elif state.get("step") == "location_state":
            if msg.isdigit() and 1 <= int(msg) <= len(INDIAN_STATES):
                state["location_state"] = INDIAN_STATES[int(msg) - 1]
                reply.body(get_message(lang, "location_city"))
                state["step"] = "location_city"
            else:
                reply.body(get_message(lang, "invalid_input"))
        
        # City
        elif state.get("step") == "location_city":
            state["location_city"] = msg.title()
            reply.body(get_message(lang, "description"))
            state["step"] = "description"
        
        # Description
        elif state.get("step") == "description":
            state["description"] = msg
            state["evidence_hash"] = hash_evidence(msg)
            reply.body(get_message(lang, "suspect_details"))
            state["step"] = "suspect_details"
        
        # Suspect
        elif state.get("step") == "suspect_details":
            state["suspect_other"] = msg
            reply.body(get_message(lang, "amount"))
            state["step"] = "amount"
        
        # Amount
        elif state.get("step") == "amount":
            try:
                state["amount"] = float(msg.replace(",", "").replace("₹", ""))
            except:
                state["amount"] = 0
            reply.body(get_message(lang, "evidence"))
            state["step"] = "evidence"
        
        # Evidence
        elif state.get("step") == "evidence":
            state["evidence_text"] = msg
            reply.body(get_message(lang, "anonymous"))
            state["step"] = "anonymous"
        
        # Anonymous
        elif state.get("step") == "anonymous":
            if msg in ["1", "2"]:
                state["anonymous"] = "YES" if msg == "1" else "NO"
                state["phone"] = "ANONYMOUS" if msg == "1" else phone
                
                reference_id = save_report(state)
                reply.body(get_message(lang, "confirmation", reference_id=reference_id))
                user_state.pop(phone, None)
            else:
                reply.body(get_message(lang, "invalid_input"))
        
        else:
            reply.body(get_message(lang, "welcome"))
            state["step"] = "welcome"
    
    except Exception as e:
        print(f"Error: {e}")
        reply.body("Error occurred. Please try again or call 1930.")
    
    return str(resp)

# =============================================================================
# ADMIN API
# =============================================================================

@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        return jsonify({"error": "Credentials required"}), 400
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT * FROM admin_users 
        WHERE username = %s AND password_hash = %s AND is_active = 1
    """, (username, password_hash))
    admin = c.fetchone()
    conn.close()
    
    if admin:
        session['admin_id'] = admin['id']
        session['admin_username'] = admin['username']
        session['admin_role'] = admin['role']
        
        return jsonify({
            "success": True,
            "admin": {
                "id": admin['id'],
                "username": admin['username'],
                "full_name": admin['full_name'],
                "role": admin['role']
            }
        })
    
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return jsonify({"success": True})

@app.route("/api/admin/reports", methods=["GET"])
def get_reports():
    if 'admin_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    
    conn = get_db()
    c = conn.cursor()
    
    c.execute("SELECT COUNT(*) as count FROM cyber_reports")
    total = c.fetchone()['count']
    
    c.execute("""
        SELECT * FROM cyber_reports 
        ORDER BY created_at DESC 
        LIMIT %s OFFSET %s
    """, (per_page, (page - 1) * per_page))
    reports = c.fetchall()
    conn.close()
    
    return jsonify({
        "reports": [dict(r) for r in reports],
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page
    })

@app.route("/api/admin/reports/<int:report_id>/status", methods=["PUT", "OPTIONS"])
def update_report_status(report_id):

    # Handle CORS preflight
    if request.method == "OPTIONS":
        return '', 200

    if 'admin_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    new_status = data.get("status")
    priority = data.get("priority")

    if not new_status:
        return jsonify({"error": "Status required"}), 400

    conn = get_db()
    c = conn.cursor()

    # Check report exists
    c.execute("SELECT * FROM cyber_reports WHERE id = %s", (report_id,))
    report = c.fetchone()

    if not report:
        conn.close()
        return jsonify({"error": "Not found"}), 404

    # UPDATE REPORT
    updates = ["status = %s", "updated_at = NOW()"]
    params = [new_status]

    if priority:
        updates.append("priority = %s")
        params.append(priority)

    if new_status == "RESOLVED":
        updates.append("resolved_at = NOW()")

    params.append(report_id)

    c.execute(
        f"UPDATE cyber_reports SET {', '.join(updates)} WHERE id = %s",
        params
    )

    conn.commit()
    conn.close()

    return jsonify({"success": True, "status": new_status})

@app.route("/api/admin/analytics/overview", methods=["GET"])
def get_analytics():
    if 'admin_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    conn = get_db()
    c = conn.cursor()
    
    c.execute("SELECT COUNT(*) as count FROM cyber_reports")
    total = c.fetchone()['count']
    
    c.execute("""
        SELECT status, COUNT(*) as count 
        FROM cyber_reports GROUP BY status
    """)
    status_breakdown = c.fetchall()
    
    c.execute("""
        SELECT fraud_medium, COUNT(*) as count 
        FROM cyber_reports 
        GROUP BY fraud_medium ORDER BY count DESC
    """)
    fraud_breakdown = c.fetchall()
    
    c.execute("""
        SELECT COALESCE(SUM(amount_involved), 0) as total 
        FROM cyber_reports
    """)
    total_amount = c.fetchone()['total']
    
    conn.close()
    
    return jsonify({
        "total_reports": total,
        "status_breakdown": [dict(r) for r in status_breakdown],
        "fraud_medium_breakdown": [dict(r) for r in fraud_breakdown],
        "state_breakdown": [],
        "daily_trend": [],
        "total_amount_involved": float(total_amount)
    })

# =============================================================================
# HEALTH
# =============================================================================

@app.route("/health", methods=["GET"])
def health():
    try:
        conn = get_db()
        conn.close()
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    return jsonify({
        "status": "healthy",
        "database": db_status,
        "timestamp": datetime.now().isoformat()
    })

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "service": "I4C Cyber Reporting Bot",
        "status": "running",
        "endpoints": ["/whatsapp", "/health", "/api/admin/login"]
    })

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
