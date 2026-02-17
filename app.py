from flask import Flask, request, jsonify, session, send_file
from flask_cors import CORS
from twilio.twiml.messaging_response import MessagingResponse
from werkzeug.utils import secure_filename
import sqlite3
import hashlib
import os
import json
from datetime import datetime, timedelta
import requests
from config import Config, MESSAGES, FRAUD_MEDIUMS, INCIDENT_TYPES, INDIAN_STATES

app = Flask(__name__)
app.config.from_object(Config)
CORS(app, supports_credentials=True)

# User conversation state
user_state = {}

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(app.config['DATABASE_PATH'])
    conn.row_factory = sqlite3.Row
    return conn

def log_audit(action, table_name=None, record_id=None, user_id=None, user_phone=None, details=None):
    """Log action for DPDP compliance"""
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO audit_log (action, table_name, record_id, user_id, user_phone, 
                              ip_address, details, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        action,
        table_name,
        record_id,
        user_id,
        user_phone,
        request.remote_addr if request else None,
        json.dumps(details) if details else None,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()

def generate_reference_id():
    """Generate unique reference ID"""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    return f"I4C-{timestamp}"

def hash_evidence(text):
    """Hash evidence for integrity"""
    return hashlib.sha256(text.encode()).hexdigest()

def get_message(lang, key, **kwargs):
    """Get message in specified language"""
    lang = lang if lang in MESSAGES else 'en'
    msg = MESSAGES.get(lang, MESSAGES['en']).get(key, MESSAGES['en'].get(key, ''))
    return msg.format(**kwargs) if kwargs else msg

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def download_whatsapp_media(media_url):
    """Download media from WhatsApp"""
    try:
        # In production, use Twilio credentials
        response = requests.get(media_url, timeout=30)
        if response.status_code == 200:
            return response.content
    except Exception as e:
        print(f"Error downloading media: {e}")
    return None

def save_report(data):
    print("DEBUG: save_report() CALLED")   # 👈 ADD

    conn = get_db()
    c = conn.cursor()
    
    reference_id = generate_reference_id()
    
    print("DEBUG: inserting into DB...")   # 👈 ADD
    print("DEBUG: REPORT INSERTED")
    c.execute("""
        INSERT INTO cyber_reports (
            phone, location_city, location_state, language_preference,
            fraud_medium, incident_type, incident_description,
            suspect_phone, suspect_email, suspect_upi_id, suspect_account_number,
            suspect_bank_name, suspect_social_media, suspect_website_url, suspect_other_details,
            transaction_id, amount_involved, payment_method,
            evidence_text, evidence_hash, media_files,
            anonymous, reference_id, status, priority,
            consent_given, data_retention_date, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        data.get("suspect_account"),
        data.get("suspect_bank"),
        data.get("suspect_social"),
        data.get("suspect_url"),
        data.get("suspect_other"),
        data.get("transaction_id"),
        data.get("amount", 0),
        data.get("payment_method"),
        data.get("evidence_text"),
        data.get("evidence_hash"),
        json.dumps(data.get("media_files", [])),
        data.get("anonymous", "NO"),
        reference_id,
        "NEW",
        "MEDIUM",
        1,
        (datetime.now() + timedelta(days=app.config['DATA_RETENTION_DAYS'])).strftime("%Y-%m-%d"),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    print("DEBUG: commit DB")   # 👈 ADD

    report_id = c.lastrowid
    conn.commit()
    conn.close()

    print("DEBUG: DB saved successfully")   # 👈 ADD
    
    log_audit("REPORT_CREATED", "cyber_reports", report_id, user_phone=data.get("phone"))

    return reference_id

def sync_to_i4c(report_id, reference_id, data):
    """Sync report to I4C systems (placeholder)"""
    # This would integrate with actual I4C API
    # For now, just log the attempt
    log_audit("I4C_SYNC_ATTEMPTED", "cyber_reports", report_id, 
              details={"reference_id": reference_id})
    pass

# =============================================================================
# WHATSAPP BOT ENDPOINT
# =============================================================================

@app.route("/whatsapp", methods=["POST"])
def whatsapp_bot():
    """Main WhatsApp bot handler"""
    msg = request.values.get("Body", "").strip()
    phone = request.values.get("From", "")
    num_media = int(request.values.get("NumMedia", 0))
    
    resp = MessagingResponse()
    reply = resp.message()
    
    # Initialize user state
    if phone not in user_state:
        user_state[phone] = {"language": "en", "step": "welcome"}
    
    state = user_state[phone]
    lang = state.get("language", "en")
    
    try:
        # STEP 0: Welcome & Language Selection
        if state.get("step") == "welcome" or msg.lower() in ["start", "hi", "hello", "hey"]:
            reply.body(get_message("en", "welcome"))
            state["step"] = "language"
        
        # STEP 1: Language Selection
        elif state.get("step") == "language":
            lang_map = {"1": "en", "2": "hi", "3": "gu"}
            if msg in lang_map:
                state["language"] = lang_map[msg]
                lang = state["language"]
                reply.body(get_message(lang, "consent"))
                state["step"] = "consent"
            else:
                reply.body(get_message(lang, "invalid_input"))
        
        # STEP 2: DPDP Consent
        elif state.get("step") == "consent":
            if msg == "1":
                state["consent"] = True
                reply.body(get_message(lang, "fraud_medium"))
                state["step"] = "fraud_medium"
                
                # Record consent
                conn = get_db()
                c = conn.cursor()
                c.execute("""
                    INSERT INTO user_consents (phone, consent_type, consent_given, consent_date)
                    VALUES (?, ?, ?, ?)
                """, (phone, "DATA_COLLECTION", 1, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                conn.commit()
                conn.close()
            elif msg == "2":
                reply.body("We respect your privacy. You can call 1930 helpline for assistance. Thank you!")
                user_state.pop(phone, None)
            else:
                reply.body(get_message(lang, "invalid_input"))
        
        # STEP 3: Fraud Medium Selection
        elif state.get("step") == "fraud_medium":
            if msg in FRAUD_MEDIUMS[lang]:
                state["fraud_medium"] = FRAUD_MEDIUMS['en'][msg]
                reply.body(get_message(lang, "incident_type"))
                state["step"] = "incident_type"
            else:
                reply.body(get_message(lang, "invalid_input"))
        
        # STEP 4: Incident Type Selection
        elif state.get("step") == "incident_type":
            if msg in INCIDENT_TYPES[lang]:
                state["incident_type"] = INCIDENT_TYPES['en'][msg]
                reply.body(get_message(lang, "location_state"))
                state["step"] = "location_state"
            else:
                reply.body(get_message(lang, "invalid_input"))
        
        # STEP 5: Location - State
        elif state.get("step") == "location_state":
            if msg.lower() == "more":
                # Show next batch of states
                start = state.get("state_page", 0) * 10
                states_batch = INDIAN_STATES[start:start+10]
                msg_text = "📍 *Select State (continued):*\n\n"
                msg_text += "\n".join([f"{start+i+1}. {s}" for i, s in enumerate(states_batch)])
                if start + 10 < len(INDIAN_STATES):
                    msg_text += "\n\nType 'more' for more states"
                reply.body(msg_text)
                state["state_page"] = state.get("state_page", 0) + 1
            elif msg.isdigit() and 1 <= int(msg) <= len(INDIAN_STATES):
                state["location_state"] = INDIAN_STATES[int(msg) - 1]
                reply.body(get_message(lang, "location_city"))
                state["step"] = "location_city"
            elif msg.title() in INDIAN_STATES:
                state["location_state"] = msg.title()
                reply.body(get_message(lang, "location_city"))
                state["step"] = "location_city"
            else:
                reply.body(get_message(lang, "invalid_input"))
        
        # STEP 6: Location - City
        elif state.get("step") == "location_city":
            state["location_city"] = msg.title()
            reply.body(get_message(lang, "description"))
            state["step"] = "description"
        
        # STEP 7: Incident Description
        elif state.get("step") == "description":
            state["description"] = msg
            state["evidence_hash"] = hash_evidence(msg)
            reply.body(get_message(lang, "suspect_details"))
            state["step"] = "suspect_details"
        
        # STEP 8: Suspect Details
        elif state.get("step") == "suspect_details":
            # Parse suspect details (simple parsing, can be enhanced)
            details = msg.lower()
            state["suspect_other"] = msg
            
            # Try to extract phone, email, UPI
            import re
            phone_match = re.search(r'\+?[\d\s-]{10,}', msg)
            email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', msg)
            upi_match = re.search(r'[\w\.-]+@[\w]+', msg)
            
            if phone_match:
                state["suspect_phone"] = phone_match.group()
            if email_match:
                state["suspect_email"] = email_match.group()
            if upi_match and '@' in upi_match.group():
                state["suspect_upi"] = upi_match.group()
            
            reply.body(get_message(lang, "amount"))
            state["step"] = "amount"
        
        # STEP 9: Amount Involved
        elif state.get("step") == "amount":
            try:
                state["amount"] = float(msg.replace(",", "").replace("₹", "").strip())
            except:
                state["amount"] = 0
            
            reply.body(get_message(lang, "evidence"))
            state["step"] = "evidence"
        
        # STEP 10: Evidence Upload
        elif state.get("step") == "evidence":
            media_files = []
            
            if msg.lower() != "skip" and num_media > 0:
                # Download and save media files
                for i in range(num_media):
                    media_url = request.values.get(f"MediaUrl{i}")
                    media_type = request.values.get(f"MediaContentType{i}")
                    
                    if media_url:
                        media_data = download_whatsapp_media(media_url)
                        if media_data:
                            # Generate filename
                            ext = media_type.split('/')[-1] if '/' in media_type else 'jpg'
                            filename = f"{phone.replace(':', '_')}_{int(datetime.now().timestamp())}_{i}.{ext}"
                            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                            
                            with open(filepath, 'wb') as f:
                                f.write(media_data)
                            
                            media_files.append(filepath)
            
            state["media_files"] = media_files
            state["evidence_text"] = msg if msg.lower() != "skip" else ""
            
            reply.body(get_message(lang, "anonymous"))
            state["step"] = "anonymous"
        
        # STEP 11: Anonymous Option
        elif state.get("step") == "anonymous":
            if msg in ["1", "2"]:
                state["anonymous"] = "YES" if msg == "1" else "NO"
                state["phone"] = "ANONYMOUS" if msg == "1" else phone
                
                # Save the report
                reference_id = save_report(state)
                
                # Send confirmation
                reply.body(get_message(lang, "confirmation", reference_id=reference_id))
                
                # Clear state
                user_state.pop(phone, None)
            else:
                reply.body(get_message(lang, "invalid_input"))
        
        else:
            reply.body(get_message(lang, "welcome"))
            state["step"] = "welcome"
    
    except Exception as e:
        print(f"Error in WhatsApp bot: {e}")
        reply.body(get_message(lang, "error"))
        log_audit("BOT_ERROR", details={"error": str(e), "phone": phone})
    
    return str(resp)

# =============================================================================
# ADMIN API ENDPOINTS
# =============================================================================

def check_admin_auth():
    """Check if user is authenticated as admin"""
    if 'admin_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return None

@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    """Admin login"""
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    # Hash password
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    conn = get_db()
    c = conn.cursor()
    admin = c.execute("""
        SELECT * FROM admin_users 
        WHERE username = ? AND password_hash = ? AND is_active = 1
    """, (username, password_hash)).fetchone()
    
    if admin:
        # Update last login
        c.execute("""
            UPDATE admin_users SET last_login = ? WHERE id = ?
        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), admin['id']))
        conn.commit()
        
        session['admin_id'] = admin['id']
        session['admin_username'] = admin['username']
        session['admin_role'] = admin['role']
        
        log_audit("ADMIN_LOGIN", user_id=admin['id'])
        
        conn.close()
        return jsonify({
            "success": True,
            "admin": {
                "id": admin['id'],
                "username": admin['username'],
                "full_name": admin['full_name'],
                "role": admin['role']
            }
        })
    
    conn.close()
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/admin/logout", methods=["POST"])
def admin_logout():
    """Admin logout"""
    admin_id = session.get('admin_id')
    session.clear()
    if admin_id:
        log_audit("ADMIN_LOGOUT", user_id=admin_id)
    return jsonify({"success": True})

@app.route("/api/admin/reports", methods=["GET"])
def get_reports():
    """Get all reports with filters"""
    auth_check = check_admin_auth()
    if auth_check:
        return auth_check
    
    # Get query parameters
    status = request.args.get('status')
    fraud_medium = request.args.get('fraud_medium')
    state = request.args.get('state')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    search = request.args.get('search')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    
    conn = get_db()
    c = conn.cursor()
    
    # Build query
    query = "SELECT * FROM cyber_reports WHERE 1=1"
    params = []
    
    if status:
        query += " AND status = ?"
        params.append(status)
    if fraud_medium:
        query += " AND fraud_medium = ?"
        params.append(fraud_medium)
    if state:
        query += " AND location_state = ?"
        params.append(state)
    if date_from:
        query += " AND created_at >= ?"
        params.append(date_from)
    if date_to:
        query += " AND created_at <= ?"
        params.append(date_to + " 23:59:59")
    if search:
        query += " AND (reference_id LIKE ? OR incident_description LIKE ? OR suspect_phone LIKE ?)"
        search_term = f"%{search}%"
        params.extend([search_term, search_term, search_term])
    
    # Get total count
    count_query = query.replace("SELECT *", "SELECT COUNT(*)")
    total = c.execute(count_query, params).fetchone()[0]
    
    # Add pagination
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([per_page, (page - 1) * per_page])
    
    reports = c.execute(query, params).fetchall()
    conn.close()
    
    return jsonify({
        "reports": [dict(r) for r in reports],
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page
    })

@app.route("/api/admin/reports/<int:report_id>", methods=["GET"])
def get_report_details(report_id):
    """Get detailed report information"""
    auth_check = check_admin_auth()
    if auth_check:
        return auth_check
    
    conn = get_db()
    c = conn.cursor()
    
    report = c.execute("SELECT * FROM cyber_reports WHERE id = ?", (report_id,)).fetchone()
    
    if not report:
        conn.close()
        return jsonify({"error": "Report not found"}), 404
    
    # Get case notes
    notes = c.execute("""
        SELECT cn.*, au.username, au.full_name 
        FROM case_notes cn
        JOIN admin_users au ON cn.admin_id = au.id
        WHERE cn.report_id = ?
        ORDER BY cn.created_at DESC
    """, (report_id,)).fetchall()
    
    conn.close()
    
    return jsonify({
        "report": dict(report),
        "notes": [dict(n) for n in notes]
    })

@app.route("/api/admin/reports/<int:report_id>/status", methods=["PUT"])
def update_report_status(report_id):
    """Update report status"""
    auth_check = check_admin_auth()
    if auth_check:
        return auth_check
    
    data = request.json
    new_status = data.get('status')
    priority = data.get('priority')
    
    if not new_status:
        return jsonify({"error": "Status required"}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    updates = ["status = ?", "updated_at = ?"]
    params = [new_status, datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
    
    if priority:
        updates.append("priority = ?")
        params.append(priority)
    
    if new_status == "RESOLVED":
        updates.append("resolved_at = ?")
        params.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    params.append(report_id)
    
    c.execute(f"UPDATE cyber_reports SET {', '.join(updates)} WHERE id = ?", params)
    conn.commit()
    conn.close()
    
    log_audit("REPORT_STATUS_UPDATED", "cyber_reports", report_id, 
              user_id=session.get('admin_id'),
              details={"new_status": new_status, "priority": priority})
    
    return jsonify({"success": True})

@app.route("/api/admin/reports/<int:report_id>/notes", methods=["POST"])
def add_case_note(report_id):
    """Add note to case"""
    auth_check = check_admin_auth()
    if auth_check:
        return auth_check
    
    data = request.json
    note_text = data.get('note')
    note_type = data.get('type', 'COMMENT')
    
    if not note_text:
        return jsonify({"error": "Note text required"}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    c.execute("""
        INSERT INTO case_notes (report_id, admin_id, note, note_type, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        report_id,
        session['admin_id'],
        note_text,
        note_type,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    
    conn.commit()
    conn.close()
    
    log_audit("CASE_NOTE_ADDED", "case_notes", report_id, user_id=session['admin_id'])
    
    return jsonify({"success": True})

@app.route("/api/admin/analytics/overview", methods=["GET"])
def get_analytics_overview():
    """Get analytics overview"""
    auth_check = check_admin_auth()
    if auth_check:
        return auth_check
    
    conn = get_db()
    c = conn.cursor()
    
    # Total reports
    total_reports = c.execute("SELECT COUNT(*) FROM cyber_reports").fetchone()[0]
    
    # Reports by status
    status_counts = c.execute("""
        SELECT status, COUNT(*) as count 
        FROM cyber_reports 
        GROUP BY status
    """).fetchall()
    
    # Reports by fraud medium
    fraud_medium_counts = c.execute("""
        SELECT fraud_medium, COUNT(*) as count 
        FROM cyber_reports 
        GROUP BY fraud_medium 
        ORDER BY count DESC
    """).fetchall()
    
    # Reports by state (top 10)
    state_counts = c.execute("""
        SELECT location_state, COUNT(*) as count 
        FROM cyber_reports 
        GROUP BY location_state 
        ORDER BY count DESC 
        LIMIT 10
    """).fetchall()
    
    # Daily trend (last 30 days)
    daily_trend = c.execute("""
        SELECT DATE(created_at) as date, COUNT(*) as count 
        FROM cyber_reports 
        WHERE created_at >= date('now', '-30 days')
        GROUP BY DATE(created_at)
        ORDER BY date
    """).fetchall()
    
    # Total amount involved
    total_amount = c.execute("""
        SELECT SUM(amount_involved) FROM cyber_reports WHERE amount_involved > 0
    """).fetchone()[0] or 0
    
    conn.close()
    
    return jsonify({
        "total_reports": total_reports,
        "status_breakdown": [dict(r) for r in status_counts],
        "fraud_medium_breakdown": [dict(r) for r in fraud_medium_counts],
        "state_breakdown": [dict(r) for r in state_counts],
        "daily_trend": [dict(r) for r in daily_trend],
        "total_amount_involved": total_amount
    })

@app.route("/api/admin/export", methods=["GET"])
def export_reports():
    """Export reports to CSV"""
    auth_check = check_admin_auth()
    if auth_check:
        return auth_check
    
    import csv
    from io import StringIO
    
    conn = get_db()
    c = conn.cursor()
    reports = c.execute("SELECT * FROM cyber_reports ORDER BY created_at DESC").fetchall()
    conn.close()
    
    # Create CSV
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'ID', 'Reference ID', 'Phone', 'Location State', 'Location City',
        'Fraud Medium', 'Incident Type', 'Description', 'Amount', 'Status',
        'Created At'
    ])
    
    # Write rows
    for r in reports:
        writer.writerow([
            r['id'], r['reference_id'], r['phone'], r['location_state'],
            r['location_city'], r['fraud_medium'], r['incident_type'],
            r['incident_description'], r['amount_involved'], r['status'],
            r['created_at']
        ])
    
    output.seek(0)
    
    log_audit("REPORTS_EXPORTED", user_id=session.get('admin_id'))
    
    return output.getvalue(), 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': f'attachment; filename=cyber_reports_{datetime.now().strftime("%Y%m%d")}.csv'
    }

# =============================================================================
# HEALTH CHECK
# =============================================================================

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "I4C Cyber Reporting Bot"
    })

@app.route("/debug/db")
def debug_db():
    import sqlite3
    conn = sqlite3.connect("cyber_reports.db")
    c = conn.cursor()
    
    c.execute("SELECT id, fraud_medium, incident_type, created_at FROM cyber_reports ORDER BY id DESC LIMIT 10")
    rows = c.fetchall()
    conn.close()
    return {"rows": rows}

if __name__ == "__main__":
    # Initialize database if it doesn't exist
    if not os.path.exists(app.config['DATABASE_PATH']):
        print("Database not found. Please run db_init.py first!")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
