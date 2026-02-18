import psycopg2
import os
from datetime import datetime

def init_database():
    conn = psycopg2.connect(os.getenv("DATABASE_URL"))
    c = conn.cursor()

    # Main reports table with all I4C required fields
    c.execute("""
    CREATE TABLE IF NOT EXISTS cyber_reports (
        id SERIAL PRIMARY KEY,
        
        -- User Information
        phone TEXT,
        location_city TEXT,
        location_state TEXT,
        language_preference TEXT DEFAULT 'en',
        
        -- Fraud Classification
        fraud_medium TEXT NOT NULL,  -- Phone, Email, UPI, SMS, Social Media, Bank, E-commerce
        incident_type TEXT NOT NULL,  -- Phishing, Scam, Fraud, Fake Profile, Malware, Other
        incident_description TEXT,
        incident_date TEXT,
        incident_time TEXT,
        
        -- Suspect Information
        suspect_phone TEXT,
        suspect_email TEXT,
        suspect_upi_id TEXT,
        suspect_account_number TEXT,
        suspect_bank_name TEXT,
        suspect_social_media TEXT,
        suspect_website_url TEXT,
        suspect_other_details TEXT,
        
        -- Transaction Details (if financial fraud)
        transaction_id TEXT,
        amount_involved REAL,
        payment_method TEXT,
        
        -- Evidence
        evidence_text TEXT,
        evidence_hash TEXT,
        media_files TEXT,  -- JSON array of file paths
        
        -- Metadata
        anonymous TEXT DEFAULT 'NO',
        reference_id TEXT UNIQUE NOT NULL,
        status TEXT DEFAULT 'NEW',  -- NEW, IN_PROGRESS, ESCALATED, RESOLVED, CLOSED
        priority TEXT DEFAULT 'MEDIUM',  -- LOW, MEDIUM, HIGH, CRITICAL
        assigned_to TEXT,
        
        -- I4C Integration
        i4c_synced INTEGER DEFAULT 0,
        i4c_case_id TEXT,
        ncrp_complaint_id TEXT,
        
        -- Timestamps
        created_at TEXT NOT NULL,
        updated_at TEXT,
        resolved_at TEXT,
        
        -- DPDP Compliance
        consent_given INTEGER DEFAULT 0,
        data_retention_date TEXT,
        deletion_requested INTEGER DEFAULT 0
    )
    """)

    # Admin users table
    c.execute("""
    CREATE TABLE IF NOT EXISTS admin_users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT,
        email TEXT,
        role TEXT DEFAULT 'VIEWER',  -- VIEWER, ANALYST, ADMIN, SUPER_ADMIN
        is_active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL,
        last_login TEXT
    )
    """)

    # Case notes/comments table
    c.execute("""
    CREATE TABLE IF NOT EXISTS case_notes (
        id SERIAL PRIMARY KEY,
        report_id INTEGER NOT NULL,
        admin_id INTEGER NOT NULL,
        note TEXT NOT NULL,
        note_type TEXT DEFAULT 'COMMENT',  -- COMMENT, STATUS_UPDATE, ESCALATION
        created_at TEXT NOT NULL,
        FOREIGN KEY (report_id) REFERENCES cyber_reports(id),
        FOREIGN KEY (admin_id) REFERENCES admin_users(id)
    )
    """)

    # Audit log for DPDP compliance
    c.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id SERIAL PRIMARY KEY,
        action TEXT NOT NULL,
        table_name TEXT,
        record_id INTEGER,
        user_id INTEGER,
        user_phone TEXT,
        ip_address TEXT,
        details TEXT,
        timestamp TEXT NOT NULL
    )
    """)

    # Analytics cache table
    c.execute("""
    CREATE TABLE IF NOT EXISTS analytics_cache (
        id SERIAL PRIMARY KEY,
        metric_name TEXT NOT NULL,
        metric_value TEXT,
        calculated_at TEXT NOT NULL,
        valid_until TEXT
    )
    """)

    # User consent records for DPDP
    c.execute("""
    CREATE TABLE IF NOT EXISTS user_consents (
        id SERIAL PRIMARY KEY,
        phone TEXT NOT NULL,
        consent_type TEXT NOT NULL,  -- DATA_COLLECTION, DATA_SHARING, COMMUNICATION
        consent_given INTEGER DEFAULT 1,
        consent_date TEXT NOT NULL,
        withdrawal_date TEXT
    )
    """)

    # Create indexes for performance
    c.execute("CREATE INDEX IF NOT EXISTS idx_reports_status ON cyber_reports(status)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_reports_created ON cyber_reports(created_at)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_reports_fraud_medium ON cyber_reports(fraud_medium)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_reports_location ON cyber_reports(location_state, location_city)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_reports_reference ON cyber_reports(reference_id)")

    # Insert default admin user (password: admin123)
    # In production, use proper password hashing with bcrypt
    import hashlib
    admin_pass = hashlib.sha256("admin123".encode()).hexdigest()
    
    try:
        c.execute("""
            INSERT INTO admin_users (username, password_hash, full_name, email, role, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            "admin",
            admin_pass,
            "System Administrator",
            "admin@i4c.gov.in",
            "SUPER_ADMIN",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
    except psycopg2.IntegrityError:
        print("Default admin user already exists")

    conn.commit()
    conn.close()
    print("✅ Database initialized successfully with all I4C requirements!")
    print("📊 Tables created: cyber_reports, admin_users, case_notes, audit_log, analytics_cache, user_consents")
    print("🔐 Default admin credentials: username=admin, password=admin123 (CHANGE IN PRODUCTION!)")

if __name__ == "__main__":
    init_database()
