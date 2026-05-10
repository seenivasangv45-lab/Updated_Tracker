import os, secrets, sqlite3, json, csv, io, random
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, send_file, g, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(hours=12)

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'production.db')
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

TAT_HOURS = 48  # 48-hour TAT requirement

# ─── Database ─────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db: db.close()

def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    c = db.cursor()
    c.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('SuperAdmin','Admin','User','Auditor')),
        user_type TEXT DEFAULT NULL CHECK(user_type IN ('Coder','Biller',NULL)),
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        created_by INTEGER
    );

    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        invoice_number TEXT UNIQUE NOT NULL,
        encounter_id TEXT,
        patient_number TEXT,
        patient_name TEXT,
        payer_name TEXT,
        location TEXT,
        provider TEXT,
        total_charge TEXT,
        withhold_code TEXT,
        date_of_service DATE,
        cpt_codes TEXT,
        icd10_codes TEXT,
        diagnosis TEXT,
        notes TEXT,
        first_upload_at TIMESTAMP,
        tat_deadline TIMESTAMP,
        upload_date DATE DEFAULT (date('now')),
        status TEXT DEFAULT 'Unassigned' CHECK(status IN (
            'Unassigned','Assigned','In-Process','Pending','Completed',
            'Assigned to Biller','Billing In Progress','Finalized',
            'Rework - Coder','Rework - Biller','Clarification Needed',
            'Audited - Passed','Audited - Failed','Cancelled'
        )),
        priority TEXT DEFAULT 'Medium' CHECK(priority IN ('Low','Medium','High')),
        assigned_coder_id INTEGER,
        assigned_biller_id INTEGER,
        coder_comments TEXT,
        biller_comments TEXT,
        auditor_id INTEGER,
        auditor_comments TEXT,
        audit_status TEXT CHECK(audit_status IN ('Passed','Failed',NULL)),
        coded_at TIMESTAMP,
        billed_at TIMESTAMP,
        finalized_at TIMESTAMP,
        audited_at TIMESTAMP,
        upload_batch_id INTEGER,
        extra_data TEXT
    );

    CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id INTEGER,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS upload_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        batch_name TEXT NOT NULL,
        filename TEXT NOT NULL,
        records_added INTEGER DEFAULT 0,
        duplicates_skipped INTEGER DEFAULT 0,
        uploaded_by INTEGER,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_acc_inv ON accounts(invoice_number);
    CREATE INDEX IF NOT EXISTS idx_acc_enc ON accounts(encounter_id);
    CREATE INDEX IF NOT EXISTS idx_acc_status ON accounts(status);
    CREATE INDEX IF NOT EXISTS idx_acc_coder ON accounts(assigned_coder_id);
    CREATE INDEX IF NOT EXISTS idx_acc_biller ON accounts(assigned_biller_id);
    CREATE INDEX IF NOT EXISTS idx_acc_priority ON accounts(priority);
    CREATE INDEX IF NOT EXISTS idx_acc_upload ON accounts(upload_date);
    CREATE INDEX IF NOT EXISTS idx_acc_batch ON accounts(upload_batch_id);
    ''')
    
    # Default SuperAdmin
    existing = c.execute("SELECT id FROM users WHERE username='superadmin'").fetchone()
    if not existing:
        c.execute("INSERT INTO users (username,password_hash,full_name,role) VALUES (?,?,?,?)",
            ('superadmin', generate_password_hash('Super@123', method='pbkdf2:sha256:260000'), 'Super Administrator', 'SuperAdmin'))
    # Default Admin
    existing = c.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not existing:
        c.execute("INSERT INTO users (username,password_hash,full_name,role) VALUES (?,?,?,?)",
            ('admin', generate_password_hash('Admin@123', method='pbkdf2:sha256:260000'), 'System Administrator', 'Admin'))
    db.commit()
    db.close()

init_db()

# ─── Auth Decorators ──────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*a, **kw):
        if 'user_id' not in session:
            flash('Please log in.', 'warning')
            return redirect(url_for('login'))
        return f(*a, **kw)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*a, **kw):
        if 'user_id' not in session: return redirect(url_for('login'))
        if session.get('role') not in ('SuperAdmin', 'Admin', 'Auditor'):
            flash('Access denied.', 'error')
            return redirect(url_for('dashboard'))
        return f(*a, **kw)
    return decorated

def superadmin_required(f):
    @wraps(f)
    def decorated(*a, **kw):
        if 'user_id' not in session: return redirect(url_for('login'))
        if session.get('role') != 'SuperAdmin':
            flash('Super Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*a, **kw)
    return decorated

def auditor_required(f):
    @wraps(f)
    def decorated(*a, **kw):
        if 'user_id' not in session: return redirect(url_for('login'))
        if session.get('role') not in ('SuperAdmin', 'Auditor', 'Admin'):
            flash('Access denied.', 'error')
            return redirect(url_for('dashboard'))
        return f(*a, **kw)
    return decorated

def can_delete():
    """Only SuperAdmin can delete."""
    return session.get('role') == 'SuperAdmin'

@app.context_processor
def inject_helpers():
    return {'can_delete': can_delete}

def log_activity(account_id, user_id, action, details=None):
    db = get_db()
    db.execute("INSERT INTO activity_log (account_id,user_id,action,details) VALUES (?,?,?,?)",
               (account_id, user_id, action, details))
    db.commit()

def generate_batch_name(db):
    """Auto-generate batch name: FIN14-YYYYMMDD-NN"""
    today = datetime.now().strftime('%Y%m%d')
    count = db.execute("SELECT COUNT(*) FROM upload_history WHERE batch_name LIKE ?", (f'FIN14-{today}-%',)).fetchone()[0]
    return f'FIN14-{today}-{count+1:02d}'

# ─── Routes ───────────────────────────────────────────────────────────
@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'user_id' in session else url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username','').strip()
        p = request.form.get('password','')
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=? AND is_active=1", (u,)).fetchone()
        if user and check_password_hash(user['password_hash'], p):
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user['full_name']
            session['role'] = user['role']
            session['user_type'] = user['user_type']
            db.execute("UPDATE users SET last_login=? WHERE id=?", (datetime.now().isoformat(), user['id']))
            db.commit()
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/change-password', methods=['GET','POST'])
@login_required
def change_password():
    if request.method == 'POST':
        cur = request.form.get('current_password','')
        new = request.form.get('new_password','')
        confirm = request.form.get('confirm_password','')
        if new != confirm:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('change_password'))
        if len(new) < 8:
            flash('Minimum 8 characters.', 'error')
            return redirect(url_for('change_password'))
        db = get_db()
        user = db.execute("SELECT password_hash FROM users WHERE id=?", (session['user_id'],)).fetchone()
        if not check_password_hash(user['password_hash'], cur):
            flash('Current password incorrect.', 'error')
            return redirect(url_for('change_password'))
        db.execute("UPDATE users SET password_hash=? WHERE id=?",
                   (generate_password_hash(new, method='pbkdf2:sha256:260000'), session['user_id']))
        db.commit()
        flash('Password changed.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('change_password.html')

# ─── Global Search ────────────────────────────────────────────────────
@app.route('/search')
@login_required
def global_search():
    q = request.args.get('q', '').strip()
    if not q:
        return redirect(url_for('dashboard'))
    db = get_db()
    results = db.execute("""
        SELECT a.*, c.full_name as coder_name, b.full_name as biller_name
        FROM accounts a LEFT JOIN users c ON a.assigned_coder_id=c.id
        LEFT JOIN users b ON a.assigned_biller_id=b.id
        WHERE a.invoice_number LIKE ? OR a.encounter_id LIKE ? OR a.patient_name LIKE ? OR a.patient_number LIKE ?
        ORDER BY a.upload_date DESC LIMIT 100
    """, (f'%{q}%',)*4).fetchall()
    return render_template('search_results.html', results=results, query=q)

# ─── Dashboard ────────────────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    role = session['role']
    uid = session['user_id']
    utype = session.get('user_type')
    today = datetime.now().strftime('%Y-%m-%d')
    data = {}

    data['total_inventory'] = db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
    data['total_completed'] = db.execute("SELECT COUNT(*) FROM accounts WHERE status IN ('Completed','Finalized','Audited - Passed')").fetchone()[0]
    data['high_priority_pending'] = db.execute("SELECT COUNT(*) FROM accounts WHERE priority='High' AND status NOT IN ('Completed','Finalized','Audited - Passed','Cancelled')").fetchone()[0]
    data['remaining'] = db.execute("SELECT COUNT(*) FROM accounts WHERE status NOT IN ('Completed','Finalized','Audited - Passed','Cancelled')").fetchone()[0]
    data['today_received'] = db.execute("SELECT COUNT(*) FROM accounts WHERE upload_date=?", (today,)).fetchone()[0]
    data['within_tat'] = db.execute("SELECT COUNT(*) FROM accounts WHERE tat_deadline IS NOT NULL AND datetime('now') <= tat_deadline AND status NOT IN ('Completed','Finalized','Audited - Passed','Cancelled')").fetchone()[0]
    data['breached_tat'] = db.execute("SELECT COUNT(*) FROM accounts WHERE tat_deadline IS NOT NULL AND datetime('now') > tat_deadline AND status NOT IN ('Completed','Finalized','Audited - Passed','Cancelled')").fetchone()[0]

    if role == 'User' and utype == 'Coder':
        # Coder bucket: includes Pending and In-Process
        data['my_assigned'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_coder_id=? AND status IN ('Assigned','In-Process','Pending','Rework - Coder','Clarification Needed')", (uid,)).fetchone()[0]
        data['my_completed'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_coder_id=? AND coded_at IS NOT NULL", (uid,)).fetchone()[0]
        data['my_high'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_coder_id=? AND priority='High' AND status IN ('Assigned','In-Process','Pending','Rework - Coder')", (uid,)).fetchone()[0]
        data['my_rework'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_coder_id=? AND status='Rework - Coder'", (uid,)).fetchone()[0]
        audited = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_coder_id=? AND audit_status IS NOT NULL", (uid,)).fetchone()[0]
        passed = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_coder_id=? AND audit_status='Passed'", (uid,)).fetchone()[0]
        data['my_quality'] = round(passed/audited*100, 1) if audited > 0 else 0
        data['my_audited'] = audited
    elif role == 'User' and utype == 'Biller':
        data['my_assigned'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_biller_id=? AND status IN ('Assigned to Biller','Billing In Progress','Rework - Biller')", (uid,)).fetchone()[0]
        data['my_completed'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_biller_id=? AND billed_at IS NOT NULL", (uid,)).fetchone()[0]
        data['my_high'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_biller_id=? AND priority='High' AND status IN ('Assigned to Biller','Billing In Progress')", (uid,)).fetchone()[0]
        data['my_rework'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_biller_id=? AND status='Rework - Biller'", (uid,)).fetchone()[0]
        audited = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_biller_id=? AND audit_status IS NOT NULL", (uid,)).fetchone()[0]
        passed = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_biller_id=? AND audit_status='Passed'", (uid,)).fetchone()[0]
        data['my_quality'] = round(passed/audited*100, 1) if audited > 0 else 0
        data['my_audited'] = audited

    if role in ('SuperAdmin', 'Admin', 'Auditor'):
        data['unassigned'] = db.execute("SELECT COUNT(*) FROM accounts WHERE status='Unassigned'").fetchone()[0]
        data['coding_pending'] = db.execute("SELECT COUNT(*) FROM accounts WHERE status IN ('Assigned','In-Process','Pending')").fetchone()[0]
        data['billing_pending'] = db.execute("SELECT COUNT(*) FROM accounts WHERE status IN ('Assigned to Biller','Billing In Progress')").fetchone()[0]
        data['rework_pending'] = db.execute("SELECT COUNT(*) FROM accounts WHERE status IN ('Rework - Coder','Rework - Biller')").fetchone()[0]
        data['audit_total'] = db.execute("SELECT COUNT(*) FROM accounts WHERE audit_status IS NOT NULL").fetchone()[0]
        data['audit_passed'] = db.execute("SELECT COUNT(*) FROM accounts WHERE audit_status='Passed'").fetchone()[0]
        data['audit_failed'] = db.execute("SELECT COUNT(*) FROM accounts WHERE audit_status='Failed'").fetchone()[0]
        data['coder_workload'] = db.execute("""
            SELECT u.full_name, 
            SUM(CASE WHEN a.status IN ('Assigned','In-Process','Pending','Rework - Coder') THEN 1 ELSE 0 END) as pending,
            SUM(CASE WHEN a.coded_at IS NOT NULL THEN 1 ELSE 0 END) as completed,
            SUM(CASE WHEN a.priority='High' AND a.status IN ('Assigned','In-Process','Pending','Rework - Coder') THEN 1 ELSE 0 END) as high_pri
            FROM users u LEFT JOIN accounts a ON u.id=a.assigned_coder_id
            WHERE u.user_type='Coder' AND u.is_active=1
            GROUP BY u.id ORDER BY pending DESC
        """).fetchall()

    rework_alerts = []
    if role == 'User' and utype == 'Coder':
        rework_alerts = db.execute("SELECT id, invoice_number, auditor_comments FROM accounts WHERE assigned_coder_id=? AND status='Rework - Coder'", (uid,)).fetchall()

    return render_template('dashboard.html', data=data, rework_alerts=rework_alerts)

# ─── Coding Review (split-pane work queue + claim detail) ───────────
@app.route('/coding-review')
@login_required
def coding_review():
    db = get_db()
    uid = session['user_id']
    role = session['role']
    utype = session.get('user_type')
    
    status_filter = request.args.get('status', '').strip()
    selected_id = request.args.get('account_id', type=int)
    
    # Build coder bucket
    if role == 'User' and utype == 'Coder':
        base_where = "a.assigned_coder_id=? AND a.status IN ('Assigned','In-Process','Pending','Rework - Coder','Clarification Needed')"
        params = [uid]
    elif role == 'User' and utype == 'Biller':
        base_where = "a.assigned_biller_id=? AND a.status IN ('Assigned to Biller','Billing In Progress','Rework - Biller')"
        params = [uid]
    else:
        base_where = "a.status IN ('Assigned','In-Process','Pending','Rework - Coder','Assigned to Biller','Billing In Progress','Rework - Biller')"
        params = []
    
    if status_filter:
        base_where += " AND a.status=?"
        params.append(status_filter)
    
    accounts = db.execute(f"""
        SELECT a.* FROM accounts a
        WHERE {base_where}
        ORDER BY 
            CASE WHEN a.priority='High' THEN 0 WHEN a.priority='Medium' THEN 1 ELSE 2 END,
            a.first_upload_at ASC
    """, params).fetchall()
    
    # Stats
    stats = {}
    if role == 'User' and utype == 'Coder':
        stats['total_assigned'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_coder_id=? AND status IN ('Assigned','In-Process','Pending','Rework - Coder','Clarification Needed','Completed')", (uid,)).fetchone()[0]
        stats['completed'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_coder_id=? AND status='Completed'", (uid,)).fetchone()[0]
        stats['in_process'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_coder_id=? AND status='In-Process'", (uid,)).fetchone()[0]
        stats['pending'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_coder_id=? AND status IN ('Pending','Assigned')", (uid,)).fetchone()[0]
        stats['high_priority'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_coder_id=? AND priority='High' AND status IN ('Assigned','In-Process','Pending','Rework - Coder')", (uid,)).fetchone()[0]
    elif role == 'User' and utype == 'Biller':
        stats['total_assigned'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_biller_id=? AND status IN ('Assigned to Biller','Billing In Progress','Rework - Biller','Finalized')", (uid,)).fetchone()[0]
        stats['completed'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_biller_id=? AND status='Finalized'", (uid,)).fetchone()[0]
        stats['in_process'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_biller_id=? AND status='Billing In Progress'", (uid,)).fetchone()[0]
        stats['pending'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_biller_id=? AND status='Assigned to Biller'", (uid,)).fetchone()[0]
        stats['high_priority'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_biller_id=? AND priority='High' AND status IN ('Assigned to Biller','Billing In Progress')", (uid,)).fetchone()[0]
    else:
        stats = {'total_assigned': len(accounts), 'completed': 0, 'in_process': 0, 'pending': 0, 'high_priority': sum(1 for a in accounts if a['priority']=='High')}
    
    # Selected claim detail
    selected = None
    if selected_id:
        selected = db.execute("SELECT * FROM accounts WHERE id=?", (selected_id,)).fetchone()
    elif accounts:
        selected = db.execute("SELECT * FROM accounts WHERE id=?", (accounts[0]['id'],)).fetchone()
    
    return render_template('coding_review.html', accounts=accounts, stats=stats, 
                           selected=selected, status_filter=status_filter)

# ─── Save Claim Detail ──────────────────────────────────────────────
@app.route('/account/<int:account_id>/save-claim', methods=['POST'])
@login_required
def save_claim_detail(account_id):
    db = get_db()
    account = db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
    if not account:
        flash('Account not found.', 'error')
        return redirect(url_for('coding_review'))
    
    payer = request.form.get('payer_name','').strip()
    dos = request.form.get('date_of_service','').strip()
    invoice = request.form.get('invoice_number','').strip()
    provider = request.form.get('provider','').strip()
    cpt = request.form.get('cpt_codes','').strip()
    icd = request.form.get('icd10_codes','').strip()
    total = request.form.get('total_charge','').strip()
    diagnosis = request.form.get('diagnosis','').strip()
    notes = request.form.get('notes','').strip()
    coder_comments = request.form.get('coder_comments','').strip()
    new_status = request.form.get('claim_status','').strip()
    
    db.execute("""UPDATE accounts SET payer_name=?, date_of_service=?, provider=?, 
                  cpt_codes=?, icd10_codes=?, total_charge=?, diagnosis=?, notes=?, 
                  coder_comments=? WHERE id=?""",
               (payer, dos or None, provider, cpt, icd, total, diagnosis, notes, coder_comments, account_id))
    
    if new_status:
        old = account['status']
        # If completing
        if new_status == 'Completed' and session.get('user_type') == 'Coder':
            db.execute("UPDATE accounts SET status='Completed', coded_at=? WHERE id=?",
                       (datetime.now().isoformat(), account_id))
            log_activity(account_id, session['user_id'], 'Status: Completed', f'From {old}')
        else:
            db.execute("UPDATE accounts SET status=? WHERE id=?", (new_status, account_id))
            log_activity(account_id, session['user_id'], f'Status: {new_status}', f'From {old}')
    
    log_activity(account_id, session['user_id'], 'Claim Saved', '')
    db.commit()
    flash('Claim details saved.', 'success')
    
    # Redirect: try next account in queue
    next_q = request.form.get('next_action','same')
    if next_q == 'next':
        return redirect(url_for('get_next_priority'))
    return redirect(url_for('coding_review', account_id=account_id, status=request.form.get('current_filter','')))

# ─── Drill-down ──────────────────────────────────────────────────────
@app.route('/drill/<metric>')
@login_required
def drill_down(metric):
    db = get_db()
    uid = session['user_id']
    utype = session.get('user_type')
    title = metric.replace('_', ' ').title()
    
    filters = {
        'total_inventory': "1=1",
        'total_completed': "a.status IN ('Completed','Finalized','Audited - Passed')",
        'high_priority_pending': "a.priority='High' AND a.status NOT IN ('Completed','Finalized','Audited - Passed','Cancelled')",
        'remaining': "a.status NOT IN ('Completed','Finalized','Audited - Passed','Cancelled')",
        'within_tat': "a.tat_deadline IS NOT NULL AND datetime('now') <= a.tat_deadline AND a.status NOT IN ('Completed','Finalized','Audited - Passed','Cancelled')",
        'breached_tat': "a.tat_deadline IS NOT NULL AND datetime('now') > a.tat_deadline AND a.status NOT IN ('Completed','Finalized','Audited - Passed','Cancelled')",
        'unassigned': "a.status='Unassigned'",
        'my_assigned': f"a.assigned_coder_id={uid} AND a.status IN ('Assigned','In-Process','Pending','Rework - Coder','Clarification Needed')" if utype=='Coder' else f"a.assigned_biller_id={uid} AND a.status IN ('Assigned to Biller','Billing In Progress','Rework - Biller')",
        'my_completed': f"a.assigned_coder_id={uid} AND a.coded_at IS NOT NULL" if utype=='Coder' else f"a.assigned_biller_id={uid} AND a.billed_at IS NOT NULL",
        'my_high': f"a.assigned_coder_id={uid} AND a.priority='High' AND a.status IN ('Assigned','In-Process','Pending','Rework - Coder')" if utype=='Coder' else f"a.assigned_biller_id={uid} AND a.priority='High' AND a.status IN ('Assigned to Biller','Billing In Progress')",
        'my_rework': f"a.assigned_coder_id={uid} AND a.status='Rework - Coder'" if utype=='Coder' else f"a.assigned_biller_id={uid} AND a.status='Rework - Biller'",
        'coding_pending': "a.status IN ('Assigned','In-Process','Pending')",
        'billing_pending': "a.status IN ('Assigned to Biller','Billing In Progress')",
        'rework_pending': "a.status IN ('Rework - Coder','Rework - Biller')",
    }
    where = filters.get(metric, "1=1")
    accounts = db.execute(f"""
        SELECT a.*, c.full_name as coder_name, b.full_name as biller_name
        FROM accounts a LEFT JOIN users c ON a.assigned_coder_id=c.id
        LEFT JOIN users b ON a.assigned_biller_id=b.id
        WHERE {where}
        ORDER BY CASE WHEN a.priority='High' THEN 0 WHEN a.priority='Medium' THEN 1 ELSE 2 END, a.first_upload_at ASC
    """).fetchall()
    return render_template('drill_down.html', accounts=accounts, title=title, metric=metric)

# ─── Get Next Priority ───────────────────────────────────────────────
@app.route('/get-next-priority')
@login_required
def get_next_priority():
    db = get_db()
    uid = session['user_id']
    utype = session.get('user_type')
    
    if utype == 'Coder':
        acc = db.execute("""
            SELECT id FROM accounts WHERE assigned_coder_id=? 
            AND status IN ('Assigned','In-Process','Pending','Rework - Coder','Clarification Needed')
            ORDER BY 
                CASE WHEN priority='High' THEN 0 WHEN priority='Medium' THEN 1 ELSE 2 END, 
                first_upload_at ASC LIMIT 1
        """, (uid,)).fetchone()
    elif utype == 'Biller':
        acc = db.execute("""
            SELECT id FROM accounts WHERE assigned_biller_id=?
            AND status IN ('Assigned to Biller','Billing In Progress','Rework - Biller')
            ORDER BY CASE WHEN priority='High' THEN 0 WHEN priority='Medium' THEN 1 ELSE 2 END, first_upload_at ASC LIMIT 1
        """, (uid,)).fetchone()
    else:
        flash('Only Coders/Billers have a work queue.', 'info')
        return redirect(url_for('dashboard'))
    
    if acc:
        # Auto-mark In-Process if Assigned
        if utype == 'Coder':
            db.execute("UPDATE accounts SET status='In-Process' WHERE id=? AND status='Assigned'", (acc['id'],))
        elif utype == 'Biller':
            db.execute("UPDATE accounts SET status='Billing In Progress' WHERE id=? AND status='Assigned to Biller'", (acc['id'],))
        db.commit()
        return redirect(url_for('coding_review', account_id=acc['id']))
    flash('No pending accounts. You are all caught up!', 'success')
    return redirect(url_for('dashboard'))

# ─── User Management ─────────────────────────────────────────────────
@app.route('/users')
@admin_required
def users_list():
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY role, full_name").fetchall()
    return render_template('users.html', users=users)

@app.route('/users/add', methods=['GET','POST'])
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form.get('username','').strip().lower()
        password = request.form.get('password','')
        full_name = request.form.get('full_name','').strip()
        role = request.form.get('role','User')
        user_type = request.form.get('user_type') if role == 'User' else None
        if not username or not password or not full_name:
            flash('All fields required.', 'error')
            return redirect(url_for('add_user'))
        if len(password) < 8:
            flash('Min 8 characters.', 'error')
            return redirect(url_for('add_user'))
        # Only SuperAdmin can create SuperAdmin
        if role == 'SuperAdmin' and session.get('role') != 'SuperAdmin':
            flash('Only Super Admin can create Super Admin users.', 'error')
            return redirect(url_for('add_user'))
        db = get_db()
        try:
            db.execute("INSERT INTO users (username,password_hash,full_name,role,user_type,created_by) VALUES (?,?,?,?,?,?)",
                (username, generate_password_hash(password, method='pbkdf2:sha256:260000'), full_name, role, user_type, session['user_id']))
            db.commit()
            flash(f'User "{username}" created.', 'success')
            return redirect(url_for('users_list'))
        except sqlite3.IntegrityError:
            flash('Username exists.', 'error')
    return render_template('add_user.html')

@app.route('/users/edit/<int:user_id>', methods=['GET','POST'])
@admin_required
def edit_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('users_list'))
    if request.method == 'POST':
        full_name = request.form.get('full_name','').strip()
        role = request.form.get('role','User')
        user_type = request.form.get('user_type') if role == 'User' else None
        is_active = 1 if request.form.get('is_active') else 0
        new_pw = request.form.get('new_password','').strip()
        if role == 'SuperAdmin' and session.get('role') != 'SuperAdmin':
            flash('Only Super Admin can assign Super Admin role.', 'error')
            return redirect(url_for('edit_user', user_id=user_id))
        db.execute("UPDATE users SET full_name=?,role=?,user_type=?,is_active=? WHERE id=?",
                   (full_name, role, user_type, is_active, user_id))
        if new_pw:
            if len(new_pw) < 8:
                flash('Min 8 characters.', 'error')
                return redirect(url_for('edit_user', user_id=user_id))
            db.execute("UPDATE users SET password_hash=? WHERE id=?",
                       (generate_password_hash(new_pw, method='pbkdf2:sha256:260000'), user_id))
        db.commit()
        flash('User updated.', 'success')
        return redirect(url_for('users_list'))
    return render_template('edit_user.html', user=user)

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@superadmin_required
def delete_user(user_id):
    db = get_db()
    if user_id == session['user_id']:
        flash('Cannot delete yourself.', 'error')
        return redirect(url_for('users_list'))
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('users_list'))
    if user['username'] in ('admin', 'superadmin'):
        flash('Cannot delete default accounts.', 'error')
        return redirect(url_for('users_list'))
    active = db.execute("SELECT COUNT(*) FROM accounts WHERE (assigned_coder_id=? AND status IN ('Assigned','In-Process','Pending','Rework - Coder')) OR (assigned_biller_id=? AND status IN ('Assigned to Biller','Billing In Progress','Rework - Biller'))", (user_id, user_id)).fetchone()[0]
    if active > 0:
        flash(f'Cannot delete — {active} active accounts. Reassign first.', 'error')
        return redirect(url_for('users_list'))
    name = user['full_name']
    db.execute("UPDATE accounts SET assigned_coder_id=NULL WHERE assigned_coder_id=?", (user_id,))
    db.execute("UPDATE accounts SET assigned_biller_id=NULL WHERE assigned_biller_id=?", (user_id,))
    db.execute("UPDATE accounts SET auditor_id=NULL WHERE auditor_id=?", (user_id,))
    db.execute("UPDATE activity_log SET user_id=NULL WHERE user_id=?", (user_id,))
    db.execute("UPDATE upload_history SET uploaded_by=NULL WHERE uploaded_by=?", (user_id,))
    db.execute("UPDATE users SET created_by=NULL WHERE created_by=?", (user_id,))
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    log_activity(None, session['user_id'], 'User Deleted', f'Deleted: {name}')
    flash(f'User "{name}" deleted.', 'success')
    return redirect(url_for('users_list'))

# ─── Upload Inventory (FIN14) ────────────────────────────────────────
@app.route('/inventory/upload', methods=['GET','POST'])
@admin_required
def upload_inventory():
    db = get_db()
    if request.method == 'POST':
        file = request.files.get('file')
        priority = request.form.get('upload_priority', 'Medium')
        if not file or file.filename == '':
            flash('No file selected.', 'error')
            return redirect(url_for('upload_inventory'))
        
        filename = secure_filename(file.filename)
        content = file.stream.read().decode('utf-8', errors='replace')
        delimiter = '\t' if '\t' in content.split('\n')[0] else ','
        reader = csv.DictReader(io.StringIO(content), delimiter=delimiter)
        
        batch_name = generate_batch_name(db)
        db.execute("INSERT INTO upload_history (batch_name,filename,records_added,duplicates_skipped,uploaded_by) VALUES (?,?,0,0,?)",
                   (batch_name, filename, session['user_id']))
        batch_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        
        added = 0
        skipped = 0
        now_iso = datetime.now().isoformat()
        tat_deadline = (datetime.now() + timedelta(hours=TAT_HOURS)).isoformat()
        
        for row in reader:
            invoice = (row.get('Inv_Num') or row.get('Invoice Number') or row.get('invoice_number') or '').strip()
            if not invoice: continue
            
            existing = db.execute("SELECT id FROM accounts WHERE invoice_number=?", (invoice,)).fetchone()
            if existing:
                skipped += 1
                continue
            
            patient_name = (row.get('Pat_Name') or row.get('Patient Name') or '').strip()
            patient_num = (row.get('Pat_Num') or row.get('Patient Number') or '').strip()
            payer = (row.get('Payer_Name') or row.get('Payer') or '').strip()
            location = (row.get('textbox18') or row.get('Location') or '').strip()
            provider = (row.get('textbox24') or row.get('Provider') or '').strip()
            charge = (row.get('Total_Charge') or row.get('Total Charge') or '').strip()
            withhold = (row.get('Withhold_Code') or '').strip()
            dos_str = (row.get('textbox5') or row.get('DOS') or row.get('Date of Service') or '').strip()
            encounter = (row.get('Encounter_ID') or row.get('Encounter ID') or '').strip()
            
            parsed_date = None
            for fmt in ('%m/%d/%Y','%Y-%m-%d','%d/%m/%Y','%m-%d-%Y'):
                try:
                    parsed_date = datetime.strptime(dos_str, fmt).strftime('%Y-%m-%d')
                    break
                except: continue
            
            db.execute("""INSERT INTO accounts 
                (invoice_number,encounter_id,patient_number,patient_name,payer_name,location,provider,total_charge,withhold_code,date_of_service,priority,first_upload_at,tat_deadline,upload_batch_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (invoice, encounter, patient_num, patient_name, payer, location, provider, charge, withhold, parsed_date, priority, now_iso, tat_deadline, batch_id))
            added += 1
        
        db.execute("UPDATE upload_history SET records_added=?, duplicates_skipped=? WHERE id=?", (added, skipped, batch_id))
        db.commit()
        log_activity(None, session['user_id'], 'Upload', f'{batch_name}: {added} added, {skipped} duplicates')
        flash(f'Upload "{batch_name}": {added} added, {skipped} duplicates skipped.', 'success')
        return redirect(url_for('inventory_list'))
    
    uploads = db.execute("SELECT uh.*, u.full_name FROM upload_history uh LEFT JOIN users u ON uh.uploaded_by=u.id ORDER BY uh.uploaded_at DESC LIMIT 50").fetchall()
    return render_template('upload_inventory.html', uploads=uploads)

# ─── Inventory List ───────────────────────────────────────────────────
@app.route('/inventory')
@login_required
def inventory_list():
    db = get_db()
    role = session['role']
    uid = session['user_id']
    utype = session.get('user_type')

    status_f = request.args.get('status','')
    priority_f = request.args.get('priority','')
    assigned_f = request.args.get('assigned','')
    user_f = request.args.get('user_id','')
    date_f = request.args.get('date','')
    search_q = request.args.get('q','').strip()
    page = max(1, int(request.args.get('page', 1)))
    per_page = 50

    query = "SELECT a.*, c.full_name as coder_name, b.full_name as biller_name FROM accounts a LEFT JOIN users c ON a.assigned_coder_id=c.id LEFT JOIN users b ON a.assigned_biller_id=b.id WHERE 1=1"
    params = []

    if role == 'User':
        if utype == 'Coder':
            query += " AND a.assigned_coder_id=?"
            params.append(uid)
        elif utype == 'Biller':
            query += " AND a.assigned_biller_id=?"
            params.append(uid)

    if status_f:
        query += " AND a.status=?"
        params.append(status_f)
    if priority_f:
        query += " AND a.priority=?"
        params.append(priority_f)
    if assigned_f == 'assigned':
        query += " AND a.assigned_coder_id IS NOT NULL"
    elif assigned_f == 'not_assigned':
        query += " AND a.assigned_coder_id IS NULL AND a.status='Unassigned'"
    if user_f and role in ('SuperAdmin','Admin','Auditor'):
        query += " AND (a.assigned_coder_id=? OR a.assigned_biller_id=?)"
        params.extend([user_f, user_f])
    if date_f:
        query += " AND a.upload_date=?"
        params.append(date_f)
    if search_q:
        query += " AND (a.invoice_number LIKE ? OR a.encounter_id LIKE ? OR a.patient_name LIKE ? OR a.payer_name LIKE ?)"
        params.extend([f'%{search_q}%']*4)

    count_q = query.replace("SELECT a.*, c.full_name as coder_name, b.full_name as biller_name FROM accounts a LEFT JOIN users c ON a.assigned_coder_id=c.id LEFT JOIN users b ON a.assigned_biller_id=b.id",
                            "SELECT COUNT(*) FROM accounts a")
    total = db.execute(count_q, params).fetchone()[0]

    # Live header metrics
    metrics = {
        'total': db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0],
        'completed': db.execute("SELECT COUNT(*) FROM accounts WHERE status IN ('Completed','Finalized','Audited - Passed')").fetchone()[0],
        'in_progress': db.execute("SELECT COUNT(*) FROM accounts WHERE status IN ('In-Process','Billing In Progress')").fetchone()[0],
        'pending': db.execute("SELECT COUNT(*) FROM accounts WHERE status IN ('Pending','Assigned','Assigned to Biller')").fetchone()[0],
    }

    query += " ORDER BY CASE WHEN a.priority='High' THEN 0 WHEN a.priority='Medium' THEN 1 ELSE 2 END, a.upload_date DESC LIMIT ? OFFSET ?"
    params.extend([per_page, (page-1)*per_page])
    accounts = db.execute(query, params).fetchall()
    total_pages = max(1, (total + per_page - 1) // per_page)

    coders = db.execute("SELECT id, full_name FROM users WHERE user_type='Coder' AND is_active=1").fetchall()
    billers = db.execute("SELECT id, full_name FROM users WHERE user_type='Biller' AND is_active=1").fetchall()
    all_users = db.execute("SELECT id, full_name, user_type FROM users WHERE user_type IS NOT NULL AND is_active=1 ORDER BY full_name").fetchall()

    return render_template('inventory.html', accounts=accounts, coders=coders, billers=billers, all_users=all_users,
        page=page, total_pages=total_pages, total=total, metrics=metrics,
        status_filter=status_f, priority_filter=priority_f, assigned_filter=assigned_f,
        user_filter=user_f, date_filter=date_f, search_q=search_q)

# ─── Account Detail ──────────────────────────────────────────────────
@app.route('/account/<int:account_id>')
@login_required
def account_detail(account_id):
    db = get_db()
    account = db.execute("""
        SELECT a.*, c.full_name as coder_name, b.full_name as biller_name, au.full_name as auditor_name
        FROM accounts a LEFT JOIN users c ON a.assigned_coder_id=c.id
        LEFT JOIN users b ON a.assigned_biller_id=b.id LEFT JOIN users au ON a.auditor_id=au.id
        WHERE a.id=?
    """, (account_id,)).fetchone()
    if not account:
        flash('Account not found.', 'error')
        return redirect(url_for('inventory_list'))
    history = db.execute("SELECT al.*, u.full_name FROM activity_log al LEFT JOIN users u ON al.user_id=u.id WHERE al.account_id=? ORDER BY al.created_at DESC", (account_id,)).fetchall()
    coders = db.execute("SELECT id, full_name FROM users WHERE user_type='Coder' AND is_active=1").fetchall()
    billers = db.execute("SELECT id, full_name FROM users WHERE user_type='Biller' AND is_active=1").fetchall()
    return render_template('account_detail.html', account=account, history=history, coders=coders, billers=billers)

# ─── Assign / Bulk Actions ───────────────────────────────────────────
@app.route('/inventory/assign', methods=['POST'])
@admin_required
def assign_accounts():
    db = get_db()
    action = request.form.get('action')

    if action == 'assign_coder':
        aids = request.form.getlist('account_ids')
        cid = request.form.get('coder_id')
        if aids and cid:
            for aid in aids:
                db.execute("UPDATE accounts SET assigned_coder_id=?, status='Assigned' WHERE id=?", (cid, aid))
                log_activity(int(aid), session['user_id'], 'Assigned to Coder', f'Coder ID: {cid}')
            db.commit()
            flash(f'{len(aids)} accounts assigned.', 'success')

    elif action == 'reassign':
        aid = request.form.get('account_id')
        new_uid = request.form.get('new_user_id')
        rr = request.form.get('reassign_role','Coder')
        if aid and new_uid:
            if rr == 'Coder':
                db.execute("UPDATE accounts SET assigned_coder_id=?, status='Assigned' WHERE id=?", (new_uid, aid))
            else:
                db.execute("UPDATE accounts SET assigned_biller_id=?, status='Assigned to Biller' WHERE id=?", (new_uid, aid))
            db.commit()
            log_activity(int(aid), session['user_id'], 'Reassigned', f'To {rr} ID: {new_uid}')
            flash('Account reassigned.', 'success')

    elif action == 'set_priority':
        aids = request.form.getlist('account_ids')
        pval = request.form.get('priority_value', 'High')
        for aid in aids:
            db.execute("UPDATE accounts SET priority=? WHERE id=?", (pval, aid))
            log_activity(int(aid), session['user_id'], f'Priority → {pval}', '')
        db.commit()
        flash(f'{len(aids)} accounts set to {pval}.', 'success')

    return redirect(request.referrer or url_for('inventory_list'))

@app.route('/inventory/assign-billers', methods=['POST'])
@admin_required
def assign_billers():
    db = get_db()
    aids = request.form.getlist('account_ids')
    bid = request.form.get('biller_id')
    if aids and bid:
        for aid in aids:
            db.execute("UPDATE accounts SET assigned_biller_id=?, status='Assigned to Biller' WHERE id=?", (bid, aid))
            log_activity(int(aid), session['user_id'], 'Assigned to Biller', f'Biller ID: {bid}')
        db.commit()
        flash(f'{len(aids)} accounts assigned to biller.', 'success')
    return redirect(request.referrer or url_for('inventory_list'))

# ─── Coder Actions (legacy detail page) ─────────────────────────────
@app.route('/account/<int:account_id>/code', methods=['POST'])
@login_required
def code_account(account_id):
    if session.get('user_type') != 'Coder' and session.get('role') not in ('SuperAdmin','Admin','Auditor'):
        abort(403)
    db = get_db()
    action = request.form.get('action')
    comments = request.form.get('coder_comments','').strip()
    if action == 'start':
        db.execute("UPDATE accounts SET status='In-Process' WHERE id=?", (account_id,))
        log_activity(account_id, session['user_id'], 'Started Coding', '')
    elif action == 'complete':
        if not comments:
            flash('Comments required.', 'error')
            return redirect(url_for('account_detail', account_id=account_id))
        db.execute("UPDATE accounts SET status='Completed', coder_comments=?, coded_at=? WHERE id=?",
                   (comments, datetime.now().isoformat(), account_id))
        log_activity(account_id, session['user_id'], 'Coding Completed', comments)
    db.commit()
    flash('Updated.', 'success')
    return redirect(url_for('account_detail', account_id=account_id))

@app.route('/account/<int:account_id>/bill', methods=['POST'])
@login_required
def bill_account(account_id):
    if session.get('user_type') != 'Biller' and session.get('role') not in ('SuperAdmin','Admin','Auditor'):
        abort(403)
    db = get_db()
    action = request.form.get('action')
    comments = request.form.get('biller_comments','').strip()
    if action == 'start':
        db.execute("UPDATE accounts SET status='Billing In Progress' WHERE id=?", (account_id,))
        log_activity(account_id, session['user_id'], 'Started Billing', '')
    elif action == 'complete':
        if not comments:
            flash('Comments required.', 'error')
            return redirect(url_for('account_detail', account_id=account_id))
        db.execute("UPDATE accounts SET status='Finalized', biller_comments=?, billed_at=?, finalized_at=? WHERE id=?",
                   (comments, datetime.now().isoformat(), datetime.now().isoformat(), account_id))
        log_activity(account_id, session['user_id'], 'Finalized', comments)
    elif action == 'clarification':
        db.execute("UPDATE accounts SET status='Clarification Needed', biller_comments=?, priority='High' WHERE id=?",
                   (comments, account_id))
        log_activity(account_id, session['user_id'], 'Clarification Requested', comments)
    db.commit()
    flash('Updated.', 'success')
    return redirect(url_for('account_detail', account_id=account_id))

# ─── Audit Module (calendar-based, separate coder/biller) ───────────
@app.route('/audit', methods=['GET','POST'])
@auditor_required
def audit_list():
    db = get_db()
    audit_type = request.args.get('type', 'coder')  # coder or biller
    audit_date = request.args.get('date', datetime.now().strftime('%Y-%m-%d'))
    
    if request.method == 'POST':
        target_user = request.form.get('audit_user_id')
        sel_date = request.form.get('audit_date', audit_date)
        audit_count = int(request.form.get('audit_count', 5))
        sel_type = request.form.get('audit_type', 'coder')
        
        if sel_type == 'coder':
            candidates = db.execute("""
                SELECT id FROM accounts WHERE assigned_coder_id=? 
                AND date(coded_at)=? AND audit_status IS NULL
            """, (target_user, sel_date)).fetchall()
        else:
            candidates = db.execute("""
                SELECT id FROM accounts WHERE assigned_biller_id=? 
                AND date(billed_at)=? AND audit_status IS NULL
            """, (target_user, sel_date)).fetchall()
        
        if not candidates:
            flash('No un-audited accounts for this user/date.', 'warning')
            return redirect(url_for('audit_list', type=sel_type, date=sel_date))
        
        selected = random.sample([c['id'] for c in candidates], min(audit_count, len(candidates)))
        flash(f'{len(selected)} accounts selected for audit.', 'success')
        return redirect(url_for('audit_list', type=sel_type, date=sel_date, selected=','.join(str(s) for s in selected)))
    
    selected_ids = request.args.get('selected','')
    status_f = request.args.get('status','')
    
    if selected_ids:
        ids = [int(x) for x in selected_ids.split(',') if x.isdigit()]
        placeholders = ','.join('?' * len(ids))
        accounts = db.execute(f"""
            SELECT a.*, c.full_name as coder_name, b.full_name as biller_name
            FROM accounts a LEFT JOIN users c ON a.assigned_coder_id=c.id
            LEFT JOIN users b ON a.assigned_biller_id=b.id
            WHERE a.id IN ({placeholders})
        """, ids).fetchall()
    else:
        if audit_type == 'coder':
            where = "a.coded_at IS NOT NULL AND date(a.coded_at)=?"
            wparams = [audit_date]
        else:
            where = "a.billed_at IS NOT NULL AND date(a.billed_at)=?"
            wparams = [audit_date]
        if status_f == 'pending':
            where += " AND a.audit_status IS NULL"
        elif status_f == 'passed':
            where += " AND a.audit_status='Passed'"
        elif status_f == 'failed':
            where += " AND a.audit_status='Failed'"
        accounts = db.execute(f"""
            SELECT a.*, c.full_name as coder_name, b.full_name as biller_name
            FROM accounts a LEFT JOIN users c ON a.assigned_coder_id=c.id
            LEFT JOIN users b ON a.assigned_biller_id=b.id
            WHERE {where} ORDER BY a.coded_at DESC LIMIT 200
        """, wparams).fetchall()
    
    if audit_type == 'coder':
        pending_users = db.execute("""
            SELECT u.id, u.full_name, COUNT(a.id) as pending_count
            FROM users u JOIN accounts a ON u.id=a.assigned_coder_id
            WHERE a.coded_at IS NOT NULL AND a.audit_status IS NULL
            AND u.user_type='Coder' AND u.is_active=1
            GROUP BY u.id ORDER BY pending_count DESC
        """).fetchall()
        users_for_audit = db.execute("SELECT id, full_name FROM users WHERE user_type='Coder' AND is_active=1").fetchall()
    else:
        pending_users = db.execute("""
            SELECT u.id, u.full_name, COUNT(a.id) as pending_count
            FROM users u JOIN accounts a ON u.id=a.assigned_biller_id
            WHERE a.billed_at IS NOT NULL AND a.audit_status IS NULL
            AND u.user_type='Biller' AND u.is_active=1
            GROUP BY u.id ORDER BY pending_count DESC
        """).fetchall()
        users_for_audit = db.execute("SELECT id, full_name FROM users WHERE user_type='Biller' AND is_active=1").fetchall()
    
    return render_template('audit.html', accounts=accounts, status_filter=status_f,
                           pending_users=pending_users, users_for_audit=users_for_audit,
                           audit_type=audit_type, audit_date=audit_date)

@app.route('/account/<int:account_id>/audit', methods=['POST'])
@auditor_required
def audit_account(account_id):
    db = get_db()
    result = request.form.get('audit_result')
    comments = request.form.get('auditor_comments','').strip()
    if result == 'Passed':
        db.execute("UPDATE accounts SET audit_status='Passed', auditor_id=?, auditor_comments=?, audited_at=?, status='Audited - Passed' WHERE id=?",
                   (session['user_id'], comments, datetime.now().isoformat(), account_id))
        log_activity(account_id, session['user_id'], 'Audit Passed', comments)
    elif result == 'Failed':
        if not comments:
            flash('Comments required for failed.', 'error')
            return redirect(url_for('account_detail', account_id=account_id))
        db.execute("UPDATE accounts SET audit_status='Failed', auditor_id=?, auditor_comments=?, audited_at=?, status='Rework - Coder' WHERE id=?",
                   (session['user_id'], comments, datetime.now().isoformat(), account_id))
        log_activity(account_id, session['user_id'], 'Audit Failed → Rework', comments)
    db.commit()
    flash('Audit recorded.', 'success')
    return redirect(url_for('audit_list'))

# ─── Reports (customizable) ──────────────────────────────────────────
@app.route('/reports')
@admin_required
def reports():
    db = get_db()
    
    # Filters from query string
    df = request.args.get('from','')
    dt = request.args.get('to','')
    status_f = request.args.get('status','')
    priority_f = request.args.get('priority','')
    user_f = request.args.get('user_id','')
    selected_cols = request.args.getlist('cols') or ['invoice_number','patient_name','payer_name','status','priority','coder','biller','received','tat_status']
    
    available_cols = {
        'invoice_number': 'Invoice #',
        'encounter_id': 'Encounter ID',
        'patient_name': 'Patient',
        'patient_number': 'Patient #',
        'payer_name': 'Payer',
        'provider': 'Provider',
        'location': 'Location',
        'total_charge': 'Total Charge',
        'cpt_codes': 'CPT Codes',
        'icd10_codes': 'ICD-10 Codes',
        'status': 'Status',
        'priority': 'Priority',
        'coder': 'Coder',
        'biller': 'Biller',
        'received': 'Upload Date',
        'date_of_service': 'DOS',
        'tat_status': 'TAT Status',
        'coded_at': 'Coded At',
        'billed_at': 'Billed At',
        'audit_status': 'Audit Status',
        'auditor': 'Auditor',
    }
    
    query = """SELECT a.*, c.full_name as coder, b.full_name as biller, au.full_name as auditor
               FROM accounts a LEFT JOIN users c ON a.assigned_coder_id=c.id
               LEFT JOIN users b ON a.assigned_biller_id=b.id
               LEFT JOIN users au ON a.auditor_id=au.id WHERE 1=1"""
    params = []
    if df: query += " AND a.upload_date >= ?"; params.append(df)
    if dt: query += " AND a.upload_date <= ?"; params.append(dt)
    if status_f: query += " AND a.status=?"; params.append(status_f)
    if priority_f: query += " AND a.priority=?"; params.append(priority_f)
    if user_f: query += " AND (a.assigned_coder_id=? OR a.assigned_biller_id=?)"; params.extend([user_f, user_f])
    query += " ORDER BY a.upload_date DESC LIMIT 1000"
    
    rows = db.execute(query, params).fetchall()
    
    # Compute TAT status for each row
    processed_rows = []
    now = datetime.now()
    for r in rows:
        d = dict(r)
        if r['tat_deadline']:
            try:
                deadline = datetime.fromisoformat(r['tat_deadline'])
                if r['status'] in ('Completed','Finalized','Audited - Passed'):
                    d['tat_status'] = 'Met' if (r['coded_at'] and datetime.fromisoformat(r['coded_at']) <= deadline) else 'Breached'
                else:
                    d['tat_status'] = 'Within' if now <= deadline else 'Breached'
            except:
                d['tat_status'] = '—'
        else:
            d['tat_status'] = '—'
        d['received'] = r['upload_date']
        processed_rows.append(d)
    
    all_users = db.execute("SELECT id, full_name, user_type FROM users WHERE user_type IS NOT NULL AND is_active=1").fetchall()
    
    return render_template('reports.html', rows=processed_rows, available_cols=available_cols,
                           selected_cols=selected_cols, all_users=all_users,
                           df=df, dt=dt, status_f=status_f, priority_f=priority_f, user_f=user_f)

@app.route('/reports/export')
@admin_required
def export_report():
    db = get_db()
    df = request.args.get('from','')
    dt = request.args.get('to','')
    status_f = request.args.get('status','')
    priority_f = request.args.get('priority','')
    user_f = request.args.get('user_id','')
    selected_cols = request.args.getlist('cols') or ['invoice_number','patient_name','status','priority','coder','biller']
    
    query = """SELECT a.*, c.full_name as coder, b.full_name as biller, au.full_name as auditor
               FROM accounts a LEFT JOIN users c ON a.assigned_coder_id=c.id
               LEFT JOIN users b ON a.assigned_biller_id=b.id
               LEFT JOIN users au ON a.auditor_id=au.id WHERE 1=1"""
    params = []
    if df: query += " AND a.upload_date >= ?"; params.append(df)
    if dt: query += " AND a.upload_date <= ?"; params.append(dt)
    if status_f: query += " AND a.status=?"; params.append(status_f)
    if priority_f: query += " AND a.priority=?"; params.append(priority_f)
    if user_f: query += " AND (a.assigned_coder_id=? OR a.assigned_biller_id=?)"; params.extend([user_f, user_f])
    query += " ORDER BY a.upload_date DESC"
    rows = db.execute(query, params).fetchall()
    
    out = io.StringIO()
    w = csv.writer(out)
    
    headers = {
        'invoice_number':'Invoice','encounter_id':'Encounter ID','patient_name':'Patient',
        'patient_number':'Patient #','payer_name':'Payer','provider':'Provider','location':'Location',
        'total_charge':'Total','cpt_codes':'CPT','icd10_codes':'ICD-10','status':'Status',
        'priority':'Priority','coder':'Coder','biller':'Biller','received':'Upload Date',
        'date_of_service':'DOS','tat_status':'TAT','coded_at':'Coded','billed_at':'Billed',
        'audit_status':'Audit','auditor':'Auditor'
    }
    w.writerow([headers.get(c, c) for c in selected_cols])
    
    now = datetime.now()
    for r in rows:
        d = dict(r)
        if r['tat_deadline']:
            try:
                deadline = datetime.fromisoformat(r['tat_deadline'])
                if r['status'] in ('Completed','Finalized','Audited - Passed'):
                    d['tat_status'] = 'Met' if (r['coded_at'] and datetime.fromisoformat(r['coded_at']) <= deadline) else 'Breached'
                else:
                    d['tat_status'] = 'Within' if now <= deadline else 'Breached'
            except:
                d['tat_status'] = ''
        else:
            d['tat_status'] = ''
        d['received'] = r['upload_date']
        w.writerow([d.get(c, '') or '' for c in selected_cols])
    
    out.seek(0)
    return send_file(io.BytesIO(out.getvalue().encode('utf-8')), mimetype='text/csv',
                     as_attachment=True, download_name=f'report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv')

# ─── Backup ──────────────────────────────────────────────────────────
@app.route('/backup')
@admin_required
def backup_database():
    import shutil
    bk = os.path.join(app.config['UPLOAD_FOLDER'], f'backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db')
    shutil.copy2(DATABASE, bk)
    return send_file(bk, as_attachment=True, download_name=os.path.basename(bk))

# ─── Emergency Reassign ──────────────────────────────────────────────
@app.route('/emergency-reassign', methods=['GET','POST'])
@admin_required
def emergency_reassign():
    db = get_db()
    if request.method == 'POST':
        fr = request.form.get('from_user')
        to = request.form.get('to_user')
        if fr and to:
            c1 = db.execute("UPDATE accounts SET assigned_coder_id=?, status='Assigned' WHERE assigned_coder_id=? AND status IN ('Assigned','In-Process','Pending','Rework - Coder')", (to, fr)).rowcount
            c2 = db.execute("UPDATE accounts SET assigned_biller_id=?, status='Assigned to Biller' WHERE assigned_biller_id=? AND status IN ('Assigned to Biller','Billing In Progress','Rework - Biller')", (to, fr)).rowcount
            db.commit()
            log_activity(None, session['user_id'], 'Emergency Reassign', f'{fr}→{to}: {c1+c2} accounts')
            flash(f'Reassigned {c1+c2} accounts.', 'success')
            return redirect(url_for('dashboard'))
    users = db.execute("SELECT id, full_name, user_type, role FROM users WHERE is_active=1").fetchall()
    return render_template('emergency_reassign.html', users=users)

# ─── Update account (Admin priority/status) ─────────────────────────
@app.route('/account/<int:account_id>/update', methods=['POST'])
@admin_required
def update_account(account_id):
    db = get_db()
    new_priority = request.form.get('priority')
    new_status = request.form.get('status')
    if new_priority:
        db.execute("UPDATE accounts SET priority=? WHERE id=?", (new_priority, account_id))
        log_activity(account_id, session['user_id'], f'Priority → {new_priority}', '')
    if new_status:
        db.execute("UPDATE accounts SET status=? WHERE id=?", (new_status, account_id))
        log_activity(account_id, session['user_id'], f'Status → {new_status}', '')
    db.commit()
    flash('Account updated.', 'success')
    return redirect(url_for('account_detail', account_id=account_id))

# ─── Delete Account (SuperAdmin only) ────────────────────────────────
@app.route('/account/<int:account_id>/delete', methods=['POST'])
@superadmin_required
def delete_account(account_id):
    db = get_db()
    inv = db.execute("SELECT invoice_number FROM accounts WHERE id=?", (account_id,)).fetchone()
    if not inv:
        flash('Account not found.', 'error')
        return redirect(url_for('inventory_list'))
    db.execute("DELETE FROM activity_log WHERE account_id=?", (account_id,))
    db.execute("DELETE FROM accounts WHERE id=?", (account_id,))
    db.commit()
    log_activity(None, session['user_id'], 'Account Deleted', f'Invoice: {inv[0]}')
    flash(f'Account {inv[0]} deleted.', 'success')
    return redirect(url_for('inventory_list'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
