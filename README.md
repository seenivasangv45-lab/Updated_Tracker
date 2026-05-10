# ProTrack — Inventory, Production & Performance Management

A production-grade web application for managing inventory, coding/billing workflows, auditing, and performance tracking. Built with Python Flask and SQLite (WAL mode for concurrent access).

---

## Features

- **3 Access Levels**: Admin, User (Coder/Biller), Auditor
- **Inventory Management**: CSV upload with automatic duplicate detection
- **Workflow Engine**: Coder → Biller → Finalized pipeline with auto-routing
- **Audit System**: Pass/Fail audits with rework reassignment
- **Priority Management**: High priority flagging with TAT tracking
- **Emergency Reassignment**: Route all accounts when a user takes leave
- **Reports & Export**: Date-wise inventory, quality metrics, CSV export
- **Database Backup**: One-click database backup download
- **Concurrent Access**: WAL mode SQLite supports multiple simultaneous users
- **Secure Authentication**: PBKDF2-SHA256 password hashing (260,000 iterations)

---

## Default Login

| Username | Password   | Role  |
|----------|------------|-------|
| admin    | Admin@123  | Admin |

**Change this password immediately after first login.**

---

## Local Setup

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/protrack.git
cd protrack

# Create virtual environment
python -m venv venv
source venv/bin/activate   # Linux/Mac
# venv\Scripts\activate    # Windows

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

Open http://localhost:5000 in your browser.

---

## Hosting on Render (Free — Recommended)

1. Push your code to GitHub
2. Go to [render.com](https://render.com) → New → Web Service
3. Connect your GitHub repo
4. Settings:
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 4`
   - **Environment Variable**: Add `SECRET_KEY` = any random string (e.g., `mysecretkey123xyz`)
5. Click Deploy

### Other Hosting Options

**Railway.app:**
1. Connect GitHub repo at [railway.app](https://railway.app)
2. Auto-detects Python, add `SECRET_KEY` env var
3. Deploy

**PythonAnywhere (Free):**
1. Upload files to [pythonanywhere.com](https://pythonanywhere.com)
2. Set up a web app with Flask
3. Point to `app.py`

**VPS (DigitalOcean/AWS/etc):**
```bash
sudo apt install python3-pip python3-venv nginx
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
gunicorn app:app --bind 0.0.0.0:5000 --workers 4 --daemon
```

---

## Database Backup (Every 3 Days)

### Option 1: Manual via UI
- Login as Admin → click the database icon in sidebar → downloads `.db` file

### Option 2: Automated Script
Create `backup.py`:
```python
import shutil, os
from datetime import datetime

db_path = 'production.db'
backup_dir = 'backups'
os.makedirs(backup_dir, exist_ok=True)

backup_name = f'production_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
shutil.copy2(db_path, os.path.join(backup_dir, backup_name))
print(f'Backup created: {backup_name}')
```

Run with cron (Linux) every 3 days:
```bash
crontab -e
# Add this line:
0 2 */3 * * cd /path/to/protrack && /path/to/venv/bin/python backup.py
```

### Option 3: Export to Excel/CSV
- Admin → Reports → Export All Data (CSV download)
- Open CSV in Excel and save as .xlsx

---

## CSV Upload Format

Your FIN14 CSV file should have these columns:

| Invoice Number | Patient Name | Received Date |
|---------------|-------------|---------------|
| INV-001       | John Doe    | 2025-01-15    |

- **Invoice Number** (required) — duplicates are auto-skipped
- **Patient Name** (optional)
- **Received Date** (optional) — multiple date formats supported
- Any extra columns are stored as metadata

---

## Security Notes

- Passwords are hashed with PBKDF2-SHA256 (260,000 iterations)
- Sessions expire after 12 hours
- Set a strong `SECRET_KEY` environment variable in production
- SQLite WAL mode enables safe concurrent reads/writes
- All user actions are logged in the activity trail

---

## Tech Stack

- **Backend**: Python 3.12 + Flask 3.1
- **Database**: SQLite with WAL mode
- **Server**: Gunicorn (4 workers)
- **Frontend**: Vanilla HTML/CSS/JS (no framework dependencies)
- **Fonts**: DM Sans + JetBrains Mono
