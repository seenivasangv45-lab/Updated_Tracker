"""
Gunicorn configuration for ProTrack.
Used automatically when running: gunicorn app:app
"""
import os
import multiprocessing

# ─── Server Socket ────────────────────────────────────────────────
bind = f"0.0.0.0:{os.environ.get('PORT', 5000)}"
backlog = 2048

# ─── Worker Processes ─────────────────────────────────────────────
# Render free tier has limited memory, so cap workers at 4.
# For paid plans, formula is (2 x CPU cores) + 1
workers = int(os.environ.get('WEB_CONCURRENCY', min(4, multiprocessing.cpu_count() * 2 + 1)))
worker_class = 'sync'
worker_connections = 1000
timeout = 120
keepalive = 5
graceful_timeout = 30

# ─── Restart Workers ──────────────────────────────────────────────
# Restart workers after handling this many requests to prevent memory leaks
max_requests = 1000
max_requests_jitter = 50

# ─── Logging ──────────────────────────────────────────────────────
accesslog = '-'   # stdout
errorlog = '-'    # stderr
loglevel = os.environ.get('LOG_LEVEL', 'info')
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)sµs'

# ─── Process Naming ───────────────────────────────────────────────
proc_name = 'protrack'

# ─── Server Mechanics ─────────────────────────────────────────────
preload_app = True   # Load app before forking workers (faster, saves memory)
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# ─── SSL ──────────────────────────────────────────────────────────
# Render handles SSL automatically — leave these as None
keyfile = None
certfile = None

# ─── Hooks (lifecycle events) ─────────────────────────────────────
def on_starting(server):
    server.log.info("ProTrack server starting up...")

def on_reload(server):
    server.log.info("ProTrack reloading...")

def when_ready(server):
    server.log.info(f"ProTrack ready. Listening on: {bind}")

def worker_int(worker):
    worker.log.info(f"Worker {worker.pid} interrupted")

def on_exit(server):
    server.log.info("ProTrack shutting down")
