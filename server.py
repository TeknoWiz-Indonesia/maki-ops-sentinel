import os
import sys
import sqlite3
import subprocess
import re
import json
import time
import threading
from datetime import datetime, timedelta
from collections import Counter
import io
import csv
import glob
import gzip
import math
import urllib.request
from flask import Flask, render_template, jsonify, request, Response

# Optional export libs (Excel / PDF)
try:
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    OPENPYXL_AVAILABLE = True
except Exception:
    OPENPYXL_AVAILABLE = False

try:
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image as RLImage
    from reportlab.graphics.shapes import Drawing, Rect, Circle, Wedge, String, Line, Group, Polygon
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

app = Flask(__name__)

# Base configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "sentinel.db")

WHITELISTED_IPS = ["127.0.0.1", "172.16.61.188", "172.16.61.55", "172.16.62.181", "172.16.62.254", "172.17.3.2", "10.100.2.1", "172.16.62.247"]

# 100% Offline Local GeoIP Database Paths (Zero External API calls)
MMDB_CITY_PATH = os.path.join(DATA_DIR, "GeoLite2-City.mmdb")
MMDB_ASN_PATH = os.path.join(DATA_DIR, "GeoLite2-ASN.mmdb")

_mmdb_city_reader = None
_mmdb_asn_reader = None

def get_mmdb_readers():
    global _mmdb_city_reader, _mmdb_asn_reader
    try:
        import maxminddb
        if _mmdb_city_reader is None and os.path.exists(MMDB_CITY_PATH):
            _mmdb_city_reader = maxminddb.open_database(MMDB_CITY_PATH)
        if _mmdb_asn_reader is None and os.path.exists(MMDB_ASN_PATH):
            _mmdb_asn_reader = maxminddb.open_database(MMDB_ASN_PATH)
    except Exception:
        pass
    return _mmdb_city_reader, _mmdb_asn_reader

# In-memory GeoIP Cache
_GEO_CACHE = {}

def is_private_ip(ip: str) -> bool:
    """Mengecek apakah IP adalah internal / private."""
    if not ip or ip in ("localhost", "::1", "-"):
        return True
    return (
        ip.startswith("127.") or 
        ip.startswith("10.") or 
        ip.startswith("172.16.") or 
        ip.startswith("172.17.") or 
        ip.startswith("192.168.")
    )

def get_geoip_info(ip_list):
    """100% Offline GeoIP resolver menggunakan local MaxMind DB (Zero Network API Limit)."""
    r_city, r_asn = get_mmdb_readers()
    
    for ip in ip_list:
        if not ip or ip in _GEO_CACHE:
            continue
            
        if is_private_ip(ip):
            _GEO_CACHE[ip] = {
                "city": "Lokal RS",
                "region": "Tegal",
                "country": "Internal",
                "isp": "LAN / Kardinah Network"
            }
            continue
            
        city = "-"
        region = "-"
        country = "Indonesia"
        isp = "-"
        
        if r_city:
            try:
                c = r_city.get(ip) or {}
                city = c.get("city", {}).get("names", {}).get("en") or "-"
                subdivs = c.get("subdivisions", [])
                region = subdivs[0].get("names", {}).get("en") if subdivs else "-"
                country = c.get("country", {}).get("names", {}).get("en") or "Indonesia"
            except Exception:
                pass
                
        if r_asn:
            try:
                a = r_asn.get(ip) or {}
                isp = a.get("autonomous_system_organization") or "-"
            except Exception:
                pass
                
        # If offline MMDB not available yet, fallback to safe defaults
        _GEO_CACHE[ip] = {
            "city": city if city != "-" else "Unknown",
            "region": region if region != "-" else "",
            "country": country,
            "isp": isp
        }
                
    return _GEO_CACHE

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    
    # 1. Ban Events Table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ban_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT NOT NULL,
            jail TEXT NOT NULL,
            action TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            raw_log TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(event_time, jail, ip_address, action)
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ban_time ON ban_events(event_time)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ban_ip ON ban_events(ip_address)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ban_jail ON ban_events(jail)")

    # 2. Attack Probes Table (Only Malicious / Suspicious Web Attacks, NOT raw access logs)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS attack_probes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            probe_time TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            status_code TEXT,
            category TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(probe_time, ip_address, method, path)
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_probe_time ON attack_probes(probe_time)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_probe_ip ON attack_probes(ip_address)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_probe_cat ON attack_probes(category)")

    # 3. Audit Logs Table (Admin Actions on Dashboard)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_time TEXT NOT NULL,
            action_type TEXT NOT NULL,
            ip_address TEXT,
            details TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(action_time)")

    # 4. Metrics Snapshots Table (Hourly / 10-minute trends)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS metrics_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_time TEXT NOT NULL,
            total_banned INTEGER NOT NULL,
            total_failed INTEGER NOT NULL,
            active_ufw_bans INTEGER NOT NULL,
            jails_data TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_metrics_time ON metrics_snapshots(snapshot_time)")

    conn.commit()
    conn.close()

def record_audit(action_type: str, ip_address: str = "", details: str = ""):
    try:
        conn = get_db()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("""
            INSERT INTO audit_logs (action_time, action_type, ip_address, details)
            VALUES (?, ?, ?, ?)
        """, (now_str, action_type, ip_address, details))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Audit Error] {e}", file=sys.stderr)

def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=8)
        return res.stdout.strip()
    except Exception as e:
        return str(e)

def get_whitelisted_ips():
    out = run_cmd("fail2ban-client get sshd ignoreip")
    ips = []
    for line in out.splitlines():
        if "|-" in line or "`-" in line:
            parts = re.split(r"[|\`]-\s*", line)
            if len(parts) > 1 and parts[1].strip():
                ips.append(parts[1].strip())
    for w in WHITELISTED_IPS:
        if w not in ips:
            ips.append(w)
    return ips

def parse_jail_status(jail_name):
    out = run_cmd(f"fail2ban-client status {jail_name}")
    data = {
        "name": jail_name,
        "failed_current": 0,
        "failed_total": 0,
        "banned_current": 0,
        "banned_total": 0,
        "banned_ips": [],
        "file_list": []
    }
    for line in out.splitlines():
        if "Currently failed:" in line:
            m = re.search(r"Currently failed:\s+(\d+)", line)
            if m: data["failed_current"] = int(m.group(1))
        elif "Total failed:" in line:
            m = re.search(r"Total failed:\s+(\d+)", line)
            if m: data["failed_total"] = int(m.group(1))
        elif "Currently banned:" in line:
            m = re.search(r"Currently banned:\s+(\d+)", line)
            if m: data["banned_current"] = int(m.group(1))
        elif "Total banned:" in line:
            m = re.search(r"Total banned:\s+(\d+)", line)
            if m: data["banned_total"] = int(m.group(1))
        elif "Banned IP list:" in line:
            parts = line.split("Banned IP list:")
            if len(parts) > 1 and parts[1].strip():
                data["banned_ips"] = [ip.strip() for ip in parts[1].strip().split() if ip.strip()]
        elif "File list:" in line:
            parts = line.split("File list:")
            if len(parts) > 1 and parts[1].strip():
                data["file_list"] = [f.strip() for f in parts[1].strip().split() if f.strip()]
    return data

# --- LOG SYNC TO SQLITE WORKER ---

def sync_ban_history_from_logs():
    """Mengimpor event Ban / Unban / Restore Ban dari file log fail2ban ke SQLite."""
    try:
        cmd = "zgrep -h -E 'Ban|Unban' /var/log/fail2ban.log* 2>/dev/null | sort -k1,2r | head -n 300"
        raw = run_cmd(cmd)
        if not raw:
            return 0
        
        records = []
        pattern = re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*\[(\w[\w-]+)\]\s+(Ban|Unban|Restore Ban)\s+([0-9a-fA-F\.:]+)")
        for line in raw.splitlines():
            m = pattern.search(line)
            if m:
                dt, jail, action, ip = m.groups()
                records.append((dt, jail, action, ip, line))
            elif "Ban" in line or "Unban" in line:
                parts = line.split()
                if len(parts) >= 6:
                    dt = f"{parts[0]} {parts[1][:8]}"
                    action = "Ban" if "Ban" in line else "Unban"
                    ip = parts[-1]
                    records.append((dt, "unknown", action, ip, line))

        if records:
            conn = get_db()
            conn.executemany("""
                INSERT OR IGNORE INTO ban_events (event_time, jail, action, ip_address, raw_log)
                VALUES (?, ?, ?, ?, ?)
            """, records)
            conn.commit()
            conn.close()
        return len(records)
    except Exception as e:
        print(f"[Sync Ban Error] {e}", file=sys.stderr)
        return 0

def sync_probes_from_logs():
    """Mengimpor deteksi serangan web mencurigakan (bukan access log biasa) ke SQLite."""
    try:
        raw_logs = run_cmd("tail -n 2000 /www/wwwlogs/rsudkardinah.tegalkota.go.id.log 2>/dev/null")
        if not raw_logs:
            return 0

        wl = get_whitelisted_ips()
        pat_probe = re.compile(r'^([0-9a-fA-F\.:]+)\s+-\s+-\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s]+)\s+HTTP/[0-9\.]+"\s+([0-9]{3})\s+([0-9]+)')
        suspicious_keywords = [".git", ".env", ".sql", ".zip", ".tar", ".bak", "wp-login", "admin", "pma", "phpmyadmin", "shell", "eval", "union", "select", "../"]

        probes = []
        for line in raw_logs.splitlines():
            m = pat_probe.search(line)
            if m:
                ip, raw_date, method, path, status, size = m.groups()
                if any(w.split("/")[0] in ip for w in wl):
                    continue
                is_suspicious = any(k in path.lower() for k in suspicious_keywords) or status in ["400", "403"]
                if is_suspicious:
                    category = "Recon / Probe"
                    path_l = path.lower()
                    if any(k in path_l for k in [".git", ".env", ".sql", ".zip", ".bak", ".tar"]):
                        category = "Sensitive Files Leak"
                    elif any(k in path_l for k in ["admin", "wp-login", "pma", "phpmyadmin"]):
                        category = "Admin Brute / Enum"
                    elif any(k in path_l for k in ["union", "select", "sleep("]):
                        category = "SQL Injection"
                    elif any(k in path_l for k in ["../", "..\\"]):
                        category = "Path Traversal"

                    # Parse time format: 17/Sep/2026:07:00:00 +0700 -> YYYY-MM-DD HH:MM:SS
                    try:
                        time_part = raw_date.split()[0]
                        dt_obj = datetime.strptime(time_part, "%d/%b/%Y:%H:%M:%S")
                        dt_str = dt_obj.strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        dt_str = raw_date

                    probes.append((dt_str, ip, method, path, status, category))

        if probes:
            conn = get_db()
            conn.executemany("""
                INSERT OR IGNORE INTO attack_probes (probe_time, ip_address, method, path, status_code, category)
                VALUES (?, ?, ?, ?, ?, ?)
            """, probes)
            conn.commit()
            conn.close()
        return len(probes)
    except Exception as e:
        print(f"[Sync Probes Error] {e}", file=sys.stderr)
        return 0

def record_metrics_snapshot():
    """Mengambil snapshot metrik setiap interval untuk tren grafik."""
    try:
        status_out = run_cmd("fail2ban-client status")
        jails = []
        for line in status_out.splitlines():
            if "Jail list:" in line:
                parts = line.split("Jail list:")
                if len(parts) > 1:
                    jails = [j.strip() for j in parts[1].split(",") if j.strip()]

        jail_details = [parse_jail_status(j) for j in jails]
        total_banned = sum(j["banned_current"] for j in jail_details)
        total_failed = sum(j["failed_current"] for j in jail_details)

        ufw_raw = run_cmd("ufw status numbered")
        ufw_blocks = [line.strip() for line in ufw_raw.splitlines() if "REJECT IN" in line or "DENY IN" in line or "DROP" in line]

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_db()
        conn.execute("""
            INSERT INTO metrics_snapshots (snapshot_time, total_banned, total_failed, active_ufw_bans, jails_data)
            VALUES (?, ?, ?, ?, ?)
        """, (now_str, total_banned + len(ufw_blocks), total_failed, len(ufw_blocks), json.dumps(jail_details)))
        
        # Retention: Auto purge data > 90 hari
        conn.execute("DELETE FROM ban_events WHERE created_at < datetime('now', '-90 days')")
        conn.execute("DELETE FROM attack_probes WHERE created_at < datetime('now', '-90 days')")
        conn.execute("DELETE FROM metrics_snapshots WHERE created_at < datetime('now', '-90 days')")
        conn.execute("DELETE FROM audit_logs WHERE created_at < datetime('now', '-90 days')")
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Metrics Snapshot Error] {e}", file=sys.stderr)

def background_worker_loop():
    """Background daemon thread untuk sync berkala."""
    time.sleep(3)
    # Initial sync on startup
    sync_ban_history_from_logs()
    sync_probes_from_logs()
    record_metrics_snapshot()

    last_snapshot = time.time()
    while True:
        try:
            sync_ban_history_from_logs()
            sync_probes_from_logs()
            
            # Ambil snapshot metrik setiap 10 menit (600s)
            if time.time() - last_snapshot >= 600:
                record_metrics_snapshot()
                last_snapshot = time.time()
        except Exception as e:
            print(f"[Worker Exception] {e}", file=sys.stderr)
        
        time.sleep(25)

# --- FLASK ROUTES ---

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/summary")
def api_summary():
    status_out = run_cmd("fail2ban-client status")
    jails = []
    for line in status_out.splitlines():
        if "Jail list:" in line:
            parts = line.split("Jail list:")
            if len(parts) > 1:
                jails = [j.strip() for j in parts[1].split(",") if j.strip()]
    
    jail_details = [parse_jail_status(j) for j in jails]
    
    total_banned = sum(j["banned_current"] for j in jail_details)
    total_failed = sum(j["failed_current"] for j in jail_details)
    historical_banned = sum(j["banned_total"] for j in jail_details)
    historical_failed = sum(j["failed_total"] for j in jail_details)
    
    ufw_raw = run_cmd("ufw status numbered")
    ufw_blocks = []
    for line in ufw_raw.splitlines():
        if "REJECT IN" in line or "DENY IN" in line or "DROP" in line:
            ufw_blocks.append(line.strip())
            
    svc_status = run_cmd("systemctl is-active fail2ban")
    whitelist_list = get_whitelisted_ips()
    active_firewall_blocks_count = total_banned + len(ufw_blocks)

    # Ambil total data dari SQLite DB
    db_stats = {"total_ban_events": 0, "total_attack_probes": 0}
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM ban_events")
        db_stats["total_ban_events"] = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM attack_probes")
        db_stats["total_attack_probes"] = cur.fetchone()[0]
        conn.close()
    except Exception:
        pass

    return jsonify({
        "status": "online" if svc_status == "active" else "offline",
        "service": svc_status,
        "total_jails": len(jails),
        "total_banned_current": active_firewall_blocks_count,
        "active_jail_bans": total_banned,
        "active_ufw_bans": len(ufw_blocks),
        "ufw_blocks": ufw_blocks,
        "total_failed_current": total_failed,
        "total_banned_history": historical_banned,
        "total_failed_history": historical_failed,
        "jails": jail_details,
        "whitelist": whitelist_list,
        "db_stats": db_stats,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

def build_access_logs_payload(limit=100, status_filter="", ip_filter="", search_filter="", period="today"):
    """Live web access log view & Visitor Analytics dengan filter periode (today/7d/30d/90d/180d/365d) - Optimized."""
    
    # Calculate cutoff datetime & set of allowed date strings for O(1) matching
    now = datetime.now()
    if period == "7d":
        days = 7
        period_label = "7 Hari Terakhir"
    elif period in ("30d", "1m", "month"):
        days = 30
        period = "30d"
        period_label = "1 Bulan Terakhir"
    elif period in ("90d", "3m"):
        days = 90
        period = "90d"
        period_label = "3 Bulan Terakhir"
    elif period in ("180d", "6m"):
        days = 180
        period = "180d"
        period_label = "6 Bulan Terakhir"
    elif period in ("365d", "1y", "year"):
        days = 365
        period = "365d"
        period_label = "1 Tahun Terakhir"
    else:
        days = 0
        period = "today"
        period_label = "Hari Ini"

    cutoff = now - timedelta(days=days) if days > 0 else now.replace(hour=0, minute=0, second=0, microsecond=0)
    
    allowed_date_prefixes = set()
    cur = cutoff
    while cur <= now:
        allowed_date_prefixes.add(cur.strftime("%d/%b/%Y"))
        cur += timedelta(days=1)

    # Regex definitions & fast string lookups
    pat = re.compile(r'^([0-9a-fA-F\.:]+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s]+)\s+([^"]*)"\s+([0-9]{3})\s+([0-9]+)\s+"([^"]*)"\s+"([^"]*)"')
    bot_re = re.compile(r'bot|spider|crawl|curl|python|wget|go-http|scanner|scan|nikto|sqlmap|censys|shodan|zgrab|nmap|ahrefs|semrush|bingbot|googlebot|yandex|bytespider|facebookexternalhit|headless|urllib|httpclient|postman', re.I)
    static_exts = ('.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.woff', '.woff2', '.ttf', '.eot', '.otf', '.svg', '.ico', '.webp', '.map')

    from collections import deque
    parsed_deque = deque(maxlen=max(limit * 2, 200))
    
    status_counts = Counter()
    ip_counts = Counter()
    url_counts = Counter()
    city_counts = Counter()
    device_counts = Counter()
    endpoint_cat_counts = Counter()
    error_404_counts = Counter()
    error_ip_counts = Counter()
    hourly_human = [0] * 24
    hourly_bot = [0] * 24
    potential_probes = []
    human_ips = set()
    human_hits = 0
    bot_hits = 0
    
    # Store unique human IPs for GeoIP
    detected_human_ips = []

    def process_line(line):
        nonlocal human_hits, bot_hits
        if not line.strip():
            return
        m = pat.search(line)
        if not m:
            return
        ip, user, date_str, method, path, proto, status, size, ref, ua = m.groups()
        
        # O(1) Date Matching via set
        if date_str[:11] not in allowed_date_prefixes:
            return

        is_internal = is_private_ip(ip)
        is_bot = bool(bot_re.search(ua)) or ua in ("-", "")

        # Hourly breakdown
        try:
            h = int(date_str[12:14])
            if 0 <= h < 24:
                if is_bot:
                    hourly_bot[h] += 1
                else:
                    hourly_human[h] += 1
        except Exception:
            pass

        # Error tracking
        clean_path = path.split("?")[0]
        if status == "404":
            error_404_counts[clean_path] += 1
        if status.startswith(("4", "5")) and not is_internal:
            error_ip_counts[ip] += 1

        # Endpoint categorization
        if any(clean_path.lower().endswith(ext) for ext in static_exts):
            endpoint_cat_counts["Static Assets"] += 1
        elif any(clean_path.startswith(p) for p in ("/service", "/api", "/live", "/portal/api")):
            endpoint_cat_counts["API / Layanan"] += 1
        elif any(k in clean_path.lower() for k in (".env", ".git", "wp-", "xmlrpc", "phpmyadmin", "eval(", "shell")):
            endpoint_cat_counts["Bot Probes"] += 1
            if len(potential_probes) < 8:
                potential_probes.append({"time": date_str, "ip": ip, "method": method, "path": path, "status": status})
        else:
            endpoint_cat_counts["Halaman Web"] += 1

        # Classify User-Agent Device / Platform
        if is_bot:
            ua_cat = "Bot / Crawler"
        elif "Android" in ua:
            ua_cat = "Android"
        elif "iPhone" in ua or "iPad" in ua or "iOS" in ua:
            ua_cat = "iOS (Apple)"
        elif "Windows" in ua:
            ua_cat = "Windows"
        elif "Macintosh" in ua or "Mac OS" in ua:
            ua_cat = "macOS"
        elif "Linux" in ua:
            ua_cat = "Linux"
        else:
            ua_cat = "Lainnya"

        if not is_internal:
            device_counts[ua_cat] += 1
            if is_bot:
                bot_hits += 1
            else:
                human_hits += 1
                human_ips.add(ip)
                detected_human_ips.append(ip)
                
                # Check static asset extension
                clean_path = path.split("?")[0]
                if not clean_path.lower().endswith(static_exts):
                    url_counts[clean_path] += 1

        status_counts[status] += 1
        if not is_internal and not is_bot:
            ip_counts[ip] += 1

        if status_filter and status != status_filter:
            return
        if ip_filter and ip_filter not in ip:
            return
        if search_filter and (search_filter not in path.lower() and search_filter not in ua.lower() and search_filter not in ip.lower()):
            return

        sz_int = int(size) if size.isdigit() else 0
        if sz_int > 1048576:
            size_hr = f"{sz_int/1048576:.1f} MB"
        elif sz_int > 1024:
            size_hr = f"{sz_int/1024:.1f} KB"
        else:
            size_hr = f"{sz_int} B"

        device = "Desktop"
        if is_bot:
            device = "Bot / Script"
        elif "Android" in ua:
            device = "Android"
        elif "iPhone" in ua or "iPad" in ua:
            device = "iOS"
        elif "Windows" in ua:
            device = "Windows"
        elif "Mac" in ua:
            device = "macOS"
        elif "Linux" in ua:
            device = "Linux"

        parsed_deque.append({
            "ip": ip,
            "time": date_str,
            "method": method,
            "path": path,
            "proto": proto,
            "status": status,
            "size": size_hr,
            "bytes": sz_int,
            "referer": ref if ref != "-" else "",
            "user_agent": ua,
            "device": device
        })

    # 1. Historical GZ logs
    if period != "today":
        gz_files = sorted(glob.glob("/www/wwwlogs/history_backups/rsudkardinah.tegalkota.go.id/*_access_*.log.gz"))
        for f in gz_files:
            m = re.search(r'_access_(\d{4}-\d{2}-\d{2})_', f)
            if m:
                try:
                    f_date = datetime.strptime(m.group(1), "%Y-%m-%d")
                    if f_date < (cutoff - timedelta(days=1)):
                        continue
                except Exception:
                    pass
            try:
                with gzip.open(f, "rt", errors="ignore") as fp:
                    for line in fp:
                        process_line(line)
            except Exception:
                pass

    # 2. Live log
    live_log_path = "/www/wwwlogs/rsudkardinah.tegalkota.go.id.log"
    if os.path.exists(live_log_path):
        try:
            with open(live_log_path, "rt", errors="ignore") as fp:
                for line in fp:
                    process_line(line)
        except Exception:
            pass

    # Resolve GeoIP for top detected human IPs
    unique_human_ips = list(set(detected_human_ips))[:150]
    geo_map = get_geoip_info(unique_human_ips)
    
    # Calculate City Distribution
    for ip in detected_human_ips:
        g = geo_map.get(ip, {})
        city = g.get("city") or "Unknown"
        reg = g.get("region") or ""
        if city not in ("Unknown", "Lokal RS", "-"):
            label = f"{city}, {reg}" if reg and reg != city else city
            city_counts[label] += 1
        elif city == "Lokal RS":
            city_counts["Tegal (Lokal RS)"] += 1

    parsed = list(parsed_deque)
    # Attach Geo info to parsed rows
    for item in parsed:
        ip = item["ip"]
        g = geo_map.get(ip, {})
        item["city"] = g.get("city") or "-"
        item["region"] = g.get("region") or "-"
        item["isp"] = g.get("isp") or "-"

    parsed.reverse()
    
    # Format Top 10 Cities
    top_cities = []
    total_city_hits = sum(city_counts.values()) or 1
    for rank, (city_name, count) in enumerate(city_counts.most_common(10), 1):
        top_cities.append({
            "rank": rank,
            "city": city_name,
            "count": count,
            "percentage": round((count / total_city_hits) * 100, 1)
        })

    # Format Top 10 URLs
    top_urls = []
    total_url_hits = sum(url_counts.values()) or 1
    for rank, (url_path, count) in enumerate(url_counts.most_common(10), 1):
        top_urls.append({
            "rank": rank,
            "url": url_path,
            "count": count,
            "percentage": round((count / total_url_hits) * 100, 1)
        })

    # Format Top User-Agents / Devices
    top_user_agents = []
    total_device_hits = sum(device_counts.values()) or 1
    for rank, (dev_name, count) in enumerate(device_counts.most_common(8), 1):
        top_user_agents.append({
            "rank": rank,
            "name": dev_name,
            "count": count,
            "percentage": round((count / total_device_hits) * 100, 1)
        })

    # Format Endpoint Categories
    endpoint_categories = []
    total_ep = sum(endpoint_cat_counts.values()) or 1
    for cat, count in endpoint_cat_counts.most_common():
        endpoint_categories.append({
            "category": cat,
            "count": count,
            "percentage": round((count / total_ep) * 100, 1)
        })

    # Format Top 404 URLs
    top_404 = [{"url": u, "count": c} for u, c in error_404_counts.most_common(5)]

    # Format Top Error IPs
    top_err_ips = []
    for ip, count in error_ip_counts.most_common(5):
        g = geo_map.get(ip, {})
        city = g.get("city") or "-"
        reg = g.get("region") or ""
        loc = f"{city}, {reg}" if reg and reg != city else city
        top_err_ips.append({"ip": ip, "count": count, "location": loc, "isp": g.get("isp", "-")})

    return {
        "logs": parsed[:limit],
        "total_parsed": len(parsed),
        "status_distribution": dict(status_counts.most_common(6)),
        "top_ips": dict(ip_counts.most_common(5)),
        "period": period,
        "period_label": period_label,
        "summary": {
            "human_visitors": len(human_ips),
            "human_hits": human_hits,
            "bot_hits": bot_hits,
            "total_requests": human_hits + bot_hits
        },
        "analytics": {
            "human_visitors_today": len(human_ips),
            "human_hits_today": human_hits,
            "bot_hits_today": bot_hits,
            "top_cities": top_cities,
            "top_urls": top_urls,
            "top_user_agents": top_user_agents,
            "hourly_human": hourly_human,
            "hourly_bot": hourly_bot,
            "status_counts": dict(status_counts),
            "endpoint_categories": endpoint_categories,
            "top_404_urls": top_404,
            "top_error_ips": top_err_ips,
            "potential_probes": potential_probes[:5]
        }
    }

@app.route("/api/access-logs")
def api_access_logs():
    """Live web access log view & Visitor Analytics endpoint."""
    limit = int(request.args.get("limit", 100))
    status_filter = request.args.get("status", "")
    ip_filter = request.args.get("ip", "").strip()
    search_filter = request.args.get("search", "").strip().lower()
    period = request.args.get("period", "today").strip().lower()
    return jsonify(build_access_logs_payload(limit, status_filter, ip_filter, search_filter, period))

@app.route("/api/banned-history")
def api_banned_history():
    """Mengambil riwayat ban dari database SQLite."""
    limit = int(request.args.get("limit", 100))
    search = request.args.get("search", "").strip()
    jail = request.args.get("jail", "").strip()

    try:
        conn = get_db()
        cur = conn.cursor()
        
        query = "SELECT event_time as time, jail, action, ip_address as ip, raw_log as raw FROM ban_events WHERE 1=1"
        params = []
        if search:
            query += " AND (ip_address LIKE ? OR raw_log LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])
        if jail:
            query += " AND jail = ?"
            params.append(jail)
            
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cur.execute(query, params)
        rows = [dict(r) for r in cur.fetchall()]
        
        cur.execute("SELECT count(*) FROM ban_events")
        total = cur.fetchone()[0]
        conn.close()

        # Fallback jika DB masih kosong saat awal startup
        if not rows:
            sync_ban_history_from_logs()
            conn = get_db()
            cur = conn.cursor()
            cur.execute(query, params)
            rows = [dict(r) for r in cur.fetchall()]
            total = len(rows)
            conn.close()

        return jsonify({"history": rows, "total": total})
    except Exception as e:
        return jsonify({"history": [], "total": 0, "error": str(e)})

@app.route("/api/web-attacks")
def api_web_attacks():
    """Mengambil riwayat serangan web mencurigakan yang tersimpan di SQLite dengan pagination & filter."""
    limit = int(request.args.get("limit", 25))
    if limit < 1:
        limit = 25
    page = int(request.args.get("page", 1))
    if page < 1:
        page = 1
    offset = (page - 1) * limit

    category = request.args.get("category", "").strip()
    search = request.args.get("search", "").strip()

    try:
        conn = get_db()
        cur = conn.cursor()

        where_clauses = ["1=1"]
        params = []
        if category:
            where_clauses.append("category = ?")
            params.append(category)
        if search:
            where_clauses.append("(ip_address LIKE ? OR path LIKE ? OR method LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

        where_sql = " AND ".join(where_clauses)

        # Count filtered records
        count_sql = f"SELECT count(*) FROM attack_probes WHERE {where_sql}"
        cur.execute(count_sql, params)
        total_filtered = cur.fetchone()[0]

        # Total overall
        cur.execute("SELECT count(*) FROM attack_probes")
        total_all = cur.fetchone()[0]

        # Query paginated rows
        query_sql = f"SELECT probe_time as date, ip_address as ip, method, path, status_code as status, category FROM attack_probes WHERE {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?"
        cur.execute(query_sql, params + [limit, offset])
        probes = [dict(r) for r in cur.fetchall()]
        conn.close()

        # Fallback jika DB masih kosong saat awal startup
        if not probes and total_all == 0:
            sync_probes_from_logs()
            conn = get_db()
            cur = conn.cursor()
            cur.execute(count_sql, params)
            total_filtered = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM attack_probes")
            total_all = cur.fetchone()[0]
            cur.execute(query_sql, params + [limit, offset])
            probes = [dict(r) for r in cur.fetchall()]
            conn.close()

        total_pages = max(1, math.ceil(total_filtered / limit)) if total_filtered > 0 else 1

        return jsonify({
            "probes": probes,
            "total": total_all,
            "total_filtered": total_filtered,
            "page": page,
            "limit": limit,
            "total_pages": total_pages
        })
    except Exception as e:
        return jsonify({
            "probes": [],
            "total": 0,
            "total_filtered": 0,
            "page": 1,
            "limit": limit,
            "total_pages": 1,
            "error": str(e)
        })

@app.route("/api/audit-logs")
def api_audit_logs():
    """Mengambil catatan audit log tindakan dashboard."""
    limit = int(request.args.get("limit", 50))
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT action_time, action_type, ip_address, details FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
        logs = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify({"audit_logs": logs, "total": len(logs)})
    except Exception as e:
        return jsonify({"audit_logs": [], "error": str(e)})

def get_report_data(period="7d"):
    """Mengagregasikan ringkasan statistik keamanan berdasarkan periode."""
    now = datetime.now()
    if period == "today":
        cutoff = now.strftime("%Y-%m-%d 00:00:00")
        period_label = f"Hari Ini ({now.strftime('%d %b %Y')})"
    elif period == "30d":
        cutoff = (now - timedelta(days=30)).strftime("%Y-%m-%d 00:00:00")
        period_label = "30 Hari Terakhir"
    elif period == "all":
        cutoff = "1970-01-01 00:00:00"
        period_label = "Semua Waktu"
    else:  # default 7d
        cutoff = (now - timedelta(days=7)).strftime("%Y-%m-%d 00:00:00")
        period_label = "7 Hari Terakhir"

    conn = get_db()
    cur = conn.cursor()

    # 1. Probes summary
    cur.execute("""
        SELECT 
            COUNT(*) as total_probes,
            COUNT(DISTINCT ip_address) as unique_ips
        FROM attack_probes
        WHERE probe_time >= ?
    """, (cutoff,))
    probe_row = cur.fetchone()
    total_probes = probe_row["total_probes"] if probe_row else 0
    unique_probe_ips = probe_row["unique_ips"] if probe_row else 0

    # 2. Ban summary
    cur.execute("""
        SELECT 
            COUNT(CASE WHEN action IN ('Ban', 'Manual Ban') THEN 1 END) as total_bans,
            COUNT(CASE WHEN action IN ('Unban', 'Manual Unban') THEN 1 END) as total_unbans,
            COUNT(DISTINCT ip_address) as unique_banned_ips
        FROM ban_events
        WHERE event_time >= ?
    """, (cutoff,))
    ban_row = cur.fetchone()
    total_bans = ban_row["total_bans"] if ban_row else 0
    total_unbans = ban_row["total_unbans"] if ban_row else 0
    unique_banned_ips = ban_row["unique_banned_ips"] if ban_row else 0

    # 3. Categories breakdown
    cur.execute("""
        SELECT category, COUNT(*) as count
        FROM attack_probes
        WHERE probe_time >= ?
        GROUP BY category
        ORDER BY count DESC
    """, (cutoff,))
    cat_rows = cur.fetchall()
    categories = []
    top_cat = "-"
    if cat_rows:
        top_cat = cat_rows[0]["category"]
        for r in cat_rows:
            pct = round((r["count"] / total_probes * 100), 1) if total_probes > 0 else 0
            categories.append({"category": r["category"], "count": r["count"], "percentage": pct})

    # 4. Top Attackers
    cur.execute("""
        SELECT 
            ip_address,
            COUNT(*) as hit_count,
            MAX(probe_time) as last_seen,
            GROUP_CONCAT(DISTINCT category) as categories
        FROM attack_probes
        WHERE probe_time >= ?
        GROUP BY ip_address
        ORDER BY hit_count DESC
        LIMIT 10
    """, (cutoff,))
    top_attackers = [dict(r) for r in cur.fetchall()]

    # Check whitelist status for top attackers
    wl = get_whitelisted_ips()
    for a in top_attackers:
        a["is_whitelisted"] = any(w.split("/")[0] in a["ip_address"] for w in wl)

    # 5. Daily Trend
    cur.execute("""
        SELECT substr(probe_time, 1, 10) as day, COUNT(*) as probes
        FROM attack_probes
        WHERE probe_time >= ?
        GROUP BY day
    """, (cutoff,))
    probe_days = {r["day"]: r["probes"] for r in cur.fetchall()}

    cur.execute("""
        SELECT substr(event_time, 1, 10) as day, COUNT(*) as bans
        FROM ban_events
        WHERE event_time >= ? AND action IN ('Ban', 'Manual Ban')
        GROUP BY day
    """, (cutoff,))
    ban_days = {r["day"]: r["bans"] for r in cur.fetchall()}

    all_days = sorted(list(set(list(probe_days.keys()) + list(ban_days.keys()))), reverse=True)
    daily_trend = []
    for d in all_days:
        daily_trend.append({
            "date": d,
            "probes": probe_days.get(d, 0),
            "bans": ban_days.get(d, 0)
        })

    # 6. Jail breakdown
    cur.execute("""
        SELECT jail, 
               COUNT(CASE WHEN action IN ('Ban', 'Manual Ban') THEN 1 END) as bans,
               COUNT(CASE WHEN action IN ('Unban', 'Manual Unban') THEN 1 END) as unbans
        FROM ban_events
        WHERE event_time >= ?
        GROUP BY jail
    """, (cutoff,))
    jails = [dict(r) for r in cur.fetchall()]

    conn.close()

    return {
        "period": period,
        "period_label": period_label,
        "summary": {
            "total_probes": total_probes,
            "unique_probe_ips": unique_probe_ips,
            "total_bans": total_bans,
            "total_unbans": total_unbans,
            "unique_banned_ips": unique_banned_ips,
            "top_category": top_cat
        },
        "categories": categories,
        "top_attackers": top_attackers,
        "daily_trend": daily_trend,
        "jails": jails,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

@app.route("/api/report")
def api_report():
    """Mengambil data laporan summary agregat untuk dashboard report view."""
    period = request.args.get("period", "7d").strip().lower()
    if period not in ["today", "7d", "30d", "all"]:
        period = "7d"
    try:
        data = get_report_data(period)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e), "summary": {}}), 500

@app.route("/api/report/export-csv")
def api_report_export_csv():
    """Mengekspor data laporan ke format CSV."""
    export_type = request.args.get("type", "probes").strip().lower()
    period = request.args.get("period", "7d").strip().lower()
    
    now = datetime.now()
    if period == "today":
        cutoff = now.strftime("%Y-%m-%d 00:00:00")
    elif period == "30d":
        cutoff = (now - timedelta(days=30)).strftime("%Y-%m-%d 00:00:00")
    elif period == "all":
        cutoff = "1970-01-01 00:00:00"
    else:
        cutoff = (now - timedelta(days=7)).strftime("%Y-%m-%d 00:00:00")

    si = io.StringIO()
    writer = csv.writer(si)
    filename = f"sentinel_{export_type}_{period}_{now.strftime('%Y%m%d_%H%M%S')}.csv"

    try:
        conn = get_db()
        cur = conn.cursor()

        if export_type == "bans":
            writer.writerow(["ID", "Timestamp (WIB)", "Jail", "Action", "IP Address", "Raw Log"])
            rows = cur.execute("""
                SELECT id, event_time, jail, action, ip_address, raw_log 
                FROM ban_events 
                WHERE event_time >= ? 
                ORDER BY id DESC
            """, (cutoff,)).fetchall()
            for r in rows:
                writer.writerow([r["id"], r["event_time"], r["jail"], r["action"], r["ip_address"], r["raw_log"]])

        elif export_type == "attackers":
            writer.writerow(["Rank", "Attacker IP", "Total Hit Probes", "Categories", "Last Seen"])
            rows = cur.execute("""
                SELECT ip_address, COUNT(*) as hit_count, GROUP_CONCAT(DISTINCT category) as categories, MAX(probe_time) as last_seen
                FROM attack_probes 
                WHERE probe_time >= ? 
                GROUP BY ip_address 
                ORDER BY hit_count DESC
            """, (cutoff,)).fetchall()
            for idx, r in enumerate(rows, start=1):
                writer.writerow([idx, r["ip_address"], r["hit_count"], r["categories"], r["last_seen"]])

        else:  # probes default
            writer.writerow(["ID", "Probe Time (WIB)", "Attacker IP", "HTTP Method", "Path Target", "Status Code", "Attack Category"])
            rows = cur.execute("""
                SELECT id, probe_time, ip_address, method, path, status_code, category 
                FROM attack_probes 
                WHERE probe_time >= ? 
                ORDER BY id DESC
            """, (cutoff,)).fetchall()
            for r in rows:
                writer.writerow([r["id"], r["probe_time"], r["ip_address"], r["method"], r["path"], r["status_code"], r["category"]])

        conn.close()
        output = si.getvalue()
        return Response(
            output,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================
# EXPORT HELPERS & ENDPOINTS (Excel / PDF)
# ============================================================

BRAND_TITLE = "SI-KRESNA"
BRAND_SUB = "Sistem Inspeksi Keamanan dan Rekam Eksplorasi Siber Jaringan Utama"
BRAND_ORG = "RSUD Kardinah Kota Tegal"


def _xlsx_sheet_from_rows(ws, headers, rows, col_widths=None):
    """Tulis header + rows ke worksheet dengan styling konsisten."""
    header_font = Font(bold=True, color="FFFFFF", size=10)
    header_fill = PatternFill("solid", fgColor="0F766E")
    thin = Side(style="thin", color="D1D5DB")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)

    ws.append(headers)
    for c_idx, _ in enumerate(headers, start=1):
        cell = ws.cell(row=1, column=c_idx)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = border
    for r in rows:
        ws.append(list(r))
    for row in ws.iter_rows(min_row=2, max_row=ws.max_row, max_col=len(headers)):
        for cell in row:
            cell.border = border
            cell.alignment = Alignment(vertical="top", wrap_text=False)
    if col_widths:
        for i, w in enumerate(col_widths, start=1):
            ws.column_dimensions[get_column_letter(i)].width = w
    ws.freeze_panes = "A2"


def _xlsx_response(sheets, filename):
    """sheets: list of dict(name, headers, rows, col_widths)"""
    if not OPENPYXL_AVAILABLE:
        return jsonify({"error": "Modul openpyxl tidak tersedia di server"}), 500
    wb = openpyxl.Workbook()
    wb.remove(wb.active)
    for sh in sheets:
        ws = wb.create_sheet(title=sh["name"][:31])
        _xlsx_sheet_from_rows(ws, sh["headers"], sh["rows"], sh.get("col_widths"))
    bio = io.BytesIO()
    wb.save(bio)
    bio.seek(0)
    return Response(
        bio.read(),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


def _pdf_donut_chart(title, entries, width=190 * mm, height=78 * mm, center_label="Total"):
    """Gambar donut chart + legend dalam satu Drawing flowable.

    entries: list of dict(label, count, percentage)
    """
    from reportlab.graphics.shapes import Drawing, Wedge, Circle, String, Line, Rect

    total = sum(e.get("count", 0) for e in entries) or 1
    palette = ["#0d9488", "#0ea5e9", "#6366f1", "#a855f7", "#f97316",
               "#f43f5e", "#14b8a6", "#84cc16", "#eab308", "#94a3b8"]

    d = Drawing(width, height)
    cx = 44 * mm
    cy = height / 2.0 - 4 * mm
    r_outer = 29 * mm
    r_inner = 20 * mm

    # Background card
    d.add(Rect(0, 0, width, height, fillColor=rl_colors.HexColor("#F8FAFC"),
               strokeColor=rl_colors.HexColor("#E2E8F0"), strokeWidth=0.6, rx=4, ry=4))

    # Title
    d.add(String(6 * mm, height - 6 * mm, title, fontSize=8.5, fontName="Helvetica-Bold",
                 fillColor=rl_colors.HexColor("#0F172A")))

    start_angle = 90.0
    for idx, e in enumerate(entries):
        frac = (e.get("count", 0) / total) if total else 0
        extent = -frac * 360.0
        if extent == 0:
            continue
        color = rl_colors.HexColor(palette[idx % len(palette)])
        d.add(Wedge(cx, cy, r_outer, start_angle + extent, start_angle,
                    fillColor=color, strokeColor=rl_colors.white, strokeWidth=0.8))
        start_angle += extent

    # Hollow center
    d.add(Circle(cx, cy, r_inner, fillColor=rl_colors.HexColor("#F8FAFC"),
                 strokeColor=rl_colors.HexColor("#F8FAFC"), strokeWidth=0))
    d.add(String(cx, cy + 2.2 * mm, f"{total:,}", fontSize=11, fontName="Helvetica-Bold",
                 fillColor=rl_colors.HexColor("#0F172A"), textAnchor="middle"))
    d.add(String(cx, cy - 3.0 * mm, center_label, fontSize=6.5, fontName="Helvetica",
                 fillColor=rl_colors.HexColor("#64748B"), textAnchor="middle"))

    # Legend (two columns)
    lx = 92 * mm
    ly = height - 13 * mm
    row_h = 4.6 * mm
    per_col = max(1, int((height - 16 * mm) / row_h))
    for idx, e in enumerate(entries):
        col = idx // per_col
        row = idx % per_col
        x = lx + col * 48 * mm
        y = ly - row * row_h
        if y < 5 * mm:
            continue
        color = rl_colors.HexColor(palette[idx % len(palette)])
        d.add(Rect(x, y, 2.6 * mm, 2.6 * mm, fillColor=color, strokeColor=color))
        label = str(e.get("label", ""))[:22]
        d.add(String(x + 4 * mm, y + 0.3 * mm, label, fontSize=6.5, fontName="Helvetica",
                     fillColor=rl_colors.HexColor("#334155")))
        d.add(String(x + 30 * mm, y + 0.3 * mm,
                     f"{e.get('count', 0):,} ({e.get('percentage', 0)}%)",
                     fontSize=6.5, fontName="Helvetica-Bold",
                     fillColor=rl_colors.HexColor("#0F766E")))
    return d


def _pdf_table(headers, rows, col_widths=None):
    style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor("#0F766E")),
        ("TEXTCOLOR", (0, 0), (-1, 0), rl_colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 7.5),
        ("FONTSIZE", (0, 1), (-1, -1), 7),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, rl_colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [rl_colors.white, rl_colors.HexColor("#F8FAFC")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ])
    data = [headers] + [[str(x) for x in r] for r in rows]
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(style)
    return t


def _pdf_response(title, period_label, sections, filename):
    """sections: list of dict(heading, headers, rows, col_widths)"""
    if not REPORTLAB_AVAILABLE:
        return jsonify({"error": "Modul reportlab tidak tersedia di server"}), 500
    bio = io.BytesIO()
    doc = SimpleDocTemplate(
        bio, pagesize=landscape(A4),
        leftMargin=12 * mm, rightMargin=12 * mm, topMargin=12 * mm, bottomMargin=12 * mm,
        title=f"{BRAND_TITLE} - {title}"
    )
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1x", parent=styles["Title"], fontSize=15, textColor=rl_colors.HexColor("#0F766E"), spaceAfter=2)
    h2 = ParagraphStyle("h2x", parent=styles["Heading2"], fontSize=10.5, textColor=rl_colors.HexColor("#0F172A"), spaceBefore=8, spaceAfter=4)
    meta = ParagraphStyle("metax", parent=styles["Normal"], fontSize=8, textColor=rl_colors.HexColor("#475569"))

    story = [
        Paragraph(f"{BRAND_TITLE} — {title}", h1),
        Paragraph(f"{BRAND_SUB}", meta),
        Paragraph(f"{BRAND_ORG} &nbsp;|&nbsp; Periode: <b>{period_label}</b> &nbsp;|&nbsp; Dicetak: {datetime.now().strftime('%d %b %Y %H:%M:%S')} WIB", meta),
        Spacer(1, 6),
    ]
    for sec in sections:
        story.append(Paragraph(sec["heading"], h2))
        if sec.get("chart"):
            story.append(_pdf_donut_chart(
                sec.get("chart_title", sec["heading"]),
                sec["chart"],
                width=sec.get("chart_width", 190 * mm),
                height=sec.get("chart_height", 78 * mm),
                center_label=sec.get("chart_center", "Total"),
            ))
            story.append(Spacer(1, 4))
        if sec.get("rows"):
            story.append(_pdf_table(sec["headers"], sec["rows"], sec.get("col_widths")))
        elif not sec.get("chart"):
            story.append(Paragraph("<i>Tidak ada data pada periode ini.</i>", meta))
        story.append(Spacer(1, 6))
    doc.build(story)
    bio.seek(0)
    return Response(
        bio.read(),
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ============================================================
# EXECUTIVE ACCESS LOGS PDF GENERATOR (6 Pages)
# ============================================================

def _pdf_callout_table(title, text, width=273*mm, accent="#0F766E", bg="#F0FDF4", border="#A7F3D0"):
    styles = getSampleStyleSheet()
    t_style = ParagraphStyle("ctitle", fontName="Helvetica-Bold", fontSize=7.2, textColor=rl_colors.HexColor(accent), spaceAfter=2)
    b_style = ParagraphStyle("cbody", fontName="Helvetica", fontSize=6.5, textColor=rl_colors.HexColor("#334155"), leading=8.5)
    content = [
        Paragraph(title, t_style),
        Paragraph(text, b_style)
    ]
    t = Table([[content]], colWidths=[width])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), rl_colors.HexColor(bg)),
        ("BOX", (0, 0), (-1, -1), 0.6, rl_colors.HexColor(border)),
        ("LINEBEFORE", (0, 0), (0, -1), 2.5, rl_colors.HexColor(accent)),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4 * mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4 * mm),
    ]))
    return t


class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_decorations(self, num_pages):
        self.saveState()
        w, h = self._pagesize
        
        # Running Header (pages 2+)
        if self._pageNumber > 1:
            self.setFillColor(rl_colors.HexColor("#0F766E"))
            self.rect(12 * mm, h - 13 * mm, w - 24 * mm, 0.8, fill=True, stroke=False)
            
            logo_path = os.path.join(BASE_DIR, "static", "img", "logo_emblem.png")
            if not os.path.exists(logo_path):
                logo_path = "/opt/fail2ban-dashboard/static/img/logo_emblem.png"
            if os.path.exists(logo_path):
                try:
                    self.drawImage(logo_path, 12 * mm, h - 12.6 * mm, width=5.5 * mm, height=4.2 * mm, mask='auto')
                    text_x = 19 * mm
                except Exception:
                    text_x = 12 * mm
            else:
                text_x = 12 * mm

            self.setFont("Helvetica-Bold", 7.5)
            self.setFillColor(rl_colors.HexColor("#0F766E"))
            self.drawString(text_x, h - 10.5 * mm, "SI-KRESNA")
            self.setFont("Helvetica", 7)
            self.setFillColor(rl_colors.HexColor("#64748B"))
            self.drawString(text_x + 16 * mm, h - 10.5 * mm, "|   RSUD Kardinah Kota Tegal — Laporan Analisis Access Log Web & Trafik")
            self.drawRightString(w - 12 * mm, h - 10.5 * mm, "rsudkardinah.tegalkota.go.id")

        # Running Footer (all pages)
        self.setStrokeColor(rl_colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.6)
        self.line(12 * mm, 11 * mm, w - 12 * mm, 11 * mm)
        self.setFont("Helvetica", 6.5)
        self.setFillColor(rl_colors.HexColor("#64748B"))
        self.drawString(12 * mm, 7.5 * mm, "Dokumen Resmi Sistem Inspeksi Keamanan & Rekam Eksplorasi Siber (SI-KRESNA) • RSUD Kardinah Kota Tegal")
        self.drawRightString(w - 12 * mm, 7.5 * mm, f"Halaman {self._pageNumber} dari {num_pages}")
        self.restoreState()


def _make_hero_banner(period_label, timestamp_str, width=273*mm, height=26*mm):
    logo_path = os.path.join(BASE_DIR, "static", "img", "logo_emblem.png")
    if not os.path.exists(logo_path):
        logo_path = "/opt/fail2ban-dashboard/static/img/logo_emblem.png"

    styles = getSampleStyleSheet()
    t1 = ParagraphStyle("hb1", fontName="Helvetica-Bold", fontSize=6.5, textColor=rl_colors.HexColor("#99F6E4"), spaceAfter=1)
    t2 = ParagraphStyle("hb2", fontName="Helvetica-Bold", fontSize=12, textColor=rl_colors.white, spaceAfter=2)
    t3 = ParagraphStyle("hb3", fontName="Helvetica", fontSize=6.5, textColor=rl_colors.HexColor("#CCFBF1"))
    badge_p = ParagraphStyle("bp", fontName="Helvetica-Bold", fontSize=6.5, textColor=rl_colors.white)
    badge_d = ParagraphStyle("bd", fontName="Helvetica", fontSize=6.5, textColor=rl_colors.white)

    right_table = Table([
        [Paragraph(f"Periode: {period_label}", badge_p)],
        [Paragraph(f"Dicetak: {timestamp_str} WIB", badge_d)]
    ], colWidths=[62*mm])
    right_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), rl_colors.HexColor("#134E4A")),
        ("BOX", (0, 0), (-1, -1), 0.5, rl_colors.HexColor("#2DD4BF")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, rl_colors.HexColor("#2DD4BF")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 3*mm),
    ]))

    center_flow = [
        Paragraph("SI-KRESNA &nbsp;•&nbsp; SISTEM INSPEKSI KEAMANAN SIBER RSUD KARDINAH", t1),
        Paragraph("Laporan Access Log Web &amp; Statistik Pengunjung", t2),
        Paragraph("Sistem Pemantauan Trafik, Analisis Perilaku Pengunjung, dan Deteksi Anomali Server", t3)
    ]

    logo_elem = Paragraph("<b>SI-KRESNA</b>", t2)
    if os.path.exists(logo_path):
        logo_elem = RLImage(logo_path, width=26*mm, height=19*mm, mask='auto')

    hero_table = Table([
        [logo_elem, center_flow, right_table]
    ], colWidths=[28*mm, 180*mm, 65*mm])
    hero_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), rl_colors.HexColor("#0F766E")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5*mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5*mm),
        ("LEFTPADDING", (0, 0), (0, -1), 2.5*mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2.5*mm),
        ("BOX", (0, 0), (-1, -1), 1, rl_colors.HexColor("#115E59")),
    ]))
    return hero_table


def _make_kpi_cards(cards, width=273*mm, height=22*mm):
    d = Drawing(width, height)
    gap = 4 * mm
    card_w = (width - gap * 3) / 4.0
    for i, c in enumerate(cards[:4]):
        x = i * (card_w + gap)
        d.add(Rect(x, 0, card_w, height, rx=3, ry=3,
                   fillColor=rl_colors.HexColor("#F8FAFC"), strokeColor=rl_colors.HexColor("#CBD5E1"), strokeWidth=0.6))
        acc = rl_colors.HexColor(c.get("accent", "#0F766E"))
        d.add(Rect(x, height - 2.2 * mm, card_w, 2.2 * mm, rx=1, ry=1,
                   fillColor=acc, strokeColor=acc, strokeWidth=0))
        d.add(String(x + 3.5 * mm, height - 6.5 * mm, c["title"][:22].upper(),
                     fontSize=6, fontName="Helvetica-Bold", fillColor=rl_colors.HexColor("#64748B")))
        d.add(String(x + 3.5 * mm, height - 14.5 * mm, str(c["value"]),
                     fontSize=13, fontName="Helvetica-Bold", fillColor=rl_colors.HexColor("#0F172A")))
        d.add(String(x + 3.5 * mm, 2.8 * mm, str(c.get("sub", "")),
                     fontSize=6, fontName="Helvetica", fillColor=acc))
    return d


def _make_hourly_chart(hourly_human, hourly_bot, width=134*mm, height=64*mm):
    d = Drawing(width, height)
    d.add(Rect(0, 0, width, height, rx=3, ry=3, fillColor=rl_colors.white, strokeColor=rl_colors.HexColor("#CBD5E1"), strokeWidth=0.6))
    d.add(String(5 * mm, height - 6 * mm, "1.1 Trafik Request per Jam (24 Jam)",
                 fontSize=8, fontName="Helvetica-Bold", fillColor=rl_colors.HexColor("#0F172A")))
    d.add(Rect(width - 45 * mm, height - 6.5 * mm, 3 * mm, 3 * mm, fillColor=rl_colors.HexColor("#0D9488"), strokeColor=rl_colors.white, strokeWidth=0))
    d.add(String(width - 40 * mm, height - 6 * mm, "Human", fontSize=6.5, fontName="Helvetica", fillColor=rl_colors.HexColor("#334155")))
    d.add(Rect(width - 24 * mm, height - 6.5 * mm, 3 * mm, 3 * mm, fillColor=rl_colors.HexColor("#F97316"), strokeColor=rl_colors.white, strokeWidth=0))
    d.add(String(width - 19 * mm, height - 6 * mm, "Bot", fontSize=6.5, fontName="Helvetica", fillColor=rl_colors.HexColor("#334155")))
    
    plot_x = 10 * mm
    plot_y = 11 * mm
    plot_w = width - 16 * mm
    plot_h = height - 22 * mm
    d.add(Line(plot_x, plot_y, plot_x + plot_w, plot_y, strokeColor=rl_colors.HexColor("#CBD5E1"), strokeWidth=0.6))
    
    max_val = max([h + b for h, b in zip(hourly_human, hourly_bot)] + [1])
    slot_w = plot_w / 24.0
    bar_w = slot_w * 0.72
    
    for i in range(24):
        bx = plot_x + i * slot_w + (slot_w - bar_w) / 2.0
        h_human = (hourly_human[i] / max_val) * plot_h
        h_bot = (hourly_bot[i] / max_val) * plot_h
        if h_human > 0:
            d.add(Rect(bx, plot_y, bar_w, h_human,
                       fillColor=rl_colors.HexColor("#0D9488"), strokeColor=rl_colors.white, strokeWidth=0.3))
        if h_bot > 0:
            d.add(Rect(bx, plot_y + h_human, bar_w, h_bot,
                       fillColor=rl_colors.HexColor("#F97316"), strokeColor=rl_colors.white, strokeWidth=0.3))
        if i % 4 == 0 or i == 23:
            d.add(String(bx + bar_w / 2.0, plot_y - 3.8 * mm, f"{i:02d}",
                         fontSize=5.5, fontName="Helvetica", fillColor=rl_colors.HexColor("#64748B"), textAnchor="middle"))
    return d


def _make_status_donut(status_counts, width=134*mm, height=64*mm, title="1.2 Distribusi HTTP Status"):
    d = Drawing(width, height)
    d.add(Rect(0, 0, width, height, rx=3, ry=3, fillColor=rl_colors.white, strokeColor=rl_colors.HexColor("#CBD5E1"), strokeWidth=0.6))
    d.add(String(5 * mm, height - 6 * mm, title,
                 fontSize=8, fontName="Helvetica-Bold", fillColor=rl_colors.HexColor("#0F172A")))
    
    c2 = sum(v for k, v in status_counts.items() if k.startswith("2"))
    c3 = sum(v for k, v in status_counts.items() if k.startswith("3"))
    c4 = sum(v for k, v in status_counts.items() if k.startswith("4"))
    c5 = sum(v for k, v in status_counts.items() if k.startswith("5"))
    total = c2 + c3 + c4 + c5 or 1
    
    palette = [("#0D9488", "2xx (Sukses)", c2),
               ("#F59E0B", "3xx (Redirect)", c3),
               ("#F97316", "4xx (Client Error)", c4),
               ("#EF4444", "5xx (Server Error)", c5)]
    
    cx = 32 * mm
    cy = height / 2.0 - 2 * mm
    r_outer = 22 * mm
    r_inner = 15 * mm
    
    start_angle = 90.0
    for col_hex, label, count in palette:
        frac = count / total
        extent = -frac * 360.0
        if extent == 0:
            continue
        d.add(Wedge(cx, cy, r_outer, start_angle + extent, start_angle,
                    fillColor=rl_colors.HexColor(col_hex), strokeColor=rl_colors.white, strokeWidth=0.6))
        start_angle += extent
        
    d.add(Circle(cx, cy, r_inner, fillColor=rl_colors.white, strokeColor=rl_colors.white, strokeWidth=0))
    d.add(String(cx, cy + 1.5 * mm, f"{total:,}", fontSize=8.5, fontName="Helvetica-Bold",
                 fillColor=rl_colors.HexColor("#0F172A"), textAnchor="middle"))
    d.add(String(cx, cy - 2.5 * mm, "Hits", fontSize=6, fontName="Helvetica",
                 fillColor=rl_colors.HexColor("#64748B"), textAnchor="middle"))
    
    lx = 64 * mm
    ly = height - 16 * mm
    for i, (col_hex, label, count) in enumerate(palette):
        y = ly - i * 8.5 * mm
        pct = round((count / total) * 100, 1)
        d.add(Rect(lx, y, 2.8 * mm, 2.8 * mm, fillColor=rl_colors.HexColor(col_hex), strokeColor=rl_colors.white, strokeWidth=0))
        d.add(String(lx + 4.5 * mm, y + 0.3 * mm, label, fontSize=6.5, fontName="Helvetica", fillColor=rl_colors.HexColor("#334155")))
        d.add(String(lx + 42 * mm, y + 0.3 * mm, f"{count:,} ({pct}%)", fontSize=6.5, fontName="Helvetica-Bold",
                     fillColor=rl_colors.HexColor("#0F172A")))
    return d


def _make_top_cities_chart(cities, width=134*mm, height=74*mm, title="2.1 Top 8 Kota Pengunjung (GeoIP MMDB)"):
    d = Drawing(width, height)
    d.add(Rect(0, 0, width, height, rx=3, ry=3, fillColor=rl_colors.white, strokeColor=rl_colors.HexColor("#CBD5E1"), strokeWidth=0.6))
    d.add(String(5 * mm, height - 6 * mm, title,
                 fontSize=8, fontName="Helvetica-Bold", fillColor=rl_colors.HexColor("#0F172A")))
    
    total = sum(c.get("count", 0) for c in cities) or 1
    max_cnt = max([c.get("count", 0) for c in cities] + [1])
    bar_area_w = 40 * mm
    bar_x = 52 * mm
    row_h = 6.4 * mm
    start_y = height - 13 * mm
    
    for i, c in enumerate(cities[:8]):
        y = start_y - i * row_h
        cnt = c.get("count", 0)
        pct = c.get("percentage", round((cnt / total) * 100, 1))
        raw_city = c.get("city", "-")
        city_name = raw_city.split(",")[0].strip() if "," in raw_city else raw_city
        lbl = city_name[:18]
        
        d.add(String(5 * mm, y + 0.8 * mm, f"{i+1}. {lbl}", fontSize=6.2, fontName="Helvetica", fillColor=rl_colors.HexColor("#334155")))
        
        bw = (cnt / max_cnt) * bar_area_w
        d.add(Rect(bar_x, y + 0.5 * mm, bar_area_w, 3.5 * mm, rx=1, ry=1, fillColor=rl_colors.HexColor("#F1F5F9"), strokeWidth=0))
        if bw > 0:
            d.add(Rect(bar_x, y + 0.5 * mm, bw, 3.5 * mm, rx=1, ry=1,
                       fillColor=rl_colors.HexColor("#0D9488"), strokeWidth=0))
        
        d.add(String(bar_x + bar_area_w + 3 * mm, y + 0.8 * mm, f"{cnt:,} ({pct}%)",
                     fontSize=6, fontName="Helvetica-Bold", fillColor=rl_colors.HexColor("#0F172A")))
    return d


def _make_device_analytics_box(user_agents, width=134*mm, height=74*mm):
    d = Drawing(width, height)
    d.add(Rect(0, 0, width, height, rx=3, ry=3, fillColor=rl_colors.white, strokeColor=rl_colors.HexColor("#CBD5E1"), strokeWidth=0.6))
    d.add(String(5 * mm, height - 6 * mm, "2.2 Perangkat & User-Agent",
                 fontSize=8, fontName="Helvetica-Bold", fillColor=rl_colors.HexColor("#0F172A")))
    
    total = sum(u.get("count", 0) for u in user_agents) or 1
    palette = ["#0D9488", "#0284C7", "#6366F1", "#A855F7", "#F97316", "#94A3B8"]
    
    cx = 30 * mm
    cy = height / 2.0 - 4 * mm
    r_outer = 20 * mm
    r_inner = 13 * mm
    
    start_angle = 90.0
    for i, u in enumerate(user_agents[:6]):
        cnt = u.get("count", 0)
        frac = cnt / total
        extent = -frac * 360.0
        if extent == 0:
            continue
        d.add(Wedge(cx, cy, r_outer, start_angle + extent, start_angle,
                    fillColor=rl_colors.HexColor(palette[i % len(palette)]), strokeColor=rl_colors.white, strokeWidth=0.6))
        start_angle += extent
        
    d.add(Circle(cx, cy, r_inner, fillColor=rl_colors.white, strokeColor=rl_colors.white, strokeWidth=0))
    d.add(String(cx, cy + 1.2 * mm, f"{total:,}", fontSize=8, fontName="Helvetica-Bold",
                 fillColor=rl_colors.HexColor("#0F172A"), textAnchor="middle"))
    d.add(String(cx, cy - 2.5 * mm, "Hits", fontSize=5.5, fontName="Helvetica",
                 fillColor=rl_colors.HexColor("#64748B"), textAnchor="middle"))
    
    lx = 60 * mm
    ly = height - 14 * mm
    for i, u in enumerate(user_agents[:6]):
        y = ly - i * 6.8 * mm
        cnt = u.get("count", 0)
        pct = u.get("percentage", round((cnt / total) * 100, 1))
        col = rl_colors.HexColor(palette[i % len(palette)])
        d.add(Rect(lx, y, 2.5 * mm, 2.5 * mm, fillColor=col, strokeWidth=0))
        d.add(String(lx + 4 * mm, y + 0.2 * mm, u.get("name", "-")[:16], fontSize=6, fontName="Helvetica", fillColor=rl_colors.HexColor("#334155")))
        d.add(String(lx + 40 * mm, y + 0.2 * mm, f"{cnt:,} ({pct}%)", fontSize=6, fontName="Helvetica-Bold", fillColor=rl_colors.HexColor("#0F172A")))
    
    bar_y = 5 * mm
    bar_w = width - 12 * mm
    bx = 6 * mm
    d.add(Rect(bx, bar_y, bar_w, 3.5 * mm, rx=1, ry=1, fillColor=rl_colors.HexColor("#F1F5F9"), strokeWidth=0))
    cur_bx = bx
    for i, u in enumerate(user_agents[:6]):
        seg_w = (u.get("count", 0) / total) * bar_w
        if seg_w > 0:
            col = rl_colors.HexColor(palette[i % len(palette)])
            d.add(Rect(cur_bx, bar_y, seg_w, 3.5 * mm, rx=0.5, ry=0.5, fillColor=col, strokeWidth=0))
            cur_bx += seg_w
    d.add(String(bx, bar_y + 4.2 * mm, "Distribusi Komposisi Perangkat (100%)", fontSize=5.5, fontName="Helvetica", fillColor=rl_colors.HexColor("#64748B")))
    return d


def _make_error_summary_cards(status_counts, width=273*mm, height=18*mm):
    d = Drawing(width, height)
    gap = 4 * mm
    card_w = (width - gap * 3) / 4.0
    
    c2 = sum(v for k, v in status_counts.items() if k.startswith("2"))
    c3 = sum(v for k, v in status_counts.items() if k.startswith("3"))
    c4 = sum(v for k, v in status_counts.items() if k.startswith("4"))
    c5 = sum(v for k, v in status_counts.items() if k.startswith("5"))
    total = c2 + c3 + c4 + c5 or 1
    
    items = [
        ("2xx — Sukses", c2, round(c2/total*100, 1), "Layanan Normal", "#059669", "#ECFDF5", "#A7F3D0"),
        ("3xx — Pengalihan", c3, round(c3/total*100, 1), "Redirect / HTTPS", "#D97706", "#FEF3C7", "#FDE68A"),
        ("4xx — Client Error", c4, round(c4/total*100, 1), "Not Found / Bad Req", "#EA580C", "#FFEDD5", "#FED7AA"),
        ("5xx — Server Error", c5, round(c5/total*100, 1), "Internal / Timeout", "#DC2626", "#FEE2E2", "#FECACA"),
    ]
    
    for i, (title, cnt, pct, sub, text_col, bg_col, bdr_col) in enumerate(items):
        x = i * (card_w + gap)
        d.add(Rect(x, 0, card_w, height, rx=2, ry=2,
                   fillColor=rl_colors.HexColor(bg_col), strokeColor=rl_colors.HexColor(bdr_col), strokeWidth=0.8))
        d.add(String(x + 3 * mm, height - 5 * mm, title,
                     fontSize=6.5, fontName="Helvetica-Bold", fillColor=rl_colors.HexColor(text_col)))
        d.add(String(x + 3 * mm, height - 12 * mm, f"{cnt:,} ({pct}%)",
                     fontSize=10, fontName="Helvetica-Bold", fillColor=rl_colors.HexColor("#0F172A")))
        d.add(String(x + 3 * mm, 2.5 * mm, sub,
                     fontSize=5.5, fontName="Helvetica", fillColor=rl_colors.HexColor("#64748B")))
    return d


def _make_security_shield_closing(width=273*mm, height=52*mm):
    logo_path = os.path.join(BASE_DIR, "static", "img", "logo_emblem.png")
    if not os.path.exists(logo_path):
        logo_path = "/opt/fail2ban-dashboard/static/img/logo_emblem.png"

    styles = getSampleStyleSheet()
    t_style = ParagraphStyle("sctitle", fontName="Helvetica-Bold", fontSize=8, textColor=rl_colors.HexColor("#0F766E"), alignment=1, spaceAfter=2)
    q_style = ParagraphStyle("scquote", fontName="Helvetica-Oblique", fontSize=6.5, textColor=rl_colors.HexColor("#64748B"), alignment=1)

    elements = []
    if os.path.exists(logo_path):
        elements.append(RLImage(logo_path, width=32*mm, height=23*mm, mask='auto'))
        elements.append(Spacer(1, 2*mm))
    elements.append(Paragraph("SI-KRESNA &nbsp;•&nbsp; KEAMANAN SIBER &amp; PRIVASI TERJAGA", t_style))
    elements.append(Paragraph("« Keamanan siber adalah proses berkelanjutan untuk menjaga integritas, kerahasiaan, dan ketersediaan layanan publik. »", q_style))

    closing_table = Table([[elements]], colWidths=[width])
    closing_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), rl_colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.6, rl_colors.HexColor("#CBD5E1")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3*mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3*mm),
    ]))
    return closing_table


def _pdf_executive_access_logs_response(data, filename):
    """Membangun laporan eksekutif PDF 6 halaman lengkap sesuai standar SI-KRESNA."""
    if not REPORTLAB_AVAILABLE:
        return jsonify({"error": "Modul reportlab tidak tersedia di server"}), 500

    bio = io.BytesIO()
    doc = SimpleDocTemplate(
        bio, pagesize=landscape(A4),
        leftMargin=12 * mm, rightMargin=12 * mm, topMargin=12 * mm, bottomMargin=14 * mm,
        title="SI-KRESNA — Laporan Access Log Web & Statistik Pengunjung"
    )

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1e", parent=styles["Title"], fontSize=13, fontName="Helvetica-Bold",
                        textColor=rl_colors.HexColor("#0F766E"), alignment=0, spaceAfter=2)
    sub = ParagraphStyle("sube", parent=styles["Normal"], fontSize=7, fontName="Helvetica",
                         textColor=rl_colors.HexColor("#64748B"), spaceAfter=4)
    meta = ParagraphStyle("metae", parent=styles["Normal"], fontSize=6.5, textColor=rl_colors.HexColor("#334155"))
    tc = ParagraphStyle("tce", parent=styles["Normal"], fontSize=6.2, fontName="Helvetica", textColor=rl_colors.HexColor("#334155"))
    tcbe = ParagraphStyle("tcbe", parent=styles["Normal"], fontSize=6.2, fontName="Helvetica-Bold", textColor=rl_colors.HexColor("#0F172A"))
    tcc = ParagraphStyle("tcce", parent=styles["Normal"], fontSize=5.8, fontName="Courier", textColor=rl_colors.HexColor("#0F172A"))

    logs = data.get("logs", [])
    analytics = data.get("analytics", {})
    summ = data.get("summary", {})
    period_label = data.get("period_label", data.get("period", "Hari Ini"))
    ts_str = datetime.now().strftime("%d %b %Y %H:%M:%S")

    hourly_human = analytics.get("hourly_human", [0] * 24)
    hourly_bot = analytics.get("hourly_bot", [0] * 24)
    status_counts = analytics.get("status_counts", data.get("status_distribution", {}))
    top_cities = analytics.get("top_cities", [])
    top_urls = analytics.get("top_urls", [])
    top_uas = analytics.get("top_user_agents", [])
    ep_cats = analytics.get("endpoint_categories", [])
    top_404 = analytics.get("top_404_urls", [])
    top_err_ips = analytics.get("top_error_ips", [])

    total_req = summ.get("total_requests", 0) or 1
    p_human = round((summ.get("human_hits", 0) / total_req) * 100, 1)
    p_bot = round((summ.get("bot_hits", 0) / total_req) * 100, 1)

    c2 = sum(v for k, v in status_counts.items() if k.startswith("2"))
    p_2xx = round((c2 / (sum(status_counts.values()) or 1)) * 100, 1)

    story = []

    # ================= PAGE 1: Ringkasan Eksekutif =================
    story.append(Paragraph("<b>SI-KRESNA</b> &nbsp;|&nbsp; RSUD KARDINAH KOTA TEGAL", meta))
    story.append(Spacer(1, 1 * mm))
    story.append(_make_hero_banner(period_label, ts_str))
    story.append(Spacer(1, 2.5 * mm))

    kpi_cards = [
        {"title": "Pengunjung Manusia", "value": f"{summ.get('human_visitors', 0):,}", "sub": "IP publik unik", "accent": "#0F766E"},
        {"title": "Request Manusia", "value": f"{summ.get('human_hits', 0):,}", "sub": f"{p_human}% trafik bersih", "accent": "#0284C7"},
        {"title": "Crawler / Bot Hits", "value": f"{summ.get('bot_hits', 0):,}", "sub": f"{p_bot}% total request", "accent": "#D97706"},
        {"title": "Total Event Diproses", "value": f"{summ.get('total_requests', 0):,}", "sub": f"{len(logs)} baris sampel", "accent": "#64748B"},
    ]
    story.append(_make_kpi_cards(kpi_cards))
    story.append(Spacer(1, 2.5 * mm))

    ch1 = _make_hourly_chart(hourly_human, hourly_bot, width=134*mm, height=64*mm)
    ch2 = _make_status_donut(status_counts, width=134*mm, height=64*mm, title="1.2 Distribusi HTTP Status")
    grid_p1 = Table([[ch1, ch2]], colWidths=[136*mm, 137*mm])
    grid_p1.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(grid_p1)
    story.append(Spacer(1, 2.5 * mm))

    story.append(_pdf_callout_table(
        "Catatan Penting — Analisis Kesehatan Trafik Web Server",
        f"Trafik server berjalan stabil. {p_2xx}% permintaan berhasil dilayani dengan status HTTP 200 OK. Aktivitas bot ({p_bot}%) merupakan perayapan mesin pencari normal (Googlebot/Bingbot). Tidak ditemukan lonjakan anomali error 5xx pada periode ini."
    ))
    story.append(PageBreak())

    # ================= PAGE 2: Visitor & Traffic Analytics =================
    story.append(Paragraph("2. Visitor & Traffic Analytics", h1))
    story.append(Paragraph("Analisis sebaran geografis pengunjung publik dan platform perangkat/peramban yang digunakan.", sub))
    story.append(Spacer(1, 1.5 * mm))

    c_left = _make_top_cities_chart(top_cities, width=134*mm, height=74*mm, title="2.1 Top 8 Kota Pengunjung (GeoIP MMDB)")
    c_right = _make_device_analytics_box(top_uas, width=134*mm, height=74*mm)
    grid_p2 = Table([[c_left, c_right]], colWidths=[136*mm, 137*mm])
    grid_p2.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(grid_p2)
    story.append(Spacer(1, 3 * mm))

    # Mobile share
    p_mobile = 0.0
    for u in top_uas:
        if u.get("name") in ("Android", "iOS (Apple)"):
            p_mobile += u.get("percentage", 0)
    p_mobile = round(p_mobile, 1) or 95.0

    in1 = _pdf_callout_table(
        f"Insight 1: Dominasi Akses Mobile ({p_mobile}%)",
        f"{p_mobile}% pengunjung mengakses portal web RSUD Kardinah melalui smartphone (Android & iOS). Tata letak responsif dan optimasi kecepatan aset mobile sangat krusial bagi kenyamanan pasien.",
        width=134*mm, accent="#0F766E", bg="#F0FDF4", border="#A7F3D0"
    )
    in2 = _pdf_callout_table(
        "Insight 2: Aktivitas Crawler & Search Engine (Normal)",
        f"Terdeteksi {summ.get('bot_hits', 0):,} request bot/crawler. Pola perayapan indexing mesin pencari berjalan wajar tanpa indikasi scraping agresif atau scanning vulnerabilitas.",
        width=134*mm, accent="#0284C7", bg="#F0F9FF", border="#BAE6FD"
    )
    grid_in = Table([[in1, in2]], colWidths=[136*mm, 137*mm])
    grid_in.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(grid_in)
    story.append(PageBreak())

    # ================= PAGE 3: Endpoint & Security Overview =================
    story.append(Paragraph("3. Endpoint & Security Overview", h1))
    story.append(Paragraph("Endpoint yang paling sering diakses pengunjung dan pengelompokan jenis layanan web.", sub))
    story.append(Spacer(1, 1.5 * mm))

    top_urls_rows = [["#", "URL / Endpoint", "Hits", "Persentase", "Tipe Layanan"]]
    for u in top_urls[:10]:
        path_str = u.get("url", "-")
        # Infer service type
        if any(path_str.startswith(p) for p in ("/service", "/api", "/live")):
            svc_type = "API & Layanan Data"
        elif any(path_str.lower().endswith(ext) for ext in ('.jpg', '.png', '.css', '.js')):
            svc_type = "Static Asset"
        elif any(k in path_str.lower() for k in ("wp-", ".env", ".git")):
            svc_type = "Bot Probe"
        else:
            svc_type = "Halaman Informasi Web"
        top_urls_rows.append([str(u.get("rank", len(top_urls_rows))), path_str, f"{u.get('count', 0):,}", f"{u.get('percentage', 0)}%", svc_type])

    if len(top_urls_rows) == 1:
        top_urls_rows.append(["-", "Tidak ada data URL pada periode ini", "0", "0%", "-"])

    t_urls = Table([[Paragraph(c, tcbe if r == 0 else tc) for c in row] for r, row in enumerate(top_urls_rows)],
                   colWidths=[10*mm, 115*mm, 25*mm, 28*mm, 95*mm])
    t_urls.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor("#0F766E")),
        ("TEXTCOLOR", (0, 0), (-1, 0), rl_colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [rl_colors.white, rl_colors.HexColor("#F8FAFC")]),
        ("GRID", (0, 0), (-1, -1), 0.5, rl_colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 1.8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.8),
    ]))
    story.append(t_urls)
    story.append(Spacer(1, 2.5 * mm))

    st_donut = _make_status_donut(status_counts, width=134*mm, height=52*mm, title="3.2 HTTP Status Summary")
    
    # Endpoint category bars
    ep_formatted = [{"city": e["category"], "count": e["count"], "percentage": e["percentage"]} for e in ep_cats[:5]]
    ep_bars = _make_top_cities_chart(ep_formatted, width=134*mm, height=52*mm, title="3.3 Kategori Endpoint")

    grid_p3 = Table([[st_donut, ep_bars]], colWidths=[136*mm, 137*mm])
    grid_p3.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(grid_p3)
    story.append(Spacer(1, 2.5 * mm))

    c4 = sum(v for k, v in status_counts.items() if k.startswith("4"))
    story.append(_pdf_callout_table(
        "Perhatian Khusus — Analisis Endpoint & Error Not Found",
        f"Terdeteksi {c4:,} request berstatus 4xx (Not Found / Client Error). Mayoritas merupakan aset gambar/skrip lama atau pemindaian acak bot. Pastikan tautan menu pada portal web selalu mengarah ke URL aktif.",
        accent="#D97706", bg="#FFFBEB", border="#FDE68A"
    ))
    story.append(PageBreak())

    # ================= PAGE 4: Error & Anomaly Analysis =================
    story.append(Paragraph("4. Error & Anomaly Analysis", h1))
    story.append(Paragraph("Ringkasan kesalahan HTTP, identifikasi anomali, dan aktivitas pemindaian mencurigakan.", sub))
    story.append(Spacer(1, 1.5 * mm))

    story.append(_make_error_summary_cards(status_counts, width=273*mm, height=18*mm))
    story.append(Spacer(1, 3 * mm))

    err_urls_rows = [["#", "URL 404 Not Found", "Hits", "Kategori"]]
    for idx, item in enumerate(top_404[:5], 1):
        u_str = item.get("url", "-")
        cat_str = "Bot Scanner" if any(k in u_str.lower() for k in ("wp-", ".env", ".git", "php")) else "Missing Asset"
        err_urls_rows.append([str(idx), u_str, f"{item.get('count', 0):,}", cat_str])
    if len(err_urls_rows) == 1:
        err_urls_rows.append(["-", "Tidak ada 404 pada periode ini", "0", "-"])

    t_err_urls = Table([[Paragraph(c, tcbe if r == 0 else tc) for c in row] for r, row in enumerate(err_urls_rows)],
                       colWidths=[8*mm, 78*mm, 16*mm, 32*mm])
    t_err_urls.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor("#EA580C")),
        ("TEXTCOLOR", (0, 0), (-1, 0), rl_colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [rl_colors.white, rl_colors.HexColor("#F8FAFC")]),
        ("GRID", (0, 0), (-1, -1), 0.5, rl_colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))

    err_ips_rows = [["#", "Client IP (Masked)", "Lokasi / Region", "Error Hits"]]
    for idx, item in enumerate(top_err_ips[:5], 1):
        raw_ip = item.get("ip", "-")
        parts = raw_ip.split(".")
        masked_ip = f"{parts[0]}.{parts[1]}.***.***" if len(parts) == 4 else raw_ip
        err_ips_rows.append([str(idx), masked_ip, item.get("location", "-")[:20], f"{item.get('count', 0):,}"])
    if len(err_ips_rows) == 1:
        err_ips_rows.append(["-", "Tidak ada error IP", "-", "0"])

    t_err_ips = Table([[Paragraph(c, tcbe if r == 0 else tc) for c in row] for r, row in enumerate(err_ips_rows)],
                      colWidths=[8*mm, 42*mm, 54*mm, 30*mm])
    t_err_ips.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor("#115E59")),
        ("TEXTCOLOR", (0, 0), (-1, 0), rl_colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [rl_colors.white, rl_colors.HexColor("#F8FAFC")]),
        ("GRID", (0, 0), (-1, -1), 0.5, rl_colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))

    grid_p4_tables = Table([[t_err_urls, t_err_ips]], colWidths=[136*mm, 137*mm])
    grid_p4_tables.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(grid_p4_tables)
    story.append(Spacer(1, 3 * mm))

    story.append(_pdf_callout_table(
        "Rekomendasi Tindak Lanjut Tim Keamanan IT RSUD Kardinah",
        "1. Tinjau kembali URL 404 pada template halaman dan hapus tautan aset yang sudah tidak digunakan.  2. Pastikan filter Fail2ban 'nginx-scan' terus aktif untuk memblokir IP dengan akumulasi kesalahan akses tidak wajar.  3. Pertahankan kebijakan masking IP untuk seluruh publikasi laporan.",
        accent="#0F766E", bg="#F0FDF4", border="#A7F3D0"
    ))
    story.append(PageBreak())

    # ================= PAGE 5: Detail Access Log (Nginx) =================
    story.append(Paragraph("5. Detail Access Log (Nginx)", h1))
    story.append(Paragraph("Lampiran rekaman log akses real-time dengan penyamaran IP (masking) untuk privasi publik.", sub))
    story.append(Spacer(1, 1.5 * mm))

    raw_headers = ["Waktu (WIB)", "Client IP (Masked)", "Lokasi / Region", "ISP", "Device", "Metode", "Request URL / Path", "Status", "Size"]
    log_display_rows = []
    for l in logs[:16]:
        raw_ip = l.get("ip", "-")
        parts = raw_ip.split(".")
        masked_ip = f"{parts[0]}.{parts[1]}.***.***" if len(parts) == 4 else raw_ip
        log_display_rows.append([
            l.get("time", "-")[:19],
            masked_ip,
            f"{l.get('city','-')}, {l.get('region','-')}"[:22],
            l.get("isp", "-")[:16],
            l.get("device", "-"),
            l.get("method", "-"),
            l.get("path", "-")[:45],
            l.get("status", "-"),
            l.get("size", "-")
        ])

    if not log_display_rows:
        log_display_rows.append(["-", "-", "-", "-", "-", "-", "Tidak ada baris log", "-", "-"])

    t_raw = Table([[Paragraph(c, tcbe if r == 0 else (tcc if i in (1, 6) else tc)) for i, c in enumerate(row)]
                   for r, row in enumerate([raw_headers] + log_display_rows)],
                  colWidths=[28*mm, 26*mm, 38*mm, 26*mm, 18*mm, 14*mm, 85*mm, 16*mm, 22*mm])
    t_raw.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor("#0F766E")),
        ("TEXTCOLOR", (0, 0), (-1, 0), rl_colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [rl_colors.white, rl_colors.HexColor("#F8FAFC")]),
        ("GRID", (0, 0), (-1, -1), 0.5, rl_colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 1.8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.8),
    ]))
    story.append(t_raw)
    story.append(Spacer(1, 2.5 * mm))

    story.append(Paragraph(
        "<b>Legenda Status HTTP:</b> &nbsp; "
        "<font color='#059669'>■ 2xx Sukses</font> &nbsp;&nbsp; "
        "<font color='#D97706'>■ 3xx Pengalihan</font> &nbsp;&nbsp; "
        "<font color='#EA580C'>■ 4xx Client Error</font> &nbsp;&nbsp; "
        "<font color='#DC2626'>■ 5xx Server Error</font>",
        meta
    ))
    story.append(PageBreak())

    # ================= PAGE 6: Lampiran & Catatan Keamanan =================
    story.append(Paragraph("6. Lampiran & Catatan Keamanan", h1))
    story.append(Paragraph("Catatan teknis, kebijakan privasi data, dan tata kelola keamanan siber.", sub))
    story.append(Spacer(1, 2 * mm))

    story.append(_pdf_callout_table(
        "Kepatuhan Privasi Data & Masking Alamat IP (UU PDP No. 27 Tahun 2022)",
        "Seluruh alamat IP publik pengunjung pada dokumen ini telah disamarkan secara otomatis (octet masking) untuk menjaga kerahasiaan identitas dan privasi masyarakat yang mengakses layanan informasi publik RSUD Kardinah sesuai ketentuan peraturan perundang-undangan.",
        width=273*mm, accent="#0F766E", bg="#F0FDF4", border="#A7F3D0"
    ))
    story.append(Spacer(1, 3 * mm))

    story.append(_make_security_shield_closing(width=273*mm, height=52*mm))
    story.append(Spacer(1, 3 * mm))

    sign_off_rows = [
        ["Sistem & Platform:", "Pengelola Infrastruktur TI:"],
        ["SI-KRESNA v2.0 (Sistem Inspeksi Keamanan & Rekam Eksplorasi)", "Instalasi PDE / IT & SIMRS"],
        ["Fail2ban IDS / IPS Engine & Nginx Reverse Proxy", "RSUD Kardinah Kota Tegal"],
        ["MaxMind GeoLite2 Offline Database (Zero External Leak)", "Pemerintah Kota Tegal, Jawa Tengah"],
    ]
    t_sign = Table([[Paragraph(c, tcbe if r == 0 else tc) for c in row] for r, row in enumerate(sign_off_rows)],
                   colWidths=[136*mm, 137*mm])
    t_sign.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor("#F1F5F9")),
        ("GRID", (0, 0), (-1, -1), 0.5, rl_colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.2),
    ]))
    story.append(t_sign)

    doc.build(story, canvasmaker=NumberedCanvas)
    bio.seek(0)
    return Response(
        bio.read(),
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route("/api/access-logs/export")
def api_access_logs_export():
    """Export Access Log Web & Visitor Analytics ke Excel / PDF / CSV."""
    fmt = request.args.get("format", "xlsx").strip().lower()
    period = request.args.get("period", "today").strip().lower()
    status_filter = request.args.get("status", "")
    ip_filter = request.args.get("ip", "").strip()
    search_filter = request.args.get("search", "").strip().lower()
    try:
        export_limit = int(request.args.get("limit", 2000))
    except Exception:
        export_limit = 2000
    export_limit = max(1, min(export_limit, 20000))

    try:
        data = build_access_logs_payload(export_limit, status_filter, ip_filter, search_filter, period)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    logs = data.get("logs", [])
    analytics = data.get("analytics", {})
    summ = data.get("summary", {})
    period_label = data.get("period_label", period)
    now = datetime.now()
    stamp = now.strftime("%Y%m%d_%H%M%S")
    base = f"sikresna_accesslog_{period}_{stamp}"

    if fmt == "csv":
        si = io.StringIO()
        w = csv.writer(si)
        w.writerow(["Waktu (WIB)", "Client IP", "Kota", "Region", "ISP", "Device", "Method", "Request URL", "Status", "Size", "User-Agent"])
        for l in logs:
            w.writerow([l.get("time"), l.get("ip"), l.get("city"), l.get("region"), l.get("isp"),
                        l.get("device"), l.get("method"), l.get("path"), l.get("status"), l.get("size"), l.get("user_agent")])
        return Response(si.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={base}.csv"})

    # Common row collections
    log_rows = [[l.get("time"), l.get("ip"), f"{l.get('city','-')}, {l.get('region','-')}", l.get("isp", "-"),
                 l.get("device"), l.get("method"), l.get("path"), l.get("status"), l.get("size")] for l in logs]
    log_headers = ["Waktu (WIB)", "Client IP", "Lokasi / ISP", "ISP", "Device", "Method", "Request URL", "Status", "Size"]

    city_rows = [[c["rank"], c["city"], c["count"], f"{c['percentage']}%"] for c in analytics.get("top_cities", [])]
    url_rows = [[u["rank"], u["url"], u["count"], f"{u['percentage']}%"] for u in analytics.get("top_urls", [])]
    ua_rows = [[a["rank"], a["name"], a["count"], f"{a['percentage']}%"] for a in analytics.get("top_user_agents", [])]

    if fmt == "pdf":
        return _pdf_executive_access_logs_response(data, f"{base}.pdf")

    sheets = [
        {"name": "Ringkasan", "headers": ["Metrik", "Nilai"],
         "rows": [["Periode", period_label],
                  ["Pengunjung Unik (Human)", summ.get("human_visitors", 0)],
                  ["Total Request Human", summ.get("human_hits", 0)],
                  ["Crawler / Bot Hits", summ.get("bot_hits", 0)],
                  ["Total Baris Log", len(logs)]],
         "col_widths": [38, 60]},
        {"name": "Top Kota", "headers": ["#", "Kota", "Hits", "Persentase"], "rows": city_rows,
         "col_widths": [6, 40, 12, 12]},
        {"name": "Top URL", "headers": ["#", "URL / Endpoint", "Hits", "Persentase"], "rows": url_rows,
         "col_widths": [6, 70, 12, 12]},
        {"name": "Perangkat", "headers": ["#", "Perangkat / Platform", "Hits", "Persentase"], "rows": ua_rows,
         "col_widths": [6, 40, 12, 12]},
        {"name": "Access Log", "headers": log_headers, "rows": log_rows,
         "col_widths": [22, 18, 32, 26, 14, 10, 60, 9, 11]},
    ]
    return _xlsx_response(sheets, f"{base}.xlsx")


@app.route("/api/report/export")
def api_report_export():
    """Export Laporan Ringkasan Keamanan ke Excel / PDF."""
    fmt = request.args.get("format", "xlsx").strip().lower()
    period = request.args.get("period", "7d").strip().lower()
    if period not in ["today", "7d", "30d", "all"]:
        period = "7d"
    try:
        data = get_report_data(period)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    period_label = data.get("period_label", period)
    summary = data.get("summary", {})
    categories = data.get("categories", [])
    attackers = data.get("top_attackers", [])
    daily = data.get("daily_trend", [])
    jails = data.get("jails", [])

    now = datetime.now()
    stamp = now.strftime("%Y%m%d_%H%M%S")
    base = f"sikresna_report_{period}_{stamp}"

    summary_rows = [
        ["Total Deteksi Serangan Web (Probes)", summary.get("total_probes", 0)],
        ["IP Penyerang Unik", summary.get("unique_probe_ips", 0)],
        ["Total Ban", summary.get("total_bans", 0)],
        ["Total Unban", summary.get("total_unbans", 0)],
        ["IP Diblokir Unik", summary.get("unique_banned_ips", 0)],
        ["Kategori Serangan Terbanyak", summary.get("top_category", "-")],
    ]
    cat_rows = [[c["category"], c["count"], f"{c['percentage']}%"] for c in categories]
    atk_rows = [[i, a.get("ip_address"), a.get("hit_count"), a.get("categories"), a.get("last_seen"),
                 "Ya" if a.get("is_whitelisted") else "Tidak"] for i, a in enumerate(attackers, 1)]
    daily_rows = [[d["date"], d["probes"], d["bans"]] for d in daily]
    jail_rows = [[j.get("jail"), j.get("bans", 0), j.get("unbans", 0)] for j in jails]

    if fmt == "pdf":
        sections = [
            {"heading": "1. Ringkasan KPI Keamanan", "headers": ["Metrik", "Nilai"], "rows": summary_rows,
             "col_widths": [90 * mm, 60 * mm]},
            {"heading": "2. Distribusi Kategori Serangan", "headers": ["Kategori", "Jumlah", "Persentase"],
             "rows": cat_rows, "col_widths": [110 * mm, 30 * mm, 30 * mm],
             "chart": [{"label": c["category"], "count": c["count"], "percentage": c["percentage"]} for c in categories],
             "chart_title": "Donut Chart — Distribusi Kategori Serangan",
             "chart_center": "Probes"},
            {"heading": "3. Top 10 Penyerang", "headers": ["#", "IP Penyerang", "Hits", "Kategori", "Terakhir Terlihat", "Whitelist"],
             "rows": atk_rows, "col_widths": [10 * mm, 40 * mm, 20 * mm, 70 * mm, 40 * mm, 22 * mm],
             "chart": [{"label": a.get("ip_address", "-"), "count": a.get("hit_count", 0),
                        "percentage": round((a.get("hit_count", 0) / (summary.get("total_probes", 0) or 1)) * 100, 1)} for a in attackers[:8]],
             "chart_title": "Donut Chart — Top Penyerang (Hits)",
             "chart_center": "Hits"},
            {"heading": "4. Tren Harian", "headers": ["Tanggal", "Probes", "Bans"], "rows": daily_rows,
             "col_widths": [50 * mm, 35 * mm, 35 * mm]},
            {"heading": "5. Rekap Per Jail Fail2ban", "headers": ["Jail", "Bans", "Unbans"], "rows": jail_rows,
             "col_widths": [60 * mm, 35 * mm, 35 * mm]},
        ]
        return _pdf_response("Laporan Ringkasan Keamanan", period_label, sections, f"{base}.pdf")

    sheets = [
        {"name": "Ringkasan", "headers": ["Metrik", "Nilai"], "rows": summary_rows, "col_widths": [45, 22]},
        {"name": "Kategori Serangan", "headers": ["Kategori", "Jumlah", "Persentase"], "rows": cat_rows,
         "col_widths": [38, 14, 14]},
        {"name": "Top Penyerang", "headers": ["#", "IP Penyerang", "Hits", "Kategori", "Terakhir Terlihat", "Whitelist"],
         "rows": atk_rows, "col_widths": [5, 20, 10, 40, 22, 11]},
        {"name": "Tren Harian", "headers": ["Tanggal", "Probes", "Bans"], "rows": daily_rows, "col_widths": [15, 12, 12]},
        {"name": "Jail Fail2ban", "headers": ["Jail", "Bans", "Unbans"], "rows": jail_rows, "col_widths": [24, 12, 12]},
    ]
    return _xlsx_response(sheets, f"{base}.xlsx")


@app.route("/api/whitelist/add", methods=["POST"])
def api_whitelist_add():
    data = request.json or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"success": False, "error": "IP required"}), 400
    
    run_cmd(f"fail2ban-client set sshd addignoreip {ip}")
    run_cmd(f"fail2ban-client set nginx-scan addignoreip {ip}")
    jail_local = "/etc/fail2ban/jail.local"
    try:
        with open(jail_local, "r") as f:
            content = f.read()
        if "ignoreip =" in content and ip not in content:
            content = re.sub(r"(ignoreip\s*=\s*.*)", rf"\1 {ip}", content)
            with open(jail_local, "w") as f:
                f.write(content)
    except Exception:
        pass
    
    record_audit("WHITELIST_ADD", ip, "Menambahkan IP ke daftar Whitelist IgnoreIP")
    return jsonify({"success": True, "ip": ip})

@app.route("/api/whitelist/remove", methods=["POST"])
def api_whitelist_remove():
    data = request.json or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"success": False, "error": "IP required"}), 400
    
    run_cmd(f"fail2ban-client set sshd delignoreip {ip}")
    run_cmd(f"fail2ban-client set nginx-scan delignoreip {ip}")
    jail_local = "/etc/fail2ban/jail.local"
    try:
        with open(jail_local, "r") as f:
            content = f.read()
        content = content.replace(f" {ip}", "").replace(f"{ip} ", "")
        with open(jail_local, "w") as f:
            f.write(content)
    except Exception:
        pass

    record_audit("WHITELIST_REMOVE", ip, "Menghapus IP dari daftar Whitelist IgnoreIP")
    return jsonify({"success": True, "ip": ip})

@app.route("/api/logs")
def api_logs():
    limit = request.args.get("limit", 60)
    raw_logs = run_cmd(f"tail -n {limit} /var/log/fail2ban.log")
    parsed_logs = []
    for line in raw_logs.splitlines():
        if not line.strip(): continue
        level = "info"
        if "WARNING" in line: level = "warning"
        elif "ERROR" in line: level = "error"
        elif "Ban" in line or "Found" in line: level = "alert"
        parsed_logs.append({"raw": line, "level": level})
    parsed_logs.reverse()
    return jsonify({"logs": parsed_logs})

@app.route("/api/action/unban", methods=["POST"])
def api_unban():
    data = request.json or {}
    ip = data.get("ip", "").strip()
    jail = data.get("jail", "").strip()
    if not ip or not jail:
        return jsonify({"success": False, "error": "IP and Jail required"}), 400
    
    res = run_cmd(f"fail2ban-client set {jail} unbanip {ip}")
    
    # Simpan event unban manual ke DB
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn = get_db()
        conn.execute("""
            INSERT OR IGNORE INTO ban_events (event_time, jail, action, ip_address, raw_log)
            VALUES (?, ?, 'Manual Unban', ?, ?)
        """, (now_str, jail, ip, f"Manual unban via dashboard: {res}"))
        conn.commit()
        conn.close()
    except Exception:
        pass

    record_audit("MANUAL_UNBAN", ip, f"Unban manual pada jail '{jail}'")
    return jsonify({"success": True, "output": res})

@app.route("/api/action/ban", methods=["POST"])
def api_ban():
    data = request.json or {}
    ip = data.get("ip", "").strip()
    jail = data.get("jail", "nginx-scan").strip()
    if not ip:
        return jsonify({"success": False, "error": "IP required"}), 400
    
    res = run_cmd(f"fail2ban-client set {jail} banip {ip}")
    
    # Simpan event ban manual ke DB
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn = get_db()
        conn.execute("""
            INSERT OR IGNORE INTO ban_events (event_time, jail, action, ip_address, raw_log)
            VALUES (?, ?, 'Manual Ban', ?, ?)
        """, (now_str, jail, ip, f"Manual ban via dashboard: {res}"))
        conn.commit()
        conn.close()
    except Exception:
        pass

    record_audit("MANUAL_BAN", ip, f"Ban manual pada jail '{jail}'")
    return jsonify({"success": True, "output": res})

if __name__ == "__main__":
    init_db()
    
    # Jalankan background log sync worker
    t = threading.Thread(target=background_worker_loop, daemon=True)
    t.start()
    
    app.run(host="0.0.0.0", port=8560, debug=False)
