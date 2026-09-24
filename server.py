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
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
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
            "top_user_agents": top_user_agents
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
        sections = [
            {"heading": "1. Ringkasan Periode",
             "headers": ["Metrik", "Nilai"],
             "rows": [["Periode", period_label],
                      ["Pengunjung Unik (Human)", summ.get("human_visitors", 0)],
                      ["Total Request Human", summ.get("human_hits", 0)],
                      ["Crawler / Bot Hits", summ.get("bot_hits", 0)],
                      ["Total Baris Log Ditampilkan", len(logs)]],
             "col_widths": [70 * mm, 60 * mm]},
            {"heading": "2. Top 10 Kota Pengunjung (GeoIP Offline MMDB)",
             "headers": ["#", "Kota", "Hits", "Persentase"], "rows": city_rows,
             "col_widths": [12 * mm, 130 * mm, 25 * mm, 25 * mm],
             "chart": [{"label": c["city"], "count": c["count"], "percentage": c["percentage"]} for c in analytics.get("top_cities", [])],
             "chart_title": "Donut Chart — Sebaran Kota Pengunjung",
             "chart_center": "Hits"},
            {"heading": "3. Top 10 Akses URL & Endpoint",
             "headers": ["#", "URL / Endpoint", "Hits", "Persentase"], "rows": url_rows,
             "col_widths": [12 * mm, 130 * mm, 25 * mm, 25 * mm]},
            {"heading": "4. Perangkat & User-Agent",
             "headers": ["#", "Perangkat / Platform", "Hits", "Persentase"], "rows": ua_rows,
             "col_widths": [12 * mm, 130 * mm, 25 * mm, 25 * mm],
             "chart": [{"label": a["name"], "count": a["count"], "percentage": a["percentage"]} for a in analytics.get("top_user_agents", [])],
             "chart_title": "Donut Chart — Perangkat & User-Agent",
             "chart_center": "Hits"},
            {"heading": "5. Detail Access Log (Nginx)",
             "headers": ["Waktu", "IP", "Lokasi / ISP", "ISP", "Device", "Method", "URL", "Status", "Size"],
             "rows": log_rows,
             "col_widths": [30 * mm, 26 * mm, 38 * mm, 32 * mm, 18 * mm, 15 * mm, 62 * mm, 13 * mm, 14 * mm]},
        ]
        return _pdf_response("Laporan Access Log Web & Statistik Pengunjung", period_label, sections, f"{base}.pdf")

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
