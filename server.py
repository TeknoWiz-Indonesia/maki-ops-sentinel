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
import urllib.request
from flask import Flask, render_template, jsonify, request, Response

app = Flask(__name__)

# Base configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "sentinel.db")

WHITELISTED_IPS = ["127.0.0.1", "172.16.61.188", "172.16.61.55", "172.16.62.181", "172.16.62.254", "172.17.3.2", "10.100.2.1", "172.16.62.247"]

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
    """Batch lookup GeoIP info dengan memory caching untuk performa tinggi."""
    needed = [ip for ip in ip_list if ip and ip not in _GEO_CACHE and not is_private_ip(ip)]
    if needed:
        try:
            # Chunk in batches of 80 to respect limits
            for i in range(0, min(len(needed), 160), 80):
                batch = needed[i:i+80]
                req = urllib.request.Request(
                    "http://ip-api.com/batch?fields=query,status,country,regionName,city,isp",
                    data=json.dumps(batch).encode(),
                    headers={"Content-Type": "application/json", "User-Agent": "MakiOpsSentinel/2.0"}
                )
                with urllib.request.urlopen(req, timeout=3) as resp:
                    data = json.loads(resp.read().decode())
                    for item in data:
                        q = item.get("query")
                        if item.get("status") == "success":
                            _GEO_CACHE[q] = {
                                "city": item.get("city") or "Unknown",
                                "region": item.get("regionName") or "",
                                "country": item.get("country") or "Indonesia",
                                "isp": item.get("isp") or "-"
                            }
                        else:
                            _GEO_CACHE[q] = {
                                "city": "Unknown",
                                "region": "",
                                "country": "Indonesia",
                                "isp": "-"
                            }
        except Exception:
            pass
            
    # Fallback for internal and unresolvable IPs
    for ip in ip_list:
        if ip not in _GEO_CACHE:
            if is_private_ip(ip):
                _GEO_CACHE[ip] = {
                    "city": "Lokal RS",
                    "region": "Tegal",
                    "country": "Internal",
                    "isp": "LAN / Kardinah Network"
                }
            else:
                _GEO_CACHE[ip] = {
                    "city": "Unknown",
                    "region": "",
                    "country": "Indonesia",
                    "isp": "-"
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

@app.route("/api/access-logs")
def api_access_logs():
    """Live web access log view & Visitor Analytics (Realtime tail + GeoIP)."""
    limit = int(request.args.get("limit", 100))
    status_filter = request.args.get("status", "")
    ip_filter = request.args.get("ip", "").strip()
    search_filter = request.args.get("search", "").strip().lower()
    
    # Read last 1500 lines for rich analytics and responsive tail
    raw_logs = run_cmd("tail -n 1500 /www/wwwlogs/rsudkardinah.tegalkota.go.id.log 2>/dev/null")
    parsed = []
    
    # Nginx Combined Log Regex & Bot Classifier
    pat = re.compile(r'^([0-9a-fA-F\.:]+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s]+)\s+([^"]*)"\s+([0-9]{3})\s+([0-9]+)\s+"([^"]*)"\s+"([^"]*)"')
    bot_re = re.compile(r'bot|spider|crawl|curl|python|wget|go-http|scanner|scan|nikto|sqlmap|censys|shodan|zgrab|nmap|ahrefs|semrush|bingbot|googlebot|yandex|bytespider|facebookexternalhit|headless|urllib|httpclient|postman', re.I)

    today_str = datetime.now().strftime("%d/%b/%Y")

    status_counts = Counter()
    ip_counts = Counter()
    url_counts = Counter()
    city_counts = Counter()
    human_ips_today = set()
    human_hits_today = 0
    bot_hits_today = 0
    
    # Unique human IPs for batch GeoIP resolution
    detected_human_ips = []

    for line in raw_logs.splitlines():
        if not line.strip():
            continue
        m = pat.search(line)
        if m:
            ip, user, date, method, path, proto, status, size, ref, ua = m.groups()
            
            is_internal = is_private_ip(ip)
            is_bot = bool(bot_re.search(ua)) or ua in ("-", "")
            is_today = date.startswith(today_str)
            
            if is_today and not is_internal:
                if is_bot:
                    bot_hits_today += 1
                else:
                    human_hits_today += 1
                    human_ips_today.add(ip)

            if not is_bot and not is_internal:
                detected_human_ips.append(ip)
                # Count clean content page URLs (filter common static images/fonts/assets)
                static_exts = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.woff', '.woff2', '.ttf', '.eot', '.otf', '.svg', '.ico', '.webp', '.map']
                is_static = any(path.lower().endswith(ext) or ext + "?" in path.lower() for ext in static_exts)
                if not is_static:
                    clean_path = path.split("?")[0]
                    url_counts[clean_path] += 1

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

            status_counts[status] += 1
            if not is_internal and not is_bot:
                ip_counts[ip] += 1

            if status_filter and status != status_filter:
                continue
            if ip_filter and ip_filter not in ip:
                continue
            if search_filter and (search_filter not in path.lower() and search_filter not in ua.lower() and search_filter not in ip.lower()):
                continue

            parsed.append({
                "ip": ip,
                "time": date,
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

    # Resolve GeoIP for human IPs (up to 80 unique)
    unique_human_ips = list(set(detected_human_ips))[:80]
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

    return jsonify({
        "logs": parsed[:limit],
        "total_parsed": len(parsed),
        "status_distribution": dict(status_counts.most_common(6)),
        "top_ips": dict(ip_counts.most_common(5)),
        "analytics": {
            "human_visitors_today": len(human_ips_today),
            "human_hits_today": human_hits_today,
            "bot_hits_today": bot_hits_today,
            "top_cities": top_cities,
            "top_urls": top_urls
        }
    })

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
    """Mengambil riwayat serangan web mencurigakan yang tersimpan di SQLite."""
    limit = int(request.args.get("limit", 50))
    category = request.args.get("category", "").strip()
    search = request.args.get("search", "").strip()

    try:
        conn = get_db()
        cur = conn.cursor()

        query = "SELECT probe_time as date, ip_address as ip, method, path, status_code as status, category FROM attack_probes WHERE 1=1"
        params = []
        if category:
            query += " AND category = ?"
            params.append(category)
        if search:
            query += " AND (ip_address LIKE ? OR path LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cur.execute(query, params)
        probes = [dict(r) for r in cur.fetchall()]

        cur.execute("SELECT count(*) FROM attack_probes")
        total = cur.fetchone()[0]
        conn.close()

        # Fallback jika DB masih kosong
        if not probes:
            sync_probes_from_logs()
            conn = get_db()
            cur = conn.cursor()
            cur.execute(query, params)
            probes = [dict(r) for r in cur.fetchall()]
            total = len(probes)
            conn.close()

        return jsonify({"probes": probes, "total": total})
    except Exception as e:
        return jsonify({"probes": [], "total": 0, "error": str(e)})

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
