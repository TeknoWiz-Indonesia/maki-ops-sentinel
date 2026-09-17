# Maki Ops Sentinel — Fail2ban & Security Operations Dashboard

Maki Ops Sentinel is a lightweight, real-time security operations dashboard deployed on the RSUD Kardinah aaPanel web server (`172.16.62.181:8560`). It provides live telemetry for Fail2ban jails, active UFW firewall blocks, malicious web probe detections, whitelist management, and audit trails backed by a dedicated SQLite database in WAL mode.

---

## 🚀 Key Features

- **Live Fail2ban Monitoring:** Real-time metrics for active jails (`nginx-scan`, `sshd`), total failed attempts, and currently banned IPs.
- **UFW Firewall Synchronization:** Displays active kernel/firewall blocks (`REJECT IN`, `DENY IN`) managed by Fail2ban banactions.
- **SQLite Event Persistence:** Persistent storage for ban/unban history, security probe alerts, audit actions, and 10-minute metrics snapshots at `data/sentinel.db`.
- **Zero-Bloat Web Streaming:** Normal Nginx access logs are streamed live (`tail`) on-the-fly without database bloat. Only detected exploit attempts are recorded.
- **Whitelist Controls:** Easy addition and removal of trusted IP addresses from `/etc/fail2ban/jail.local` directly via UI or REST API.
- **Hairpin NAT False-Ban Immunity:** Pre-configured protection for FortiGate SNAT (`172.17.3.2`) and Core Switch (`10.100.2.1`) to prevent internal staff false-bans.

---

## 🛠️ Architecture & Tech Stack

- **Backend:** Python 3 (Flask), SQLite3 (WAL Mode, Multi-thread Safe).
- **Frontend:** HTML5, Tailwind CSS, Vanilla JavaScript (Fast, responsive, zero-build).
- **Process Manager:** Systemd service (`fail2ban-dashboard.service`).
- **Data Retention:** Automatic 90-day retention cleanup loop.

---

## 📂 Project Structure

```
.
├── data/                  # SQLite persistent storage (sentinel.db)
├── templates/
│   └── index.html         # Responsive monitoring dashboard UI
├── server.py              # Flask API backend, SQLite schema & background sync worker
├── requirements.txt       # Python dependencies
├── .gitignore             # Ignored runtime artifacts & DBs
└── README.md              # Project documentation
```

---

## ⚙️ REST API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/summary` | Service status, jail details, UFW blocks, whitelist & DB stats |
| `GET` | `/api/report` | Aggregated security summary report (supports `period=today\|7d\|30d\|all`) |
| `GET` | `/api/report/export-csv` | Downloadable CSV report (supports `type=probes\|bans\|attackers` & `period`) |
| `GET` | `/api/banned-history` | Ban/unban event history from SQLite (supports `search` & `jail` filter) |
| `GET` | `/api/web-attacks` | Detected malicious web probes from SQLite (supports `category` & `search`) |
| `GET` | `/api/audit-logs` | Administrative audit trail of dashboard actions |
| `GET` | `/api/access-logs` | Live streaming tail of Nginx access logs (not saved in DB) |
| `POST` | `/api/whitelist/add` | Add IP to Fail2ban `ignoreip` whitelist |
| `POST` | `/api/whitelist/remove` | Remove IP from Fail2ban `ignoreip` whitelist |
| `POST` | `/api/action/ban` | Manually ban an IP in a specific jail |
| `POST` | `/api/action/unban` | Manually unban an IP from a jail |

---

## 📦 Deployment (Systemd)

Service unit file located at `/etc/systemd/system/fail2ban-dashboard.service`:

```ini
[Unit]
Description=Fail2ban Web Monitoring Dashboard
After=network.target fail2ban.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/fail2ban-dashboard
ExecStart=/usr/bin/python3 /opt/fail2ban-dashboard/server.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
# Reload & restart
sudo systemctl daemon-reload
sudo systemctl restart fail2ban-dashboard.service
sudo systemctl status fail2ban-dashboard.service
```

---

*Maintained by TeknoWiz Indonesia & IT RSUD Kardinah.*
