# Agnivarta AI — Intelligent Fire Network
### AI-Powered Cybersecurity & Identity Trust Platform for Banking

---

## Quick Start (3 steps)

**Step 1 — Install Python dependencies**
```bash
pip install -r requirements.txt
```

**Step 2 — Start the backend**
```bash
python start.py
```
Or manually:
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

**Step 3 — Open the frontend**
Open `frontend/index.html` in your browser.

> The frontend talks to the backend at `http://127.0.0.1:8000`.

---

## Demo Accounts

| Role | Email | Password | Trust Level |
|------|-------|----------|-------------|
| Regular User | arjun@novabank.com | user1pass | Trusted |
| Suspicious User | rohan@novabank.com | user3pass | Suspicious |
| High-Risk User | vikram@novabank.com | user5pass | Dangerous |
| Admin | admin@novabank.com | adminpass | Trusted |

---

## Project Structure

```
agnivarta/
├── start.py                  ← One-click launcher
├── requirements.txt
├── frontend/
│   └── index.html            ← Complete UI (NovaBank + Security Dashboard)
├── backend/
│   └── main.py               ← FastAPI server + AI Engine + WebSocket
├── database/
│   └── agnivarta.db          ← SQLite (auto-created on first run)
└── logs/
    └── server.log
```

---

## Platform Features

### NovaBank (Banking Demo)
- Landing page with live threat stats
- Secure login with AI risk assessment at signin
- Signup with fake-email detection
- Account dashboard with balance and transactions
- Transaction history and new transaction panel
- Security Center with checklist and recommendations
- Session Activity log

### Agnivarta AI Security Dashboard
- **Overview** — Live metrics: sessions, alerts, blocked entities, risk users
- **Live Threats** — Real-time alert feed with resolve action
- **Active Sessions** — All sessions with IP, device, risk score
- **Blocked Entities** — IPs, users, sessions, emails blocked by AI or admin
- **Behavioral Analytics** — Risk score distribution, user risk profiles
- **Device Trust Engine** — Browser fingerprint, IP, location tracking
- **Traffic Analysis** — 24-hour request history with spike detection
- **User Risk Intelligence** — All users sorted by AI risk score
- **Activity Logs** — Complete audit trail, flagged events highlighted
- **Attack Simulation** — 5 attack types triggerable via buttons
- **AI Audit Report** — Automated security posture assessment

### Attack Simulations
| Simulation | What it does |
|-----------|-------------|
| Brute Force | 8 rapid failed logins, IP auto-blocked |
| Suspicious Login | Tor exit node + unknown device fingerprint |
| Fake User | Bot account with disposable email detected |
| Traffic Spike | DDoS-like surge 2400% above baseline |
| Insider Threat | Bulk data export at 2:34 AM flagged |

### AI Risk Engine
- Email pattern analysis (disposable email detection)
- Login history analysis (brute force detection)
- Session behavior analysis (scraping, long sessions)
- Composite risk scoring 0–100
- Auto-block at risk score ≥ 75
- Trust classification: Trusted (green) / Suspicious (yellow) / Dangerous (red)

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /health | Server health check |
| POST | /api/auth/login | User login with AI assessment |
| POST | /api/auth/signup | User registration with email risk check |
| GET | /api/user/{id} | Get user details |
| GET | /api/transactions/{user_id} | Get transaction history |
| POST | /api/transactions/create | Create new transaction |
| GET | /api/security/dashboard | Security metrics and alerts |
| GET | /api/security/users | All users with risk scores |
| GET | /api/security/sessions | Active sessions |
| GET | /api/security/alerts | Security alerts |
| GET | /api/security/blocked | Blocked entities |
| GET | /api/security/activity-logs | Activity audit logs |
| GET | /api/security/audit | AI audit report |
| POST | /api/security/resolve-alert/{id} | Resolve an alert |
| POST | /api/security/block-user/{id} | Block a user |
| POST | /api/simulate/attack | Trigger attack simulation |
| WS | /ws/monitor | WebSocket live updates |

Interactive API docs: http://127.0.0.1:8000/docs

---

## Technology Stack

- **Frontend**: Vanilla HTML5 + CSS3 + JavaScript (zero build tools needed)
- **Backend**: Python 3.10+ / FastAPI
- **Database**: SQLite (auto-created, no setup needed)
- **Real-time**: WebSockets (native FastAPI support)
- **AI Engine**: Rule-based behavioral analytics in Python

No cloud. No MongoDB. No npm. Runs entirely locally.
