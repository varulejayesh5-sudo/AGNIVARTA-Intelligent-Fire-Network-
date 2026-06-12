"""
Agnivarta AI - Intelligent Fire Network
Main FastAPI Backend Server
Handles: REST API, WebSocket, AI Engine, SQLite DB, Security Core
"""

import asyncio
import hashlib
import json
import math
import os
import random
import re
import sqlite3
import time
import uuid
from datetime import datetime, timedelta
from typing import Optional, List
import threading

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

# ─── App Init ────────────────────────────────────────────────────────────────
app = FastAPI(title="Agnivarta AI Security Platform", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Database Setup ───────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), "../database/agnivarta.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def get_db():
    """Return a new SQLite connection with row_factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Create all tables and seed demo data."""
    conn = get_db()
    c = conn.cursor()

    # Users table
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        account_number TEXT UNIQUE,
        balance REAL DEFAULT 50000.0,
        role TEXT DEFAULT 'user',
        created_at TEXT,
        risk_score INTEGER DEFAULT 0,
        status TEXT DEFAULT 'active',
        trust_level TEXT DEFAULT 'trusted'
    )""")

    # Sessions table
    c.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        ip_address TEXT,
        device_info TEXT,
        browser TEXT,
        location TEXT,
        login_time TEXT,
        last_active TEXT,
        status TEXT DEFAULT 'active',
        risk_score INTEGER DEFAULT 0,
        pages_visited TEXT DEFAULT '[]',
        fingerprint TEXT
    )""")

    # Login attempts table
    c.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts (
        id TEXT PRIMARY KEY,
        email TEXT,
        ip_address TEXT,
        success INTEGER,
        timestamp TEXT,
        reason TEXT,
        device_info TEXT
    )""")

    # Transactions table
    c.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        type TEXT,
        amount REAL,
        description TEXT,
        timestamp TEXT,
        status TEXT DEFAULT 'completed',
        recipient TEXT
    )""")

    # Security alerts table
    c.execute("""
    CREATE TABLE IF NOT EXISTS security_alerts (
        id TEXT PRIMARY KEY,
        alert_type TEXT,
        severity TEXT,
        user_id TEXT,
        description TEXT,
        timestamp TEXT,
        resolved INTEGER DEFAULT 0,
        session_id TEXT
    )""")

    # Blocked users table
    c.execute("""
    CREATE TABLE IF NOT EXISTS blocked_entities (
        id TEXT PRIMARY KEY,
        entity_type TEXT,
        entity_value TEXT,
        reason TEXT,
        blocked_at TEXT,
        blocked_by TEXT DEFAULT 'AI Engine'
    )""")

    # Activity logs table
    c.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        session_id TEXT,
        action TEXT,
        details TEXT,
        timestamp TEXT,
        ip_address TEXT,
        risk_flag INTEGER DEFAULT 0
    )""")

    # Traffic stats table
    c.execute("""
    CREATE TABLE IF NOT EXISTS traffic_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        requests_per_min INTEGER,
        unique_ips INTEGER,
        blocked_requests INTEGER,
        suspicious_count INTEGER
    )""")

    conn.commit()

    # ── Seed demo users ──
    demo_users = [
        ("usr_001", "Arjun Mehta",      "arjun@novabank.com",   "user1pass",  "NB-2024-001", 125000.0, "user",  "trusted"),
        ("usr_002", "Priya Sharma",     "priya@novabank.com",   "user2pass",  "NB-2024-002",  87500.0, "user",  "trusted"),
        ("usr_003", "Rohan Gupta",      "rohan@novabank.com",   "user3pass",  "NB-2024-003",  43200.0, "user",  "suspicious"),
        ("usr_004", "Neha Patel",       "neha@novabank.com",    "user4pass",  "NB-2024-004", 201500.0, "user",  "trusted"),
        ("usr_005", "Vikram Singh",     "vikram@novabank.com",  "user5pass",  "NB-2024-005",  15800.0, "user",  "dangerous"),
        ("adm_001", "Security Admin",   "admin@novabank.com",   "adminpass",  "NB-ADMIN-001",     0.0, "admin", "trusted"),
        ("usr_006", "Sunita Reddy",     "sunita@novabank.com",  "user6pass",  "NB-2024-006",  98000.0, "user",  "trusted"),
        ("usr_007", "Kiran Joshi",      "kiran@novabank.com",   "user7pass",  "NB-2024-007",  32100.0, "user",  "suspicious"),
    ]

    for u in demo_users:
        uid, name, email, pwd, acc, bal, role, trust = u
        ph = hashlib.sha256(pwd.encode()).hexdigest()
        risk = {"trusted": 12, "suspicious": 58, "dangerous": 87}.get(trust, 10)
        c.execute("""
            INSERT OR IGNORE INTO users
            (id,name,email,password_hash,account_number,balance,role,created_at,risk_score,status,trust_level)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (uid, name, email, ph, acc, bal, role,
              (datetime.now() - timedelta(days=random.randint(10,300))).isoformat(),
              risk, "active", trust))

    # ── Seed demo transactions ──
    tx_types = ["credit","debit","transfer","credit","debit"]
    descs = ["Salary Credit","Online Purchase","Fund Transfer","Interest Credit",
             "Bill Payment","ATM Withdrawal","UPI Payment","Mutual Fund"]
    for i in range(40):
        uid = random.choice(["usr_001","usr_002","usr_003","usr_004","usr_006"])
        t = random.choice(tx_types)
        amt = round(random.uniform(500, 25000), 2)
        c.execute("""
            INSERT OR IGNORE INTO transactions (id,user_id,type,amount,description,timestamp,status)
            VALUES (?,?,?,?,?,?,?)
        """, (f"tx_{i:04d}", uid, t, amt, random.choice(descs),
              (datetime.now() - timedelta(hours=random.randint(1,720))).isoformat(), "completed"))

    # ── Seed demo alerts ──
    alert_types = [
        ("brute_force",     "high",   "usr_005", "Multiple failed login attempts detected from IP 192.168.1.45"),
        ("suspicious_login","medium", "usr_003", "Login from unusual geographic location - Rajasthan vs usual Mumbai"),
        ("fake_identity",   "high",   "usr_007", "Email pattern matches disposable email service"),
        ("abnormal_traffic","medium", "usr_003", "Traffic spike 450% above baseline detected"),
        ("insider_threat",  "critical","usr_005","Accessing sensitive financial records outside business hours"),
    ]
    for i, (atype, sev, uid, desc) in enumerate(alert_types):
        c.execute("""
            INSERT OR IGNORE INTO security_alerts (id,alert_type,severity,user_id,description,timestamp,resolved)
            VALUES (?,?,?,?,?,?,?)
        """, (f"alert_{i:04d}", atype, sev, uid, desc,
              (datetime.now() - timedelta(minutes=random.randint(5,300))).isoformat(), 0))

    # ── Seed blocked entities ──
    blocked = [
        ("blk_001","ip",      "192.168.1.45",       "Brute force attack - 23 failed attempts"),
        ("blk_002","user",    "usr_005",             "Insider threat - unauthorized data access"),
        ("blk_003","ip",      "10.0.0.99",           "Bot traffic detected"),
        ("blk_004","email",   "fake@tempmail.io",    "Disposable email - fake identity"),
        ("blk_005","session", "sess_malicious_001",  "Session hijack attempt"),
    ]
    for b in blocked:
        c.execute("""
            INSERT OR IGNORE INTO blocked_entities (id,entity_type,entity_value,reason,blocked_at)
            VALUES (?,?,?,?,?)
        """, (*b, (datetime.now() - timedelta(minutes=random.randint(10,480))).isoformat()))

    # ── Seed traffic stats ──
    for i in range(24):
        ts = (datetime.now() - timedelta(hours=23-i)).isoformat()
        c.execute("""
            INSERT OR IGNORE INTO traffic_stats (timestamp,requests_per_min,unique_ips,blocked_requests,suspicious_count)
            VALUES (?,?,?,?,?)
        """, (ts, random.randint(20,180), random.randint(5,60),
              random.randint(0,15), random.randint(0,8)))

    conn.commit()
    conn.close()
    print("[Agnivarta] Database initialized with demo data.")


# ─── Pydantic Models ──────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: str
    password: str
    device_info: Optional[str] = "Unknown"
    ip_address: Optional[str] = "127.0.0.1"

class SignupRequest(BaseModel):
    name: str
    email: str
    password: str
    device_info: Optional[str] = "Unknown"

class TransactionRequest(BaseModel):
    user_id: str
    type: str
    amount: float
    description: str
    recipient: Optional[str] = ""

class SimulationRequest(BaseModel):
    attack_type: str
    target_user: Optional[str] = "usr_003"


# ─── AI Risk Engine ────────────────────────────────────────────────────────────
class AIRiskEngine:
    """
    Rule-based + behavioral analytics AI risk scoring engine.
    Calculates risk scores 0-100 and classifies trust levels.
    """

    FAKE_EMAIL_PATTERNS = [
        r".*@tempmail\.", r".*@mailinator\.", r".*@guerrillamail\.",
        r".*@10minutemail\.", r".*@throwam\.", r".*@yopmail\.",
        r".*@fakeinbox\.", r".*@trashmail\.", r".*@dispostable\.",
        r"random\d{5,}@", r"test\d{3,}@", r"user\d{4,}@"
    ]

    def analyze_email(self, email: str) -> dict:
        """Check email for fake/disposable patterns."""
        score = 0
        flags = []
        email_lower = email.lower()
        for pattern in self.FAKE_EMAIL_PATTERNS:
            if re.search(pattern, email_lower):
                score += 40
                flags.append("Disposable/fake email pattern detected")
                break
        if re.search(r"\d{4,}", email.split("@")[0]):
            score += 15
            flags.append("Numeric pattern in username suggests bot")
        if len(email.split("@")[0]) < 3:
            score += 20
            flags.append("Very short email username")
        return {"score": min(score, 60), "flags": flags}

    def analyze_login_history(self, user_id: str) -> dict:
        """Detect brute force, unusual timing, location anomalies."""
        conn = get_db()
        c = conn.cursor()
        score = 0
        flags = []

        # Failed attempts in last 10 minutes
        cutoff = (datetime.now() - timedelta(minutes=10)).isoformat()
        c.execute("""
            SELECT COUNT(*) as cnt FROM login_attempts
            WHERE email=(SELECT email FROM users WHERE id=?) AND success=0 AND timestamp>?
        """, (user_id, cutoff))
        row = c.fetchone()
        failed = row["cnt"] if row else 0
        if failed >= 5:
            score += 50
            flags.append(f"Brute force: {failed} failed attempts in 10 min")
        elif failed >= 3:
            score += 25
            flags.append(f"Multiple failed logins: {failed} attempts")

        # Off-hours login (before 6am or after 11pm)
        hour = datetime.now().hour
        if hour < 6 or hour > 23:
            score += 15
            flags.append("Login during unusual hours")

        conn.close()
        return {"score": min(score, 70), "flags": flags}

    def analyze_session_behavior(self, session_id: str) -> dict:
        """Detect unusual navigation, long sessions, rapid page switching."""
        conn = get_db()
        c = conn.cursor()
        score = 0
        flags = []

        c.execute("SELECT * FROM sessions WHERE id=?", (session_id,))
        sess = c.fetchone()
        if sess:
            try:
                pages = json.loads(sess["pages_visited"] or "[]")
            except:
                pages = []
            if len(pages) > 20:
                score += 20
                flags.append("Excessive page navigation - possible scraping")
            login_time = datetime.fromisoformat(sess["login_time"])
            duration = (datetime.now() - login_time).total_seconds() / 60
            if duration > 120:
                score += 15
                flags.append("Unusually long session duration")

        conn.close()
        return {"score": min(score, 40), "flags": flags}

    def calculate_composite_risk(self, user_id: str, session_id: str = None, email: str = None) -> dict:
        """Aggregate all risk signals into a final composite score."""
        total_score = 0
        all_flags = []

        if email:
            email_risk = self.analyze_email(email)
            total_score += email_risk["score"]
            all_flags.extend(email_risk["flags"])

        login_risk = self.analyze_login_history(user_id)
        total_score += login_risk["score"]
        all_flags.extend(login_risk["flags"])

        if session_id:
            session_risk = self.analyze_session_behavior(session_id)
            total_score += session_risk["score"]
            all_flags.extend(session_risk["flags"])

        final_score = min(total_score, 100)

        # Trust classification
        if final_score <= 25:
            trust = "trusted"
            color = "green"
        elif final_score <= 60:
            trust = "suspicious"
            color = "yellow"
        else:
            trust = "dangerous"
            color = "red"

        return {
            "risk_score": final_score,
            "trust_level": trust,
            "color": color,
            "flags": all_flags,
            "timestamp": datetime.now().isoformat()
        }

    def should_block(self, risk_score: int) -> bool:
        return risk_score >= 75

    def generate_audit_report(self) -> dict:
        """AI-driven security audit scanning the banking platform."""
        conn = get_db()
        c = conn.cursor()

        c.execute("SELECT COUNT(*) as cnt FROM users WHERE trust_level='dangerous'")
        dangerous = c.fetchone()["cnt"]
        c.execute("SELECT COUNT(*) as cnt FROM security_alerts WHERE resolved=0")
        open_alerts = c.fetchone()["cnt"]
        c.execute("SELECT COUNT(*) as cnt FROM blocked_entities")
        blocked = c.fetchone()["cnt"]
        c.execute("SELECT COUNT(*) as cnt FROM login_attempts WHERE success=0")
        failed_logins = c.fetchone()["cnt"]

        conn.close()

        findings = []
        if dangerous > 0:
            findings.append({"severity":"critical","finding":f"{dangerous} users classified as high-risk/dangerous","recommendation":"Immediately review and suspend suspicious accounts"})
        if open_alerts > 0:
            findings.append({"severity":"high","finding":f"{open_alerts} unresolved security alerts pending","recommendation":"Assign security team to investigate alerts immediately"})
        if failed_logins > 10:
            findings.append({"severity":"medium","finding":f"{failed_logins} failed login attempts recorded","recommendation":"Enable account lockout policy after 5 failed attempts"})
        findings.append({"severity":"info","finding":"Multi-factor authentication not enforced for all users","recommendation":"Mandate MFA for all banking transactions above INR 10,000"})
        findings.append({"severity":"medium","finding":"Session timeout policy not uniformly applied","recommendation":"Enforce 15-minute idle session timeout across all banking pages"})

        security_score = max(0, 100 - (dangerous * 15) - (open_alerts * 5) - min(failed_logins, 20))

        return {
            "audit_timestamp": datetime.now().isoformat(),
            "overall_security_score": security_score,
            "total_findings": len(findings),
            "findings": findings,
            "blocked_entities": blocked,
            "recommendation_summary": "Immediate action required on critical findings. Platform security posture needs improvement."
        }


ai_engine = AIRiskEngine()


# ─── WebSocket Manager ─────────────────────────────────────────────────────────
class ConnectionManager:
    """Manages all active WebSocket connections for real-time updates."""
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data: dict):
        msg = json.dumps(data)
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(msg)
            except:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

manager = ConnectionManager()


# ─── Background Task: Live Metrics Broadcaster ────────────────────────────────
async def broadcast_live_metrics():
    """Push live dashboard metrics every 4 seconds via WebSocket."""
    while True:
        try:
            conn = get_db()
            c = conn.cursor()

            c.execute("SELECT COUNT(*) as cnt FROM sessions WHERE status='active'")
            active_sessions = c.fetchone()["cnt"]

            c.execute("SELECT COUNT(*) as cnt FROM security_alerts WHERE resolved=0")
            open_alerts = c.fetchone()["cnt"]

            c.execute("SELECT COUNT(*) as cnt FROM blocked_entities")
            blocked = c.fetchone()["cnt"]

            c.execute("SELECT COUNT(*) as cnt FROM users WHERE trust_level='dangerous'")
            dangerous_users = c.fetchone()["cnt"]

            conn.close()

            payload = {
                "type": "live_metrics",
                "data": {
                    "active_sessions": active_sessions,
                    "open_alerts": open_alerts,
                    "blocked_entities": blocked,
                    "dangerous_users": dangerous_users,
                    "requests_per_min": random.randint(45, 120),
                    "timestamp": datetime.now().isoformat(),
                    "threat_level": "high" if dangerous_users > 2 else "medium" if open_alerts > 3 else "low"
                }
            }
            await manager.broadcast(payload)
        except Exception as e:
            pass
        await asyncio.sleep(4)


@app.on_event("startup")
async def startup():
    init_db()
    asyncio.create_task(broadcast_live_metrics())
    print("[Agnivarta] Server started. AI Engine armed.")


# ─── WebSocket Endpoint ────────────────────────────────────────────────────────
@app.websocket("/ws/monitor")
async def websocket_monitor(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            data = await ws.receive_text()
            # Echo back acknowledgement
            await ws.send_text(json.dumps({"type": "ack", "message": "Connected to Agnivarta AI monitor"}))
    except WebSocketDisconnect:
        manager.disconnect(ws)


# ─── Auth Endpoints ────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
async def login(req: LoginRequest):
    conn = get_db()
    c = conn.cursor()

    ph = hashlib.sha256(req.password.encode()).hexdigest()
    c.execute("SELECT * FROM users WHERE email=? AND password_hash=?", (req.email, ph))
    user = c.fetchone()

    attempt_id = str(uuid.uuid4())
    ts = datetime.now().isoformat()

    if not user:
        # Record failed attempt
        c.execute("""
            INSERT INTO login_attempts (id,email,ip_address,success,timestamp,reason,device_info)
            VALUES (?,?,?,0,?,'Invalid credentials',?)
        """, (attempt_id, req.email, req.ip_address, ts, req.device_info))
        conn.commit()

        # Check if IP should be blocked
        cutoff = (datetime.now() - timedelta(minutes=10)).isoformat()
        c.execute("SELECT COUNT(*) as cnt FROM login_attempts WHERE email=? AND success=0 AND timestamp>?",
                  (req.email, cutoff))
        fails = c.fetchone()["cnt"]

        if fails >= 5:
            blk_id = str(uuid.uuid4())
            c.execute("""
                INSERT OR IGNORE INTO blocked_entities (id,entity_type,entity_value,reason,blocked_at)
                VALUES (?,?,?,?,?)
            """, (blk_id, "ip", req.ip_address, f"Brute force: {fails} failed attempts", ts))

            alert_id = str(uuid.uuid4())
            c.execute("""
                INSERT INTO security_alerts (id,alert_type,severity,user_id,description,timestamp)
                VALUES (?,?,?,?,?,?)
            """, (alert_id, "brute_force", "high", "unknown",
                  f"Brute force attack from {req.ip_address} - {fails} attempts", ts))
            conn.commit()

            await manager.broadcast({
                "type": "alert",
                "data": {"message": f"Brute force detected from {req.ip_address}", "severity": "high"}
            })

        conn.close()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Check if blocked
    c.execute("SELECT * FROM blocked_entities WHERE entity_value=? AND entity_type='user'",
              (str(user["id"]),))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=403, detail="Account blocked by security system")

    # Create session
    session_id = f"sess_{uuid.uuid4().hex[:12]}"
    fingerprint = hashlib.md5(f"{req.device_info}{req.ip_address}".encode()).hexdigest()

    c.execute("""
        INSERT INTO sessions (id,user_id,ip_address,device_info,browser,location,login_time,last_active,status,risk_score,fingerprint)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (session_id, user["id"], req.ip_address, req.device_info, req.device_info,
          "India", ts, ts, "active", user["risk_score"], fingerprint))

    # Record successful login
    c.execute("""
        INSERT INTO login_attempts (id,email,ip_address,success,timestamp,reason,device_info)
        VALUES (?,?,?,1,?,'Successful login',?)
    """, (attempt_id, req.email, req.ip_address, ts, req.device_info))

    # Log activity
    log_id = str(uuid.uuid4())
    c.execute("""
        INSERT INTO activity_logs (id,user_id,session_id,action,details,timestamp,ip_address)
        VALUES (?,?,?,?,?,?,?)
    """, (log_id, user["id"], session_id, "login", f"Successful login from {req.ip_address}", ts, req.ip_address))

    conn.commit()

    # AI risk analysis
    risk = ai_engine.calculate_composite_risk(user["id"], session_id, req.email)

    # Auto-block if risk too high
    if ai_engine.should_block(risk["risk_score"]):
        blk_id = str(uuid.uuid4())
        c.execute("""
            INSERT OR IGNORE INTO blocked_entities (id,entity_type,entity_value,reason,blocked_at)
            VALUES (?,?,?,?,?)
        """, (blk_id, "session", session_id, f"AI auto-block: risk score {risk['risk_score']}", ts))
        c.execute("UPDATE sessions SET status='blocked' WHERE id=?", (session_id,))
        conn.commit()
        await manager.broadcast({
            "type": "alert",
            "data": {"message": f"AI auto-blocked session for {user['email']}", "severity": "critical"}
        })

    conn.close()
    return {
        "success": True,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "account_number": user["account_number"],
            "balance": user["balance"],
            "trust_level": user["trust_level"],
            "risk_score": risk["risk_score"]
        },
        "session_id": session_id,
        "risk_assessment": risk
    }


@app.post("/api/auth/signup")
async def signup(req: SignupRequest):
    conn = get_db()
    c = conn.cursor()

    # Check email exists
    c.execute("SELECT id FROM users WHERE email=?", (req.email,))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered")

    # AI email risk check
    email_risk = ai_engine.analyze_email(req.email)

    uid = f"usr_{uuid.uuid4().hex[:8]}"
    ph = hashlib.sha256(req.password.encode()).hexdigest()
    acc = f"NB-{datetime.now().year}-{random.randint(100,999)}"
    ts = datetime.now().isoformat()
    trust = "suspicious" if email_risk["score"] > 30 else "trusted"

    c.execute("""
        INSERT INTO users (id,name,email,password_hash,account_number,balance,role,created_at,risk_score,status,trust_level)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (uid, req.name, req.email, ph, acc, 10000.0, "user", ts, email_risk["score"], "active", trust))

    if email_risk["flags"]:
        alert_id = str(uuid.uuid4())
        c.execute("""
            INSERT INTO security_alerts (id,alert_type,severity,user_id,description,timestamp)
            VALUES (?,?,?,?,?,?)
        """, (alert_id, "fake_identity", "medium", uid,
              f"Suspicious signup: {', '.join(email_risk['flags'])}", ts))

    conn.commit()
    conn.close()

    return {"success": True, "user_id": uid, "account_number": acc,
            "risk_flags": email_risk["flags"],
            "message": "Account created successfully. Welcome to NovaBank."}


# ─── Banking Endpoints ─────────────────────────────────────────────────────────
@app.get("/api/user/{user_id}")
async def get_user(user_id: str):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id,name,email,account_number,balance,role,created_at,risk_score,status,trust_level FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return dict(user)


@app.get("/api/transactions/{user_id}")
async def get_transactions(user_id: str, limit: int = 10):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT * FROM transactions WHERE user_id=? ORDER BY timestamp DESC LIMIT ?
    """, (user_id, limit))
    txns = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"transactions": txns}


@app.post("/api/transactions/create")
async def create_transaction(req: TransactionRequest):
    conn = get_db()
    c = conn.cursor()

    # Check user balance for debit
    c.execute("SELECT balance FROM users WHERE id=?", (req.user_id,))
    user = c.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    if req.type == "debit" and user["balance"] < req.amount:
        conn.close()
        raise HTTPException(status_code=400, detail="Insufficient balance")

    tx_id = f"tx_{uuid.uuid4().hex[:10]}"
    ts = datetime.now().isoformat()

    c.execute("""
        INSERT INTO transactions (id,user_id,type,amount,description,timestamp,status,recipient)
        VALUES (?,?,?,?,?,?,?,?)
    """, (tx_id, req.user_id, req.type, req.amount, req.description, ts, "completed", req.recipient))

    # Update balance
    if req.type in ["debit","transfer"]:
        c.execute("UPDATE users SET balance=balance-? WHERE id=?", (req.amount, req.user_id))
    else:
        c.execute("UPDATE users SET balance=balance+? WHERE id=?", (req.amount, req.user_id))

    # Flag large transactions
    if req.amount > 50000:
        alert_id = str(uuid.uuid4())
        c.execute("""
            INSERT INTO security_alerts (id,alert_type,severity,user_id,description,timestamp)
            VALUES (?,?,?,?,?,?)
        """, (alert_id, "large_transaction", "medium", req.user_id,
              f"Large transaction of INR {req.amount:,.0f} detected", ts))

    conn.commit()
    conn.close()

    await manager.broadcast({
        "type": "transaction",
        "data": {"user_id": req.user_id, "amount": req.amount, "type": req.type, "timestamp": ts}
    })

    return {"success": True, "transaction_id": tx_id}


# ─── Security Dashboard Endpoints ─────────────────────────────────────────────
@app.get("/api/security/dashboard")
async def security_dashboard():
    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT COUNT(*) as cnt FROM sessions WHERE status='active'")
    active_sessions = c.fetchone()["cnt"]

    c.execute("SELECT COUNT(*) as cnt FROM security_alerts WHERE resolved=0")
    open_alerts = c.fetchone()["cnt"]

    c.execute("SELECT COUNT(*) as cnt FROM blocked_entities")
    blocked = c.fetchone()["cnt"]

    c.execute("SELECT COUNT(*) as cnt FROM users WHERE trust_level='dangerous'")
    dangerous = c.fetchone()["cnt"]

    c.execute("SELECT COUNT(*) as cnt FROM users WHERE trust_level='suspicious'")
    suspicious = c.fetchone()["cnt"]

    c.execute("SELECT COUNT(*) as cnt FROM users WHERE trust_level='trusted'")
    trusted = c.fetchone()["cnt"]

    c.execute("SELECT COUNT(*) as cnt FROM login_attempts WHERE success=0")
    failed_logins = c.fetchone()["cnt"]

    c.execute("SELECT COUNT(*) as cnt FROM login_attempts WHERE success=1")
    successful_logins = c.fetchone()["cnt"]

    c.execute("SELECT COUNT(*) as cnt FROM users")
    total_users = c.fetchone()["cnt"]

    c.execute("SELECT * FROM security_alerts WHERE resolved=0 ORDER BY timestamp DESC LIMIT 10")
    recent_alerts = [dict(r) for r in c.fetchall()]

    c.execute("SELECT * FROM traffic_stats ORDER BY timestamp DESC LIMIT 24")
    traffic = [dict(r) for r in c.fetchall()]

    conn.close()

    return {
        "metrics": {
            "active_sessions": active_sessions,
            "open_alerts": open_alerts,
            "blocked_entities": blocked,
            "dangerous_users": dangerous,
            "suspicious_users": suspicious,
            "trusted_users": trusted,
            "failed_logins": failed_logins,
            "successful_logins": successful_logins,
            "total_users": total_users
        },
        "recent_alerts": recent_alerts,
        "traffic_data": traffic
    }


@app.get("/api/security/users")
async def get_all_users():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id,name,email,account_number,balance,role,created_at,risk_score,status,trust_level FROM users ORDER BY risk_score DESC")
    users = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"users": users}


@app.get("/api/security/sessions")
async def get_sessions():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT s.*, u.name, u.email, u.trust_level
        FROM sessions s
        LEFT JOIN users u ON s.user_id = u.id
        ORDER BY s.login_time DESC LIMIT 20
    """)
    sessions = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"sessions": sessions}


@app.get("/api/security/alerts")
async def get_alerts():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM security_alerts ORDER BY timestamp DESC LIMIT 50")
    alerts = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"alerts": alerts}


@app.get("/api/security/blocked")
async def get_blocked():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM blocked_entities ORDER BY blocked_at DESC")
    blocked = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"blocked": blocked}


@app.get("/api/security/activity-logs")
async def get_activity_logs():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT al.*, u.name, u.email
        FROM activity_logs al
        LEFT JOIN users u ON al.user_id = u.id
        ORDER BY al.timestamp DESC LIMIT 50
    """)
    logs = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"logs": logs}


@app.get("/api/security/audit")
async def get_audit_report():
    report = ai_engine.generate_audit_report()
    return report


@app.post("/api/security/resolve-alert/{alert_id}")
async def resolve_alert(alert_id: str):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE security_alerts SET resolved=1 WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Alert resolved"}


@app.post("/api/security/block-user/{user_id}")
async def block_user(user_id: str):
    conn = get_db()
    c = conn.cursor()
    blk_id = str(uuid.uuid4())
    ts = datetime.now().isoformat()
    c.execute("""
        INSERT OR IGNORE INTO blocked_entities (id,entity_type,entity_value,reason,blocked_at,blocked_by)
        VALUES (?,?,?,?,?,?)
    """, (blk_id, "user", user_id, "Manually blocked by admin", ts, "Admin"))
    c.execute("UPDATE users SET status='blocked' WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    await manager.broadcast({"type":"alert","data":{"message":f"User {user_id} blocked by admin","severity":"high"}})
    return {"success": True}


# ─── Attack Simulation Endpoints ───────────────────────────────────────────────
@app.post("/api/simulate/attack")
async def simulate_attack(req: SimulationRequest):
    """Simulate various cyberattack scenarios for demo purposes."""
    conn = get_db()
    c = conn.cursor()
    ts = datetime.now().isoformat()
    results = []

    if req.attack_type == "brute_force":
        fake_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        for i in range(8):
            attempt_id = str(uuid.uuid4())
            c.execute("""
                INSERT INTO login_attempts (id,email,ip_address,success,timestamp,reason,device_info)
                VALUES (?,?,?,0,?,'Invalid credentials','Bot/Script')
            """, (attempt_id, "victim@novabank.com", fake_ip,
                  (datetime.now() - timedelta(seconds=i*30)).isoformat()))
        alert_id = str(uuid.uuid4())
        c.execute("""
            INSERT INTO security_alerts (id,alert_type,severity,user_id,description,timestamp)
            VALUES (?,?,?,?,?,?)
        """, (alert_id, "brute_force", "high", req.target_user,
              f"SIMULATED: Brute force attack from {fake_ip} - 8 rapid attempts", ts))
        blk_id = str(uuid.uuid4())
        c.execute("""
            INSERT OR IGNORE INTO blocked_entities (id,entity_type,entity_value,reason,blocked_at)
            VALUES (?,?,?,?,?)
        """, (blk_id, "ip", fake_ip, "AI auto-block: brute force simulation", ts))
        results.append(f"Brute force: 8 failed attempts from {fake_ip} - IP auto-blocked")

    elif req.attack_type == "suspicious_login":
        session_id = f"sess_{uuid.uuid4().hex[:12]}"
        c.execute("""
            INSERT INTO sessions (id,user_id,ip_address,device_info,browser,location,login_time,last_active,status,risk_score,fingerprint)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (session_id, req.target_user, "185.220.101.45",
              "Unknown Linux CLI", "curl/7.8", "Tor Exit Node", ts, ts, "active", 88,
              hashlib.md5(b"suspicious_device").hexdigest()))
        alert_id = str(uuid.uuid4())
        c.execute("""
            INSERT INTO security_alerts (id,alert_type,severity,user_id,description,timestamp)
            VALUES (?,?,?,?,?,?)
        """, (alert_id, "suspicious_login", "critical", req.target_user,
              "SIMULATED: Login from Tor exit node with unknown device fingerprint", ts))
        c.execute("UPDATE users SET risk_score=88, trust_level='dangerous' WHERE id=?", (req.target_user,))
        results.append("Suspicious login from Tor node detected - risk elevated to CRITICAL")

    elif req.attack_type == "fake_user":
        fake_uid = f"fake_{uuid.uuid4().hex[:8]}"
        c.execute("""
            INSERT OR IGNORE INTO users (id,name,email,password_hash,account_number,balance,role,created_at,risk_score,status,trust_level)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (fake_uid, "John D0e_B0t", f"fakeusr{random.randint(1000,9999)}@tempmail.io",
              hashlib.sha256(b"fakepass").hexdigest(),
              f"NB-FAKE-{random.randint(100,999)}", 0.0, "user", ts, 92, "active", "dangerous"))
        alert_id = str(uuid.uuid4())
        c.execute("""
            INSERT INTO security_alerts (id,alert_type,severity,user_id,description,timestamp)
            VALUES (?,?,?,?,?,?)
        """, (alert_id, "fake_identity", "high", fake_uid,
              "SIMULATED: Bot account created with disposable email and numeric username", ts))
        results.append(f"Fake user account created and flagged (ID: {fake_uid})")

    elif req.attack_type == "traffic_spike":
        for i in range(6):
            c.execute("""
                INSERT INTO traffic_stats (timestamp,requests_per_min,unique_ips,blocked_requests,suspicious_count)
                VALUES (?,?,?,?,?)
            """, ((datetime.now() - timedelta(minutes=i*2)).isoformat(),
                  random.randint(800, 2000), random.randint(200, 500),
                  random.randint(50, 200), random.randint(20, 80)))
        alert_id = str(uuid.uuid4())
        c.execute("""
            INSERT INTO security_alerts (id,alert_type,severity,user_id,description,timestamp)
            VALUES (?,?,?,?,?,?)
        """, (alert_id, "abnormal_traffic", "high", "system",
              "SIMULATED: DDoS spike - 1,800 req/min from 400+ IPs (baseline: 80 req/min)", ts))
        results.append("Traffic spike simulated: 2000 req/min vs baseline 80 req/min - 2400% increase")

    elif req.attack_type == "insider_threat":
        log_id = str(uuid.uuid4())
        c.execute("""
            INSERT INTO activity_logs (id,user_id,session_id,action,details,timestamp,ip_address,risk_flag)
            VALUES (?,?,?,?,?,?,?,1)
        """, (log_id, req.target_user, "sess_insider_001",
              "data_exfiltration",
              "SIMULATED: Bulk export of customer PAN/Aadhaar data at 02:34 AM - 4,200 records",
              ts, "192.168.1.105"))
        alert_id = str(uuid.uuid4())
        c.execute("""
            INSERT INTO security_alerts (id,alert_type,severity,user_id,description,timestamp)
            VALUES (?,?,?,?,?,?)
        """, (alert_id, "insider_threat", "critical", req.target_user,
              "SIMULATED: Insider data exfiltration - bulk PAN/Aadhaar export outside business hours", ts))
        c.execute("UPDATE users SET risk_score=95, trust_level='dangerous' WHERE id=?", (req.target_user,))
        results.append("Insider threat simulated: bulk data export flagged at 2:34 AM")

    conn.commit()
    conn.close()

    # Broadcast to all connected dashboards
    await manager.broadcast({
        "type": "simulation",
        "data": {
            "attack_type": req.attack_type,
            "results": results,
            "timestamp": ts,
            "severity": "critical"
        }
    })

    return {"success": True, "attack_type": req.attack_type, "results": results, "timestamp": ts}


# ─── Serve Frontend ────────────────────────────────────────────────────────────
frontend_dir = os.path.join(os.path.dirname(__file__), "../frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

@app.get("/", response_class=HTMLResponse)
async def root():
    index_path = os.path.join(frontend_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path) as f:
            return f.read()
    return HTMLResponse("<h1>Agnivarta AI - Frontend not found. Run from project root.</h1>")

@app.get("/health")
async def health():
    return {"status": "operational", "service": "Agnivarta AI Security Platform", "version": "1.0.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False, log_level="info")
