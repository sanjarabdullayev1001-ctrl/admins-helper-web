
import os
import re
import json
import time
import hmac
import hashlib
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from passlib.context import CryptContext


# =========================================================
# ADMINS HELPER WEB — CONFIG
# =========================================================

APP_NAME = "ADMINS HELPER"
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
BRIDGE_SECRET = os.getenv("BRIDGE_SECRET", "")
OWNER_USERNAME = os.getenv("WEB_OWNER_USERNAME", "owner")
OWNER_PASSWORD = os.getenv("WEB_OWNER_PASSWORD", "")
DATABASE_URL = os.getenv("DATABASE_URL", "")

DB_PATH = os.getenv("WEB_DB_PATH", "admins_helper_web.sqlite3")

if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET sozlanmagan")

if not OWNER_PASSWORD:
    raise RuntimeError("WEB_OWNER_PASSWORD sozlanmagan")

app = FastAPI(title=APP_NAME)

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    https_only=True,
    same_site="lax",
    max_age=60 * 60 * 12,
)

pwd = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


# =========================================================
# DATABASE
# =========================================================

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            active INTEGER NOT NULL DEFAULT 1,
            permissions TEXT NOT NULL DEFAULT '{}',
            created_at INTEGER NOT NULL,
            telegram_id TEXT
        );

        CREATE TABLE IF NOT EXISTS group_access (
            telegram_id TEXT NOT NULL,
            chat_id TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'member',
            updated_at INTEGER NOT NULL,
            PRIMARY KEY(telegram_id, chat_id)
        );

        CREATE TABLE IF NOT EXISTS groups_data (
            chat_id TEXT PRIMARY KEY,
            title TEXT NOT NULL DEFAULT '',
            members INTEGER NOT NULL DEFAULT 0,
            last_seen INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS bridge_events (
            event_id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            chat_id TEXT NOT NULL DEFAULT '',
            payload TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            success INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
        """)

        cols = {r["name"] for r in c.execute("PRAGMA table_info(admins)").fetchall()}
        if "telegram_id" not in cols:
            c.execute("ALTER TABLE admins ADD COLUMN telegram_id TEXT")

        c.execute(
            "INSERT OR IGNORE INTO admins "
            "(username,password_hash,role,active,permissions,created_at) "
            "VALUES (?,?,?,?,?,?)",
            (
                OWNER_USERNAME,
                pwd.hash(OWNER_PASSWORD),
                "owner",
                1,
                '{"all":true}',
                int(time.time())
            )
        )


init_db()


# =========================================================
# HELPERS
# =========================================================

def now():
    return int(time.time())


def current_user(request: Request):
    uid = request.session.get("uid")
    if not uid:
        return None

    with db() as c:
        user = c.execute(
            "SELECT * FROM admins WHERE id=? AND active=1",
            (uid,)
        ).fetchone()

    return dict(user) if user else None


def require_login(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(401, "Login talab qilinadi")
    return user


def visible_chat_ids(user):
    if user["role"] == "owner":
        return None
    tid = str(user.get("telegram_id") or "")
    if not tid:
        return []
    with db() as c:
        return [r["chat_id"] for r in c.execute(
            "SELECT chat_id FROM group_access WHERE telegram_id=? AND LOWER(role) IN ('creator','administrator','admin','owner')", (tid,)
        ).fetchall()]

def require_group_access(user, chat_id):
    ids = visible_chat_ids(user)
    if ids is not None and str(chat_id) not in ids:
        raise HTTPException(403, "Bu guruh sizga biriktirilmagan")

def require_owner(request: Request):
    user = require_login(request)
    if user["role"] != "owner":
        raise HTTPException(403, "Faqat Owner uchun")
    return user


def can(user, permission):
    if user["role"] == "owner":
        return True

    try:
        permissions = json.loads(user["permissions"])
    except Exception:
        return False

    return bool(permissions.get(permission))


def audit(actor, action, details=""):
    with db() as c:
        c.execute(
            "INSERT INTO audit_logs(actor,action,details,created_at) "
            "VALUES(?,?,?,?)",
            (actor, action, details[:2000], now())
        )


def page(title, content):
    return HTMLResponse(f"""
    <!doctype html>
    <html lang="uz">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>{title} | {APP_NAME}</title>
      <style>
        *{{box-sizing:border-box}}
        body{{margin:0;background:#090b12;color:#eee;font-family:Arial,sans-serif}}
        header{{padding:20px 6%;border-bottom:1px solid #292d39;
        display:flex;justify-content:space-between;align-items:center}}
        .logo{{font-weight:900;color:#ff334f;letter-spacing:2px}}
        main{{max-width:1100px;margin:45px auto;padding:20px}}
        .card{{background:#121622;border:1px solid #292f40;border-radius:15px;
        padding:22px;margin-bottom:18px}}
        h1,h2{{margin-top:0}}
        h1{{font-size:34px}}
        p{{color:#b7bdcc;line-height:1.6}}
        a{{color:#ff536a;text-decoration:none}}
        .btn{{display:inline-block;background:#e92e49;color:white;
        border:0;border-radius:9px;padding:12px 18px;cursor:pointer;
        font-weight:bold;margin:5px 4px 5px 0}}
        .btn.secondary{{background:#272e40}}
        input,select{{width:100%;padding:13px;margin:8px 0 15px;
        border:1px solid #343b4d;border-radius:8px;
        background:#090e19;color:white}}
        label{{color:#c8cede;font-size:14px}}
        table{{width:100%;border-collapse:collapse}}
        td,th{{padding:12px;border-bottom:1px solid #303648;text-align:left}}
        th{{color:#ff536a}}
        .muted{{color:#8992a5;font-size:13px}}
        .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:15px}}
        .number{{font-size:30px;font-weight:bold;color:#ff536a}}
        .danger{{color:#ff687c}}
      </style>
    </head>
    <body>
      <header>
        <div class="logo">ADMINS HELPER</div>
        <a href="/">BOSH SAHIFA</a>
      </header>
      <main>{content}</main>
    </body>
    </html>
    """)


# =========================================================
# PUBLIC HOME — NO LOGIN
# =========================================================

@app.get("/", response_class=HTMLResponse)
async def home():
    return page("Bosh sahifa", """
    <div class="card">
      <p class="logo">CYBER CONTROL SYSTEM</p>
      <h1>ADMINS HELPER</h1>
      <p>Guruhlar boshqaruvi, statistika va xavfsizlik nazorati uchun yagona platforma.</p>
      <a class="btn" href="/portal">WEB SERVERGA KIRISH →</a>
    </div>
    <div class="grid">
      <div class="card"><h2>Statistika</h2><p>Ulangan guruhlar va faollik ko‘rsatkichlari.</p></div>
      <div class="card"><h2>Xavfsizlik</h2><p>Ruxsatlar va boshqaruv amallari nazorati.</p></div>
      <div class="card"><h2>Monitoring</h2><p>Bot yuborgan hodisalar tarixi.</p></div>
    </div>
    <p class="muted">Ommaviy sahifa. Boshqaruv ma’lumotlari faqat ruxsatli foydalanuvchilarga ko‘rsatiladi.</p>
    """)


# =========================================================
# LOGIN / LOGOUT
# =========================================================

@app.get("/admin-login", response_class=HTMLResponse)
async def login_page():
    return page("Admin login", """
    <div class="card" style="max-width:450px;margin:auto">
      <h1>ADMIN PANEL</h1>
      <p>Shaxsiy hisobingizga kiring.</p>
      <form method="post" action="/api/auth/login">
        <label>Login</label>
        <input name="username" required maxlength="64">
        <label>Parol</label>
        <input name="password" type="password" required maxlength="200">
        <button class="btn" type="submit">TIZIMGA KIRISH →</button>
      </form>
    </div>
    """)


@app.post("/api/auth/login")
async def login(request: Request):
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))

    with db() as c:
        recent = c.execute(
            "SELECT COUNT(*) n FROM login_attempts "
            "WHERE created_at>? AND success=0",
            (now() - 600,)
        ).fetchone()["n"]

        if recent >= 30:
            raise HTTPException(429, "Juda ko‘p urinish. Keyinroq urinib ko‘ring.")

        user = c.execute(
            "SELECT * FROM admins WHERE username=? AND active=1",
            (username,)
        ).fetchone()

        valid = bool(user and pwd.verify(password, user["password_hash"]))

        c.execute(
            "INSERT INTO login_attempts(username,success,created_at) VALUES(?,?,?)",
            (username[:64], int(valid), now())
        )

    if not valid:
        return page("Xatolik", """
        <div class="card">
          <h2 class="danger">Login yoki parol noto‘g‘ri</h2>
          <a class="btn" href="/admin-login">QAYTA URINISH</a>
        </div>
        """)

    request.session.clear()
    request.session["uid"] = user["id"]
    audit(username, "LOGIN", "Admin panelga kirdi")

    return RedirectResponse("/dashboard", status_code=303)


@app.post("/api/auth/logout")
async def logout(request: Request):
    user = current_user(request)
    if user:
        audit(user["username"], "LOGOUT")
    request.session.clear()
    return RedirectResponse("/", status_code=303)


# =========================================================
# DASHBOARD
# =========================================================

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    user = require_login(request)

    if not can(user, "dashboard"):
        raise HTTPException(403, "Dashboard ruxsati yo‘q")

    allowed_ids = visible_chat_ids(user)
    with db() as c:
        if allowed_ids is None:
            groups = c.execute("SELECT COUNT(*) n FROM groups_data").fetchone()["n"]
            messages = c.execute("SELECT COUNT(*) n FROM bridge_events WHERE event_type='message'").fetchone()["n"]
            events = c.execute("SELECT COUNT(*) n FROM bridge_events").fetchone()["n"]
            recent = c.execute("SELECT event_type,chat_id,payload,created_at FROM bridge_events ORDER BY created_at DESC LIMIT 15").fetchall()
        elif not allowed_ids:
            groups = messages = events = 0
            recent = []
        else:
            marks = ",".join("?" for _ in allowed_ids)
            groups = len(allowed_ids)
            messages = c.execute(f"SELECT COUNT(*) n FROM bridge_events WHERE event_type='message' AND chat_id IN ({marks})", allowed_ids).fetchone()["n"]
            events = c.execute(f"SELECT COUNT(*) n FROM bridge_events WHERE chat_id IN ({marks})", allowed_ids).fetchone()["n"]
            recent = c.execute(f"SELECT event_type,chat_id,payload,created_at FROM bridge_events WHERE chat_id IN ({marks}) ORDER BY created_at DESC LIMIT 15", allowed_ids).fetchall()

    rows = ""
    for e in recent:
        rows += (
            "<tr><td>" + str(e["event_type"]) +
            "</td><td>" + str(e["chat_id"]) +
            "</td><td>" + datetime.fromtimestamp(
                e["created_at"], timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S UTC") +
            "</td></tr>"
        )

    return page("Dashboard", f"""
    <div class="card">
      <h1>Dashboard</h1>
      <p>Salom, {user['username']} ({user['role']})</p>
      <a class="btn" href="/groups">GURUHLAR</a>
      <a class="btn secondary" href="/events">HODISALAR</a>
      <a class="btn secondary" href="/admins">ADMINLAR</a>
      <a class="btn secondary" href="/audit">AUDIT</a>
      <form method="post" action="/api/auth/logout">
        <button class="btn secondary">CHIQISH</button>
      </form>
    </div>
    <div class="grid">
      <div class="card"><p>Ulangan guruhlar</p><div class="number">{groups}</div></div>
      <div class="card"><p>Xabar hodisalari</p><div class="number">{messages}</div></div>
      <div class="card"><p>Jami hodisalar</p><div class="number">{events}</div></div>
    </div>
    <div class="card">
      <h2>Oxirgi hodisalar</h2>
      <table><tr><th>Turi</th><th>Guruh ID</th><th>Vaqt</th></tr>{rows}</table>
    </div>
    """)


# =========================================================
# GROUPS
# =========================================================

@app.get("/groups", response_class=HTMLResponse)
async def groups_page(request: Request):
    user = require_login(request)

    if not can(user, "groups"):
        raise HTTPException(403, "Guruhlar ruxsati yo‘q")

    allowed_ids = visible_chat_ids(user)
    with db() as c:
        if allowed_ids is None:
            groups = c.execute("SELECT * FROM groups_data ORDER BY updated_at DESC").fetchall()
        elif allowed_ids:
            marks = ",".join("?" for _ in allowed_ids)
            groups = c.execute(f"SELECT * FROM groups_data WHERE chat_id IN ({marks}) ORDER BY updated_at DESC", allowed_ids).fetchall()
        else:
            groups = []

    rows = ""
    for g in groups:
        rows += (
            f"<tr><td>{g['title']}</td>"
            f"<td>{g['chat_id']}</td>"
            f"<td>{g['members']}</td>"
            f"<td><a href='/group/{g['chat_id']}'>KO‘RISH</a></td></tr>"
        )

    return page("Guruhlar", f"""
    <div class="card">
      <h1>GURUHLAR</h1>
      <a class="btn secondary" href="/dashboard">ORTGA</a>
      <table><tr><th>Nomi</th><th>ID</th><th>A’zolar</th><th></th></tr>{rows}</table>
      <p class="muted">Faqat bot yuborgan va bazaga yozilgan guruhlar ko‘rsatiladi.</p>
    </div>
    """)


@app.get("/group/{chat_id}", response_class=HTMLResponse)
async def group_detail(chat_id: str, request: Request):
    user = require_login(request)

    if not can(user, "groups"):
        raise HTTPException(403, "Ruxsat yo‘q")

    require_group_access(user, chat_id)
    with db() as c:
        group = c.execute(
            "SELECT * FROM groups_data WHERE chat_id=?",
            (chat_id,)
        ).fetchone()

        events = c.execute(
            "SELECT event_type,payload,created_at FROM bridge_events "
            "WHERE chat_id=? ORDER BY created_at DESC LIMIT 100",
            (chat_id,)
        ).fetchall()

    if not group:
        raise HTTPException(404, "Guruh topilmadi")

    rows = ""
    for e in events:
        rows += (
            f"<tr><td>{e['event_type']}</td>"
            f"<td><pre>{str(e['payload'])[:1500]}</pre></td>"
            f"<td>{e['created_at']}</td></tr>"
        )

    return page("Guruh", f"""
    <div class="card">
      <h1>{group['title']}</h1>
      <p>Guruh ID: {chat_id}</p>
      <p>A’zolar: {group['members']}</p>
      <h2>Guruh hodisalari</h2>
      <table><tr><th>Turi</th><th>Ma’lumot</th><th>Vaqt</th></tr>{rows}</table>
      <a class="btn secondary" href="/groups">ORTGA</a>
    </div>
    """)


# =========================================================
# EVENTS
# =========================================================

@app.get("/events", response_class=HTMLResponse)
async def events_page(request: Request):
    user = require_login(request)

    if not can(user, "events"):
        raise HTTPException(403, "Hodisalar ruxsati yo‘q")

    allowed_ids = visible_chat_ids(user)
    with db() as c:
        if allowed_ids is None:
            events = c.execute("SELECT * FROM bridge_events ORDER BY created_at DESC LIMIT 200").fetchall()
        elif allowed_ids:
            marks = ",".join("?" for _ in allowed_ids)
            events = c.execute(f"SELECT * FROM bridge_events WHERE chat_id IN ({marks}) ORDER BY created_at DESC LIMIT 200", allowed_ids).fetchall()
        else:
            events = []

    rows = ""
    for e in events:
        rows += (
            f"<tr><td>{e['event_type']}</td>"
            f"<td>{e['chat_id']}</td>"
            f"<td><pre>{str(e['payload'])[:1000]}</pre></td>"
            f"<td>{e['created_at']}</td></tr>"
        )

    return page("Hodisalar", f"""
    <div class="card">
      <h1>HODISALAR TARIXI</h1>
      <a class="btn secondary" href="/dashboard">ORTGA</a>
      <table><tr><th>Turi</th><th>Guruh</th><th>Ma’lumot</th><th>Vaqt</th></tr>{rows}</table>
    </div>
    """)


# =========================================================
# OWNER: ADMIN MANAGEMENT
# =========================================================

@app.get("/admins", response_class=HTMLResponse)
async def admins_page(request: Request):
    owner = require_owner(request)

    with db() as c:
        admins = c.execute(
            "SELECT id,username,role,active,created_at,telegram_id FROM admins ORDER BY id"
        ).fetchall()

    rows = ""
    for a in admins:
        rows += (
            f"<tr><td>{a['username']}</td><td>{a['role']}</td>"
            f"<td>{'Faol' if a['active'] else 'O‘chirilgan'}</td>"
            f"<td>{a['id']}</td><td>{a['telegram_id'] or '—'}</td></tr>"
        )

    return page("Adminlar", f"""
    <div class="card">
      <h1>ADMINLARNI BOSHQARISH</h1>
      <a class="btn secondary" href="/dashboard">ORTGA</a>
      <form method="post" action="/api/admins/create">
        <label>Yangi admin login</label>
        <input name="username" required maxlength="40" pattern="[A-Za-z0-9_.-]+">
        <label>Telegram ID (ixtiyoriy, guruhlarni bog‘lash uchun)</label>
        <input name="telegram_id" inputmode="numeric" pattern="[0-9]{5,20}">
        <label>Yangi admin parol</label>
        <input name="password" type="password" required minlength="10" maxlength="200">
        <button class="btn">ADMIN QO‘SHISH</button>
      </form>
      <table><tr><th>Login</th><th>Rol</th><th>Holat</th><th>ID</th><th>Telegram ID</th></tr>{rows}</table>
    </div>
    """)


@app.post("/api/admins/create")
async def create_admin(request: Request):
    owner = require_owner(request)
    form = await request.form()

    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    telegram_id = str(form.get("telegram_id", "")).strip() or None
    if telegram_id and not telegram_id.isdigit():
        raise HTTPException(400, "Telegram ID faqat raqam bo‘lishi kerak")

    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", username):
        raise HTTPException(400, "Login formati noto‘g‘ri")

    if len(password) < 10:
        raise HTTPException(400, "Parol kamida 10 belgidan iborat bo‘lsin")

    with db() as c:
        c.execute(
            "INSERT INTO admins(username,password_hash,role,active,permissions,created_at,telegram_id) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                username,
                pwd.hash(password),
                "admin",
                1,
                json.dumps({"dashboard": True, "groups": True, "events": True}),
                now(),
                telegram_id
            )
        )

    audit(owner["username"], "ADMIN_CREATE", username)
    return RedirectResponse("/admins", status_code=303)


# =========================================================
# OWNER: AUDIT LOG
# =========================================================

@app.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request):
    owner = require_owner(request)

    with db() as c:
        logs = c.execute(
            "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 200"
        ).fetchall()

    rows = ""
    for x in logs:
        rows += (
            f"<tr><td>{x['actor']}</td><td>{x['action']}</td>"
            f"<td>{x['details']}</td><td>{x['created_at']}</td></tr>"
        )

    return page("Audit", f"""
    <div class="card">
      <h1>AUDIT LOG</h1>
      <a class="btn secondary" href="/dashboard">ORTGA</a>
      <table><tr><th>Kim</th><th>Amal</th><th>Ma’lumot</th><th>Vaqt</th></tr>{rows}</table>
    </div>
    """)


# =========================================================
# TELEGRAM BOT BRIDGE
# =========================================================

@app.post("/bridge/event")
async def receive_bridge_event(request: Request):
    supplied = request.headers.get("x-bridge-secret", "")

    if not BRIDGE_SECRET or not hmac.compare_digest(supplied, BRIDGE_SECRET):
        raise HTTPException(403, "Bridge ruxsati yo‘q")

    raw = await request.body()

    if len(raw) > 32000:
        raise HTTPException(413, "Event juda katta")

    try:
        payload = json.loads(raw)
    except Exception:
        raise HTTPException(400, "JSON noto‘g‘ri")

    if not isinstance(payload, dict):
        raise HTTPException(400, "Event formati noto‘g‘ri")

    event_type = payload.get("type")

    if event_type not in {"access", "group", "message", "member", "group_access", "security", "application", "audit"}:
        raise HTTPException(400, "Event turi noto‘g‘ri")

    chat_id = str(
        payload.get("chat_id")
        or payload.get("group_id")
        or ""
    )[:100]

    event_id = str(
        payload.get("event_id")
        or hashlib.sha256(raw).hexdigest()
    )[:200]

    created = now()

    with db() as c:
        c.execute(
            "INSERT OR IGNORE INTO bridge_events "
            "(event_id,event_type,chat_id,payload,created_at) "
            "VALUES(?,?,?,?,?)",
            (
                event_id,
                event_type,
                chat_id,
                json.dumps(payload, ensure_ascii=False),
                created
            )
        )

        if event_type == "group_access":
            telegram_id = str(payload.get("user_id") or "")
            role = str(payload.get("role") or "member")[:30]
            if telegram_id.isdigit() and chat_id:
                c.execute("INSERT INTO group_access(telegram_id,chat_id,role,updated_at) VALUES(?,?,?,?) ON CONFLICT(telegram_id,chat_id) DO UPDATE SET role=excluded.role,updated_at=excluded.updated_at",
                          (telegram_id, chat_id, role, created))

        if event_type == "member" and chat_id:
            kind = str(payload.get("kind") or "")
            delta = 1 if kind == "join" else (-1 if kind == "leave" else 0)
            if delta:
                c.execute("UPDATE groups_data SET members=MAX(0,members+?),updated_at=? WHERE chat_id=?",
                          (delta, created, chat_id))

        if event_type == "group":
            title = str(
                payload.get("title")
                or payload.get("name")
                or "Nomsiz guruh"
            )[:250]

            members = int(payload.get("members") or payload.get("member_count") or 0)
            members = max(0, min(members, 100000000))

            c.execute(
                "INSERT INTO groups_data(chat_id,title,members,last_seen,updated_at) "
                "VALUES(?,?,?,?,?) "
                "ON CONFLICT(chat_id) DO UPDATE SET "
                "title=excluded.title,members=excluded.members,"
                "last_seen=excluded.last_seen,updated_at=excluded.updated_at",
                (chat_id, title, members, created, created)
            )

    return {"ok": True}


# =========================================================
# HEALTH
# =========================================================

@app.get("/health")
async def health():
    return {"ok": True, "service": "admins-helper-web"}




# Standalone browser portal (not a Telegram Mini App)
from portal_api import install as _install_portal
_install_portal(app, db, pwd, audit, now, require_login, require_owner, visible_chat_ids, require_group_access)
