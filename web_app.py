
import os
import re
import json
import time
import hmac
import hashlib
import secrets
import sqlite3
import html
import urllib.parse
import urllib.request
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
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "") or os.getenv("BOT_TOKEN", "")
TELEGRAM_BOT_USERNAME = os.getenv("TELEGRAM_BOT_USERNAME", "").lstrip("@")

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

class PostgresCompat:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, query, params=()):
        if re.search(r"INSERT\s+OR\s+IGNORE", query, flags=re.I):
            query = re.sub(r"INSERT\s+OR\s+IGNORE", "INSERT", query, flags=re.I)
            query += " ON CONFLICT DO NOTHING"
        query = re.sub(
            r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT",
            "BIGSERIAL PRIMARY KEY", query, flags=re.I
        )
        query = query.replace("?", "%s")
        return self.connection.execute(query, params)

    def executescript(self, script):
        for statement in script.split(";"):
            if statement.strip():
                self.execute(statement)

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()

    def close(self):
        self.connection.close()


@contextmanager
def db():
    if DATABASE_URL:
        import psycopg
        from psycopg.rows import dict_row
        dsn = DATABASE_URL.replace("postgres://", "postgresql://", 1)
        raw = psycopg.connect(dsn, connect_timeout=10, row_factory=dict_row)
        conn = PostgresCompat(raw)
    else:
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
            created_at INTEGER NOT NULL
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

        CREATE TABLE IF NOT EXISTS telegram_users (
            telegram_id BIGINT PRIMARY KEY,
            username TEXT NOT NULL DEFAULT '',
            first_name TEXT NOT NULL DEFAULT '',
            photo_url TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS group_access (
            telegram_id BIGINT NOT NULL,
            chat_id TEXT NOT NULL,
            verified_at INTEGER NOT NULL,
            PRIMARY KEY (telegram_id, chat_id)
        );

        CREATE TABLE IF NOT EXISTS group_protection (
            chat_id TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS trusted_group_admins (
            chat_id TEXT NOT NULL,
            telegram_id BIGINT NOT NULL,
            added_by BIGINT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (chat_id, telegram_id)
        );
        """)

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
    if uid:
        with db() as c:
            user = c.execute(
                "SELECT * FROM admins WHERE id=? AND active=1",
                (uid,)
            ).fetchone()
        if user:
            return dict(user)

    telegram_id = request.session.get("tg_uid")
    if telegram_id:
        with db() as c:
            user = c.execute(
                "SELECT telegram_id,username,first_name,photo_url,active "
                "FROM telegram_users WHERE telegram_id=? AND active=1",
                (telegram_id,)
            ).fetchone()
        if user:
            result = dict(user)
            result.update({
                "id": result["telegram_id"],
                "role": "telegram_admin",
                "permissions": '{"dashboard":true,"groups":true,"events":true}',
            })
            return result
    return None


def require_login(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(401, "Login talab qilinadi")
    return user


def require_owner(request: Request):
    user = require_login(request)
    if user["role"] != "owner":
        raise HTTPException(403, "Faqat Owner uchun")
    return user


def can(user, permission):
    if user["role"] in {"owner", "telegram_admin"}:
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
        <nav>
          <a href="/">BOSH SAHIFA</a>
          &nbsp; | &nbsp;
          <a href="/admin-login">ADMIN PANEL</a>
          &nbsp; | &nbsp;
          <a href="/admin-login">AKKAUNT ULASH</a>
        </nav>
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
      <a class="btn" href="/admin-login">ADMIN PANEL →</a>
      <a class="btn secondary" href="/admin-login">AKKAUNT ULASH</a>
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
    telegram_login = ""
    if TELEGRAM_BOT_USERNAME and TELEGRAM_BOT_TOKEN:
        telegram_login = """
        <div class="card">
          <h2>Telegram akkauntini ulash</h2>
          <p>Telegram orqali shaxsingiz tasdiqlanadi. Shaxsiy akkaunt sessiyasi yoki maxfiy kodi saqlanmaydi.</p>
          <script async src="https://telegram.org/js/telegram-widget.js?22"
            data-telegram-login="__BOT_USERNAME__"
            data-size="large" data-userpic="false"
            data-onauth="onTelegramAuth(user)" data-request-access="write"></script>
        </div>
        <script>
        async function onTelegramAuth(user) {
          const response = await fetch("/api/auth/telegram", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(user)
          });
          const result = await response.json();
          if (response.ok && result.ok) location.href = "/dashboard";
          else alert(result.detail || "Telegram tasdiqlash amalga oshmadi");
        }
        </script>
        """.replace("__BOT_USERNAME__", html.escape(TELEGRAM_BOT_USERNAME))
    else:
        telegram_login = '<p class="muted">Telegram orqali kirish uchun serverda TELEGRAM_BOT_USERNAME va TELEGRAM_BOT_TOKEN sozlanishi kerak.</p>'
    return page("Admin login", f"""
    <div class="card" style="max-width:520px;margin:auto">
      <h1>ADMIN PANEL</h1>
      <p>Owner hisobi yoki Telegram akkauntingiz orqali kiring.</p>
      <form method="post" action="/api/auth/login">
        <label>Owner login</label>
        <input name="username" required maxlength="64">
        <label>Parol</label>
        <input name="password" type="password" required maxlength="200">
        <button class="btn" type="submit">TIZIMGA KIRISH →</button>
      </form>
    </div>
    {telegram_login}
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

        valid = bool(
            user
            and user["role"] == "owner"
            and pwd.verify(password, user["password_hash"])
        )

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


@app.post("/api/auth/telegram")
async def telegram_login(request: Request):
    if not TELEGRAM_BOT_TOKEN:
        raise HTTPException(503, "Telegram login sozlanmagan")
    try:
        data = await request.json()
        if not isinstance(data, dict):
            raise ValueError("bad payload")
        supplied_hash = str(data.get("hash", ""))
        auth_date = int(data.get("auth_date", 0))
        telegram_id = int(data.get("id", 0))
    except Exception:
        raise HTTPException(400, "Telegram ma’lumoti noto‘g‘ri")

    if not supplied_hash or telegram_id <= 0 or auth_date > now() + 60 or now() - auth_date > 86400:
        raise HTTPException(401, "Telegram tasdiqlash muddati tugagan")

    check_data = {str(k): str(v) for k, v in data.items() if k != "hash"}
    check_string = "\n".join(f"{k}={check_data[k]}" for k in sorted(check_data))
    secret_key = hashlib.sha256(TELEGRAM_BOT_TOKEN.encode()).digest()
    expected_hash = hmac.new(secret_key, check_string.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_hash, supplied_hash):
        raise HTTPException(401, "Telegram imzosi noto‘g‘ri")

    username = str(data.get("username", ""))[:64]
    first_name = str(data.get("first_name", ""))[:128]
    photo_url = str(data.get("photo_url", ""))[:1000]
    with db() as c:
        c.execute(
            "INSERT INTO telegram_users(telegram_id,username,first_name,photo_url,active,created_at,updated_at) "
            "VALUES(?,?,?,?,1,?,?) ON CONFLICT(telegram_id) DO UPDATE SET "
            "username=excluded.username,first_name=excluded.first_name,photo_url=excluded.photo_url,"
            "active=1,updated_at=excluded.updated_at",
            (telegram_id, username, first_name, photo_url, now(), now())
        )
    request.session.clear()
    request.session["tg_uid"] = telegram_id
    audit(f"telegram:{telegram_id}", "TELEGRAM_LOGIN", username)
    return {"ok": True}


def telegram_api(method, params=None):
    if not TELEGRAM_BOT_TOKEN:
        raise HTTPException(503, "Telegram bot token sozlanmagan")
    url = "https://api.telegram.org/bot" + TELEGRAM_BOT_TOKEN + "/" + method
    body = urllib.parse.urlencode(params or {}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=body), timeout=8) as response:
            result = json.loads(response.read(1024 * 1024))
    except Exception:
        raise HTTPException(502, "Telegram API bilan bog‘lanib bo‘lmadi")
    if not result.get("ok"):
        raise HTTPException(400, "Telegram guruhni tekshira olmadi")
    return result.get("result")


def refresh_telegram_group_access(user):
    if user.get("role") != "telegram_admin":
        return
    with db() as c:
        linked = c.execute(
            "SELECT chat_id,verified_at FROM group_access WHERE telegram_id=?",
            (user["telegram_id"],)
        ).fetchall()
    for item in linked:
        if now() - int(item["verified_at"]) < 300:
            continue
        chat_id = str(item["chat_id"])
        try:
            member = telegram_api(
                "getChatMember",
                {"chat_id": chat_id, "user_id": user["telegram_id"]}
            )
            bot = telegram_api("getMe")
            bot_member = telegram_api(
                "getChatMember", {"chat_id": chat_id, "user_id": bot["id"]}
            )
        except HTTPException:
            # Telegram vaqtincha javob bermasa, mavjud ruxsatni avtomatik o‘chirmaymiz.
            continue
        still_admin = member.get("status") in {"creator", "administrator"}
        bot_is_admin = bot_member.get("status") in {"creator", "administrator"}
        with db() as c:
            if not still_admin or not bot_is_admin:
                c.execute(
                    "DELETE FROM group_access WHERE telegram_id=? AND chat_id=?",
                    (user["telegram_id"], chat_id)
                )
            else:
                c.execute(
                    "UPDATE group_access SET verified_at=? WHERE telegram_id=? AND chat_id=?",
                    (now(), user["telegram_id"], chat_id)
                )


@app.post("/api/telegram/groups/link")
async def link_telegram_group(request: Request):
    user = require_login(request)
    if user.get("role") != "telegram_admin":
        raise HTTPException(403, "Guruh ulash uchun Telegram orqali kiring")
    form = await request.form()
    chat_id = str(form.get("chat_id", "")).strip()
    if not re.fullmatch(r"-?\d{5,20}", chat_id):
        raise HTTPException(400, "Guruh ID noto‘g‘ri")
    member = telegram_api("getChatMember", {"chat_id": chat_id, "user_id": user["telegram_id"]})
    if member.get("status") not in {"creator", "administrator"}:
        raise HTTPException(403, "Bu guruhda Telegram administratori ekaningiz tasdiqlanmadi")
    chat = telegram_api("getChat", {"chat_id": chat_id})
    bot = telegram_api("getMe")
    bot_member = telegram_api("getChatMember", {"chat_id": chat_id, "user_id": bot["id"]})
    if bot_member.get("status") not in {"administrator", "creator"}:
        raise HTTPException(403, "Avval botni shu guruhga administrator qiling")
    try:
        count = int(telegram_api("getChatMemberCount", {"chat_id": chat_id}))
    except Exception:
        count = 0
    with db() as c:
        c.execute(
            "INSERT INTO groups_data(chat_id,title,members,last_seen,updated_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(chat_id) DO UPDATE SET title=excluded.title,members=excluded.members,updated_at=excluded.updated_at",
            (chat_id, str(chat.get("title") or chat.get("username") or chat_id)[:250], count, now(), now())
        )
        c.execute(
            "INSERT INTO group_access(telegram_id,chat_id,verified_at) VALUES(?,?,?) "
            "ON CONFLICT(telegram_id,chat_id) DO UPDATE SET verified_at=excluded.verified_at",
            (user["telegram_id"], chat_id, now())
        )
        c.execute(
            "INSERT INTO trusted_group_admins(chat_id,telegram_id,added_by,created_at) "
            "VALUES(?,?,?,?) ON CONFLICT(chat_id,telegram_id) DO NOTHING",
            (chat_id, user["telegram_id"], user["telegram_id"], now())
        )
        c.execute(
            "INSERT INTO group_protection(chat_id,enabled,updated_at) VALUES(?,0,?) "
            "ON CONFLICT(chat_id) DO NOTHING",
            (chat_id, now())
        )
    audit(f"telegram:{user['telegram_id']}", "GROUP_ACCESS_GRANTED", chat_id)
    return RedirectResponse("/dashboard", status_code=303)


@app.post("/api/telegram/groups/unlink")
async def unlink_telegram_group(request: Request):
    user = require_login(request)
    if user.get("role") != "telegram_admin":
        raise HTTPException(403, "Telegram hisob talab qilinadi")
    form = await request.form()
    chat_id = str(form.get("chat_id", "")).strip()
    with db() as c:
        c.execute("DELETE FROM group_access WHERE telegram_id=? AND chat_id=?", (user["telegram_id"], chat_id))
    audit(f"telegram:{user['telegram_id']}", "GROUP_ACCESS_REVOKED", chat_id)
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
    refresh_telegram_group_access(user)

    if not can(user, "dashboard"):
        raise HTTPException(403, "Dashboard ruxsati yo‘q")

    owner_view = user["role"] == "owner"
    scope = "" if owner_view else " WHERE chat_id IN (SELECT chat_id FROM group_access WHERE telegram_id=?)"
    params = () if owner_view else (user["telegram_id"],)
    with db() as c:
        groups = c.execute(
            "SELECT COUNT(*) n FROM groups_data" + scope, params
        ).fetchone()["n"]
        messages = c.execute(
            "SELECT COUNT(*) n FROM bridge_events WHERE event_type='message'" +
            ("" if owner_view else " AND chat_id IN (SELECT chat_id FROM group_access WHERE telegram_id=?)"),
            params
        ).fetchone()["n"]
        events = c.execute(
            "SELECT COUNT(*) n FROM bridge_events" + scope, params
        ).fetchone()["n"]
        recent = c.execute(
            "SELECT event_type,chat_id,payload,created_at FROM bridge_events" +
            scope + " ORDER BY created_at DESC LIMIT 15", params
        ).fetchall()

    rows = ""
    for e in recent:
        rows += (
            "<tr><td>" + html.escape(str(e["event_type"])) +
            "</td><td>" + html.escape(str(e["chat_id"])) +
            "</td><td>" + datetime.fromtimestamp(
                e["created_at"], timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S UTC") +
            "</td></tr>"
        )

    owner_links = '<a class="btn secondary" href="/admins">ADMINLAR</a><a class="btn secondary" href="/audit">AUDIT</a>' if owner_view else ''
    account_box = ""
    if user["role"] == "telegram_admin":
        account_box = f"""
        <div class="card">
          <h2>AKKAUNT ULASH</h2>
          <p>Telegram: @{html.escape(user.get('username') or str(user['telegram_id']))}</p>
          <form method="post" action="/api/telegram/groups/link">
            <label>Admin bo‘lgan guruhingiz ID raqami</label>
            <input name="chat_id" required placeholder="-1001234567890">
            <button class="btn">GURUHNI TEKSHIRIB ULASH</button>
          </form>
          <p class="muted">Faqat Telegram API orqali adminligingiz tekshirilgan va bot administrator bo‘lgan guruhlar ulanadi.</p>
        </div>
        """
    return page("Dashboard", f"""
    <div class="card">
      <h1>Dashboard</h1>
      <p>Salom, {html.escape(str(user.get('username') or user.get('first_name') or user['role']))} ({user['role']})</p>
      <a class="btn" href="/groups">GURUHLAR</a>
      <a class="btn secondary" href="/events">HODISALAR</a>
      {owner_links}
      <form method="post" action="/api/auth/logout">
        <button class="btn secondary">CHIQISH</button>
      </form>
    </div>
    {account_box}
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
    refresh_telegram_group_access(user)

    if not can(user, "groups"):
        raise HTTPException(403, "Guruhlar ruxsati yo‘q")

    if user["role"] == "owner":
        query = "SELECT * FROM groups_data ORDER BY updated_at DESC"
        params = ()
    else:
        query = ("SELECT g.* FROM groups_data g JOIN group_access a ON a.chat_id=g.chat_id "
                 "WHERE a.telegram_id=? ORDER BY g.updated_at DESC")
        params = (user["telegram_id"],)
    with db() as c:
        groups = c.execute(query, params).fetchall()

    rows = ""
    for g in groups:
        rows += (
            f"<tr><td>{html.escape(str(g['title']))}</td>"
            f"<td>{html.escape(str(g['chat_id']))}</td>"
            f"<td>{g['members']}</td>"
            f"<td><a href='/group/{g['chat_id']}'>KO‘RISH</a> | "
          f"<a href='/group/{g['chat_id']}/protection'>HIMOYA</a></td></tr>"
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
    refresh_telegram_group_access(user)

    if not can(user, "groups"):
        raise HTTPException(403, "Ruxsat yo‘q")

    with db() as c:
        if user["role"] == "owner":
            group = c.execute("SELECT * FROM groups_data WHERE chat_id=?", (chat_id,)).fetchone()
        else:
            group = c.execute(
                "SELECT g.* FROM groups_data g JOIN group_access a ON a.chat_id=g.chat_id "
                "WHERE g.chat_id=? AND a.telegram_id=?",
                (chat_id, user["telegram_id"])
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
            f"<tr><td>{html.escape(str(e['event_type']))}</td>"
            f"<td><pre>{html.escape(str(e['payload'])[:1500])}</pre></td>"
            f"<td>{e['created_at']}</td></tr>"
        )

    return page("Guruh", f"""
    <div class="card">
      <h1>{html.escape(str(group['title']))}</h1>
      <p>Guruh ID: {html.escape(str(chat_id))}</p>
      <p>A’zolar: {group['members']}</p>
      <h2>Guruh hodisalari</h2>
      <table><tr><th>Turi</th><th>Ma’lumot</th><th>Vaqt</th></tr>{rows}</table>
      <a class="btn secondary" href="/groups">ORTGA</a>
    </div>
    """)


@app.get("/group/{chat_id}/protection", response_class=HTMLResponse)
async def group_protection_page(chat_id: str, request: Request):
    user = require_login(request)
    refresh_telegram_group_access(user)
    with db() as c:
        if user["role"] == "owner":
            group = c.execute("SELECT * FROM groups_data WHERE chat_id=?", (chat_id,)).fetchone()
        else:
            group = c.execute(
                "SELECT g.* FROM groups_data g JOIN group_access a ON a.chat_id=g.chat_id "
                "WHERE g.chat_id=? AND a.telegram_id=?",
                (chat_id, user["telegram_id"])
            ).fetchone()
        state = c.execute(
            "SELECT enabled FROM group_protection WHERE chat_id=?", (chat_id,)
        ).fetchone()
        trusted = c.execute(
            "SELECT telegram_id,created_at FROM trusted_group_admins WHERE chat_id=? ORDER BY telegram_id",
            (chat_id,)
        ).fetchall()
    if not group:
        raise HTTPException(404, "Guruh topilmadi")
    enabled = bool(state and state["enabled"])
    rows = "".join(
        f"<tr><td>{html.escape(str(item['telegram_id']))}</td>"
        f"<td>{item['created_at']}</td><td>"
        f"<form method='post' action='/api/group-protection/trusted/remove'>"
        f"<input type='hidden' name='chat_id' value='{html.escape(chat_id)}'>"
        f"<input type='hidden' name='telegram_id' value='{item['telegram_id']}'>"
        f"<button class='btn secondary'>O‘CHIRISH</button></form></td></tr>"
        for item in trusted
    )
    status = "YOQILGAN" if enabled else "O‘CHIRILGAN"
    return page("Soxta admin himoyasi", f"""
    <div class="card">
      <h1>SOXTA ADMIN HIMOYASI</h1>
      <p>Guruh: {html.escape(str(group['title']))}</p>
      <p>Holat: <b>{status}</b></p>
      <p>Himoya yoqilganda bot tasdiqlangan shubhali admin hodisasini yuboradi. Faqat Telegram’da haqiqiy administrator bo‘lgan, lekin ishonchli ro‘yxatda yo‘q akkauntning admin huquqi bekor qilinadi. Ban berilmaydi.</p>
      <form method="post" action="/api/group-protection/toggle">
        <input type="hidden" name="chat_id" value="{html.escape(chat_id)}">
        <input type="hidden" name="enabled" value="{0 if enabled else 1}">
        <button class="btn">{'HIMOYANI O‘CHIRISH' if enabled else 'HIMOYANI YOQISH'}</button>
      </form>
      <h2>Ishonchli adminlar</h2>
      <form method="post" action="/api/group-protection/trusted/add">
        <input type="hidden" name="chat_id" value="{html.escape(chat_id)}">
        <label>Telegram user ID</label>
        <input name="telegram_id" required inputmode="numeric" pattern="[0-9]{5,15}">
        <button class="btn secondary">ISHONCHLI ADMIN QO‘SHISH</button>
      </form>
      <table><tr><th>Telegram ID</th><th>Qo‘shilgan vaqt</th><th></th></tr>{rows}</table>
      <p class="muted">Himoyani yoqishdan oldin guruhdagi barcha haqiqiy adminlarni ishonchli ro‘yxatga kiriting. Botda “Boshqa adminlarni tayinlash” huquqi bo‘lishi kerak.</p>
      <a class="btn secondary" href="/group/{html.escape(chat_id)}">GURUHGA QAYTISH</a>
    </div>
    """)


def ensure_group_manager(user, chat_id):
    if user["role"] == "owner":
        return
    with db() as c:
        row = c.execute(
            "SELECT 1 FROM group_access WHERE telegram_id=? AND chat_id=?",
            (user["telegram_id"], chat_id)
        ).fetchone()
    if not row:
        raise HTTPException(403, "Bu guruhni boshqarish ruxsati yo‘q")


@app.post("/api/group-protection/trusted/remove")
async def remove_trusted_group_admin(request: Request):
    user = require_login(request)
    form = await request.form()
    chat_id = str(form.get("chat_id", "")).strip()
    raw_id = str(form.get("telegram_id", "")).strip()
    ensure_group_manager(user, chat_id)
    if not raw_id.isdigit():
        raise HTTPException(400, "Telegram ID noto‘g‘ri")
    telegram_id = int(raw_id)
    with db() as c:
        c.execute(
            "DELETE FROM trusted_group_admins WHERE chat_id=? AND telegram_id=?",
            (chat_id, telegram_id)
        )
        remaining = c.execute(
            "SELECT COUNT(*) n FROM trusted_group_admins WHERE chat_id=?",
            (chat_id,)
        ).fetchone()["n"]
        if remaining == 0:
            c.execute(
                "UPDATE group_protection SET enabled=0,updated_at=? WHERE chat_id=?",
                (now(), chat_id)
            )
    audit(str(user.get("username") or user.get("telegram_id") or "owner"),
          "TRUSTED_GROUP_ADMIN_REMOVE", f"{chat_id}:{telegram_id}")
    return RedirectResponse(f"/group/{chat_id}/protection", status_code=303)


@app.post("/api/group-protection/toggle")
async def toggle_group_protection(request: Request):
    user = require_login(request)
    form = await request.form()
    chat_id = str(form.get("chat_id", "")).strip()
    enabled = int(str(form.get("enabled", "0"))) == 1
    ensure_group_manager(user, chat_id)
    if enabled:
        with db() as c:
            count = c.execute(
                "SELECT COUNT(*) n FROM trusted_group_admins WHERE chat_id=?",
                (chat_id,)
            ).fetchone()["n"]
        if count < 1:
            raise HTTPException(400, "Avval ishonchli adminlarni kiriting")
    with db() as c:
        c.execute(
            "INSERT INTO group_protection(chat_id,enabled,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(chat_id) DO UPDATE SET enabled=excluded.enabled,updated_at=excluded.updated_at",
            (chat_id, int(enabled), now())
        )
    audit(str(user.get("username") or user.get("telegram_id") or "owner"),
          "GROUP_PROTECTION_TOGGLE", f"{chat_id}:{int(enabled)}")
    return RedirectResponse(f"/group/{chat_id}/protection", status_code=303)


@app.post("/api/group-protection/trusted/add")
async def add_trusted_group_admin(request: Request):
    user = require_login(request)
    form = await request.form()
    chat_id = str(form.get("chat_id", "")).strip()
    raw_id = str(form.get("telegram_id", "")).strip()
    ensure_group_manager(user, chat_id)
    if not re.fullmatch(r"[0-9]{5,15}", raw_id):
        raise HTTPException(400, "Telegram ID noto‘g‘ri")
    telegram_id = int(raw_id)
    member = telegram_api("getChatMember", {"chat_id": chat_id, "user_id": telegram_id})
    if member.get("status") not in {"creator", "administrator"}:
        raise HTTPException(400, "Bu foydalanuvchi hozir guruh administratori emas")
    actor_id = int(user.get("telegram_id") or 0)
    with db() as c:
        c.execute(
            "INSERT INTO trusted_group_admins(chat_id,telegram_id,added_by,created_at) "
            "VALUES(?,?,?,?) ON CONFLICT(chat_id,telegram_id) DO NOTHING",
            (chat_id, telegram_id, actor_id, now())
        )
    audit(str(user.get("username") or actor_id or "owner"),
          "TRUSTED_GROUP_ADMIN_ADD", f"{chat_id}:{telegram_id}")
    return RedirectResponse(f"/group/{chat_id}/protection", status_code=303)


# =========================================================
# EVENTS
# =========================================================

@app.get("/events", response_class=HTMLResponse)
async def events_page(request: Request):
    user = require_login(request)
    refresh_telegram_group_access(user)

    if not can(user, "events"):
        raise HTTPException(403, "Hodisalar ruxsati yo‘q")

    with db() as c:
        if user["role"] == "owner":
            events = c.execute(
                "SELECT * FROM bridge_events ORDER BY created_at DESC LIMIT 200"
            ).fetchall()
        else:
            events = c.execute(
                "SELECT * FROM bridge_events WHERE chat_id IN "
                "(SELECT chat_id FROM group_access WHERE telegram_id=?) "
                "ORDER BY created_at DESC LIMIT 200",
                (user["telegram_id"],)
            ).fetchall()

    rows = ""
    for e in events:
        rows += (
            f"<tr><td>{html.escape(str(e['event_type']))}</td>"
            f"<td>{html.escape(str(e['chat_id']))}</td>"
            f"<td><pre>{html.escape(str(e['payload'])[:1000])}</pre></td>"
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
            "SELECT id,username,role,active,created_at FROM admins ORDER BY id"
        ).fetchall()

    rows = ""
    for a in admins:
        rows += (
            f"<tr><td>{html.escape(str(a['username']))}</td><td>{a['role']}</td>"
            f"<td>{'Faol' if a['active'] else 'O‘chirilgan'}</td>"
            f"<td>{a['id']}</td></tr>"
        )

    return page("Adminlar", f"""
    <div class="card">
      <h1>ADMINLARNI BOSHQARISH</h1>
      <a class="btn secondary" href="/dashboard">ORTGA</a>
      <form method="post" action="/api/admins/create">
        <label>Yangi admin login</label>
        <input name="username" required maxlength="40" pattern="[A-Za-z0-9_.-]+">
        <label>Yangi admin parol</label>
        <input name="password" type="password" required minlength="10" maxlength="200">
        <button class="btn">ADMIN QO‘SHISH</button>
      </form>
      <table><tr><th>Login</th><th>Rol</th><th>Holat</th><th>ID</th></tr>{rows}</table>
    </div>
    """)


@app.post("/api/admins/create")
async def create_admin(request: Request):
    owner = require_owner(request)
    form = await request.form()

    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))

    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", username):
        raise HTTPException(400, "Login formati noto‘g‘ri")

    if len(password) < 10:
        raise HTTPException(400, "Parol kamida 10 belgidan iborat bo‘lsin")

    with db() as c:
        c.execute(
            "INSERT INTO admins(username,password_hash,role,active,permissions,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (
                username,
                pwd.hash(password),
                "admin",
                1,
                json.dumps({"dashboard": True, "groups": True, "events": True}),
                now()
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
            f"<tr><td>{html.escape(str(x['actor']))}</td><td>{html.escape(str(x['action']))}</td>"
            f"<td>{html.escape(str(x['details']))}</td><td>{x['created_at']}</td></tr>"
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

    if event_type not in {"access", "group", "message", "member", "admin_change", "security"}:
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

        if (event_type == "security"
                and payload.get("action") == "fake_admin_detected"
                and payload.get("confirmed") is True):
            chat_user_id = payload.get("user_id")
            try:
                target_id = int(chat_user_id)
            except (TypeError, ValueError):
                raise HTTPException(400, "Security event user_id noto‘g‘ri")
            with db() as c:
                protection = c.execute(
                    "SELECT enabled FROM group_protection WHERE chat_id=?",
                    (chat_id,)
                ).fetchone()
                trusted = c.execute(
                    "SELECT 1 FROM trusted_group_admins WHERE chat_id=? AND telegram_id=?",
                    (chat_id, target_id)
                ).fetchone()
            if protection and protection["enabled"] and not trusted:
                try:
                    target = telegram_api(
                        "getChatMember", {"chat_id": chat_id, "user_id": target_id}
                    )
                except HTTPException:
                    target = {"status": "unknown"}
                demoted = False
                if target.get("status") == "administrator":
                    try:
                        demoted = bool(telegram_api("promoteChatMember", {
                            "chat_id": chat_id,
                            "user_id": target_id,
                            "can_manage_chat": False,
                            "can_delete_messages": False,
                            "can_manage_video_chats": False,
                            "can_restrict_members": False,
                            "can_promote_members": False,
                            "can_change_info": False,
                            "can_invite_users": False,
                            "can_post_stories": False,
                            "can_edit_stories": False,
                            "can_delete_stories": False,
                            "can_pin_messages": False,
                            "can_manage_topics": False,
                            "can_post_messages": False,
                            "can_edit_messages": False,
                            "can_manage_direct_messages": False
                        }))
                    except HTTPException:
                        demoted = False
                warning = (
                    f"⚠️ SOXTA ADMIN HIMOYASI: Telegram ID {target_id} tekshirildi. "
                    + ("Admin huquqi bekor qilindi." if demoted else
                       "Admin huquqini avtomatik bekor qilib bo‘lmadi; guruh egalari tekshirsin.")
                    + " Ban berilmadi."
                )
                telegram_api("sendMessage", {"chat_id": chat_id, "text": warning})
                audit("bot-bridge", "FAKE_ADMIN_REVIEW", f"{chat_id}:{target_id}:demoted={demoted}")

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


