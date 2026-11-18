import json, os, re, time, html
from datetime import datetime, timezone
from pathlib import Path
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
import hmac

def install(app, db, pwd, audit, now, require_login, require_owner, visible_chat_ids, require_group_access):
    import sqlite3
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS web_blacklist(telegram_id TEXT PRIMARY KEY, reason TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL, created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS web_applications(id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id TEXT NOT NULL, actor TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', payload TEXT NOT NULL DEFAULT '{}', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS web_outgoing(id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id TEXT NOT NULL, sender TEXT NOT NULL, text TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued', created_at INTEGER NOT NULL, media_type TEXT NOT NULL DEFAULT '', media_name TEXT NOT NULL DEFAULT '', media_data BLOB, result TEXT NOT NULL DEFAULT '');
        CREATE INDEX IF NOT EXISTS web_events_chat_time ON bridge_events(chat_id,created_at);
        """)

    with db() as c:
        cols = {r['name'] for r in c.execute('PRAGMA table_info(web_outgoing)').fetchall()}
        for name, definition in (('media_type', "TEXT NOT NULL DEFAULT ''"), ('media_name', "TEXT NOT NULL DEFAULT ''"), ('media_data', 'BLOB'), ('result', "TEXT NOT NULL DEFAULT ''")):
            if name not in cols:
                c.execute(f'ALTER TABLE web_outgoing ADD COLUMN {name} {definition}')
    def stamp(ts):
        return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def visible(user):
        ids = visible_chat_ids(user)
        return ids

    @app.get("/portal", response_class=HTMLResponse)
    async def portal_home():
        p = Path(__file__).with_name("portal.html")
        if not p.exists():
            raise HTTPException(404, "Portal UI topilmadi")
        return HTMLResponse(p.read_text(encoding="utf-8"))

    @app.post("/api/v2/register")
    async def v2_register(request: Request):
        data = await request.json()
        username = str(data.get("username","")).strip()
        password = str(data.get("password",""))
        tid = str(data.get("telegram_id","")).strip() or None
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", username):
            raise HTTPException(400,"Login 3-40 belgi bo‘lsin")
        if len(password) < 10:
            raise HTTPException(400,"Parol kamida 10 belgidan iborat bo‘lsin")
        if tid and not tid.isdigit():
            raise HTTPException(400,"Telegram ID faqat raqam")
        with db() as c:
            if c.execute("SELECT 1 FROM admins WHERE username=?",(username,)).fetchone():
                raise HTTPException(409,"Bu login band")
            c.execute("INSERT INTO admins(username,password_hash,role,active,permissions,created_at,telegram_id) VALUES(?,?,?,?,?,?,?)",
                      (username,pwd.hash(password),"user",1,json.dumps({"dashboard":True,"groups":True,"events":True}),now(),tid))
            uid=c.execute("SELECT id FROM admins WHERE username=?",(username,)).fetchone()["id"]
        request.session.clear(); request.session["uid"]=uid
        audit(username,"REGISTER","Yangi web hisob yaratildi")
        return {"id":uid,"username":username,"role":"user"}

    @app.post("/api/v2/login")
    async def v2_login(request: Request):
        data=await request.json()
        username=str(data.get("username","")).strip()
        password=str(data.get("password",""))
        with db() as c:
            u=c.execute("SELECT * FROM admins WHERE username=?",(username,)).fetchone()
            if not u or not pwd.verify(password,u["password_hash"]):
                raise HTTPException(401,"Login yoki parol noto‘g‘ri")
            tid=str(u["telegram_id"] or "")
            blocked=bool(tid and c.execute("SELECT 1 FROM web_blacklist WHERE telegram_id=?",(tid,)).fetchone())
            if not u["active"] or blocked:
                return JSONResponse({"blocked":True,"detail":"ACCOUNT BLOCKED"},status_code=403)
        request.session.clear(); request.session["uid"]=u["id"]
        audit(username,"LOGIN","Portalga kirdi")
        return {"id":u["id"],"username":u["username"],"role":u["role"]}

    @app.get("/api/v2/me")
    async def v2_me(request: Request):
        u=require_login(request)
        tid=str(u.get("telegram_id") or "")
        with db() as c:
            blocked=bool(tid and c.execute("SELECT 1 FROM web_blacklist WHERE telegram_id=?",(tid,)).fetchone())
        if blocked: raise HTTPException(403,"ACCOUNT BLOCKED")
        return {"id":u["id"],"username":u["username"],"role":u["role"],"telegram_id":tid}

    @app.post("/api/v2/logout")
    async def v2_logout(request: Request):
        u=require_login(request); audit(u["username"],"LOGOUT","Portaldan chiqdi"); request.session.clear()
        return {"ok":True}

    @app.get("/api/v2/overview")
    async def v2_overview(request: Request):
        u=require_login(request); ids=visible(u)
        with db() as c:
            if ids is None:
                g=c.execute("SELECT COUNT(*) n FROM groups_data").fetchone()["n"]
                ev=c.execute("SELECT * FROM bridge_events ORDER BY created_at DESC LIMIT 20").fetchall()
                msg=c.execute("SELECT COUNT(*) n FROM bridge_events WHERE event_type='message'").fetchone()["n"]
                joins=c.execute("SELECT COUNT(*) n FROM bridge_events WHERE event_type='member' AND payload LIKE '%join%'").fetchone()["n"]
                leaves=c.execute("SELECT COUNT(*) n FROM bridge_events WHERE event_type='member' AND payload LIKE '%leave%'").fetchone()["n"]
            elif not ids: g=msg=joins=leaves=0; ev=[]
            else:
                marks=",".join("?" for _ in ids)
                g=len(ids); msg=c.execute(f"SELECT COUNT(*) n FROM bridge_events WHERE event_type='message' AND chat_id IN ({marks})",ids).fetchone()["n"]
                ev=c.execute(f"SELECT * FROM bridge_events WHERE chat_id IN ({marks}) ORDER BY created_at DESC LIMIT 20",ids).fetchall()
                joins=c.execute(f"SELECT COUNT(*) n FROM bridge_events WHERE event_type='member' AND chat_id IN ({marks}) AND payload LIKE '%join%'",ids).fetchone()["n"]
                leaves=c.execute(f"SELECT COUNT(*) n FROM bridge_events WHERE event_type='member' AND chat_id IN ({marks}) AND payload LIKE '%leave%'",ids).fetchone()["n"]
        recent=[]
        for x in ev:
            try: p=json.loads(x["payload"])
            except: p={}
            recent.append({"type":x["event_type"],"chat_id":x["chat_id"],"summary":str(p.get("text") or p.get("kind") or p.get("status") or p.get("title") or x["payload"])[:180],"time":stamp(x["created_at"])})
        return {"groups":g,"messages":msg,"events":len(ev),"joins":joins,"leaves":leaves,"recent":recent}

    @app.get("/api/v2/groups")
    async def v2_groups(request: Request):
        u=require_login(request); ids=visible(u)
        with db() as c:
            if ids is None: rows=c.execute("SELECT * FROM groups_data ORDER BY updated_at DESC").fetchall()
            elif ids:
                marks=",".join("?" for _ in ids); rows=c.execute(f"SELECT * FROM groups_data WHERE chat_id IN ({marks}) ORDER BY updated_at DESC",ids).fetchall()
            else: rows=[]
        return {"groups":[{"chat_id":r["chat_id"],"title":r["title"],"members":r["members"]} for r in rows]}

    @app.get("/api/v2/group/{chat_id}")
    async def v2_group(chat_id: str,request: Request):
        u=require_login(request); require_group_access(u,chat_id)
        with db() as c:
            g=c.execute("SELECT * FROM groups_data WHERE chat_id=?",(chat_id,)).fetchone()
            rows=c.execute("SELECT * FROM bridge_events WHERE chat_id=? ORDER BY created_at DESC LIMIT 200",(chat_id,)).fetchall()
        if not g: raise HTTPException(404,"Guruh topilmadi")
        ev=[]
        for r in rows:
            try:p=json.loads(r["payload"])
            except:p={}
            ev.append({"type":r["event_type"],"actor":p.get("sender") or p.get("user_id") or p.get("actor",""),"summary":str(p.get("text") or p.get("kind") or p.get("status") or p)[:400],"time":stamp(r["created_at"])})
        return {"group":{"chat_id":chat_id,"title":g["title"],"members":g["members"]},"events":ev}

    @app.get("/api/v2/events")
    async def v2_events(request: Request):
        u=require_login(request); ids=visible(u)
        with db() as c:
            if ids is None: rows=c.execute("SELECT * FROM bridge_events ORDER BY created_at DESC LIMIT 300").fetchall()
            elif ids:
                marks=",".join("?" for _ in ids); rows=c.execute(f"SELECT * FROM bridge_events WHERE chat_id IN ({marks}) ORDER BY created_at DESC LIMIT 300",ids).fetchall()
            else: rows=[]
        out=[]
        for r in rows:
            try:p=json.loads(r["payload"])
            except:p={}
            out.append({"type":r["event_type"],"chat_id":r["chat_id"],"actor":p.get("sender") or p.get("user_id") or p.get("actor",""),"summary":str(p.get("text") or p.get("reason") or p.get("status") or p.get("kind") or p)[:400],"time":stamp(r["created_at"])})
        return {"events":out}

    @app.get("/api/v2/applications")
    async def v2_applications(request: Request):
        u=require_login(request); ids=visible(u)
        with db() as c:
            if ids is None: rows=c.execute("SELECT * FROM web_applications ORDER BY created_at DESC LIMIT 300").fetchall()
            elif ids:
                marks=",".join("?" for _ in ids); rows=c.execute(f"SELECT * FROM web_applications WHERE chat_id IN ({marks}) ORDER BY created_at DESC LIMIT 300",ids).fetchall()
            else: rows=[]
        return {"items":[{"id":r["id"],"chat_id":r["chat_id"],"actor":r["actor"],"status":r["status"],"time":stamp(r["created_at"])} for r in rows]}

    @app.post("/api/v2/applications/{item_id}")
    async def v2_application_action(item_id:int,request:Request):
        u=require_login(request); data=await request.json(); status=data.get("status")
        if status not in ("accepted","rejected"): raise HTTPException(400,"Status noto‘g‘ri")
        with db() as c:
            row=c.execute("SELECT * FROM web_applications WHERE id=?",(item_id,)).fetchone()
            if not row: raise HTTPException(404,"Ariza topilmadi")
            require_group_access(u,row["chat_id"])
            c.execute("UPDATE web_applications SET status=?,updated_at=? WHERE id=?",(status,now(),item_id))
        audit(u["username"],"APPLICATION_"+status,str(item_id))
        return {"ok":True}

    @app.get("/api/v2/blacklist")
    async def v2_blacklist(request:Request):
        require_owner(request)
        with db() as c: rows=c.execute("SELECT * FROM web_blacklist ORDER BY created_at DESC").fetchall()
        return {"items":[{"telegram_id":r["telegram_id"],"reason":r["reason"],"time":stamp(r["created_at"])} for r in rows]}

    @app.post("/api/v2/blacklist")
    async def v2_block(request:Request):
        u=require_owner(request); d=await request.json(); tid=str(d.get("telegram_id","")).strip(); reason=str(d.get("reason",""))[:500]
        if not tid.isdigit(): raise HTTPException(400,"Telegram ID noto‘g‘ri")
        with db() as c:
            c.execute("INSERT INTO web_blacklist(telegram_id,reason,created_by,created_at) VALUES(?,?,?,?) ON CONFLICT(telegram_id) DO UPDATE SET reason=excluded.reason,created_by=excluded.created_by,created_at=excluded.created_at",(tid,reason,u["username"],now()))
            c.execute("UPDATE admins SET active=0 WHERE telegram_id=?",(tid,))
        audit(u["username"],"BLACKLIST_ADD",tid+" "+reason)
        return {"ok":True}

    @app.delete("/api/v2/blacklist/{telegram_id}")
    async def v2_unblock(telegram_id:str,request:Request):
        u=require_owner(request)
        with db() as c:
            c.execute("DELETE FROM web_blacklist WHERE telegram_id=?",(telegram_id,))
            c.execute("UPDATE admins SET active=1 WHERE telegram_id=? AND role!='owner'",(telegram_id,))
        audit(u["username"],"BLACKLIST_REMOVE",telegram_id)
        return {"ok":True}

    @app.get("/api/v2/admins")
    async def v2_admins(request:Request):
        require_owner(request)
        with db() as c: rows=c.execute("SELECT id,username,role,active,telegram_id FROM admins ORDER BY id").fetchall()
        return {"items":[dict(r) for r in rows]}

    @app.post("/api/v2/admins")
    async def v2_create_admin(request:Request):
        u=require_owner(request); d=await request.json(); name=str(d.get("username","")).strip(); pw=str(d.get("password","")); tid=str(d.get("telegram_id","")).strip() or None
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}",name) or len(pw)<10: raise HTTPException(400,"Login/parol talablari bajarilmadi")
        if tid and not tid.isdigit(): raise HTTPException(400,"Telegram ID noto‘g‘ri")
        with db() as c: c.execute("INSERT INTO admins(username,password_hash,role,active,permissions,created_at,telegram_id) VALUES(?,?,?,?,?,?,?)",(name,pwd.hash(pw),"admin",1,json.dumps({"dashboard":True,"groups":True,"events":True}),now(),tid))
        audit(u["username"],"ADMIN_CREATE",name); return {"ok":True}

    @app.patch("/api/v2/admins/{admin_id}")
    async def v2_toggle_admin(admin_id:int,request:Request):
        u=require_owner(request); d=await request.json(); active=1 if d.get("active") else 0
        with db() as c:
            row=c.execute("SELECT role,username FROM admins WHERE id=?",(admin_id,)).fetchone()
            if not row: raise HTTPException(404,"Admin topilmadi")
            if row["role"]=="owner": raise HTTPException(400,"Owner bloklanmaydi")
            c.execute("UPDATE admins SET active=? WHERE id=?",(active,admin_id))
        audit(u["username"],"ADMIN_STATUS",str(admin_id)+":"+str(active)); return {"ok":True}

        def check_bridge_secret(request: Request):
        supplied = request.headers.get('x-bridge-secret', '')
        expected = os.getenv('BRIDGE_SECRET', '')
        if not expected or not hmac.compare_digest(supplied, expected):
            raise HTTPException(403, 'Bridge ruxsati yo‘q')

    @app.post('/api/v2/chat/send')
    async def v2_chat_send(request: Request):
        u = require_login(request)
        form = await request.form()
        chat_id = str(form.get('chat_id', '')).strip()
        message_text = str(form.get('text', '')).strip()
        media_type = str(form.get('media_type', '')).strip().lower()
        upload = form.get('file')
        require_group_access(u, chat_id)
        with db() as c:
            group = c.execute('SELECT chat_id FROM groups_data WHERE chat_id=?', (chat_id,)).fetchone()
        if not group:
            raise HTTPException(404, 'Guruh topilmadi yoki bot bu guruhda yo‘q')
        media_data = None
        media_name = ''
        if upload and getattr(upload, 'filename', ''):
            media_name = os.path.basename(upload.filename)[:180]
            media_data = await upload.read()
            if len(media_data) > 20 * 1024 * 1024:
                raise HTTPException(413, 'Fayl 20 MB dan kichik bo‘lishi kerak')
            if media_type not in {'photo','video','voice','audio','animation','sticker','document'}:
                raise HTTPException(400, 'Media turi noto‘g‘ri')
        else:
            media_type = ''
        if not message_text and not media_data:
            raise HTTPException(400, 'Xabar matni yoki fayl tanlang')
        if len(message_text) > (1024 if media_data else 4096):
            raise HTTPException(400, 'Xabar matni juda uzun')
        with db() as c:
            cur = c.execute("INSERT INTO web_outgoing(chat_id,sender,text,status,created_at,media_type,media_name,media_data) VALUES(?,?,?,'queued',?,?,?,?)", (chat_id,u['username'],message_text,now(),media_type,media_name,media_data))
            item_id = cur.lastrowid
        audit(u['username'], 'BOT_GROUP_MESSAGE_QUEUED', f'{chat_id}:{item_id}:{media_type}')
        return {'ok':True,'id':item_id,'status':'queued'}

    @app.get('/api/v2/chat')
    async def v2_chat(request: Request):
        u = require_login(request)
        ids = visible(u)
        with db() as c:
            if ids is None:
                groups = c.execute('SELECT chat_id,title,members FROM groups_data ORDER BY title COLLATE NOCASE').fetchall()
                rows = c.execute('SELECT id,chat_id,sender,text,status,created_at,media_type,result FROM web_outgoing ORDER BY id DESC LIMIT 100').fetchall()
            elif ids:
                marks = ','.join('?' for _ in ids)
                groups = c.execute(f'SELECT chat_id,title,members FROM groups_data WHERE chat_id IN ({marks}) ORDER BY title COLLATE NOCASE', ids).fetchall()
                rows = c.execute(f'SELECT id,chat_id,sender,text,status,created_at,media_type,result FROM web_outgoing WHERE chat_id IN ({marks}) ORDER BY id DESC LIMIT 100', ids).fetchall()
            else:
                groups, rows = [], []
        return {'groups':[{'chat_id':r['chat_id'],'title':r['title'],'members':r['members']} for r in groups], 'items':[{'id':r['id'],'chat_id':r['chat_id'],'sender':r['sender'],'text':r['text'],'status':r['status'],'time':stamp(r['created_at']),'media_type':r['media_type'],'result':r['result']} for r in rows]}

    @app.get('/bridge/outgoing')
    async def bridge_outgoing(request: Request):
        check_bridge_secret(request)
        with db() as c:
            rows = c.execute("SELECT id,chat_id,text,media_type,media_name FROM web_outgoing WHERE status='queued' OR (status='sending' AND created_at<?) ORDER BY id LIMIT 10", (now()-120,)).fetchall()
            ids = [r['id'] for r in rows]
            if ids:
                marks = ','.join('?' for _ in ids)
                c.execute(f"UPDATE web_outgoing SET status='sending',created_at=? WHERE id IN ({marks})", [now(), *ids])
        return {'items':[{'id':r['id'],'chat_id':r['chat_id'],'text':r['text'],'media_type':r['media_type'],'media_name':r['media_name']} for r in rows]}

    @app.get('/bridge/media/{item_id}')
    async def bridge_media(item_id: int, request: Request):
        check_bridge_secret(request)
        with db() as c:
            row = c.execute('SELECT media_data,media_name,media_type FROM web_outgoing WHERE id=?',(item_id,)).fetchone()
        if not row or row['media_data'] is None:
            raise HTTPException(404,'Media topilmadi')
        mime = {'photo':'image/jpeg','video':'video/mp4','voice':'audio/ogg','audio':'audio/mpeg','animation':'video/mp4','sticker':'image/webp','document':'application/octet-stream'}.get(row['media_type'],'application/octet-stream')
        return Response(content=bytes(row['media_data']), media_type=mime)

    @app.post('/bridge/outgoing/{item_id}/result')
    async def bridge_outgoing_result(item_id: int, request: Request):
        check_bridge_secret(request)
        data = await request.json()
        status = str(data.get('status','failed'))
        if status not in {'sent','failed'}:
            raise HTTPException(400,'Status noto‘g‘ri')
        with db() as c:
            c.execute('UPDATE web_outgoing SET status=?,result=? WHERE id=?',(status,str(data.get('result',''))[:500],item_id))
        return {'ok':True}
