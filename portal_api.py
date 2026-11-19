    # ULANGAN AKKAUNTLAR RO'YXATINI SAYTGA CHIQARISH
    @app.get('/api/v2/chat/accounts')
    async def v2_chat_accounts(request: Request):
        u = require_owner(request)
        with db() as c:
            try:
                rows = c.execute("SELECT account_id, user_id, phone, first_name, username, is_active FROM connected_user_accounts WHERE is_active=1").fetchall()
                accounts = [{"id": r["account_id"], "name": r["first_name"] or str(r["account_id"]), "username": r["username"] or "", "phone": r["phone"] or ""} for r in rows]
            except Exception:
                accounts = []
        return {"accounts": accounts}

    # XABAR YUBORISH (BOT YOKI ULANGAN AKKAUNT NOMIDAN, REPLY VA BUYRUQLAR BILAN)
    @app.post('/api/v2/chat/send')
    async def v2_chat_send(request: Request):
        u = require_owner(request)
        form = await request.form()
        chat_id = str(form.get('chat_id', '')).strip()
        message_text = str(form.get('text', '')).strip()
        sender_mode = str(form.get('sender_mode', 'bot')).strip() # 'bot' yoki 'account'
        account_id = str(form.get('account_id', '0')).strip()
        reply_to_msg_id = str(form.get('reply_to_msg_id', '0')).strip()

        require_group_access(u, chat_id)
        if not message_text:
            raise HTTPException(400, "Xabar matnini kiriting")

        # Sender nomini belgilaymiz: bot yoki account:ID
        sender_tag = f"account:{account_id}" if sender_mode == "account" and account_id != "0" else "bot"

        with db() as c:
            # Agar ustunlar bo'lmasa avtomatik qo'shamiz
            cols = {r['name'] for r in c.execute('PRAGMA table_info(web_outgoing)').fetchall()}
            if 'reply_to' not in cols:
                c.execute("ALTER TABLE web_outgoing ADD COLUMN reply_to INTEGER DEFAULT 0")

            cur = c.execute(
                "INSERT INTO web_outgoing(chat_id, sender, text, status, created_at, reply_to) VALUES(?,?,?,'queued',?,?)",
                (chat_id, sender_tag, message_text, now(), int(reply_to_msg_id) if reply_to_msg_id.isdigit() else 0)
            )
            item_id = cur.lastrowid

        return {'ok': True, 'id': item_id, 'status': 'queued'}
        
