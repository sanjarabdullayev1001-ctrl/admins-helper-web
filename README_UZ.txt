ADMINS HELPER — YANGI ALOHIDA WEB SAYT (1-BOSQICH)

FAYLLAR
- web_app.py       yangi brauzer sayti va admin login tizimi
- db_backend.py    mavjud loyiha SQLite/PostgreSQL adapteri
- requirements_web.txt  kerakli kutubxonalar

MUHIM
Bu yangi alohida web servis. Hozirgi Render bot/Mini App o‘zgartirilmaydi.
Bu versiyada brauzer login, Owner paneli, admin yaratish/o‘chirish/faolsizlantirish,
admin ruxsatlari, cyber sozlamalar va 18+ GUARD tekshiruv navbati mavjud.
Telegram guruhlariga avtomatik ban, profil rasmini AI bilan ko‘rish va kanalni
tekshirish hali bot integratsiyasi qilinmagan — tugmalar hozircha sozlamalarni saqlaydi.

ENVIRONMENT VARIABLES (Render Environment yoki hosting panelida)
OWNER_ID=hozirgi Telegram Owner ID raqami
SESSION_SECRET=kamida 32 belgili tasodifiy maxfiy kalit
WEB_OWNER_USERNAME=owner (ixtiyoriy, standart: owner)
WEB_OWNER_PASSWORD=kamida 12 belgili yangi kuchli parol
COOKIE_SECURE=true
MINIAPP_DB=miniapp.db (SQLite ishlatilsa)
DATABASE_URL=PostgreSQL ulanish manzili (PostgreSQL ishlatilsa, MINIAPP_DB kerak emas)

Eslatma: WEB_OWNER_PASSWORD ni hech kimga chatda yubormang. Uni faqat hostingning
Environment Variables bo‘limiga o‘zingiz kiriting. Eski BOT_TOKEN va BRIDGE_SECRET
qiymatlarini bu yangi servisga ko‘chirish hozircha shart emas.

LOCAL TEST (Windows CMD)
1) Python 3.11+ o‘rnating.
2) Shu papkada CMD oching.
3) Buyruqlar:
   py -m venv venv
   venv\Scripts\activate
   py -m pip install -r requirements_web.txt
   set OWNER_ID=TELEGRAM_OWNER_ID
   set SESSION_SECRET=32_BELGIDAN_UZUN_TASODIFIY_KALIT
   set WEB_OWNER_PASSWORD=12_BELGIDAN_UZUN_KUCHLI_PAROL
   set COOKIE_SECURE=false
   py -m uvicorn web_app:app --host 127.0.0.1 --port 8000
4) Brauzerda http://127.0.0.1:8000 ni oching.
5) Login: WEB_OWNER_USERNAME (standart owner), parol: WEB_OWNER_PASSWORD.

RENDER UCHUN
Alohida yangi Web Service yarating. Eski service'ni o‘chirmang va unga deploy qilmang.
Build Command: pip install -r requirements_web.txt
Start Command: uvicorn web_app:app --host 0.0.0.0 --port $PORT
Environment Variables yuqoridagi ro‘yxatdan kiriting; COOKIE_SECURE=true qolsin.
Ma’lumotlar yo‘qolmasligi uchun PostgreSQL DATABASE_URL tavsiya qilinadi.

SINOV HOLATI
Python syntax, JS syntax, Owner login, dashboard, admin yaratish va himoya sozlamalari
lokal testda tekshirildi. Productionga chiqarishdan oldin yangi alohida servisda
HTTPS, PostgreSQL va mavjud bot bilan bridge integratsiyasi alohida sinovdan o‘tkazilsin.

YANGI WEB PANEL SOZLAMALARI
==========================

Render Web Service:
- Build Command: pip install -r requirements_web.txt
- Start Command: uvicorn web_app:app --host 0.0.0.0 --port $PORT

Majburiy Environment Variables:
- SESSION_SECRET: uzun, tasodifiy maxfiy qiymat
- WEB_OWNER_USERNAME: Owner login
- WEB_OWNER_PASSWORD: Owner uchun kuchli parol
- BRIDGE_SECRET: bot va sayt orasidagi umumiy maxfiy kalit
- DATABASE_URL: Render PostgreSQL ulanish manzili

Telegram orqali akkaunt ulash:
- TELEGRAM_BOT_TOKEN: bot tokeni (faqat Render Environment Variables ichida)
- TELEGRAM_BOT_USERNAME: bot username, @ belgisiz
- BotFather orqali /setdomain buyrug‘ida sayt domenini tasdiqlash kerak.
- Bot guruhda administrator bo‘lishi kerak.
- Guruh ulash vaqtida Telegram API foydalanuvchi va bot adminligini tekshiradi.

XAVFSIZLIK:
- Telegram login widget akkaunt egasini tasdiqlaydi; foydalanuvchining shaxsiy sessiyasi yoki SMS/login kodi olinmaydi.
- Telegram admini faqat o‘zi admin bo‘lgan va bot ulangan guruhni ko‘ra oladi.
- Owner barcha guruhlarni ko‘radi.
- Telegram login va guruh ulash ishlashi uchun yuqoridagi token va domen sozlamalari shart.
- Soxta adminni avtomatik aniqlash va adminlikdan tushirish botning alohida Telegram moderation kodini ham talab qiladi. Web panelning o‘zi buni bajarmaydi; noto‘g‘ri aniqlash bilan haqiqiy adminni tushirib yubormaslik uchun bu qism bot kodi va guruhning ishonchli admin ro‘yxati bilan birga joriy qilinishi kerak.


SOXTA ADMIN HIMOYASI
====================

- Har bir guruh admini /group/GURUH_ID/protection sahifasida ishonchli adminlar ro‘yxatini sozlaydi.
- Himoyani yoqishdan oldin guruhdagi barcha haqiqiy adminlarning Telegram ID raqamini ro‘yxatga kiriting.
- Guruhni birinchi ulagan Telegram admin avtomatik ishonchli ro‘yxatga qo‘shiladi.
- Himoya yoqilganda, bot BRIDGE_SECRET bilan tasdiqlangan security event yuborishi kerak:
  {"type":"security","action":"fake_admin_detected","confirmed":true,"chat_id":"-100...","user_id":123456}
- Web servis foydalanuvchi haqiqiy Telegram admin ekanini qayta tekshiradi. Agar himoya yoqilgan va u ishonchli ro‘yxatda bo‘lmasa, bot API orqali admin huquqlarini bekor qilishga urinadi va guruhga ogohlantirish yuboradi.
- Ban berilmaydi. Agar botda "Boshqa adminlarni tayinlash" (can_promote_members) huquqi bo‘lmasa, adminlikni bekor qila olmaydi; lekin ogohlantirish yuborishga urinadi.
- Creator/egani avtomatik tushirishga urinilmaydi.
- Bu eventni aniqlab yuborish uchun Enzonic botning main.py qismida Telegram chat_member/admin o‘zgarishlarini kuzatish va faqat tasdiqlangan shubhali hodisani bridge'ga yuborish kodi ham kerak. Hozirgi GitHub repozitoriyda main.py mavjud emas; shu sababli aniqlashni botga ulash hali bajarilmagan.

Eslatma: Telegram Login Widget akkaunt egasining shaxsini tasdiqlaydi. U to‘liq shaxsiy Telegram sessiyasini ulab bermaydi va login kod/parolni saytga saqlamaydi.

CI: GitHub Actions tekshiruvi web_app.py va db_backend.py sintaksisini tekshiradi.
