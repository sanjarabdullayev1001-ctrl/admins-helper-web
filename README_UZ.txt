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
