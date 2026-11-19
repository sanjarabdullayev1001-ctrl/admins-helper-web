ADMINS HELPER — MUSTAQIL WEB SERVER

Bu loyiha Telegram Mini App emas. Oddiy brauzer orqali ochiladigan mustaqil web-server.

FAYLLAR
- web_app.py: FastAPI server, session login va bridge endpoint
- portal.html: brauzer boshqaruv paneli
- portal_api.py: ro'yxatdan o'tish, login, guruhlar, hodisalar, arizalar, qora ro'yxat va admin API
- db_backend.py: eski Mini App DB adapteri (alohida modul, hozir portal API unga tayanmaydi)

RENDER
Build Command:
pip install -r requirements_web.txt

Start Command:
uvicorn web_app:app --host 0.0.0.0 --port $PORT

Kerakli Environment Variables:
SESSION_SECRET = kamida 32 belgili tasodifiy maxfiy qiymat
WEB_OWNER_USERNAME = owner (ixtiyoriy)
WEB_OWNER_PASSWORD = kuchli, kamida 12 belgili parol
BRIDGE_SECRET = bot bilan bridge uchun botdagi aynan bir xil maxfiy qiymat
WEB_DB_PATH = persistent diskdagi SQLite yo'li (yoki Render PostgreSQL adapteri keyingi bosqichda)

Portal:
https://admins-helper-miniapp.onrender.com/portal

Asosiy sahifa / portalga yo'naltiruvchi tugma beradi.

MUHIM XAVFSIZLIK
- Har bir yangi foydalanuvchi login/parol bilan ro'yxatdan o'tadi.
- Telegram ID ko'rsatilsa, bot bridge guruhdagi adminligini tasdiqlaganidan keyin guruhlar ko'rinadi.
- QR bog'lash Telegram botidagi bir martalik deep-link orqali foydalanuvchining Telegram ID'sini tasdiqlaydi; bu shaxsiy MTProto sessiyasini olmaydi va shaxsiy xabarlarni o'qish yoki foydalanuvchi nomidan harakat qilish huquqini bermaydi.
- QR token 3 daqiqa amal qiladi, bir marta ishlatiladi va Telegram ID boshqa faol portal hisobiga bog'langan bo'lsa rad etiladi.
- Har bir foydalanuvchi faqat o'z portal hisobiga QR tasdiqlashi kerak; QR havolasini boshqalarga yubormang.
- Foydalanuvchilar faqat group_access orqali o'zlariga biriktirilgan guruhlarni ko'radi.
- Owner barcha guruhlar va adminlarni boshqaradi.
- Qora ro'yxat web hisobiga kirishni to'sadi; Telegram guruhidan ban qilishni o'zi bajarmaydi.
- Web chat hozircha ko'rish/bo'lim interfeysi. Botdan haqiqiy xabar, rasm, GIF, sticker yoki ovoz yuborish uchun bot-serverda alohida outbound command worker va media relay qo'shilishi shart.
- 18+ profil aniqlash/ban qilish, fake-adminni avtomatik olib tashlash va Telegram join request'ni tasdiqlash hozircha real bajariladigan funksiyalar emas; ular faqat botning tasdiqlangan eventlari kelganda tarixda ko'rinishi mumkin.
- Bot event bridge guruh/xabar/member/group_access hodisalarini qabul qiladi. Botdagi BRIDGE_SECRET va MINIAPP_URL sozlamalari to'g'ri bo'lishi shart.
- WEB_DB_PATH uchun doimiy disk ishlating, aks holda deploy paytida SQLite ma'lumotlari yo'qolishi mumkin.

Bu versiya mustaqil web server asosini va boshqaruv API'larini qo'shadi. Productionga chiqarishdan oldin Render deploy, database persistence, CSRF/rate-limit va bot outbound integratsiyasini alohida tekshirish talab qilinadi.
