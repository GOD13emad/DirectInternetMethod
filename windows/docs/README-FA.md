# روش Direct Internet مستقل

## وضعیت پذیرش
نسخهٔ 1.0.0 در Windows با دو چرخهٔ کامل Start/Stop پذیرفته شده است. در هر دو چرخه DNS و HTTPS برای YouTube، GitHub و OpenAI و همچنین بازشدن YouTube در Chrome پیش‌فرض PASS شده و rollback دقیق PASS بوده است.

این بسته برای استفادهٔ مستقل روی Windows ساخته شده و برای Start/Stop به ChatGPT نیاز ندارد.

## استفادهٔ عادی
1. از Start Menu برنامه **Direct Internet Method** را باز کنید.
2. دکمه **Start** را بزنید و UAC استاندارد Windows را تأیید کنید.
3. وضعیت باید **ACTIVE** شود.
4. برای خاموش‌کردن، دکمه **Stop** را بزنید.
5. اگر وضعیت **DEGRADED** شد، **Recovery** را اجرا کنید و سپس دوباره Start کنید.

میانبرهای جداگانه Start، Stop، Status و Recovery نیز در Start Menu نصب می‌شوند.

## معماری
- DNS رمزگذاری‌شده: ctrld v1.5.7 → DoH مستقیم Control D.
- listener محلی: ULA اختصاصی IPv6 با آدرس `fd53:4444:48::53/128` روی Loopback.
- Windows resolver: NRPT catch-all فقط در زمان ACTIVE به ULA هدایت می‌شود.
- DPI: zapret/winws + WinDivert فقط برای TCP/443 و hostlist.
- Adapter DNS تغییر نمی‌کند.
- VPN، HTTP/SOCKS proxy و default-route tunnel ساخته نمی‌شود.
- ICS نباید تغییر کند.

## رفتار ایمنی
Start ابتدا state PREPARED می‌نویسد و سپس mutation را انجام می‌دهد. اگر Start fail شود، rollback اجرا می‌شود. Stop فقط resourceهای متعلق به این بسته را حذف می‌کند و prestate DNS/NRPT/ICS/routes/proxy را verify می‌کند. Recovery برای residueهای متعلق به همین بسته است.

## نیازمندی
Windows و PowerShell 7 (`pwsh.exe`). بسته dependencyهای ctrld/zapret/WinDivert را همراه خودش دارد و برای اجرا دانلود جدید لازم نیست.

## نکته
UAC بخشی از امنیت Windows است و عمداً دور زده نشده است. نیاز نداشتن به ChatGPT به معنی حذف UAC نیست.


## وضعیت نهایی
این نسخه در ۲۰۲۶-۰۹-۲۹ دو چرخهٔ کامل Start/Stop را با موفقیت گذرانده است. YouTube در Chrome default-mode، DNS سیستم، GitHub و OpenAI در هر دو چرخه تست شدند و rollback دقیق تأیید شد.
