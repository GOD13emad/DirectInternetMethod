# روش Direct Internet مستقل — Windows 1.1.0

## وضعیت پذیرش
نسخهٔ **1.1.0** هم در Windows Sandbox و هم روی میزبان Windows واقعی با نصب، Start، وضعیت ACTIVE، DNS/HTTPS، Stop، rollback دقیق و Recovery پذیرفته شده است.

- YouTube در baseline مستقیم timeout بود و در حالت ACTIVE پاسخ `204` داد.
- OpenAI پاسخ `401` و GitHub پاسخ `200` دادند.
- Adapter DNS، default route، WinHTTP و وضعیت ICS دست‌کاری نشدند.
- بعد از Stop/Recovery هیچ NRPT/ULA/ctrld/winws/WinDivert residue باقی نماند.

## استفادهٔ عادی
1. از Start Menu برنامه **Direct Internet Method** را باز کنید.
2. **Start** را بزنید. اجرای عادی Start/Stop/Recovery نیاز به UAC ندارد.
3. وضعیت باید **ACTIVE** شود.
4. برای خاموش‌کردن **Stop** را بزنید.
5. اگر وضعیت ناسالم شد، **Recovery** را اجرا کنید.

UAC فقط هنگام نصب یا upgrade بخش privileged ممکن است ظاهر شود.

## معماری
- UI بومی WPF برای کاربر عادی.
- Backend ثابت و privilege-separated: سرویس `DirectInternetMethodSvc`.
- PowerShell 7.6.6 داخل بسته و در مسیر protected نصب می‌شود؛ PowerShell خارجی لازم نیست.
- DNS: سرویس owned و demand-start به نام `ctrld` v1.5.7 → DoH مستقیم Control D.
- listener محلی: `fd53:4444:48::53/128` روی Loopback.
- Windows resolver: NRPT catch-all فقط در زمان ACTIVE.
- DPI: zapret/winws + WinDivert فقط برای TCP/443 و hostlist.
- VPN، HTTP/SOCKS proxy یا default-route tunnel ساخته نمی‌شود.
- Adapter DNS و ICS باید حفظ شوند.

## رفتار ایمنی
Start ابتدا prestate/state را ثبت می‌کند و در failure rollback می‌کند. Stop فقط resourceهای owned را حذف و external state را verify می‌کند. Recovery نیز fail-closed و ownership-aware است.

## محدودیت
Installer فعلاً Authenticode-signed نیست.
