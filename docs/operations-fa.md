پنل سرور اول با پروفایل نصب‌شدهٔ lab-reverse یک لینک واقعی روی 10.241.0.0/30 ساخته است. وضعیت job را با Show deployment status ببینید. Deploy برای ساخت اولیه است؛ لینک موجود را جایگزین نمی‌کند. پروفایل‌های JSON در /etc/tunnelmgr/mesh را فقط مدیر سیستم تعریف می‌کند. کلید استقرار دو سرور تست فقط فرمان mesh-worker را اجرا می‌کند.

برای ساخت حساب فقط‌خواندنی روی همان سرور:
```sh
sudo -u tunnelmgr env TUNNELMGR_HOME=/var/lib/tunnelmgr python3 /opt/tunnelmgr/tunnelmgr/tunnelctl.py account create ali --role viewer
```
توکن خروجی را در Sign in وارد کنید. operator اجازهٔ روشن/خاموش/راه‌اندازی مجدد دارد. admin اجازهٔ ساخت، حذف و استقرار نیز دارد. به جای create از list یا revoke NAME برای مشاهده یا لغو حساب استفاده کنید.

برای پروفایل native، نمونهٔ packaging/examples/native.json را با IPهای واقعی در /etc/tunnelmgr/network/NAME.json نصب کنید؛ kind یکی از gre و ipip است. در سمت دوم آدرس‌ها را جابه‌جا کنید. سرویس را با systemctl enable --now tunnelmgr-network@NAME فعال کنید. این پروتکل‌ها رمزنگاری ندارند.

برای مسیر ثابت، packaging/examples/routes.json را با subnet مقصد، IP داخلی همسایه و نام interface واقعی پر کنید. در طرف مقابل مسیر برگشت لازم است. برای هر interface ورودی روی روتر میانی پروفایل جدا مانند {"kind":"forward","interface":"bh0000"} فعال کنید. در مسیریابی روی LAN، gateway میزبان‌های LAN و قوانین firewall هم باید این مسیر را بپذیرند. سرویس‌های مسیر/forward باید بعد از سرویس سازندهٔ interface شروع شوند؛ در drop-in هر پروفایل به آن سرویس Requires= و After= بدهید.

برای ارتقای نصب موجود scripts/update-release.sh را به عنوان root اجرا کنید. مسیر نسخهٔ پشتیبان چاپ می‌شود. scripts/update-release.sh rollback PATH فایل‌های برنامه و واحدهای systemd قبلی را بازیابی می‌کند. داده‌های جاری تونل‌ها، کلیدها و موجودی SQLite در زمان برگشت حفظ می‌شوند. این روش برای ارتقای دارای تغییر ناسازگار در schema طراحی نشده است.
