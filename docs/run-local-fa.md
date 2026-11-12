# اجرای پیش‌نمایش محلی

نیازمندی این مرحله Python 3.11+. ابتدا `python3 tunnelmgr/tunnelctl.py init` را اجرا کنید؛ سپس مدیر را با `python3 tunnelmgr/tunnelctl.py account create admin --role admin` بسازید. گذرواژه به‌صورت salted scrypt ذخیره می‌شود و ورود وب از نشست HttpOnly استفاده می‌کند. API را با `./scripts/run-local.sh` اجرا کنید. عملیات privileged محلی از helper محدود روی Unix socket عبور می‌کند. برای ثبت سرور راه‌دور، SSH و کلید خصوصی را به پنل معرفی کنید؛ نصب راه‌دور به دسترسی root یا sudo غیرتعاملی نیاز دارد.

```sh
python3 tunnelmgr/tunnelctl.py init
./scripts/run-local.sh
```

API به loopback محدود است. برای دسترسی راه‌دور از SSH forwarding استفاده کنید. helper هنوز فقط وقتی systemd/Linux و کاربر `tunnelmgr` نصب شده باشد کار می‌کند.
