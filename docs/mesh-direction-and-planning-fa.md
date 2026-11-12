# مدل direct/reverse و mesh

## جهت اتصال

در این نسخه، `direct` یعنی در هر لینک node A اتصال را به listener روی node B آغاز کند؛ پس B نقش Backhaul server و A نقش client می‌گیرد. `reverse` جهت dial/listen را برعکس می‌کند. خود TUN دوطرفه است؛ تفاوت این گزینه فقط سمت شروع اتصال و نیاز به listener قابل‌دسترسی را مشخص می‌کند.

برای لینک direct، node B باید از node A قابل دسترسی باشد. برای reverse، node A باید listener عمومی باشد. در صورت NAT، جهت را طوری انتخاب کنید که سمت public listener شود. اگر هیچ‌کدام public نیستند، باید relay قابل‌دسترسی به topology اضافه شود.

## توپولوژی

- Full mesh با `N` گره `N*(N-1)/2` لینک مستقیم دارد.
- Hub-and-spoke با `N` گره `N-1` لینک دارد.
- هر لینک یک شناسه، یک /30 جداگانه، یک interface، پورت listen یکتا، health port یکتا و دو config متناظر server/client می‌گیرد.
- آدرس‌های overlay هر دو سمت در هر لینک جفت‌اند؛ config طرف دیگر همان دو آدرس را با local/peer معکوس می‌گیرد.
- هر گرهی که لینک‌های متعدد دارد، روی هر peer interface جداگانه دارد. این طرح به‌تنهایی route یا forwarding برای عبور ترافیک بین گره‌های واسط تنظیم نمی‌کند.

نمونهٔ CLI:

```sh
python3 tunnelmgr/tunnelctl.py mesh plan \
  --nodes hel1,fsn1 \
  --topology full \
  --direction direct \
  --pool 10.240.0.0/16 \
  --public-nodes hel1,fsn1 \
  --endpoints hel1=65.109.179.222,fsn1=91.107.139.87
```

API محلی نیز `POST /api/v1/mesh/plan` می‌پذیرد. فرم پنل همین پارامترها را می‌گیرد و پیکربندی هر سمت را برمی‌گرداند. برای استقرار واقعی از `scripts/mesh-deploy.py` روی رایانهٔ مدیر استفاده کنید. ابزار با OpenSSH به هر میزبان وصل می‌شود و با هویت SSH عملیات محدودشده را از طریق helper تونل اجرا می‌کند؛ گذرواژهٔ کاربر وب یا نشست آن را منتقل نمی‌کند. برای هر لینک secret تصادفی جداگانه می‌سازد، پورت‌ها و نام TUN آزاد را انتخاب می‌کند و دو طرف لینک را ایجاد می‌کند. استقرار یک لینک را rollback می‌کند و در صورت خطای لینک بعدی، لینک‌هایی را که همان اجرا ساخته نیز پاک می‌کند. اجرای `--check` وضعیت systemd و ping هر دو سمت را بررسی می‌کند. این روش به SSH قابل‌دسترسی، نصب قبلی preview روی تمام نودها و بازبودن پورت listener نیاز دارد.

نمونهٔ استقرار و بررسی دو نود:

```sh
python3 scripts/mesh-deploy.py \
  --nodes hel1,fsn1 \
  --endpoints hel1=65.109.179.222,fsn1=91.107.139.87 \
  --topology full --direction direct

python3 scripts/mesh-deploy.py \
  --nodes hel1,fsn1 \
  --endpoints hel1=65.109.179.222,fsn1=91.107.139.87 \
  --topology full --direction direct --check
```

ابزار خودش route بین شبکه‌های پشت نودها را اضافه نمی‌کند؛ هر edge یک لینک مستقل /30 است.
