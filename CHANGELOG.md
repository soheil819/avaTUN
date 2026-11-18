## avaTUN 2.0.6 · فعال‌سازی IPv6 روی رابط تونل

- هنگام تنظیم آدرس IPv6، avaTUN IPv6 را روی همان رابط مجازی فعال می‌کند؛ این کار تنظیم IPv6 سرور یا رابط‌های دیگر را تغییر نمی‌دهد.
- اگر کرنل نتواند IPv6 را روی رابط تونل فعال کند، پیام خطا علت را مشخص می‌کند.

## avaTUN 2.0.5 · اعتبارسنجی آدرس‌های SIT

- الزام ورود هر دو آدرس IPv6 داخلی برای SIT FoU و نمایش خطای روشن در API به‌جای خطای خام `inner_local`.
- الزام آدرس IPv6 داخلی برای SIT ISATAP.

## avaTUN 2.0.4 · اصلاح ویرایش تونل Geneve

- بازیابی فیلدهای ویرایش از بخش فرم مربوط به همان نوع تونل؛ ورودی هم‌نام Backhaul دیگر رابط Geneve را بازنویسی نمی‌کند.

## avaTUN 2.0.3 · نمایش آمار GitHub

- اتصال بخش پایینی پنل به مخزن عمومی avaTUN؛ تعداد ستاره‌ها و Milestoneهای باز را نمایش می‌دهد.
- فهرست هدف‌ها از Milestoneهای GitHub خوانده می‌شود و با کش محلی ۱۵ دقیقه‌ای به‌روز می‌ماند.

## avaTUN 2.0.2 · مدیریت وابستگی‌های OpenConnect

- حذف نصب خودکار بسته‌های `ocserv` و `openconnect` از سرور مرکزی و سرورهای مدیریت‌شده.
- در دسترس قرارگرفتن صفحهٔ پورت‌فوروارد TCP مبتنی بر HAProxy در نصب نسخهٔ 2.0.2.

## avaTUN 2.0.1 · چندزبانه‌سازی و دسترسی اختیاری با HTTPS

- افزودن رابط کامل انگلیسی، روسی، چینی ساده‌شده و ترکی به پنل و Telegram Mini App؛ زبان فارسی با نام «پارسی» در دسترس است.
- نگه‌داشتن دسترسی HTTP از راه دور وقتی TLS پنل پیکربندی نشده است؛ HTTPS اختیاری است و پس از پیکربندی گواهی معتبر، درخواست HTTP به HTTPS هدایت می‌شود.
- اختیاری‌کردن ثبت‌نام مدیر در ورود دومرحله‌ای؛ استفاده از TOTP همچنان به HTTPS نیاز دارد.

## avaTUN 2.0.0 · نسخهٔ پایدار

- تثبیت avaTUN 2.0.0 به‌عنوان نسخهٔ پایدار پروژه.
- حذف سکشن مسیریابی جفتی BGP/OSPF و API، پروفایل‌های FRR و وابستگی نصب آن؛ طراحی Mesh چندسروری برای بازطراحی آینده کنار گذاشته شده است.
- حذف بررسی مخصوص route profile از اعتبارسنجی مقصدهای HAProxy؛ امکان استفاده از مسیرهای IP که سیستم‌عامل از قبل دارد حفظ شد.

## avaTUN 1.0.0.13 · تأیید مستقیم نسخهٔ اسلیو

- نتیجهٔ نصب موفق، نسخهٔ نصب‌شده را مستقیم به پنل برمی‌گرداند؛ رابط برای اعلام موفقیت به snapshot کش‌شدهٔ پایش وابسته نیست.

## avaTUN 1.0.0.12 · اصلاح به‌روزرسانی اسلیو و نمایش پیشرفت

- برای اسلیوهای دارای توزیع یا نسخهٔ Ubuntu/Debian متفاوت، نسخهٔ بسته‌ها از مخازن سازگار همان اسلیو انتخاب می‌شود؛ نسخهٔ مرکزی فقط روی همان انتشار سیستم‌عامل و در صورت موجودبودن در مخزن اعمال می‌شود.
- نوار به‌روزرسانی اسلیو دیگر درصد حدسی نشان نمی‌دهد و خطای نصب حتی وقتی شمارهٔ نسخه از قبل برابر است، به‌عنوان موفقیت نمایش داده نمی‌شود.

## avaTUN 1.0.0.11 · همگام‌سازی وابستگی‌های اسلیو

- هنگام نصب یا به‌روزرسانی اسلیو، نسخهٔ بسته‌های Debian موردنیاز با سرور مرکزی مقایسه و در صورت دسترسی در مخازن اسلیو، نسخهٔ دقیق مرکزی نصب می‌شود؛ نسخهٔ ناموجود با خطای مشخص گزارش می‌شود.
- تنظیمات `/etc/haproxy` پیش از همگام‌سازی HAProxy نسخهٔ پشتیبان می‌شود و پس از آن عیناً بازگردانده می‌شود.
- Xray Core نسخهٔ avaTUN فقط در مسیر اختصاصی `/opt/tunnelmgr/bin/xray` همگام می‌شود؛ فایل‌ها و سرویس‌های Xray خارج از این مسیر دست‌نخورده می‌مانند.

## avaTUN 1.0.0.10 · حذف secretهای Backhaul

- هنگام حذف دائمی تونل Backhaul، فایل secret مدیریت‌شده (`token` یا `psk`) و نسخهٔ حفظ‌شدهٔ آن از `/etc/backhaul/secrets` نیز روی همان سرور پاک می‌شوند.
- حذف از پنل، مسیر مدیریت اسلیو و ابزار استقرار به پاک‌سازی سمت سرور متصل شد؛ بازسازی یا به‌روزرسانی تونل secret را حفظ می‌کند.

## avaTUN 1.0.0.9 · پاک‌سازی خودکار مسیرهای HAProxy

- هنگام حذف تونل، مسیرهای وابسته از قوانین HAProxy همان سرور حذف می‌شوند؛ اگر قانون مسیر دیگری داشته باشد حفظ می‌شود و اگر خالی بماند خود قانون هم حذف می‌شود.
- پیش از ذخیرهٔ قانون HAProxy، ارجاع‌های قدیمی به تونل‌های حذف‌شده پاک‌سازی می‌شوند تا ویرایش قانون‌های دیگر هم شکست نخورد.
- در حالت Failover، اگر مسیر اصلی حذف شود، یک مسیر باقی‌مانده به‌عنوان اصلی ارتقا می‌یابد.

## avaTUN 1.0.0.8 · بسته‌بندی اسلیوها

- اسکریپت `tunnelmgr` در نصب مرکزی به مسیر اسکریپت‌های پنل کپی می‌شود تا در بستهٔ ارسالی برای اسلیوها نیز موجود باشد.

## avaTUN 1.0.0.7 · تکمیل به‌روزرسانی اسلیوها

- اسکریپت `tunnelmgr` به بستهٔ ارسالی از پنل مرکزی افزوده شد تا نصب روی اسلیوها بدون خطای `cannot stat` کامل شود.

## avaTUN 1.0.0.6 · مدیریت حساب‌های پنل

- فرمان `tunnelmgr` برای مدیریت حساب‌ها نصب می‌شود و به دیتابیس سرویس پنل وصل است.
- ساخت دوبارهٔ نام کاربری موجود پیام راهنما می‌دهد؛ برای تغییر نقش از `account edit` و برای گذرواژه از `account password` استفاده کنید.
- تغییر نقش و گذرواژه با `account edit NAME --role ROLE` و `--set-password` امکان‌پذیر است.
- راهنمای ورود، فرمان کامل ساخت مدیر نخست را نمایش می‌دهد.

## avaTUN 1.0.0.5 · نمایش حجم تبادل

- نمایش حجم دریافتی، ارسالی و مجموع بایت‌های هر تونل در پنل و Telegram Mini App؛ شمارش از یک سمت تونل انجام می‌شود تا دو بار شمرده نشود.
- نمایش حجم ورودی و خروجی برای هر قانون پورت HAProxy با استفاده از آمار listener همان پورت.
- نگهداری جمع شمارنده‌ها در دیتابیس محلی و ادامهٔ شمارش پس از ری‌استارت سرویس یا صفرشدن شمارندهٔ خام.

## avaTUN 1.0.0.4 · انتشار پایدار

- انتخاب تصادفی پورت‌های UDP برای L2TPv3 و بررسی bind آزاد بودن هر پورت روی endpoint مربوطه از پنل مرکزی، پیش از ساخت تونل.

## avaTUN 1.0.0.3 · انتشار پایدار

- رفرش جداگانهٔ تنظیمات گزارش تلگرام برای به‌روزشدن سریع دکمه‌های سرورها.
- فعال‌کردن HTTPS با گواهی خودامضا به‌صورت پیش‌فرض و هدایت HTTP به HTTPS.
- نمایش پیوستهٔ وضعیت نصب به‌روزرسانی پنل و گزارش خطا یا پایان نصب.

## avaTUN 1.0.0.2 · انتشار پایدار

- افزودن نصب تک‌دستوری از GitHub با نصب خودکار پیش‌نیازهای راستی‌آزمایی و بررسی attestation ریلیز پیش از اجرا.
- به‌روزرسانی شمارهٔ نسخهٔ پنل، ربات و Mini App به 1.0.0.2.

## avaTUN 1.0.0.1 · انتشار پایدار

- افزودن اسکریپت حذف avaTUN با تأیید صریح؛ سرویس‌ها و اینترفیس‌های مدیریت‌شدهٔ همین میزبان را متوقف می‌کند و بسته‌های مشترک، فایروال و سرویس‌های نامرتبط را حفظ می‌کند.
- اصلاح تشخیص و مقایسهٔ نسخه‌های چهارقسمتی در به‌روزرسان خودکار.

## avaTUN 0.2.49 · انتقال امنیت حساب به تنظیمات

- قراردادن مدیریت MFA داخل صفحهٔ تنظیمات و حذف ورودی مستقل از منو؛ پیوند قدیمی `#security` نیز به تنظیمات هدایت می‌شود.

## avaTUN 0.2.48 · اصلاح ردشدن کدهای MFA

- اصلاح ترتیب آرگومان‌های اعتبارسنج TOTP؛ کدهای برنامه و عملیات کد بازیابی اکنون با آخرین گام مصرف‌شده مقایسه می‌شوند.

## avaTUN 0.2.47 · حفظ وضعیت MFA در به‌روزرسانی پنل

- ذخیرهٔ امن snapshot از secret رمز‌شدهٔ MFA، کلید رمزنگاری و کدهای بازیابی پیش از ارتقا؛ بازگردانی آن پیش از راه‌اندازی سرویس جدید.
- اجرای نصب با سرویس پنل و ربات متوقف تا بازیابی وضعیت MFA کامل شود.
- جلوگیری از ساخت کلید رمزنگاری جایگزین وقتی حساب MFA فعال دارد و کلید اصلی گم شده است.

## avaTUN 0.2.46 · روشن‌کردن خطای کد TOTP و حفظ چالش ورود

- تشخیص جداگانهٔ کد TOTP مصرف‌شده از کد نامعتبر.
- نگه‌داشتن فرم و چالش ورود پس از خطای کد تا کاربر بتواند کد تازه را در همان ورود امتحان کند.

## avaTUN 0.2.45 · دسترسی حساب ماشینی ربات تلگرام با MFA مدیرها

- نگه‌داشتن الزام MFA برای مدیرهای انسانی و مجازکردن حساب اختصاصی `avatun-telegram` برای نشست‌های API ربات.
- حساب ربات همچنان با گذرواژهٔ تصادفی و فهرست مجاز مدیران تلگرام محافظت می‌شود.

## avaTUN 0.2.44 · اصلاح ورودی QR برنامهٔ احراز هویت

- ارسال URI به ورودی استاندارد `qrencode`؛ گزینهٔ `--read-from` برای مسیر فایل است و `-` در آن به‌عنوان نام فایل تفسیر می‌شد.

## avaTUN 0.2.43 · ورود دومرحله‌ای با برنامهٔ TOTP

- افزودن ورود سازگار با Google Authenticator، QR راه‌اندازی و تأیید کد پیش از صدور نشست کامل.
- اجباری‌کردن MFA برای مدیرها؛ امکان فعال‌سازی اختیاری برای کاربران دیگر.
- افزودن کدهای بازیابی یک‌بارمصرف، چرخاندن کدها و بازنشانی مدیریتی MFA.
- نگهداری رمز‌شدهٔ secretهای TOTP و افزودن `qrencode` و `python3-cryptography` به نصب‌کننده.
- محدودکردن ورود و تنظیم MFA به HTTPS؛ مدیر تازه‌وارد می‌تواند ابتدا HTTPS پنل را تنظیم کند.

## avaTUN 0.2.42 · تنظیم چیدمان گرهٔ پروکسی

- کوچک‌تر کردن آیکون گیت‌وی و قراردادن نام، نشانی و شمار مسیرها بالای آن.

## avaTUN 0.2.41 · هم‌اندازه‌کردن گرهٔ خط پروکسی با سرورها

- بزرگ‌کردن گیت‌وی SVG در Mesh و نمایش نام و نشانی خط زیر آیکون، هم‌راستا با گره‌های سرور.

## avaTUN 0.2.40 · آیکون خط پروکسی در Mesh

- افزودن آیکون دروازهٔ ترافیک ارسالی به گرهٔ خط Xray روی نقشه.

## avaTUN 0.2.39 · جابه‌جایی گره‌های پروکسی در نقشه Mesh

- امکان جابه‌جایی گره‌های خط Xray با کشیدن روی نقشه و ذخیرهٔ جای آن‌ها.
- بزرگ‌تر شدن بوم نقشهٔ Mesh و تنظیم بازهٔ جابه‌جایی متناسب با ابعاد جدید.

## avaTUN 0.2.38 · نمایش خط‌های پروکسی در نقشه Mesh

- نمایش همهٔ خط‌های Xray به‌صورت گره و مسیرهای فوروارد از هر سرور تا خط و مقصد در نقشه Mesh.
- دریافت فورواردهای همهٔ سرورها برای ساخت توپولوژی کامل؛ کلیک روی مسیر پروکسی صفحهٔ خطوط پروکسی را باز می‌کند.

## avaTUN 0.2.37 · نصب مستقل Xray و بررسی تداخل پورت

- نصب Xray Core نسخهٔ ثابت با checksum در مسیر اختصاصی avaTUN؛ فایل‌ها و سرویس‌های Xray و x-ui موجود تغییر نمی‌کنند.
- بسته‌بندی Core از سرور مرکزی هنگام به‌روزرسانی سرورهای مدیریت‌شده، برای نصب بدون نیاز به دسترسی GitHub از سرور مقصد.
- رد کردن فوروارد در صورت اشغال بودن IP، پورت و پروتکل شنود و اعلام سرویس مالک؛ در rollback سرویس موجود دست‌نخورده می‌ماند.

## avaTUN 0.2.36 · خط‌های خروجی Xray و مسیر SSH انتخابی

- افزودن مدیریت لینک‌های VLESS، VMess و Trojan با نگهداری محرمانهٔ اطلاعات اتصال.
- افزودن فوروارد TCP/UDP از طریق خط انتخابی روی سرور مرکزی یا هر سرور مدیریت‌شده.
- امکان عبور SSH به سرورهای انتخابی از خط Xray؛ مسیر پیش‌فرض شبکه تغییر نمی‌کند.
- افزودن سرویس Xray مدیریت‌شده با آزمون کانفیگ و بازگردانی در صورت خطای راه‌اندازی.
- امکان شنود روی پورت‌های پایین ۱۰۲۴ با capability محدود به سرویس Xray فراهم شد.

## avaTUN 0.2.35 · حفظ listener مشترک GRE-FoU

- Keep a FoU UDP listener registered while another active tunnel profile on the same server still uses the same protocol and port.
- Pass the profile identity through rollback cleanup so a failed start cannot remove another tunnel's shared listener.

## avaTUN 0.2.34 · انتظار آماده‌شدن تونل پیش از تست سرعت

- Wait for both tunnel peers to answer over their inner path before starting iperf3.
- Retry transient zero-throughput and listener-start failures up to three times, cleaning up each temporary listener.

## avaTUN 0.2.33 · سنجش و اعمال گروهی MTU

- Wire the all-tunnels MTU button to a sequential per-tunnel probe and coordinated two-endpoint apply.
- Show progress and a per-tunnel success or failure result; cap every applied automatic MTU at 1400.

## avaTUN 0.2.32 · محدودیت MTU و آزمون سرعت

- Cap automatically recommended tunnel MTU at 1400, even when path discovery reports a larger value.
- Run iperf3 without omitting its first second, which returned zero throughput on the Finland → tofin-1 L2TPv3 path.

## avaTUN 0.2.31 · پردازش پیام‌های webhook

- Process webhook updates on the bot's main thread so its SQLite state is accessed safely.

## avaTUN 0.2.30 · دریافت پیام با webhook

- Use the domain entered in panel TLS settings to configure a secured Telegram webhook on port 8443. The bot switches automatically after the certificate is issued or renewed; before TLS is ready, polling remains active.

## avaTUN 0.2.29 · تلاش دوبارهٔ ویجت

- Remove the Telegram widget delivery cooldown so each `/start` retries widget delivery immediately.

## avaTUN 0.2.28 · محافظت از پیام‌های ربات

- Protect native Telegram bot messages from forwarding and saving, matching the existing widget protection.

## avaTUN 0.2.27 · رنگ‌بندی گسترده‌تر تم‌ها

- Extend the selected palette across the page background, navigation, cards, forms, notices, tables and mesh canvas.
- Keep status colors and readable foreground text stable while tinting each section with the selected theme.
- Use the Telegram HTML widget console for status and navigation screens, with native text fallback for unsupported chats.

## avaTUN 0.2.26 · بازطراحی تم‌های رنگی

- Replace the broad gradient theme override with eight restrained accent palettes; keep panel surfaces, navigation layout and neutral actions consistent.
- Remove oversized palette glows, improve text contrast and migrate existing browser selections to the new palette set.

## avaTUN 0.2.25 · beta19 · نخستین نسخهٔ آزمایش عملی

- Add 12 selectable neon accent palettes to dashboard settings; the chosen palette is saved per browser and the default layout remains intact.
- Carry forward the 0.2.24 IPsec peer-routing fix and the recent Backhaul, VXLAN/Geneve allocation, and mesh improvements into the practical test release.

## avaTUN 0.2.24

- Install and remove table 220 inner-peer routes for managed IPsec profiles so unbound traffic selects the tunnel source address and matches XFRM policies.
- Verify the route fix with Finland↔Germany ESP-over-UDP and three successful pings in each direction.

## avaTUN 0.2.23

- Automatically allocate VXLAN/Geneve interfaces, conflict-free private /30 addresses, unique VNIs and UDP ports after inspecting both servers.
- Include active network addresses, routes, interfaces, UDP listeners and saved network profiles in central collision checks.

## avaTUN 0.2.22

- Back up and detach managed Backhaul tunnel configs during core upgrades, then restore, validate and restart enabled tunnels transactionally.
- Keep the existing core and manager in place until the replacement is verified; roll back the core and tunnel state if installation fails.

## avaTUN 0.2.21

- Apply neon colors and lighting while keeping the existing layout.

## avaTUN 0.2.20

- Add Mesh map zoom controls and subtle depth shading to tunnel paths.

## avaTUN 0.2.19

- Allow vertical as well as horizontal globe rotation; automatically place server labels to prevent overlaps.

## avaTUN 0.2.18

- Use the supplied equirectangular world map as the overview globe texture.

## avaTUN 0.2.17

- Add a GeoIP globe with server positions and tunnel routes to the overview.

## 0.2.16 · beta17

- Restore strongSwan table 220 routing during IPsec profile startup and bind speed tests to the actual inner source IP.
- Allocate unique TUN names, private inner addresses and health ports for each Backhaul IPX pair.
- Skip rollback deletion when a failed endpoint was never registered, preserving the original startup error.
- Verified german-core to toger-1 IPsec ping and bidirectional iperf3, plus simultaneous Finland IPX links to tofin-1 and tofin-2.

## 0.2.15 · beta16

- Real TUN IP links over all Backhaul stream carriers, including TCPMux and TLS/WebSocket variants.
- Central two-endpoint address/interface allocation, paired creation and legacy edit migration.
- Complete reproducible offline core source, namespace ping and HAProxy forwarding checks.

## avaTUN 0.2.14

- Rebuild tunnel edits and restarts as one controller transaction: read and validate both endpoint configs, fully remove both managed endpoints, then create both from scratch with the responder first.
- Explicitly stop/disable the tunnel service and clean leftover interfaces even for inactive/failed units; keep shared service templates and physical interfaces protected. Make L2TP cleanup idempotent and remove IPsec loopback addresses with their actual `/32` prefix.
- Keep saved keys, shared secrets, interface names and internal addresses during restart. Retain interface/address values during native edits unless explicitly changed, and preserve paired WireGuard/OpenVPN credentials.
- Save private recovery journals before teardown and restore both previous endpoint configs on failure. Report incomplete cleanup/rollback rather than silently treating it as success.
- Route web, MTU edits, and Telegram restarts through the coordinated rebuild path for every supported tunnel transport.
- Add HAProxy statistics on `0.0.0.0:18404/stats` and the built-in Prometheus exporter at `/metrics` to every managed HAProxy configuration, including stats-only servers. Keep authentication in private runtime configuration and transfer it to managed nodes during installation.

## avaTUN 0.2.13

- Make only the Telegram resources screen a live per-server card with CPU/RAM/disk/swap meters, upload/download rates, sample age, and 15-second refresh.
- Use the dedicated resources HTML widget where permitted by Telegram. If widget delivery is rejected, refresh the native card automatically in the same message instead.
- Add server paging, pause/resume, ten-minute live sessions, stable server selection, and cancellation on leaving resources. Persist widget query state and keep scoped resource cards restricted to their selected server.

## avaTUN 0.2.12

- Redesign the Telegram bot around native, single-message screens: a compact home, named server/tunnel selectors, scoped details, pagination, timestamps, and consistent back/home/refresh controls.
- Add dedicated server selection for HAProxy, guided forms with cancellation and stale-step protection, escaped HTML display, and automatic conversion of decimal digits to ASCII.
- Persist user-bound callback buttons across restarts and consume operational confirmations atomically. Run confirmed operations in background workers, report partial results, and never replay interrupted mutations.
- Keep HTML widgets as an explicit experiment under settings instead of attempting them during normal navigation. Preserve monitoring, daily reports, GitHub update notifications, and viewer/admin authorization.

## avaTUN 0.2.11

- Replace the permanent global Telegram widget disable flag with a five-minute retry cooldown scoped to each bot token and private chat. Show the actual delivery rejection in the fallback menu and retain manual retry.
- Send a fresh widget when its HTML layout changes, and check both HTML byte and compressed-size limits before delivery.
- Consume fallback operation confirmations once; repair overview refresh and forward cancellation routes, and restore report navigation in the fallback menu.
- Add regression coverage for widget delivery, cooldown expiry, user isolation, layout upgrades, and fallback confirmations. Telegram may still reject widget delivery with `INPUT_MEDIA_WIDGET_NOT_ALLOWED`; these changes do not grant Telegram-side permissions.

## avaTUN 0.2.10

- Gracefully handle Telegram rejecting HTML widgets for this bot and keep `/start` usable with an inline-keyboard interface.
- Preserve server, tunnel, resource, forwarding, update, and confirmation flows in the fallback interface; allow an admin to retry widget delivery later.

## avaTUN 0.2.9

- Consolidate Telegram bot navigation into one interactive HTML widget message for overview, servers, tunnels, resources, forwards, reports, audit, and updates.
- Add server-scoped tunnel and resource views, safer confirmation flows, and in-widget status refreshes.
- Queue GitHub update checks without blocking Telegram widget queries; run tunnel, forwarding, and panel update operations in the background and publish their result back into the widget.
- Keep text-based prompts for HAProxy rule creation and editing, where the widget interface has no text-entry field.

## avaTUN 0.2.8

- Increase separation between tunnel labels for parallel links in the Mesh map.

## avaTUN 0.2.7

- Add a manual per-tunnel iperf3 speed test button in the tunnel list; rerunning updates the saved bidirectional throughput result.

## avaTUN 0.2.6

- Install iperf3 with the server installer and automatically measure TCP throughput in both directions after tunnel creation or reconfiguration.
- Show the latest approximate throughput in the tunnel table and cards.
- Show Backhaul TUN/IPX internal addresses read from the actual TUN interfaces, and use those addresses for reachability checks.

## avaTUN 0.2.5

- Generate tunnel-specific default IKE identities so multiple IPsec tunnels between the same servers cannot select the wrong CHILD_SA traffic selectors.
- Install StrongSwan's extra crypto and charon plugin bundles so `ctr`, `ccm`, and `curl` are available on minimal installs and upgrades.
- Report `TS_UNACCEPTABLE` and `NO_PROPOSAL_CHOSEN` directly, without optional plugin warnings obscuring the cause.

## avaTUN 0.2.4

- Allocate a random free WireGuard interface after checking both servers, use it on both peers, and preserve saved interfaces when editing. The form no longer accepts a physical interface name for WireGuard.

## avaTUN 0.2.3

- Disable StrongSwan `start_action` for generated IPsec children because the network profile explicitly invokes `swanctl --initiate`; this prevents a duplicate CHILD_SA request from tearing down an otherwise established tunnel.

## avaTUN 0.2.2

- Detect the resolved StrongSwan library path and add narrowly scoped AppArmor read/map rules for VICI, libstrongswan, and StrongSwan plugins before enabling `strongswan.service`.

## avaTUN 0.2.1

- Create and update paired IPsec tunnels with the responder endpoint first, then start the initiator after the responder configuration is loaded.

## avaTUN 0.2.0
- Fix remote tunnel allocation, resource, network inventory, and MTU requests to call helpers through the imported tunnel manager module.

## avaTUN 0.1.70
- Add a GitHub panel updater action to the central server row and a visible admin notice when a newer version is available.
- Check GitHub after admin login and refresh the stored update status while the panel remains open; retain the six-hour systemd check.

## avaTUN 0.1.69
- Read each managed tunnel's local and peer IP from its actual network interface and send health pings through that interface.
- Probe IPsec using its configured inner addresses and source IP because these profiles assign addresses to loopback instead of creating a tunnel device.
- Show tunnel interface addresses and ping state in the Mesh map without assuming every link is a TUN device.

## avaTUN 0.1.68
- Install and activate the VICI-capable `charon-systemd` daemon required by `swanctl`; stop the legacy starter unit when migrating.
- Fail with a direct VICI socket error instead of exposing `swanctl` usage output.

## avaTUN 0.1.67
- Make managed HAProxy TCP forwards listen on `127.0.0.1` in addition to their selected address. IPv4 wildcard and loopback listeners already cover localhost.
- Reject ambiguous duplicate localhost ports when multiple managed rules would claim the same loopback port.
- Point the GitHub bootstrap installer at the canonical `main` branch.

## avaTUN 0.1.66

- Include Backhaul TUN/IPX links in the forwarder when their peer address is known or can be supplied, and validate that the backend route uses the selected IPX interface.

## avaTUN 0.1.65

- Prefer free L2TPv3 UDP ports outside each server's ephemeral range, and fall back to an unbound port when the OS reserves the entire usable range.

## avaTUN 0.1.64

- Automatically allocate conflict-free L2TPv3 tunnel/session IDs and UDP ports after inspecting both servers; keep the chosen values while editing.
- Install the StrongSwan systemd daemon when neither supported service exists and start the unit actually installed on each server.

## avaTUN 0.1.63

- Automatically generate and share a strong PSK for paired IPsec tunnels, derive default IKE identities from each peer's outer IP, and keep existing secrets when editing.

## avaTUN 0.1.62

- Allow `AF_NETLINK` in the panel service sandbox so IP address and route inspection works inside systemd.

## avaTUN 0.1.61

- Include the retrying `ip` JSON helper in delegated code so the central panel can read allocation snapshots from managed servers.

## avaTUN 0.1.60

- Retry transient `ip` network-snapshot failures and include the command's stderr when the address or route dump still fails.

## avaTUN 0.1.59

- Check the `main` branch for panel self-updates so published releases are visible to the central panel updater.

## avaTUN 0.1.58

- Prepare the kernel modules used by WireGuard, TUN/OpenVPN, GRE, IPIP, GRETAP, Geneve, VXLAN, SIT, FoU, L2TPv3, and IPsec/ESP during installation and after reboot.
- Load each tunnel type's required modules before starting its native profile.

## avaTUN 0.1.57

- Load required FoU/IP tunnel modules before starting native FoU profiles and configure them for automatic loading after reboot.
- Include the exact failing `ip` command in RTNETLINK errors to make tunnel startup failures diagnosable.

## avaTUN 0.1.56

- Read live addresses from each tunnel interface on both endpoints, show the internal pair on the mesh, and ping the peer IP through that TUN interface.
- Stop treating Backhaul IPX outer addresses as tunnel health targets; probe IPX using the live TUN peer address instead.

## avaTUN 0.1.55

- Show Backhaul TUN/IPX outer endpoint IPs on mesh links and probe the configured peer IP from the configured local source IP.
- Show inner TUN peer IPs and their measured ping on mesh links; make missing or incomplete address pairs explicit.

## avaTUN 0.1.54

- Show the auto-assignment behavior in native tunnel forms and make allocator-owned interface and inner IP fields read-only where the central panel assigns them.
- Convert Unicode decimal digits to ASCII English digits in typed fields and visible UI text, including pasted content and dynamically rendered values.

## avaTUN 0.1.53

- Allocate a random unused native tunnel interface and a conflict-free private /30 after checking addresses, routes, and managed tunnels on both selected servers.
- Route native tunnel create and edit through a coordinated two-server operation with rollback if either endpoint fails.
- Fix native GRE stop/update ordering so an existing interface is removed before the start-time collision check; verify cleanup before replacing a profile.
- Report the actual non-RFC1918 prefix in routing validation errors.

## avaTUN 0.1.52

- Read native tunnel interface names from the native form so the Backhaul `eth0` field cannot be used for GRE/IPIP devices.
- Validate Backhaul IPX outer IPv4 addresses before submitting the tunnel and reject CIDR suffixes with a clear form error.
- Reject occupied native tunnel interface names, avoid Apport crash-report noise, and include the actual `ip`/`tc` error in the service journal.
- Make the panel update action always visible and have one click check GitHub before offering installation; simplify the Telegram update confirmation to one install action.

## avaTUN 0.1.51

- Hide the panel public IP field unless the central panel server is a tunnel endpoint, and leave it blank until supplied.
- Keep Telegram server, tunnel, and resource status in native message widgets; log Telegram's reason when widget delivery falls back.

## avaTUN 0.1.50

- Ignore stale TUN/TCP peer addresses in Backhaul IPX requests; IPX uses only the configured outer IP addresses.

## avaTUN 0.1.49

- Include `github-update.py` in managed-server bootstrap bundles so slave installers receive every file referenced by the installer.

## avaTUN 0.1.48

- Every installer run stops Backhaul services, removes previous installed Backhaul cores and manager entry points, installs the manifest-verified bundled core, and restarts previously active managed tunnels while preserving tunnel configs and state.
- First-time Telegram settings now create the missing bot configuration and a dedicated internal panel account automatically; saving valid bot credentials enables the bot service.
- GRE and other native network profiles start through a non-blocking systemd request and remain registered while network dependencies are still activating, instead of being rolled back by a 12-second wait timeout.
- A six-hour GitHub version checker reports new versions in the panel and Telegram; admins can review and confirm a background update from either interface.

## avaTUN 0.1.47

- Bootstrap missing Backhaul manager state only when canonical managed configs/units are absent, then replace the mismatched core with the manifest-verified build using its exact current checksum as the guard.

## avaTUN 0.1.46

- Repair legacy Backhaul manager states that lack a recorded core checksum by reconciling against the bundled manifest-verified core with an exact current-checksum guard.

## avaTUN 0.1.45

- Repair managed Backhaul installations whose installed core checksum no longer matches manager state. The installer now replaces it only with the bundled, manifest-verified core and passes the exact current checksum as a guard; managed tunnels are preserved or the update fails safely.

## avaTUN 0.1.44

- Fixed Backhaul repair on partially installed servers: when the verified Backhaul core exists but the manager command is missing, installation restores only the missing manager entry point and preserves the existing core, state, tunnel configs, and service units.

## avaTUN 0.1.40

- هماهنگ‌کردن نقشهٔ «شبکه در یک نگاه» با نقشهٔ Mesh؛ استفاده از تصویرهای SVG سرورها، پس‌زمینه، مسیرهای رنگی و نشان وضعیت یکسان.
- نمایش نام، IP، تعداد تونل و آنلاین‌بودن هر سرور در نقشهٔ نمای کلی.

## avaTUN 0.1.39

- Added a live Telegram server status widget with online state, tunnel count, installed version, service status, selected server details, and 15-second refresh.
- Renamed the Telegram home buttons to “وضعیت تونل‌ها” and “فورواردر”.

## avaTUN 0.1.38

- Added Telegram live widgets for tunnel health and HAProxy forwarding rules, with periodic refresh and status summaries.
- Added admin-only HAProxy and TCP port-forward management in Telegram: guided create/edit, listener and backend ports, balancing method, PROXY protocol, health-check options, tunnel pool selection, weights, and primary/backup roles.
- Added confirmation before deleting a forwarding rule; enable/disable remains a confirmed action. All changes use the panel's validated forwarding API and are recorded in the operation audit.
- Added `/haproxy` and `/tunnel_list` bot commands and updated the documented Telegram controls.

## avaTUN 0.1.37

- رفع خطای نحوی در اسکریپت پنل که ارسال فرم ورود را متوقف می‌کرد.
- فرم ورود در حالت خطای جاوااسکریپت هم گذرواژه را داخل نشانی مرورگر نمی‌فرستد.

## avaTUN 0.1.36

- Fixed panel loading when legacy URL query parameters are present; credential query parameters are cleared by redirect.
- Redacted password, token, and secret query values from API access logs.

## avaTUN 0.1.35

- Fixed the Telegram live resource widget so CPU, RAM, disk, and swap percentages use the correct metric keys instead of rendering as zero.

## avaTUN 0.1.34

- منابع سرورها اکنون به شکل ویجت تعاملی و زنده داخل پیام خصوصی ربات تلگرام نمایش داده می‌شوند.
- CPU، RAM، دیسک، Swap و نرخ دانلود/آپلود در یک کارت جمع‌وجور برای هر سرور نمایش داده می‌شود؛ پیمایش بین سرورها، تازه‌سازی دستی و تازه‌سازی خودکار ۱۵ ثانیه‌ای اضافه شد.
- درخواست‌های ویجت به کاربران مجاز و چت خصوصی محدود شده‌اند و پاسخ خطا نیز در همان ویجت نمایش داده می‌شود.

## avaTUN 0.1.33

- Corrected Python 3.14 HTTPS handler construction for the IPv4-only Telegram transport and verified bot startup behavior.

## avaTUN 0.1.32

- Fixed slow Telegram bot responses on IPv4-only servers by forcing Telegram HTTPS connections to use IPv4 instead of waiting for unreachable IPv6 routes.
- Replaced the Telegram settings token suffix with a live service/bot readiness indicator and a short post-save status check that reports startup, ready, retrying, or stopped state.
- Added a secret-free bot health status file and exposed its freshness and systemd state through the restricted settings API.

## avaTUN 0.1.31

- The Telegram bot now reads network snapshots from one authenticated panel endpoint and processes waiting updates before monitoring work, reducing command response delay.
- Added admin-only panel settings for replacing the Telegram bot token and editing numeric Telegram administrator IDs. Tokens are never returned to the browser; saving writes the protected server config and restarts the bot service.
- Extended the restricted privileged helper only for validated Telegram settings, with atomic config replacement and preserved viewer/panel credentials.

## avaTUN 0.1.30

- Added a private Telegram management bot with server resources, tunnel status, confirmed two-sided operations, live diagnostics, and HAProxy controls.
- Added persistent outage/recovery and high-resource alerts, daily reports, viewer/admin roles, and operation audit records.
- Added a monitored tunnel snapshot API and reversible HAProxy rule enable/disable actions.
- Included the optional Telegram service in the installer.

## avaTUN 0.1.29

- Connected Mesh cables underneath the server SVGs so transparent margins cannot leave detached endpoints.

## avaTUN 0.1.28

- Tightened Mesh node hit areas, label spacing, and cable anchors around the SVG artwork.
- Backfilled GeoIP locations for existing servers so Iranian nodes use the Iran SVG.
- Persisted automatic/manual GeoIP choices and retried unresolved lookups in the background.

## avaTUN 0.1.27

- Replaced Mesh server artwork with the supplied central, Iran, and abroad SVG designs.
- Added static SVG asset serving for the Mesh map.

## avaTUN 0.1.26

- Switched GeoIP to ipwho.is and added ipapi.co as a fallback provider, so a rate limit or outage from one service does not immediately disable country detection.

## avaTUN 0.1.25

- Reduced the Mesh server illustrations and their status indicators to half size while keeping server labels readable.
- Added automatic Iran / abroad classification using GeoIP when adding or editing managed servers; administrators can turn detection off and select the map location manually.
- GeoIP checks resolve hostnames to a public IP and cache country results for one hour. Failed lookups keep the selected location and show the reason.

## avaTUN 0.1.24

- Uses the supplied HTML/CSS server structures and exact 3D transforms inside the SVG Mesh canvas, including the central server indicators and all regional tier details.
- Keeps the map connectors and node interactions in SVG while isolating the embedded artwork styles from the rest of the dashboard.

## avaTUN 0.1.23

- Replaced hand-drawn server SVGs with the supplied HTML/CSS isometric tier designs for Iran, overseas, and central servers.

## avaTUN 0.1.22

- Corrected the SVG LED matrix projection so it stays inside each server roof, tightened the tier spacing to match the supplied perspective, and moved node labels below the server artwork.

## avaTUN 0.1.21

- Matched the central server icon to the supplied four-tier isometric design, with a roof LED matrix, cyan and amber indicators, and amber side bars.

## avaTUN 0.1.20

- Matched the Iran and overseas server icons to the supplied isometric designs: compact three-tier Iran appliance and larger four-tier overseas rack, both with an 8×8 roof matrix and illuminated side details.

## avaTUN 0.1.19

- Refined Mesh server icons: six-layer rack for overseas nodes, compact three-layer appliance for Iran, and anchored status indicators.

# Changelog

## avaTUN 0.1.18

### Isometric Mesh server artwork

- Replaced flat Mesh server cards with custom isometric SVG server illustrations. The central panel uses a compute cube, servers in Iran use a compact three-layer appliance with a top indicator grid, and servers abroad use a taller rack.
- Added a persistent Iran / abroad location selector when adding or editing a managed server; the Mesh map uses this metadata to choose its illustration.
- Kept nodes selectable and draggable, retained tunnel labels and click-to-edit links, and recalculated link anchors for the illustrated node sizes.
- Moved the saved Mesh layout to a new version so the new artwork opens in a clean, readable arrangement while remaining manually movable.

## avaTUN 0.1.17

### Explicit Backhaul IPX source address controls

- Added an opt-in source-address toggle for raw IPX tunnels.
- Added separate source IP fields for server A and server B; each side's expected peer source is paired automatically when building the opposite endpoint.
- Existing IPX tunnel edit forms translate the saved source settings into the new A/B fields.
- The source-address inputs remain limited to raw IPX, and enabling the feature requires at least one source IP.

## avaTUN 0.1.16

### Backhaul transport choices

The tunnel form now exposes the independently rebuilt Backhaul core's supported carrier modes: TUN, TCP, TCP Mux, X-TCP Mux, WebSocket, WebSocket TLS, WebSocket Mux, WebSocket TLS Mux, X-WS Mux, and AnyTLS. The selected carrier is shown with each tunnel.

For TUN, the form distinguishes the normal TCP encapsulation (with a paired private tunnel address and health interface) from raw IPX encapsulation. IPX exposes the six available profiles: ICMP, IPIP, UDP, TCP, GRE, and BIP. The form only displays the settings relevant to the selected mode.

### Paired configuration and controls

- Direct and reverse creation now build matching client/server configurations, including peer address reversal and paired raw-source settings.
- TCP modes expose port mapping and connection-pool controls; relevant server modes expose UDP acceptance and PROXY protocol settings.
- WebSocket modes expose the edge destination, while TLS modes expose server certificate/key and client CA/SNI settings on the appropriate side.
- IPX secrets are generated and validated as a 32-byte base64 PSK. Other Backhaul modes continue to use a shared token.
- Privileged tunnel creation validates carrier names, ports, IP addresses, interface names, pool sizes, and mode-specific fields before invoking the manager.
- Existing Backhaul entries remain compatible: tunnels without an explicit carrier continue to be treated as TUN.

### Validation

The deployed Backhaul 0.1.0 core accepted all 33 generated configuration checks on the central test server: nine non-TUN carriers in both roles (18), TCP with UDP acceptance (1), TUN/TCP in both roles (2), and six IPX profiles in both roles (12). These are configuration-validation checks; they do not claim a live traffic-path test for every carrier/profile.
