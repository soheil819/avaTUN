# طرح معماری سامانه مدیریت تونل لینوکس

## وضعیت اولیه

مخزن کاری فعلی خالی است؛ بنابراین این سند نقطه شروع طراحی است. هدف، ساخت سامانه‌ای برای Ubuntu LTS و Debian stable روی Linux amd64/arm64 است. توسعه روی macOS امکان‌پذیر است، اما اعتبارسنجی عملی درایورها و نصب باید روی Linux انجام شود.

در این سامانه، Backhaul معمولی از طریق مدیر Backhaul نصب‌شده روی هر endpoint اجرا می‌شود. قابلیت‌ها و گزینه‌های پنل باید با همان نسخهٔ معمولی سازگار باشند؛ قابلیت اختصاصی یا تغییریافته‌ای به آن نسبت داده نمی‌شود.

## معماری پیشنهادی

برای کم‌وابستگی و توزیع آسان، هسته، REST API و CLI در Go پیاده می‌شوند؛ رابط وب React + TypeScript به فایل‌های ایستا کامپایل می‌شود. SQLite با مهاجرت‌های نسخه‌دار نگهداری پیکربندی، کاربران، رویدادها و دادهٔ پایش را برعهده دارد. سرویس HTTP با دسترسی loopback یا Unix socket اجرا می‌شود. اجرای دستورات ممتاز تنها از طریق درایورهای محدود و با آرگومان‌های جداگانه انجام می‌گیرد؛ ورودی کاربر هرگز به shell الحاق نمی‌شود.

```text
Browser ── HTTPS ── API/Auth ─┐
CLI ────── Unix socket/API ────┼── Core + SQLite
                              ├── Protocol drivers ── iproute2 / strongSwan
                              ├── Backhaul adapter ── regular Backhaul manager
                              └── Monitor ── rtnetlink / procfs / systemd journal
```

مدل چرخهٔ عمر مشترک درایورها: `Validate`, `Dependencies`, `Plan`, `Apply`, `Start`, `Stop`, `Delete`, `Status`, `Diagnose`. عملیات `Plan` پیش از تغییر، اختلاف‌ها و اثر مسیریابی را نشان می‌دهد. هر Apply دارای snapshot و rollback محدود به همان منابع مدیریت‌شده است. فایل‌های بیرونی و تنظیمات نامرتبط سیستم دستکاری نمی‌شوند.

### اجزای اجرایی

- `tunneld`: API، احراز هویت، مجری عملیات، صف کار و پایش؛ کاربر اختصاصی غیر root.
- `tunnel-privd`: helper کوچک root با API محلی و allowlist عملیات/فایل‌ها؛ تنها جزء دارای capabilityهای لازم برای netlink و systemd است.
- `tunnelctl`: کلاینت CLI با دستورات غیرتعاملی و منوی تعاملی.
- پنل وب ایستا: از همان API و مدل وضعیت CLI استفاده می‌کند.
- `systemd`: واحدهای سرویس برای دو daemon، و واحدهای اختصاصی برای هر نمونهٔ Backhaul؛ تونل‌های kernel-native با reconciler زمان‌بندی‌شده مدیریت می‌شوند.

## نگاشت پروتکل‌ها به پیاده‌سازی لینوکس

نسخهٔ دقیق ماژول و قابلیت باید در میزبان هدف با `modprobe -n`, `/sys/module`, `ip -Version` و ایجاد آزمایشی در network namespace بررسی شود؛ نام ماژول‌ها به‌تنهایی تضمین پشتیبانی نیست.

| نوع | مسیر اجرا و وابستگی اصلی | مرز/محدودیت |
|---|---|---|
| GRE | `ip link ... type gre` / `ip tunnel`; `ip_gre` | تونل L3؛ کلید GRE به معنای رمزنگاری نیست. |
| GRE Key | همان GRE با کلید ورودی/خروجی | شناسهٔ demultiplexing است، نه احراز هویت. |
| GRETAP | `ip link ... type gretap`; `ip_gre` | L2؛ برای bridge؛ حلقه و MTU باید مدیریت شود. |
| Geneve | `ip link ... type geneve`; `geneve` | معمولاً UDP؛ گزینه‌های metadata وابسته به kernel/iproute2. |
| VXLAN | `ip link ... type vxlan`; `vxlan` | VNI و پورت؛ multicast/learning وابسته به طراحی شبکه. |
| IPIP | `ip tunnel ... mode ipip`; `ipip` | IPv4 داخل IPv4؛ رمزنگاری ندارد. |
| 6to4 | SIT با آدرس‌دهی 2002::/16 | فناوری انتقال قدیمی و وابسته به relay/مسیریابی؛ پیش‌فرض غیرفعال و هشداردهنده. |
| ISATAP | SIT/ISATAP semantics و route/neighbor مناسب | استقرار محدود؛ صرف ایجاد SIT معادل پیکربندی کامل ISATAP نیست. |
| ERSPAN | GRE ERSPAN type II/III عبر iproute2/kernel | فقط اگر kernel و iproute2 هر دو نوع و پارامترها را پشتیبانی کنند؛ capture/monitoring نیازمند تنظیم جداست. |
| L2TPv3 | `ip link ... type l2tp` و `ip l2tp`; `l2tp_eth`/`l2tp_ip` | شناسه‌های session/tunnel و کنترل peer باید دقیقاً جفت شوند؛ L2TPv3 خودش رمزنگاری نیست. |
| IKEv2/IPsec | strongSwan `charon-systemd`, `swanctl`, kernel XFRM | PSK/گواهی؛ الگوریتم‌ها از capabilities واقعی strongSwan/kernel انتخاب شوند. |
| ESP خام | XFRM state/policy و پروتکل IP 50 | SA کلید/پارامتر نیاز دارد؛ برای NAT نامناسب؛ رابط سادهٔ عمومی ارائه نشود مگر پیکربندی کامل SA. |
| ESP over UDP | strongSwan NAT-T / UDP encapsulation | NAT-T جزئی از SA/IPsec است، نه تونل عمومی UDP مستقل. |
| GRE/IPIP/SIT over FoU | `ip fou` و `encap fou` در tunnel | پشتیبانی بر اساس kernel/iproute2؛ UDP port و mode باید همسان باشد. |
| Backhaul TUN | adapter برای `backhaul-manager` نصب‌شده | فقط گزینه‌های مستند و پشتیبانی‌شدهٔ مدیر Backhaul معمولی استفاده شوند. |

ابزارهای پایه: `iproute2`, `systemd`, `nftables` (فقط در صورت درخواست قواعد مدیریت‌شده), `strongSwan` برای IPsec، `ethtool` اختیاری برای شمارنده‌های NIC، `ca-certificates`. برای TUN: `/dev/net/tun` و دسترسی مناسب. نصب‌کننده باید OS/معماری/kernel را تشخیص دهد و وابستگی‌ها را قبل از تغییر نمایش دهد.

## امنیت و دسترسی ممتاز

پنل عمومی root اجرا نمی‌شود. ورود با Argon2id، session امن، CSRF برای cookie-auth، محدودسازی نرخ، نقش administrator/operator/read-only و audit log انجام می‌شود. secretها با مجوز فایل محدود و ترجیحاً systemd credentials نگهداری می‌شوند؛ در API/CLI/log هرگز چاپ نمی‌شوند. helper ریشه فقط پیام‌های ساختاریافته از socket با مجوز گروه محدود می‌پذیرد و executable/عملیات را از allowlist انتخاب می‌کند. قبل از route یا firewall change، مسیر SSH/API و routeهای endpoint کنترل و rollback با زمان انقضا آماده می‌شود.

## API و سازگاری وضعیت

API نسخه‌دار `/api/v1`: منابع `tunnels`, `plans`, `jobs`, `events`, `metrics`, `auth`. تغییرات طولانی به job با شناسه تبدیل می‌شوند؛ SSE برای وضعیت و لاگ‌های جدید. CLI همان endpointهای API را صدا می‌زند؛ هیچ فایل وضعیت موازی ندارد. پیکربندی canonical در SQLite است و فایل‌های تولیدی دارای مالکیت/هش هستند.

## پایش واقعی

وضعیت kernel از netlink و `ip -j`; وضعیت سرویس از systemd D-Bus یا `systemctl show`; Backhaul از manager/status و journal مستند بسته خوانده می‌شود. نرخ ترافیک از counterهای رابط در دو نمونه زمانی محاسبه می‌شود. وضعیت `UP` رابط از سلامت end-to-end جداست؛ ping/latency فقط وقتی قابل تعریف و مجاز باشد اجرا می‌شود. سابقهٔ سبک در SQLite با retention قابل تنظیم ذخیره می‌شود.

## مراحل پیاده‌سازی

1. **اسکلت و قراردادها:** مدل داده، مهاجرت SQLite، پیکربندی، structured logging، خطاها و lifecycle interface.
2. **هستهٔ ایمن:** API محلی، helper ممتاز محدود، plan/rollback، تشخیص وابستگی و مدیریت job.
3. **درایورهای پایه:** GRE/GRETAP، IPIP، VXLAN، Geneve؛ تست‌های unit و namespace روی Linux.
4. **CLI و سرویس‌ها:** دستورات install/create/list/status/start/stop/logs/diagnose و systemd.
5. **پروتکل‌های تخصصی:** SIT/6to4/ISATAP، ERSPAN، L2TPv3، FoU، سپس strongSwan با تست‌های جدا و هشدار محدودیت.
6. **Backhaul adapter:** ابتدا بررسی hash، معماری، مجوز، `--help` و قرارداد مستند همین بسته؛ سپس ساخت/اعتبارسنجی config و سرویس instance. هیچ flag/config ناشناخته حدس زده نمی‌شود.
7. **پنل:** ورود، dashboard دادهٔ واقعی، wizardهای متناسب با پروتکل، log/metrics، Persian/English و RTL.
8. **استقرار/سخت‌سازی:** installer/uninstaller، backup/restore، مستندات عملیاتی، آزمون‌های Debian/Ubuntu در VM و پذیرش روی VPS.

## گام بعدی اجرایی

پیش از پیاده‌سازی، باید آرشیوهای موجود را بدون اجرای installer بررسی و استخراج امن انجام داد: manifest/hash، سورس manager، CLI و قرارداد تنظیمات Backhaul. سپس قراردادهای هسته و اسکلت Go در همین مخزن ایجاد می‌شوند. محیط فعلی macOS است و مقصد Linux هنوز در دسترس این workspace نیست؛ بنابراین عملیات واقعی kernel و تست integration تا اجرای پروژه روی Linux قابل ادعا نیست.

## منابع فنی

- [Linux kernel: VXLAN](https://cdn.kernel.org/doc/html/latest/networking/vxlan.html)
- [Ubuntu ip-tunnel manual](https://manpages.ubuntu.com/manpages/resolute/man8/ip-tunnel.8.html)
- [strongSwan: Introduction to IKEv2/IPsec](https://docs.strongswan.org/docs/latest/howtos/introduction.html)
- [strongSwan: Installation and swanctl/charon-systemd](https://docs.strongswan.org/docs/latest/install/install.html)


## وضعیت اجرای نسخهٔ آزمایشی

تا ۱۰ نوامبر ۲۰۲۶، preview روی هر دو میزبان Ubuntu نصب شده است. داشبورد فقط روی loopback اجرا می‌شود. عملیات Backhaul TUN از API احراز‌شده به helper با socket محلی و allowlist محدود می‌رود. helper، آدرس‌های خصوصی جفت، subnet یکسان، نام رابط و MTU را اعتبارسنجی می‌کند. در صورت نیاز به دو میزبان، نمونهٔ `server` و `client` جداگانه ساخته می‌شوند؛ شناسه/secret/interface هماهنگ و local/peer IPها معکوس هستند. دو تونل TUN فعال روی سرورها آزموده شده‌اند؛ این مرحله هیچ‌یک از درایورهای GRE/IPIP/Geneve/VXLAN/IPsec را پیاده‌سازی نمی‌کند.
