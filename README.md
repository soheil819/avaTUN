# avaTUN | پنل مدیریت تونل و سرور لینوکس

**نسخهٔ پایدار: 2.0.6**

avaTUN پنل وبی برای مدیریت تونل‌های لینوکس و سرورهای راه‌دور است. از طریق SSH سرورها را اضافه و مدیریت کنید، تونل‌های دوطرفه بسازید، سلامت و منابع را ببینید، توپولوژی را روی نقشهٔ Mesh دنبال کنید و ترافیک TCP را با HAProxy از مسیر تونل‌های خروجی هدایت کنید. ربات تلگرام نیز به‌صورت اختیاری در دسترس است.

**زبان‌ها:** [پارسی](#پارسی) · [English](#english) · [简体中文](#简体中文) · [Русский](#русский) · [Türkçe](#türkçe)

---

## پارسی

### قابلیت‌ها و تونل‌های پشتیبانی‌شده

avaTUN پنل وبی برای مدیریت تونل‌ها و سرورهای لینوکس است. سرورها از طریق SSH اضافه می‌شوند و پنل می‌تواند نصب و به‌روزرسانی avaTUN و مدیریت چرخهٔ عمر تونل‌ها را روی آن‌ها انجام دهد. نقشهٔ Mesh توپولوژی و ارتباط سرورها را نمایش می‌دهد؛ برای نمایش یک لینک، شناسهٔ تونل باید در هر دو سرور یکسان باشد. پایش زندهٔ منابع، سلامت لینک با بررسی دوره‌ای ICMP و ربات تلگرام اختیاری هم فراهم است.

انواع تونل: **Backhaul TUN، GRE، IPIP، GRETAP، Geneve، VXLAN، ERSPAN، 6to4، ISATAP، GRE/IPIP/SIT FoU، L2TPv3، حالت‌های IPsec/ESP، WireGuard، OpenVPN و OpenConnect.** نقش هر سرور را می‌توان مستقیم یا معکوس تنظیم کرد. عملیات جفت‌سازی WireGuard، OpenVPN و OpenConnect پیکربندی هماهنگ دو سر، کلید یا گواهی اختصاصی و نشانی‌های peer را می‌سازد. OpenConnect بر ocserv متکی است و برای لینک نقطه‌به‌نقطه از جفت نشانی ثابت /31 استفاده می‌کند. ERSPAN ترافیک را آینه می‌کند و در پنل فقط به‌صورت مانیتورینگ نمایش داده می‌شود، نه لینک IP دوطرفه.

### اتصال سرورها و Port Forwarding

سرورهای لینوکسی را با دسترسی SSH به پنل اضافه کنید. هنگام ثبت اولیه، گذرواژهٔ SSH می‌تواند فقط برای ساخت کلید اختصاصی همان سرور استفاده شود و سپس دور انداخته می‌شود؛ گذرواژه ذخیره نمی‌شود. کلیدهای SSH بارگذاری‌شده یا ساخته‌شده با مجوز 0600 در مسیر دادهٔ کنترلر نگه‌داری می‌شوند؛ در نصب سرویس، مسیر پیش‌فرض /var/lib/tunnelmgr/ssh-keys است. عامل سلامت هر ده ثانیه peer را از طریق رابط تونل ping می‌کند.

صفحهٔ Port Forwarding شنونده‌های **TCP** را با **HAProxy** روی سرور پنل مدیریت می‌کند. HAProxy را روی کنترلر نصب کنید، سپس یک یا چند لینک تونل محلی را به‌عنوان مسیر backend برگزینید؛ IP تونلی peer مقصد backend می‌شود. وزن‌دهی، الگوریتم‌های leastconn، roundrobin و چسبندگی به مبدأ، همراه با بررسی سلامت TCP پشتیبانی می‌شوند. برنامهٔ مقصد باید روی IP تونلی peer یا همهٔ رابط‌ها گوش کند. این قابلیت فعلاً به میزبان‌های LAN پشت peer یا سرویس‌های UDP دلخواه فوروارد نمی‌کند.

برای لینک دوطرفه، نقطهٔ پایانی را روی هر سرور جداگانه بسازید و در سمت مقابل نشانی‌های محلی/peer و شناسه‌های peer را برعکس وارد کنید. نقشهٔ Mesh یال را وقتی نشان می‌دهد که شناسهٔ تونل یکسان در هر دو سرور موجود باشد.

### نصب سریع روی Debian یا Ubuntu

فرمان زیر آخرین نسخهٔ پایدار را از GitHub می‌گیرد. اسکریپت، پیش‌نیازهای بررسی را آماده می‌کند و پیش از اجرای بسته، attestation امضاشدهٔ GitHub Actions را تأیید می‌کند:

```sh
curl -fsSL https://raw.githubusercontent.com/soheil819/avaTUN/main/install.sh | sudo bash
```

نشانی پنل و اطلاعات ورود اولیه در پایان نصب در ترمینال نمایش داده می‌شوند. اگر Swap فعال موجود نباشد، نصب‌کننده Swap پایدار ۵۱۲ مگابایتی می‌سازد. پورت پیش‌فرض پنل 8765 است. برای نصب از checkout دستی:

```sh
git clone https://github.com/soheil819/avaTUN.git
cd avaTUN
sudo bash scripts/install-from-github.sh
```

برای اجرای محیط محلی از سورس:

```sh
python3 tunnelmgr/tunnelctl.py init
python3 tunnelmgr/tunnelctl.py account create admin --role admin
./scripts/run-local.sh
```

### HTTP، HTTPS و امنیت

پنل پس از نصب با HTTP قابل‌استفاده است و تونل SSH برای دسترسی به پنل الزامی نیست. برای HTTPS، دامنه و گواهی Let's Encrypt را از **تنظیمات ← گواهی TLS** پیکربندی کنید. پس از آماده‌شدن گواهی، درخواست‌های HTTP به HTTPS هدایت می‌شوند؛ HSTS و کوکی امن نشست نیز روی TLS فعال‌اند. راه‌اندازی و ورود TOTP به HTTPS نیاز دارد؛ برای صدور و تمدید گواهی، TCP پورت 80 باید در دسترس باشد. گذرواژه‌های حساب با scrypt نمک‌دار ذخیره می‌شوند و نشست مرورگر از کوکی HttpOnly استفاده می‌کند.

نصب‌کننده برای Debian/Ubuntu پیش‌نیازها و بسته‌های موردنیاز قابلیت‌های انتخاب‌شده را آماده می‌کند و اگر UFW فعال باشد، TCP پورت 8765 را باز می‌کند. فایروال ارائه‌دهنده را جداگانه تنظیم کنید. برای تغییر نشانی نمایشی پنل، متغیر PANEL_HOST را پیش از نصب تنظیم کنید. اطلاعات ورود اولیه فقط در ترمینال نمایش داده می‌شوند و گذرواژهٔ تصادفی در فایل متنی ذخیره نمی‌شود.

### حذف و به‌روزرسانی

برای حذف avaTUN، از پوشهٔ سورس روی همان میزبانی که می‌خواهید پاک‌سازی شود اجرا کنید:

```sh
sudo ./uninstall.sh
```

دامنهٔ حذف را بخوانید و عبارت REMOVE AVATUN را وارد کنید. حذف‌کننده پنل، ربات تلگرام، سرویس‌های تونل محلیِ مدیریت‌شده توسط avaTUN، فایل‌ها، پیکربندی، دادهٔ TLS و وضعیت محلی برنامه را حذف می‌کند؛ تونل‌های فعال مدیریت‌شده روی همان میزبان متوقف می‌شوند. بسته‌های سیستمی یا سرویس‌های مشترکی مانند FRR، HAProxy، Certbot و StrongSwan، قوانین فایروال، Swap، ماژول‌های کرنل، حساب tunnelmgr و نصب‌های سرورهای راه‌دور حذف نمی‌شوند. برای حذف نصب راه‌دور، حذف‌کننده را روی همان سرور اجرا کنید.

بستهٔ نصب شامل هسته و مدیر Backhaul TUN با checksum تأییدشده برای Linux amd64 است. این اجزا در نصب نخست اضافه می‌شوند و به‌روزرسانی‌های بعدی پنل آن‌ها را حفظ می‌کنند. معماری‌های دیگر به بستهٔ هستهٔ Backhaul سازگار نیاز دارند. مجوز و اطلاعیه‌های وابستگی در vendor/backhaul/ قرار دارند. scripts/install-preview.sh برای به‌روزرسانی نصب موجود است و حساب ورود نمی‌سازد؛ به‌روزرسانی سرورهای راه‌دور نیز همان دارایی‌های تأییدشدهٔ Backhaul را منتقل می‌کند. اگر حسابی با طرح توکن قدیمی ساخته شده، گذرواژهٔ آن را یک‌بار بازنشانی کنید:

```sh
python3 /opt/tunnelmgr/tunnelmgr/tunnelctl.py account password admin
```

### استقرار Mesh از CLI

اسکریپت scripts/mesh-deploy.py می‌تواند روی گره‌هایی که از قبل نسخهٔ preview را اجرا می‌کنند، Mesh مبتنی بر Backhaul TUN اعمال کند. اسکریپت از OpenSSH استفاده می‌کند، برای هر لینک secret جدا می‌سازد، پورت‌های آزاد listener و سلامت و نام رابط‌های TUN را انتخاب می‌کند و اگر ساخت یک یال شکست بخورد، endpointهای ساخته‌شده برای همان عملیات را rollback می‌کند.

---

## English

### Overview and supported tunnels

avaTUN is a web panel for Linux tunnels and remote servers. Add servers over SSH, install or update avaTUN on them, and manage tunnel lifecycles from one dashboard. The Mesh map displays server topology and links; the same tunnel ID must exist on both servers for an edge to appear. The panel also provides live resource monitoring, periodic ICMP link health checks, and an optional Telegram bot.

Supported tunnel types: **Backhaul TUN, GRE, IPIP, GRETAP, Geneve, VXLAN, ERSPAN, 6to4, ISATAP, GRE/IPIP/SIT FoU, L2TPv3, IPsec/ESP modes, WireGuard, OpenVPN, and OpenConnect.** Choose a direct or reverse endpoint role. The WireGuard, OpenVPN, and OpenConnect pair actions create coordinated configurations for both ends, including per-side keys or certificates and peer addresses. OpenConnect relies on ocserv and uses a fixed point-to-point /31 address pair. ERSPAN mirrors traffic and is shown as monitor-only, not as a bidirectional IP link.

### Server connections and port forwarding

Add Linux servers through SSH. During enrollment, the SSH password can bootstrap a key dedicated to that server; the password is then discarded and is never stored. Uploaded or generated SSH keys are stored with mode 0600 under the controller data directory. For a service installation, the default path is /var/lib/tunnelmgr/ssh-keys. The health worker pings each configured peer through its tunnel interface every ten seconds.

The **Port forwarding** page manages **TCP** listeners with **HAProxy** on the panel server. Install HAProxy on the controller, then select one or more local tunnel links as backend paths; the peer tunnel IP becomes the destination. Weighted backends, leastconn, roundrobin, source affinity, and TCP health checks are supported. The destination application must listen on the peer tunnel IP or on all interfaces. This feature does not currently forward to LAN hosts behind a peer or balance arbitrary UDP services.

For a two-ended link, create each endpoint on its own server and reverse the local/peer addresses and peer IDs on the other end. The Mesh map draws an edge when both servers contain the same tunnel ID.

### Quick install on Debian or Ubuntu

The command below fetches the latest stable release from GitHub. The installer bootstraps its verification prerequisites and verifies the GitHub Actions signed attestation before running the release package:

```sh
curl -fsSL https://raw.githubusercontent.com/soheil819/avaTUN/main/install.sh | sudo bash
```

The installer prints the panel URL and initial login details at the end. If no active swap is found, it creates a persistent 512 MB swap file. The default panel port is 8765. To install from a manual checkout:

```sh
git clone https://github.com/soheil819/avaTUN.git
cd avaTUN
sudo bash scripts/install-from-github.sh
```

To start a local development instance from source:

```sh
python3 tunnelmgr/tunnelctl.py init
python3 tunnelmgr/tunnelctl.py account create admin --role admin
./scripts/run-local.sh
```

### HTTP, HTTPS, and security

The panel works over HTTP after installation; an SSH tunnel is optional. To enable HTTPS, configure a domain and a Let's Encrypt certificate under **Settings → TLS certificate**. Once the certificate is ready, HTTP requests redirect to HTTPS; HSTS and Secure session cookies are used over TLS. TOTP setup and login require HTTPS. Keep TCP port 80 reachable for certificate issuance and renewal. Account passwords use salted scrypt hashes, and browser sessions use an HttpOnly cookie.

On Debian or Ubuntu, the installer prepares prerequisites and packages needed for the selected features. If UFW is active, it opens TCP port 8765; configure the provider firewall separately. Set PANEL_HOST before installation to change the displayed panel address. Initial login details are printed only in the terminal, and the generated password is not written to a plaintext file.

### Uninstall and updates

Run the uninstaller from the source directory on the host you want to remove avaTUN from:

```sh
sudo ./uninstall.sh
```

Review the removal scope and type REMOVE AVATUN. The uninstaller removes the panel, Telegram bot, avaTUN-managed local tunnel services, application files, configuration, TLS data, and local state. Active tunnels managed on that host are stopped. It preserves system packages and shared services such as FRR, HAProxy, Certbot, and StrongSwan, along with firewall rules, swap, kernel modules, the tunnelmgr account, and installations on remote servers. Run the uninstaller on a remote host to remove its own installation.

The installer bundles the checksum-verified Backhaul TUN core and manager for Linux amd64. They are installed on first setup and preserved during later panel updates. Other CPU architectures need a matching Backhaul core package. License and third-party notices are in vendor/backhaul/. The scripts/install-preview.sh package installer updates an existing installation without creating login credentials. Remote server updates transfer the same verified Backhaul assets. Accounts created under the former token scheme need a one-time password reset:

```sh
python3 /opt/tunnelmgr/tunnelmgr/tunnelctl.py account password admin
```

### CLI Mesh deployment

scripts/mesh-deploy.py can apply a Backhaul TUN Mesh to nodes already running the preview. It uses OpenSSH, creates a secret per link, selects free listener and health-check ports and TUN interface names, and rolls back endpoints created in that operation if an edge fails.

---

## 简体中文

### 项目简介与支持的隧道

avaTUN 是用于管理 Linux 隧道和远程服务器的 Web 面板。通过 SSH 添加服务器，并从同一面板安装或更新 avaTUN、管理隧道生命周期。Mesh 拓扑图展示服务器及链路；只有两端服务器具有相同隧道 ID 时才会显示连接线。面板还提供实时资源监控、周期性 ICMP 链路检测，以及可选的 Telegram 机器人。

支持的隧道类型：**Backhaul TUN、GRE、IPIP、GRETAP、Geneve、VXLAN、ERSPAN、6to4、ISATAP、GRE/IPIP/SIT FoU、L2TPv3、IPsec/ESP 模式、WireGuard、OpenVPN 和 OpenConnect。**端点角色可设置为正向或反向。WireGuard、OpenVPN 和 OpenConnect 的双端创建功能会生成配套配置，并为两端分别创建密钥或证书及 peer 地址。OpenConnect 使用 ocserv，并采用固定的点对点 /31 地址对。ERSPAN 用于镜像流量，因此在面板中只作为监控项显示，不作为双向 IP 链路。

### 服务器连接与端口转发

通过 SSH 添加 Linux 服务器。首次登记时，SSH 密码可用于为该服务器初始化专用密钥，随后密码会被丢弃，不会保存。上传或生成的 SSH 密钥以 0600 权限保存在控制端数据目录中；服务安装的默认目录为 /var/lib/tunnelmgr/ssh-keys。健康检查任务每十秒通过隧道接口 ping 配置的 peer。

**端口转发**页面使用面板服务器上的 **HAProxy** 管理 **TCP** 监听端口。在控制端安装 HAProxy 后，选择一个或多个本地隧道链路作为后端路径；peer 的隧道 IP 将作为目标地址。支持后端权重、leastconn、roundrobin、源地址保持和 TCP 健康检查。目标应用必须监听 peer 隧道 IP 或所有网卡。当前不能转发到 peer 后方的局域网主机，也不支持任意 UDP 服务的负载均衡。

建立双端链路时，分别在两台服务器上创建端点，并在另一端反向填写本地/peer 地址和 peer ID。两端存在相同隧道 ID 时，Mesh 图才会绘制链路。

### Debian 或 Ubuntu 快速安装

下面的命令从 GitHub 获取最新稳定版。安装脚本会准备校验所需的前置工具，并在运行发布包之前验证 GitHub Actions 签名的 attestation：

```sh
curl -fsSL https://raw.githubusercontent.com/soheil819/avaTUN/main/install.sh | sudo bash
```

安装结束时，终端会显示面板地址和初始登录信息。如果系统没有启用 swap，安装脚本会创建持久化的 512 MB swap 文件。面板默认端口为 8765。从手动克隆的代码安装：

```sh
git clone https://github.com/soheil819/avaTUN.git
cd avaTUN
sudo bash scripts/install-from-github.sh
```

从源码启动本地开发实例：

```sh
python3 tunnelmgr/tunnelctl.py init
python3 tunnelmgr/tunnelctl.py account create admin --role admin
./scripts/run-local.sh
```

### HTTP、HTTPS 与安全

安装后面板默认可通过 HTTP 使用；SSH 隧道不是必需的。若要启用 HTTPS，请在 **设置 → TLS 证书** 中配置域名和 Let's Encrypt 证书。证书就绪后，HTTP 请求会跳转到 HTTPS；TLS 下启用 HSTS 和 Secure 会话 Cookie。设置和登录 TOTP 必须使用 HTTPS。签发和续期证书时请保持 TCP 80 可访问。账户密码使用加盐 scrypt 哈希保存，浏览器会话使用 HttpOnly Cookie。

Debian/Ubuntu 安装程序会准备前置依赖及所选功能所需的软件包。若 UFW 已启用，安装程序会开放 TCP 8765；云服务商的防火墙需另行配置。安装前设置 PANEL_HOST 可更改面板显示的地址。初始登录信息只在终端显示，随机密码不会写入明文文件。

### 卸载与更新

在要卸载 avaTUN 的那台主机上，进入源码目录并运行：

```sh
sudo ./uninstall.sh
```

阅读卸载范围并输入 REMOVE AVATUN 确认。卸载程序会移除面板、Telegram 机器人、由 avaTUN 管理的本地隧道服务、应用文件、配置、TLS 数据和本地状态；该主机上由 avaTUN 管理的活动隧道会停止。它不会删除 FRR、HAProxy、Certbot、StrongSwan 等系统软件包或共享服务，也会保留防火墙规则、swap、内核模块、tunnelmgr 账户和远程服务器上的安装。要卸载远程服务器，请在那台服务器上运行其卸载程序。

安装包附带经过 checksum 验证、适用于 Linux amd64 的 Backhaul TUN 核心和管理器。首次安装时会安装它们，之后更新面板时会保留已安装版本。其他 CPU 架构需要匹配的 Backhaul 核心包。许可证和第三方声明位于 vendor/backhaul/。scripts/install-preview.sh 用于更新已有安装，不会创建登录账户。远程服务器更新也会传输相同的已验证 Backhaul 文件。使用旧 token 方案创建的账户需要重置一次密码：

```sh
python3 /opt/tunnelmgr/tunnelmgr/tunnelctl.py account password admin
```

### CLI 部署 Mesh

scripts/mesh-deploy.py 可在已运行 preview 的节点上部署 Backhaul TUN Mesh。它通过 OpenSSH 工作，为每条链路生成独立 secret，选择空闲的监听端口、健康检查端口和 TUN 接口名称；若某条边创建失败，会回滚本次操作已创建的端点。

---

## Русский

### О проекте и поддерживаемые туннели

avaTUN — веб-панель для управления Linux-туннелями и удалёнными серверами. Добавляйте серверы по SSH, устанавливайте и обновляйте на них avaTUN и управляйте жизненным циклом туннелей из одной панели. Карта Mesh показывает топологию и соединения; ребро отображается, если на обоих серверах существует туннель с одинаковым ID. Также доступны мониторинг ресурсов в реальном времени, периодическая проверка канала через ICMP и необязательный бот Telegram.

Поддерживаемые типы туннелей: **Backhaul TUN, GRE, IPIP, GRETAP, Geneve, VXLAN, ERSPAN, 6to4, ISATAP, GRE/IPIP/SIT FoU, L2TPv3, режимы IPsec/ESP, WireGuard, OpenVPN и OpenConnect.** Для конечной точки можно выбрать прямую или обратную роль. Парные операции WireGuard, OpenVPN и OpenConnect создают согласованную конфигурацию для обеих сторон, отдельные ключи или сертификаты и адреса peer. OpenConnect использует ocserv и фиксированную пару адресов /31 для соединения точка-точка. ERSPAN зеркалирует трафик, поэтому отображается только как мониторинг, а не как двунаправленный IP-канал.

### Подключение серверов и перенаправление портов

Добавляйте Linux-серверы по SSH. При первичной регистрации пароль SSH может использоваться для создания отдельного ключа этого сервера; после этого пароль отбрасывается и не сохраняется. Загруженные или созданные SSH-ключи хранятся с правами 0600 в каталоге данных контроллера. При установке службы путь по умолчанию — /var/lib/tunnelmgr/ssh-keys. Проверка состояния каждые десять секунд отправляет ping peer через туннельный интерфейс.

Страница **Port forwarding** управляет TCP-портами прослушивания с помощью **HAProxy** на сервере панели. Установите HAProxy на контроллере и выберите один или несколько локальных туннелей как backend-маршруты; туннельный IP peer становится адресом назначения. Поддерживаются веса backend, алгоритмы leastconn и roundrobin, привязка к источнику и TCP-проверки здоровья. Целевое приложение должно слушать туннельный IP peer или все интерфейсы. Сейчас функция не перенаправляет трафик к хостам LAN за peer и не балансирует произвольные UDP-службы.

Для двустороннего канала создайте endpoint на каждом сервере; на другой стороне поменяйте местами локальный адрес, адрес peer и идентификаторы peer. Карта Mesh нарисует связь, если на обоих серверах есть один и тот же ID туннеля.

### Быстрая установка на Debian или Ubuntu

Команда ниже загружает последний стабильный выпуск с GitHub. Установщик подготавливает инструменты проверки и проверяет подписанную GitHub Actions attestation до запуска пакета выпуска:

```sh
curl -fsSL https://raw.githubusercontent.com/soheil819/avaTUN/main/install.sh | sudo bash
```

В конце установки в терминале отображаются адрес панели и начальные данные входа. Если активный swap отсутствует, установщик создаёт постоянный файл подкачки размером 512 MB. Порт панели по умолчанию — 8765. Установка из вручную клонированного репозитория:

```sh
git clone https://github.com/soheil819/avaTUN.git
cd avaTUN
sudo bash scripts/install-from-github.sh
```

Запуск локального экземпляра из исходного кода:

```sh
python3 tunnelmgr/tunnelctl.py init
python3 tunnelmgr/tunnelctl.py account create admin --role admin
./scripts/run-local.sh
```

### HTTP, HTTPS и безопасность

После установки панель доступна по HTTP; SSH-туннель для доступа не обязателен. Для HTTPS настройте домен и сертификат Let's Encrypt в разделе **Settings → TLS certificate**. После выпуска сертификата HTTP-запросы перенаправляются на HTTPS; при TLS используются HSTS и Secure-cookie для сессии. Настройка и вход через TOTP требуют HTTPS. Для выпуска и продления сертификата должен быть доступен TCP-порт 80. Пароли аккаунтов хранятся в виде salted scrypt-хэшей, браузерная сессия использует cookie HttpOnly.

В Debian/Ubuntu установщик подготавливает системные зависимости и пакеты, нужные выбранным функциям. Если включён UFW, он открывает TCP-порт 8765; брандмауэр провайдера настройте отдельно. Чтобы изменить отображаемый адрес панели, задайте PANEL_HOST до установки. Начальные данные входа выводятся только в терминал, случайный пароль не записывается в открытый текстовый файл.

### Удаление и обновление

Запустите удаление из каталога исходников на том узле, с которого нужно убрать avaTUN:

```sh
sudo ./uninstall.sh
```

Проверьте перечень удаляемых компонентов и введите REMOVE AVATUN. Скрипт удаляет панель, бота Telegram, локальные туннельные службы под управлением avaTUN, файлы приложения, настройки, TLS-данные и локальное состояние. Активные туннели, управляемые на этом узле, будут остановлены. Системные пакеты и общие службы FRR, HAProxy, Certbot и StrongSwan, правила firewall, swap, модули ядра, аккаунт tunnelmgr и установки на удалённых серверах сохраняются. Для удаления удалённой установки запустите её собственный скрипт на том сервере.

В установщик включены проверенные по checksum ядро и менеджер Backhaul TUN для Linux amd64. Они устанавливаются при первом запуске и сохраняются при последующих обновлениях панели. Для других архитектур требуется подходящий пакет ядра Backhaul. Лицензия и уведомления третьих сторон находятся в vendor/backhaul/. Установщик пакетов scripts/install-preview.sh обновляет существующую установку и не создаёт учётные данные. Обновления удалённых серверов передают те же проверенные файлы Backhaul. Для аккаунтов старой схемы токенов требуется один раз сбросить пароль:

```sh
python3 /opt/tunnelmgr/tunnelmgr/tunnelctl.py account password admin
```

### Развёртывание Mesh из CLI

scripts/mesh-deploy.py разворачивает Mesh на базе Backhaul TUN на узлах, где уже работает preview. Скрипт использует OpenSSH, создаёт отдельный secret для каждой связи, выбирает свободные порты прослушивания и проверки здоровья, а также имена интерфейсов TUN. Если создание ребра не удаётся, созданные в этой операции endpoint откатываются.

---

## Türkçe

### Genel bakış ve desteklenen tüneller

avaTUN, Linux tünellerini ve uzak sunucuları yönetmek için bir web panelidir. Sunucuları SSH üzerinden ekleyin; avaTUN’ı bu sunuculara kurup güncelleyin ve tünel yaşam döngüsünü tek panelden yönetin. Mesh haritası sunucu topolojisini ve bağlantıları gösterir; bir bağlantının çizilmesi için aynı tünel kimliği iki sunucuda da bulunmalıdır. Panel ayrıca canlı kaynak izleme, düzenli ICMP bağlantı kontrolleri ve isteğe bağlı Telegram botu sunar.

Desteklenen tünel türleri: **Backhaul TUN, GRE, IPIP, GRETAP, Geneve, VXLAN, ERSPAN, 6to4, ISATAP, GRE/IPIP/SIT FoU, L2TPv3, IPsec/ESP kipleri, WireGuard, OpenVPN ve OpenConnect.** Uç nokta rolü doğrudan veya ters olarak seçilebilir. WireGuard, OpenVPN ve OpenConnect eşli kurulumları iki taraf için uyumlu yapılandırma, ayrı anahtar veya sertifikalar ve peer adresleri oluşturur. OpenConnect, ocserv kullanır ve noktadan noktaya sabit bir /31 adres çifti kullanır. ERSPAN trafiği aynaladığı için panelde çift yönlü IP bağlantısı olarak değil, yalnızca izleme amacıyla gösterilir.

### Sunucu bağlantıları ve port yönlendirme

Linux sunucularını SSH ile panele ekleyin. İlk kayıt sırasında SSH parolası yalnızca o sunucuya özel bir anahtar oluşturmak için kullanılabilir; işlemden sonra parola atılır ve saklanmaz. Yüklenen veya oluşturulan SSH anahtarları denetleyici veri dizininde 0600 izinleriyle saklanır. Servis kurulumunda varsayılan yol /var/lib/tunnelmgr/ssh-keys şeklindedir. Sağlık denetimi her on saniyede bir tünel arayüzünden peer adresine ping gönderir.

**Port forwarding** sayfası, panel sunucusunda **HAProxy** kullanarak **TCP** dinleyicilerini yönetir. Denetleyiciye HAProxy kurun, ardından bir veya daha fazla yerel tünel bağlantısını backend yolu olarak seçin; peer tünel IP’si hedef olur. Backend ağırlıkları, leastconn, roundrobin ve kaynak adresine bağlılık algoritmaları ile TCP sağlık kontrolleri desteklenir. Hedef uygulama peer tünel IP’sini veya tüm arayüzleri dinlemelidir. Bu özellik şu anda peer arkasındaki LAN makinelerine yönlendirme yapmaz ve rastgele UDP hizmetlerini yük dengelemez.

İki uçlu bir bağlantı için her sunucuda kendi endpoint’ini oluşturun; diğer tarafta yerel/peer adreslerini ve peer kimliklerini ters çevirin. İki sunucuda da aynı tünel kimliği varsa Mesh haritası bağlantıyı çizer.

### Debian veya Ubuntu için hızlı kurulum

Aşağıdaki komut GitHub’dan en son kararlı sürümü alır. Kurucu doğrulama önkoşullarını hazırlar ve sürüm paketini çalıştırmadan önce GitHub Actions imzalı attestation bilgisini doğrular:

```sh
curl -fsSL https://raw.githubusercontent.com/soheil819/avaTUN/main/install.sh | sudo bash
```

Kurulum sonunda panel adresi ve ilk giriş bilgileri terminalde gösterilir. Etkin swap yoksa kurucu kalıcı 512 MB swap dosyası oluşturur. Varsayılan panel portu 8765’tir. Elle klonlanan kaynak koddan kurulum:

```sh
git clone https://github.com/soheil819/avaTUN.git
cd avaTUN
sudo bash scripts/install-from-github.sh
```

Kaynak koddan yerel geliştirme örneğini başlatmak için:

```sh
python3 tunnelmgr/tunnelctl.py init
python3 tunnelmgr/tunnelctl.py account create admin --role admin
./scripts/run-local.sh
```

### HTTP, HTTPS ve güvenlik

Kurulumdan sonra panel HTTP ile kullanılabilir; erişim için SSH tüneli zorunlu değildir. HTTPS için **Settings → TLS certificate** bölümünde alan adı ve Let's Encrypt sertifikası yapılandırın. Sertifika hazır olduğunda HTTP istekleri HTTPS’e yönlendirilir; TLS üzerinde HSTS ve Secure oturum çerezleri kullanılır. TOTP kurulumu ve oturum açma HTTPS gerektirir. Sertifika alma ve yenileme için TCP 80 erişilebilir olmalıdır. Hesap parolaları salt eklenmiş scrypt özetiyle saklanır; tarayıcı oturumu HttpOnly çerezi kullanır.

Debian/Ubuntu kurucusu önkoşulları ve seçilen özelliklerin gerektirdiği paketleri hazırlar. UFW etkinse TCP 8765’i açar; sağlayıcı güvenlik duvarını ayrıca yapılandırın. Panelin gösterilen adresini değiştirmek için kurulumdan önce PANEL_HOST ayarlayın. İlk giriş bilgileri yalnızca terminalde gösterilir; rastgele parola düz metin dosyasına yazılmaz.

### Kaldırma ve güncelleme

avaTUN’ı kaldırmak istediğiniz makinede kaynak dizininden kaldırıcıyı çalıştırın:

```sh
sudo ./uninstall.sh
```

Kaldırma kapsamını inceleyin ve REMOVE AVATUN yazarak onaylayın. Kaldırıcı paneli, Telegram botunu, avaTUN tarafından yönetilen yerel tünel servislerini, uygulama dosyalarını, yapılandırmayı, TLS verilerini ve yerel durumu siler. O makinede avaTUN tarafından yönetilen etkin tüneller durdurulur. FRR, HAProxy, Certbot ve StrongSwan gibi sistem paketleri veya paylaşılan servisler; güvenlik duvarı kuralları, swap, çekirdek modülleri, tunnelmgr hesabı ve uzak sunuculardaki kurulumlar korunur. Uzak kurulumu kaldırmak için kaldırıcıyı o sunucuda çalıştırın.

Kurucu, Linux amd64 için checksum doğrulaması yapılmış Backhaul TUN çekirdeğini ve yöneticisini içerir. İlk kurulumda yüklenir ve sonraki panel güncellemelerinde korunur. Diğer işlemci mimarileri uygun bir Backhaul çekirdek paketine ihtiyaç duyar. Lisans ve üçüncü taraf bildirimleri vendor/backhaul/ dizinindedir. scripts/install-preview.sh mevcut kurulumu günceller ve giriş hesabı oluşturmaz. Uzak sunucu güncellemeleri de aynı doğrulanmış Backhaul dosyalarını aktarır. Eski token şemasıyla oluşturulmuş hesapların parolası bir kez sıfırlanmalıdır:

```sh
python3 /opt/tunnelmgr/tunnelmgr/tunnelctl.py account password admin
```

### CLI ile Mesh dağıtımı

scripts/mesh-deploy.py, preview sürümünü çalıştıran düğümlere Backhaul TUN Mesh uygulayabilir. OpenSSH kullanır, her bağlantı için ayrı secret oluşturur, boşta olan dinleme ve sağlık denetimi portlarını ve TUN arayüz adlarını seçer. Bir bağlantı başarısız olursa bu işlemde oluşturulan endpoint’leri geri alır.
