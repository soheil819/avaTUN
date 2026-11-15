# avaTUN | tunnel manager web panel

**مدیریت تونل‌ها و سرورها از یک پنل وب، همراه با نقشهٔ Mesh و ربات تلگرام. نسخهٔ پایدار 1.0.0.2.**

avaTUN پنلی برای نصب و مدیریت تونل‌های لینوکس است. سرورها را با SSH اضافه کنید، تونل‌های دوطرفه بسازید، وضعیت و منابع را ببینید و مسیرهای TCP را با HAProxy مدیریت کنید.

## نصب سریع

روی Debian یا Ubuntu فقط این دستور را اجرا کنید؛ پیش‌نیازها خودکار نصب می‌شوند:

```sh
curl -fsSL https://raw.githubusercontent.com/soheil819/avaTUN/main/install.sh | sudo bash
```

این ورودی آخرین ریلیز پایدار را از API عمومی GitHub می‌گیرد و قبل از اجرا، attestation امضاشدهٔ GitHub Actions را بررسی می‌کند. برای نصب دستی از checkout محلی نیز می‌توانید این مسیر را اجرا کنید:

```sh
git clone https://github.com/soheil819/avaTUN.git
cd avaTUN
sudo bash scripts/install-from-github.sh
```

اسکریپت آغاز نصب، فایل ریلیز را تا پیش از تأیید attestation امضاشدهٔ GitHub Actions اجرا نمی‌کند. سپس پیش‌نیازها را نصب می‌کند و نشانی پنل و اطلاعات ورود اولیه را در ترمینال نشان می‌دهد. در صورت نبود Swap، فایل Swap پایدار ۵۱۲ مگابایتی ساخته می‌شود. پورت پیش‌فرض پنل ۸۷۶۵ است.

نسخهٔ پایدار avaTUN 1.0.0.2 است. برای دسترسی امن، HTTPS پنل را از تنظیمات فعال کنید.

### English

avaTUN is a stable Linux tunnel and server management dashboard with a Mesh map, live resource monitoring, HAProxy TCP forwarding, and an optional Telegram bot. On Debian or Ubuntu, use the one-command installer below; it bootstraps its verification prerequisites and verifies the GitHub Actions attestation before installation:

```sh
curl -fsSL https://raw.githubusercontent.com/soheil819/avaTUN/main/install.sh | sudo bash
```

For a manual checkout-based install:

```sh
git clone https://github.com/soheil819/avaTUN.git
cd avaTUN
sudo bash scripts/install-from-github.sh
```

The installer prints the panel URL and initial login credentials in the terminal. Test on non-production servers before operational use.

---

See [architecture](outputs/architecture-plan-fa.md) and [local run guide](docs/run-local-fa.md). avaTUN provides a password-based web dashboard, SQLite tunnel and server inventory, SSH-based remote installation and tunnel lifecycle actions, periodic ICMP health probes, and a topology view. Backhaul TUN integration uses the regular Backhaul manager installed on each endpoint.

## Start the dashboard

```sh
python3 tunnelmgr/tunnelctl.py init
python3 tunnelmgr/tunnelctl.py account create admin --role admin
./scripts/run-local.sh
```

Passwords are stored with salted scrypt hashes. The browser uses an HttpOnly session cookie. The packaged systemd service listens on all interfaces at port 8765, but remote cleartext requests are refused until HTTPS is configured. For first setup, open an SSH tunnel with `ssh -L 8765:127.0.0.1:8765 user@SERVER` and visit `http://127.0.0.1:8765`; then configure a domain and issue a Let's Encrypt certificate under **Settings → TLS certificate**. After the certificate is ready, browser and API requests over HTTP are redirected to HTTPS, HSTS is enabled, and the session cookie is marked Secure. The local health endpoint remains available to the updater. Keep TCP/80 reachable for certificate issuance and renewal.

The unified tunnel form lists Backhaul TUN, GRE, IPIP, GRETAP, Geneve, VXLAN, ERSPAN, 6to4, ISATAP, GRE/IPIP/SIT FoU, L2TPv3, IPsec/ESP modes, WireGuard, OpenVPN, and OpenConnect. Select direct or reverse for the endpoint role. The WireGuard, OpenVPN, and OpenConnect pair actions create coordinated endpoint configurations with per-side keys/certificates and peer addresses. OpenConnect uses ocserv and a fixed point-to-point `/31` address pair. Add Linux servers with SSH access to install or update the manager and control tunnel endpoints. During enrollment, the SSH password can bootstrap a per-server key and is then discarded; it is never stored. Uploaded or generated SSH keys are stored with mode `0600` under the controller data directory (for the installed service, `/var/lib/tunnelmgr/ssh-keys`). The health worker pings the configured peer through its tunnel interface every ten seconds. ERSPAN is reported as monitor-only because it mirrors traffic instead of carrying a bidirectional IP link.

The **Port forwarding** page manages TCP listeners with HAProxy on the panel server. Install `haproxy` on the controller, then select one or more local tunnel links; each link's peer tunnel IP becomes a backend path, with configurable weight, `leastconn`/`roundrobin`/source-affinity scheduling, and TCP health checks. The destination application must listen on those peer IPs (or on all interfaces). This page does not yet forward to LAN hosts behind a peer or balance arbitrary UDP services.

For a two-ended link, create each endpoint on its server and reverse the local/peer addresses and peer IDs on the other side. The mesh view draws edges when the same tunnel ID is present on both servers; a combined transactional two-server wizard is not yet included.

The routing page can configure paired BGP or OSPF profiles through FRR on both tunnel endpoints. BGP and OSPF export only the explicitly entered private prefixes; port-forward backends on routed remote networks are accepted only when covered by the matching far-side route profile. The routing daemon must be available through the system `frr` package.

## نصب از سورس

برای سورس موجود روی سرور، `sudo ./install.sh` همان نصب را بدون دریافت مخزن اجرا می‌کند. نصب‌کننده پیش‌نیازها و بسته‌های تونل پشتیبانی‌شده را نصب می‌کند، در صورت نبود Swap فعال یک Swap پایدار ۵۱۲ مگابایتی می‌سازد، سرویس‌ها را راه می‌اندازد و حساب اولیهٔ `admin` را ایجاد می‌کند. نشانی پنل و گذرواژهٔ تصادفی فقط در پایان ترمینال نمایش داده می‌شوند و گذرواژه در فایل متنی ذخیره نمی‌شود. برای تغییر نشانی نمایشی، `PANEL_HOST` را پیش از اجرا تنظیم کنید. اگر UFW فعال باشد، TCP پورت ۸۷۶۵ باز می‌شود؛ فایروال ارائه‌دهنده را جداگانه تنظیم کنید. پنل با HTTP شروع می‌شود و HTTPS از بخش **تنظیمات** قابل پیکربندی است.

For a source checkout already on the server, `sudo ./install.sh` runs the same installation without fetching from GitHub.

### Remove avaTUN

Run the uninstaller from the avaTUN source directory on the host you want to
remove it from:

```sh
sudo ./uninstall.sh
```

Read the displayed scope, then type `REMOVE AVATUN` to confirm. The script
stops the panel, Telegram bot, and avaTUN-managed local tunnel services, then
removes the panel files, configuration, TLS data, and local application state.
This stops active tunnels managed by avaTUN on that host. It does not remove
system packages or shared services such as FRR, HAProxy, Certbot, or
StrongSwan; it preserves firewall rules, swap, kernel modules, the
`tunnelmgr` account, and avaTUN installations on remote servers. To remove a
remote installation, run its own uninstaller on that remote host.

The installer includes the supplied, checksum-verified Backhaul TUN core and its manager for Linux amd64. It installs them on first setup and preserves an already installed manager/core on later panel updates. Other CPU architectures still install avaTUN, but need a matching Backhaul core package before they can create Backhaul TUN links. The core's license and third-party notices are in `vendor/backhaul/`.

The underlying package installer is `scripts/install-preview.sh`; unlike `install.sh`, it is intended for updating an existing installation and does not create login credentials. Remote server updates transfer the same verified Backhaul assets. Existing accounts created under the former token scheme need a one-time password reset:

```sh
python3 /opt/tunnelmgr/tunnelmgr/tunnelctl.py account password admin
```

## CLI mesh deployment

`scripts/mesh-deploy.py` can apply a Backhaul TUN mesh to nodes already running the preview. It uses OpenSSH, creates per-link secrets, selects free listener/health ports and TUN interface names, and rolls back created endpoints if an edge fails.
