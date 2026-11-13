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
