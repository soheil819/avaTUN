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
