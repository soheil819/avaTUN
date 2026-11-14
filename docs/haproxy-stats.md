# HAProxy statistics and Prometheus

Every panel-generated HAProxy configuration includes a managed `haproxy_stats`
frontend on `0.0.0.0:18404`:

- `/stats`: HAProxy's statistics page, HTTP basic authentication, refresh every
  five seconds, legends and node name enabled.
- `/metrics`: the built-in `prometheus-exporter` HTTP service. As in the requested
  configuration, `stats auth` protects the statistics page; `/metrics` is served
  directly by the exporter.

The listener remains present when forwarding rules are empty or disabled.
The panel reserves port 18404 so a forwarding rule cannot use it.
Existing unmanaged frontend sections are preserved. A conflicting unmanaged
`haproxy_stats` section must be renamed rather than silently overwritten.

Credentials live in `/etc/avatun/haproxy-stats.json` (root, mode 0600), never
in Git. The controller transfers these settings over SSH in the temporary
installation bundle for newly managed nodes. A standalone installer with no
provided runtime settings generates a persistent random password.

The installer validates HAProxy configuration and enables the statistics
listener. When UFW is active, it permits TCP/18404. The HAProxy package must
include the built-in Prometheus exporter; configuration validation rejects an
unsupported build before replacing the previous configuration.

Example Prometheus target:

```yaml
scrape_configs:
  - job_name: avatun-haproxy
    metrics_path: /metrics
    static_configs:
      - targets: ["SERVER_IP:18404"]
```
