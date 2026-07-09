# Grafana & Prometheus Integration

Phantom Grid supports native integration with **Prometheus** and **Grafana** to provide long-term storage and advanced alerting for your security metrics.

The agent exposes a standard Prometheus `/metrics` endpoint on the Web Dashboard port (default: 8080).

## 1. Exposed Metrics

Phantom Grid exports the following eBPF statistics in Prometheus format:

- `phantom_dropped_packets_total` (Counter): Total number of malicious or unauthorized packets dropped at the XDP layer.
- `phantom_spa_auth_success_total` (Counter): Total number of successful Single Packet Authorization (SPA) requests.
- `phantom_spa_auth_failed_total` (Counter): Total number of failed or invalid SPA requests.

## 2. Prometheus Configuration

To scrape data from Phantom Grid, add the following job to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'phantom-grid'
    scrape_interval: 5s
    static_configs:
      - targets: ['192.168.1.100:8080'] # Replace with your Phantom Grid Agent IP
```

Restart your Prometheus server to apply the changes.

## 3. Grafana Dashboard Setup

1. Open Grafana and add your Prometheus server as a Data Source.
2. Create a new Dashboard.
3. Add a Time Series panel.
4. Use the following PromQL queries to visualize your data:

### Block Rate (Packets Dropped per Second)
To see the real-time rate of dropped packets (useful for detecting DDoS spikes):
```promql
rate(phantom_dropped_packets_total[1m])
```

### SPA Success vs Failure
To monitor authentication attempts to your hidden services:
```promql
rate(phantom_spa_auth_success_total[5m])
```
```promql
rate(phantom_spa_auth_failed_total[5m])
```

> **Note:** The `/metrics` endpoint is intentionally public (bypasses the Web Dashboard authentication) to allow standard Prometheus scrapers to collect data without requiring session cookies. If your management network is exposed to the internet, it is highly recommended to place the Agent behind a reverse proxy (like Nginx) and restrict access to the `/metrics` path to your Prometheus server's IP address.
