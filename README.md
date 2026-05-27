# infra-sentinel

Weekly CVE & upgrade check for self-hosted infrastructure nodes.

Checks nginx versions via SSH, queries the NVD database for known CVEs, and sends alerts to Mattermost, Slack, or Telegram when new vulnerabilities are found or package upgrades are available.

## What it checks

| Target | Method | What's reported |
|--------|--------|-----------------|
| nginx nodes | SSH → `apt-cache policy` | Upgrade available + new CVEs |
| Elasticsearch cluster | REST API `/version` | New CVEs for installed version |
| Kubernetes clusters | REST API `/version` | New CVEs for installed version |

- **No duplicate alerts**: tracks seen CVE IDs in `seen.json` — you only get notified once per CVE
- **Severity filter**: configurable minimum CVSS score (default: 7.0 = HIGH and above)

## Setup

```bash
pip install -r requirements.txt
cp config.example.yaml config.yaml
# Edit config.yaml with your node IPs, credentials, and webhook URL
```

## Usage

```bash
# Normal run (send alerts for new CVEs only)
python infra_sentinel.py

# Custom config path
python infra_sentinel.py -c /etc/infra-sentinel/config.yaml

# Test without sending notifications
python infra_sentinel.py --dry-run

# Re-check all CVEs (ignore seen list)
python infra_sentinel.py --force
```

## Cron setup

```cron
# Run every Monday at 09:00
0 9 * * 1 /usr/bin/python3 /opt/infra-sentinel/infra_sentinel.py -c /etc/infra-sentinel/config.yaml
```

## Notifications

Configure at least one channel in `config.yaml`:

| Channel | How to get webhook |
|---------|-------------------|
| **Mattermost** | Main Menu → Integrations → Incoming Webhooks |
| **Slack** | api.slack.com/apps → Incoming Webhooks |
| **Telegram** | Create bot via @BotFather, get token + chat_id |

Multiple channels can be active simultaneously.

## NVD API key

Without an API key, NVD rate-limits requests to 5 per 30 seconds (a 7-second delay is added automatically between requests). With a free API key, the limit increases to 50 per 30 seconds.

Get a free key at: https://nvd.nist.gov/developers/request-an-api-key

Add to `config.yaml`:
```yaml
nvd_api_key: "your-key-here"
```

## Adding more node types

The config supports any number of nodes per type. To add more:

```yaml
nginx_nodes:
  - name: "My New Node"
    host: "ubuntu@10.0.0.50"
```

SSH key-based auth is assumed. Ensure the running user's SSH key is authorized on all target nodes.

## License

MIT
