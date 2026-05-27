#!/usr/bin/env python3
"""
infra-sentinel — Weekly CVE & upgrade check for infra nodes.
Checks: nginx (via SSH), Elasticsearch, Kubernetes.
Notifies: Mattermost / Slack / Telegram.
"""

import argparse
import base64
import json
import os
import ssl
import subprocess
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    raise SystemExit("pyyaml not installed. Run: pip install pyyaml")

# ── Config loading ─────────────────────────────────────────────────────────────

DEFAULT_CONFIG_PATH = Path("config.yaml")


def load_config(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(f"Config file not found: {path}\nCopy config.example.yaml → config.yaml and fill in your values.")
    with path.open() as f:
        cfg = yaml.safe_load(f)
    return cfg


# ── Logging ───────────────────────────────────────────────────────────────────

_log_file: Path | None = None


def log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    if _log_file:
        try:
            _log_file.parent.mkdir(parents=True, exist_ok=True)
            with _log_file.open("a") as f:
                f.write(line + "\n")
        except Exception:
            pass


# ── Seen-CVE tracking ─────────────────────────────────────────────────────────

def load_seen(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            return {}
    return {}


def save_seen(seen: dict, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(seen, indent=2, ensure_ascii=False))


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _http_get(url: str, headers: dict = None, timeout: int = 20,
              skip_tls: bool = False) -> dict | None:
    ctx = ssl._create_unverified_context() if skip_tls else None
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        log(f"  HTTP error {url}: {e}")
        return None


def _http_post_json(url: str, payload: dict, timeout: int = 10) -> bool:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=timeout)
        return True
    except Exception as e:
        log(f"  Webhook error: {e}")
        return False


# ── Notifications ─────────────────────────────────────────────────────────────

def send_alerts(text: str, cfg: dict, dry_run: bool):
    notif = cfg.get("notifications", {})

    if dry_run:
        log("[dry-run] Would send alert:")
        print(text)
        return

    sent = False

    if webhook := notif.get("mattermost", {}).get("webhook"):
        log("Sending Mattermost alert...")
        _http_post_json(webhook, {"text": text})
        sent = True

    if webhook := notif.get("slack", {}).get("webhook"):
        log("Sending Slack alert...")
        # Slack uses 'text' field same as Mattermost
        _http_post_json(webhook, {"text": text})
        sent = True

    if tg := notif.get("telegram", {}):
        token = tg.get("bot_token")
        chat_id = tg.get("chat_id")
        if token and chat_id:
            log("Sending Telegram alert...")
            # Telegram max message length is 4096
            chunks = [text[i:i+4000] for i in range(0, len(text), 4000)]
            for chunk in chunks:
                url = f"https://api.telegram.org/bot{token}/sendMessage"
                _http_post_json(url, {
                    "chat_id": chat_id,
                    "text": chunk,
                    "parse_mode": "Markdown",
                })
            sent = True

    if not sent:
        log("WARNING: No notification channel configured in config.yaml")


# ── NVD CVE lookup ────────────────────────────────────────────────────────────

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DELAY = 7  # seconds between requests (free tier: 5 req/30s)


def query_nvd(keyword: str, api_key: str | None = None) -> list[dict]:
    url = f"{NVD_API}?keywordSearch={urllib.request.quote(keyword)}&resultsPerPage=20"
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    data = _http_get(url, headers=headers)
    if not data:
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        published = cve.get("published", "")[:10]

        metrics = cve.get("metrics", {})
        score, severity = None, "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                data_v = entries[0].get("cvssData", {})
                score    = data_v.get("baseScore")
                severity = data_v.get("baseSeverity") or entries[0].get("baseSeverity", "?")
                break

        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "No description",
        )

        results.append({
            "id":          cve_id,
            "score":       score,
            "severity":    severity.upper(),
            "description": desc[:200],
            "published":   published,
        })

    results.sort(key=lambda x: x["score"] or 0, reverse=True)
    return results


def filter_cves(cves: list[dict], seen: dict, min_cvss: float, force: bool) -> list[dict]:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    result = []
    for cve in cves:
        score = cve["score"] or 0
        if score < min_cvss:
            continue
        if not force and cve["id"] in seen:
            continue
        seen[cve["id"]] = today
        result.append(cve)
    return result


# ── nginx checks ──────────────────────────────────────────────────────────────

def _ssh(host: str, cmd: str, timeout: int = 20) -> str | None:
    try:
        r = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
             "-o", "BatchMode=yes", host, cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception as e:
        log(f"  SSH {host} error: {e}")
        return None


def get_nginx_versions(host: str) -> tuple[str | None, str | None]:
    out = _ssh(host, "apt-cache policy nginx 2>/dev/null")
    if not out:
        return None, None
    installed = candidate = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Installed:"):
            installed = line.split(":", 1)[1].strip()
            if installed in ("(none)", ""):
                installed = None
        elif line.startswith("Candidate:"):
            candidate = line.split(":", 1)[1].strip()
    if installed and candidate and installed != candidate:
        return installed, candidate
    return installed, None


def check_nginx_nodes(cfg: dict, seen: dict, min_cvss: float, force: bool) -> list[str]:
    alerts = []
    nvd_key = cfg.get("nvd_api_key")
    for node in cfg.get("nginx_nodes", []):
        name, host = node["name"], node["host"]
        log(f"Checking nginx on {name} ({host})...")

        installed, candidate = get_nginx_versions(host)
        if installed is None:
            log(f"  Could not determine nginx version on {name}")
            continue

        log(f"  nginx installed={installed} candidate={candidate or 'up-to-date'}")

        if candidate:
            alerts.append(
                f"### :package: nginx upgrade available — **{name}**\n"
                f"- Installed: `{installed}`\n"
                f"- Available: `{candidate}`\n"
                f"- Run: `sudo apt-get install nginx`"
            )

        short_ver = installed.split("-")[0].split(":").pop()
        keyword = f"nginx {short_ver}"
        log(f"  Querying NVD for '{keyword}' (min CVSS {min_cvss})...")
        cves = query_nvd(keyword, api_key=nvd_key)
        if not nvd_key:
            time.sleep(NVD_DELAY)

        new_cves = filter_cves(cves, seen, min_cvss, force)
        if new_cves:
            lines = [f"### :shield: nginx CVEs — **{name}** (`{short_ver}`)"]
            for c in new_cves:
                score_str = f"CVSS {c['score']}" if c['score'] else "score N/A"
                lines.append(f"- **{c['id']}** [{c['severity']} / {score_str}] {c['description']}")
            alerts.append("\n".join(lines))

    return alerts


# ── Elasticsearch checks ──────────────────────────────────────────────────────

def _es_auth_header(cfg: dict) -> dict:
    user = cfg.get("es_user", "")
    pwd  = cfg.get("es_pass", "")
    creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()
    return {"Authorization": f"Basic {creds}"}


def get_es_version(url: str, auth: dict) -> str | None:
    data = _http_get(f"{url}/", headers=auth, skip_tls=True)
    if data:
        return data.get("version", {}).get("number")
    return None


def check_es_cluster(cfg: dict, seen: dict, min_cvss: float, force: bool) -> list[str]:
    alerts = []
    checked: set[str] = set()
    auth = _es_auth_header(cfg)
    nvd_key = cfg.get("nvd_api_key")

    for node in cfg.get("es_hosts", []):
        name, url = node["name"], node["url"]
        log(f"Checking ES on {name} ({url})...")

        version = get_es_version(url, auth)
        if not version:
            log(f"  Could not reach {name}")
            continue

        log(f"  Elasticsearch version: {version}")
        if version in checked:
            log(f"  Version {version} already checked, skipping")
            continue
        checked.add(version)

        keyword = f"elasticsearch {version}"
        log(f"  Querying NVD for '{keyword}' (min CVSS {min_cvss})...")
        cves = query_nvd(keyword, api_key=nvd_key)
        if not nvd_key:
            time.sleep(NVD_DELAY)

        new_cves = filter_cves(cves, seen, min_cvss, force)
        if new_cves:
            lines = [f"### :shield: Elasticsearch CVEs — `{version}`"]
            for c in new_cves:
                score_str = f"CVSS {c['score']}" if c['score'] else "score N/A"
                lines.append(f"- **{c['id']}** [{c['severity']} / {score_str}] {c['description']}")
            alerts.append("\n".join(lines))

    return alerts


# ── Kubernetes checks ─────────────────────────────────────────────────────────

def get_k8s_version(url: str) -> str | None:
    data = _http_get(f"{url}/version", skip_tls=True)
    if data:
        major = data.get("major", "")
        minor = data.get("minor", "").rstrip("+")
        return f"{major}.{minor}" if major else None
    return None


def check_k8s_clusters(cfg: dict, seen: dict, min_cvss: float, force: bool) -> list[str]:
    alerts = []
    checked: set[str] = set()
    nvd_key = cfg.get("nvd_api_key")

    for cluster in cfg.get("k8s_clusters", []):
        name, url = cluster["name"], cluster["url"]
        log(f"Checking K8s on {name} ({url})...")

        version = get_k8s_version(url)
        if not version:
            log(f"  Could not reach {name}")
            continue

        log(f"  Kubernetes version: {version}")
        if version in checked:
            continue
        checked.add(version)

        keyword = f"kubernetes {version}"
        log(f"  Querying NVD for '{keyword}' (min CVSS {min_cvss})...")
        cves = query_nvd(keyword, api_key=nvd_key)
        if not nvd_key:
            time.sleep(NVD_DELAY)

        new_cves = filter_cves(cves, seen, min_cvss, force)
        if new_cves:
            lines = [f"### :shield: Kubernetes CVEs — **{name}** (`{version}`)"]
            for c in new_cves:
                score_str = f"CVSS {c['score']}" if c['score'] else "score N/A"
                lines.append(f"- **{c['id']}** [{c['severity']} / {score_str}] {c['description']}")
            alerts.append("\n".join(lines))

    return alerts


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="infra-sentinel: CVE & upgrade checker")
    parser.add_argument("-c", "--config", default=str(DEFAULT_CONFIG_PATH),
                        help="Path to config.yaml (default: ./config.yaml)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print alerts without sending notifications")
    parser.add_argument("--force", action="store_true",
                        help="Re-check all CVEs, ignoring previously seen list")
    args = parser.parse_args()

    cfg = load_config(Path(args.config))

    global _log_file
    log_path = cfg.get("log_file", "~/.infra-sentinel/check.log")
    _log_file = Path(os.path.expanduser(log_path))

    seen_path = Path(os.path.expanduser(cfg.get("seen_file", "~/.infra-sentinel/seen.json")))
    min_cvss  = float(cfg.get("min_cvss", 7.0))

    log("=" * 60)
    log(f"infra-sentinel start (min_cvss={min_cvss}, force={args.force}, dry_run={args.dry_run})")

    seen = {} if args.force else load_seen(seen_path)
    all_alerts: list[str] = []

    log("--- nginx nodes ---")
    all_alerts += check_nginx_nodes(cfg, seen, min_cvss, args.force)

    log("--- Elasticsearch cluster ---")
    all_alerts += check_es_cluster(cfg, seen, min_cvss, args.force)

    log("--- Kubernetes clusters ---")
    all_alerts += check_k8s_clusters(cfg, seen, min_cvss, args.force)

    if not args.force:
        save_seen(seen, seen_path)

    if all_alerts:
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        header = f"## :rotating_light: Infra CVE / Upgrade Report — {now}\n"
        body = "\n\n---\n\n".join(all_alerts)
        send_alerts(header + body, cfg, dry_run=args.dry_run)
        log(f"Done — {len(all_alerts)} alert(s)")
    else:
        log("No new CVEs or upgrades found — no alert sent")

    log("infra-sentinel done")


if __name__ == "__main__":
    main()
