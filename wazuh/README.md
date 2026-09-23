# Wazuh 6.0.0 — single-node Docker deployment

One Wazuh **manager** + **indexer** (OpenSearch) + **dashboard**, straight from
the official `wazuh-docker` release branch. This directory holds the compose
files and the configs they mount; the SOC agent in `../` can pull Wazuh alerts
once this stack is up.

## Requirements

- Docker Engine + Docker Compose v2 (`docker compose version`)
- Linux host; ensure `vm.max_map_count` is raised (the indexer needs it):
  ```bash
  sudo sysctl -w vm.max_map_count=262144
  ```
  (to make it permanent: add `vm.max_map_count=262144` to `/etc/sysctl.conf`)
- ~4 GB free RAM if you're also running the SOC agent/dashboard locally

## Deploy

```bash
cd wazuh

# 1) Generate the internal PKI (root CA + per-service certs).
#    Run once, BEFORE the first `up`. Output lands in
#    config/wazuh_indexer_ssl_certs/ (git-ignored - contains private keys).
docker compose -f generate-certs.yml run --rm generator

# 2) Bring the stack up
docker compose up -d

# 3) Watch it get healthy (takes 1-2 min on first boot)
docker compose ps
docker compose logs -f wazuh.indexer
```

To tear it down: `docker compose down` (add `-v` to also drop the data volumes).

## Access

| What | URL / port | Credentials |
|---|---|---|
| Wazuh dashboard | https://localhost | `admin` / `admin` |
| Wazuh indexer API (OpenSearch) | https://localhost:9200 | `admin` / `admin` |
| Manager REST API | https://localhost:55000 | `wazuh-wui` / `MyS3cr37P450r.*-` |
| Agent event traffic | 1514 (tcp) · 1515 (enrollment) · 514/udp (syslog) | — |

Certs are self-signed (generated above) — your browser will warn; accept and
continue, or set up the generated CA as trusted.

> ⚠️ **Production hardening**: `admin/admin` and `MyS3cr37P450r.*-` are the
> image defaults for a lab. Before any real deployment change the indexer
> admin password, the API password, and the dashboards' passwords, enable
> enrollment auth (`<use_password>yes</use_password>` in
> `config/wazuh_cluster/wazuh_manager.conf`), and restrict published ports.

## Enrolling agents

Point agents at this host on ports 1514/1515. Quick smoke-test with the same
host:

```bash
docker run -d --name wazuh-agent \
  -e WAZUH_MANAGER_ENDPOINT=$(hostname -I | awk '{print $1}'):1517/wazuh-manager/ \
  wazuh/wazuh-agent:6.0.0
```

(see the official agent docs for fleet enrollment on real endpoints). Agents
show up in the dashboard under **Agents**; once they report events you'll have
alerts in the `wazuh-alerts-*` index.

## Wiring it into the SOC triage agent

The Wazuh indexer speaks OpenSearch, so the agent's `wazuh` SIEM connector
reads alerts straight from `https://localhost:9200`:

```bash
cd ..
# .env
SIEM_PROVIDER=wazuh
WAZUH_HOST=https://localhost:9200
WAZUH_USERNAME=admin
WAZUH_PASSWORD=admin
WAZUH_VERIFY_SSL=false      # self-signed CA by default
```

Then:

```bash
python main.py live --siem wazuh
# or add it as a dashboard provider:
python dashboard.py          # Add provider -> Wazuh
```

Give the stack a minute and generate some load (e.g. `nmap -sT localhost` or
a failed `sudo`) so there are alerts to triage, then hit
**Test / Alerts / Run triage** on the Wazuh card in the dashboard.

## Layout

```
wazuh/
├── docker-compose.yml              # manager + indexer + dashboard
├── generate-certs.yml              # cert tool run (step 1)
├── config/
│   ├── certs.yml                   # certificate node names/IPs
│   ├── wazuh_indexer_ssl_certs/    # GENERATED - PKI, git-ignored
│   ├── wazuh_cluster/wazuh_manager.conf
│   └── wazuh_dashboard/wazuh.yml
└── README.md
```

Versions are pinned to the official `wazuh-docker` 6.0.0 release branch.