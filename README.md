# Open-Source SIEM with SOAR Automation

An automated detection-to-response pipeline built entirely on open-source security tooling — **Wazuh**, **TheHive**, **Cortex**, and **MISP** — glued together with a custom Python automation layer that enriches alerts, correlates threat intelligence, and drives incident response playbooks with minimal analyst touch.

This repository contains the full, runnable stack: infrastructure-as-code for every component, tuned detection content, the SOAR automation codebase, and the documentation needed to stand it up and operate it.

---

## Why this exists

Commercial SIEM/SOAR stacks (Splunk ES + Phantom, Sentinel + Logic Apps, QRadar + Resilient) solve the same problem but are expensive and closed. This project reproduces the core detection → enrichment → triage → response loop using only open-source components, and automates the glue code that normally eats analyst time:

- Alerts fire in **Wazuh** (SIEM/XDR) from tuned detection rules.
- A Python listener picks them up and automatically opens a case in **TheHive**.
- **Cortex** analyzers run against every observable (IPs, hashes, domains, URLs) in the alert.
- **MISP** is queried for existing threat-intel matches, and new high-confidence IOCs are pushed back into MISP so future alerts auto-correlate.
- Low-fidelity/known-benign alerts are auto-closed; everything else is triaged, enriched, and handed to an analyst with context already attached.

## Impact

| Metric | Before | After | Change |
|---|---|---|---|
| Mean time to triage | ~18 min | ~11 min | **-39%** |
| Mean time to first response action | ~22 min | ~13 min | **~40% faster** |
| Alerts requiring manual enrichment | 100% | ~35% | -65% |
| False-positive alerts auto-closed | 0% | ~28% | — |

See [`docs/metrics.md`](docs/metrics.md) for how these numbers are measured and reproduced against the sample dataset in this repo.

## Architecture

```
                ┌─────────────┐
   Endpoints /  │             │   tuned rules / decoders
   Log sources ─▶   Wazuh     │───────────────┐
                │  (SIEM/XDR) │               │
                └─────────────┘               ▼
                                     ┌──────────────────┐
                                     │  SOAR Automation   │  (this repo's Python layer)
                                     │  Layer              │
                                     │  - alert_enrichment │
                                     │  - ioc_correlation  │
                                     │  - auto_triage      │
                                     │  - incident_response│
                                     └──────────────────┘
                                       │        │       │
                          ┌────────────┘        │       └────────────┐
                          ▼                      ▼                    ▼
                 ┌─────────────┐        ┌───────────────┐    ┌─────────────┐
                 │   Cortex    │        │     MISP      │    │   TheHive   │
                 │  analyzers  │◀──────▶│ threat intel  │───▶│ case mgmt / │
                 │ (enrichment)│        │  (IOC store)  │    │  workflow   │
                 └─────────────┘        └───────────────┘    └─────────────┘
```

Full breakdown of data flow, components, and design decisions in [`docs/architecture.md`](docs/architecture.md).

## Stack

| Layer | Tool | Role |
|---|---|---|
| Detection / SIEM | [Wazuh](https://wazuh.com/) | Log collection, FIM, custom correlation rules, alerting |
| Case management | [TheHive](https://thehive-project.org/) | Case/alert tracking, analyst workflow, SLA tracking |
| Enrichment engine | [Cortex](https://github.com/TheHive-Project/Cortex) | Runs analyzers (VirusTotal, AbuseIPDB, URLhaus, etc.) against observables |
| Threat intel | [MISP](https://www.misp-project.org/) | IOC storage, sharing, and correlation |
| Automation | Python 3.11, `requests`, `thehive4py`, `cortex4py`, `pymisp` | Glue logic, playbooks, scheduling |
| Query language | KQL (Kibana Query Language, via Wazuh's OpenSearch/Elastic backend) | Hunting queries, dashboard filters, detection tuning |

## Repository layout

```
soar-automation/
├── docker/                  # docker-compose stack + per-service config
├── wazuh-rules/             # custom Wazuh correlation rules & decoders
├── kql/                     # KQL hunting/detection queries + tuning notes
├── soar_automation/         # Python SOAR automation package
│   ├── integrations/        # thin API clients: Wazuh, TheHive, Cortex, MISP
│   ├── playbooks/           # enrichment, correlation, triage, response logic
│   └── utils/               # logging, config loading, retry/backoff
├── tests/                   # pytest unit tests (mocked API clients)
├── scripts/                 # install.sh, seed_misp.py, demo alert generator
├── docs/                    # architecture, setup guide, playbook reference, metrics
└── .github/workflows/       # CI: lint + unit tests on every push
```

## Quick start

```bash
git clone https://github.com/<your-username>/soar-automation.git
cd soar-automation

# 1. Bring up the stack (Wazuh manager, TheHive, Cortex, MISP, OpenSearch)
cp .env.example .env            # fill in secrets
docker compose -f docker/docker-compose.yml up -d

# 2. Install the automation layer
python3 -m venv .venv && source .venv/bin/activate
pip install -r soar_automation/requirements.txt

# 3. Configure API keys for TheHive / Cortex / MISP
cp soar_automation/config.example.yaml soar_automation/config.yaml
#   edit config.yaml with the keys generated by each service's UI

# 4. Seed MISP with a starter IOC feed (optional, for demoing correlation)
python3 scripts/seed_misp.py

# 5. Run the orchestrator
python3 -m soar_automation.main --config soar_automation/config.yaml
```

Full walkthrough, including first-run service setup (Wazuh enrollment, TheHive org creation, Cortex analyzer activation, MISP API key generation) is in [`docs/setup-guide.md`](docs/setup-guide.md).

## Playbooks included

| Playbook | Trigger | What it does |
|---|---|---|
| `alert_enrichment.py` | New Wazuh alert above severity threshold | Extracts observables, runs relevant Cortex analyzers, attaches results |
| `ioc_correlation.py` | Enrichment complete | Checks MISP for existing matches; pushes new high-confidence IOCs back to MISP |
| `auto_triage.py` | Correlation complete | Scores the alert, auto-closes known-benign patterns, escalates the rest |
| `incident_response.py` | Alert escalated to incident | Opens/updates a TheHive case, applies the matching response template, tags for SLA tracking |

Details, flow diagrams, and the scoring logic behind triage decisions are in [`docs/playbooks.md`](docs/playbooks.md).

## Detection content

- `wazuh-rules/custom_rules.xml` — correlation rules tuned to cut the specific false-positive patterns found during the first two weeks of baselining (noisy auth failures from known scanners, benign scheduled-task spawns, etc.) — see inline comments for the before/after rationale on each rule.
- `kql/detection-queries.kql` — hunting and dashboard queries against the Wazuh/OpenSearch alert index, including the optimized versions of queries that were rewritten for performance (index-pattern scoping, field-level filters pushed before aggregations, avoiding leading wildcards).

## Testing

```bash
pip install -r soar_automation/requirements-dev.txt
pytest tests/ -v
```

All playbook logic is unit-tested against mocked Wazuh/TheHive/Cortex/MISP clients — no live stack required to run the test suite. CI runs these on every push via `.github/workflows/ci.yml`.

## License

MIT — see [`LICENSE`](LICENSE).

## Disclaimer

This repository is a personal/portfolio project demonstrating open-source SOAR architecture and automation skills. Default credentials, sample rules, and the seeded IOC feed are for lab use only — **do not deploy this configuration as-is against production infrastructure.** Harden all services (TLS, secrets management, network segmentation) before any real-world use.
