# Lab n8n + Splunk (NUC)

Repo dedicato: [soc-n8n-splunk-lab](https://github.com/DarkGreen-projects/soc-n8n-splunk-lab).

Qui sul NUC uso Splunk Free come SIEM e n8n per detection/triage/enrichment, perché sul Free non hai alert schedulate e il REST remoto non autentica. I workflow JSON sanitizzati stanno anche in [`workflows/`](workflows/).

```mermaid
flowchart LR
  WinLogs[Windows_Event_Log] --> Export[winlogs_export]
  Export --> Splunk[Splunk_index_main]
  Export --> WinInbox[winlogs_inbox]
  Bridge[splunk_warning_export] --> State[n8n_state_jsonl]
  Poller[n8n_Poller] --> State
  Poller --> WinInbox
  Poller -->|JSON_open| Triage[alerts_triage]
  Triage --> SplunkTriage[index_alerts_triage]
  Poller --> Dispatcher[TI_Dispatcher]
  Dispatcher --> FreeTI[ip_api_DNS_CIRCL]
  Poller --> Ollama[Ollama]
  Poller --> Reports[soc_reports]
  CloseWH[webhook_close] --> Triage
  Manual[webhook_reputation] --> Dispatcher
```

## Sul lab

```powershell
C:\lab\lab-up.ps1
powershell -File C:\lab\scripts\import-n8n-workflows.ps1
powershell -File C:\lab\scripts\demo-soc-pipeline.ps1
powershell -File C:\lab\scripts\splunk-warning-export.ps1
```

- Reputation: http://localhost:5678/webhook/lab-reputation?ip=8.8.8.8  
- Splunk: http://localhost:8000 (`index=alerts_triage`)  
- Report: `C:\lab\data\soc-reports\`

Enrichment live: ip-api, Google DNS, CIRCL. Stub voluti: VT / Shodan / AbuseIPDB / MISP.  
Pattern Dispatcher ispirato a [inthecyber securityonion-n8n-workflows](https://github.com/inthecyber-group/securityonion-n8n-workflows).
