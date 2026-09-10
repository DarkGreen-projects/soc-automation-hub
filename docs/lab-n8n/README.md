# Lab n8n + Splunk (NUC)

Repository dedicato: [soc-n8n-splunk-lab](https://github.com/DarkGreen-projects/soc-n8n-splunk-lab).

Laboratorio SOC su NUC: Splunk Free come SIEM e n8n come orchestration. Sulla Free non sono disponibili alert schedulate native e il login REST remoto è disabilitato; i workflow compensano con bridge file, triage open/closed ed enrichment IOC. Gli export JSON sanitizzati sono anche in [`workflows/`](workflows/).

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

## Esecuzione sul lab

```powershell
C:\lab\lab-up.ps1
powershell -File C:\lab\scripts\import-n8n-workflows.ps1
powershell -File C:\lab\scripts\demo-soc-pipeline.ps1
powershell -File C:\lab\scripts\splunk-warning-export.ps1
```

- Reputation: http://localhost:5678/webhook/lab-reputation?ip=8.8.8.8  
- Splunk: http://localhost:8000 (`index=alerts_triage`)  
- Report: `C:\lab\data\soc-reports\`

Enrichment operativo: ip-api, Google DNS, CIRCL. Stub dichiarati: VirusTotal, Shodan, AbuseIPDB, MISP.  
Riferimento di pattern: [inthecyber securityonion-n8n-workflows](https://github.com/inthecyber-group/securityonion-n8n-workflows).
