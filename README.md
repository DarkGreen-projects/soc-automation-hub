# SOC Automation Hub

[![Focus](https://img.shields.io/badge/Focus-Security%20Automation-3ddc97)]()
[![Location](https://img.shields.io/badge/Location-Torino%2C%20IT-green)]()

**Portfolio open source di progetti Security, automazione SOC e integrazioni cloud.**

Creato da **Federico Parisi** ([DarkGreen Projects](https://github.com/DarkGreen-projects)) — SOC Analyst con background da sviluppatore, specializzato in detection, automazione e AI-assisted workflows.

## Mission

Costruire strumenti che collegano:

`Detection` → `Enrichment` → `Automazione` → `Risposta`

## Demo live

- **CSV VT Scanner (web demo):** https://darkgreen-projects.github.io/soc-automation-hub/
- **App Windows (scan VirusTotal reale):** [Releases](https://github.com/DarkGreen-projects/soc-automation-hub/releases)

## Progetti

| Tool | Stato | Descrizione |
|------|-------|-------------|
| [csv-vt-scanner](tools/csv-vt-scanner/) | Attivo | Verifica IP da export LogPoint via VirusTotal, grafico a torta, export CSV malevoli |
| splunk-detections | Prossimo | Regole SPL + dati sintetici |
| power-platform-soc | Prossimo | Template Power Automate / Logic Apps per SOC |
| ai-alert-triage | Prossimo | LLM per summarization e classificazione alert |

## Stack

`Python` · `React` · `Tauri` · `Power Automate` · `Logic Apps` · `SIEM` · `Splunk` · `NIST CSF`

## Struttura

```
soc-automation-hub/
├── tools/           # Moduli standalone
├── docs/            # Architettura e roadmap
├── examples/        # Dati di esempio (sanitizzati)
└── .github/         # CI: Pages + Release Windows
```

## Policy

I progetti aziendali non vengono pubblicati. Qui trovi solo codice open source, template e versioni **sanitizzate/demo**.

## Licenza

MIT — vedi [LICENSE](LICENSE).
