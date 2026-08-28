# SOC Automation Hub

Repository di tool per automazione SOC. Ogni modulo in `tools/` è indipendente, con documentazione, test e (dove previsto) demo web o build desktop.

## Moduli disponibili

### Demo web (hub unificato)

[darkgreen-projects.github.io/soc-automation-hub](https://darkgreen-projects.github.io/soc-automation-hub/) — due moduli nella stessa interfaccia:

| Modulo | Cosa fa |
|--------|---------|
| **CSV VT Scanner** | Upload CSV IP, classificazione simulata, grafico ed export |
| **Alert Rule Planner** | Tecniche MITRE + export alert (CSV/JSON) → gap analysis e pack rule suggerite |

### [csv-vt-scanner](tools/csv-vt-scanner/)

Analizza export CSV di indirizzi IP (formato SIEM/LogPoint), classifica gli IP e produce statistiche con grafico a torta ed export CSV. Include anche il modulo **Alert Rule Planner** nella demo web.

| Modalità | URL / percorso | Cosa fa |
|----------|----------------|---------|
| **Demo web** | [darkgreen-projects.github.io/soc-automation-hub](https://darkgreen-projects.github.io/soc-automation-hub/) | CSV VT Scanner + Alert Rule Planner |
| **Desktop** | [Releases](https://github.com/DarkGreen-projects/soc-automation-hub/releases) | Scan VirusTotal reale, più chiavi API, checkpoint |

Guida completa: [tools/csv-vt-scanner/README.md](tools/csv-vt-scanner/README.md) · [Wiki](https://github.com/DarkGreen-projects/soc-automation-hub/wiki)

## Avvio rapido (demo web)

**CSV VT Scanner**

1. Apri la [demo](https://darkgreen-projects.github.io/soc-automation-hub/)
2. Carica un CSV (es. [examples/sample-logpoint-ips.csv](examples/sample-logpoint-ips.csv))
3. Clicca **Anteprima demo**
4. Esporta gli IP malevoli o il report completo

**Alert Rule Planner**

1. Nella demo, apri il tab **Alert Rule Planner**
2. Incolla o modifica l'elenco tecniche MITRE coperte
3. Carica un export alert in CSV o JSON (es. [examples/sample-alert-events.json](examples/sample-alert-events.json))
4. Clicca **Analizza coverage** e copia i pack rule suggeriti per i gap

## Struttura repository

```
soc-automation-hub/
├── tools/csv-vt-scanner/   # Modulo principale (VT + Alert Rule Planner in demo web)
├── examples/               # CSV/JSON di esempio (dati fittizi)
├── docs/architecture.md    # Architettura tecnica
└── .github/workflows/      # Deploy Pages e release Windows
```

## Sviluppo locale

```powershell
cd tools/csv-vt-scanner
npm ci
npm test
npm run dev          # demo web in locale
npm run tauri:dev    # app desktop (richiede Rust)
```

## Dati e sicurezza

- Usa solo CSV di esempio o dati anonimizzati nei report pubblici.
- I file di configurazione locale (chiavi VT) restano solo sulla macchina dell'utente e sono esclusi da git.

## Licenza

MIT vedi [LICENSE](LICENSE).
