# SOC Automation Hub

Repository di tool per automazione SOC. Ogni modulo in `tools/` è indipendente, con documentazione, test e (dove previsto) demo web o build desktop.

## Moduli disponibili

### [csv-vt-scanner](tools/csv-vt-scanner/)

Analizza export CSV di indirizzi IP (formato SIEM/LogPoint), classifica gli IP e produce statistiche con grafico a torta ed export CSV.

| Modalità | URL / percorso | Cosa fa |
|----------|----------------|---------|
| **Demo web** | [darkgreen-projects.github.io/soc-automation-hub](https://darkgreen-projects.github.io/soc-automation-hub/) | Upload CSV, anteprima con classificazione simulata, export |
| **Desktop** | [Releases](https://github.com/DarkGreen-projects/soc-automation-hub/releases) | Scan VirusTotal reale, più chiavi API, checkpoint |

Guida completa: [tools/csv-vt-scanner/README.md](tools/csv-vt-scanner/README.md)

## Avvio rapido (demo web)

1. Apri la [demo](https://darkgreen-projects.github.io/soc-automation-hub/)
2. Carica un CSV (es. [examples/sample-logpoint-ips.csv](examples/sample-logpoint-ips.csv))
3. Clicca **Anteprima demo**
4. Esporta gli IP malevoli o il report completo

## Struttura repository

```
soc-automation-hub/
├── tools/csv-vt-scanner/   # Modulo CSV → VirusTotal
├── examples/               # CSV di esempio (dati fittizi)
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
- Non inserire chiavi API, log reali o path interni nei commit.
- I file di configurazione locale (chiavi VT) restano solo sulla macchina dell'utente e sono esclusi da git.

## Licenza

MIT — vedi [LICENSE](LICENSE).
