# SOC Automation Hub

Repository di tool per automazione SOC. La **demo web** unifica più moduli in un'unica interfaccia; l'app desktop aggiunge scan VirusTotal reale.

Parte del portfolio [DarkGreen Projects](https://github.com/DarkGreen-projects).

## Moduli demo web

[darkgreen-projects.github.io/soc-automation-hub](https://darkgreen-projects.github.io/soc-automation-hub/)

| Modulo | Cosa fa |
|--------|---------|
| **CSV VT Scanner** | Upload CSV IP → classificazione simulata, grafico, export |
| **Alert Rule Planner** | Tecniche MITRE + export alert → gap analysis e pack rule |
| **SIEM Decoder** | Log grezzo → IOC, hunt query pack, report caso |
| **CSV Pivot** | Export CSV SIEM → top valori, bucket temporali, query pivot |
| **Bulk IOC** | Lista IP/hash/domain/URL → classificazione bulk (demo simulata) |

| Modalità | URL | Cosa fa |
|----------|-----|---------|
| **Demo web** | [Pages](https://darkgreen-projects.github.io/soc-automation-hub/) | Tutti e 5 i moduli in browser |
| **Desktop** | [Releases](https://github.com/DarkGreen-projects/soc-automation-hub/releases) | VT reale, multi-chiave, checkpoint |

Guida dettagliata: [tools/csv-vt-scanner/README.md](tools/csv-vt-scanner/README.md) · [Documentazione moduli](docs/wiki/Home.md)

Tool correlato (OSINT Python completo): [Decoder_SIEMjoson](https://github.com/DarkGreen-projects/Decoder_SIEMjoson)

## Avvio rapido (demo web)

**CSV VT Scanner** — carica [sample-logpoint-ips.csv](examples/sample-logpoint-ips.csv) → **Anteprima demo** → export.

**Alert Rule Planner** — tab omonimo → tecniche MITRE → [sample-alert-events.json](examples/sample-alert-events.json) → **Analizza coverage**.

**SIEM Decoder** — incolla o carica esempio → **Analizza** → copia query/report; opzionale **Invia IOC a Bulk scan**.

**CSV Pivot** — carica [sample-logpoint-export.csv](examples/sample-logpoint-export.csv) → **Analizza** → **Copia query** su un top value.

**Bulk IOC** — [sample-ioc-list.txt](examples/sample-ioc-list.txt) → **Parsa lista** → **Anteprima demo**.

## Struttura repository

```
soc-automation-hub/
├── tools/csv-vt-scanner/   # Hub demo web + app desktop Tauri
├── examples/               # CSV/JSON/TXT di esempio (dati fittizi)
├── docs/architecture.md
└── docs/wiki/              # Documentazione moduli in-repo
```

## Sviluppo locale

```powershell
cd tools/csv-vt-scanner
npm ci
npm test
npm run dev          # http://localhost:1421
npm run tauri:dev    # desktop (Rust)
```

## Dati e sicurezza

- Solo dati fittizi negli esempi pubblici (RFC5737, domini di esempio).
- Chiavi VT e checkpoint restano solo in locale sull'app desktop.
- Non committare export reali o credenziali.

## Licenza

MIT — vedi [LICENSE](LICENSE).
