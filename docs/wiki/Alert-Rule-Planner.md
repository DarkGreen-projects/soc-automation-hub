# Alert Rule Planner

Modulo demo per **detection engineering**: confronta le tecniche MITRE già coperte dalle alert rule con gli eventi recenti e propone pack rule per i gap.

## Demo web

1. Tab **Alert Rule Planner** nella [demo](https://darkgreen-projects.github.io/soc-automation-hub/)
2. Incolla tecniche coperte (es. `Brute Force – T1110.001`) → **Applica tecniche**
3. Carica export alert **CSV** o **JSON** → **Analizza coverage**
4. Filtra Gap / Coperti / Blind → **Copia pack rule**

## Input supportati

**Tecniche** — testo libero con ID MITRE (`T1110`, `T1190`, …) e nome opzionale.

**Eventi** — uno dei formati:

- CSV con header (export SIEM)
- JSON array di oggetti evento
- JSON oggetto con chiave `records`, `rows`, `events`, `alerts`, `data` o `results`

Esempi: [sample-alert-events.json](https://github.com/DarkGreen-projects/soc-automation-hub/blob/main/examples/sample-alert-events.json), [sample-alert-events.csv](https://github.com/DarkGreen-projects/soc-automation-hub/blob/main/examples/sample-alert-events.csv)

## Output

Per ogni gap (e anche sulle tecniche coperte viste):

- Nome rule (`AR-{techniqueId}-…`)
- Query LogPoint-ready (single-line)
- Intervallo, throttle, risk
- Template Jinja notifica
- **Copy pack** — blocco pronto da incollare

## Stati coverage

| Stato | Significato |
|-------|-------------|
| **Gap** | Segnale osservato nell'export, tecnica non in inventario coperto |
| **Coperto** | Tecnica in inventario e segnale visto |
| **Blind** | Tecnica coperta ma nessun hit rilevante nell'export |

## Persistenza

L'inventario tecniche è salvato in `localStorage` del browser (solo demo). Nessun backend.

Vedi [architettura](https://github.com/DarkGreen-projects/soc-automation-hub/blob/main/docs/architecture.md) e [README tool](https://github.com/DarkGreen-projects/soc-automation-hub/blob/main/tools/csv-vt-scanner/README.md#alert-rule-planner-demo-web).
