# CSV VT Scanner

Modulo per analizzare export CSV di indirizzi IP da un SIEM e classificarli (VirusTotal o demo simulata).

## Demo web

1. Tab **CSV VT Scanner** nella [demo](https://darkgreen-projects.github.io/soc-automation-hub/)
2. Carica CSV (es. [sample-logpoint-ips.csv](https://github.com/DarkGreen-projects/soc-automation-hub/blob/main/examples/sample-logpoint-ips.csv))
3. **Anteprima demo** → grafico + tabella
4. Export malevoli o report completo

La demo **non** chiama VirusTotal: classificazione deterministica lato browser.

## Desktop

- Download da [Releases](https://github.com/DarkGreen-projects/soc-automation-hub/releases)
- Chiavi VT salvate solo in locale
- Scan reale, più chiavi in parallelo, checkpoint/ripresa

## Formato input

Colonne tipiche: `ip`, `country`, `count`, `event_type`. Ogni IPv4 nella riga viene estratto; IP privati/duplicati gestiti automaticamente.

Vedi [README completo](https://github.com/DarkGreen-projects/soc-automation-hub/blob/main/tools/csv-vt-scanner/README.md).
