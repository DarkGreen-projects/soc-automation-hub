# CSV VT Scanner

Verifica indirizzi IP esportati da LogPoint/Guardsix tramite **VirusTotal**, con grafico a torta delle percentuali e export CSV degli IP malevoli.

Parte del [SOC Automation Hub](https://github.com/DarkGreen-projects/soc-automation-hub).

## Demo web

https://darkgreen-projects.github.io/soc-automation-hub/

La demo web permette:
- upload CSV LogPoint (`ip,country,count,event_type`)
- **Anteprima demo** con classificazione simulata
- grafico a torta e percentuali
- export CSV (download browser)

## App desktop (VirusTotal reale)

Scarica l'ultima release Windows: [GitHub Releases](https://github.com/DarkGreen-projects/soc-automation-hub/releases)

Funzionalità desktop aggiuntive:
- scan VirusTotal reale
- **multi-API key** con parallelismo (~15s per chiave)
- checkpoint e ripresa scan
- export con dialog Salva con nome

### Avvio sviluppo desktop

```powershell
cd tools/csv-vt-scanner
npm ci
npm run tauri:dev
```

Richiede Node.js 20+ e [Rust](https://rustup.rs/).

### Build portable

```powershell
.\scripts\build-portable.ps1
```

Output in `dist/CsvVtScanner/`.

## Formato CSV

Esempio export LogPoint:

```csv
ip,country,count,event_type
8.8.8.8,United States,100,dns
192.168.1.1,Internal,50,server-rst
```

Gli IP privati vengono saltati automaticamente.

## Test

```powershell
npm test
```

## Sicurezza

- Non committare `osint-keys.json` o file con API key
- Usa solo dati di esempio nei repository pubblici
