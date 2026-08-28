# CSV VT Scanner

Tool per analizzare liste di indirizzi IP esportate da un SIEM (es. export CSV LogPoint) e verificarne la reputazione tramite VirusTotal.

## Cosa fa

1. **Legge** un file CSV con IP pubblici (e metadati opzionali: paese, conteggio, tipo evento)
2. **Classifica** ogni IP: malevolo, pulito, non trovato, errore, saltato (privato/invalido)
3. **Mostra** statistiche con grafico a torta e percentuali
4. **Esporta** un CSV con solo gli IP malevoli o con tutti i risultati

## Demo web vs app desktop

| Funzione | Demo web | App desktop |
|----------|----------|-------------|
| Upload CSV | Sì | Sì |
| Grafico a torta | Sì | Sì |
| Export CSV | Sì (download browser) | Sì (dialog Salva con nome) |
| Scan VirusTotal reale | No | Sì |
| Più chiavi API in parallelo | No | Sì |
| Checkpoint / ripresa scan | No | Sì |

- **Demo:** https://darkgreen-projects.github.io/soc-automation-hub/
- **Desktop:** [GitHub Releases](https://github.com/DarkGreen-projects/soc-automation-hub/releases)

La demo usa una **classificazione simulata** (nessuna chiamata esterna, nessuna chiave richiesta).

## Alert Rule Planner (demo web)

Modulo nel tab omonimo della demo: confronta le **tecniche MITRE** già coperte dalle tue alert rule con gli eventi degli ultimi giorni.

1. Incolla l'inventario tecniche (es. `Brute Force – T1110.001`) e clicca **Applica tecniche**
2. Carica un export SIEM in **CSV** (con header) o **JSON** (array di eventi, oppure oggetto con chiave `records`, `rows`, `events` o `alerts`)
3. Clicca **Analizza coverage**
4. Filtra per **Gap** / **Coperti** / **Blind** e usa **Copia pack rule** (query, intervallo, throttle, template Jinja)

File di esempio: [../../examples/sample-alert-events.json](../../examples/sample-alert-events.json) e [../../examples/sample-alert-events.csv](../../examples/sample-alert-events.csv)

## SIEM Decoder (demo web)

Tab **SIEM Decoder**: incolla JSON Cynet/Defender, syslog FortiGate o lista IOC.

1. **Analizza** → tabella artefatti (IP, hash, domain, …) con link VT/AbuseIP
2. **Copia query** / **Copia report** / export Markdown
3. **Hunt query pack** — query suggerite per approfondire l'incidente
4. **Invia IOC a Bulk scan** — passa gli IOC pubblici al tab Bulk IOC

Esempio: [../../examples/sample-siem-cynet.json](../../examples/sample-siem-cynet.json)

Per OSINT Python multi-fonte (VT, AbuseIPDB, OTX, URLhaus): [Decoder_SIEMjoson](https://github.com/DarkGreen-projects/Decoder_SIEMjoson)

## CSV Pivot Analyzer (demo web)

Tab **CSV Pivot**: analizza export CSV da SIEM Search.

1. Carica CSV con header (es. `source_address`, `log_ts`, …)
2. Scegli colonna → **top valori** e **bucket temporali**
3. **Copia query** pivot con allowlist anti-rumore

Esempio: [../../examples/sample-logpoint-export.csv](../../examples/sample-logpoint-export.csv)

## Bulk IOC Scanner (demo web / desktop)

Tab **Bulk IOC**: IP, hash, domain, URL — uno per riga.

| Funzione | Demo web | Desktop |
|----------|----------|---------|
| Parse lista | Sì | Sì |
| Classificazione VT | Simulata | Reale |
| Checkpoint | No | Sì |
| Export CSV | Sì | Sì |

Esempio: [../../examples/sample-ioc-list.txt](../../examples/sample-ioc-list.txt)

## Utilizzo — demo web

1. Apri la demo nel browser
2. Clicca **Carica CSV** e seleziona il file
3. Verifica il riepilogo (IP unici, quanti verranno analizzati, quanti saltati)
4. Clicca **Anteprima demo**
5. Consulta grafico e tabella
6. Usa **Esporta malevoli** o **Esporta tutti i risultati**

## Utilizzo — app desktop

1. Scarica e avvia `csv-vt-scanner.exe` dalla release (cartella portable completa)
2. Nella sezione **API VirusTotal**, incolla una o più chiavi (una per riga) oppure importa da file `.txt`
3. Clicca **Salva elenco** o **Aggiungi a esistenti**
4. Carica il CSV e clicca **Avvia scan VT**
5. Per file grandi: aggiungi più chiavi API per ridurre i tempi (~15 secondi per richiesta per chiave)
6. Se interrompi lo scan, usa **Continua** per riprendere dagli IP ancora in coda

Le chiavi vengono salvate **solo in locale** nella cartella `data/` accanto all'eseguibile. Non vengono inviate al repository né alla demo web.

## Formato CSV

Colonne tipiche (header opzionale):

```csv
ip,country,count,event_type
8.8.8.8,United States,100,dns
203.0.113.50,Documentation,7,scan
192.168.1.1,Internal,50,local
```

Regole di parsing:

- Ogni **IPv4** presente nella riga viene estratto (anche in righe di testo libero)
- IP **duplicati** vengono ignorati (resta la prima occorrenza)
- IP **privati o riservati** (RFC1918, loopback, ecc.) sono marcati come saltati
- La verifica VT parte dal **fondo del file** verso l'alto

File di esempio: [../../examples/sample-logpoint-ips.csv](../../examples/sample-logpoint-ips.csv)

## Output export

Il CSV esportato include, per ogni IP:

`ip`, `country`, `count`, `event_type`, `category`, `vt_malicious`, `vt_total`, `vt_ratio`, `vt_permalink`, `error`

## Sviluppo

```powershell
npm ci
npm test
npm run dev          # http://localhost:1421
npm run tauri:dev    # desktop + hot reload
```

Build portable Windows:

```powershell
.\scripts\build-portable.ps1
```

Requisiti: Node.js 20+, Rust ([rustup](https://rustup.rs/)) per la build desktop.
