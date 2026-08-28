# SIEM Decoder

Tab demo: estrazione IOC da log multi-vendor e generazione hunt query pack.

## Utilizzo

1. Tab **SIEM Decoder**
2. Incolla JSON (Cynet, Defender), syslog FortiGate o lista IOC — oppure **Esempio JSON**
3. **Analizza** → artefatti, link VT/AbuseIP, pack query
4. **Copia report** o **Invia IOC a Bulk scan**

## Formati

JSON SIEM, CEF/syslog FortiGate, lista IOC (IP, hash, domain, URL).

Esempio: [sample-siem-cynet.json](https://github.com/DarkGreen-projects/soc-automation-hub/blob/main/examples/sample-siem-cynet.json)

## OSINT completo

Per enrich API reali (VT, AbuseIPDB, OTX, URLhaus) usa [Decoder_SIEMjoson](https://github.com/DarkGreen-projects/Decoder_SIEMjoson).
