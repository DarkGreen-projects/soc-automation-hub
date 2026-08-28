import { useEffect, useMemo, useRef, useState } from "react";
import { exportAllResultsCsv, exportMaliciousCsv } from "@/lib/csvVt/exportCsv";
import { parseLogpointIpCsv, scannableRows } from "@/lib/csvVt/parseCsv";
import {
  countClassified,
  countResumable,
  estimateEtaSeconds,
  formatEta,
  runCsvVtScan,
  type ScanMode,
} from "@/lib/csvVt/scan";
import {
  PIE_COLORS,
  categoryLabel,
  computePercents,
  computeStats,
  initialResults,
} from "@/lib/csvVt/stats";
import type { ScanCategory, ScanRowResult } from "@/lib/csvVt/types";
import {
  clearCsvVtCheckpoint,
  getDataDirectory,
  importVtKeysFromFile,
  isTauri,
  loadCsvVtCheckpoint,
  loadOsintKeys,
  loadVtKeyPoolStatus,
  saveCsvVtCheckpoint,
  saveOsintKeys,
  type OsintKeysStatus,
  type VtKeyPoolStatus,
} from "@/lib/portableStore";
import { runDemoScan } from "@/lib/csvVt/demoScan";
import { lookupVirusTotal } from "@/lib/osint";

interface CsvVtScannerProps {
  onBusyStatus?: (text: string | null) => void;
}

const CHECKPOINT_EVERY = 25;

function PieChart({
  stats,
}: {
  stats: ReturnType<typeof computeStats>;
}) {
  const slices: { key: Exclude<ScanCategory, "pending">; value: number }[] = (
    [
      { key: "malicious" as const, value: stats.malicious },
      { key: "clean" as const, value: stats.clean },
      { key: "not_found" as const, value: stats.notFound },
      { key: "error" as const, value: stats.error },
      { key: "skipped" as const, value: stats.skipped },
    ] as const
  ).filter((s) => s.value > 0);

  const total = slices.reduce((a, s) => a + s.value, 0);
  const size = 180;
  const cx = size / 2;
  const cy = size / 2;
  const r = 78;

  if (total === 0) {
    return (
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-label="Nessun dato">
        <circle cx={cx} cy={cy} r={r} fill="var(--bg-elevated)" stroke="var(--border)" />
        <text x={cx} y={cy} textAnchor="middle" dominantBaseline="middle" fill="var(--text-muted)" fontSize="12">
          Nessun dato
        </text>
      </svg>
    );
  }

  if (slices.length === 1) {
    const only = slices[0];
    return (
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-label="Grafico a torta">
        <circle cx={cx} cy={cy} r={r} fill={PIE_COLORS[only.key]} />
      </svg>
    );
  }

  let angle = -Math.PI / 2;
  const paths: { d: string; fill: string; key: string }[] = [];

  for (const slice of slices) {
    const sweep = (slice.value / total) * Math.PI * 2;
    const x1 = cx + r * Math.cos(angle);
    const y1 = cy + r * Math.sin(angle);
    angle += sweep;
    const x2 = cx + r * Math.cos(angle);
    const y2 = cy + r * Math.sin(angle);
    const large = sweep > Math.PI ? 1 : 0;
    paths.push({
      key: slice.key,
      fill: PIE_COLORS[slice.key],
      d: `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} Z`,
    });
  }

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-label="Grafico a torta">
      {paths.map((p) => (
        <path key={p.key} d={p.d} fill={p.fill} />
      ))}
    </svg>
  );
}

function isScanRowResult(value: unknown): value is ScanRowResult {
  if (!value || typeof value !== "object") return false;
  const o = value as Record<string, unknown>;
  return typeof o.ip === "string" && typeof o.category === "string";
}

export function CsvVtScanner({ onBusyStatus }: CsvVtScannerProps) {
  const [fileName, setFileName] = useState("");
  const [parseInfo, setParseInfo] = useState("");
  const [results, setResults] = useState<ScanRowResult[]>([]);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState({
    current: 0,
    total: 0,
    ip: "",
    lastError: "" as string,
  });
  const [error, setError] = useState("");
  const [keys, setKeys] = useState<OsintKeysStatus>({
    vtConfigured: false,
    vtKeyCount: 0,
    abuseConfigured: false,
  });
  const [pool, setPool] = useState<VtKeyPoolStatus>({ total: 0, active: 0, cooled: 0 });
  const [dataDir, setDataDir] = useState("");
  const [vtInput, setVtInput] = useState("");
  const [keysMsg, setKeysMsg] = useState("");
  const [exportMsg, setExportMsg] = useState("");
  const [checkpointMsg, setCheckpointMsg] = useState("");
  const abortRef = useRef<AbortController | null>(null);
  const busyTimer = useRef<number | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const resultsRef = useRef<ScanRowResult[]>([]);
  const fileNameRef = useRef("");
  const parseInfoRef = useRef("");
  const lastUiFlush = useRef(0);
  const pendingUiResults = useRef<ScanRowResult[] | null>(null);
  const uiFlushTimer = useRef<number | null>(null);

  const TABLE_LIMIT = 150;

  const setBusy = (text: string | null, clearAfterMs?: number) => {
    onBusyStatus?.(text);
    if (busyTimer.current != null) {
      window.clearTimeout(busyTimer.current);
      busyTimer.current = null;
    }
    if (clearAfterMs != null) {
      busyTimer.current = window.setTimeout(() => {
        onBusyStatus?.(null);
        busyTimer.current = null;
      }, clearAfterMs);
    }
  };

  useEffect(() => {
    resultsRef.current = results;
  }, [results]);
  useEffect(() => {
    fileNameRef.current = fileName;
  }, [fileName]);
  useEffect(() => {
    parseInfoRef.current = parseInfo;
  }, [parseInfo]);

  const onBusyRef = useRef(onBusyStatus);
  onBusyRef.current = onBusyStatus;

  useEffect(() => {
    void (async () => {
      const status = await loadOsintKeys();
      setKeys(status);
      setDataDir(await getDataDirectory());
      if (isTauri()) {
        setPool(await loadVtKeyPoolStatus());
      }
      const ckpt = await loadCsvVtCheckpoint();
      if (ckpt?.results?.length) {
        setCheckpointMsg(
          `Checkpoint trovato (${ckpt.fileName || "senza nome"}, ${ckpt.results.length} IP, ${ckpt.savedAt}). Usa Ripristina per recuperare.`,
        );
      }
    })();
  }, []);

  // Abort only on real unmount — do NOT depend on onBusyStatus (would kill in-flight scans).
  useEffect(() => {
    return () => {
      abortRef.current?.abort();
      if (busyTimer.current != null) window.clearTimeout(busyTimer.current);
      if (uiFlushTimer.current != null) window.clearTimeout(uiFlushTimer.current);
      onBusyRef.current?.(null);
    };
  }, []);

  const stats = useMemo(() => computeStats(results), [results]);
  const percents = useMemo(() => computePercents(stats), [stats]);
  const resumable = useMemo(() => countResumable(results), [results]);
  const classified = useMemo(() => countClassified(results), [results]);
  const activeKeys = Math.max(1, pool.active || keys.vtKeyCount || 1);
  const eta = formatEta(
    estimateEtaSeconds(Math.max(0, progress.total - progress.current), 15, activeKeys),
  );
  const canExportMalicious = stats.malicious > 0;
  const canExportAll = classified > 0 || stats.skipped > 0;

  /** Prefer completed outcomes; avoid rendering thousands of pending rows (freezes UI). */
  const tableRows = useMemo(() => {
    const done = results.filter((r) => r.category !== "pending");
    if (done.length > 0) {
      return done.slice(0, TABLE_LIMIT);
    }
    return results.slice(0, Math.min(50, results.length));
  }, [results]);

  const flushResultsToUi = (rows: ScanRowResult[], force = false) => {
    const now = Date.now();
    pendingUiResults.current = rows;
    if (!force && now - lastUiFlush.current < 750) {
      if (uiFlushTimer.current == null) {
        uiFlushTimer.current = window.setTimeout(() => {
          uiFlushTimer.current = null;
          lastUiFlush.current = Date.now();
          if (pendingUiResults.current) {
            setResults(pendingUiResults.current.slice());
          }
        }, 750);
      }
      return;
    }
    lastUiFlush.current = now;
    setResults(rows.slice());
  };

  const persistCheckpoint = async (rows: ScanRowResult[]) => {
    try {
      await saveCsvVtCheckpoint({
        fileName: fileNameRef.current,
        parseInfo: parseInfoRef.current,
        results: rows,
        savedAt: new Date().toISOString(),
      });
    } catch {
      /* ignore checkpoint errors during scan */
    }
  };

  const refreshPool = async () => {
    if (!isTauri()) return;
    try {
      setPool(await loadVtKeyPoolStatus());
    } catch {
      /* ignore */
    }
  };

  const parseVtKeysInput = (text: string): string[] =>
    text
      .split(/[\r\n,;]+/)
      .map((k) => k.trim())
      .filter(Boolean);

  const onFile = async (file: File | null) => {
    if (!file) return;
    setError("");
    setCheckpointMsg("");
    setFileName(file.name);
    const text = await file.text();
    const parsed = parseLogpointIpCsv(text);
    const init = initialResults(parsed.rows);
    setResults(init);
    const publicN = scannableRows(parsed.rows).length;
    const skippedN = parsed.rows.length - publicN;
    const keysN = Math.max(1, keys.vtKeyCount || 1);
    const etaHint = formatEta(estimateEtaSeconds(publicN, 15, keysN));
    const info =
      `${parsed.uniqueCount} IP unici` +
      (parsed.hadHeader ? " (header rilevato)" : "") +
      ` — ${publicN} da verificare, ${skippedN} saltati` +
      (parsed.skippedLines > (parsed.hadHeader ? 1 : 0)
        ? `, ${parsed.skippedLines - (parsed.hadHeader ? 1 : 0)} righe duplicate/vuote ignorate`
        : "") +
      (publicN > 0
        ? ` · ETA stimata ~${etaHint} con ${keysN} chiav${keysN === 1 ? "e" : "i"}`
        : "");
    setParseInfo(info);
    setProgress({ current: 0, total: publicN, ip: "", lastError: "" });
    await persistCheckpoint(init);
  };

  const saveKeys = async () => {
    const list = parseVtKeysInput(vtInput);
    if (list.length === 0) {
      setKeysMsg("Incolla una o più API key (una per riga).");
      return;
    }
    const status = await saveOsintKeys({ vtApiKeys: list });
    setKeys(status);
    setVtInput("");
    setKeysMsg(
      `${status.vtKeyCount} chiav${status.vtKeyCount === 1 ? "e" : "i"} salvate in osint-keys.json.`,
    );
    await refreshPool();
  };

  const addKeys = async () => {
    const incoming = parseVtKeysInput(vtInput);
    if (incoming.length === 0) {
      setKeysMsg("Incolla una o più API key da aggiungere.");
      return;
    }
    let status = keys;
    for (const key of incoming) {
      status = await saveOsintKeys({ vtApiKey: key });
    }
    setKeys(status);
    setVtInput("");
    setKeysMsg(
      `Aggiunte. Totale: ${status.vtKeyCount} chiav${status.vtKeyCount === 1 ? "e" : "i"} in osint-keys.json.`,
    );
    await refreshPool();
  };

  const importKeysFile = async () => {
    setKeysMsg("");
    try {
      const status = await importVtKeysFromFile();
      setKeys(status);
      setKeysMsg(
        `Import ok: ${status.vtKeyCount} chiav${status.vtKeyCount === 1 ? "e" : "i"} totali (merge + dedupe).`,
      );
      await refreshPool();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (!msg.includes("annullato")) setKeysMsg(msg);
    }
  };

  const runDemo = async () => {
    setError("");
    if (results.length === 0) {
      setError("Carica prima un CSV.");
      return;
    }
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setScanning(true);
    setBusy("Demo: classificazione simulata…");
    try {
      const baseRows = results.map(
        ({ ip, country, count, eventType, skipped, skipReason }) => ({
          ip,
          country,
          count,
          eventType,
          skipped,
          skipReason,
        }),
      );
      const fresh = initialResults(baseRows);
      const finalResults = await runDemoScan({
        rows: fresh,
        signal: ac.signal,
        onProgress: (p) => {
          resultsRef.current = p.results;
          setProgress({
            current: p.current,
            total: p.total,
            ip: p.ip,
            lastError: "",
          });
          flushResultsToUi(p.results, p.current === p.total && p.total > 0);
        },
      });
      resultsRef.current = finalResults;
      setResults(finalResults.slice());
      setBusy("Demo completata", 1200);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setScanning(false);
      abortRef.current = null;
    }
  };

  const runScan = async (mode: ScanMode) => {
    setError("");
    if (!isTauri()) {
      setError("VirusTotal è disponibile solo nell'app desktop. Usa Anteprima demo o scarica l'exe.");
      return;
    }
    const status = await loadOsintKeys();
    setKeys(status);
    if (!status.vtConfigured || status.vtKeyCount < 1) {
      setError("Nessuna chiave VT: importa un .txt o salva le key qui sotto.");
      return;
    }
    await refreshPool();

    if (results.length === 0) {
      setError("Carica prima un CSV.");
      return;
    }

    if (mode === "resume" && resumable === 0) {
      setError("Niente da continuare (nessun IP in coda o in errore).");
      return;
    }

    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setScanning(true);
    lastUiFlush.current = 0;
    resultsRef.current = results;
    setError("");
    setProgress((p) => ({ ...p, lastError: "" }));
    setBusy("CSV VT: test connessione API…");

    try {
      // Preflight: one cheap lookup so we fail fast if Rust/HTTP/keys are broken.
      try {
        await lookupVirusTotal("ip", "8.8.8.8", { maxAttempts: Math.max(status.vtKeyCount, 3) });
      } catch (probeErr) {
        const msg = probeErr instanceof Error ? probeErr.message : String(probeErr);
        setError(`Test VT fallito: ${msg}. Controlla rete/chiavi e riprova.`);
        setScanning(false);
        abortRef.current = null;
        setBusy(null);
        return;
      }
      if (ac.signal.aborted) {
        setScanning(false);
        abortRef.current = null;
        return;
      }

      setBusy(mode === "resume" ? "CSV VT: ripresa…" : "CSV VT: avvio…");
      const finalResults = await runCsvVtScan({
        rows: results,
        mode,
        signal: ac.signal,
        concurrency: Math.max(1, status.vtKeyCount),
        onProgress: (p) => {
          resultsRef.current = p.results;
          setProgress({
            current: p.current,
            total: p.total,
            ip: p.ip,
            lastError: p.lastError ?? "",
          });
          flushResultsToUi(p.results, p.current === p.total && p.total > 0);
          if (p.current > 0 && p.current % CHECKPOINT_EVERY === 0) {
            void persistCheckpoint(p.results);
          }
          if (p.current > 0 && p.current % 50 === 0) {
            void refreshPool();
          }
          if (p.total > 0) {
            const pct = Math.round((p.current / p.total) * 100);
            setBusy(
              `CSV VT ${pct}% — ${p.current}/${p.total}` +
                (p.ip ? ` (${p.ip})` : "") +
                ` · ${status.vtKeyCount} chiavi` +
                (p.lastError ? ` · ultimo err: ${p.lastError}` : ""),
            );
          }
        },
      });
      if (uiFlushTimer.current != null) {
        window.clearTimeout(uiFlushTimer.current);
        uiFlushTimer.current = null;
      }
      resultsRef.current = finalResults;
      setResults(finalResults.slice());
      await persistCheckpoint(finalResults);
      await refreshPool();
      if (ac.signal.aborted) {
        setBusy("CSV VT interrotto — risultati conservati", 2000);
        setCheckpointMsg("Scan interrotto: puoi esportare o continuare.");
      } else {
        setBusy("CSV VT completato", 1200);
        setCheckpointMsg("");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      await persistCheckpoint(resultsRef.current);
      setBusy(null);
    } finally {
      setScanning(false);
      abortRef.current = null;
    }
  };

  const stopScan = () => {
    abortRef.current?.abort();
  };

  const restoreCheckpoint = async () => {
    const ckpt = await loadCsvVtCheckpoint();
    if (!ckpt?.results?.length) {
      setCheckpointMsg("Nessun checkpoint da ripristinare.");
      return;
    }
    const rows = ckpt.results.filter(isScanRowResult);
    if (rows.length === 0) {
      setCheckpointMsg("Checkpoint non valido.");
      return;
    }
    setFileName(ckpt.fileName || "checkpoint");
    setParseInfo(ckpt.parseInfo || "");
    setResults(rows);
    const pending = rows.filter((r) => r.category === "pending").length;
    setProgress({
      current: rows.length - pending,
      total: rows.filter((r) => !r.skipped).length,
      ip: "",
      lastError: "",
    });
    setCheckpointMsg(
      `Ripristinati ${rows.length} IP da checkpoint (${ckpt.savedAt}). Usa Continua per riprendere.`,
    );
    setError("");
  };

  const clearAll = async () => {
    abortRef.current?.abort();
    setResults([]);
    setFileName("");
    setParseInfo("");
    setError("");
    setProgress({ current: 0, total: 0, ip: "", lastError: "" });
    setBusy(null);
    setExportMsg("");
    setCheckpointMsg("");
    if (fileRef.current) fileRef.current.value = "";
    try {
      await clearCsvVtCheckpoint();
    } catch {
      /* ignore */
    }
  };

  return (
    <div className="csvvt-shell">
      <div className="csvvt-left">
        {!isTauri() && (
          <div className="demo-banner">
            <strong>Modalità demo web</strong> — upload CSV, grafico e export funzionano con
            classificazione simulata. Per scan VirusTotal reale e multi-API scarica l&apos;app
            Windows dalle{" "}
            <a
              href="https://github.com/DarkGreen-projects/soc-automation-hub/releases"
              target="_blank"
              rel="noreferrer"
            >
              Releases
            </a>
            .
          </div>
        )}
        <p className="csvvt-intro">
          Carica un CSV LogPoint (<code>ip,country,count,event_type</code>) oppure un file con
          righe libere: ogni IPv4 presente riga per riga viene estratto e verificato uno a uno.
          Con più API key lo scan parallela (~15s/chiave); su quota/errore API passa da solo a
          un&apos;altra chiave. La verifica parte dal <strong>fondo</strong> del file. Puoi
          esportare anche a metà scan.
        </p>

        <div className="decoder-actions">
          <label className="btn btn-sm btn-primary csvvt-file-btn">
            Carica CSV
            <input
              ref={fileRef}
              type="file"
              accept=".csv,text/csv,text/plain"
              hidden
              onChange={(e) => void onFile(e.target.files?.[0] ?? null)}
            />
          </label>
          {!isTauri() ? (
            <button
              type="button"
              className="btn btn-sm btn-primary"
              disabled={scanning || results.length === 0}
              onClick={() => void runDemo()}
            >
              {classified > 0 ? "Riesegui demo" : "Anteprima demo"}
            </button>
          ) : (
            <button
              type="button"
              className="btn btn-sm btn-primary"
              disabled={scanning || results.length === 0}
              onClick={() => void runScan("fresh")}
            >
              {classified > 0 ? "Ricomincia da zero" : "Avvia scan VT"}
            </button>
          )}
          {isTauri() && (
            <button
              type="button"
              className="btn btn-sm"
              disabled={scanning || resumable === 0}
              onClick={() => void runScan("resume")}
            >
              Continua ({resumable})
            </button>
          )}
          {scanning && (
            <button type="button" className="btn btn-sm" onClick={stopScan}>
              Interrompi
            </button>
          )}
          <button type="button" className="btn btn-sm" onClick={() => void clearAll()} disabled={scanning}>
            Pulisci
          </button>
          <button
            type="button"
            className="btn btn-sm"
            disabled={scanning}
            onClick={() => void restoreCheckpoint()}
          >
            Ripristina checkpoint
          </button>
        </div>

        {fileName && (
          <p className="decoder-ctx" style={{ marginTop: "0.75rem" }}>
            File: <strong>{fileName}</strong>
            {parseInfo ? ` — ${parseInfo}` : ""}
          </p>
        )}

        {checkpointMsg && <p className="decoder-keys-msg">{checkpointMsg}</p>}

        {(scanning || progress.total > 0) && (
          <div className="csvvt-progress">
            <div className="csvvt-progress-bar">
              <div
                className="csvvt-progress-fill"
                style={{
                  width: `${progress.total ? Math.round((progress.current / progress.total) * 100) : 0}%`,
                }}
              />
            </div>
            <span className="decoder-ctx">
              {progress.current}/{progress.total}
              {progress.ip ? ` — ${progress.ip}` : ""} · ETA ~{eta}
              {pool.total > 0
                ? ` · chiavi ${pool.active} attive / ${pool.cooled} cooldown`
                : keys.vtKeyCount > 0
                  ? ` · ${keys.vtKeyCount} chiavi`
                  : ""}
              {scanning ? " · in corso…" : ""}
            </span>
            {progress.lastError ? (
              <p className="decoder-error" style={{ margin: "0.25rem 0 0" }}>
                Ultimo errore lookup: {progress.lastError}
              </p>
            ) : null}
          </div>
        )}

        {error && <p className="decoder-error">{error}</p>}

        <div className="decoder-keys">
          <div className="decoder-keys-title">
            API VirusTotal {!isTauri() && "(solo desktop)"}
          </div>
          <p className="decoder-keys-msg">
            {keys.vtKeyCount > 0
              ? `${keys.vtKeyCount} chiav${keys.vtKeyCount === 1 ? "e" : "i"} già salvate`
              : "Nessuna chiave salvata"}
            {dataDir ? ` in ${dataDir}\\osint-keys.json` : " in osint-keys.json"}. Non serve
            reincollarle a ogni avvio: importa un .txt o aggiungi sotto.
          </p>
          <div className="decoder-key-row">
            <span>Aggiungi key (una per riga) oppure importa da file</span>
            <textarea
              className="csvvt-keys-textarea"
              placeholder={"vt-key-1\nvt-key-2\nvt-key-3"}
              value={vtInput}
              onChange={(e) => setVtInput(e.target.value)}
              disabled={!isTauri()}
              rows={3}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <div className="decoder-actions">
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => void importKeysFile()}
              disabled={!isTauri()}
            >
              Importa da file .txt
            </button>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => void addKeys()}
              disabled={!isTauri() || !vtInput.trim()}
            >
              Aggiungi a esistenti
            </button>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => void saveKeys()}
              disabled={!isTauri() || !vtInput.trim()}
              title="Sostituisce tutto l'elenco con quanto scritto nella textarea"
            >
              Sostituisci elenco
            </button>
          </div>
          {keysMsg && <p className="decoder-keys-msg">{keysMsg}</p>}
        </div>
      </div>

      <div className="csvvt-right">
        {results.length === 0 ? (
          <p className="decoder-ctx">Nessun CSV caricato.</p>
        ) : (
          <>
            <div className="csvvt-summary">
              <div className="csvvt-pie-wrap">
                <PieChart stats={stats} />
                <ul className="csvvt-legend">
                  {(
                    [
                      ["malicious", stats.malicious, percents.malicious],
                      ["clean", stats.clean, percents.clean],
                      ["not_found", stats.notFound, percents.notFound],
                      ["error", stats.error, percents.error],
                      ["skipped", stats.skipped, percents.skipped],
                    ] as const
                  ).map(([key, count, pct]) => (
                    <li key={key}>
                      <span
                        className="csvvt-swatch"
                        style={{ background: PIE_COLORS[key] }}
                      />
                      {categoryLabel(key)}: <strong>{count}</strong> ({pct}%)
                    </li>
                  ))}
                  {stats.pending > 0 && (
                    <li>
                      <span className="csvvt-swatch csvvt-swatch-pending" />
                      In coda: <strong>{stats.pending}</strong>
                    </li>
                  )}
                </ul>
              </div>

              <div className="decoder-actions" style={{ marginTop: "0.75rem" }}>
                <button
                  type="button"
                  className="btn btn-sm btn-primary"
                  disabled={!canExportMalicious}
                  onClick={() => {
                    void (async () => {
                      setExportMsg("");
                      try {
                        const snap =
                          resultsRef.current.length > 0 ? resultsRef.current : results;
                        const saved = await exportMaliciousCsv(snap);
                        setExportMsg(
                          saved ? "CSV malevoli salvato." : "Esportazione annullata.",
                        );
                      } catch (err) {
                        setExportMsg(err instanceof Error ? err.message : String(err));
                      }
                    })();
                  }}
                >
                  Esporta malevoli ({stats.malicious})
                </button>
                <button
                  type="button"
                  className="btn btn-sm"
                  disabled={!canExportAll}
                  onClick={() => {
                    void (async () => {
                      setExportMsg("");
                      try {
                        const snap =
                          resultsRef.current.length > 0 ? resultsRef.current : results;
                        const saved = await exportAllResultsCsv(snap);
                        setExportMsg(
                          saved ? "CSV completo salvato." : "Esportazione annullata.",
                        );
                      } catch (err) {
                        setExportMsg(err instanceof Error ? err.message : String(err));
                      }
                    })();
                  }}
                >
                  Esporta tutti i risultati
                </button>
              </div>
              {exportMsg && <p className="decoder-keys-msg">{exportMsg}</p>}
            </div>

            <p className="decoder-ctx" style={{ marginTop: "0.5rem" }}>
              Tabella: primi {tableRows.length} esiti
              {results.length > tableRows.length
                ? ` (su ${results.length} totali; la coda pending non è listata per non bloccare l’UI)`
                : ""}
              . Export CSV include tutto.
            </p>
            <table className="decoder-table">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Paese</th>
                  <th>Count</th>
                  <th>Tipo</th>
                  <th>Esito</th>
                  <th>VT</th>
                </tr>
              </thead>
              <tbody>
                {tableRows.map((r) => (
                  <tr key={r.ip} className={`csvvt-row-${r.category}`}>
                    <td className="decoder-value">{r.ip}</td>
                    <td>{r.country}</td>
                    <td>{r.count}</td>
                    <td>{r.eventType}</td>
                    <td>
                      <span className={`tag tag-csvvt-${r.category}`}>
                        {categoryLabel(r.category)}
                        {r.skipReason === "private"
                          ? " (privato)"
                          : r.skipReason === "invalid"
                            ? " (invalido)"
                            : ""}
                      </span>
                    </td>
                    <td className="decoder-osint">
                      {r.vt?.detectionRatio
                        ? r.vt.detectionRatio
                        : r.error
                          ? r.error
                          : r.category === "pending"
                            ? "…"
                            : "—"}
                      {r.vt?.permalink ? (
                        <>
                          {" "}
                          <a href={r.vt.permalink} target="_blank" rel="noreferrer">
                            VT
                          </a>
                        </>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
    </div>
  );
}
