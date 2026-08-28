import { useEffect, useMemo, useRef, useState } from "react";
import { runBulkDemoScan } from "@/lib/bulkOsint/demoScan";
import { exportBulkAllCsv, exportBulkMaliciousCsv } from "@/lib/bulkOsint/exportCsv";
import { parseBulkIocs } from "@/lib/bulkOsint/parseIocs";
import {
  countClassified,
  countResumable,
  runBulkOsintScan,
} from "@/lib/bulkOsint/scan";
import {
  PIE_COLORS,
  categoryLabel,
  computeBulkStats,
  initialBulkResults,
  type BulkScanRow,
  type ScanCategory,
} from "@/lib/bulkOsint/types";
import {
  isTauri,
  loadBulkOsintCheckpoint,
  loadOsintKeys,
  loadVtKeyPoolStatus,
  saveBulkOsintCheckpoint,
} from "@/lib/portableStore";

export const HUB_PREFILL_IOC = "soc-hub-prefill-ioc";

function PieChart({ stats }: { stats: ReturnType<typeof computeBulkStats> }) {
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
  const size = 160;
  const cx = size / 2;
  const cy = size / 2;
  const r = 70;
  if (total === 0) {
    return (
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={cx} cy={cy} r={r} fill="var(--bg-elevated)" stroke="var(--border)" />
      </svg>
    );
  }
  if (slices.length === 1) {
    return (
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={cx} cy={cy} r={r} fill={PIE_COLORS[slices[0].key]} />
      </svg>
    );
  }
  let angle = -Math.PI / 2;
  const paths: { d: string; fill: string; key: string }[] = [];
  for (const s of slices) {
    const sweep = (s.value / total) * Math.PI * 2;
    const x1 = cx + r * Math.cos(angle);
    const y1 = cy + r * Math.sin(angle);
    angle += sweep;
    const x2 = cx + r * Math.cos(angle);
    const y2 = cy + r * Math.sin(angle);
    const large = sweep > Math.PI ? 1 : 0;
    paths.push({
      key: s.key,
      fill: PIE_COLORS[s.key],
      d: `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} Z`,
    });
  }
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      {paths.map((p) => (
        <path key={p.key} d={p.d} fill={p.fill} />
      ))}
    </svg>
  );
}

export function BulkIocPanel() {
  const [text, setText] = useState("");
  const [results, setResults] = useState<BulkScanRow[]>([]);
  const [scanning, setScanning] = useState(false);
  const [keys, setKeys] = useState({ vtConfigured: false, vtKeyCount: 0, abuseConfigured: false });
  const [msg, setMsg] = useState("");
  const abortRef = useRef<AbortController | null>(null);
  const fileNameRef = useRef("paste");

  useEffect(() => {
    void loadOsintKeys().then(setKeys);
    if (isTauri()) {
      void loadBulkOsintCheckpoint().then((cp) => {
        if (!cp?.results?.length) return;
        setResults(cp.results as BulkScanRow[]);
        fileNameRef.current = cp.fileName || "checkpoint";
        setMsg(`Ripristinato checkpoint (${cp.results.length} IOC).`);
      });
    }
    const prefill = sessionStorage.getItem(HUB_PREFILL_IOC);
    if (prefill) {
      sessionStorage.removeItem(HUB_PREFILL_IOC);
      loadText(prefill, "decoder");
    }
  }, []);

  const stats = useMemo(() => computeBulkStats(results), [results]);
  const resumable = countResumable(results);

  const loadText = (content: string, name: string) => {
    const rows = parseBulkIocs(content);
    setText(content);
    setResults(initialBulkResults(rows));
    fileNameRef.current = name;
    setMsg(`${rows.length} IOC (${rows.filter((r) => !r.skipped).length} scannabili).`);
  };

  const loadSample = async () => {
    try {
      const res = await fetch(`${import.meta.env.BASE_URL}samples/sample-ioc-list.txt`);
      loadText(await res.text(), "sample");
    } catch {
      setMsg("Impossibile caricare l'esempio.");
    }
  };

  const startScan = async (mode: "fresh" | "resume") => {
    if (results.length === 0) return;
    const controller = new AbortController();
    abortRef.current = controller;
    setScanning(true);
    try {
      const onProgress = ({
        current,
        total,
        value,
        results: r,
      }: {
        current: number;
        total: number;
        value: string;
        results: BulkScanRow[];
      }) => {
        setResults(r);
        setMsg(`Scan ${current}/${total}: ${value}`);
        if (isTauri() && (current % 25 === 0 || current === total)) {
          void saveBulkOsintCheckpoint({
            fileName: fileNameRef.current,
            parseInfo: msg,
            results: r,
            savedAt: new Date().toISOString(),
          });
        }
      };

      const next = isTauri()
        ? await (async () => {
            if (!keys.vtConfigured) {
              setMsg("Configura almeno una chiave VT nell'app desktop.");
              return results;
            }
            const pool = await loadVtKeyPoolStatus();
            const concurrency = Math.max(1, pool.active || keys.vtKeyCount || 1);
            return runBulkOsintScan({
              rows: results,
              signal: controller.signal,
              concurrency,
              mode,
              onProgress,
            });
          })()
        : await runBulkDemoScan({
            rows: results,
            signal: controller.signal,
            onProgress,
          });

      setResults(next);
      if (isTauri()) {
        await saveBulkOsintCheckpoint({
          fileName: fileNameRef.current,
          parseInfo: msg,
          results: next,
          savedAt: new Date().toISOString(),
        });
      }
      setMsg(
        `Completato: ${countClassified(next)} classificati, ${next.filter((r) => r.category === "malicious").length} malevoli.` +
          (isTauri() ? "" : " (demo simulata)"),
      );
    } catch (e) {
      if (!(e instanceof DOMException && e.name === "AbortError")) {
        setMsg(e instanceof Error ? e.message : String(e));
      }
    } finally {
      setScanning(false);
      abortRef.current = null;
    }
  };

  return (
    <div className="decoder-shell">
      <section className="decoder-input">
        {!isTauri() && (
          <p className="demo-banner">
            Modalità demo web — classificazione VT simulata. Scan reale multi-IOC nell&apos;app desktop
            Windows.
          </p>
        )}
        <p className="panel-hint">
          IP, hash (MD5/SHA1/SHA256), dominio, URL — uno per riga o separati da spazio/virgola.
        </p>
        <div className="decoder-actions" style={{ marginBottom: "0.5rem" }}>
          <label className="btn btn-sm">
            Carica file
            <input
              type="file"
              accept=".txt,.csv,.ioc,text/plain"
              hidden
              onChange={async (e) => {
                const f = e.target.files?.[0];
                if (!f) return;
                loadText(await f.text(), f.name);
              }}
            />
          </label>
          <button type="button" className="btn btn-sm" onClick={() => void loadSample()}>
            Esempio IOC
          </button>
          <button type="button" className="btn btn-sm btn-primary" onClick={() => loadText(text, "paste")}>
            Parsa lista
          </button>
          <button
            type="button"
            className="btn btn-sm btn-primary"
            disabled={scanning || results.length === 0}
            onClick={() => void startScan("fresh")}
          >
            {isTauri() ? "Avvia scan VT" : "Anteprima demo"}
          </button>
          {isTauri() && (
            <button
              type="button"
              className="btn btn-sm"
              disabled={scanning || resumable === 0}
              onClick={() => void startScan("resume")}
            >
              Continua ({resumable})
            </button>
          )}
          <button
            type="button"
            className="btn btn-sm"
            disabled={!scanning}
            onClick={() => abortRef.current?.abort()}
          >
            Stop
          </button>
          <button
            type="button"
            className="btn btn-sm"
            disabled={results.length === 0}
            onClick={() => void exportBulkMaliciousCsv(results)}
          >
            Export malevoli
          </button>
          <button
            type="button"
            className="btn btn-sm"
            disabled={results.length === 0}
            onClick={() => void exportBulkAllCsv(results)}
          >
            Export tutti
          </button>
        </div>
        <textarea
          className="decoder-textarea"
          rows={8}
          placeholder={"203.0.113.50\nevil.example.com\nhttps://bad.example/path"}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        {msg && <p className="decoder-keys-msg">{msg}</p>}
      </section>

      {results.length > 0 && (
        <section className="decoder-output">
          <div style={{ display: "flex", gap: "1.5rem", alignItems: "flex-start", flexWrap: "wrap" }}>
            <PieChart stats={stats} />
            <ul className="wiki-steps">
              {(
                ["malicious", "clean", "not_found", "error", "skipped", "pending"] as ScanCategory[]
              ).map((k) => (
                <li key={k}>
                  {categoryLabel(k)}:{" "}
                  {k === "malicious"
                    ? stats.malicious
                    : k === "clean"
                      ? stats.clean
                      : k === "not_found"
                        ? stats.notFound
                        : k === "error"
                          ? stats.error
                          : k === "skipped"
                            ? stats.skipped
                            : stats.pending}
                </li>
              ))}
            </ul>
          </div>
          <table className="decoder-table">
            <thead>
              <tr>
                <th>Valore</th>
                <th>Tipo</th>
                <th>Esito</th>
                <th>VT</th>
              </tr>
            </thead>
            <tbody>
              {results
                .filter((r) => r.category !== "pending" && r.category !== "skipped")
                .slice(0, 200)
                .map((r) => (
                  <tr key={`${r.kind}|${r.value}`}>
                    <td>
                      <code>{r.value}</code>
                    </td>
                    <td>{r.kind}</td>
                    <td>{categoryLabel(r.category)}</td>
                    <td>{r.vt?.summary ?? r.error ?? "—"}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}
