import { useEffect, useMemo, useState } from "react";
import seedData from "@/data/alert-coverage.seed.json";
import {
  analyzeCoverage,
  type CoverageAnalysis,
  type CoverageRow,
} from "@/lib/alertCoverage/analyzeCoverage";
import { formatVendors } from "@/lib/alertCoverage/vendors";
import {
  mergeTechniqueMeta,
  parseTechniquesFromText,
  techniquesToText,
  type AlertCoverageState,
  type CoveredTechnique,
} from "@/lib/alertCoverage/parseTechniques";
import { parseAlertsInput } from "@/lib/csvLp/parseAlertsInput";

interface AlertCoveragePanelProps {
  onMessage?: (text: string) => void;
}

const SEED = seedData as AlertCoverageState;
const STORAGE_KEY = "soc-hub-alert-coverage";

const EXPORT_FIELDS_QUERY =
  "| fields log_ts, norm_id, col_type, device_name, event_category, sub_category, subtype, action, category, application, app, label, msg, title, severity, log_severity, event_id, source_address, destination_address, srcip, dstip, user, hostname, computer, process_name, file_path, threat_name, attack";

function statusLabel(status: CoverageRow["status"]): string {
  switch (status) {
    case "gap":
      return "Osservato, non coperto";
    case "covered":
      return "Coperto e visto";
    case "blind":
      return "Coperto, non visto nel export";
  }
}

function loadStoredTechniques(): CoveredTechnique[] | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as AlertCoverageState;
    if (!Array.isArray(parsed.covered) || parsed.covered.length === 0) return null;
    return mergeTechniqueMeta(parsed.covered, SEED.covered);
  } catch {
    return null;
  }
}

export function AlertCoveragePanel({ onMessage }: AlertCoveragePanelProps) {
  const [techText, setTechText] = useState(() => techniquesToText(SEED.covered));
  const [covered, setCovered] = useState<CoveredTechnique[]>(SEED.covered);
  const [alertText, setAlertText] = useState("");
  const [analysis, setAnalysis] = useState<CoverageAnalysis | null>(null);
  const [msg, setMsg] = useState("");
  const [filter, setFilter] = useState<"all" | "gap" | "covered" | "blind">("all");

  const notify = (text: string) => {
    setMsg(text);
    onMessage?.(text);
  };

  useEffect(() => {
    const stored = loadStoredTechniques();
    if (stored) {
      setCovered(stored);
      setTechText(techniquesToText(stored));
      notify(`Caricate ${stored.length} tecniche dal browser.`);
    }
  }, []);

  const filteredRows = useMemo(() => {
    if (!analysis) return [];
    if (filter === "all") return analysis.rows;
    return analysis.rows.filter((r) => r.status === filter);
  }, [analysis, filter]);

  const saveCovered = () => {
    const parsed = parseTechniquesFromText(techText);
    const merged = mergeTechniqueMeta(parsed, SEED.covered);
    const state: AlertCoverageState = { covered: merged, notes: SEED.notes };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    setCovered(merged);
    setTechText(techniquesToText(merged));
    notify(`Salvate ${merged.length} tecniche (solo in questo browser).`);
    if (alertText.trim()) runAnalyze(alertText);
  };

  const resetSeed = () => {
    setCovered(SEED.covered);
    setTechText(techniquesToText(SEED.covered));
    localStorage.setItem(STORAGE_KEY, JSON.stringify(SEED));
    notify("Ripristinato elenco tecniche di esempio.");
    if (alertText.trim()) runAnalyze(alertText);
  };

  const runAnalyze = (content: string) => {
    const parsedTable = parseAlertsInput(content);
    if (parsedTable.rowCount === 0) {
      notify("Nessun evento valido. Usa CSV con header o JSON (array di oggetti).");
      setAnalysis(null);
      return;
    }
    const result = analyzeCoverage(parsedTable, covered, SEED.covered);
    setAnalysis(result);
    notify(
      `${parsedTable.rowCount} eventi · gap ${result.gaps.length} · coperti visti ${result.coveredSeen.length} · blind ${result.blinds.length}`,
    );
  };

  const loadSample = async (kind: "json" | "csv") => {
    const path =
      kind === "json"
        ? `${import.meta.env.BASE_URL}samples/sample-alert-events.json`
        : `${import.meta.env.BASE_URL}samples/sample-alert-events.csv`;
    try {
      const res = await fetch(path);
      const text = await res.text();
      setAlertText(text);
      runAnalyze(text);
    } catch {
      notify("Impossibile caricare il file di esempio.");
    }
  };

  const copyRule = async (row: CoverageRow) => {
    const block = row.suggestion?.copyBlock ?? row.suggestion?.query;
    if (!block) return;
    try {
      await navigator.clipboard.writeText(block);
      notify(`Copiato pack rule ${row.techniqueId}.`);
    } catch {
      notify("Copia fallita.");
    }
  };

  return (
    <div className="alert-coverage-shell">
      <p className="panel-intro">
        Confronta le <strong>tecniche MITRE già coperte</strong> dalle tue alert rule con gli
        eventi degli ultimi giorni (export CSV o JSON). Per ogni gap propone un pack rule: nome,
        query, intervallo, throttle e template notifica.
      </p>

      <section className="panel-section">
        <h2>1. Tecniche coperte</h2>
        <p className="panel-hint">
          Incolla l&apos;inventario (nome + ID MITRE). Esempio:{" "}
          <code>Brute Force – T1110.001</code>
        </p>
        <textarea
          className="panel-textarea"
          rows={7}
          value={techText}
          onChange={(e) => setTechText(e.target.value)}
        />
        <div className="decoder-actions">
          <button type="button" className="btn btn-sm btn-primary" onClick={saveCovered}>
            Applica tecniche
          </button>
          <button type="button" className="btn btn-sm" onClick={resetSeed}>
            Reset esempio
          </button>
        </div>
      </section>

      <section className="panel-section">
        <h2>2. Eventi / alert (24h o più)</h2>
        <p className="panel-hint">
          Carica un export SIEM in <strong>CSV</strong> (con header) o <strong>JSON</strong> (array
          di eventi, oppure oggetto con chiave <code>records</code>, <code>rows</code>,{" "}
          <code>events</code> o <code>alerts</code>).
        </p>
        <pre className="panel-code">{EXPORT_FIELDS_QUERY}</pre>
        <div className="decoder-actions">
          <label className="btn btn-sm">
            Carica file
            <input
              type="file"
              accept=".csv,.json,.txt,text/csv,application/json"
              hidden
              onChange={async (e) => {
                const f = e.target.files?.[0];
                if (!f) return;
                const content = await f.text();
                setAlertText(content);
                runAnalyze(content);
              }}
            />
          </label>
          <button type="button" className="btn btn-sm" onClick={() => void loadSample("json")}>
            Esempio JSON
          </button>
          <button type="button" className="btn btn-sm" onClick={() => void loadSample("csv")}>
            Esempio CSV
          </button>
          <button
            type="button"
            className="btn btn-sm btn-primary"
            onClick={() => runAnalyze(alertText)}
          >
            Analizza coverage
          </button>
        </div>
        <textarea
          className="panel-textarea"
          rows={6}
          value={alertText}
          onChange={(e) => setAlertText(e.target.value)}
          placeholder='[{"source_address":"203.0.113.1","action":"pass","sub_category":"ips"}]'
        />
        {msg && <p className="decoder-keys-msg">{msg}</p>}
      </section>

      {analysis && (
        <section className="panel-section">
          <h2>3. Gap e suggerimenti rule</h2>
          <p className="panel-hint">Vendor rilevati: {formatVendors(analysis.detectedVendors)}</p>
          <div className="decoder-actions">
            {(
              [
                ["all", "Tutti"],
                ["gap", "Gap"],
                ["covered", "Coperti"],
                ["blind", "Blind"],
              ] as const
            ).map(([id, label]) => (
              <button
                key={id}
                type="button"
                className={`btn btn-sm ${filter === id ? "btn-primary" : ""}`}
                onClick={() => setFilter(id)}
              >
                {label}
              </button>
            ))}
          </div>

          {analysis.signalsFired.length > 0 && (
            <table className="decoder-table">
              <thead>
                <tr>
                  <th>Segnale</th>
                  <th>Hit</th>
                </tr>
              </thead>
              <tbody>
                {analysis.signalsFired
                  .sort((a, b) => b.hits - a.hits)
                  .map((s) => (
                    <tr key={s.signalId}>
                      <td>{s.label}</td>
                      <td>{s.hits}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          )}

          <table className="decoder-table coverage-table">
            <thead>
              <tr>
                <th>Tecnica</th>
                <th>Stato</th>
                <th>Hit</th>
                <th>Gravità</th>
                <th>Alert rule suggerita</th>
              </tr>
            </thead>
            <tbody>
              {filteredRows.map((row) => (
                <tr key={row.techniqueId}>
                  <td>
                    <strong>{row.techniqueId}</strong>
                    <div className="row-sub">{row.techniqueName}</div>
                  </td>
                  <td>{statusLabel(row.status)}</td>
                  <td>{row.hitCount}</td>
                  <td>
                    <span className="tag">{row.severity}</span>
                  </td>
                  <td>
                    {row.suggestion ? (
                      <div className="rule-pack">
                        <div className="row-sub">
                          <strong>{row.suggestion.ruleName}</strong>
                        </div>
                        <div className="row-sub">{row.suggestion.description}</div>
                        <pre className="panel-code panel-code-sm">{row.suggestion.query}</pre>
                        <button
                          type="button"
                          className="btn btn-sm btn-primary"
                          onClick={() => void copyRule(row)}
                        >
                          Copia pack rule
                        </button>
                      </div>
                    ) : (
                      "—"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}
