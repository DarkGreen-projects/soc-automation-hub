import { useMemo, useState } from "react";
import {
  buildSummaryCsv,
  timeBuckets,
  topByColumn,
  type TopValue,
} from "@/lib/csvLp/aggregate";
import {
  parseLogpointExport,
  preferredColumns,
  resolveColumn,
  type CsvLpTable,
} from "@/lib/csvLp/parseExport";
import { pivotQueryForCell } from "@/lib/csvLp/pivots";
import { getDefaultAllowlist } from "@/lib/allowlist";
import { exportTextFile } from "@/lib/portableStore";

export function CsvPivotPanel() {
  const [text, setText] = useState("");
  const [table, setTable] = useState<CsvLpTable | null>(null);
  const [column, setColumn] = useState("");
  const [msg, setMsg] = useState("");
  const allowlist = getDefaultAllowlist();

  const columns = useMemo(
    () => (table ? preferredColumns(table.headers) : []),
    [table],
  );

  const tops: TopValue[] = useMemo(() => {
    if (!table || !column) return [];
    return topByColumn(table, column, 40);
  }, [table, column]);

  const timeCol = table
    ? resolveColumn(table.headers, "log_ts") ?? resolveColumn(table.headers, "timestamp")
    : null;
  const buckets = useMemo(() => {
    if (!table || !timeCol) return [];
    return timeBuckets(table, timeCol, 48);
  }, [table, timeCol]);

  const applyParse = (content: string, label?: string) => {
    const parsed = parseLogpointExport(content);
    if (parsed.rowCount === 0) {
      setMsg("Nessuna riga dati (serve header + almeno una riga).");
      setTable(null);
      return;
    }
    setTable(parsed);
    const prefs = preferredColumns(parsed.headers);
    setColumn(prefs[0] ?? parsed.headers[0] ?? "");
    setMsg(
      label
        ? `${label}: ${parsed.rowCount} righe, ${parsed.headers.length} colonne.`
        : `${parsed.rowCount} righe, ${parsed.headers.length} colonne.`,
    );
  };

  const loadSample = async () => {
    try {
      const res = await fetch(`${import.meta.env.BASE_URL}samples/sample-logpoint-export.csv`);
      const content = await res.text();
      setText(content);
      applyParse(content, "Esempio");
    } catch {
      setMsg("Impossibile caricare l'esempio.");
    }
  };

  const copyQuery = async (q: string) => {
    try {
      await navigator.clipboard.writeText(q);
      setMsg("Query pivot copiata.");
    } catch {
      setMsg("Copia fallita.");
    }
  };

  return (
    <div className="decoder-shell">
      <section className="decoder-input">
        <p className="panel-hint">
          Analizza un export CSV da SIEM Search: top valori, bucket temporali e query di pivot con
          allowlist anti-rumore.
        </p>
        <div className="decoder-actions" style={{ marginBottom: "0.5rem" }}>
          <label className="btn btn-sm">
            Carica CSV
            <input
              type="file"
              accept=".csv,.txt,text/csv,text/plain"
              hidden
              onChange={async (e) => {
                const f = e.target.files?.[0];
                if (!f) return;
                const content = await f.text();
                setText(content);
                applyParse(content, f.name);
              }}
            />
          </label>
          <button type="button" className="btn btn-sm" onClick={() => void loadSample()}>
            Esempio CSV
          </button>
          <button type="button" className="btn btn-sm btn-primary" onClick={() => applyParse(text)}>
            Analizza
          </button>
          <button
            type="button"
            className="btn btn-sm"
            disabled={tops.length === 0}
            onClick={() =>
              void exportTextFile(buildSummaryCsv(column, tops), {
                title: "Esporta top valori",
                defaultFileName: `csv-pivot-top-${column}.csv`,
              })
            }
          >
            Esporta top
          </button>
        </div>
        <textarea
          className="decoder-textarea"
          rows={8}
          placeholder={"source_address,user,action,log_ts\n203.0.113.1,alice,blocked,2026-08-28T12:00:00Z"}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        {msg && <p className="decoder-keys-msg">{msg}</p>}
      </section>

      {table && (
        <section className="decoder-output">
          <div className="decoder-actions">
            <label>
              Colonna{" "}
              <select value={column} onChange={(e) => setColumn(e.target.value)}>
                {columns.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </label>
          </div>

          {buckets.length > 0 && (
            <>
              <h3>Volume nel tempo ({timeCol})</h3>
              <table className="decoder-table">
                <thead>
                  <tr>
                    <th>Bucket</th>
                    <th>Count</th>
                  </tr>
                </thead>
                <tbody>
                  {buckets.map((b) => (
                    <tr key={b.bucket}>
                      <td>{b.bucket}</td>
                      <td>{b.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}

          <h3>Top {column}</h3>
          <table className="decoder-table">
            <thead>
              <tr>
                <th>Valore</th>
                <th>Count</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {tops.map((t) => {
                const q = pivotQueryForCell(column, t.value, allowlist);
                return (
                  <tr key={t.value}>
                    <td>
                      <code>{t.value}</code>
                    </td>
                    <td>{t.count}</td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-sm btn-primary"
                        disabled={!q}
                        onClick={() => void copyQuery(q)}
                      >
                        Copia query
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}
