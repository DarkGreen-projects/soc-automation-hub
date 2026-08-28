import { useEffect, useMemo, useState, type ReactNode } from "react";
import { getDefaultAllowlist, type Allowlist } from "@/lib/allowlist";
import { buildCaseReportMarkdown } from "@/lib/decoder/caseReport";
import { buildInvestigationPack } from "@/lib/decoder/investigationPack";
import {
  RELIABILITY_LABEL,
  artifactKey,
  emptyEnrichment,
  openExternalUrl,
  osintEligible,
  osintPermalinks,
} from "@/lib/decoder/osint";
import { decodeSiemText, queryForAll, queryForArtifact } from "@/lib/decoder/pipeline";
import {
  captureSchema,
  catalogToJson,
  mergeIntoCatalog,
  parseCatalogJson,
  type SchemaCatalog,
} from "@/lib/decoder/schemaCapture";
import type { Artifact, DecodeResult } from "@/lib/decoder/types";
import { exportTextFile } from "@/lib/portableStore";

const SCHEMA_STORAGE_KEY = "soc-hub-schema-catalog";

interface SiemDecoderPanelProps {
  onSendToBulk?: (iocText: string) => void;
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

function loadCatalog(): SchemaCatalog {
  try {
    const raw = localStorage.getItem(SCHEMA_STORAGE_KEY);
    if (!raw) return { samples: [] };
    return parseCatalogJson(raw);
  } catch {
    return { samples: [] };
  }
}

export function SiemDecoderPanel({ onSendToBulk }: SiemDecoderPanelProps) {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<DecodeResult | null>(null);
  const [catalog, setCatalog] = useState<SchemaCatalog>({ samples: [] });
  const [allowlist] = useState<Allowlist>(getDefaultAllowlist());
  const [msg, setMsg] = useState("");

  useEffect(() => {
    setCatalog(loadCatalog());
  }, []);

  const analyze = () => {
    const decoded = decodeSiemText(input);
    setResult(decoded);
    const sample = captureSchema(input, decoded);
    if (sample) {
      const next = mergeIntoCatalog(catalog, sample);
      setCatalog(next);
      localStorage.setItem(SCHEMA_STORAGE_KEY, catalogToJson(next));
      setMsg(
        `Estratti ${decoded.artifacts.length} artefatti · schema ${sample.fields.length} campi (solo browser).`,
      );
    } else if (decoded.error) {
      setMsg(decoded.error);
    } else {
      setMsg(`Estratti ${decoded.artifacts.length} artefatti. Usa i link VT/AbuseIP o copia le query.`);
    }
  };

  const loadSample = async () => {
    try {
      const res = await fetch(`${import.meta.env.BASE_URL}samples/sample-siem-cynet.json`);
      const text = await res.text();
      setInput(text);
      setMsg("Esempio Cynet caricato — clicca Analizza.");
    } catch {
      setMsg("Impossibile caricare l'esempio.");
    }
  };

  const allQuery = result ? queryForAll(result.artifacts) : "";
  const pack = result && !result.error ? buildInvestigationPack(result, allowlist) : [];

  const publicIocs = useMemo(() => {
    if (!result?.artifacts) return "";
    return result.artifacts
      .filter((a) => osintEligible(a))
      .map((a) => a.value)
      .join("\n");
  }, [result]);

  return (
    <div className="decoder-shell">
      <section className="decoder-input">
        <p className="panel-hint">
          Incolla JSON Cynet/Defender, syslog FortiGate o lista IOC. Estrazione locale; link OSINT
          senza chiavi API. Per enrich OSINT completo vedi{" "}
          <a
            href="https://github.com/DarkGreen-projects/Decoder_SIEMjoson"
            target="_blank"
            rel="noreferrer"
          >
            Decoder_SIEMjoson
          </a>
          .
        </p>
        <textarea
          className="decoder-textarea"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder='{"HostIp":"203.0.113.10", "HostName":"WKS01", ...}'
          spellCheck={false}
        />
        <div className="decoder-actions">
          <button type="button" className="btn btn-sm btn-primary" onClick={analyze}>
            Analizza
          </button>
          <button type="button" className="btn btn-sm" onClick={() => void loadSample()}>
            Esempio JSON
          </button>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => {
              setInput("");
              setResult(null);
              setMsg("");
            }}
          >
            Pulisci
          </button>
        </div>
        {msg && <p className="decoder-keys-msg">{msg}</p>}
      </section>

      <section className="decoder-output">
        {result?.error && <p className="decoder-error">{result.error}</p>}
        {result && !result.error && (
          <>
            <div className="decoder-meta">
              <span className="tag">{result.format}</span>
              {result.vendor && <span className="tag">{result.vendor}</span>}
            </div>
            <div className="decoder-actions">
              {allQuery && (
                <button
                  type="button"
                  className="btn btn-sm btn-primary"
                  onClick={() => void copyText(allQuery).then((ok) => setMsg(ok ? "Query copiata." : "Copia fallita."))}
                >
                  Copia query globale
                </button>
              )}
              {publicIocs && onSendToBulk && (
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => onSendToBulk(publicIocs)}
                >
                  Invia IOC a Bulk scan
                </button>
              )}
              <button
                type="button"
                className="btn btn-sm"
                onClick={async () => {
                  const md = buildCaseReportMarkdown({ result, pack, enrichment: {} });
                  const ok = await copyText(md);
                  setMsg(ok ? "Report copiato." : "Copia fallita.");
                }}
              >
                Copia report
              </button>
              <button
                type="button"
                className="btn btn-sm"
                onClick={async () => {
                  const md = buildCaseReportMarkdown({ result, pack, enrichment: {} });
                  const ok = await exportTextFile(md, {
                    title: "Esporta report",
                    defaultFileName: `case-report-${result.vendor ?? "generic"}.md`,
                  });
                  setMsg(ok ? "Report scaricato." : "Export annullato.");
                }}
              >
                Export .md
              </button>
            </div>

            {result.artifacts.length === 0 ? (
              <p className="panel-hint">Nessun artefatto estratto.</p>
            ) : (
              <table className="decoder-table">
                <thead>
                  <tr>
                    <th>Tipo</th>
                    <th>Valore</th>
                    <th>Scope</th>
                    <th>OSINT</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {result.artifacts.map((art) => (
                    <ArtifactRow key={artifactKey(art)} art={art} />
                  ))}
                </tbody>
              </table>
            )}

            {pack.length > 0 && (
              <div className="decoder-pack">
                <h3>Hunt query pack</h3>
                {pack.map((item) => (
                  <article key={item.id} className="wiki-query-card">
                    <div className="wiki-query-title">{item.title}</div>
                    <p>{item.why}</p>
                    <pre className="panel-code panel-code-sm">{item.query}</pre>
                    <button
                      type="button"
                      className="btn btn-sm btn-primary"
                      onClick={() =>
                        void copyText(item.query).then((ok) =>
                          setMsg(ok ? `Copiata: ${item.title}` : "Copia fallita."),
                        )
                      }
                    >
                      Copia query
                    </button>
                  </article>
                ))}
              </div>
            )}
          </>
        )}
      </section>
    </div>
  );
}

function ArtifactRow({ art }: { art: Artifact }) {
  const enrichment = emptyEnrichment(art.scope);
  const links = osintPermalinks(art);
  const label = RELIABILITY_LABEL[enrichment.reliability];

  return (
    <tr>
      <td>{art.type}</td>
      <td className="decoder-value">{art.value}</td>
      <td>
        <span className={`tag ${art.scope === "internal" ? "tag-internal" : ""}`}>{art.scope}</span>
      </td>
      <td className="decoder-osint">
        <OsintLinks art={art} links={links} label={label} />
      </td>
      <td>
        {["ip", "hash_sha256", "hash_sha1", "hash_md5", "domain", "url", "hostname", "username"].includes(
          art.type,
        ) && (
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => void copyText(queryForArtifact(art))}
          >
            Copia query
          </button>
        )}
      </td>
    </tr>
  );
}

function OsintLinks({
  art,
  links,
  label,
}: {
  art: Artifact;
  links: ReturnType<typeof osintPermalinks>;
  label: string;
}) {
  if (art.scope === "internal" || !osintEligible(art)) return <>—</>;
  const parts: ReactNode[] = [];
  if (links.vt) {
    parts.push(
      <button key="vt" type="button" className="decoder-rel-ext" onClick={() => openExternalUrl(links.vt!)}>
        VT
      </button>,
    );
  }
  if (links.abuse) {
    parts.push(
      <button
        key="abuse"
        type="button"
        className="decoder-rel-ext"
        onClick={() => openExternalUrl(links.abuse!)}
      >
        AbuseIP
      </button>,
    );
  }
  if (parts.length === 0) return <span className="tag">{label}</span>;
  return <span className="decoder-rel">{parts}</span>;
}
