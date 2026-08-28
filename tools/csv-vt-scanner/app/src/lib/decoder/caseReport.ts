import type { InvestigationQuery } from "./investigationPack";
import type { ArtifactEnrichment } from "./osint";
import { RELIABILITY_LABEL, artifactKey } from "./osint";
import type { Artifact, DecodeResult } from "./types";

export interface CaseReportInput {
  result: DecodeResult;
  pack: InvestigationQuery[];
  enrichment?: Record<string, ArtifactEnrichment>;
  generatedAt?: string;
}

function scopeLabel(scope: Artifact["scope"]): string {
  return scope === "public" ? "public" : "internal";
}

export function buildCaseReportMarkdown(input: CaseReportInput): string {
  const { result, pack } = input;
  const when = input.generatedAt ?? new Date().toISOString();
  const enrichment = input.enrichment ?? {};
  const lines: string[] = [];

  lines.push("# Segnalazione caso — LogPoint Query Assistant");
  lines.push("");
  lines.push(`- Generato: ${when}`);
  lines.push(`- Formato input: ${result.format}`);
  lines.push(`- Vendor: ${result.vendor ?? "sconosciuto"}`);
  lines.push("");

  const ctxEntries = Object.entries(result.context).filter(([, v]) => v && String(v).trim());
  if (ctxEntries.length > 0) {
    lines.push("## Contesto");
    lines.push("");
    for (const [k, v] of ctxEntries) {
      lines.push(`- **${k}**: ${v}`);
    }
    lines.push("");
  }

  const pubs = result.artifacts.filter((a) => a.scope === "public");
  const ints = result.artifacts.filter((a) => a.scope !== "public");

  lines.push("## IOC pubblici");
  lines.push("");
  if (pubs.length === 0) {
    lines.push("_Nessuno_");
  } else {
    lines.push("| Tipo | Valore | OSINT | Affidabilità |");
    lines.push("| --- | --- | --- | --- |");
    for (const art of pubs) {
      const enr = enrichment[artifactKey(art)];
      const vt = enr?.vt?.summary ?? enr?.vt?.detectionRatio ?? "—";
      const abuse = enr?.abuse?.summary ?? "—";
      const osint = `VT: ${vt}; Abuse: ${abuse}`;
      const rel = enr ? RELIABILITY_LABEL[enr.reliability] : "—";
      lines.push(
        `| ${art.type} | \`${art.normalizedValue}\` | ${osint.replace(/\|/g, "/")} | ${rel} |`,
      );
    }
  }
  lines.push("");

  lines.push("## IOC interni / privati");
  lines.push("");
  if (ints.length === 0) {
    lines.push("_Nessuno_");
  } else {
    for (const art of ints) {
      lines.push(`- \`${art.type}\` (${scopeLabel(art.scope)}): \`${art.normalizedValue}\` — ${art.provenance}`);
    }
  }
  lines.push("");

  if (pack.length > 0) {
    lines.push("## Query di indagine");
    lines.push("");
    for (const q of pack) {
      lines.push(`### ${q.title}`);
      lines.push("");
      lines.push(q.why);
      lines.push("");
      lines.push("```");
      lines.push(q.query);
      lines.push("```");
      lines.push("");
    }
  }

  lines.push("---");
  lines.push("_Bozza generata localmente. Verificare time-range e risultati su LogPoint prima di inviare al cliente._");
  lines.push("");

  return lines.join("\n");
}
