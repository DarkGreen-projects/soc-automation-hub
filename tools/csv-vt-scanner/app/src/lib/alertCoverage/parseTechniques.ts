export type AlertSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface CoveredTechnique {
  id: string;
  name: string;
  severity: AlertSeverity;
}

export interface AlertCoverageState {
  covered: CoveredTechnique[];
  notes?: string;
}

/** MITRE technique id: T1234 or T1234.001 */
export const TECHNIQUE_ID_RE = /\bT\d{4}(?:\.\d{3})?\b/gi;

export function normalizeTechniqueId(id: string): string {
  const m = id.trim().toUpperCase().match(/^T\d{4}(?:\.\d{3})?$/);
  return m ? m[0] : id.trim().toUpperCase();
}

/**
 * Parse free-text technique lists (names + IDs, slashes, commas).
 * Returns unique techniques by id (last name/severity wins if duplicated).
 */
export function parseTechniquesFromText(
  text: string,
  severityFallback: AlertSeverity = "medium",
): CoveredTechnique[] {
  const map = new Map<string, CoveredTechnique>();
  const lines = text.replace(/\r\n/g, "\n").split("\n");

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const ids = [...trimmed.matchAll(TECHNIQUE_ID_RE)].map((m) =>
      normalizeTechniqueId(m[0]),
    );
    if (ids.length === 0) continue;

    let namePart = trimmed
      .replace(TECHNIQUE_ID_RE, " ")
      .replace(/[–—\-:/|,]+/g, " ")
      .replace(/\s+/g, " ")
      .trim();

    for (const id of ids) {
      map.set(id, {
        id,
        name: namePart || id,
        severity: severityFallback,
      });
    }
  }

  // Also catch ids not on their own line (whole blob)
  if (map.size === 0) {
    for (const m of text.matchAll(TECHNIQUE_ID_RE)) {
      const id = normalizeTechniqueId(m[0]);
      if (!map.has(id)) {
        map.set(id, { id, name: id, severity: severityFallback });
      }
    }
  }

  return [...map.values()].sort((a, b) => a.id.localeCompare(b.id));
}

export function techniquesToText(covered: CoveredTechnique[]): string {
  return covered.map((t) => `${t.name} – ${t.id}`).join("\n");
}

export function mergeTechniqueMeta(
  parsed: CoveredTechnique[],
  known: CoveredTechnique[],
): CoveredTechnique[] {
  const knownMap = new Map(known.map((k) => [k.id, k]));
  return parsed.map((p) => {
    const k = knownMap.get(p.id);
    if (!k) return p;
    return {
      id: p.id,
      name: p.name && p.name !== p.id ? p.name : k.name,
      severity: k.severity,
    };
  });
}
