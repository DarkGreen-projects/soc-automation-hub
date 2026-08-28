import type { CsvLpTable } from "@/lib/csvLp/parseExport";
import {
  TECHNIQUE_ID_RE,
  normalizeTechniqueId,
  type AlertSeverity,
  type CoveredTechnique,
} from "./parseTechniques";
import {
  SIGNAL_RULES,
  maxSeverity,
  signalVendorsForTechnique,
  techniqueSeverityFromSeed,
  type SignalRule,
} from "./signalMap";
import {
  buildAlertRuleSuggestion,
  getTemplateVendors,
  type AlertRuleSuggestion,
} from "./ruleTemplates";
import {
  detectVendors,
  vendorsIntersect,
  type VendorFamily,
} from "./vendors";

export type CoverageStatus = "covered" | "gap" | "blind";

export interface CoverageRow {
  techniqueId: string;
  techniqueName: string;
  status: CoverageStatus;
  hitCount: number;
  severity: AlertSeverity;
  signals: string[];
  suggestion?: AlertRuleSuggestion;
}

export interface CoverageAnalysis {
  rows: CoverageRow[];
  gaps: CoverageRow[];
  blinds: CoverageRow[];
  coveredSeen: CoverageRow[];
  totalRowsScanned: number;
  signalsFired: { signalId: string; label: string; hits: number }[];
  detectedVendors: VendorFamily[];
}

function col(row: Record<string, string>, ...names: string[]): string {
  const keys = Object.keys(row);
  for (const name of names) {
    if (row[name]?.trim()) return row[name].trim();
    const found = keys.find((k) => k.toLowerCase() === name.toLowerCase());
    if (found && row[found]?.trim()) return row[found].trim();
  }
  return "";
}

function extractExplicitTechniques(row: Record<string, string>): string[] {
  const blob = [
    col(row, "mitre", "technique", "mitre_technique", "attack_technique"),
    col(row, "msg"),
    col(row, "label"),
    col(row, "title"),
  ].join(" ");
  return [...blob.matchAll(TECHNIQUE_ID_RE)].map((m) => normalizeTechniqueId(m[0]));
}

function techniqueVendors(techniqueId: string): VendorFamily[] {
  const fromTpl = getTemplateVendors(techniqueId);
  if (fromTpl.length && !(fromTpl.length === 1 && fromTpl[0] === "generic")) {
    return fromTpl;
  }
  const fromSignals = signalVendorsForTechnique(techniqueId);
  return fromSignals.length > 0 ? fromSignals : fromTpl;
}

/** Blind only if this export could have seen the technique (vendor overlap). */
function isBlindRelevant(techniqueId: string, detected: VendorFamily[]): boolean {
  // Poor CSV: do not flood with catalog blinds
  if (detected.length === 1 && detected[0] === "generic") return false;
  const vendors = techniqueVendors(techniqueId);
  // Untagged / generic-only packs are not vendor-specific blinds
  if (vendors.length === 1 && vendors[0] === "generic") return false;
  return vendorsIntersect(vendors, detected);
}

function suggestionRelevant(techniqueId: string, detected: VendorFamily[]): boolean {
  if (detected.length === 1 && detected[0] === "generic") return false;
  return vendorsIntersect(getTemplateVendors(techniqueId), detected);
}

export function analyzeCoverage(
  table: CsvLpTable,
  covered: CoveredTechnique[],
  seedMeta: CoveredTechnique[],
): CoverageAnalysis {
  const detected = detectVendors(table);
  const coveredIds = new Set(covered.map((c) => c.id));
  const nameById = new Map<string, string>();
  for (const t of seedMeta) nameById.set(t.id, t.name);
  for (const t of covered) nameById.set(t.id, t.name || nameById.get(t.id) || t.id);

  const hitByTechnique = new Map<string, number>();
  const signalsByTechnique = new Map<string, Set<string>>();
  const severityByTechnique = new Map<string, AlertSeverity>();
  const signalHits = new Map<string, { label: string; hits: number }>();

  const bump = (techId: string, signalLabel: string, sev: AlertSeverity) => {
    hitByTechnique.set(techId, (hitByTechnique.get(techId) ?? 0) + 1);
    const set = signalsByTechnique.get(techId) ?? new Set();
    set.add(signalLabel);
    signalsByTechnique.set(techId, set);
    const prev = severityByTechnique.get(techId) ?? "info";
    severityByTechnique.set(techId, maxSeverity(prev, sev));
  };

  for (const row of table.rows) {
    for (const rule of SIGNAL_RULES) {
      if (rule.id === "explicit-mitre-field") continue;
      if (!rule.match(row)) continue;
      const prev = signalHits.get(rule.id) ?? { label: rule.label, hits: 0 };
      prev.hits += 1;
      signalHits.set(rule.id, prev);
      for (const tech of rule.techniques) {
        const sev = techniqueSeverityFromSeed(tech, seedMeta, rule.severity);
        bump(tech, rule.label, sev);
      }
    }

    for (const tech of extractExplicitTechniques(row)) {
      const sev = techniqueSeverityFromSeed(tech, seedMeta, "medium");
      bump(tech, "Campo MITRE esplicito", sev);
      const prev = signalHits.get("explicit-mitre") ?? {
        label: "Campo MITRE esplicito",
        hits: 0,
      };
      prev.hits += 1;
      signalHits.set("explicit-mitre", prev);
    }
  }

  const allTechIds = new Set<string>([
    ...coveredIds,
    ...hitByTechnique.keys(),
  ]);

  const rows: CoverageRow[] = [];
  for (const id of [...allTechIds].sort()) {
    const hits = hitByTechnique.get(id) ?? 0;
    let status: CoverageStatus;
    if (coveredIds.has(id) && hits > 0) status = "covered";
    else if (coveredIds.has(id) && hits === 0) status = "blind";
    else status = "gap";

    if (status === "blind" && !isBlindRelevant(id, detected)) continue;

    const severity =
      severityByTechnique.get(id) ??
      techniqueSeverityFromSeed(id, seedMeta, "medium");
    const techniqueName = nameById.get(id) ?? id;
    const signals = [...(signalsByTechnique.get(id) ?? [])];

    const row: CoverageRow = {
      techniqueId: id,
      techniqueName,
      status,
      hitCount: hits,
      severity,
      signals,
      suggestion: suggestionRelevant(id, detected)
        ? buildAlertRuleSuggestion(id, techniqueName, severity)
        : undefined,
    };
    rows.push(row);
  }

  rows.sort((a, b) => {
    const order = { gap: 0, covered: 1, blind: 2 };
    return order[a.status] - order[b.status] || b.hitCount - a.hitCount;
  });

  return {
    rows,
    gaps: rows.filter((r) => r.status === "gap"),
    blinds: rows.filter((r) => r.status === "blind"),
    coveredSeen: rows.filter((r) => r.status === "covered"),
    totalRowsScanned: table.rowCount,
    signalsFired: [...signalHits.entries()].map(([signalId, v]) => ({
      signalId,
      label: v.label,
      hits: v.hits,
    })),
    detectedVendors: detected,
  };
}

export function findSignalRule(id: string): SignalRule | undefined {
  return SIGNAL_RULES.find((r) => r.id === id);
}
