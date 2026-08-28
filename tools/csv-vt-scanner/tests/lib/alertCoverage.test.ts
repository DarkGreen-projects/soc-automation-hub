import { describe, expect, it } from "vitest";
import { analyzeCoverage } from "../../app/src/lib/alertCoverage/analyzeCoverage";
import { parseTechniquesFromText } from "../../app/src/lib/alertCoverage/parseTechniques";
import { buildAlertRuleSuggestion } from "../../app/src/lib/alertCoverage/ruleTemplates";
import { parseAlertsInput } from "../../app/src/lib/csvLp/parseAlertsInput";
import { parseLogpointExport } from "../../app/src/lib/csvLp/parseExport";
import seed from "../../app/src/data/alert-coverage.seed.json";
import type { CoveredTechnique } from "../../app/src/lib/alertCoverage/parseTechniques";

const seedCovered = seed.covered as CoveredTechnique[];

describe("parseAlertsInput", () => {
  it("parses JSON array of alert events", () => {
    const json = JSON.stringify([
      { source_address: "203.0.113.1", action: "pass", sub_category: "ips" },
      { event_id: "4625", label: "login failed" },
    ]);
    const table = parseAlertsInput(json);
    expect(table.rowCount).toBe(2);
    expect(table.headers).toContain("source_address");
    expect(table.headers).toContain("event_id");
    expect(table.rows[0].source_address).toBe("203.0.113.1");
    expect(table.rows[1].event_id).toBe("4625");
  });

  it("parses JSON wrapper with events key", () => {
    const json = JSON.stringify({
      events: [{ norm_id: "FortiOS", action: "pass", sub_category: "ips" }],
    });
    const table = parseAlertsInput(json);
    expect(table.rowCount).toBe(1);
    expect(table.rows[0].norm_id).toBe("FortiOS");
  });

  it("falls back to CSV when input is not JSON", () => {
    const csv = "source_address,action\n203.0.113.1,pass\n";
    const table = parseAlertsInput(csv);
    expect(table.rowCount).toBe(1);
    expect(table.rows[0].source_address).toBe("203.0.113.1");
  });
});

describe("parseTechniquesFromText", () => {
  it("parses the operator technique list", () => {
    const text = `Impair Defenses – T1562.006
Application Layer Protocol – T1071.001
T1189, T1090, T1219
T1204, T1189 / T1486
Brute Force – T1110.001`;
    const techs = parseTechniquesFromText(text);
    const ids = techs.map((t) => t.id);
    expect(ids).toContain("T1562.006");
    expect(ids).toContain("T1071.001");
    expect(ids).toContain("T1189");
    expect(ids).toContain("T1090");
    expect(ids).toContain("T1219");
    expect(ids).toContain("T1486");
    expect(ids).toContain("T1110.001");
  });
});

describe("analyzeCoverage", () => {
  it("flags IPS pass as gap when not covered", () => {
    const csv = [
      "source_address,action,sub_category,event_category,norm_id,log_severity",
      "203.0.113.1,pass,ips,utm,FortiOS,high",
    ].join("\n");
    const table = parseLogpointExport(csv);
    const covered = parseTechniquesFromText("Brute Force – T1110");
    const result = analyzeCoverage(table, covered, seedCovered);
    expect(result.gaps.some((g) => g.techniqueId === "T1190")).toBe(true);
    expect(result.gaps.find((g) => g.techniqueId === "T1190")?.suggestion?.query).toBeTruthy();
  });

  it("marks covered technique as covered when seen", () => {
    const csv = [
      "source_address,action,sub_category,event_category,norm_id,log_severity",
      "203.0.113.1,pass,ips,utm,FortiOS,high",
    ].join("\n");
    const table = parseLogpointExport(csv);
    const covered = parseTechniquesFromText("Exploit Public-Facing Application – T1190");
    const result = analyzeCoverage(table, covered, seedCovered);
    expect(result.coveredSeen.some((r) => r.techniqueId === "T1190")).toBe(true);
  });
});

describe("ruleTemplates", () => {
  it("emits single-line LogPoint-ready query", () => {
    const s = buildAlertRuleSuggestion("T1190", "Exploit Public-Facing Application", "critical");
    expect(s.query.includes("\n")).toBe(false);
    expect(s.query).toContain("norm_id=FortiOS");
    expect(s.copyBlock).toContain("Risk: Critical");
    expect(s.copyBlock).toContain("Name:");
    expect(s.searchInterval).toBe("15m");
  });

  it("builds full Director pack for T1036 including Jinja", () => {
    const s = buildAlertRuleSuggestion("T1036", "Masquerading", "medium");
    expect(s.ruleName).toContain("T1036");
    expect(s.jinjaTemplate).toContain("{% for row in rows %}");
    expect(s.jinjaTemplate).toContain("{{ row.process_name }}");
    expect(s.copyBlock).toContain("Name:");
    expect(s.copyBlock).toContain("Query:");
    expect(s.copyBlock).toContain("Jinja template:");
    expect(s.query.includes("\n")).toBe(false);
    expect(s.condition).toBe("simple");
    expect(s.risk).toBe("Medium");
  });
});

describe("analyzeCoverage suggestions", () => {
  it("attaches rule pack to covered rows too", () => {
    const csv = [
      "source_address,action,sub_category,event_category,norm_id,log_severity",
      "203.0.113.1,pass,ips,utm,FortiOS,high",
    ].join("\n");
    const table = parseLogpointExport(csv);
    const covered = parseTechniquesFromText("Exploit Public-Facing Application – T1190");
    const result = analyzeCoverage(table, covered, seedCovered);
    const row = result.coveredSeen.find((r) => r.techniqueId === "T1190");
    expect(row?.suggestion?.jinjaTemplate).toContain("for row in rows");
    expect(row?.suggestion?.copyBlock).toContain("Jinja template:");
  });
});

describe("vendor filter", () => {
  it("Forti-only CSV keeps T1190 and drops AgentX T1036 blinds", () => {
    const csv = [
      "source_address,action,sub_category,event_category,norm_id,log_severity",
      "203.0.113.1,pass,ips,utm,FortiOS,high",
    ].join("\n");
    const table = parseLogpointExport(csv);
    const covered = parseTechniquesFromText(
      "Exploit Public-Facing Application – T1190\nMasquerading – T1036",
    );
    const result = analyzeCoverage(table, covered, seedCovered);
    expect(result.detectedVendors).toContain("fortigate");
    expect(result.rows.some((r) => r.techniqueId === "T1190")).toBe(true);
    expect(result.rows.some((r) => r.techniqueId === "T1036")).toBe(false);
  });

  it("Windows 4625 enables T1110 and does not force Forti-only blinds", () => {
    const csv = ["event_id,label,user,computer", "4625,login failed,alice,WS01"].join("\n");
    const table = parseLogpointExport(csv);
    const covered = parseTechniquesFromText(
      "Brute Force – T1110\nExploit Public-Facing Application – T1190",
    );
    const result = analyzeCoverage(table, covered, seedCovered);
    expect(result.detectedVendors).toContain("windows");
    expect(result.rows.some((r) => r.techniqueId === "T1110")).toBe(true);
    expect(result.rows.find((r) => r.techniqueId === "T1110")?.suggestion).toBeTruthy();
    // Forti T1190 covered but not seen and not relevant → no blind/gap without hit
    expect(result.blinds.some((r) => r.techniqueId === "T1190")).toBe(false);
    expect(result.gaps.some((g) => g.techniqueId === "T1190")).toBe(false);
  });
});
