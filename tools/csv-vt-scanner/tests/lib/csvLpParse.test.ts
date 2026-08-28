import { describe, expect, it } from "vitest";
import { parseLogpointExport, preferredColumns } from "../../app/src/lib/csvLp/parseExport";
import { topByColumn } from "../../app/src/lib/csvLp/aggregate";
import { pivotQueryForCell } from "../../app/src/lib/csvLp/pivots";
import { getDefaultAllowlist } from "../../app/src/lib/allowlist";

describe("csvLp parseExport", () => {
  it("parses comma CSV with header", () => {
    const text = "source_address,user,action\n203.0.113.1,alice,blocked\n203.0.113.1,bob,pass\n";
    const table = parseLogpointExport(text);
    expect(table.rowCount).toBe(2);
    expect(table.headers).toContain("source_address");
    expect(preferredColumns(table.headers)[0]).toBe("source_address");
    expect(topByColumn(table, "source_address")[0]).toEqual({
      value: "203.0.113.1",
      count: 2,
    });
  });

  it("parses semicolon delimiter", () => {
    const text = "hostname;action\nWKS1;alert\n";
    const table = parseLogpointExport(text);
    expect(table.delimiter).toBe(";");
    expect(table.rows[0].hostname).toBe("WKS1");
  });

  it("builds pivot query with ClientIP aliases for IPs", () => {
    const q = pivotQueryForCell("source_address", "8.8.8.8", getDefaultAllowlist());
    expect(q).toContain('source_address = "8.8.8.8"');
    expect(q).toContain("ClientIP");
  });
});
