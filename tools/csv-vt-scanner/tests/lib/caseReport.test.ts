import { describe, expect, it } from "vitest";
import { buildCaseReportMarkdown } from "../../app/src/lib/decoder/caseReport";
import type { DecodeResult } from "../../app/src/lib/decoder/types";

describe("caseReport", () => {
  it("includes vendor context iocs and queries", () => {
    const result: DecodeResult = {
      format: "json",
      vendor: "Microsoft365",
      context: { user_name: "a@b.test", host_ip: "203.0.113.1" },
      artifacts: [
        {
          type: "ip",
          value: "203.0.113.1",
          normalizedValue: "203.0.113.1",
          scope: "public",
          provenance: "test",
        },
        {
          type: "ip",
          value: "10.0.0.5",
          normalizedValue: "10.0.0.5",
          scope: "internal",
          provenance: "test",
        },
      ],
    };
    const md = buildCaseReportMarkdown({
      result,
      pack: [
        {
          id: "t1",
          title: "Query test",
          why: "Perché",
          query: 'UserId = "a@b.test"',
        },
      ],
      generatedAt: "2024-01-01T00:00:00.000Z",
    });
    expect(md).toContain("Microsoft365");
    expect(md).toContain("203.0.113.1");
    expect(md).toContain("10.0.0.5");
    expect(md).toContain("Query test");
    expect(md).toContain('UserId = "a@b.test"');
  });
});
