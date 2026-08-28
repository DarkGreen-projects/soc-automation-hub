import { describe, expect, it } from "vitest";
import { parseBulkIocs } from "../../app/src/lib/bulkOsint/parseIocs";

describe("bulkOsint parseIocs", () => {
  it("classifies ip hash domain url and skips private", () => {
    const hash = "a".repeat(64);
    const rows = parseBulkIocs(
      `8.8.8.8\n10.0.0.1\nevil.example.com\nhttps://bad.test/x\n${hash}\n# comment\n`,
    );
    expect(rows.some((r) => r.value === "8.8.8.8" && r.kind === "ip" && !r.skipped)).toBe(true);
    expect(rows.some((r) => r.value === "10.0.0.1" && r.skipped)).toBe(true);
    expect(rows.some((r) => r.kind === "domain" && r.value === "evil.example.com")).toBe(true);
    expect(rows.some((r) => r.kind === "url")).toBe(true);
    expect(rows.some((r) => r.kind === "hash_sha256" && r.value === hash)).toBe(true);
  });

  it("dedupes case-insensitively for domains", () => {
    const rows = parseBulkIocs("Evil.Example.com\nevil.example.com");
    expect(rows.filter((r) => r.kind === "domain")).toHaveLength(1);
  });
});
