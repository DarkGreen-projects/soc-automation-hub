import { describe, expect, it } from "vitest";
import {
  applyAllowlistToQuery,
  getDefaultAllowlist,
  normalizeAllowlist,
} from "../../app/src/lib/allowlist";

describe("allowlist", () => {
  it("appends -attack IN before pipe when attack is referenced", () => {
    const list = getDefaultAllowlist();
    const q = applyAllowlistToQuery(
      'norm_id=FortiOS attack="X" | chart count() by source_address',
      list,
    );
    expect(q).toContain("-attack IN [");
    expect(q).toContain("Censys.io.Scanner");
    expect(q.indexOf("-attack")).toBeLessThan(q.indexOf("|"));
  });

  it("does not duplicate existing -attack IN", () => {
    const list = getDefaultAllowlist();
    const base =
      'norm_id=FortiOS attack="X" -attack IN ["Already"] | chart count() by action';
    expect(applyAllowlistToQuery(base, list)).toBe(base);
  });

  it("normalizes partial JSON", () => {
    const n = normalizeAllowlist({ attacks: ["  Foo  "], applications: [] });
    expect(n.attacks).toEqual(["Foo"]);
    expect(n.applications).toEqual([]);
  });
});
