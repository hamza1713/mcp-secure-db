import { describe, it, expect, afterAll } from "vitest";
import { sqlValidator } from "../src/security/validator.js";
import { SecureDatabaseEngine } from "../src/database/engine.js";
import { ALL_BYPASS_CASES, BypassTestCase } from "./bypass-corpus/index.js";

describe("Public Bypass Corpus (tests/bypass-corpus/)", () => {
  const engine = new SecureDatabaseEngine(2500);

  afterAll(async () => {
    await engine.close();
  });

  it(`executes ${ALL_BYPASS_CASES.length} structured bypass attack vectors; all must fail closed`, async () => {
    expect(ALL_BYPASS_CASES.length).toBeGreaterThanOrEqual(30);

    for (const testCase of ALL_BYPASS_CASES) {
      // 1. Validator must reject the attack query
      const validation = sqlValidator.validate(testCase.sql, testCase.role);
      expect(
        validation.valid,
        `Expected validator to reject '${testCase.id}' (${testCase.name}): rule '${testCase.ruleThatStopsIt}'`
      ).toBe(false);

      // 2. Engine executeQuery must fail closed (via AST validation or authorizer)
      await expect(
        engine.executeQuery(testCase.sql, testCase.role, "bypass-corpus-tester"),
        `Expected engine to reject '${testCase.id}' (${testCase.name})`
      ).rejects.toThrow();
    }
  });

  describe.each(ALL_BYPASS_CASES)(
    "Vector $id: $category - $name",
    (testCase: BypassTestCase) => {
      it(`enforces stopping rule: ${testCase.ruleThatStopsIt}`, () => {
        const res = sqlValidator.validate(testCase.sql, testCase.role);
        expect(res.valid).toBe(false);
        expect(res.violationReason).toBeDefined();
      });
    }
  );
});
