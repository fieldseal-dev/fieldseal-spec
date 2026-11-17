/**
 * The index context's suite_id is the DECLARED suite (spec §7.2, #213;
 * docs/09 §2, §7; docs/11 §2).
 *
 * Every test here pins one half of one rule: the declaration names a suite and
 * has no default (refusals), the declared suite is independent of the client's
 * write suite and allow-list (acceptance, bytes), nothing on the index path
 * reads the write suite (the context the provider is handed), and the
 * validated declaration reports the suite (reflection).
 *
 * The expected bytes below are not computed by this core: `9f6a` and `b214`
 * are `blind-index/hmac-sha512/ascii-email-b15` and `…/ascii-email-suite-ff02-b15`
 * (vectors/blind-index/hmac-sha512.json), whose inputs `helpers.ts` shares
 * (tenant index key 0x20…0x3f, tenant "tenant-0001", the vector's table and
 * column, index-id `email-eq`).
 */

import { describe, expect, it } from "vitest";
import { Fieldseal, SUITE_FF01, validateIndexDeclaration, type IndexDeclaration, type ValidatedIndex } from "../src/index.ts";
import { ConfigurationError } from "../src/errors.ts";
import { SUITE_FF02 } from "../src/registry.ts";
import type { EncryptionKey, KeyProvider } from "../src/keyprovider.ts";
import type { ResolvedContext } from "../src/context.ts";
import { codeOf, codeOfAsync, CTX, DEK, INDEX_BASE, INDEX_KEY, KEY_ID, makeClient, messageOf, OVERRIDE } from "./helpers.ts";

const PT = "alice@example.com";
const IDX_CTX = { ...CTX, purpose: "index:email-eq" };
const decl = (over: Record<string, unknown> = {}): IndexDeclaration =>
  ({ ...INDEX_BASE, indexId: "email-eq", idf: "hmac-sha512", ...over }) as IndexDeclaration;
const hexOf = (b: Uint8Array): string => Buffer.from(b).toString("hex");

describe("the declaration names its suite, with no default (spec §7.2, #213)", () => {
  it("a declaration naming no suite is refused with ConfigurationError, at construction", () => {
    const { suiteId: _omitted, ...without } = decl();
    expect(codeOf(() => makeClient({ indexes: [without as unknown as IndexDeclaration] }))).toBe("CONFIGURATION_ERROR");
    expect(() => makeClient({ indexes: [without as unknown as IndexDeclaration] })).toThrow(ConfigurationError);
    expect(messageOf(() => makeClient({ indexes: [without as unknown as IndexDeclaration] }))).toMatch(/suiteId is required and has no default/);
  });

  it("is refused by validateIndexDeclaration itself, not completed from anything", () => {
    const { suiteId: _omitted, ...without } = decl();
    expect(() => validateIndexDeclaration(without as unknown as IndexDeclaration)).toThrow(ConfigurationError);
    // `undefined` and `null` are both "names no suite".
    expect(() => validateIndexDeclaration(decl({ suiteId: undefined }))).toThrow(/no default/);
    expect(() => validateIndexDeclaration(decl({ suiteId: null }))).toThrow(/no default/);
  });

  it("is refused whatever the client's write suite is (no default from writeSuite)", () => {
    // Only 0xFF01 can be a write suite in this core, so this is the one client
    // a default could have been filled in from.
    const { suiteId: _omitted, ...without } = decl();
    const c = (): Fieldseal => makeClient({ writeSuite: SUITE_FF01, allowedSuites: [SUITE_FF01], indexes: [without as unknown as IndexDeclaration] });
    expect(() => c()).toThrow(ConfigurationError);
  });

  it.each([
    ["0x0001 (reserved, unassigned: not registered)", 0x0001],
    ["0x0002 (reserved, unassigned: not registered)", 0x0002],
    ["0", 0],
    ["0xFFFF (provisional range, not registered)", 0xffff],
    ["0xFF00", 0xff00],
    ["0xFF03", 0xff03],
  ])("a suite that is not registered is refused: %s", (_name, suiteId) => {
    expect(codeOf(() => makeClient({ indexes: [decl({ suiteId })] }))).toBe("CONFIGURATION_ERROR");
    expect(messageOf(() => makeClient({ indexes: [decl({ suiteId })] }))).toMatch(/not a registered suite/);
  });

  it.each([
    ["a string", "0xFF01"],
    ["a numeric string", "65281"],
    ["a non-integer", 1.5],
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["negative", -1],
    ["past 16 bits", 0x10000],
    ["a bigint", 0xff01n],
    ["an object", {}],
    ["a boolean", true],
    ["bytes", new Uint8Array([0xff, 0x01])],
  ])("a value that is not a valid suite number is refused: %s", (_name, suiteId) => {
    expect(codeOf(() => makeClient({ indexes: [decl({ suiteId })] }))).toBe("CONFIGURATION_ERROR");
    expect(messageOf(() => makeClient({ indexes: [decl({ suiteId })] }))).toMatch(/not a 16-bit suite identifier/);
  });

  it("the refusal comes at declaration time, never at call time", () => {
    // A client cannot be built, so there is no call to fail late.
    expect(() => makeClient({ indexes: [decl({ suiteId: 0x0001 })] })).toThrow(ConfigurationError);
  });
});

describe("the declared suite is independent of the write suite and the allow-list (spec §7.2, §4.3)", () => {
  const c = makeClient({ indexes: [decl({ suiteId: SUITE_FF02, indexId: "email-eq" })] });

  it("0xFF02 is accepted on a client whose write suite and allow-list are 0xFF01 only", () => {
    expect([...c.allowedSuites]).toEqual([SUITE_FF01]);
    expect(c.writeSuite).toBe(SUITE_FF01);
    expect([...c.indexes.values()].map((v) => v.suiteId)).toEqual([SUITE_FF02]);
  });

  it("derives bytes that differ from the same index declared under 0xFF01, and match the pinned vectors", () => {
    const ff01 = makeClient({ indexes: [decl({ suiteId: SUITE_FF01 })] });
    const a = hexOf(ff01.blindIndex(PT, IDX_CTX));
    const b = hexOf(c.blindIndex(PT, IDX_CTX));
    expect(a).not.toBe(b);
    // vectors/blind-index/hmac-sha512.json: ascii-email-b15 and ascii-email-suite-ff02-b15.
    expect(a).toBe("9f6a");
    expect(b).toBe("b214");
  });

  it("the async companions derive the same declared-suite bytes", async () => {
    expect(hexOf(await c.blindIndexAsync(PT, IDX_CTX))).toBe("b214");
    expect(hexOf(await c.unindexableMarkerAsync(IDX_CTX))).toBe(hexOf(c.unindexableMarker(IDX_CTX)));
  });

  it("two declarations that differ only in suite are different registry values", () => {
    const x = makeClient({ indexes: [decl({ suiteId: SUITE_FF01 })] }).indexes.get([...c.indexes.keys()][0] as string) as ValidatedIndex;
    const y = [...c.indexes.values()][0] as ValidatedIndex;
    expect(x.key).toBe(y.key);
    expect(x.suiteId).not.toBe(y.suiteId);
  });

  it("a client's encrypt path is unaffected: the write suite still fills the envelope's context", () => {
    const seen: ResolvedContext[] = [];
    const p = recording(seen);
    const k = makeClient({ keyProvider: p, indexes: [decl({ suiteId: SUITE_FF02 })] });
    k.encrypt(new Uint8Array([1]), CTX);
    expect(seen.map((s) => s.suiteId)).toEqual([SUITE_FF01]);
  });
});

/** A provider that records the context it is asked for a key under, and hands out the helper keys. */
function recording(seen: ResolvedContext[]): KeyProvider {
  return {
    encryptionKey(ctx: ResolvedContext): EncryptionKey {
      seen.push(ctx);
      return { key: new Uint8Array(ctx.purpose === "encrypt" ? DEK : INDEX_KEY), keyId: new Uint8Array(KEY_ID) };
    },
    decryptionKeys: () => [new Uint8Array(DEK)],
  };
}

describe("the context handed to the key provider carries the declared suite, not the write suite", () => {
  const unindexable = { onUnindexable: "bucket", unindexableOverride: OVERRIDE };

  function client(seen: ResolvedContext[]): Fieldseal {
    return makeClient({ keyProvider: recording(seen), indexes: [decl({ suiteId: SUITE_FF02, ...unindexable })] });
  }

  it("blindIndex", () => {
    const seen: ResolvedContext[] = [];
    client(seen).blindIndex(PT, IDX_CTX);
    expect(seen).toHaveLength(1);
    expect(seen[0]?.purpose).toBe("index:email-eq");
    expect(seen[0]?.suiteId).toBe(SUITE_FF02);
    expect(seen[0]?.suiteId).not.toBe(SUITE_FF01); // the write suite
  });

  it("unindexableMarker", () => {
    const seen: ResolvedContext[] = [];
    client(seen).unindexableMarker(IDX_CTX);
    expect(seen.map((s) => s.suiteId)).toEqual([SUITE_FF02]);
  });

  it("blindIndexAsync and unindexableMarkerAsync", async () => {
    const seen: ResolvedContext[] = [];
    const c = client(seen);
    await c.blindIndexAsync(PT, IDX_CTX);
    await c.unindexableMarkerAsync(IDX_CTX);
    expect(seen.map((s) => s.suiteId)).toEqual([SUITE_FF02, SUITE_FF02]);
  });

  it("a caller cannot put a suite into the context: whatever the FieldContext carries is overwritten", () => {
    const seen: ResolvedContext[] = [];
    client(seen).blindIndex(PT, { ...IDX_CTX, suiteId: 0x0001 } as typeof IDX_CTX);
    expect(seen[0]?.suiteId).toBe(SUITE_FF02);
  });

  it("an index declared under 0xFF01 hands the provider 0xFF01 (the control)", () => {
    const seen: ResolvedContext[] = [];
    makeClient({ keyProvider: recording(seen), indexes: [decl({ suiteId: SUITE_FF01 })] }).blindIndex(PT, IDX_CTX);
    expect(seen.map((s) => s.suiteId)).toEqual([SUITE_FF01]);
  });

  it("two indexes on one client, declared under different suites, each use their own", () => {
    const seen: ResolvedContext[] = [];
    const c = makeClient({
      keyProvider: recording(seen),
      indexes: [decl({ suiteId: SUITE_FF01, indexId: "one" }), decl({ suiteId: SUITE_FF02, indexId: "two" })],
    });
    c.blindIndex(PT, { ...CTX, purpose: "index:one" });
    c.blindIndex(PT, { ...CTX, purpose: "index:two" });
    expect(seen.map((s) => s.suiteId)).toEqual([SUITE_FF01, SUITE_FF02]);
  });

  it("warm() hands the provider the caller's contexts untouched: no suite is added, none is needed", async () => {
    const got: unknown[] = [];
    const p: KeyProvider = {
      ...recording([]),
      warm: async (contexts) => {
        for (const c of contexts) got.push(c);
      },
    };
    const c = makeClient({ keyProvider: p, indexes: [decl({ suiteId: SUITE_FF02 })] });
    await c.warm([IDX_CTX]);
    expect(got).toEqual([IDX_CTX]);
    expect("suiteId" in (got[0] as object)).toBe(false);
  });

  it("a failing provider still surfaces as KEY_UNAVAILABLE on the index path (precedence unchanged)", async () => {
    const p: KeyProvider = {
      encryptionKey: () => {
        throw new Error("boom");
      },
      decryptionKeys: () => [],
    };
    const c = makeClient({ keyProvider: p, indexes: [decl({ suiteId: SUITE_FF02 })] });
    expect(codeOf(() => c.blindIndex(PT, IDX_CTX))).toBe("KEY_UNAVAILABLE");
    expect(await codeOfAsync(() => c.blindIndexAsync(PT, IDX_CTX))).toBe("KEY_UNAVAILABLE");
  });
});

describe("the validated declaration reports the suite (docs/09 §2)", () => {
  it("fs.indexes carries suiteId in validated form", () => {
    const c = makeClient({ indexes: [decl({ suiteId: SUITE_FF02 })] });
    const v = [...c.indexes.values()][0] as ValidatedIndex;
    expect(v.suiteId).toBe(0xff02);
    expect(typeof v.suiteId).toBe("number");
  });

  it("is frozen with the rest of the validated declaration", () => {
    const v = validateIndexDeclaration(decl({ suiteId: SUITE_FF01 }));
    expect(Object.isFrozen(v)).toBe(true);
    expect(() => {
      (v as { suiteId: number }).suiteId = SUITE_FF02;
    }).toThrow(TypeError);
    expect(v.suiteId).toBe(SUITE_FF01);
  });

  it("is not read back from the caller's object after validation", () => {
    const d = { ...decl({ suiteId: SUITE_FF02 }) } as { suiteId: number } & IndexDeclaration;
    const c = makeClient({ indexes: [d] });
    (d as { suiteId: number }).suiteId = SUITE_FF01; // a later mutation of the input object
    expect(hexOf(c.blindIndex(PT, IDX_CTX))).toBe("b214");
    expect([...c.indexes.values()][0]?.suiteId).toBe(SUITE_FF02);
  });
});
