/**
 * Unicode NFC and full case folding over vendored UCD 17.0.0 tables.
 *
 * `nfc-casefold-v1` is pinned to one Unicode version (docs/09 §7). Neither
 * step may come from the platform here. `String.prototype.normalize` follows
 * whatever ICU the runtime was built against, so the same input would index
 * differently on two Node builds -- and a blind-index mismatch is a silent
 * lookup miss, not an error. The tables in `tables-17.0.0.ts` are generated
 * from the published UCD by `tools/ucd-gen/generate.py`.
 *
 * The spec permits platform NFC when the platform's Unicode version is at
 * least the pinned one and the core proves agreement exhaustively in its own
 * tests. This core does not take that route: the vendored path costs a table
 * this core already ships a sibling of, and it makes the answer independent
 * of the runtime. `tests/unicode.test.ts` still checks the two agree wherever
 * the platform is new enough, because a disagreement there would mean one of
 * them is wrong.
 *
 * Everything here operates on strings. Decoding bytes and refusing invalid
 * UTF-8 is the caller's job (`normalize.ts`).
 */

import {
  ASSIGNED,
  CASEFOLD,
  CCC,
  DECOMP,
  EXCLUSIONS,
  UNICODE_VERSION,
} from "./tables-17.0.0.ts";

export { UNICODE_VERSION };
export {
  ASSIGNED_RANGE_COUNT,
  CASEFOLD_ENTRY_COUNT,
  DECOMPOSITION_COUNT,
} from "./tables-17.0.0.ts";

// Hangul composes algorithmically rather than from the tables (UAX #15 §3.12).
const S_BASE = 0xac00;
const L_BASE = 0x1100;
const V_BASE = 0x1161;
const T_BASE = 0x11a7;
const L_COUNT = 19;
const V_COUNT = 21;
const T_COUNT = 28;
const N_COUNT = V_COUNT * T_COUNT;
const S_COUNT = L_COUNT * N_COUNT;

interface Tables {
  casefold: Map<number, string>;
  ccc: Map<number, number>;
  decomp: Map<number, number[]>;
  comp: Map<number, number>; // pairKey(lead, trail)  ->  composite
  lo: number[];
  hi: number[];
}

let tables: Tables | undefined;

/**
 * Key for the composition table.
 *
 * Multiplication, not `(lead << 21) | trail`: JavaScript's bitwise operators
 * coerce to 32-bit signed integers, so a lead above U+07FF would overflow and
 * collide. The product peaks around 2.3e12, comfortably exact as a double.
 */
function pairKey(lead: number, trail: number): number {
  return lead * 0x200000 + trail;
}

/** `String.fromCodePoint` takes its arguments on the stack, so a long value
 * would overflow it; build the result in chunks instead. */
function fromCodePoints(cps: number[]): string {
  if (cps.length <= 4096) return String.fromCodePoint(...cps);
  let out = "";
  for (let i = 0; i < cps.length; i += 4096) {
    out += String.fromCodePoint(...cps.slice(i, i + 4096));
  }
  return out;
}

/** Expanded once, lazily -- importing the core should not pay for a
 * normalizer the caller may never reach. */
function load(): Tables {
  if (tables !== undefined) return tables;

  const casefold = new Map<number, string>();
  for (const entry of CASEFOLD.split(";")) {
    const gt = entry.indexOf(">");
    const cp = parseInt(entry.slice(0, gt), 16);
    let folded = "";
    for (const h of entry.slice(gt + 1).split(",")) folded += String.fromCodePoint(parseInt(h, 16));
    casefold.set(cp, folded);
  }

  const ccc = new Map<number, number>();
  for (const entry of CCC.split(";")) {
    const c = entry.indexOf(":");
    ccc.set(parseInt(entry.slice(0, c), 16), parseInt(entry.slice(c + 1), 16));
  }

  const decomp = new Map<number, number[]>();
  for (const entry of DECOMP.split(";")) {
    const gt = entry.indexOf(">");
    const cp = parseInt(entry.slice(0, gt), 16);
    decomp.set(cp, entry.slice(gt + 1).split(",").map((h) => parseInt(h, 16)));
  }

  const excluded = new Set<number>();
  for (const h of EXCLUSIONS.split(";")) if (h) excluded.add(parseInt(h, 16));

  const comp = new Map<number, number>();
  for (const [cp, d] of decomp) {
    if (d.length === 2 && !excluded.has(cp)) comp.set(pairKey(d[0]!, d[1]!), cp);
  }

  const lo: number[] = [];
  const hi: number[] = [];
  for (const range of ASSIGNED.split(";")) {
    const dash = range.indexOf("-");
    if (dash === -1) {
      const cp = parseInt(range, 16);
      lo.push(cp);
      hi.push(cp);
    } else {
      lo.push(parseInt(range.slice(0, dash), 16));
      hi.push(parseInt(range.slice(dash + 1), 16));
    }
  }

  tables = { casefold, ccc, decomp, comp, lo, hi };
  return tables;
}

export function combiningClass(cp: number): number {
  return load().ccc.get(cp) ?? 0;
}

/**
 * The first code point not assigned in the pinned Unicode version, or
 * undefined.
 *
 * Surrogates count as unassigned. UnicodeData.txt does list them (category
 * Cs), but a lone surrogate has no UTF-8 encoding, so a normalizer that
 * accepted one could not produce the bytes the index is derived from. In a
 * JavaScript string a lone surrogate reaches here as its own code point,
 * which is exactly the case that must be refused.
 */
export interface UnassignedCodePoint {
  /** The offending code point, e.g. `0x0378`. */
  readonly codePoint: number;
  /**
   * Its position **in code points**, not in UTF-16 units.
   *
   * The unit is load-bearing and is stated because the two are not the same
   * number: `"\u{1F510}\u0378"` faults at code-point index 1 and UTF-16 index
   * 2. Code points is the choice because it is what a person counting
   * characters in a form field means (`docs/12` §10.2 renders this as "the Nth
   * character"), and because it is the one unit every target language can
   * agree on -- UTF-16 offsets are an artifact of this binding's string type
   * and Python's `str` cannot produce them without extra work.
   *
   * `encodeUtf8Strict`'s own message reports a UTF-16 index, and deliberately
   * still does: that is the bytes path, its exception is addressed to whoever
   * wired the column, and changing published error text is not this
   * accessor's job. An adapter that wants a position should call this rather
   * than read that message -- which is the whole reason `docs/09` §7.1 asks
   * for the export.
   */
  readonly offset: number;
}

export function firstUnassigned(text: string): UnassignedCodePoint | undefined {
  const { lo, hi } = load();
  let offset = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xd800 && cp <= 0xdfff) return { codePoint: cp, offset };
    // upper bound: last range whose start is <= cp
    let a = 0;
    let b = lo.length - 1;
    let found = -1;
    while (a <= b) {
      const mid = (a + b) >> 1;
      if (lo[mid]! <= cp) {
        found = mid;
        a = mid + 1;
      } else {
        b = mid - 1;
      }
    }
    if (found < 0 || cp > hi[found]!) return { codePoint: cp, offset };
    offset++;
  }
  return undefined;
}

/**
 * Full case folding, UCD CaseFolding.txt statuses C + F, per code point.
 *
 * Not `toLowerCase`: that is locale-sensitive and is not full folding -- it
 * maps "ß" to "ß" where full folding maps it to "ss".
 */
export function caseFoldFull(s: string): string {
  const { casefold } = load();
  let out = "";
  for (const ch of s) {
    const folded = casefold.get(ch.codePointAt(0)!);
    out += folded === undefined ? ch : folded;
  }
  return out;
}

/** Canonical decomposition followed by canonical ordering (UAX #15 D68). */
function decompose(text: string): number[] {
  const { decomp, ccc } = load();
  const out: number[] = [];

  const expand = (cp: number): void => {
    if (cp >= S_BASE && cp < S_BASE + S_COUNT) {
      const i = cp - S_BASE;
      out.push(L_BASE + Math.floor(i / N_COUNT));
      out.push(V_BASE + Math.floor((i % N_COUNT) / T_COUNT));
      if (i % T_COUNT) out.push(T_BASE + (i % T_COUNT));
      return;
    }
    const d = decomp.get(cp);
    if (d === undefined) {
      out.push(cp);
      return;
    }
    for (const c of d) expand(c);
  };

  for (const ch of text) expand(ch.codePointAt(0)!);

  // Canonical ordering: sort each run of non-starters by combining class,
  // stably -- equal classes must keep their input order.
  let i = 0;
  while (i < out.length) {
    if ((ccc.get(out[i]!) ?? 0) === 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < out.length && (ccc.get(out[j]!) ?? 0) !== 0) j++;
    const run = out.slice(i, j).map((cp, idx) => ({ cp, idx }));
    run.sort((x, y) => (ccc.get(x.cp) ?? 0) - (ccc.get(y.cp) ?? 0) || x.idx - y.idx);
    for (let k = 0; k < run.length; k++) out[i + k] = run[k]!.cp;
    i = j;
  }
  return out;
}

/** Canonical composition (UAX #15 D69). */
function compose(cps: number[]): string {
  if (cps.length === 0) return "";
  const { ccc, comp } = load();

  const out: number[] = [cps[0]!];
  let starter = (ccc.get(cps[0]!) ?? 0) === 0 ? 0 : -1;
  let lastCc = ccc.get(cps[0]!) ?? 0;

  for (let i = 1; i < cps.length; i++) {
    const cp = cps[i]!;
    const cc = ccc.get(cp) ?? 0;
    // `cp` is blocked from the last starter when something between them has a
    // combining class greater than or equal to its own.
    if (starter >= 0 && (lastCc === 0 || lastCc < cc)) {
      const base = out[starter]!;
      let composite: number | undefined;
      if (base >= L_BASE && base < L_BASE + L_COUNT && cp >= V_BASE && cp < V_BASE + V_COUNT) {
        composite = S_BASE + ((base - L_BASE) * V_COUNT + (cp - V_BASE)) * T_COUNT;
      } else if (
        base >= S_BASE && base < S_BASE + S_COUNT &&
        (base - S_BASE) % T_COUNT === 0 &&
        cp > T_BASE && cp < T_BASE + T_COUNT
      ) {
        composite = base + (cp - T_BASE);
      } else {
        composite = comp.get(pairKey(base, cp));
      }
      if (composite !== undefined) {
        out[starter] = composite;
        continue; // `cp` is consumed; `lastCc` is unchanged
      }
    }
    out.push(cp);
    if (cc === 0) {
      starter = out.length - 1;
      lastCc = 0;
    } else {
      lastCc = cc;
    }
  }

  return fromCodePoints(out);
}

/** Normalization Form C, at the pinned Unicode version. */
export function nfc(text: string): string {
  return compose(decompose(text));
}
