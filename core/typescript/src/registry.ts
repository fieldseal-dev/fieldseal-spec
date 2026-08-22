/**
 * The frozen suite registry (spec §4.2, docs/09 §6).
 *
 * A hard-coded table, not a plugin surface: adding a suite is a code change in
 * every core plus vectors plus a spec revision. Two suites are *registered*
 * (recognized by `isCiphertext`, spec §3.4); only one is *implemented* by this
 * core.
 *
 * 0xFF02 is registered and deliberately unbuilt: its AEAD (XChaCha20-Poly1305)
 * has no citable normative definition (spec §4.2 note, gap G7). Registering it
 * keeps recognition correct -- a 0xFF02 envelope is ciphertext, never
 * unmigrated plaintext, which is what §3.4's double-encryption story is about
 * -- while `implemented: false` keeps it off every allow-list this core will
 * accept at construction (see config.ts for the reasoning).
 */

export const FMT_VER = 0x01;

/** Header bytes that precede the nonce: fmt_ver(1) + suite_id(2) + key_id(16) + msg_seed(32). */
export const HEADER_FIXED_LEN = 51;
export const KEY_ID_LEN = 16;
export const MSG_SEED_LEN = 32;

export interface Suite {
  readonly id: number;
  readonly name: string;
  readonly aead: "AES-256-GCM" | "XChaCha20-Poly1305";
  readonly keyLen: number;
  readonly nonceLen: number;
  readonly tagLen: number;
  readonly commitLen: number;
  readonly kdf: "HKDF-SHA-512";
  /** Whether this core can perform the suite's AEAD. */
  readonly implemented: boolean;
  /** Spec §4.8: identifiers in 0xFF00-0xFFFF are provisional and require arming to write. */
  readonly provisional: boolean;
}

export const SUITE_FF01 = 0xff01;
export const SUITE_FF02 = 0xff02;

const SUITES: ReadonlyMap<number, Suite> = new Map<number, Suite>([
  [
    SUITE_FF01,
    {
      id: SUITE_FF01,
      name: "FLE-AES256GCM-HKDF-SHA512-PROVISIONAL",
      aead: "AES-256-GCM",
      keyLen: 32,
      nonceLen: 12,
      tagLen: 16,
      commitLen: 32,
      kdf: "HKDF-SHA-512",
      implemented: true,
      provisional: true,
    },
  ],
  [
    SUITE_FF02,
    {
      id: SUITE_FF02,
      name: "FLE-XCHACHA20POLY1305-HKDF-SHA512-PROVISIONAL",
      aead: "XChaCha20-Poly1305",
      keyLen: 32,
      nonceLen: 24,
      tagLen: 16,
      commitLen: 32,
      kdf: "HKDF-SHA-512",
      implemented: false,
      provisional: true,
    },
  ],
]);

export function getSuite(id: number): Suite | undefined {
  return SUITES.get(id);
}

export function isRegistered(id: number): boolean {
  return SUITES.has(id);
}

export function isProvisionalId(id: number): boolean {
  // §4.8: one masked comparison on suite_id.
  return (id & 0xff00) === 0xff00;
}

/** Fixed (plaintext-independent) envelope overhead for a suite, in bytes. */
export function fixedOverhead(s: Suite): number {
  return HEADER_FIXED_LEN + s.nonceLen + s.tagLen + s.commitLen;
}

/** The smallest envelope any registered suite can produce (an empty plaintext). */
export function minRegisteredEnvelopeLen(): number {
  let min = Number.POSITIVE_INFINITY;
  for (const s of SUITES.values()) min = Math.min(min, fixedOverhead(s));
  return min;
}

export function registeredSuiteIds(): number[] {
  return [...SUITES.keys()];
}
