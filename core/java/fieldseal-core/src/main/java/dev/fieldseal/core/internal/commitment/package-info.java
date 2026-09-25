/**
 * Module {@code commitment} (docs/09 §1): key-commitment compute and verify
 * (spec §4.6; the construction is provisional, G1).
 *
 * <p>Dependencies: {@code registry} and {@code errors} only (docs/09 §1). The
 * suite's KDF, which lives in {@code kdf}, is passed in by {@code api} as a
 * {@link dev.fieldseal.core.internal.commitment.Commitment.Kdf} (docs/07 §7,
 * 2026-09-25).
 */
package dev.fieldseal.core.internal.commitment;
