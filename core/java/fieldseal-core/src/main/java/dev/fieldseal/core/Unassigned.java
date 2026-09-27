package dev.fieldseal.core;

/**
 * What {@link Fieldseal#firstUnassigned} reports (docs/09 §7.1, §12): the first code point {@code
 * nfc-casefold-v1} would refuse, and where it is.
 *
 * @param codePoint the code point: unassigned in Unicode {@value Fieldseal#UNICODE_VERSION}, or a
 *     lone surrogate, which is refused on the same terms
 * @param offset its position counted in code points, not UTF-16 units, so that a message can say
 *     "the Nth character" (docs/12 §10.2)
 */
public record Unassigned(int codePoint, int offset) {}
