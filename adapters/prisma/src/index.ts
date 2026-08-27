/**
 * @fieldseal/prisma -- transparent field-level encryption at rest for Prisma.
 *
 * Design: `docs/13-adapter-prisma.md`.
 *
 * **AD-1 (spec §11.3): this package contains no cryptography.** It calls the
 * core's published operations and nothing else. Installing it pulls in
 * `@fieldseal/core`, and that is where every cipher, KDF and random draw lives.
 * CI asserts this rather than trusting review, because it is the kind of rule
 * that decays one convenient import at a time.
 *
 * **Status: L1, and not usable in production.** Values encrypt and decrypt
 * transparently and index siblings are derived on write, but the L2 query path
 * -- the index rewrite and the spec §7.5 re-verification that makes it correct
 * -- is not in this release, and equality on an encrypted column is refused
 * rather than approximated. Nothing here is frozen: the suite identifier is
 * provisional (spec §4.8), Gate 0b is open, and the project does not invite
 * adoption.
 */

export { fieldsealExtension } from "./extension.ts";
export type { FieldsealExtensionOptions, QueryExtension } from "./extension.ts";

export { getTenant, tenantScope } from "./context.ts";

export {
  FieldsealAdapterError,
  FieldsealConfigurationError,
  FieldsealNotSupported,
} from "./errors.ts";
export { FieldsealUnindexable } from "./unindexable.ts";
export type { UnindexableDetail } from "./unindexable.ts";

export { FIELD_MAP_VERSION } from "./fieldmap.ts";
export type {
  EncryptedFieldDecl,
  FieldMap,
  IndexFieldDecl,
  ModelMap,
  RelationDecl,
  Storage,
} from "./fieldmap.ts";

export type { ScopedOverride } from "./client.ts";
export type { TenantResolver } from "./context.ts";
