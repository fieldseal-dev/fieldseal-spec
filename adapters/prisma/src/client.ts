/**
 * Core-client construction.
 *
 * The extension builds the `Fieldseal` client itself rather than accepting a
 * pre-built one. That is not a convenience: the core's §7.4 truncation band and
 * §7.6 cardinality gate run at client construction, against the index registry
 * it is given, and this is the only arrangement in which they see the columns
 * that actually exist.
 *
 * `docs/13` §2 removes the `client` option for a related but distinct reason,
 * and the distinction was narrowed by G18 ([#75]) on 2026-08-26: verifying a
 * supplied client is no longer *impossible* -- `Fieldseal.indexes` now reports
 * the validated registry, and Django's E006 checks exactly that. Removing it
 * here remains right because this extension always builds the registry from the
 * schema, so a supplied client would be a second source for declarations that
 * already have one, with no deployment need served. A design choice, not a
 * constraint.
 *
 * The overrides spec §7.6 and docs/09 §7.2 require live in *code*, passed to
 * `fieldsealExtension`, never in a schema comment: the point of the ceremony is
 * that a human reviewed and approved it, and a `///` comment is not where that
 * review happens.
 */

import {
  type CardinalityOverride,
  Fieldseal,
  type IndexDeclaration,
  type ReadMode,
  type Warning,
  validateIndexDeclaration,
} from "@fieldseal/core";

import { uuidBytes } from "./context.ts";
import { FieldsealConfigurationError } from "./errors.ts";
import type { ResolvedMap } from "./fieldmap.ts";

/** A §7.6 / §7.2 override, keyed to the column it applies to. */
export interface ScopedOverride extends CardinalityOverride {
  readonly model: string;
  readonly field: string;
}

export interface ClientOptions {
  readonly keyProvider: ConstructorParameters<typeof Fieldseal>[0]["keyProvider"];
  readonly allowedSuites: readonly number[];
  readonly writeSuite: number;
  readonly readMode?: ReadMode | undefined;
  readonly cardinalityOverride?: readonly ScopedOverride[] | undefined;
  readonly unindexableOverride?: readonly ScopedOverride[] | undefined;
  readonly onWarning?: ((w: Warning) => void) | undefined;
  readonly armProvisionalSuites?: boolean | undefined;
}

/** Build the index registry the core validates at construction. */
export function buildIndexRegistry(map: ResolvedMap, opts: ClientOptions): IndexDeclaration[] {
  const cardinality = indexOverrides(opts.cardinalityOverride, "cardinalityOverride", map);
  const unindexable = indexOverrides(opts.unindexableOverride, "unindexableOverride", map);

  const out: IndexDeclaration[] = [];
  for (const model of map.source.models) {
    for (const idx of model.indexes) {
      const key = `${model.model}.${idx.source}`;
      // The generator guarantees both of these on any model that carries an
      // index; a miss here means the map was edited or a map-shape change
      // regressed, and the failure should say so rather than surface as a
      // property read on undefined.
      const source = model.encrypted.find((e) => e.field === idx.source);
      if (source === undefined || model.tableUuid === null) {
        throw new FieldsealConfigurationError(
          `fieldseal: the field map carries an index ${model.model}.${idx.field} ` +
            `over "${idx.source}", but ` +
            (source === undefined
              ? `no encrypted declaration for that column`
              : `no table_uuid for the model`) +
            ` is in the map. The generator emits both together, so the map is ` +
            `stale or was edited -- re-run \`prisma generate\`.`,
        );
      }
      out.push({
        tableUuid: uuidBytes(model.tableUuid),
        columnUuid: uuidBytes(source.columnUuid),
        indexId: idx.indexId,
        idf: idx.idf,
        normalize: idx.normalize,
        truncateBits: idx.truncateBits,
        projectedPopulation: idx.projectedPopulation,
        onUnindexable: idx.onUnindexable,
        skewed: idx.skewed,
        ...(idx.argon2 !== undefined ? { argon2: idx.argon2 } : {}),
        ...(cardinality.has(key) ? { cardinalityOverride: strip(cardinality.get(key)!) } : {}),
        ...(unindexable.has(key) ? { unindexableOverride: strip(unindexable.get(key)!) } : {}),
      });
    }
  }
  return out;
}

/**
 * Construct the client.
 *
 * Every refusal here is the *core's*, re-thrown with the column that caused it
 * attached. The adapter deliberately does not pre-screen: see `declarations.ts`
 * on why a second copy of a gate is worse than none.
 */
export function buildClient(map: ResolvedMap, opts: ClientOptions): Fieldseal {
  const indexes = buildIndexRegistry(map, opts);

  // Validate one at a time first, using the core's own `validateIndexDeclaration`
  // -- not a second copy of the gate, the same function. The core identifies a
  // declaration by its `indexId`, which is "exact" on nearly every column, so a
  // failure from the whole set says "index declaration exact: ..." and names no
  // column. Asking per declaration is the only way to attribute it.
  let i = 0;
  for (const model of map.source.models) {
    for (const idx of model.indexes) {
      const decl = indexes[i++]!;
      try {
        validateIndexDeclaration(decl);
      } catch (e) {
        throw new FieldsealConfigurationError(
          `fieldseal: ${model.model}.${idx.source} (index "${idx.indexId}", sibling ` +
            `${model.model}.${idx.field}) was refused by the core:\n\n${
              e instanceof Error ? e.message : String(e)
            }\n\nDeclaration gates -- the §7.4 truncation band, the §7.6 ` +
            `cardinality gate, the Argon2id minima, the §7.2 bucket ceremony -- ` +
            `are the core's and run here, against the columns your schema ` +
            `actually declares. The overrides §7.6 and docs/09 §7.2 require are ` +
            `passed to fieldsealExtension() in code, never in a schema comment: ` +
            `the point of the ceremony is that a human approved it.`,
        );
      }
    }
  }

  try {
    return new Fieldseal(
      {
        keyProvider: opts.keyProvider,
        allowedSuites: [...opts.allowedSuites],
        writeSuite: opts.writeSuite,
        indexes,
        ...(opts.readMode !== undefined ? { readMode: opts.readMode } : {}),
        ...(opts.onWarning !== undefined
          ? { onWarning: opts.onWarning }
          : {}),
      },
      opts.armProvisionalSuites === true ? { armProvisionalSuites: true } : {},
    );
  } catch (e) {
    throw new FieldsealConfigurationError(
      `fieldseal: the core refused this configuration.\n\n${
        e instanceof Error ? e.message : String(e)
      }\n\nThe declarations came from the generated field map (${map.source.generator}). ` +
        `Declaration gates -- the §7.4 truncation band, the §7.6 cardinality ` +
        `gate, the Argon2id minima, the §7.2 bucket ceremony -- are the core's ` +
        `and run here, against the columns your schema actually declares.`,
    );
  }
}

function strip(o: ScopedOverride): CardinalityOverride {
  return { reason: o.reason, approvedBy: o.approvedBy, date: o.date };
}

/**
 * Index the overrides by column, refusing any that names a column with no
 * index. An override that applies to nothing is not harmless: it is a recorded
 * human approval pointing at the wrong place, and the column it was *meant* for
 * is still ungated.
 */
function indexOverrides(
  list: readonly ScopedOverride[] | undefined,
  option: string,
  map: ResolvedMap,
): Map<string, ScopedOverride> {
  const out = new Map<string, ScopedOverride>();
  if (list === undefined) return out;
  for (const o of list) {
    const model = map.byModel.get(o.model);
    const idx = model?.indexBySource.get(o.field);
    if (idx === undefined) {
      throw new FieldsealConfigurationError(
        `fieldseal: ${option} names ${o.model}.${o.field}, which has no declared ` +
          `blind index. An override that matches no column is refused rather ` +
          `than ignored -- it records a human approval pointing somewhere it ` +
          `does not apply, while the column it was meant for stays ungated.`,
      );
    }
    const key = `${o.model}.${o.field}`;
    if (out.has(key)) {
      throw new FieldsealConfigurationError(
        `fieldseal: ${option} lists ${key} more than once.`,
      );
    }
    out.set(key, o);
  }
  return out;
}
