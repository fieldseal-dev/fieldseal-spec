# G18 — docs/09 §2, §8: a client cannot report its own validated index registry, so a check `docs/12` §5 specifies as an error cannot be written

**Labels:** docs/09 §2 · docs/09 §7 · docs/09 §8 · docs/10 · docs/11 · docs/12 §5 · docs/13 · spec-gap
**Blocks:** `docs/12` §5's E006, which shipped as a **W004 warning** instead; the same check in any future adapter; `docs/15`'s backfill *config hash*, which has no defined inputs for the same reason.
**Found:** 2026-08-25, implementing `docs/12` §5 in PR [#73](https://github.com/fieldseal-dev/fieldseal-spec/pull/73). Raised independently by three of that PR's four reviews and recorded as finding 2 in `docs/07` §7, with the deviation written into `docs/12` §5's W004 row rather than left to a reader to discover.

**Status:** CLOSED 2026-08-26 — tracker [#75](https://github.com/fieldseal-dev/fieldseal-spec/issues/75), posted and closed the same day. Resolution in `docs/07` §7 and in the README closure note. **Closed as filed, with one addition:** `validate_index_declaration`/`validateIndexDeclaration` and `index_registry_key`/`indexRegistryKey` became public alongside `ValidatedIndex`, because a caller that can read a client's registry and cannot resolve its own declarations to the same form still cannot compare against it — the draft below names only the type.

## Gap

`docs/09` §2 specifies a client that **validates everything at construction** and is **immutable afterwards**:

> **Construction validates everything**: write suite in allow-list, cache thresholds within §5.5 bounds, every declared index passing the §7.6 cardinality gate or carrying an explicit logged override […]
> **The client is immutable after construction.** […] This removes a class of concurrency bugs and makes "which config produced this ciphertext" answerable.

It says nothing about reading any of that back. **The claim in the second sentence is not actually met by either shipped core**: "which config produced this ciphertext" is answerable in principle and unanswerable through the API, because a constructed client reflects almost nothing about itself.

### Part A — the validated index registry is unreachable, and one specified check is unimplementable because of it

`docs/12` §5 specifies:

| ID | Level | Condition |
|---|---|---|
| fieldseal.E006 | **Error** | A user-supplied `FIELDSEAL["CLIENT"]` whose index registry does not exactly match the model-declared indexes (§7) |

The Django adapter constructs the core client itself in `AppConfig.ready()`, precisely so the §7.6 gate and the §7.4 band run against the indexes actually declared on models (`docs/12` §7's settings and client-construction note). `FIELDSEAL["CLIENT"]` is the escape hatch for deployments that must own their provider wiring — and E006 is what keeps the escape hatch from silently disabling the model-driven guarantee.

**It could not be written.** Both cores keep the validated registry private:

```python
# core/python/src/fieldseal/api.py:125
self._indexes: dict[str, ValidatedIndex] = {}
```

```ts
// core/typescript/src/api.ts:53
readonly #cfg: ValidatedConfig;      // ValidatedConfig.indexes: ReadonlyMap<string, ValidatedIndex>
```

Neither exposes an accessor. So the check shipped as a **new `W004` warning** that reports the gap instead of closing it — a deliberate choice, on the ground that a check reading `Fieldseal._indexes` fails silently the first time that attribute moves, which is worse than the gap it closes.

**The two cores are not equally bad here, and the worse one is the one with no workaround.** Python's `_indexes` is private by convention; a determined adapter could read it and accept the fragility. TypeScript's `#cfg` is a hard private field — `Object.freeze(this)` in the constructor, and `#`-names are unreachable from outside the class by construction, not by convention. **A TypeScript adapter cannot implement this check at all, well or badly.** That matters because `docs/13` §2 records the Prisma adapter reaching the opposite design conclusion under the same silence:

> There is no `client` option: a pre-built core client cannot contain declarations parsed from the schema, and a split registry (some indexes in the client, some in the extension) is exactly the configuration-drift failure the Django adapter's E006 check exists to catch.

So the project currently has **two adapters answering one question two different ways** — Django offers the escape hatch and cannot verify it; Prisma removes the escape hatch to avoid having to. Neither is wrong under the text as it stands, because the text has nothing to say. That is the same shape as G16: the divergence is downstream of a silence, not of a mistake.

### Part B — the two cores disagree about what a client reflects at all, and no document specifies either answer

The TypeScript core exposes four read-only accessors:

```ts
// core/typescript/src/api.ts:73-89
get readMode(): ReadMode
get writeSuite(): number
get allowedSuites(): ReadonlySet<number>
get provisionalArmed(): boolean          // spec §4.8 arming
```

The Python core exposes **none** of the four. Its only public attribute is `plaintext_reads` (`api.py:142`), the §10.3 counter — which is public, mutable, and the one piece of client state that is *not* configuration.

Neither set is specified anywhere. `docs/09` §2 lists what a client is constructed from; `docs/10` and `docs/11` bind constructor idioms per language and are silent on reflection. So this is unspecified surface that has already drifted, in a project whose entire premise is that two implementations of one document agree. It is not a portability failure in the byte sense — no stored value changes — but it is an **interoperability failure at the layer above**: an adapter author porting the Django adapter's startup checks to TypeScript finds three of them expressible and one not, from the same interface document.

The registry accessor is the load-bearing one, because it is the only element of the configuration whose mismatch produces **silent wrong answers** rather than an error. A client missing a declared index fails every lookup on that column at runtime — visibly. A client carrying an **extra** index derives and stores values for a column under rules no model states, and nothing ever raises. That asymmetry is why E006 was specified as an exact match in both directions, and it is why a presence predicate would not have been enough (see the rejected alternatives below).

### Part C — the type the accessor would return is not public either

Both cores keep `ValidatedIndex` internal. Python exports `IndexDeclaration`, `Argon2Params` and `CardinalityOverride` from `fieldseal/__init__.py` (`__all__`, line 15); TypeScript exports `IndexDeclaration`, `IdfId`, `Argon2Params`, `CardinalityOverride` from `src/index.ts:58`. **`ValidatedIndex` appears in neither.** So closing Part A also means deciding what shape becomes public API, and that decision has one non-obvious consequence worth stating up front:

**The validated form is the useful one, not the as-declared form.** Validation resolves `argon2` to concrete `{time_cost, memory_kib}` — filling in the §7.3 minima when the declaration omits them — and defaults `index_id` to `"exact"` and `on_unindexable` to `refuse`. Comparing as-declared inputs would let two declarations that differ textually and agree operationally register as a mismatch, and, worse, let two that agree textually and differ operationally register as a match. The second is not hypothetical: [#62](https://github.com/fieldseal-dev/fieldseal-spec/issues/62) is exactly that failure, a core reading the Argon2 cost from a module constant while the other took it per column, agreeing on every shipped vector and diverging the first time an operator raised the cost. An accessor returning **resolved** parameters makes that class of divergence assertable from outside the core for the first time.

### A second consumer, named because it is under-specified for the same reason

`docs/15` §1.1 requires the backfill tool to persist a **config hash** in `fieldseal_backfill_runs` alongside the resume cursor, and never defines its inputs. The purpose of such a hash is to refuse a resume whose configuration has changed since the run started — and the change that most needs refusing is a changed index declaration, since a raised Argon2 cost is a **new index** under spec §7.8, not a reconfiguration of an existing one. A run resumed across that change writes two index values for one column and the older half becomes unfindable. The hash cannot include what the tool cannot read. This issue does not propose the hash's definition — that belongs to `docs/15` — but it is the second place the missing accessor turns into a missing guarantee, and it should be noted when the accessor lands.

## Proposed direction (starting point, not a decision)

**`docs/09` §2 gains a reflection subsection, stated as a principle rather than a list.**

> **Configuration reflection (normative).** A constructed client MUST be able to report back every element of its validated configuration that affects stored bytes, query results, or read behaviour: at minimum `read_mode`, `write_suite`, `allowed_suites`, the §4.8 arming state, and the **validated index declarations** (§7). Values MUST be returned in their validated, resolved form — defaults filled in, not as supplied. A client MUST NOT expose its `KeyProvider`, its cache, or any key material through this surface. Accessors MUST NOT permit mutation of the client: a core returning a collection MUST return one the caller cannot use to alter the client's own state (§2's immutability rule).

Three parts of that wording are doing specific work and should not be trimmed:

- **"stored bytes, query results, or read behaviour"** is what draws the line, so the rule does not have to be re-litigated per field as the configuration grows.
- **The `KeyProvider` carve-out** is the point of stating a principle at all. "Expose the configuration" would otherwise put a handle to the object holding key material on the public surface of every client — a strictly larger attack surface than any consumer needs, and one nothing in this issue asks for. The registry contains no key material: it is table/column UUIDs, an index id, an IDF name, cost parameters, a normalizer id, a truncation length, a projected population, and two override flags.
- **The anti-mutation clause is not pedantry in at least one binding.** `ValidatedConfig.indexes` is typed `ReadonlyMap` but is a plain `Map` at runtime (`config.ts:112`), so an accessor returning it directly hands every caller a live handle to the client's registry, and `ReadonlyMap` stops nothing that a single `as Map` cast does not. Python's `dict` has the same property with no type-level fig leaf. A copy, a frozen mapping, or an iterator satisfies this; returning the live collection does not.

**`ValidatedIndex` becomes public API in both cores** (Part C), keyed for lookup by the existing `index_registry_key(table_uuid, column_uuid, index_id)` (`blindindex.py:248`, `blindindex.ts:178`) so the accessor's keys are the ones the core already derives rather than a second scheme.

**`docs/10` and `docs/11` name their per-binding accessors**, as they already do for constructor idioms. The Python core gains the four accessors TypeScript already has; TypeScript gains the registry accessor. Neither core's value path is touched.

**`docs/12` §5 restores E006 to an Error and withdraws W004**, which exists only to report this gap. `docs/13`'s no-`client`-option decision should be **left as it is** — it is defensible on its own terms, since a Prisma extension always parses the schema and a split registry has no legitimate use there — but once the accessor exists it becomes a design choice rather than a constraint, and `docs/13` §2's justification should stop citing the Django check as the reason.

### Rejected alternatives, recorded

- **A presence predicate only** — `has_index(ctx) → bool`, no enumeration. Rejected: it detects a **missing** index and cannot detect an **extra** one, and the extra is the failure that is silent (Part B). E006 is specified as an exact match in both directions and cannot be built on a predicate. It is also the weaker answer for the `docs/15` config hash, which needs the parameter values and not merely the key set.
- **Leave it; let adapters read private attributes.** Rejected: it is what W004 declined to do, and in TypeScript it is not a matter of taste — `#cfg` is unreachable, so the Prisma and TypeORM adapters have no bad option to fall back on either.
- **Remove the escape hatch instead**, generalising Prisma's answer: forbid a pre-built client everywhere. Rejected. It works for Prisma because the extension owns schema parsing; Django's `FIELDSEAL["CLIENT"]` exists for deployments that must own provider wiring — KMS clients, credential rotation, an existing key service — and "you may not own your provider wiring" is a larger cost imposed on operators than an accessor is on cores. It would also leave Part B untouched: the two cores would still disagree about reflection, for no stated reason.
- **Expose the whole validated config object.** Rejected on the `KeyProvider` carve-out above.
- **Say nothing; W004 is an honest warning.** This is the do-nothing baseline. It is defensible for exactly one release and does not survive the second adapter: `docs/12` and `docs/13` already answer the same question differently, and the next core inherits a reflection surface that no document describes and that already differs by four accessors between the two that exist.

### Not proposed: a `pinned_decisions` key

**Deliberately unlike G17**, and the distinction is worth stating because the two issues otherwise look alike. G17's property — buffer lifetime after a call — is unobservable *in principle*: a wiped buffer and a live one produce identical bytes and identical error codes, so a declared key in the conformance report was the only executable instrument available. An accessor's presence is directly testable in each core's own suite. More importantly, a report key would carry the wrong meaning: `pinned_decisions` declares a choice a conformant core is entitled to make differently (G5's decrypt order, G17's ownership stance). This is a **required interface**, and a core without it is non-conformant to `docs/09` §2 rather than differently-configured. Adding a key would legitimise exactly the divergence the issue is filed to end. No `out_of_band` entry either, for the same reason: `out_of_band` substitutes for a vector that cannot be expressed, and here there is no vector to substitute for.

## Justification

- **`CONTRIBUTING.md`'s citation rule is met by the project's own specified behaviour**, which is the strongest available form here: `docs/12` §5 specifies E006 as an Error, the shipped adapter cannot implement it, and the deviation is written into that same table's W004 row. This is not a proposal that something *would* be useful — it is a specified requirement currently unmet, with the reason recorded at both ends.
- **Configuration a caller cannot read back is configuration a caller cannot check.** This is the same argument spec §7.4 makes for recording both `b` and the projected population `P`, and §7.6 makes for the logged override ceremony: a validated decision that leaves no inspectable trace cannot be audited afterwards. The registry is validated at construction and then invisible.
- **The immutability claim in `docs/09` §2 is currently rhetorical.** "Makes 'which config produced this ciphertext' answerable" is stated as a benefit of immutability; immutability is necessary for it and not sufficient, and the sufficient half — being able to ask — was never specified.
- **A private-by-convention attribute and a hard-private field are not the same gap**, and the project has one of each. Any rule written for this must be satisfiable in a language where the workaround does not exist, which is why the fix is an accessor rather than a documented internal.
- **Precedent.** G16 established that a divergence downstream of a specification silence is the project's own to close and belongs in text rather than in each core's judgment; G17 established the same for an interface contract that both cores happened to satisfy. This is narrower than either: the interface is silent, the cores already differ, and one specified check is blocked.

## What it breaks

**Nothing stored, and no cryptographic behaviour.** No envelope byte, no derived value, no vector expectation, no error code, no registry entry, no `pinned_decisions` key, and no line of either core's value path. Every change is additive public surface plus the documents that describe it:

- `docs/09` §2 gains the reflection subsection; §7 gains a cross-reference from the `IndexDeclaration` block to it.
- `docs/10` and `docs/11` gain per-binding accessor names, and `docs/11` notes the `ReadonlyMap`-is-not-frozen point as the reason its accessor copies.
- Both cores gain accessors and promote `ValidatedIndex` (or an equivalent public projection) to exported API. **This is a compatibility commitment**, and the honest statement of the cost is that a type currently free to change becomes one that is not — mitigated only by the pre-1.0 status everything else here shares.
- `docs/12` §5: W004 withdrawn, E006 restored as an Error, and the adapter check rewritten against the accessor. The adapter's existing W004 test becomes an E006 test with both failure directions covered — a client missing a declared index **and** a client carrying an extra one.
- `docs/13` §2's justification stops citing the Django check; the no-`client`-option decision itself is unchanged.
- `docs/15` §1.1's config hash gains a defined input set when it is next touched. Not in scope here.

## Vector obligations

**None, and unlike G10 and G17 this needs no substitute instrument.** A test vector expresses bytes crossing a language boundary; an accessor is a language-local API surface, and no produce/consume matrix can observe whether one exists. The executable obligations are:

- **Per-core tests**: construct a client with a known declaration set, read the registry back, assert the resolved values (`argon2` filled from the §7.3 minima, `index_id` defaulted to `"exact"`, `on_unindexable` defaulted to `refuse`), and assert that mutating the returned collection does not change what a second read returns.
- **One adapter test per direction** for E006, missing and extra, since only the second failure is silent.
- **No `docs/14` §4 change** — no new `pinned_decisions` key and no new `out_of_band` entry, for the reasons in *Not proposed* above. The reports keep the key sets they have carried since G17.

## Review flag

**No cryptographic review required.** This adds read-only accessors over already-validated configuration and changes no construction, derivation, encoding, error code or stored byte, and the one security-relevant decision in it — that the `KeyProvider` and the cache stay off the reflected surface — is a carve-out that *narrows* exposure rather than widening it. Closable by engineering judgment under the rule that closed G3, G6, G8–G13, G16 and G17. Like G16 and G17 and unlike G14, it has **no bearing on any Gate 0b question**: nothing here touches Q1–Q8, and nothing here may be read as freezing anything.
