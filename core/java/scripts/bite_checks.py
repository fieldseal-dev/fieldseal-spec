"""Bite checks for the Java core: each mutation must turn the tests it names red.

A test that has never been seen to fail proves only that it does not fail. For each entry below,
this script applies one mutation to the core's source, runs the named Gradle test tasks, records
the verdict, and restores the file, whatever happens.

Three rules keep a verdict honest (docs/07 §7, 2026-09-25, the S4b entry):

1. **A control first.** Every task named below is run unmutated before any mutation, and must
   pass. A task that fails unmutated would "bite" every mutation.
2. **Only failing tests count.** A mutation bites only when Gradle reports failing tests. A
   compile error or a launch failure is reported as BROKEN, never as a bite. (The S4a record was
   produced by a runner whose Gradle call never launched, and every run was printed as a bite.)
3. **The wrapper by absolute path.** `cmd /c gradlew.bat` from a subprocess does not launch on
   every Windows setup; the wrapper is invoked by its full path.

Entries marked `expect="none"` are mutations that cannot be observed today. They are run to show
that they change no outcome, which is itself a claim the record makes.

Usage, from anywhere, with JAVA_HOME set to a JDK 21:

    python core/java/scripts/bite_checks.py              # every entry
    python core/java/scripts/bite_checks.py cache warm   # entries whose name contains a word

Exit status 0 when every verdict is as expected; 1 otherwise; 3 when the control fails.
"""
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent  # core/java
M = ROOT / "fieldseal-core/src/main/java/dev/fieldseal/core"
I = M / "internal"
CORE = ":fieldseal-core:test --tests "
VEC = ":fieldseal-core-testing:test --tests "

# (name, file, old text, new text, test tasks, expectation). The old text must occur exactly once.
MUTATIONS = [
    # ---- S4a: the primitives -------------------------------------------------------------
    ("s4a hkdf: empty salt passed through, not 64 zero bytes", I / "kdf/Hkdf.java",
     "byte[] macKey = salt.length == 0 ? new byte[HASH_LEN] : salt;", "byte[] macKey = salt;",
     [CORE + "*HkdfTest", VEC + "*CommitmentVectorsTest"], "red"),
    ("s4a context: row_id presence bit wrong", I / "context/CanonicalContext.java",
     "PRESENCE_ROW = 0x02;", "PRESENCE_ROW = 0x04;",
     [VEC + "*ContextVectorsTest", CORE + "*CanonicalContextTest"], "red"),
    ("s4a context: purpose without its u64be prefix", I / "context/CanonicalContext.java",
     "        w.prefixed(purpose);\n        return w.done();",
     "        w.raw(purpose);\n        return w.done();",
     [VEC + "*ContextVectorsTest"], "red"),
    ("s4a context: absent tenant_id encoded as empty", I / "context/CanonicalContext.java",
     "int presence = (ctx.tenantId() != null ? PRESENCE_TENANT : 0)",
     "int presence = (ctx.tenantId() != null && ctx.tenantId().length > 0 ? PRESENCE_TENANT : 0)",
     [VEC + "*ContextVectorsTest"], "red"),
    # Until suite 0.9.0 the pinned kdf/index-key/row-id-dropped vector carried no row_id, so only
    # the unit test saw this one (docs/07 §7, 2026-09-25); since 0.9.0 it carries one (#191).
    ("s4a context: index key keeps row_id", I / "context/CanonicalContext.java",
     "return encode(ctx.withoutRowId());", "return encode(ctx);",
     [VEC + "*KdfVectorsTest", CORE + "*CanonicalContextTest"], "red"),
    ("s4a commitment: label off by one byte", I / "commitment/Commitment.java",
     '"fieldseal-commit-v1".getBytes', '"fieldseal-commit-v2".getBytes',
     [VEC + "*CommitmentVectorsTest", CORE + "*CommitmentTest"], "red"),
    ("s4a context: AAD drops the fmt_ver prefix", I / "context/CanonicalContext.java",
     "        w.prefixed(ver);", "        w.raw(ver);",
     [VEC + "*EnvelopeCryptoVectorsTest"], "red"),
    ("s4a kdf: record-key salt is msg_seed only", I / "kdf/KeyDerivation.java",
     "return Hkdf.derive(tenantDek, recordKeySalt(keyId, msgSeed), canonicalContext,",
     "return Hkdf.derive(tenantDek, msgSeed, canonicalContext,",
     [VEC + "*KdfVectorsTest"], "red"),
    ("s4a aead: decrypt through update() then doFinal", I / "aead/Ff01Aead.java",
     "int written = c.doFinal(envelope, ctOffset, ctAndTagLen, out, 0);",
     "int written = c.update(envelope, ctOffset, ctAndTagLen, out, 0);"
     " written += c.doFinal(out, written);",
     [CORE + "*Ff01AeadTest"], "red"),
    ("s4a commitment: length check removed", I / "commitment/Commitment.java",
     "        if (envelopeCommitment.length != suite.commitLen()) {", "        if (false) {",
     [CORE + "*CommitmentTest"], "red"),
    ("s4a aead: range check removed", I / "aead/Ff01Aead.java",
     "        if (offset < 0 || offset + len > envelope.length) {", "        if (false) {",
     [CORE + "*Ff01AeadTest"], "red"),
    ("s4a context: fmt_ver narrowed unchecked", I / "context/CanonicalContext.java",
     "        if (fmtVer < 0 || fmtVer > 0xFF) {", "        if (false) {",
     [CORE + "*CanonicalContextTest"], "red"),

    # ---- S4b: the client, providers and cache --------------------------------------------
    ("s4b client: encrypt guard moved one statement later", M / "Fieldseal.java",
     "        BufferLimits.requirePlaintextWithinBound(plaintext);\n"
     "        FieldContext c = requireContext(ctx);\n",
     "        FieldContext c = requireContext(ctx);\n"
     "        BufferLimits.requirePlaintextWithinBound(plaintext);\n",
     [CORE + "*ApiBoundaryOrderTest"], "red"),
    ("s4b client: encrypt guard removed", M / "Fieldseal.java",
     "        BufferLimits.requirePlaintextWithinBound(plaintext);\n"
     "        FieldContext c = requireContext(ctx);\n",
     "        FieldContext c = requireContext(ctx);\n",
     [CORE + "*SeamWiringTest"], "red"),
    ("s4b client: SUITE_PROVISIONAL before MODE_VIOLATION", M / "Fieldseal.java",
     "        refuseInReadonly(\"encrypt\");\n        requireArmed();\n",
     "        requireArmed();\n        refuseInReadonly(\"encrypt\");\n",
     [CORE + "*ApiBoundaryOrderTest", VEC + "*ClientVectorsTest"], "red"),
    ("s4b client: AEAD opened without a verified commitment", M / "Fieldseal.java",
     "                if (!Commitment.verify(suite, recordKey, p.commitment(), KDF)) {\n"
     "                    continue;\n                }\n",
     "                Commitment.verify(suite, recordKey, p.commitment(), KDF);\n",
     [VEC + "*ClientVectorsTest", CORE + "*ApiBoundaryOrderTest"], "red"),
    ("s4b client: record_key not erased on decrypt", M / "Fieldseal.java",
     "            } finally {\n                Arrays.fill(recordKey, (byte) 0);\n            }\n"
     "        }\n        throw new CommitmentInvalidError",
     "            } finally {\n            }\n        }\n        throw new CommitmentInvalidError",
     [CORE + "*KeyMaterialOwnershipTest"], "red"),
    ("s4b client: record_key not erased on encrypt", M / "Fieldseal.java",
     "            return env;\n        } finally {\n            Arrays.fill(recordKey, (byte) 0);\n"
     "        }",
     "            return env;\n        } finally {\n        }",
     [CORE + "*KeyMaterialOwnershipTest"], "red"),
    ("s4b client: the core erases the provider's candidate key", M / "Fieldseal.java",
     "            } finally {\n                Arrays.fill(recordKey, (byte) 0);\n            }\n"
     "        }\n        throw new CommitmentInvalidError",
     "            } finally {\n                Arrays.fill(recordKey, (byte) 0);\n"
     "                Arrays.fill(dek, (byte) 0);\n            }\n        }\n"
     "        throw new CommitmentInvalidError",
     [CORE + "*KeyMaterialOwnershipTest"], "red"),
    ("s4b client: strict mode passes non-envelopes through", M / "Fieldseal.java",
     "                if (readMode == ReadMode.STRICT) {\n", "                if (false) {\n",
     [VEC + "*ClientVectorsTest"], "red"),
    ("s4b client: rotate passes non-envelopes through", M / "Fieldseal.java",
     "            case DecryptFront.NonEnvelope n -> throw new NotCiphertextError(\"rotate takes an\"\n"
     "                    + \" envelope in every read mode (spec §11.1)\");",
     "            case DecryptFront.NonEnvelope n -> bytes(envelope).clone();",
     [VEC + "*ClientVectorsTest"], "red"),
    ("s4b client: 0xFF02 accepted in allowedSuites", M / "Fieldseal.java",
     "                if (!s.implemented()) {", "                if (false) {",
     [CORE + "*FieldsealTest"], "red"),
    ("s4b client: arming trims whitespace", M / "Fieldseal.java",
     "|| \"1\".equals(environment.apply(SuiteProvisionalError.ARMING_VARIABLE));",
     "|| \"1\".equals(String.valueOf(environment.apply(SuiteProvisionalError.ARMING_VARIABLE))"
     ".strip());",
     [CORE + "*FieldsealTest"], "red"),
    ("s4b client: provider exception escapes unmapped", M / "Fieldseal.java",
     "            km = provider.encryptionKey(r);\n        } catch (KeyUnavailableError e) {\n"
     "            throw e;\n        } catch (RuntimeException e) {",
     "            km = provider.encryptionKey(r);\n        } catch (KeyUnavailableError e) {\n"
     "            throw e;\n        } catch (UnsupportedOperationException e) {",
     [CORE + "*FieldsealTest"], "red"),
    # docs/09 §3.2 step 4. With 0xFF01 the only configurable suite, the header's suite_id and
    # writeSuite are always equal, so this cannot bite until a second suite is built.
    ("s4b client: decrypt context suite_id from writeSuite (cannot bite yet)", M / "Fieldseal.java",
     "        byte[] cc = CanonicalContext.encode(fields(c, suite.id()));\n"
     "        List<byte[]> candidates",
     "        byte[] cc = CanonicalContext.encode(fields(c, writeSuite.id()));\n"
     "        List<byte[]> candidates",
     [":fieldseal-core:test", ":fieldseal-core-testing:test"], "none"),
    ("s4b cache: reads count as uses", I / "cache/DekCache.java",
     "                    out.put(k.version(), e.key.clone());",
     "                    e.uses++;\n                    out.put(k.version(), e.key.clone());",
     [CORE + "*DekCacheTest"], "red"),
    ("s4b cache: maxUses off by one", I / "cache/DekCache.java",
     "            if (e.uses >= limits.maxUses()) {", "            if (e.uses > limits.maxUses()) {",
     [CORE + "*DekCacheTest"], "red"),
    ("s4b cache: eviction does not erase", I / "cache/DekCache.java",
     "            Arrays.fill(e.key, (byte) 0);\n            evictions",
     "            evictions",
     [CORE + "*DekCacheTest"], "red"),
    ("s4b cache: no single-flight", I / "cache/DekCache.java",
     "        CompletableFuture<Void> running = inFlight.putIfAbsent(key, mine);",
     "        CompletableFuture<Void> running = null;",
     [CORE + "*DekCacheTest"], "red"),
    ("s4b cache: a failed load poisons the key", I / "cache/DekCache.java",
     "        } finally {\n            inFlight.remove(key, mine);\n        }",
     "        } finally {\n        }",
     [CORE + "*DekCacheTest"], "red"),
    ("s4b provider: unwraps on the value path", M / "EnvelopeProvider.java",
     "        String version = active.get(slot);\n        if (version == null) {",
     "        if (active.get(slot) == null) {\n            warm(java.util.List.of(request)).join();\n"
     "        }\n        String version = active.get(slot);\n        if (version == null) {",
     [CORE + "*EnvelopeProviderTest"], "red"),
    ("s4b policy: CachePolicy accepts 2^32 + 1", M / "CachePolicy.java",
     "        if (maxUses < 1 || maxUses > MAX_USES_BOUND) {",
     "        if (maxUses < 1 || maxUses > MAX_USES_BOUND + 1) {",
     [CORE + "*CachePolicyProperties"], "red"),

    # ---- #190 review round -----------------------------------------------------------------
    ("review cache: an Error strands the joiners", I / "cache/DekCache.java",
     "        } catch (Throwable t) {", "        } catch (RuntimeException t) {",
     [CORE + "*DekCacheTest"], "red"),
    ("review cache: a fresh entry is not refreshed", I / "cache/DekCache.java",
     "        CompletableFuture<Void> mine = new CompletableFuture<>();",
     "        synchronized (entries) {\n            Entry e0 = entries.get(key);\n"
     "            if (e0 != null && fresh(key, e0)) {\n"
     "                return CompletableFuture.completedFuture(null);\n            }\n        }\n"
     "        CompletableFuture<Void> mine = new CompletableFuture<>();",
     [CORE + "*DekCacheTest", CORE + "*EnvelopeProviderTest"], "red"),
    ("review provider: unlisted versions are not retired", M / "EnvelopeProvider.java",
     "        cache.retain(slot, listed);\n", "",
     [CORE + "*EnvelopeProviderTest"], "red"),
    ("review provider: active set before the slot has loaded", M / "EnvelopeProvider.java",
     "        for (WrappedKeyStore.WrappedKey w : versions) {\n            cache.load(",
     "        if (!listed.isEmpty()) {\n            active.put(slot, listed.iterator().next());\n"
     "        }\n        for (WrappedKeyStore.WrappedKey w : versions) {\n            cache.load(",
     [CORE + "*EnvelopeProviderTest"], "red"),
    ("review client: warm throws instead of failing its future", M / "Fieldseal.java",
     "        } catch (RuntimeException e) {\n            return CompletableFuture.failedFuture(e);",
     "        } catch (UnsupportedOperationException e) {\n"
     "            return CompletableFuture.failedFuture(e);",
     [CORE + "*EnvelopeProviderTest"], "red"),
    ("review client: allowedSuites copied with Set.copyOf", M / "Fieldseal.java",
     "new java.util.HashSet<>(suites);", "Set.copyOf(suites);",
     [CORE + "*FieldsealTest"], "red"),

    # ---- #192: the cache indexed by slot ---------------------------------------------------
    ("192 cache: a read walks every slot, as before the index", I / "cache/DekCache.java",
     "            for (Key k : keysOf(slot)) {\n                Entry e = entries.get(k);\n"
     "                if (fresh(k, e)) {",
     "            for (Key k : List.copyOf(entries.keySet())) {\n"
     "                Entry e = entries.get(k);\n"
     "                if (k.slot().equals(slot) && fresh(k, e)) {",
     [CORE + "*DekCacheTest"], "red"),
    ("192 cache: a read age-checks other slots", I / "cache/DekCache.java",
     "            for (Key k : keysOf(slot)) {\n                Entry e = entries.get(k);",
     "            for (Key o : List.copyOf(entries.keySet())) {\n"
     "                fresh(o, entries.get(o));\n            }\n"
     "            for (Key k : keysOf(slot)) {\n                Entry e = entries.get(k);",
     [CORE + "*DekCacheTest"], "red"),
    ("192 cache: eviction leaves the key in its slot's index", I / "cache/DekCache.java",
     "            keys.remove(key);\n", "",
     [CORE + "*DekCacheTest"], "red"),
]

RED, GREEN, BROKEN = 1, 0, 2


def gradle(task):
    """GREEN (0), RED (1: Gradle reports failing tests) or BROKEN (2: anything else)."""
    wrapper = ROOT / ("gradlew.bat" if os.name == "nt" else "gradlew")
    r = subprocess.run([str(wrapper), "-q", "--offline", *task.split()], cwd=ROOT,
                       capture_output=True, text=True)
    if r.returncode == 0:
        return GREEN
    out = r.stdout + r.stderr
    if "There were failing tests" in out:
        return RED
    print("  BROKEN, not a test failure:", " | ".join(out[-600:].splitlines()), flush=True)
    return BROKEN


def main():
    if not os.environ.get("JAVA_HOME"):
        sys.exit("JAVA_HOME must point at a JDK 21")
    words = sys.argv[1:]
    chosen = [m for m in MUTATIONS if not words or any(w in m[0] for w in words)]

    for task in sorted({t for m in chosen for t in m[4]}):
        ok = gradle(task) == GREEN
        print(f"control {'GREEN' if ok else 'NOT GREEN'} :: {task}", flush=True)
        if not ok:
            sys.exit(3)

    as_expected = True
    for name, path, old, new, tasks, expect in chosen:
        src = path.read_text(encoding="utf-8")
        if src.count(old) != 1:
            print(f"ANCHOR x{src.count(old)}        {name}: the source moved; update this entry")
            as_expected = False
            continue
        try:
            path.write_text(src.replace(old, new), encoding="utf-8", newline="")
            verdicts = [gradle(t) for t in tasks]
        finally:
            path.write_text(src, encoding="utf-8", newline="")
        if expect == "red":
            for t, v in zip(tasks, verdicts):
                label = {RED: "RED (bites)", GREEN: "GREEN (DOES NOT BITE)", BROKEN: "BROKEN"}[v]
                print(f"{label:22} {name} :: {t}", flush=True)
            as_expected &= all(v == RED for v in verdicts)
        else:
            ok = all(v == GREEN for v in verdicts)
            print(f"{'no bite, as stated' if ok else f'NOT AS STATED {verdicts}':22} {name}",
                  flush=True)
            as_expected &= ok
    print("every file restored")
    sys.exit(0 if as_expected else 1)


if __name__ == "__main__":
    main()
