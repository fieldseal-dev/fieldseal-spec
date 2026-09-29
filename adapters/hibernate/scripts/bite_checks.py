"""Bite checks for the Hibernate adapter: each mutation must turn the tests it names red.

The Java core's script (core/java/scripts/bite_checks.py) with this adapter's list, and the same
three rules:

1. **A control first.** Every test task named below runs unmutated first and must pass.
2. **Only failing tests count.** A mutation bites only when Gradle reports failing tests; a
   compile error or a launch failure is BROKEN, never a bite.
3. **The wrapper by absolute path.**

Entries marked `expect="none"` are mutations no test can observe today, run to show that they
change no outcome; the reason is beside each. The run mutates src/main in place and restores
each file whatever happens: stage files by explicit path while it runs.

Usage, with JAVA_HOME set to a JDK 21 (runs on H2 unless FIELDSEAL_TEST_DB says otherwise):

    python adapters/hibernate/scripts/bite_checks.py            # every entry
    python adapters/hibernate/scripts/bite_checks.py walker     # entries whose name has a word

Exit status 0 when every verdict is as expected; 1 otherwise; 3 when the control fails.
"""
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent  # adapters/hibernate
M = ROOT / "src/main/java/dev/fieldseal/hibernate"
T = "test --tests "

# (name, file, old text, new text, test tasks, expectation). The old text must occur exactly once.
MUTATIONS = [
    # ---- the write path (docs/29 §2.1) ------------------------------------------------------
    ("listener: seals nothing, so a plain value reaches the binding", M / "SealingListener.java",
     "            state[slot] = new Sealed(col, value, envelope);", "",
     [T + "*ValuePathTest", T + "*HibernateBehaviourTest"], "red"),
    ("listener: the index goes to the state array but not the entity",
     M / "SealingListener.java",
     "            persister.setValue(entity, s.indexes[i], index == null ? null : index.clone());",
     "", [T + "*ValuePathTest", T + "*HibernateBehaviourTest"], "red"),
    ("listener: the stored index is kept even when its source changed",
     M / "SealingListener.java",
     "return b != null && java.util.Arrays.equals(col.codec.render(a), col.codec.render(b));",
     "return true;", [T + "*ValuePathTest"], "red"),
    # Re-deriving an unchanged source gives the same bytes; only Argon2id's cost would show it.
    ("listener: an unchanged source is re-derived rather than restored",
     M / "SealingListener.java",
     "return b != null && java.util.Arrays.equals(col.codec.render(a), col.codec.render(b));",
     "return false;", [T + "*ValuePathTest", T + "*HibernateBehaviourTest"], "none"),
    ("type: equals compares a sealed value by identity", M / "EncryptedType.java",
     "        return v instanceof Sealed s ? s.plaintext : v;", "        return v;",
     [T + "*HibernateBehaviourTest"], "red"),
    ("type: a plain value at the binding is bound as text", M / "EncryptedType.java",
     "        throw new FieldsealNotSupportedException(b.spec.label + \": a plain value reached the \"",
     "        if (true) { st.setBytes(position, String.valueOf(value).getBytes()); return; }\n"
     "        throw new FieldsealNotSupportedException(b.spec.label + \": a plain value reached the \"",
     [T + "*BindingGuardTest"], "red"),
    ("context: a tenant-bound column ignores the session's tenant", M / "ColumnSpec.java",
     "        if (!tenantBound) {", "        if (true) {",
     [T + "*ValuePathTest", T + "*FinderTest"], "red"),
    # ---- the codec (spec §3.6) --------------------------------------------------------------
    ("codec: float through Double.toString", M / "Codec.java",
     "        return ecmaScriptToString(x);", "        return Double.toString(x);",
     [T + "*CodecVectorsTest"], "red"),
    ("codec: a nanosecond instant is truncated, not refused", M / "Codec.java",
     "        if (i.getNano() % 1000 != 0) {", "        if (false) {",
     [T + "*CodecVectorsTest", T + "*ValuePathTest"], "red"),
    # ---- the walker (docs/29 §3.3) ----------------------------------------------------------
    ("walker: an encrypted attribute is allowed anywhere but order by", M / "RefusalWalker.java",
     "                case SELECT, NULLNESS, COUNT -> {",
     "                case SELECT, NULLNESS, COUNT, OTHER, INDEX_MATCH -> {",
     [T + "*QueryRefusalTest"], "red"),
    ("walker: an index predicate is allowed outside the finder", M / "RefusalWalker.java",
     "        return finderScope && negations == 0 && !negated;",
     "        return negations == 0 && !negated;",
     [T + "*QueryRefusalTest", T + "*FinderTest"], "red"),
    ("walker: not (...) is not counted as a negation", M / "RefusalWalker.java",
     "    public Object visitNegatedPredicate(SqmNegatedPredicate predicate) {\n        negations++;",
     "    public Object visitNegatedPredicate(SqmNegatedPredicate predicate) {\n        negations += 0;",
     [T + "*QueryRefusalTest"], "red"),
    ("walker: any comparison operator counts as an index match", M / "RefusalWalker.java",
     "                && predicate.getSqmOperator() == ComparisonOperator.EQUAL",
     "                && predicate.getSqmOperator() != null", [T + "*QueryRefusalTest"], "red"),
    ("walker: count(distinct x) passes as a plain count", M / "RefusalWalker.java",
     "\n                && function.getArguments().get(0) instanceof SqmBasicValuedSimplePath<?>;",
     ";", [T + "*QueryRefusalTest"], "red"),
    ("walker: a subquery's or a distinct selection counts as top-level",
     M / "RefusalWalker.java",
     "        return depth == 0 && !distinctSelect ? Position.SELECT : Position.OTHER;",
     "        return Position.SELECT;", [T + "*QueryRefusalTest"], "red"),
    # ---- the finder (docs/29 §3.1) ----------------------------------------------------------
    ("finder: candidates are returned unverified", M / "FieldsealQueries.java",
     "        if (!verify || terms.isEmpty()) {", "        if (true) {",
     [T + "*FinderTest"], "red"),
    # The #238 review, finding 2: the permission is the statement's, not the thread's.
    ("finder: its query does not carry its scope's token", M / "FieldsealQueries.java",
     "        query.setComment(scope.token());", "", [T + "*FinderTest"], "red"),
    ("scope: any statement on a thread with an open scope is permitted", M / "FinderScope.java",
     "        return comment != null && OPEN.get().contains(comment);",
     "        return !OPEN.get().isEmpty();", [T + "*QueryRefusalTest"], "red"),
    # Criteria plans are not cached by default, so the finder's query is translated on every
    # run with or without the call; it is kept so that enabling that cache cannot leak the scope.
    ("finder: its query plan may be cached", M / "FieldsealQueries.java",
     "        query.setQueryPlanCacheable(false);", "",
     [T + "*FinderTest", T + "*QueryRefusalTest"], "none"),
    # ---- startup (docs/29 §5) ---------------------------------------------------------------
    ("startup: FS-H006, a cacheable entity, not checked", M / "FieldsealIntegrator.java",
     "        if (pc.isCached()) {", "        if (false) {", [T + "*StartupChecksTest"], "red"),
    ("startup: FS-H007, @DynamicUpdate, not checked", M / "FieldsealIntegrator.java",
     "        if (!d.indexes.isEmpty() && pc.useDynamicUpdate()) {", "        if (false) {",
     [T + "*StartupChecksTest"], "red"),
    # The #238 review, finding 1: the query cache holds decrypted results.
    ("startup: FS-H010, the query cache, not checked", M / "FieldsealIntegrator.java",
     "        if (sessionFactory.getSessionFactoryOptions().isQueryCacheEnabled()) {",
     "        if (false) {", [T + "*StartupChecksTest"], "red"),
    ("startup: FS-H010 fires on a factory with no encrypted attribute",
     M / "FieldsealIntegrator.java",
     "        if (drafts.isEmpty()) {\n            return;\n        }",
     "        if (sessionFactory.getSessionFactoryOptions().isQueryCacheEnabled()) {\n"
     "            throw new FieldsealConfigurationException(\"FS-H010: unconditional\");\n"
     "        }\n        if (drafts.isEmpty()) {\n            return;\n        }",
     [T + "*StartupChecksTest"], "red"),
    ("startup: FS-H004, the registry, not compared", M / "FieldsealIntegrator.java",
     "        if (!client.indexes().equals(want)) {", "        if (false) {",
     [T + "*StartupChecksTest"], "red"),
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
    tally = {"bite": 0, "not as expected": 0, "none, as stated": 0}
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
            bit = all(v == RED for v in verdicts)
            tally["bite" if bit else "not as expected"] += 1
            as_expected &= bit
        else:
            ok = all(v == GREEN for v in verdicts)
            print(f"{'no bite, as stated' if ok else f'NOT AS STATED {verdicts}':22} {name}",
                  flush=True)
            tally["none, as stated" if ok else "not as expected"] += 1
            as_expected &= ok
    anchors = len(chosen) - sum(tally.values())
    print(f"{len(chosen)} mutations: {tally['bite']} bite, {tally['none, as stated']} change"
          f" nothing as stated, {tally['not as expected']} not as expected, {anchors} anchors"
          " moved. RED lines above are one per mutation and test task.")
    print("every file restored")
    sys.exit(0 if as_expected else 1)


if __name__ == "__main__":
    main()
