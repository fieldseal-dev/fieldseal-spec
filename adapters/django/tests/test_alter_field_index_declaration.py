"""`migrate` refuses an `AlterField` that changes a blind index's declaration
(#303).

Spec §7.8: the IDF, the normalize function, the truncation length and the
key-derivation context (the `index_id` and the declared `suite_id`, §7.2) MUST
NOT change once an index is written. An `AlterField` that changes one runs no
SQL on any backend (#283), so the stored index values stay those of the old
declaration and an equality lookup finds nothing: the silent empty result spec
§10.2 says the adapter must refuse. Likewise an `EncryptedIndex` whose
`source` is repointed. These tests run real `migrate` commands over the
model-less `tests.app252` through the `case` fixture of `conftest.py`, as
`test_alter_field_identity.py` does for #288, whose walk this one shares. The
one cryptographic fact the refusal rests on is measured by a test of its own,
on the real `Patient` model. Rebuilding an index under a new declaration is
#315, not tested here.
"""

from __future__ import annotations

import dataclasses
import textwrap

import pytest
from django.core.management import call_command

from fieldseal_django import FieldsealNotSupported
from fieldseal_django.apps import reset_client

from .migration_cases import alter, create, guard_off, mig

pytestmark = [
    pytest.mark.django_db(transaction=True),
    pytest.mark.filterwarnings("ignore::fieldseal.errors.FieldsealWarning"),
]

UUID_A = "018f3c2e-0000-7000-8000-000000303001"
UUID_B = "018f3c2e-0000-7000-8000-000000303002"
UUID_U = "018f3c2e-0000-7000-8000-000000303003"
STAND_IN = b"\x01\xff stand-in for an index value"


class Raw(str):
    """Source text that `index` writes as it is, not as a string literal."""

    def __repr__(self) -> str:
        return str(self)


def index(**kw: object) -> str:
    """A `BlindIndex` as migration source: hmac, which keeps the tests fast,
    unless a test says otherwise."""
    args = {"suite_id": 0xFF01, "index_id": "exact", "idf": "hmac-sha512",
            "normalize": "nfc-casefold-v1", "truncate_bits": 15,
            "projected_population": 100000, **kw}
    return ("fieldseal_django.BlindIndex("
            + ", ".join(f"{k}={v!r}" for k, v in args.items()) + ")")


def enc(idx: str | None = None, *, uuid: str = UUID_A) -> str:
    """An indexed `Encrypted` declaration as migration source."""
    extra = f", index={idx}" if idx else ""
    return (f"fieldseal_django.fields.Encrypted("
            f"models.CharField(max_length=100), column_uuid={uuid!r}, "
            f"null=True{extra})")


OLD = enc(index())

#: A second `Encrypted` field and the two index columns, for `source`.
EXTRA = f"""
    ("u", {enc(uuid=UUID_U)}),
    ("v_bidx", fieldseal_django.fields.EncryptedIndex(source="v")),
"""


def alter_index(source: str) -> str:
    """An `AlterField` of `Thing.v_bidx` to an `EncryptedIndex` of `source`."""
    return ('[migrations.AlterField(model_name="thing", name="v_bidx", '
            f'field=fieldseal_django.fields.EncryptedIndex(source="{source}"))]')


def graph_of(old: str, change: str):
    """`0001` creates `v`, `u` and `v_bidx`; `0002` runs `change`."""
    def graph(table: str) -> dict[str, str]:
        return {"0001_initial": create(table, old, extra=EXTRA),
                "0002_change": mig(["0001_initial"], change)}
    return graph


def refused(case, new: str, *, old: str = OLD):
    c = case(graph=graph_of(old, alter(new)))
    c.migrate("0001")
    c.insert(STAND_IN)
    return c


#: (id, the old index, the new one, what the message must name)
REFUSED = [
    ("index_id", index(), index(index_id="exact2"),
     "index_id from exact to exact2"),
    ("idf", index(), index(idf="argon2id"),
     "idf from hmac-sha512 to argon2id"),
    ("normalize", index(), index(normalize="nfc-v1"),
     "normalize from nfc-casefold-v1 to nfc-v1"),
    ("truncate_bits", index(), index(truncate_bits=16),
     "truncate_bits from 15 to 16"),
    ("time_cost", index(idf="argon2id", time_cost=3),
     index(idf="argon2id", time_cost=4), "time_cost from 3 to 4"),
    ("memory_kib", index(idf="argon2id", memory_kib=65536),
     index(idf="argon2id", memory_kib=131072),
     "memory_kib from 65536 to 131072"),
    ("time_cost-unstated-to-value", index(idf="argon2id"),
     index(idf="argon2id", time_cost=4),
     "time_cost from not declared to 4"),
    ("suite_id", index(), index(suite_id=0xFF02),
     "suite_id from 0xff01 to 0xff02"),
]
IDS = [r[0] for r in REFUSED]
PARAMS = [(enc(old), enc(new), named) for _, old, new, named in REFUSED]


# -- refused: forwards --------------------------------------------------------


@pytest.mark.parametrize(("old", "new", "named"), PARAMS, ids=IDS)
def test_migrate_refuses_the_change_before_any_ddl(case, old, new, named):
    c = refused(case, new, old=old)
    with pytest.raises(FieldsealNotSupported) as e:
        c.migrate("0002")
    assert named in str(e.value)
    assert "0002_change" not in c.applied()
    assert c.values() == [STAND_IN]


def test_an_encrypted_index_repointed_is_refused(case):
    c = case(graph=graph_of(OLD, alter_index("u")))
    c.migrate("0001")
    with pytest.raises(FieldsealNotSupported) as e:
        c.migrate("0002")
    assert "AlterField v_bidx on thing" in str(e.value)
    assert "source from v to u" in str(e.value)
    assert "0002_change" not in c.applied()


# -- refused: unapplying ------------------------------------------------------


@pytest.mark.parametrize(("old", "new", "named"), PARAMS, ids=IDS)
def test_migrate_refuses_unapplying_the_change(case, old, new, named):
    c = case(graph=graph_of(old, alter(new)))
    with guard_off():
        c.migrate("0002")
    with pytest.raises(FieldsealNotSupported) as e:
        c.migrate("0001")
    msg = str(e.value)
    assert "unapplying" in msg
    # The direction of change: the migration's declaration is what the
    # column leaves.
    attribute, _, rest = named.partition(" from ")
    before, _, after = rest.partition(" to ")
    assert f"{attribute} from {after} to {before}" in msg
    assert "0002_change" in c.applied()


def test_unapplying_a_repointed_encrypted_index_is_refused(case):
    c = case(graph=graph_of(OLD, alter_index("u")))
    with guard_off():
        c.migrate("0002")
    with pytest.raises(FieldsealNotSupported) as e:
        c.migrate("0001")
    assert "unapplying" in str(e.value)
    assert "source from u to v" in str(e.value)


# -- refused: --fake ----------------------------------------------------------


@pytest.mark.parametrize(("old", "new", "named"), PARAMS, ids=IDS)
def test_migrate_fake_is_refused_too(case, old, new, named):
    """`pre_migrate` does not say the run is fake, so the receiver cannot
    tell, and a faked change is the same silent loss."""
    c = refused(case, new, old=old)
    with pytest.raises(FieldsealNotSupported, match="blind index"):
        call_command("migrate", "app252", "0002", fake=True, verbosity=0)
    assert "0002_change" not in c.applied()


def test_fake_over_a_repointed_encrypted_index_is_refused(case):
    c = case(graph=graph_of(OLD, alter_index("u")))
    c.migrate("0001")
    with pytest.raises(FieldsealNotSupported, match="source from v to u"):
        call_command("migrate", "app252", "0002", fake=True, verbosity=0)
    assert "0002_change" not in c.applied()


# -- the escape hatch, and what it does not cover -----------------------------


def test_the_escape_hatch_state_operations_let_the_change_through(case):
    """A `SeparateDatabaseAndState` whose state operations carry the
    `AlterField` is the operator's statement that the index column was
    rebuilt under the new declaration by other means. The migration also
    holds an ordinary `AlterField` of the same column that changes nothing
    refused, so the plan is walked."""
    later = enc(index(index_id="exact2", projected_population=200000),
                uuid=UUID_A)
    change = textwrap.dedent(f"""[
        migrations.SeparateDatabaseAndState(
            database_operations=[],
            state_operations={alter(enc(index(index_id="exact2")))},
        ),
        {alter(later)[1:-1]},
    ]""")
    c = case(graph=graph_of(OLD, change))
    c.migrate("0001")
    c.migrate("0002")
    assert "0002_change" in c.applied()
    c.migrate("0001")
    assert c.applied() == {"0001_initial"}


def test_the_escape_hatch_carries_a_repointed_encrypted_index(case):
    change = textwrap.dedent(f"""[
        migrations.SeparateDatabaseAndState(
            database_operations=[],
            state_operations={alter_index("u")},
        ),
        {alter(enc(index(projected_population=1)))[1:-1]},
    ]""")
    c = case(graph=graph_of(OLD, change))
    c.migrate("0001")
    c.migrate("0002")
    assert "0002_change" in c.applied()


def test_the_alter_field_among_the_database_operations_is_refused(case):
    field = enc(index(index_id="exact2"))
    change = textwrap.dedent(f"""[migrations.SeparateDatabaseAndState(
        database_operations={alter(field)},
        state_operations={alter(field)},
    )]""")
    c = case(graph=graph_of(OLD, change))
    c.migrate("0001")
    with pytest.raises(FieldsealNotSupported, match="index_id"):
        c.migrate("0002")
    assert "0002_change" not in c.applied()


# -- the message --------------------------------------------------------------


def test_the_message_names_what_changed_and_where_to_go(case):
    c = refused(case, enc(index(index_id="exact2", truncate_bits=16)))
    with pytest.raises(FieldsealNotSupported) as e:
        c.migrate("0002")
    msg = str(e.value)
    assert "app252.0002_change" in msg
    assert "AlterField v on thing" in msg
    assert "index_id from exact to exact2" in msg
    assert "truncate_bits from 15 to 16" in msg
    assert "spec §7.8" in msg and "spec §10.2" in msg
    assert "returns no rows" in msg
    assert "SeparateDatabaseAndState" in msg and "state_operations" in msg
    assert "issues/315" in msg
    assert "Nothing has run: migrate refused the plan before any DDL" in msg
    assert "issues/303" in msg
    # Not the #288 message: no re-encryption remedy applies to an index.
    assert "two-column shape" not in msg
    assert "identity" not in msg


def test_when_the_idf_differs_the_cost_is_not_reported(case):
    c = refused(case, enc(index(idf="argon2id", time_cost=4)))
    with pytest.raises(FieldsealNotSupported) as e:
        c.migrate("0002")
    assert "idf from hmac-sha512 to argon2id" in str(e.value)
    assert "time_cost" not in str(e.value)


def test_the_identity_and_the_index_refusals_are_both_in_one_message(case):
    c = refused(case, enc(index(index_id="exact2"), uuid=UUID_B))
    with pytest.raises(FieldsealNotSupported) as e:
        c.migrate("0002")
    msg = str(e.value)
    assert f"column_uuid from {UUID_A} to {UUID_B}" in msg
    assert "index_id from exact to exact2" in msg
    assert "issues/288" in msg and "issues/303" in msg


# -- allowed ------------------------------------------------------------------

OVERRIDE = Raw("fieldseal_django.Override(reason='r', approved_by='a', "
               "date='2026-11-25')")

ALLOWED = [
    ("index-added", enc(), enc(index())),
    ("index-removed", OLD, enc()),
    ("projected-population", OLD, enc(index(projected_population=5000000))),
    ("skewed", OLD, enc(index(skewed=True))),
    ("cardinality-override", OLD,
     enc(index(cardinality_override=OVERRIDE))),
    ("on-unindexable-bucket", OLD,
     enc(index(on_unindexable="bucket", unindexable_override=OVERRIDE))),
    # #213: every project with an index generated this AlterField, and
    # unapplying it goes the other way. Both must work.
    ("suite-unstated-to-stated", enc(index(suite_id=None)), OLD),
    ("suite-stated-to-unstated", OLD, enc(index(suite_id=None))),
    # The core refuses a declaration with Argon2 costs on an hmac index at
    # startup, so this one cannot serve; the case only pins that the
    # migration check compares the costs under argon2id alone.
    ("cost-under-hmac", OLD, enc(index(time_cost=9, memory_kib=9))),
    ("cost-unchanged-under-argon2id",
     enc(index(idf="argon2id", time_cost=3)),
     enc(index(idf="argon2id", time_cost=3, projected_population=7))),
]


@pytest.mark.parametrize(("old", "new"), [a[1:] for a in ALLOWED],
                         ids=[a[0] for a in ALLOWED])
def test_a_change_that_keeps_the_index_declaration_is_let_through(
        case, old, new):
    """Forwards, then unapplied: both directions pass."""
    c = case(graph=graph_of(old, alter(new)))
    c.migrate("0001")
    c.insert(STAND_IN)
    c.migrate("0002")
    assert c.values() == [STAND_IN]
    c.migrate("0001")
    assert c.applied() == {"0001_initial"}


def test_an_encrypted_index_with_the_same_source_is_let_through(case):
    c = case(graph=graph_of(OLD, alter_index("v")))
    c.migrate("0002")
    assert "0002_change" in c.applied()


def test_the_suite_recorded_by_213_unapplies_under_fake_too(case):
    c = case(graph=graph_of(enc(index(suite_id=None)), alter(OLD)))
    call_command("migrate", "app252", "0002", fake=True, verbosity=0)
    call_command("migrate", "app252", "0001", fake=True, verbosity=0)
    call_command("migrate", "app252", "zero", fake=True, verbosity=0)
    assert c.applied() == set()


# -- the fact the refusal rests on --------------------------------------------


@pytest.mark.parametrize(("attribute", "changed", "value"), [
    ("index_id", "exact-v2", "ada@example.com"),
    ("suite_id", 0xFF02, "ada@example.com"),
    # A lowercase value derives the same under both functions, so this one
    # has capitals.
    ("normalize", "identity", "Ada@Example.com"),
], ids=["index_id", "suite_id", "normalize"])
def test_a_row_written_under_one_declaration_is_not_found_under_another(
        attribute, changed, value):
    """Write a row through the real `Patient` model, change the declared
    index as an `AlterField` would, and look the value up: the stored index
    value was derived under the old declaration (spec §7.2, §7.8), so the
    lookup returns nothing, and nothing about the column says why. Reads of
    the value itself are unaffected. The core registers `identity`,
    `nfc-casefold-v1` and `digits-only-v1`; `normalize` is measured from
    `nfc-casefold-v1` to `identity` on a value with capitals. `truncate_bits`
    matches by chance when the differing bits are zero (spec §7.2), so it is
    not measured here; `idf` and the cost need Argon2id's cost on a model
    that does not exist yet."""
    from .models import Patient

    field = Patient._meta.get_field("email")
    declared = field.index
    reset_client()
    try:
        pk = Patient.objects.create(email=value).pk
        assert [p.pk for p in
                Patient.objects.filter(email=value)] == [pk]
        field.index = dataclasses.replace(declared, **{attribute: changed})
        reset_client()
        assert list(Patient.objects.filter(email=value)) == []
        assert Patient.objects.get(pk=pk).email == value
    finally:
        field.index = declared
        reset_client()
    assert [p.pk for p in
            Patient.objects.filter(email=value)] == [pk]


# -- a rename of the indexed field (the PR #316 review) -----------------------

#: What makemigrations writes for renaming `v`, which `v_bidx` indexes:
#: `RenameField` leaves the custom `source` of the state's `v_bidx` as it was.
RENAME_V = """
    migrations.RenameField(model_name="thing", old_name="v", new_name="x"),
"""
REPOINT_V_BIDX = """
    migrations.AlterField(model_name="thing", name="v_bidx",
        field=fieldseal_django.fields.EncryptedIndex(null=True, source="%s")),
"""


def ops(*parts: str) -> str:
    return "[" + "".join(parts) + "]"


def test_renaming_the_indexed_field_is_let_through_both_ways(case):
    """The autodetector's own output: the `RenameField` and then the
    `AlterField` of the index to the new name."""
    c = case(graph=graph_of(OLD, ops(RENAME_V, REPOINT_V_BIDX % "x")))
    c.migrate("0001")
    c.migrate("0002")
    assert "0002_change" in c.applied()
    c.migrate("0001")
    assert c.applied() == {"0001_initial"}


def test_a_rename_in_an_applied_migration_is_resolved_for_a_later_alter(case):
    """`0002` is applied before the plan, which holds only `0003`."""
    def graph(table: str) -> dict[str, str]:
        return {"0001_initial": create(table, OLD, extra=EXTRA),
                "0002_rename": mig(["0001_initial"], ops(RENAME_V)),
                "0003_repoint": mig(["0002_rename"],
                                    ops(REPOINT_V_BIDX % "x"))}
    c = case(graph=graph)
    c.migrate("0002")
    c.migrate("0003")
    assert "0003_repoint" in c.applied()
    c.migrate("0002")
    assert "0003_repoint" not in c.applied()


def test_a_rename_in_a_state_operation_is_resolved_too(case):
    state_rename = ('migrations.SeparateDatabaseAndState('
                    f'state_operations=[{RENAME_V}])')
    def graph(table: str) -> dict[str, str]:
        return {"0001_initial": create(table, OLD, extra=EXTRA),
                "0002_rename": mig(["0001_initial"], ops(state_rename)),
                "0003_repoint": mig(["0002_rename"],
                                    ops(REPOINT_V_BIDX % "x"))}
    c = case(graph=graph)
    # Only the state is renamed, so the column is still `v`: fake the rest.
    c.migrate("0001")
    call_command("migrate", "app252", "0002", fake=True, verbosity=0)
    call_command("migrate", "app252", "0003", fake=True, verbosity=0)
    assert "0003_repoint" in c.applied()


def test_a_rename_chain_is_resolved(case):
    tmp = '''migrations.RenameField(model_name="thing", old_name="v",
                                  new_name="tmp"),
    migrations.RenameField(model_name="thing", old_name="tmp",
                           new_name="x"),'''
    c = case(graph=graph_of(OLD, ops(tmp, REPOINT_V_BIDX % "x")))
    c.migrate("0002")
    assert "0002_change" in c.applied()


def test_a_rename_then_a_repoint_to_another_field_is_still_refused(case):
    c = case(graph=graph_of(OLD, ops(RENAME_V, REPOINT_V_BIDX % "u")))
    c.migrate("0001")
    with pytest.raises(FieldsealNotSupported, match="source from x to u"):
        c.migrate("0002")
    assert c.applied() == {"0001_initial"}


def test_renaming_the_model_and_the_field_is_let_through(case):
    rename_model = ('migrations.RenameModel(old_name="Thing", '
                    'new_name="Widget"),')
    rename_field = RENAME_V.replace('"thing"', '"widget"')
    repoint = (REPOINT_V_BIDX % "x").replace('"thing"', '"widget"')
    change = ops(rename_model, rename_field, repoint)

    def graph(table: str) -> dict[str, str]:
        # Django injects a contenttypes RunPython after a RenameModel, which
        # needs the app in the state when it is unapplied.
        depends = mig(["0001_initial"], change).replace(
            "dependencies = [",
            'dependencies = [("contenttypes", "0002_remove_content_type_name"),'
            ' ', 1)
        return {"0001_initial": create(table, OLD, extra=EXTRA),
                "0002_change": depends}
    c = case(graph=graph)
    c.migrate("0001")
    c.migrate("0002")
    assert "0002_change" in c.applied()
