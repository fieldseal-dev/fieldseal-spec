"""`migrate` refuses an `AlterField` that changes an `Encrypted` column's
identity (#288).

An `AlterField` between two `Encrypted` declarations that change the
`column_uuid`, the inner field's spec §3.6 logical type, or `tenant_bound`
runs no SQL on any backend (#283) and leaves every stored envelope as it was,
under an identity the field no longer has. These tests run real `migrate`
commands over the model-less `tests.app252` through the `case` fixture of
`conftest.py`, as `test_convert_to_encrypted.py` does for #252, and are not
backend-specific: the column is `bytea` or `BLOB` on both sides, so what is
asserted is the refusal and that nothing ran. The one cryptographic fact the
refusal of `tenant_bound` rests on is measured by a test of its own.
"""

from __future__ import annotations

import itertools
import textwrap

import pytest
from django.core.management import call_command
from django.db import connection, models
from django.test.utils import isolate_apps, override_settings
from fieldseal.errors import FieldsealError

from fieldseal_django import (
    Encrypted,
    FieldsealMeta,
    FieldsealNotSupported,
    tenant_scope,
)
from fieldseal_django import operations as ops

from .migration_cases import alter, create, guard_off, mig

pytestmark = [
    pytest.mark.django_db(transaction=True),
    pytest.mark.filterwarnings("ignore::fieldseal.errors.FieldsealWarning"),
]

UUID_A = "018f3c2e-0000-7000-8000-000000288001"
UUID_B = "018f3c2e-0000-7000-8000-000000288002"


def enc(inner: str = "models.CharField(max_length=100)", *,
        uuid: str = UUID_A, **kw: str) -> str:
    """An `Encrypted` declaration as migration source."""
    extra = "".join(f", {k}={v}" for k, v in kw.items())
    return (f"fieldseal_django.fields.Encrypted({inner}, "
            f"column_uuid={uuid!r}, null=True{extra})")


OLD = enc()

#: (id, the declaration the migration alters to, what the message must name)
REFUSED = [
    ("column_uuid", enc(uuid=UUID_B), "column_uuid"),
    ("logical-type", enc("models.IntegerField()"), "inner logical type"),
    ("logical-type-date", enc("models.DateField()"), "inner logical type"),
    ("tenant-bound-on", enc(tenant_bound="True"), "tenant_bound"),
    ("storage-to-base64", enc(storage='"base64"'), "storage"),
]


def refused(case, new: str, *, old: str = OLD):
    c = case(old, alter(new))
    c.migrate("0001")
    c.insert(b"\x01\xff stand-in for an envelope")
    return c


# -- refused: forwards --------------------------------------------------------


@pytest.mark.parametrize(("new", "named"), [r[1:] for r in REFUSED],
                         ids=[r[0] for r in REFUSED])
def test_migrate_refuses_the_change_before_any_ddl(case, new, named):
    c = refused(case, new)
    with pytest.raises(FieldsealNotSupported) as e:
        c.migrate("0002")
    assert named in str(e.value)
    assert "0002_change" not in c.applied()
    assert c.values() == [b"\x01\xff stand-in for an envelope"]


def test_storage_base64_to_binary_is_refused_too(case):
    c = case(enc(storage='"base64"'), alter(enc()))
    c.migrate("0001")
    with pytest.raises(FieldsealNotSupported) as e:
        c.migrate("0002")
    assert "storage from base64 to binary" in str(e.value)
    assert "0002_change" not in c.applied()


def test_storage_base64_to_binary_unapplied_and_fake_are_refused(case):
    c = case(enc(storage='"base64"'), alter(enc()))
    c.migrate("0001")
    with pytest.raises(FieldsealNotSupported, match="storage"):
        call_command("migrate", "app252", "0002", fake=True, verbosity=0)
    with guard_off():
        c.migrate("0002")
    with pytest.raises(FieldsealNotSupported, match="unapplying"):
        c.migrate("0001")
    assert "0002_change" in c.applied()


def test_the_message_for_a_storage_change(case):
    c = refused(case, enc(storage='"base64"'))
    with pytest.raises(FieldsealNotSupported) as e:
        c.migrate("0002")
    msg = str(e.value)
    assert "storage from binary to base64" in msg
    assert "spec §3.3" in msg and "NOT_CIPHERTEXT" in msg
    assert "base64 text as the plaintext" in msg
    assert "spec §10.2" in msg
    assert "Nothing has run: migrate refused the plan before any DDL" in msg
    assert "SeparateDatabaseAndState" in msg


def test_the_escape_hatch_carries_a_storage_change(case):
    field = enc("models.CharField(max_length=300)", storage='"base64"')
    change = textwrap.dedent(f"""[
        migrations.SeparateDatabaseAndState(
            database_operations=[],
            state_operations={alter(enc(storage='"base64"'))},
        ),
        {alter(field)[1:-1]},
    ]""")
    c = case(OLD, change)
    c.migrate("0001")
    c.migrate("0002")
    assert "0002_change" in c.applied()


def test_tenant_bound_off_is_refused_too(case):
    c = refused(case, enc(tenant_bound="False"),
                old=enc(tenant_bound="True"))
    with pytest.raises(FieldsealNotSupported, match="tenant_bound"):
        c.migrate("0002")


def test_tenant_bound_declared_against_not_declared_is_refused(case):
    """`None` leaves it to the model's `FieldsealMeta`, which a migration
    state does not carry, so the change may be one and is refused."""
    c = refused(case, enc(tenant_bound="False"))
    with pytest.raises(FieldsealNotSupported, match="not declared"):
        c.migrate("0002")


def test_every_change_in_one_alter_field_is_named(case):
    c = refused(case, enc("models.IntegerField()", uuid=UUID_B,
                          tenant_bound="True"))
    with pytest.raises(FieldsealNotSupported) as e:
        c.migrate("0002")
    msg = str(e.value)
    assert "column_uuid" in msg and "inner logical type" in msg
    assert "tenant_bound" in msg


# -- refused: unapplying ------------------------------------------------------


@pytest.mark.parametrize(("new", "named"), [r[1:] for r in REFUSED],
                         ids=[r[0] for r in REFUSED])
def test_migrate_refuses_unapplying_the_change(case, new, named):
    c = case(OLD, alter(new))
    with guard_off():
        c.migrate("0002")
    c.insert(b"\x01\xff stand-in for an envelope")
    with pytest.raises(FieldsealNotSupported) as e:
        c.migrate("0001")
    assert named in str(e.value)
    assert "unapplying" in str(e.value)
    assert "0002_change" in c.applied()


def test_unapplying_names_the_values_in_the_direction_they_change(case):
    c = case(OLD, alter(enc(uuid=UUID_B)))
    with guard_off():
        c.migrate("0002")
    with pytest.raises(FieldsealNotSupported) as e:
        c.migrate("0001")
    msg = str(e.value)
    assert f"column_uuid from {UUID_B} to {UUID_A}" in msg


# -- refused: --fake ----------------------------------------------------------


@pytest.mark.parametrize(("new", "named"), [r[1:] for r in REFUSED],
                         ids=[r[0] for r in REFUSED])
def test_migrate_fake_is_refused_too(case, new, named):
    """`pre_migrate` does not say the run is fake, so the receiver cannot
    tell, and a faked change is the same silent loss."""
    c = refused(case, new)
    with pytest.raises(FieldsealNotSupported, match=named):
        call_command("migrate", "app252", "0002", fake=True, verbosity=0)
    assert "0002_change" not in c.applied()


def test_unapplying_with_fake_is_refused_too(case):
    c = case(OLD, alter(enc(uuid=UUID_B)))
    with guard_off():
        c.migrate("0002")
    with pytest.raises(FieldsealNotSupported, match="column_uuid"):
        call_command("migrate", "app252", "0001", fake=True, verbosity=0)
    assert "0002_change" in c.applied()


# -- the message --------------------------------------------------------------


def test_the_message_for_a_column_uuid_change(case):
    c = refused(case, enc(uuid=UUID_B))
    with pytest.raises(FieldsealNotSupported) as e:
        c.migrate("0002")
    msg = str(e.value)
    assert "app252.0002_change" in msg
    assert "AlterField v on thing" in msg
    assert f"column_uuid from {UUID_A} to {UUID_B}" in msg
    assert "spec §6.1" in msg
    assert "data-loss" in msg
    assert "Nothing has run: migrate refused the plan before any DDL" in msg
    assert "SeparateDatabaseAndState" in msg and "state_operations" in msg
    assert "two-column shape (docs/12 §7)" in msg
    assert "issues/288" in msg


def test_the_message_for_a_logical_type_change(case):
    c = refused(case, enc("models.IntegerField()"))
    with pytest.raises(FieldsealNotSupported) as e:
        c.migrate("0002")
    msg = str(e.value)
    assert "inner logical type from string (CharField) to int " \
        "(IntegerField)" in msg
    assert "spec §3.6" in msg
    assert "Nothing has run: migrate refused the plan before any DDL" in msg
    assert "SeparateDatabaseAndState" in msg
    assert "issues/288" in msg


def test_the_message_for_a_tenant_bound_change(case):
    c = refused(case, enc(tenant_bound="True"),
                old=enc(tenant_bound="False"))
    with pytest.raises(FieldsealNotSupported) as e:
        c.migrate("0002")
    msg = str(e.value)
    assert "tenant_bound from False to True" in msg
    assert "spec §6; docs/12 §4" in msg
    assert "Nothing has run: migrate refused the plan before any DDL" in msg


# -- allowed ------------------------------------------------------------------


ALLOWED = [
    ("max-length", enc("models.CharField(max_length=200)")),
    ("email-field-to-char-field", enc("models.CharField(max_length=254)"),
     enc("models.EmailField(max_length=254)")),
    ("char-field-to-text-field", enc("models.TextField()")),
    ("same-uuid-written-another-way", enc(uuid=UUID_A.upper())),
    ("unindexable-noun", enc(unindexable_noun='"name"')),
    ("blank-and-verbose-name", enc(blank="True", verbose_name='"Email"')),
    ("tenant-bound-unchanged",
     enc(tenant_bound="True"), enc(tenant_bound="True")),
]


@pytest.mark.parametrize("new,old", [(a[1], a[2] if len(a) > 2 else OLD)
                                     for a in ALLOWED],
                         ids=[a[0] for a in ALLOWED])
def test_a_change_that_keeps_the_identity_is_let_through(case, new, old):
    c = case(old, alter(new))
    c.migrate("0001")
    c.insert(b"\x01\xff stand-in for an envelope")
    c.migrate("0002")
    assert c.values() == [b"\x01\xff stand-in for an envelope"]
    c.migrate("0001")
    assert c.applied() == {"0001_initial"}


def test_an_index_declaration_change_is_let_through(case):
    """`index` is not part of the stored value's identity: the envelope does
    not depend on it. (Whether the *index column* stays right is the open
    question #288 records, not decided here.)"""
    index = ("fieldseal_django.BlindIndex(suite_id=0xFF01, "
             "index_id='exact', idf='hmac-sha512', "
             "normalize='nfc-casefold-v1', truncate_bits=15, "
             "projected_population=100000)")
    c = case(OLD, alter(enc(index=index)))
    c.migrate("0002")
    assert "0002_change" in c.applied()


def test_the_escape_hatch_state_operations_let_the_change_through(case):
    """A `SeparateDatabaseAndState` whose state operations carry the
    `AlterField` is the operator's statement that the values were
    re-encrypted another way; only its database operations are checked.

    The migration also holds an ordinary `AlterField` of the same column, so
    the plan is walked: a walk that checked the state operations would stop
    at the first."""
    later = enc("models.CharField(max_length=300)", uuid=UUID_B)
    change = textwrap.dedent(f"""[
        migrations.SeparateDatabaseAndState(
            database_operations=[],
            state_operations={alter(enc(uuid=UUID_B))},
        ),
        {alter(later)[1:-1]},
    ]""")
    c = case(OLD, change)
    c.migrate("0001")
    c.migrate("0002")
    assert "0002_change" in c.applied()
    # Unapplying is the same statement in reverse.
    c.migrate("0001")
    assert c.applied() == {"0001_initial"}


def test_the_alter_field_among_the_database_operations_is_refused(case):
    field = enc(uuid=UUID_B)
    change = textwrap.dedent(f"""[migrations.SeparateDatabaseAndState(
        database_operations={alter(field)},
        state_operations={alter(field)},
    )]""")
    c = case(OLD, change)
    c.migrate("0001")
    with pytest.raises(FieldsealNotSupported, match="column_uuid"):
        c.migrate("0002")


# -- a ConvertToEncrypted never escapes the walk (#252) -----------------------


def test_convert_out_of_an_encrypted_column_is_refused_under_fake(case):
    """A `ConvertToEncrypted` whose field is plain starts the walk on every
    backend: its declaration refusals are raised before the plan starts,
    `--fake` included (`dev` refused this; #288's trigger must not lose it)."""
    conv = ('[fieldseal_django.operations.ConvertToEncrypted('
            'model_name="thing", name="v", '
            'field=models.TextField(null=True))]')
    c = case(enc(storage='"base64"'), conv)
    c.migrate("0001")
    with pytest.raises(FieldsealNotSupported, match="ConvertToEncrypted"):
        call_command("migrate", "app252", "0002", fake=True, verbosity=0)
    assert "0002_change" not in c.applied()


def test_a_refused_convert_stops_the_plan_before_earlier_migrations(case):
    """Plain to plain is refused by the declaration; an earlier migration in
    the same plan must not have committed when it is."""
    def graph(table: str) -> dict[str, str]:
        add = ('[migrations.AddField(model_name="thing", name="z", '
               'field=models.IntegerField(null=True))]')
        conv = ('[fieldseal_django.operations.ConvertToEncrypted('
                'model_name="thing", name="v", '
                'field=models.TextField(null=True, blank=True))]')
        return {
            "0001_initial": create(table, "models.TextField(null=True)"),
            "0002_w": mig(["0001_initial"], add),
            "0003_conv": mig(["0002_w"], conv),
        }

    c = case(graph=graph)
    c.migrate("0001")
    with pytest.raises(FieldsealNotSupported, match="ConvertToEncrypted"):
        c.migrate("0003")
    assert "0002_w" not in c.applied()


# -- a fresh database runs the whole history ----------------------------------


def test_a_fresh_database_is_refused_for_a_history_with_an_identity_change(
        case):
    """A test database or a new environment runs every migration, so a
    historical change of `column_uuid` is refused although the table is
    empty: a `RunPython` in between could have written rows, so the receiver
    does not guess. docs/12 §6 gives the remedies."""
    c = case(OLD, alter(enc(uuid=UUID_B)))
    with pytest.raises(FieldsealNotSupported, match="column_uuid"):
        c.migrate("0002")
    assert c.applied() == set()


def test_wrapping_the_historical_change_lets_a_fresh_database_through(case):
    change = textwrap.dedent(f"""[migrations.SeparateDatabaseAndState(
        state_operations={alter(enc(uuid=UUID_B))},
    )]""")
    c = case(OLD, change)
    c.migrate("0002")
    assert "0002_change" in c.applied()


def test_squashing_folds_the_change_into_the_create_model():
    """The optimizer, as `squashmigrations` runs it, leaves no `AlterField`
    for the receiver to refuse."""
    from django.db import migrations
    from django.db.migrations.optimizer import MigrationOptimizer

    from fieldseal_django.fields import Encrypted

    def field(uuid: str) -> Encrypted:
        return Encrypted(models.CharField(max_length=100), column_uuid=uuid,
                         null=True)

    operations = [
        migrations.CreateModel("Thing", [
            ("id", models.BigAutoField(primary_key=True)),
            ("v", field(UUID_A))]),
        migrations.AlterField("Thing", "v", field(UUID_B)),
    ]
    optimized = MigrationOptimizer().optimize(operations, "app252")
    assert [type(op) for op in optimized] == [migrations.CreateModel]
    assert dict(optimized[0].fields)["v"].column_uuid_raw == UUID_B


# -- unapplying, the cast message ---------------------------------------------


def test_the_cast_message_is_reversed_when_unapplying(case, monkeypatch):
    """On PostgreSQL the #252 message rides with the identity one, and must
    name the same direction. Relabelled to PostgreSQL so this runs anywhere
    (the check reads the field types from the real backend's `data_types`)."""
    c = case(OLD, alter(enc(storage='"base64"')))
    with guard_off():
        c.migrate("0002")
    binary = connection.data_types["BinaryField"]
    text = connection.data_types["TextField"]
    with monkeypatch.context() as mp:
        mp.setattr(connection, "vendor", "postgresql")
        with pytest.raises(FieldsealNotSupported) as e:
            c.migrate("0001")
    msg = str(e.value)
    assert "storage from base64 to binary" in msg
    assert msg.count("unapplying AlterField v on thing") == 2
    assert f"changes the column from {text} to {binary}" in msg


# -- what is walked -----------------------------------------------------------


def test_a_change_in_an_applied_migration_outside_the_plan_is_not_refused(
        case):
    """0002 changed the identity and was applied (the operator accepted it);
    migrating on to 0003 walks only 0003, which changes only a length."""
    def graph(table: str) -> dict[str, str]:
        return {
            "0001_initial": create(table, OLD),
            "0002_change": mig(["0001_initial"], alter(enc(uuid=UUID_B))),
            "0003_length": mig(
                ["0002_change"],
                alter(enc("models.CharField(max_length=300)", uuid=UUID_B))),
        }

    c = case(graph=graph)
    with guard_off():
        c.migrate("0002")
    c.migrate("0003")
    assert "0003_length" in c.applied()


def test_the_walk_starts_from_the_applied_states(case):
    """The same 0003 with a new `column_uuid` against 0002's state is
    refused, naming 0003 and the value 0002 left."""
    def graph(table: str) -> dict[str, str]:
        return {
            "0001_initial": create(table, OLD),
            "0002_change": mig(["0001_initial"], alter(enc(uuid=UUID_B))),
            "0003_again": mig(
                ["0002_change"],
                alter(enc(uuid="018f3c2e-0000-7000-8000-000000288003"))),
        }

    c = case(graph=graph)
    with guard_off():
        c.migrate("0002")
    with pytest.raises(FieldsealNotSupported) as e:
        c.migrate("0003")
    assert "0003_again" in str(e.value)
    assert f"column_uuid from {UUID_B} to " in str(e.value)


def test_an_alter_field_from_a_plain_field_is_not_an_identity_change(case):
    """Into `Encrypted` from a plain field is the conversion of #252, whose
    rows hold no envelope yet. On PostgreSQL that has its own refusal; here
    the identity check must not add one."""
    c = case("models.BinaryField(null=True)", alter(enc("models.CharField()")))
    c.migrate("0002")
    assert "0002_change" in c.applied()


class _ModelHintRouter:
    def allow_migrate(self, db, app_label, model_name=None, **hints):
        model = hints.get("model")
        if model is not None and model._meta.app_label == "app252":
            return False
        return None


def test_a_model_routed_away_is_not_refused(case):
    c = case(OLD, alter(enc(uuid=UUID_B)))
    with override_settings(DATABASE_ROUTERS=[_ModelHintRouter()]):
        c.migrate("0002")
        assert c.applied() == {"0001_initial", "0002_change"}
        c.migrate("zero")


def _no_walk(monkeypatch):
    def walk(*args, **kwargs):
        raise AssertionError("the plan was walked")

    monkeypatch.setattr(ops, "_unsafe_alter_fields", walk)


def test_no_walk_when_the_plan_has_no_alter_field(case, monkeypatch):
    """The fast path: rendering the states is the expensive part."""
    _no_walk(monkeypatch)
    c = case(OLD, "[migrations.RunSQL('SELECT 1', 'SELECT 1')]")
    c.migrate("0002")
    assert "0002_change" in c.applied()


@pytest.mark.skipif(connection.vendor == "postgresql",
                    reason="PostgreSQL walks every AlterField (#252)")
def test_off_postgres_no_walk_for_an_alter_field_to_a_plain_field(
        case, monkeypatch):
    """Off PostgreSQL only a change between two `Encrypted` declarations can
    be refused, so an `AlterField` to a plain field starts no walk."""
    _no_walk(monkeypatch)
    c = case(OLD, alter("models.BinaryField(null=True)"))
    c.migrate("0002")
    assert "0002_change" in c.applied()


@pytest.mark.skipif(connection.vendor != "postgresql", reason="PostgreSQL")
def test_postgres_reports_the_bytea_cast_beside_the_identity_change(case):
    """Both refusals in one message, when one `AlterField` earns both:
    `base64` storage is `text`, so this one also casts out of `bytea`."""
    c = case(OLD, alter(enc(uuid=UUID_B, storage='"base64"')))
    c.migrate("0001")
    with pytest.raises(FieldsealNotSupported) as e:
        c.migrate("0002")
    msg = str(e.value)
    assert "column_uuid" in msg
    assert "cast between bytea and text" in msg


# -- the fact the tenant_bound refusal rests on -------------------------------

_serial = itertools.count(1)


@isolate_apps("tests")
@pytest.mark.parametrize(("written", "read"), [
    (False, True), (True, False), (None, True), (True, None),
], ids=["off-to-on", "on-to-off", "inherited-to-on", "on-to-inherited"])
def test_a_value_written_under_one_tenant_bound_setting_does_not_read_under_the_other(  # noqa: E501
        written, read):
    """Write a value under one declaration, flip it, read it back: the
    envelope was encrypted under a context the new declaration does not
    build (spec §6; docs/12 §4), and nothing about the column says so."""
    n = next(_serial)
    table = f"tenant288_{n}"

    def model(name: str, tenant_bound: bool | None) -> type[models.Model]:
        kw = {} if tenant_bound is None else {"tenant_bound": tenant_bound}
        return type(name, (models.Model,), {
            "__module__": "tests",
            "v": Encrypted(models.CharField(max_length=50), null=True,
                           column_uuid=UUID_A, **kw),
            "fieldseal": FieldsealMeta(table_uuid=UUID_B),
            "Meta": type("Meta", (), {"db_table": table}),
        })

    Before, After = model(f"Before{n}", written), model(f"After{n}", read)
    with connection.schema_editor() as editor:
        editor.create_model(Before)
    try:
        with tenant_scope(b"tenant-a"):
            pk = Before.objects.create(v="ada@example.com").pk
            assert Before.objects.get(pk=pk).v == "ada@example.com"
        with connection.schema_editor(collect_sql=True) as editor:
            editor.alter_field(Before, Before._meta.get_field("v"),
                               After._meta.get_field("v"))
        assert editor.collected_sql == []
        with tenant_scope(b"tenant-a"), pytest.raises(FieldsealError):
            After.objects.get(pk=pk)
    finally:
        with connection.schema_editor() as editor:
            editor.delete_model(Before)
