"""Settings for the Django half of the patient-directory demo.

**Postgres only, and one connection string.** The demo's whole assertion is
that two stacks share one physical database, so there is nothing for a second
backend to mean here: SQLite has no `uuid` type, and a scenario that ran on a
database only one of the two stacks could open would prove nothing. The URL
comes from `DATABASE_URL` because that is the variable Prisma reads, and two
variables that must agree are a variable that will not.

**The keys are public test material, resolved by `key_ref`.** They come from
`vectors/keys/test-keys.json`, the same file the cross-language producers use,
so the banner in that file travels with anything copied out of here. No key is
embedded in this directory, and nothing here may be used outside a test.

The installed-apps list is deliberately minimal -- no `contenttypes`, no
`auth`. Those would put four more tables in the schema, and the schema is the
artifact this demo compares between two stacks (`check_schema_shape.py`).
`django_migrations` is then the only table in the database that Prisma does
not declare, which is a fact small enough to state.
"""

from __future__ import annotations

import json
import os
import pathlib
import urllib.parse

from fieldseal.keyprovider import StaticKeyProvider

BASE_DIR = pathlib.Path(__file__).resolve().parent
REPO = BASE_DIR.parents[2]

SECRET_KEY = "fieldseal-patient-directory-demo-not-a-real-secret"
DEBUG = False
ALLOWED_HOSTS: list[str] = []
USE_TZ = True

INSTALLED_APPS = [
    "fieldseal_django",
    "directory",
]

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/fieldseal_demo"
)
_url = urllib.parse.urlparse(DATABASE_URL)
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": _url.path.lstrip("/") or "fieldseal_demo",
        "USER": urllib.parse.unquote(_url.username or "postgres"),
        "PASSWORD": urllib.parse.unquote(_url.password or "postgres"),
        "HOST": _url.hostname or "localhost",
        "PORT": str(_url.port or 5432),
    }
}

#: The shared key, by reference. `tenant-a-dek-v1` is the key every pinned
#: vector uses, and the Prisma half of this demo resolves the same entry from
#: the same file -- which is the only thing the two stacks share besides the
#: database.
KEY_REF = "tenant-a-dek-v1"
_keyfile = json.loads(
    (REPO / "vectors" / "keys" / "test-keys.json").read_text("utf-8")
)
_key = _keyfile["keys"][KEY_REF]
SUITE_ID = int(_key["suite_id"], 16)
#: Public test material, and not secret in any sense -- it is the opaque
#: identifier that occupies bytes 3..19 of every envelope this demo writes,
#: which is what makes the "both stacks wrote the same header" assertion in
#: act 5 checkable without a key.
KEY_ID = bytes.fromhex(_key["key_id"])

FIELDSEAL = {
    "KEY_PROVIDER": lambda: StaticKeyProvider(
        key_id=bytes.fromhex(_key["key_id"]),
        tenant_dek=bytes.fromhex(_key["tenant_dek"]),
        tenant_index_key=bytes.fromhex(_key["tenant_index_key"]),
    ),
    "ALLOWED_SUITES": {SUITE_ID},
    "WRITE_SUITE": SUITE_ID,
    "READ_MODE": "strict",
    # Spec §4.8: the suite is provisional, so writing under it is an
    # affirmative act rather than a default. Armed in code here, as the
    # adapter suites do, so the gate stays visible in the file that decides
    # it rather than in an environment variable somebody exports once.
    "ARM_PROVISIONAL_SUITES": True,
}
