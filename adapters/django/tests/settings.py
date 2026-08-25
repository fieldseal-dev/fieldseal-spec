"""Django settings for the adapter test suite.

SQLite by default so the suite runs anywhere; `docs/12` §8 also requires
Postgres in CI, because binary-column behaviour differs between the two and
that difference is exactly the sort of thing a single-backend suite hides.
Set `FIELDSEAL_TEST_DB=postgres` with the usual PG* environment variables to
run against Postgres.
"""

from __future__ import annotations

import os

from fieldseal.keyprovider import StaticKeyProvider

SECRET_KEY = "fieldseal-adapter-tests-not-a-real-secret"
USE_TZ = True

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "fieldseal_django",
    "tests",
]

if os.environ.get("FIELDSEAL_TEST_DB") == "postgres":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.environ.get("PGDATABASE", "fieldseal_test"),
            "USER": os.environ.get("PGUSER", "postgres"),
            "PASSWORD": os.environ.get("PGPASSWORD", "postgres"),
            "HOST": os.environ.get("PGHOST", "localhost"),
            "PORT": os.environ.get("PGPORT", "5432"),
        }
    }
else:
    DATABASES = {
        "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}
    }

DEK = bytes(range(32))
INDEX_KEY = bytes(range(32, 64))
KEY_ID = bytes(range(16))

FIELDSEAL = {
    "KEY_PROVIDER": lambda: StaticKeyProvider(
        key_id=KEY_ID, tenant_dek=DEK, tenant_index_key=INDEX_KEY
    ),
    "ALLOWED_SUITES": {0xFF01},
    "WRITE_SUITE": 0xFF01,
    "READ_MODE": "strict",
    # Spec §4.8: the suite is provisional, so writing under it is an
    # affirmative act. A test suite arms it explicitly rather than setting the
    # environment variable, so the gate itself stays testable.
    "ARM_PROVISIONAL_SUITES": True,
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
