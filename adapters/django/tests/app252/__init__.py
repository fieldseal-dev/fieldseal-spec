"""An app with no models of its own, for the #252 migration tests.

`tests/test_convert_to_encrypted.py` points `MIGRATION_MODULES` for this app
at migration packages it writes per case, so `migrate` runs a real plan --
and sends `pre_migrate` -- without touching the suite's own tables.
"""
