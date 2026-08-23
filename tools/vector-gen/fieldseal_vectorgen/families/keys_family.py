"""`keys/test-keys.json` -- the shared, PUBLIC key material `cross/`
producers and consumers resolve `key_ref` against (docs/08 §4.7).

Not a vector family: nothing here has an expected value. It is listed in
MANIFEST.json under `support`, not `files`, so a harness iterating the
families never tries to run it.
"""

from __future__ import annotations

from .. import inputs as I
from ..manifest import SPEC_VERSION, VECTOR_SUITE_VERSION
from ._common import suite_str

BANNER = (
    "PUBLIC TEST MATERIAL. Every value in this file is published in a public "
    "repository and is known to everyone. It exists so that cross-"
    "implementation producers and consumers share key material by reference "
    "(key_ref) instead of embedding it per file. No value here may ever be "
    "used outside a test, and an implementation that accepts it outside "
    "FIELDSEAL_TEST_MODE is misconfigured, not conformant."
)


def generate() -> dict:
    def entry(key_id, dek, index_key, label):
        return {
            "label": label,
            "suite_id": suite_str(0xFF01),
            "key_id": key_id.hex(),
            "tenant_dek": dek.hex(),
            "tenant_index_key": index_key.hex(),
        }
    return {
        "schema": "fieldseal-vectors/keys/v1",
        "vector_suite_version": VECTOR_SUITE_VERSION,
        "spec_version": SPEC_VERSION,
        "banner": BANNER,
        "keys": {
            "tenant-a-dek-v1": entry(I.KEY_ID, I.TENANT_DEK, I.TENANT_INDEX_KEY,
                                     "the tenant every pinned vector uses"),
            "tenant-b-dek-v1": entry(I.KEY_ID_B, I.TENANT_DEK_B,
                                     I.TENANT_INDEX_KEY_B,
                                     "a second tenant, for multi-key cases"),
        },
        "context_defaults": {
            "table_uuid": I.TABLE_UUID.hex(),
            "column_uuid": I.COLUMN_UUID.hex(),
            "tenant_id": I.TENANT_ID.hex(),
        },
    }
