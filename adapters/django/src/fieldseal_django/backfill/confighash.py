"""SHA-256 of the configuration document (PROCEDURE §4).

The one module under `src/` that imports `hashlib`, and it holds nothing
else. The hash is a change detector over public configuration, not a
cryptographic control, and PROCEDURE §4 says computing it is not
cryptographic code in the sense of AD-1 (spec §11.3). CI's AD-1 grep skips
this file by name and checks that it stays this small.
"""

from __future__ import annotations

import hashlib


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
