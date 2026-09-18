"""Install the built release artifacts into clean environments and use them.

    python tools/release/smoke.py dist-release

`check_release_conditions.py` reads the artifacts; this runs them. A fresh
virtualenv gets the two wheels, a fresh npm project gets the two tarballs
(plus `@prisma/client`, the adapter's peer), and nothing from the checkout is
importable in either. Then:

- **Condition 2, behaviourally.** Every suite each core registers is in the
  spec §4.8 provisional range, and a client constructed without arming refuses
  to encrypt with `SUITE_PROVISIONAL` -- with `FIELDSEAL_ARM_PROVISIONAL_SUITES`
  removed from the environment, so the default is what is tested.
- **The central claim, between published packages.** Each core encrypts under
  the shared public test key and the other decrypts it. CI's cross job proves
  that for the checkouts; `conformance.yml` says in as many words that it does
  not prove it for two published packages, and this does.
- **The adapters import and run their codec.** The Django adapter renders a
  spec §3.6 decimal; the Prisma adapter's entry point loads with its peer.

Needs network access for dependencies (cryptography, django, @prisma/client).
The Python side uses `--no-index` for our own two wheels' names, so a PyPI
`fieldseal` can never stand in for the one being tested.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
NPM = "npm.cmd" if sys.platform == "win32" else "npm"
PLAINTEXT = "fieldseal release smoke: café"

PY_SIDE = r'''
import json, os, sys, warnings
from decimal import Decimal

mode, keyfile, io = sys.argv[1], sys.argv[2], sys.argv[3]
import fieldseal
from fieldseal import FieldContext, Fieldseal, SUITES, is_provisional
from fieldseal.errors import FieldsealError
from fieldseal.keyprovider import StaticKeyProvider

assert "site-packages" in fieldseal.__file__, f"not the installed wheel: {fieldseal.__file__}"
keys = json.load(open(keyfile, encoding="utf-8"))
k, cd = keys["keys"]["tenant-a-dek-v1"], keys["context_defaults"]
H = bytes.fromhex
ctx = FieldContext(table_uuid=H(cd["table_uuid"]), column_uuid=H(cd["column_uuid"]),
                   purpose="encrypt", tenant_id=H(cd["tenant_id"]), row_id=None)
sid = int(k["suite_id"], 16)

def client(armed):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return Fieldseal(key_provider=StaticKeyProvider(H(k["key_id"]), H(k["tenant_dek"]), H(k["tenant_index_key"])),
                         allowed_suites={sid}, write_suite=sid, arm_provisional_suites=armed)

if mode == "produce":
    assert SUITES and all(is_provisional(s) for s in SUITES), sorted(SUITES)
    try:
        client(False).encrypt(b"x", ctx)
        raise SystemExit("an unarmed client encrypted: the arming gate is not the default")
    except FieldsealError as e:
        assert e.code == "SUITE_PROVISIONAL", e.code
    env = client(True).encrypt(sys.argv[4].encode(), ctx)
    json.dump({"envelope": env.hex()}, open(io, "w"))

    import django
    from django.conf import settings
    settings.configure(INSTALLED_APPS=["fieldseal_django"], USE_TZ=True)
    django.setup()
    from django.db import models
    import fieldseal_django
    from fieldseal_django import codec
    assert codec.to_bytes(models.DecimalField(max_digits=9, decimal_places=2), Decimal("1.50")) == b"1.5"
    print(f"python: fieldseal {fieldseal.__version__}, fieldseal-django {fieldseal_django.__version__}: "
          f"{len(SUITES)} suite(s), all provisional; unarmed refuses; encrypted; adapter codec ok")
else:
    got = client(False).decrypt(H(json.load(open(io))["envelope"]), ctx)
    assert got.decode() == sys.argv[4], got
    print("python: decrypted the TypeScript core's envelope")
'''

NODE_SIDE = r'''
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { Fieldseal, StaticKeyProvider, FieldsealError, registeredSuiteIds, isProvisionalId } from "@fieldseal/core";

const [mode, keyfile, io, plaintext] = process.argv.slice(2);
const path = createRequire(import.meta.url).resolve("@fieldseal/core");
if (!path.includes("node_modules")) throw new Error(`not the installed tarball: ${path}`);
const keys = JSON.parse(readFileSync(keyfile, "utf8"));
const k = keys.keys["tenant-a-dek-v1"], cd = keys.context_defaults;
const H = (h) => new Uint8Array(Buffer.from(h, "hex"));
const ctx = { tableUuid: H(cd.table_uuid), columnUuid: H(cd.column_uuid), tenantId: H(cd.tenant_id), rowId: null, purpose: "encrypt" };
const sid = parseInt(k.suite_id.slice(2), 16);
const client = (armed) => new Fieldseal(
  { keyProvider: new StaticKeyProvider({ dek: H(k.tenant_dek), keyId: H(k.key_id), indexKey: H(k.tenant_index_key) }),
    allowedSuites: [sid], writeSuite: sid, onWarning: () => {} },
  armed ? { armProvisionalSuites: true } : {});

if (mode === "consume-then-produce") {
  const ids = registeredSuiteIds();
  if (ids.length === 0 || !ids.every(isProvisionalId)) throw new Error(`non-provisional suite registered: ${ids}`);
  try {
    client(false).encrypt(H("78"), ctx);
    throw new Error("an unarmed client encrypted: the arming gate is not the default");
  } catch (e) {
    if (!(e instanceof FieldsealError) || e.code !== "SUITE_PROVISIONAL") throw e;
  }
  const got = Buffer.from(client(false).decrypt(H(JSON.parse(readFileSync(io, "utf8")).envelope), ctx)).toString("utf8");
  if (got !== plaintext) throw new Error(`decrypted ${JSON.stringify(got)}`);
  const env = client(true).encrypt(new Uint8Array(Buffer.from(plaintext, "utf8")), ctx);
  writeFileSync(io, JSON.stringify({ envelope: Buffer.from(env).toString("hex") }));
  const prisma = await import("@fieldseal/prisma");
  if (typeof prisma.fieldsealExtension !== "function") throw new Error("@fieldseal/prisma has no fieldsealExtension");
  // Neither package exports ./package.json, so read it from node_modules.
  const v = (p) => JSON.parse(readFileSync(`node_modules/${p}/package.json`, "utf8")).version;
  console.log(`node: @fieldseal/core ${v("@fieldseal/core")}, @fieldseal/prisma ${v("@fieldseal/prisma")}: ` +
    `${ids.length} suite(s), all provisional; unarmed refuses; decrypted the Python core's envelope; encrypted; adapter loads`);
}
'''


def run(cmd: list[str], cwd: Path, env: dict[str, str]) -> None:
    print(f"  $ {' '.join(str(c) for c in cmd)}", flush=True)
    subprocess.run(cmd, cwd=cwd, env=env, check=True)


def main(argv: list[str]) -> int:
    out = Path(argv[1] if len(argv) > 1 else REPO / "dist-release").resolve()
    wheels = sorted(out.glob("*.whl"))
    tgzs = sorted(out.glob("*.tgz"))
    assert len(wheels) == 2 and len(tgzs) == 2, (wheels, tgzs)
    keyfile = REPO / "vectors" / "keys" / "test-keys.json"
    # The default is what is under test: nothing may arrive armed.
    env = {k: v for k, v in os.environ.items()
           if k not in ("FIELDSEAL_ARM_PROVISIONAL_SUITES", "FIELDSEAL_TEST_MODE", "PYTHONPATH")}

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        io = tmp_path / "envelope.json"

        venv.create(tmp_path / "venv", with_pip=True)
        py = tmp_path / "venv" / ("Scripts" if sys.platform == "win32" else "bin") / "python"
        run([py, "-m", "pip", "install", "--quiet", "--disable-pip-version-check",
             *map(str, wheels)], tmp_path, env)
        (tmp_path / "side.py").write_text(PY_SIDE, "utf-8")
        run([py, "side.py", "produce", keyfile, io, PLAINTEXT], tmp_path, env)

        node_dir = tmp_path / "node"
        node_dir.mkdir()
        (node_dir / "package.json").write_text('{"name": "smoke", "private": true, "type": "module"}\n')
        # --ignore-scripts: @prisma/client's postinstall would run `prisma
        # generate` against a schema this project does not have.
        run([NPM, "install", "--no-audit", "--no-fund", "--ignore-scripts",
             *map(str, tgzs), "@prisma/client@7.10.0"], node_dir, env)
        (node_dir / "side.mjs").write_text(NODE_SIDE, "utf-8")
        run(["node", "side.mjs", "consume-then-produce", keyfile, io, PLAINTEXT], node_dir, env)

        run([py, "side.py", "consume", keyfile, io, PLAINTEXT], tmp_path, env)
    print("\nsmoke: both published cores interoperate, and neither writes unarmed.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
