---
title: "Fieldseal"
---

## Latest release: v0.1.3 (experimental)

> **Not independently reviewed, not for production data.** The format may change
> before 1.0, and data written now may have to be re-encrypted if review changes
> a construction. Writing refuses until provisional use is explicitly armed.

The two reference cores and two ORM adapters can now be installed, for evaluation
and feedback:

- Python: `pip install "fieldseal[argon2]"` · Django: `pip install fieldseal-django`
- TypeScript/Node: `npm install @fieldseal/core` · Prisma: `npm install @fieldseal/prisma`

**If you installed `fieldseal-django` 0.1.2 or earlier, upgrade.** Those
releases did not declare the Argon2id dependency, so a PyPI install could not
save to an indexed column. 0.1.3 fixes the dependency; the format, the cipher
suite and the test vectors are unchanged. The `argon2` extra on the Python core
is what Argon2id blind indexes need; leave it out only if you use none.

Both cores pass the same 146 test vectors. Each decrypts what the other
encrypts: CI checks this on every run, and the release process checked it again
on the published packages. That shows the implementations agree with each other
and with the specification. It does not show that the design is sound. That
needs independent cryptographic review, which is the gate on 1.0.

[Release notes](https://github.com/fieldseal-dev/fieldseal-spec/releases/tag/v0.1.3) ·
[How to review the design](/docs/reviewer-brief/)

## The problem

A company holding regulated consumer data has three options today, and all three
are bad.

**Storage-layer encryption (TDE, encrypted volumes)** defends exactly one thing:
physical loss of a disk. It gives transparent decryption to anything that can
authenticate to the database. PCI DSS v4.0.1 Req. 3.5.1.2 says so explicitly,
and has been enforceable since 31 March 2025.

**Building application-layer encryption yourself** took 37signals roughly two
years of a senior engineer's time, for one framework in one language -- with an
abandoned first prototype, an RCE via `Marshal` serialization caught by luck, and
a deterministic-encryption flaw found by audit days before launch.

**Buying a data-privacy vault** starts around $12k--$23k/year plus per-tenant
fees, and requires either moving your PII into a vendor's vault or routing
traffic through a proxy that discards your ORM's semantics.

Underneath all three sits a problem nobody has addressed: **there is no portable
format.** Data encrypted by Rails cannot be read by a Python job. Every
implementation invents its own ciphertext layout, so application-layer encryption
becomes a one-way door into a single language ecosystem.

## What this is

1. **A specification** -- a self-describing ciphertext envelope for a single
   database cell, a frozen cipher-suite registry, a key hierarchy, a blind-index
   construction with a declared leakage budget, and a key-provider interface.
   With machine-readable test vectors.
2. **Reference implementations** -- a core library per language (Python,
   TypeScript, Java, .NET, Go) that all pass the same vectors, plus thin per-ORM
   adapters. Core knows nothing about SQL; adapters know nothing about
   cryptography.
3. **An operational playbook** -- threat model, data-classification gate,
   zero-downtime migration, key-rotation runbook, KMS-outage degradation modes,
   and published benchmarks.

## What this is not

- **Not protection against a compromised application process.** The keys are in
  that process.
- **Not range queries, sorting, `LIKE`, or full-text search over ciphertext.**
  Order-preserving and order-revealing encryption are explicitly forbidden by the
  spec; the attack literature is unambiguous.
- **Not a replacement for storage-layer encryption.** Keep TDE underneath.
- **Not a hosted service, proxy, or vault.**
- **Not a GDPR Article 17 erasure guarantee.** No regulator has endorsed key
  destruction as standalone erasure.
