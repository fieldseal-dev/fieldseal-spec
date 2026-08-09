---
title: "Fieldseal"
---

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
