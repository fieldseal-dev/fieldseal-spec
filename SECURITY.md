# Security Policy

## Current status

**This project is pre-alpha. The specification has not been independently reviewed and no implementation exists. Do not use it in production.**

An independent security review of the specification and at least one implementation is a **release gate for v1.0**, not a nice-to-have. The most relevant precedent: 37signals had a professional audit of their Rails encryption work and it found a deterministic-encryption flaw requiring emergency remediation days before launch, at a company with unusual engineering depth.

## Reporting

Do not open a public issue for a suspected vulnerability in the specification or in any implementation.

Report privately to: **[SECURITY CONTACT TO BE ADDED]**

Include: the affected document section or implementation, the conditions required, and the impact. A proof of concept is welcome but not required — a clear description of a design flaw in the specification is at least as valuable as working exploit code.

Expect an acknowledgement within 72 hours and an assessment within 14 days.

## Scope

**In scope:**

- Flaws in the envelope format, key hierarchy, key derivation, or blind-index construction
- Attacks that recover plaintext, key material, or index keys within the threat model of spec §2.1
- Cross-implementation divergence that causes a ciphertext to decrypt differently, or to decrypt at all when it should not
- Adapter paths that silently write plaintext or silently return wrong results
- Anything that defeats the suite allow-list, the header authentication, or the key commitment

**Out of scope — these are documented limitations, not vulnerabilities** (spec §2.2):

- Compromise of the application process. The keys are in that process.
- Inference from query logs, slow-query logs, the DBMS buffer cache, or replication logs. These are documented as in-scope *sensitive artifacts* that the deployment must protect, not as something the design defends against.
- Frequency analysis against a blind index whose column was explicitly configured past the default-deny cardinality gate with a logged override.
- Availability loss caused by key-service outage. Documented as a hard dependency.
- Data loss caused by key destruction. Documented as unrecoverable.

If you believe something in the "out of scope" list should be in scope, that is itself a specification issue worth raising — publicly is fine.

## Disclosure

Coordinated disclosure. A fix, or a documented mitigation where no fix is possible, before public detail. Credit given unless you prefer otherwise.

Specification flaws will be disclosed publicly in full even where they cannot be fixed compatibly, because implementers need to know. Where a flaw requires a format change, the retirement mechanism is the suite allow-list plus a re-encryption sweep (spec §4.3, §5.9).
