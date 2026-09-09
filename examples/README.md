# examples

End-to-end demonstration applications. One exists:

- **[`patient-directory/`](patient-directory/)** — one Postgres table with a
  Django frontend and a Prisma frontend over it, and a scripted seven-act
  scenario asserting that a row written by either stack reads, searches and
  matches from the other. This is PRD Phase 1's WS-G deliverable (`docs/07`
  §2), and its design is [`docs/20-demo-patient-directory.md`](../docs/20-demo-patient-directory.md).

**These are demonstrations, not starter templates.** Each one exists to make a
claim checkable by a person rather than only by CI. Nothing under this
directory is frozen, the suite identifiers are provisional (spec §4.8), Gate 0b
is open, and the project does not invite adoption. Key material in an example
comes from `vectors/keys/test-keys.json` by reference, so the
public-test-material banner in that file travels with anything copied out.

**An example is not an adapter.** AD-1 (spec §11.3) binds adapters to contain
no cryptographic code, and CI asserts it with a grep over `adapters/*/src`.
That grep deliberately does not extend here: an application is not an adapter,
and extending a normative rule to a new class of thing is a decision that gets
an issue first.
