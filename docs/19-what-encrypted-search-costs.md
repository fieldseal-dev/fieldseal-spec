# What Encrypted Search Costs — a plain-language guide

**Date:** 2026-08-31 · **Status:** Draft 1 · **Purpose:** what it costs to *search* an encrypted field, written for the people who decide whether to adopt this specification rather than for the people implementing it. No cryptography background assumed, and no need to read the specification first.

Everything here is stated more precisely, with more caveats, in [`docs/11-core-typescript.md`](11-core-typescript.md) §2 and in the [`docs/07-implementation-plan.md`](07-implementation-plan.md) §7 log entry dated 2026-08-31. **Where this document and those disagree, they are right and this one is wrong** — this is a summary, and summaries lose things.

One thing to know before the numbers: this project is pre-alpha, the specification has not been independently reviewed, and nothing here is an invitation to adopt it yet. This document exists so that when the invitation comes, the cost is not a surprise.

---

## 1. The problem, in one paragraph

If you encrypt someone's email address before storing it, you can no longer search for it. That is not a bug — a good encryption scheme stores the same email as a *different* value every time, precisely so that nobody can tell which two rows hold the same address. But it means `WHERE email = ...` finds nothing, ever.

Fieldseal's answer is a **blind index**: a short fingerprint of the value, stored in its own column, that you *can* match on. Look up the fingerprint, get a handful of candidate rows, decrypt them, and keep the ones that really match. (The decrypt-and-check step is not optional — the specification requires it, because fingerprints are deliberately allowed to collide. See §7.5 of the specification.)

Making that fingerprint costs something. This document is about how much.

---

## 2. Why the fingerprint is slow on purpose

For data that is hard to guess, the fingerprint is cheap — microseconds.

For data that is *easy* to guess, the specification requires a deliberately slow calculation called **Argon2id**. The reason is straightforward: there are only so many possible email addresses, phone numbers, or dates of birth. If making a fingerprint were fast, anyone who stole your database could make fingerprints of every plausible value and match them against your columns, and the encryption would have bought you nothing. Slowness is what makes that attack impractical.

So the slowness is the security feature. **Nobody is trying to optimise it away**, and nobody can. The only real question is *who has to wait while it happens* — and that turned out to have a surprising answer.

Which fields get the slow treatment is a **security** decision the specification makes for you based on the kind of data, not a performance dial you can turn. That matters for §7 below.

---

## 3. What was measured, and on what

Two machines, because one machine is an anecdote:

| | |
|---|---|
| **Machine A** | Windows desktop, AMD Zen 4, Node 24.16 |
| **Machine B** | Apple Silicon Mac, arm64, Node 24.7 |

Both ran the same benchmark at the cheapest settings the specification permits — the *best* case, not a pessimistic one. The measurement code is in the repository (`core/typescript/tests/bench/argon2-eventloop.ts` and `adapters/prisma/tests/bench/argon2-request-path.ts`) and is not part of the test suite or CI; it is evidence for a decision, run by hand.

**One fingerprint takes about 44 ms on Machine A and about 62–70 ms on Machine B.** A twentieth of a second. On its own, unremarkable — which is exactly why the next section is the interesting part.

---

## 4. Finding one: the server stops

This part is specific to Node.js, and it is the reason the benchmark was run at all.

A Node server handles every user through a **single lane**. It is extremely good at juggling thousands of simultaneous requests, but only because each request hands the lane back the moment it starts waiting on something. Anything that *holds* the lane holds everybody.

A slow fingerprint holds the lane. We counted how many times the server got to do anything at all while 20 fingerprints were calculated:

| | how many times the server could act |
|---|---|
| doing nothing at all | ~832,000 times (Machine A) |
| **calculating 20 fingerprints** | **once** |

Not "slower". **Once.** For roughly nine-tenths of a second on Machine A, and 1.2 seconds on Machine B, the server could not answer anybody.

That result was **identical on both machines** — one turn, both times. It is not a quirk of a laptop or an operating system; it follows from how Node is built.

---

## 5. Finding two: the bystander pays

This is the finding that should drive decisions.

We loaded a page that has **nothing to do with encrypted data** — a query against a table with no encrypted column in it — while other users searched an encrypted field. Machine A, through the real Prisma database adapter:

| people searching encrypted fields | how long the *unrelated* page took |
|---|---|
| nobody | 0.8 ms |
| 4 | 187 ms |
| 8 | **352 ms** |

A user who never touches encrypted data waits a third of a second because somebody else searched an encrypted field. **They are paying for a feature they are not using.**

This is the part that does not show up in a naive benchmark. If you measure only "how long does an encrypted search take", you get 44 ms and conclude everything is fine. The cost lands on the requests you were not measuring.

---

## 6. The fix, and its catch

Node can hand slow work to a small pool of **background workers** instead of running it in the single lane. That works, and the project has decided to build it.

But it is not free, and it is not uniform:

**It moves the cost, it does not remove it.** The worker pool has **four slots by default**, and it is shared with ordinary work like reading files. Four fingerprints at once fill it completely. We measured an unrelated file read — nothing to do with encryption — while fingerprints ran:

| file read, four fingerprints running | Machine A | Machine B |
|---|---|---|
| normally | 0.28 ms | 0.28 ms |
| under load | **67 ms** | **402 ms** |

So an implementation that quietly moves the work to the background workers, and says nothing, has starved every file read in the process. That is why the decision recorded in `docs/11` §2 is "build it **and** document the pool-sizing obligation", not "build it and call the problem solved". Enlarging the pool is the right lever; **this benchmark has not yet measured how much it helps**, and until it does, no number should be quoted for it.

**How well it recovers depends on your hardware.** On Machine A the server stayed responsive — 97% of its idle capacity. On Machine B, 50%; and under eight simultaneous searches it still froze for half a second. The background-worker version is better than the blocking version on both machines, always. But "it frees the server" was true on one machine and not the other, so what we can honestly say is narrower: *it turns a total stall into a partial one, and how partial depends on the machine.*

---

## 7. What this means for you

**If you are implementing this specification.** You owe an asynchronous version of the fingerprint function, and it is not a small addition. The specification requires proving it produces byte-for-byte identical output — the entire test suite run a second time through it — plus a specific test that nobody has faked it by calling the slow version underneath and waiting. You also owe your users documentation of the worker-pool setting. See spec §11.1 and [`docs/08`](08-test-vector-spec.md) §5.

**If you are a developer building on it.** Two practical rules.

1. You do not get to pick the fast fingerprint to make your app quicker. Which method a field uses is a security decision driven by how guessable the data is. Trying to "optimise" a slow field to a fast one is choosing to weaken it.
2. Where a field genuinely needs the slow method, design around it. Search on something else where you can. Do not put an encrypted-field lookup in a page that loads for every visitor, or in a health check, or in a loop.

**If you are an organisation deciding whether to adopt.** Treat this as a capacity fact rather than a tuning problem. Roughly **14–23 encrypted searches per second per processor core** is the ceiling — that is arithmetic from the per-fingerprint cost, and the range is hardware, not implementation quality. No amount of engineering moves it, because the cost *is* the security.

Two things make that ceiling much less alarming than it sounds:

- It applies **only to the fields you choose to make searchable**. Encrypting a field you never search costs essentially nothing on the read path.
- It applies **per search term**, not per row. Searching a million-row table costs one fingerprint, not a million.

The number to take into a capacity plan is therefore *how many encrypted-field searches per second does this application actually do*, which for most applications is a much smaller number than total traffic.

---

## 8. What is structural and what is just your hardware

Worth separating, because they age differently:

| Structural — will be true on your machine too | Hardware-dependent — measure your own |
|---|---|
| A blocking fingerprint stops a Node server completely | How long one fingerprint takes (44 ms vs 62–70 ms here) |
| The cost lands on unrelated requests, not just encrypted ones | How badly the background-worker version still stalls |
| The background-worker pool is shared and small by default | How much worse it gets as concurrency rises |

The left column is the reason this document exists. The right column is why it gives ranges instead of single numbers.

---

## 9. What this document does not claim

- **Two machines is two machines.** Both were developer hardware, not servers, and neither was a production workload. Repeat runs on the *same* Mac varied by about 10% (69.8 ms and 62.5 ms), so read every figure as approximate.
- **The asynchronous version is decided, not built.** As of this document's date it is a recorded decision with evidence behind it; the code is the next step.
- **This measures Node.js.** The same specification implemented in Java, Go, or .NET does not have the single-lane problem in this form. The *cost per fingerprint* is universal; the *stops the whole server* consequence is a Node consequence.
- **The first version of this benchmark was wrong**, in a way worth knowing about if you plan to measure this yourself. Section 11 has the details.

---

## 10. The other costs, in one place

Search cost is what was measured here. It is not the only thing adopting this specification costs, and it would be misleading to present it alone. The others are already documented and are not summarised here beyond a pointer:

| Cost | Where it is stated |
|---|---|
| **Storage.** A 9-byte value becomes ~120 bytes stored, or ~160 in base64 — roughly 13× | spec §3.3 |
| **Your key service becomes a hard dependency on every read** touching an encrypted field. If it is down, those queries fail | spec §8.1 |
| **Database query logs become sensitive artifacts** and need the same handling as the data | spec §2.3 |
| **No protection against an attacker inside your application process** — that is where the keys are | spec §2 |

The last one is worth reading twice. This specification protects data at rest: stolen backups, stolen disks, a compromised database server. It does not protect you from an attacker who has your application.

---

## 11. If you want to check any of this

Everything above is reproducible:

```
cd core/typescript   && npm ci && npm run bench:argon2   # the mechanism
cd adapters/prisma   && npm ci && npm run bench:argon2   # the request-path effect (needs a database)
```

Each prints a JSON block with the machine it ran on, so results from two machines can be compared directly.

Two notes for anyone measuring this themselves, both learned the hard way:

**The obvious instrument does not work.** Node ships `perf_hooks.monitorEventLoopDelay`, which is the natural tool for "is my server responsive". It reported **zero delay** for the full stalls above — 893 ms on one machine, 1219 ms on the other. It is not broken and it is not a Windows problem: it works by sampling, and a stall is precisely the period during which it takes no samples. It cannot report what it was not awake for. Anyone trusting it here would conclude the blocking version is fine.

**Measure at a fixed rate, not one-at-a-time.** The first version of the worker-pool probe waited for each file read to finish before starting the next. Under load that means it issued fewer reads exactly when they were slowest, so the worst case was scored from two samples and the numbers came out far too kind — and on Machine B they came out *backwards*, appearing to show no problem where the problem was worst. This is a well-known trap called coordinated omission. The fixed probe issues requests on a clock regardless of whether earlier ones have returned; the corrected numbers are the ones in §6, and they are worse than the originals.

Both mistakes produced plausible, publishable, wrong answers. That is the general lesson, and it is not specific to this project.
