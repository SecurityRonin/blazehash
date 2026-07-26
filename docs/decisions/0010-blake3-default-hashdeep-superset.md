# 10. BLAKE3 is the default algorithm, while remaining a strict hashdeep superset

Date: 2026-07-27
Status: Accepted

## Context

blazehash's whole positioning is a *drop-in superset of hashdeep*: every hashdeep
flag and output format works unchanged, so an examiner's existing scripts keep
running (README "What's New vs hashdeep"; PRD "Scope"). hashdeep, however, computes
MD5 + SHA-256 when no algorithm is named — the general-purpose cryptographic hashes
of its era. Defaulting to those makes blazehash's headline advantage (BLAKE3 at
~1,640 MB/s, README "Performance") invisible to the most common invocation, where a
user simply points the tool at a tree and takes the default.

The tension: a superset is expected to behave like the original, but the original's
default no longer reflects the fastest, most modern primitive the tool ships. Two
things pull in opposite directions — compatibility (keep hashdeep's default) and the
product's reason to exist (lead with BLAKE3).

## Decision

1. **The zero-argument default algorithm is BLAKE3.** `-c/--compute` defaults to
   `"blake3"` (`src/cli.rs:18`), and the fall-through when no algorithm resolves is
   `vec![Algorithm::Blake3]` (`src/cli.rs:488`). A plain `blazehash <path>` produces
   BLAKE3 digests.
2. **Every hashdeep algorithm remains selectable, unchanged.** `-c` takes a
   comma-separated list parsed by `parse_algorithms` into the `Algorithm` enum
   (`core/src/algorithm.rs`), which includes MD5, the SHA-1/2/3 families, Tiger,
   Whirlpool, and the rest — so `blazehash -c md5,sha256` reproduces hashdeep's
   default behaviour exactly. Compatibility is preserved by *keeping the flags*, not
   by keeping the default.
3. **The algorithm set lives in the lean engine.** `Algorithm`, its parsing, and
   dispatch are `blazehash-core` ([ADR 0001](0001-lean-core-full-app-split.md)); the
   app selects among them. The default is an application/CLI decision, not baked into
   the engine.
4. **Correctness rests on audited upstream crates.** BLAKE3 via the `blake3` crate,
   the rest via RustCrypto; blazehash writes no hand-rolled hash math (PRD "Non-Goals").

## Consequences

- The common path showcases the differentiator: the fastest invocation is also the
  one a new user runs first, matching the README's "BLAKE3 by default" tagline.
- A user migrating a hashdeep workflow that relied on the *implicit* MD5+SHA-256
  default must name those algorithms explicitly (`-c md5,sha256`). This is the one
  visible behavioural divergence from hashdeep, and it is deliberate — the flags
  make it a one-token fix, so the superset promise holds for anything that named its
  algorithms (the norm in forensic scripting).
- Because the algorithms are all present, changing the default is a low-risk,
  reversible CLI choice, not an architectural commitment.
