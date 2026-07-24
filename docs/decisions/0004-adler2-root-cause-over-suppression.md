# 4. Resolve advisories at the root cause — migrate `adler` → `adler2`, not ignore-list them

Date: 2026-07-24
Status: Accepted

## Context

When a gate flags a problem, the fleet default (`ronin-issen/CLAUDE.md`,
"Root-Cause Over Suppression — the adler2 law") is to eliminate the cause, not add
it to an ignore list. The canonical exemplar is `RUSTSEC-2025-0056` on the
unmaintained `adler` crate: the lazy move is a `deny.toml` ignore; the right move
is migrating to `adler2`, the maintained drop-in fork, and verifying the output is
byte-identical so the fix is provably behavior-preserving.

blazehash pulled `adler` transitively and, at one point, carried a set of advisory
ignores that existed only to paper over broken/unmaintained transitive crates.

## Decision

1. **Depend on `adler2` directly.** `[workspace.dependencies]` declares
   `adler2 = "2"`; both crates use it. Commit `0109e72` ("migrate adler->adler2 +
   indicatif 0.17->0.18 (resolve 3 advisories)") made the swap, and `CHANGELOG`
   0.2.6 records dropping the `adler`, `instant`, `number_prefix`, `sled`, `sqlx`,
   and `indicatif` advisory ignores that only existed to cover the old trees.
2. **Bump the parent to pull the fix, not ignore the leaf.** The same change
   raised `indicatif 0.17 → 0.18` (which pulls the patched `console 0.16` and drops
   `number_prefix`) and later updated `crossbeam-epoch 0.9.18 → 0.9.20` via a
   lockfile bump for `RUSTSEC-2026-0204`.
3. **A remaining ignore is annotated with why the true fix is unavailable.** The
   `deny.toml` `[advisories] ignore` entries that survive are all *transitive*
   through `yara-x`/`wgpu`/`bloomfilter` with no drop-in upstream fix, each
   documented inline with the crate, the reason, and the removal condition (e.g.
   the wasmtime advisories resolve "when yara-x upgrades its wasmtime dependency").

## Consequences

- The default-feature graph audits clean on the advisories blazehash can actually
  fix; the residual ignores are narrow, transitive, and each names its removal
  trigger rather than being a blanket silence.
- `CHANGELOG` 0.2.6 is the visible record that suppression entries were *removed*,
  not accumulated — the direction the adler2 law requires.
