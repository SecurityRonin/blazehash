# 5. Relicense MIT → Apache-2.0 (fleet standard, explicit patent grant)

Date: 2026-07-24
Status: Accepted

## Context

blazehash originally shipped under MIT. The fleet standardized on **Apache-2.0**
for its explicit patent grant (`ronin-issen/CLAUDE.md`, README Standard: "the
fleet standardized on Apache-2.0 for its explicit patent grant — migrate any
residual MIT repos"). A forensic tool distributed to third parties benefits from
the patent-peace and defensive-termination clauses MIT lacks.

## Decision

1. **License is Apache-2.0.** Both `Cargo.toml` and `core/Cargo.toml` declare
   `license = "Apache-2.0"`; the repo ships the full verbatim Apache-2.0 text in
   `LICENSE`. Commit `d3a03b6` ("relicense MIT → Apache-2.0 (fleet standard)")
   performed the switch and `9f683bb` ("use verbatim Apache-2.0 license text")
   corrected the text to the canonical form.
2. **No `## License` section in the README.** The Apache-2.0 badge links to
   `LICENSE`, which is the single source of truth; per the fleet README standard
   the licence is not restated in prose.

## Consequences

- Every published crate and distributed binary carries the Apache-2.0 patent
  grant, consistent with the rest of the fleet.
- The `deny.toml` `[licenses] allow` list permits Apache-2.0 (and the permissive
  set the dependency graph needs, including `BSL-1.0` for xxhash and the
  `Apache-2.0 WITH LLVM-exception` used by the yara-x/wasmtime toolchain crates).
