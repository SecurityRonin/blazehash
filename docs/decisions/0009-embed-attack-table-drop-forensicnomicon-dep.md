# 9. Embed the ATT&CK prefix table locally; carry no compile-time dependency on forensicnomicon

Date: 2026-07-24
Status: Accepted

## Context

blazehash's YARA scanning resolves a matched rule-name prefix to a MITRE ATT&CK
technique (`src/attack.rs`, `lookup_attack`). The canonical prefix → technique
table also lives in the fleet KNOWLEDGE leaf `forensicnomicon::mitre`, so the
default fleet instinct (prefer-our-own, single source of truth) is to depend on
forensicnomicon and delegate.

That is what was tried first. Commit `5c60cc3` made forensicnomicon a mandatory
dependency and `e0449dc` rewrote `blazehash::attack` as a thin delegation to
`forensicnomicon::attack`. It was then **reversed**: commit `cf58440`
("embed ~500-entry ATTACK_PREFIXES table in blazehash::attack") moved the table
back into blazehash, and later `2988091` pruned it. The current `src/attack.rs`
header states the resulting posture: "The same table lives in
`forensicnomicon::mitre`; it is duplicated here so blazehash has no compile-time
dependency on forensicnomicon."

## Decision

1. **The ATT&CK prefix table is embedded in `src/attack.rs`** (the
   `ATTACK_PREFIXES` table, ~500 entries), and `blazehash` declares **no**
   dependency on `forensicnomicon` (absent from `Cargo.toml`; the only
   forensicnomicon mention in `src/` is the explanatory comment).
2. **The table is a deliberate, documented duplicate**, kept in sync by hand with
   the forensicnomicon source of truth, traded against a compile-time dependency
   edge from the app onto the KNOWLEDGE leaf.

## Consequences

- The app's dependency graph and build stay decoupled from forensicnomicon's
  release cadence; the ATT&CK lookup has no cross-crate version coupling.
- The cost is a duplicated table that must be reconciled against
  `forensicnomicon::mitre` when either changes — an accepted maintenance burden
  documented in the source.
- *Rationale partially reconstructed.* The stated benefit ("no compile-time
  dependency on forensicnomicon") is recorded in `src/attack.rs`; the deeper
  motive for preferring duplication over the dependency edge — after having
  adopted it — is not spelled out in the commit history and is not recovered here.
