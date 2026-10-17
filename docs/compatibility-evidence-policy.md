# Compatibility evidence policy

UrProtect does **not** claim a quantified reverse-engineering resistance factor
from its automated CI. The former Scheme-A synthetic attack-scoring system has
been retired: its SHA-256 workloads and deterministic "attack-success" records
were not measurements of real attacker effort.

## Required CI evidence

- Four native ARM64 shards collectively run the registered 100-unit strict corpus and emit six-stage,
  hash-bound execution evidence for every required and applicable unit.
- The independent compatibility gate first validates four exact shard summaries and **rechecks all 100 product trees** with
  `check-rehydration-evidence.py` and refuses missing, symlinked, invalid or
  incomplete product evidence. The corpus execution summary is checked but
  is never sufficient on its own.
- Existing real upstream software samples, Native Runtime platform matrices,
  TLS/HostContext checks, fixtures, fuzzing and behavioral oracles remain
  separate required checks. Nothing about a completed compatibility corpus
  establishes general compatibility with all ELF binaries.
- The compatibility verifier emits a JSON report whose
  `securityStrengthClaim` is always `null`. It never declares a protection
  strength factor or success of an unexecuted attack.

Historical benchmark notes can be recovered through Git history; they are not
live CI specifications and must not be advertised as evidence that UrProtect
makes reverse engineering 100 times harder.

## Reviewer checklist

1. Run `python3 -m unittest discover -s tests -p test_strict_product_corpus.py -v`.
2. Compare the product corpus manifest identities against the independent report.
3. Confirm CI fails on missing product units, failed stage or changed hashes.
4. Confirm real sample, bionic, musl and Runtime Matrix jobs remain mandatory
   for PR validation, and that the independent job retains its required name.
5. Do not restore a strength claim without a separate, empirically defensible
   and reviewed testing protocol.
