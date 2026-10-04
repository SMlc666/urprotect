# Evaluator Implementation Plan

## 1. Add manifests and schemas

- Add append-only compatibility corpus and Scheme-A manifest with protocol/tool/oracle/budget hashes.
- Add JSON validators and unit identity checks.
- Add baseline reference lock and content-addressed snapshot writer.

## 2. Add evaluator runner

- Validate all manifest and baseline digests before execution.
- Capture runner/runtime/isolation/tool facts.
- Execute existing auxiliary evidence without counting it as strict compatibility.
- Emit baseline-zero and baseline-not-calibrated states when appropriate.
- Retain all rows, failures, unavailable capabilities, raw logs and hashes.

## 3. Add compatibility gate

- Validate six stage records and source/artifact/native-image hashes.
- Enforce fixed/growth views, distinct identity, no duplicate variants, first-failure classification, and exact integer 100x rule.
- Add schema and anti-gaming tests.

## 4. Add Scheme-A gate

- Validate six families, three replicas, equal budgets/tools/oracles, finite baseline, cost/censoring rules, and conjunction.
- Add objective result schema and raw evidence manifests.
- Keep missing attack backend as explicit environment-unavailable/baseline-not-calibrated.

## 5. CI integration

- Add evaluator job after build/native runtime provisioning.
- Upload evaluator artifacts with `if: always()`.
- Keep existing jobs unchanged and add evaluator status as an independent required gate.
- Produce `analysis-input.json` for the next analysis agent.

## Validation

```sh
python3 scripts/validate-evaluator-manifests.py ...
python3 tests/test_evaluator_schema.py
python3 tests/test_evaluator_antigaming.py
python3 tests/test_compatibility_unit_rules.py
python3 tests/test_scheme_a_gate.py
./scripts/run-independent-evaluator.sh --tier pr
python3 scripts/check-independent-evaluator.py .artifacts/evaluator/pr
```

## Rollback

Disable only the new evaluator CI job and runner invocation. Retain manifests, baseline artifacts, reports, and existing CI evidence. Never overwrite the immutable baseline.
