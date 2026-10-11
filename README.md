# PolicyComplianceVerdict

PolicyComplianceVerdict dies without GenLayer: no EVM contract can read a Notion governance document and a Solidity source file on-chain simultaneously, reason about whether the code satisfies natural language policy rules, and produce a multi-validator consensus compliance report — only GenLayer's AI validators can do this during consensus.

## Problem

DAOs and protocols publish security policies and governance rules as natural language: Notion pages, GitHub READMEs, and forum posts. Typical rules say "all contracts must have a 48-hour timelock", "no admin keys", "must be audited before deploy", or "no upgradeable proxy without a multisig". Checking a proposed contract against every rule by hand is slow, easy to miss, and depends on reviewers who may not read the same sentence the same way.

## Solution

PolicyComplianceVerdict stores a compliance request, then reads the contract source URL and the policy URL on-chain. Validators identify each checkable rule and compare it to the source. The result is a permanent record: `COMPLIANT`, `NON_COMPLIANT`, or `NEEDS_REVIEW`, plus the specific violations or concerns.

Remove `web.render` and the LLM and this contract is only a registry of whatever status the caller types in. The AI policy analysis is the product.

## How it works

1. **Submit.** Anyone calls `submit_check(contract_name, contract_url, policy_name, policy_url)`. The record is stored as `PENDING` and the method returns a `check_id`.
2. **Run the check.** Anyone calls `run_check(check_id)`. Validators fetch both pages and judge the source against the policy.
3. **Read the verdict.** `get_verdict(check_id)` returns the decision, confidence, reasoning, violations, and rule counts. `get_check(check_id)` returns the full record.
4. **List.** `list_checks(verdict_filter)` returns matching records. Pass `""` for every check.

The contract owner can call `invalidate_check(check_id)` on a `PENDING` record. That sets status to `UNCHECKABLE` and reasoning to `Invalidated by admin`.

## Verdict types

| Verdict | Meaning |
| --- | --- |
| `COMPLIANT` | Every identifiable rule is satisfied. No violations. Status becomes `CHECKED`. |
| `NON_COMPLIANT` | At least one rule is clearly violated. Status becomes `CHECKED`. |
| `NEEDS_REVIEW` | No clear violation, but at least one rule cannot be proven from source alone (audit, multisig setup, deploy process). Status becomes `CHECKED`. |
| `UNCHECKABLE` | A page could not be read, the model output could not be parsed, or the verdict string was not one of the four labels. Status becomes `UNCHECKABLE`. |

`get_verdict` reverts with `Not yet checked` while status is `PENDING`.

## Violations structure

`violations` is a JSON array string. Each object has:

- `rule`: short description of the policy rule
- `status`: `VIOLATED` or `NEEDS_REVIEW`
- `detail`: what in the contract triggered the finding

An empty check stores `[]`.

## Consistency rule

`NON_COMPLIANT` is stored only when the violations list contains at least one entry with `status` `VIOLATED`. If the model returns `NON_COMPLIANT` with an empty list, a non-list, or only `NEEDS_REVIEW` entries, the verdict is downgraded to `NEEDS_REVIEW` before it is returned to consensus.

## Consensus design

`run_check` runs inside `gl.vm.run_nondet_unsafe`. Each URL is fetched in its own try/except. A failed fetch becomes text in the prompt. `leader_fn` always returns a dict.

Validators do not accept a result just because the JSON is well formed. They re-run the fetch and the audit, then apply three checks:

- **Verdict exact match.** `COMPLIANT`, `NON_COMPLIANT`, `NEEDS_REVIEW`, and `UNCHECKABLE` must agree exactly. A validator that returns `NEEDS_REVIEW` rejects a leader result of `NON_COMPLIANT`.
- **NON_COMPLIANT violations presence.** When the verdict is `NON_COMPLIANT`, both the leader payload and the validator's own result must contain at least one violation. Agreeing on the string `NON_COMPLIANT` is not enough. An empty list on either side rejects the leader.
- **Confidence bands.** Confidence is not compared as an exact integer. The bands are 0-34, 35-79, and 80-100. Both sides must land in the same band. Reasoning text is not compared.

## Use cases

- DAO deploy gate: block a proposal when the verdict is `NON_COMPLIANT`.
- Protocol upgrade review: check a new implementation against the published security policy.
- Security policy enforcement: keep a permanent record of which rules passed.
- Governance automation: let a later contract read `get_verdict` instead of waiting on a manual reviewer.

## Supported policy sources

Any public URL the validators can render, including:

- Notion pages
- GitHub READMEs and source files
- Governance forum posts
- Any other public document URL

The contract source URL can be a GitHub file, an Etherscan source page, or a raw paste. The two URLs must be different.

## Edge cases handled

- A failed fetch on the contract URL, the policy URL, or both is caught per URL and written into the prompt. The call still finishes.
- An empty or very short page is replaced with `(empty or too short to analyze)`.
- Malformed model JSON falls back to `UNCHECKABLE` with confidence 0 and violations `[]`.
- An unknown verdict string is normalized to `UNCHECKABLE`.
- A `violations` value that is not a list is stored as `[]`. If the verdict was `NON_COMPLIANT`, it is downgraded to `NEEDS_REVIEW`.
- `NON_COMPLIANT` without a `VIOLATED` entry is downgraded to `NEEDS_REVIEW`.
- Only the owner can invalidate a `PENDING` check. A `CHECKED` check cannot be invalidated or run again.

## Deploy on GenLayer Studio (studionet)

1. Open [GenLayer Studio](https://studio.genlayer.com) and create an Intelligent Contract.
2. Paste `contracts/policy_compliance_verdict.py`. The file header must stay the first lines (`v0.2.16` and the `py-genlayer` dependency). Do not add a frontend.
3. Select network **studionet**.
4. Deploy. The constructor takes no arguments and sets `owner` to the deployer.
5. Call `submit_check(contract_name, contract_url, policy_name, policy_url)`.
6. Call `run_check(check_id)`. Then read `get_verdict(check_id)` or `list_checks("")`.

## Run tests

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements-dev.txt
pytest tests/test_policy_compliance_verdict.py -v
```

## Deployment

- **CONTRACT_ADDRESS:** `0x748765937c548119Ad50eE525112Eda1687f203F`
- **NETWORK:** studionet
- **Deploy transaction:** `0xccf37ee92ce147522ea5b7711cff039edbb3385881d9b2437f44956cb8c9329a` (FINALIZED, GenVM result SUCCESS, consensus Accepted)
- **Explorer:** https://explorer-studio.genlayer.com/address/0x748765937c548119Ad50eE525112Eda1687f203F

A read-only `get_count()` call against this address returned `0`. The account has the deploy transaction only, so no compliance check is stored on-chain yet. The worked example below is the expected result from the local test suite (`test_compliant_verdict`), not a receipt from studionet.

### Worked example (expected output, not a live studionet verdict)

Input to `submit_check`:

```text
contract_name:  Treasury v2
contract_url:   https://github.com/dao/treasury/blob/main/Treasury.sol
policy_name:    SpaceDAO Security Policy
policy_url:     https://notion.so/spacedao/security-policy
```

The contract source sets `TIMELOCK_DELAY` to 48 hours and gates calls with a multisig. The policy requires a 48-hour timelock, no single admin key, DAO-governed upgrades, and an audit before mainnet.

Expected `get_verdict` after `run_check` returns `"1"`:

```json
{
  "check_id": "1",
  "contract_name": "Treasury v2",
  "policy_name": "SpaceDAO Security Policy",
  "verdict": "COMPLIANT",
  "confidence": 85,
  "reasoning": "Contract implements 48h timelock and multisig. Rule 4 needs human confirmation of audit.",
  "violations": "[]",
  "rules_checked": 4,
  "rules_passed": 3,
  "status": "CHECKED"
}
```

This is the outcome the local validator accepts when both sides return `COMPLIANT` and confidence stays in the 80-100 band. A validator that returns `NON_COMPLIANT` or `NEEDS_REVIEW` for the same pages rejects this result, even when both payloads are valid JSON.
