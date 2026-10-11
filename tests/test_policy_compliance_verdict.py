import json
import pytest


def _payload(verdict, confidence, reasoning, violations, rules_checked, rules_passed):
    return json.dumps({
        "verdict": verdict,
        "confidence": confidence,
        "reasoning": reasoning,
        "violations": violations,
        "rules_checked": rules_checked,
        "rules_passed": rules_passed,
    })


def _raise(_url=None):
    raise RuntimeError("source unreachable")


def _submit(contract, direct_vm, caller, name, contract_url, policy_name, policy_url):
    with direct_vm.prank(caller):
        return contract.submit_check(name, contract_url, policy_name, policy_url)


# 1. Happy path — COMPLIANT
def test_compliant_verdict(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/policy_compliance_verdict.py")

    with direct_vm.prank(direct_alice):
        check_id = contract.submit_check(
            "Treasury v2",
            "https://github.com/dao/treasury/blob/main/Treasury.sol",
            "SpaceDAO Security Policy",
            "https://notion.so/spacedao/security-policy",
        )
    assert check_id == "1"
    assert contract.get_count() == 1

    direct_vm.mock_web(
        r".*github.*treasury.*",
        "contract Treasury {\n"
        "  uint256 public constant TIMELOCK_DELAY = 48 hours;\n"
        "  address public multisig;\n"
        "  modifier onlyMultisig() { require(msg.sender == multisig); _; }\n"
        "  // No admin keys. Upgrades require DAO vote.\n"
        "}",
    )
    direct_vm.mock_web(
        r".*notion.*security.*",
        "SpaceDAO Security Policy v1.2\n"
        "Rule 1: All contracts must have a minimum 48-hour timelock.\n"
        "Rule 2: No single admin keys allowed; multisig required.\n"
        "Rule 3: No upgradeable proxies without DAO governance vote.\n"
        "Rule 4: Contracts must be audited before mainnet deploy.",
    )
    direct_vm.mock_llm(
        r".*policy compliance auditor.*",
        _payload(
            "COMPLIANT",
            85,
            "Contract implements 48h timelock and multisig. "
            "Rule 4 needs human confirmation of audit.",
            [],
            4,
            3,
        ),
    )

    contract.run_check(check_id)

    result = json.loads(contract.get_verdict(check_id))
    assert result["verdict"] == "COMPLIANT"
    assert result["confidence"] == 85
    assert result["rules_checked"] == 4
    assert json.loads(result["violations"]) == []

    full = json.loads(contract.get_check(check_id))
    assert full["status"] == "CHECKED"


# 2. NON_COMPLIANT — clear violations found
def test_non_compliant_with_violations(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/policy_compliance_verdict.py")
    check_id = _submit(
        contract,
        direct_vm,
        direct_alice,
        "Admin Vault",
        "https://github.com/dao/vault/blob/main/Vault.sol",
        "SpaceDAO Security Policy",
        "https://notion.so/spacedao/security-policy",
    )

    direct_vm.mock_web(
        r".*github.*vault.*",
        "contract Vault {\n"
        "  address public owner;\n"
        "  function withdraw() external { require(msg.sender == owner); }\n"
        "  // No timelock. Single admin key controls funds.\n"
        "}",
    )
    direct_vm.mock_web(
        r".*notion.*security.*",
        "Rule 1: All contracts must have a minimum 48-hour timelock.\n"
        "Rule 2: No single admin keys allowed; multisig required.",
    )
    violations = [
        {
            "rule": "48-hour timelock required",
            "status": "VIOLATED",
            "detail": "Vault.sol has no timelock delay before withdrawals.",
        },
        {
            "rule": "No single admin keys",
            "status": "VIOLATED",
            "detail": "withdraw() is gated by a single owner address.",
        },
    ]
    direct_vm.mock_llm(
        r".*policy compliance auditor.*",
        _payload(
            "NON_COMPLIANT",
            90,
            "The vault has an owner-only withdraw and no timelock.",
            violations,
            2,
            0,
        ),
    )

    contract.run_check(check_id)

    result = json.loads(contract.get_verdict(check_id))
    assert result["verdict"] == "NON_COMPLIANT"
    parsed = json.loads(result["violations"])
    assert len(parsed) == 2
    assert parsed[0]["status"] == "VIOLATED"
    assert json.loads(contract.get_check(check_id))["status"] == "CHECKED"


# 3. NEEDS_REVIEW — no violations but rules unverifiable from source
def test_needs_review_unverifiable_rules(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/policy_compliance_verdict.py")
    check_id = _submit(
        contract,
        direct_vm,
        direct_alice,
        "Treasury v2",
        "https://github.com/dao/treasury/blob/main/Treasury.sol",
        "Audit Policy",
        "https://forum.spacedao.org/policy",
    )

    direct_vm.mock_web(
        r".*github.*treasury.*",
        "contract Treasury {\n"
        "  uint256 public constant TIMELOCK_DELAY = 48 hours;\n"
        "  address public multisig;\n"
        "}",
    )
    direct_vm.mock_web(
        r".*forum.*policy.*",
        "Rule 1: Contracts must be audited by an independent firm before mainnet deploy.\n"
        "The audit report must be linked from the governance forum.",
    )
    concerns = [
        {
            "rule": "Independent audit before deploy",
            "status": "NEEDS_REVIEW",
            "detail": "Source alone cannot prove an external audit happened.",
        }
    ]
    direct_vm.mock_llm(
        r".*policy compliance auditor.*",
        _payload(
            "NEEDS_REVIEW",
            70,
            "No code violation is visible, but the audit requirement cannot be proven from source.",
            concerns,
            1,
            0,
        ),
    )

    contract.run_check(check_id)

    result = json.loads(contract.get_verdict(check_id))
    assert result["verdict"] == "NEEDS_REVIEW"
    parsed = json.loads(result["violations"])
    assert len(parsed) == 1
    assert parsed[0]["status"] == "NEEDS_REVIEW"
    assert json.loads(contract.get_check(check_id))["status"] == "CHECKED"


# 4. UNCHECKABLE — contract URL fails to fetch
def test_uncheckable_contract_fetch_fail(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/policy_compliance_verdict.py")
    check_id = _submit(
        contract,
        direct_vm,
        direct_alice,
        "Hidden Treasury",
        "https://github.com/dao/hidden/Treasury.sol",
        "Security Policy",
        "https://notion.so/spacedao/security-policy",
    )

    direct_vm.mock_web(r".*github.*hidden.*", _raise)
    direct_vm.mock_web(
        r".*notion.*security.*",
        "Rule 1: All contracts must have a minimum 48-hour timelock.",
    )
    direct_vm.mock_llm(
        r".*policy compliance auditor.*",
        _payload(
            "UNCHECKABLE",
            10,
            "The contract source could not be fetched.",
            [],
            0,
            0,
        ),
    )

    contract.run_check(check_id)

    result = json.loads(contract.get_verdict(check_id))
    assert result["verdict"] == "UNCHECKABLE"
    assert json.loads(contract.get_check(check_id))["status"] == "UNCHECKABLE"


# 5. UNCHECKABLE — policy URL fails to fetch
def test_uncheckable_policy_fetch_fail(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/policy_compliance_verdict.py")
    check_id = _submit(
        contract,
        direct_vm,
        direct_alice,
        "Treasury v2",
        "https://github.com/dao/treasury/blob/main/Treasury.sol",
        "Missing Policy",
        "https://notion.so/spacedao/missing-policy",
    )

    direct_vm.mock_web(
        r".*github.*treasury.*",
        "contract Treasury { uint256 public constant TIMELOCK_DELAY = 48 hours; }",
    )
    direct_vm.mock_web(r".*notion.*missing-policy.*", _raise)
    direct_vm.mock_llm(
        r".*policy compliance auditor.*",
        _payload(
            "UNCHECKABLE",
            12,
            "The policy document could not be fetched.",
            [],
            0,
            0,
        ),
    )

    contract.run_check(check_id)

    result = json.loads(contract.get_verdict(check_id))
    assert result["verdict"] == "UNCHECKABLE"
    assert json.loads(contract.get_check(check_id))["status"] == "UNCHECKABLE"


# 6. UNCHECKABLE — both URLs fail
def test_uncheckable_both_fail(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/policy_compliance_verdict.py")
    check_id = _submit(
        contract,
        direct_vm,
        direct_alice,
        "Both Fail",
        "https://github.com/dao/both-fail/Contract.sol",
        "Both Fail Policy",
        "https://notion.so/dao/both-fail-policy",
    )

    direct_vm.mock_web(r".*github.*both-fail.*", _raise)
    direct_vm.mock_web(r".*notion.*both-fail.*", _raise)
    direct_vm.mock_llm(
        r".*policy compliance auditor.*",
        _payload(
            "UNCHECKABLE",
            5,
            "Neither the contract source nor the policy could be read.",
            [],
            0,
            0,
        ),
    )

    contract.run_check(check_id)

    full = json.loads(contract.get_check(check_id))
    assert full["status"] == "UNCHECKABLE"
    assert full["verdict"] == "UNCHECKABLE"


# 7. NON_COMPLIANT consistency: no VIOLATED in violations -> downgraded
def test_non_compliant_without_violated_downgraded(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy("contracts/policy_compliance_verdict.py")
    check_id = _submit(
        contract,
        direct_vm,
        direct_alice,
        "Treasury v2",
        "https://github.com/dao/treasury/blob/main/Treasury.sol",
        "Security Policy",
        "https://notion.so/spacedao/security-policy",
    )

    direct_vm.mock_web(
        r".*github.*treasury.*",
        "contract Treasury { uint256 public constant TIMELOCK_DELAY = 48 hours; }",
    )
    direct_vm.mock_web(
        r".*notion.*security.*",
        "Rule 1: Contracts must be audited before mainnet deploy.",
    )
    direct_vm.mock_llm(
        r".*policy compliance auditor.*",
        _payload(
            "NON_COMPLIANT",
            60,
            "The model flagged a review item but no clear code violation.",
            [
                {
                    "rule": "Audit required",
                    "status": "NEEDS_REVIEW",
                    "detail": "Source cannot prove an audit occurred.",
                }
            ],
            1,
            0,
        ),
    )

    contract.run_check(check_id)

    result = json.loads(contract.get_verdict(check_id))
    assert result["verdict"] == "NEEDS_REVIEW"


# 8. Malformed LLM JSON — graceful fallback
def test_malformed_llm_json_fallback(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/policy_compliance_verdict.py")
    check_id = _submit(
        contract,
        direct_vm,
        direct_alice,
        "Treasury v2",
        "https://github.com/dao/treasury/blob/main/Treasury.sol",
        "Security Policy",
        "https://notion.so/spacedao/security-policy",
    )

    direct_vm.mock_web(
        r".*github.*treasury.*",
        "contract Treasury { uint256 public constant TIMELOCK_DELAY = 48 hours; }",
    )
    direct_vm.mock_web(
        r".*notion.*security.*",
        "Rule 1: All contracts must have a minimum 48-hour timelock.",
    )
    direct_vm.mock_llm(r".*policy compliance auditor.*", "this is not json!!")

    contract.run_check(check_id)

    result = json.loads(contract.get_verdict(check_id))
    assert result["verdict"] == "UNCHECKABLE"
    assert json.loads(contract.get_check(check_id))["status"] == "UNCHECKABLE"


# 9. LLM returns invalid verdict string — normalized
def test_invalid_verdict_normalized(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/policy_compliance_verdict.py")
    check_id = _submit(
        contract,
        direct_vm,
        direct_alice,
        "Treasury v2",
        "https://github.com/dao/treasury/blob/main/Treasury.sol",
        "Security Policy",
        "https://notion.so/spacedao/security-policy",
    )

    direct_vm.mock_web(
        r".*github.*treasury.*",
        "contract Treasury { uint256 public constant TIMELOCK_DELAY = 48 hours; }",
    )
    direct_vm.mock_web(
        r".*notion.*security.*",
        "Rule 1: All contracts must have a minimum 48-hour timelock.",
    )
    direct_vm.mock_llm(
        r".*policy compliance auditor.*",
        _payload("MAYBE_OK", 40, "The model returned an unknown label.", [], 2, 1),
    )

    contract.run_check(check_id)

    result = json.loads(contract.get_verdict(check_id))
    assert result["verdict"] == "UNCHECKABLE"
    assert json.loads(contract.get_check(check_id))["status"] == "UNCHECKABLE"


# 10. LLM returns violations as non-list — handled gracefully
def test_violations_non_list_handled(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/policy_compliance_verdict.py")
    check_id = _submit(
        contract,
        direct_vm,
        direct_alice,
        "Treasury v2",
        "https://github.com/dao/treasury/blob/main/Treasury.sol",
        "Security Policy",
        "https://notion.so/spacedao/security-policy",
    )

    direct_vm.mock_web(
        r".*github.*treasury.*",
        "contract Treasury { address public owner; function sweep() external {} }",
    )
    direct_vm.mock_web(
        r".*notion.*security.*",
        "Rule 1: No single admin keys allowed.",
    )
    direct_vm.mock_llm(
        r".*policy compliance auditor.*",
        json.dumps({
            "verdict": "NON_COMPLIANT",
            "confidence": 55,
            "reasoning": "Violations field was not a list.",
            "violations": "some string not a list",
            "rules_checked": 1,
            "rules_passed": 0,
        }),
    )

    contract.run_check(check_id)

    result = json.loads(contract.get_verdict(check_id))
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["violations"] == "[]"


# 11. Submit with empty contract_name — UserError
def test_empty_contract_name(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/policy_compliance_verdict.py")
    with direct_vm.prank(direct_alice):
        with direct_vm.expect_revert("contract_name cannot be empty"):
            contract.submit_check(
                "",
                "https://github.com/c.sol",
                "Policy",
                "https://notion.so/policy",
            )


# 12. Submit with invalid contract_url — UserError
def test_invalid_contract_url(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/policy_compliance_verdict.py")
    with direct_vm.prank(direct_alice):
        with direct_vm.expect_revert("Invalid contract_url"):
            contract.submit_check(
                "Name",
                "not-a-url",
                "Policy",
                "https://notion.so/policy",
            )


# 13. Submit with invalid policy_url — UserError
def test_invalid_policy_url(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/policy_compliance_verdict.py")
    with direct_vm.prank(direct_alice):
        with direct_vm.expect_revert("Invalid policy_url"):
            contract.submit_check(
                "Name",
                "https://github.com/c.sol",
                "Policy",
                "bad-url",
            )


# 14. Submit with same URL for both — UserError
def test_same_url_for_both_rejected(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/policy_compliance_verdict.py")
    with direct_vm.prank(direct_alice):
        with direct_vm.expect_revert("contract_url and policy_url must differ"):
            contract.submit_check(
                "Name",
                "https://github.com/c.sol",
                "Policy",
                "https://github.com/c.sol",
            )


# 15. run_check on already-checked — UserError
def test_run_check_already_checked(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/policy_compliance_verdict.py")
    check_id = _submit(
        contract,
        direct_vm,
        direct_alice,
        "Treasury v2",
        "https://github.com/dao/treasury/blob/main/Treasury.sol",
        "Security Policy",
        "https://notion.so/spacedao/security-policy",
    )

    direct_vm.mock_web(
        r".*github.*treasury.*",
        "contract Treasury { uint256 public constant TIMELOCK_DELAY = 48 hours; }",
    )
    direct_vm.mock_web(
        r".*notion.*security.*",
        "Rule 1: All contracts must have a minimum 48-hour timelock.",
    )
    direct_vm.mock_llm(
        r".*policy compliance auditor.*",
        _payload("COMPLIANT", 88, "Timelock is present.", [], 1, 1),
    )

    contract.run_check(check_id)
    assert json.loads(contract.get_check(check_id))["status"] == "CHECKED"

    with direct_vm.expect_revert("only PENDING"):
        contract.run_check(check_id)


# 16. get_verdict on PENDING — UserError
def test_get_verdict_pending(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/policy_compliance_verdict.py")
    with direct_vm.prank(direct_alice):
        check_id = contract.submit_check(
            "Name",
            "https://github.com/c.sol",
            "Policy",
            "https://notion.so/policy",
        )
    with direct_vm.expect_revert("Not yet checked"):
        contract.get_verdict(check_id)


# 17. list_checks filtering
def test_list_checks_filter(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = direct_deploy("contracts/policy_compliance_verdict.py")

    with direct_vm.prank(direct_alice):
        compliant_id = contract.submit_check(
            "Treasury Alpha",
            "https://github.com/dao/alpha/Treasury.sol",
            "Security Policy",
            "https://notion.so/spacedao/alpha-policy",
        )
        non_compliant_id = contract.submit_check(
            "Admin Vault",
            "https://github.com/dao/vault/Vault.sol",
            "Security Policy",
            "https://notion.so/spacedao/vault-policy",
        )
    with direct_vm.prank(direct_bob):
        pending_id = contract.submit_check(
            "Pending Module",
            "https://github.com/dao/pending/Module.sol",
            "Security Policy",
            "https://notion.so/spacedao/pending-policy",
        )

    direct_vm.mock_web(
        r".*github.*alpha.*",
        "contract Treasury { uint256 public constant TIMELOCK_DELAY = 48 hours; }",
    )
    direct_vm.mock_web(
        r".*notion.*alpha-policy.*",
        "Rule 1: All contracts must have a minimum 48-hour timelock.",
    )
    direct_vm.mock_llm(
        r".*Treasury Alpha.*",
        _payload("COMPLIANT", 86, "Timelock is present.", [], 1, 1),
    )
    contract.run_check(compliant_id)

    direct_vm.mock_web(
        r".*github.*vault.*",
        "contract Vault { address public owner; function withdraw() external {} }",
    )
    direct_vm.mock_web(
        r".*notion.*vault-policy.*",
        "Rule 1: No single admin keys allowed.",
    )
    direct_vm.mock_llm(
        r".*Admin Vault.*",
        _payload(
            "NON_COMPLIANT",
            91,
            "A single owner can withdraw.",
            [
                {
                    "rule": "No single admin keys",
                    "status": "VIOLATED",
                    "detail": "owner can call withdraw without a multisig.",
                }
            ],
            1,
            0,
        ),
    )
    contract.run_check(non_compliant_id)

    compliant = json.loads(contract.list_checks("COMPLIANT"))
    non_compliant = json.loads(contract.list_checks("NON_COMPLIANT"))
    pending = json.loads(contract.list_checks("PENDING"))
    everything = json.loads(contract.list_checks(""))

    assert len(compliant) == 1
    assert compliant[0]["check_id"] == compliant_id
    assert len(non_compliant) == 1
    assert non_compliant[0]["check_id"] == non_compliant_id
    assert len(pending) == 1
    assert pending[0]["check_id"] == pending_id
    assert len(everything) == 3


# 18. invalidate_check — owner only, pending only
def test_invalidate_owner_only(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = direct_deploy("contracts/policy_compliance_verdict.py")
    check_id = _submit(
        contract,
        direct_vm,
        direct_alice,
        "Treasury v2",
        "https://github.com/dao/treasury/blob/main/Treasury.sol",
        "Security Policy",
        "https://notion.so/spacedao/security-policy",
    )

    with direct_vm.prank(direct_bob):
        with direct_vm.expect_revert("Only owner"):
            contract.invalidate_check(check_id)

    contract.invalidate_check(check_id)
    full = json.loads(contract.get_check(check_id))
    assert full["status"] == "UNCHECKABLE"
    assert full["reasoning"] == "Invalidated by admin"


# 19. invalidate already-checked — UserError
def test_invalidate_non_pending(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/policy_compliance_verdict.py")
    check_id = _submit(
        contract,
        direct_vm,
        direct_alice,
        "Treasury v2",
        "https://github.com/dao/treasury/blob/main/Treasury.sol",
        "Security Policy",
        "https://notion.so/spacedao/security-policy",
    )

    direct_vm.mock_web(
        r".*github.*treasury.*",
        "contract Treasury { uint256 public constant TIMELOCK_DELAY = 48 hours; }",
    )
    direct_vm.mock_web(
        r".*notion.*security.*",
        "Rule 1: All contracts must have a minimum 48-hour timelock.",
    )
    direct_vm.mock_llm(
        r".*policy compliance auditor.*",
        _payload("COMPLIANT", 84, "Timelock is present.", [], 1, 1),
    )
    contract.run_check(check_id)

    with direct_vm.expect_revert("only PENDING"):
        contract.invalidate_check(check_id)


# 20. Multiple violations stored and retrievable
def test_multiple_violations_stored(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/policy_compliance_verdict.py")
    check_id = _submit(
        contract,
        direct_vm,
        direct_alice,
        "Proxy Admin",
        "https://github.com/dao/proxy/Proxy.sol",
        "Security Policy",
        "https://notion.so/spacedao/proxy-policy",
    )

    direct_vm.mock_web(
        r".*github.*proxy.*",
        "contract Proxy {\n"
        "  address public owner;\n"
        "  function upgrade(address next) external { require(msg.sender == owner); }\n"
        "}",
    )
    direct_vm.mock_web(
        r".*notion.*proxy-policy.*",
        "Rule 1: 48-hour timelock.\n"
        "Rule 2: No single admin key.\n"
        "Rule 3: Upgrades require a multisig.",
    )
    violations = [
        {
            "rule": "48-hour timelock",
            "status": "VIOLATED",
            "detail": "upgrade() executes immediately.",
        },
        {
            "rule": "No single admin key",
            "status": "VIOLATED",
            "detail": "owner is a single address.",
        },
        {
            "rule": "Multisig required for upgrades",
            "status": "VIOLATED",
            "detail": "upgrade() checks owner, not a multisig.",
        },
    ]
    direct_vm.mock_llm(
        r".*policy compliance auditor.*",
        _payload(
            "NON_COMPLIANT",
            93,
            "Three policy rules are violated by the proxy admin.",
            violations,
            3,
            0,
        ),
    )

    contract.run_check(check_id)

    result = json.loads(contract.get_verdict(check_id))
    parsed = json.loads(result["violations"])
    assert result["verdict"] == "NON_COMPLIANT"
    assert len(parsed) == 3
    for entry in parsed:
        assert "rule" in entry
        assert "status" in entry
        assert "detail" in entry
