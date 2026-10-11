# v0.2.16
# {
#   "Seq": [
#     { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
#   ]
# }
import json
from dataclasses import dataclass
from genlayer import *


def _addr_str(a: Address) -> str:
    try:
        return a.as_hex
    except Exception:
        return str(a)


def _to_address(val) -> Address:
    if isinstance(val, Address):
        return val
    if isinstance(val, str):
        val_str = val.strip()
        if not val_str.startswith("0x"):
            val_str = "0x" + val_str
        return Address(val_str)
    return Address(val)


def _is_http_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")


def _as_int(val, default: int = 0) -> int:
    try:
        return int(val)
    except Exception:
        return default


def _violation_list(val) -> list:
    if isinstance(val, list):
        return val
    if isinstance(val, str):
        parsed = json.loads(val)
        if isinstance(parsed, list):
            return parsed
    return []


@allow_storage
@dataclass
class ComplianceCheck:
    submitter: Address
    contract_name: str
    contract_url: str
    policy_name: str
    policy_url: str
    status: str
    verdict: str
    confidence: u256
    reasoning: str
    violations: str
    rules_checked: u256
    rules_passed: u256


class PolicyComplianceVerdict(gl.Contract):
    checks: TreeMap[str, ComplianceCheck]
    next_id: bigint
    owner: Address

    def __init__(self):
        self.owner = _to_address(gl.message.sender_address)
        self.next_id = bigint(1)

    def _check_dict(self, check_id: str, check: ComplianceCheck) -> dict:
        return {
            "check_id": check_id,
            "submitter": _addr_str(check.submitter),
            "contract_name": check.contract_name,
            "contract_url": check.contract_url,
            "policy_name": check.policy_name,
            "policy_url": check.policy_url,
            "status": check.status,
            "verdict": check.verdict,
            "confidence": _as_int(check.confidence),
            "reasoning": check.reasoning,
            "violations": check.violations,
            "rules_checked": _as_int(check.rules_checked),
            "rules_passed": _as_int(check.rules_passed),
        }

    @gl.public.write
    def submit_check(
        self,
        contract_name: str,
        contract_url: str,
        policy_name: str,
        policy_url: str,
    ) -> str:
        if not contract_name or len(contract_name.strip()) == 0:
            raise gl.vm.UserError("contract_name cannot be empty")
        if len(contract_name) > 100:
            raise gl.vm.UserError("contract_name cannot exceed 100 characters")
        if not contract_url or not _is_http_url(contract_url):
            raise gl.vm.UserError("Invalid contract_url")
        if len(policy_name) > 100:
            raise gl.vm.UserError("policy_name cannot exceed 100 characters")
        if not policy_url or not _is_http_url(policy_url):
            raise gl.vm.UserError("Invalid policy_url")
        if contract_url == policy_url:
            raise gl.vm.UserError("contract_url and policy_url must differ")

        check_id = str(self.next_id)
        self.next_id += bigint(1)

        record = ComplianceCheck(
            submitter=_to_address(gl.message.sender_address),
            contract_name=contract_name,
            contract_url=contract_url,
            policy_name=policy_name,
            policy_url=policy_url,
            status="PENDING",
            verdict="",
            confidence=u256(0),
            reasoning="",
            violations="[]",
            rules_checked=u256(0),
            rules_passed=u256(0),
        )
        self.checks[check_id] = record
        return check_id

    @gl.public.write
    def run_check(self, check_id: str) -> None:
        if check_id not in self.checks:
            raise gl.vm.UserError("Check not found")

        check = self.checks[check_id]
        if check.status != "PENDING":
            raise gl.vm.UserError("only PENDING")

        contract_url_cap = check.contract_url
        policy_url_cap = check.policy_url
        contract_name_cap = check.contract_name
        policy_name_cap = check.policy_name

        def leader_fn():
            contract_source = ""
            try:
                res = gl.nondet.web.render(contract_url_cap)
                body = res.body if hasattr(res, "body") else str(res)
                if not isinstance(body, str):
                    body = str(body)
                if body and len(body.strip()) > 30:
                    contract_source = body[:5000]
                else:
                    contract_source = "(empty or too short to analyze)"
            except Exception as e:
                contract_source = f"(fetch failed: {str(e)})"

            policy_content = ""
            try:
                res2 = gl.nondet.web.render(policy_url_cap)
                body2 = res2.body if hasattr(res2, "body") else str(res2)
                if not isinstance(body2, str):
                    body2 = str(body2)
                if body2 and len(body2.strip()) > 30:
                    policy_content = body2[:4000]
                else:
                    policy_content = "(empty or too short to analyze)"
            except Exception as e:
                policy_content = f"(fetch failed: {str(e)})"

            policy_label = policy_name_cap if policy_name_cap else "Governance Policy"
            prompt = f"""You are an expert smart contract policy compliance auditor
on GenLayer. Your job is to check whether a smart contract satisfies all
the rules defined in a governance policy document.

Contract Being Reviewed: {contract_name_cap}
Contract Source fetched on-chain:
{contract_source}

Policy Document: {policy_label}
Policy Content fetched on-chain:
{policy_content}

Instructions:
1. First, identify and list every distinct, checkable rule or requirement
   in the policy document. Number them internally.
2. For each rule, check whether the contract source satisfies it, violates
   it, or cannot be determined from the source alone.
3. Compile a list of violations for rules that are clearly violated.
4. Compile a list of concerns for rules that need human review (e.g. the
   policy requires an audit but the source alone cannot prove one happened).

Verdict options:
- "COMPLIANT": All identifiable rules are satisfied by the contract source.
  No violations found.
- "NON_COMPLIANT": At least one rule is clearly violated by the contract
  source. List all violations.
- "NEEDS_REVIEW": No clear violations found, but some rules cannot be
  verified from source alone (e.g. audit requirement, multisig setup,
  deployment process). Human review needed.
- "UNCHECKABLE": Either the contract source or the policy document could
  not be read, or neither contains enough content to perform a check.

For violations and concerns, each entry must have:
- "rule": short description of the policy rule
- "status": "VIOLATED" or "NEEDS_REVIEW"
- "detail": specific explanation of the issue found in the contract

Return ONLY raw JSON, no markdown, no backticks:
{{"verdict": "COMPLIANT"|"NON_COMPLIANT"|"NEEDS_REVIEW"|"UNCHECKABLE",
  "confidence": <0-100>,
  "reasoning": "<2-3 sentence overall summary>",
  "violations": [
    {{"rule": "<rule description>",
      "status": "VIOLATED"|"NEEDS_REVIEW",
      "detail": "<specific issue>"}}
  ],
  "rules_checked": <integer>,
  "rules_passed": <integer>}}"""

            try:
                raw = gl.nondet.exec_prompt(prompt, response_format="json")
                if isinstance(raw, dict):
                    parsed = raw
                else:
                    cleaned = str(raw).strip()
                    if cleaned.startswith("```json"):
                        cleaned = cleaned[7:]
                    if cleaned.startswith("```"):
                        cleaned = cleaned[3:]
                    if cleaned.endswith("```"):
                        cleaned = cleaned[:-3]
                    parsed = json.loads(cleaned.strip())

                verdict = parsed.get("verdict", "UNCHECKABLE")
                if verdict not in [
                    "COMPLIANT",
                    "NON_COMPLIANT",
                    "NEEDS_REVIEW",
                    "UNCHECKABLE",
                ]:
                    verdict = "UNCHECKABLE"

                try:
                    conf = max(0, min(100, int(parsed.get("confidence", 0))))
                except Exception:
                    conf = 0

                try:
                    rules_checked = max(0, int(parsed.get("rules_checked", 0)))
                except Exception:
                    rules_checked = 0

                try:
                    rules_passed = max(
                        0, min(rules_checked, int(parsed.get("rules_passed", 0)))
                    )
                except Exception:
                    rules_passed = 0

                raw_violations = parsed.get("violations", [])
                if not isinstance(raw_violations, list):
                    raw_violations = []

                clean_violations = []
                for item in raw_violations:
                    if isinstance(item, dict):
                        clean_violations.append({
                            "rule": str(item.get("rule", "")),
                            "status": str(item.get("status", "NEEDS_REVIEW")),
                            "detail": str(item.get("detail", "")),
                        })

                # NON_COMPLIANT is only valid when at least one rule is VIOLATED.
                if verdict == "NON_COMPLIANT":
                    has_violated = any(
                        entry.get("status") == "VIOLATED" for entry in clean_violations
                    )
                    if not has_violated:
                        verdict = "NEEDS_REVIEW"

                return {
                    "verdict": verdict,
                    "confidence": conf,
                    "reasoning": str(parsed.get("reasoning", "")),
                    "violations": json.dumps(clean_violations),
                    "rules_checked": rules_checked,
                    "rules_passed": rules_passed,
                }
            except Exception as e:
                return {
                    "verdict": "UNCHECKABLE",
                    "confidence": 0,
                    "reasoning": f"Parse error: {str(e)}",
                    "violations": "[]",
                    "rules_checked": 0,
                    "rules_passed": 0,
                }

        def validator_fn(leader_res) -> bool:
            if not isinstance(leader_res, gl.vm.Return):
                return False
            lp = leader_res.calldata
            if not isinstance(lp, dict):
                return False

            leader_verdict = lp.get("verdict")
            leader_conf = lp.get("confidence")

            valid_verdicts = [
                "COMPLIANT",
                "NON_COMPLIANT",
                "NEEDS_REVIEW",
                "UNCHECKABLE",
            ]
            if leader_verdict not in valid_verdicts:
                return False
            try:
                lc = int(leader_conf)
                if not (0 <= lc <= 100):
                    return False
            except Exception:
                return False

            try:
                my_result = leader_fn()
            except Exception:
                return False
            if not isinstance(my_result, dict):
                return False

            # The compliance decision must match exactly.
            if my_result.get("verdict") != leader_verdict:
                return False

            # NON_COMPLIANT: leader and validator must each list at least one violation.
            if leader_verdict == "NON_COMPLIANT":
                try:
                    my_violations = _violation_list(my_result.get("violations", "[]"))
                    leader_violations = _violation_list(lp.get("violations", "[]"))
                    if len(my_violations) == 0 or len(leader_violations) == 0:
                        return False
                except Exception:
                    return False

            try:
                mc = int(my_result.get("confidence", 0))
                if not (0 <= mc <= 100):
                    return False
            except Exception:
                return False

            def _band(c):
                if c < 35:
                    return 1
                elif c < 80:
                    return 2
                else:
                    return 3

            return _band(mc) == _band(lc)

        ruling = gl.vm.run_nondet_unsafe(leader_fn, validator_fn)
        result_data = ruling.calldata if hasattr(ruling, "calldata") else ruling
        if not isinstance(result_data, dict):
            result_data = {
                "verdict": "UNCHECKABLE",
                "confidence": 0,
                "reasoning": "Invalid nondet result",
                "violations": "[]",
                "rules_checked": 0,
                "rules_passed": 0,
            }

        result_verdict = result_data.get("verdict", "UNCHECKABLE")
        if result_verdict not in [
            "COMPLIANT",
            "NON_COMPLIANT",
            "NEEDS_REVIEW",
            "UNCHECKABLE",
        ]:
            result_verdict = "UNCHECKABLE"

        try:
            conf = max(0, min(100, int(result_data.get("confidence", 0))))
        except Exception:
            conf = 0
        try:
            rules_checked = max(0, int(result_data.get("rules_checked", 0)))
        except Exception:
            rules_checked = 0
        try:
            rules_passed = max(
                0, min(rules_checked, int(result_data.get("rules_passed", 0)))
            )
        except Exception:
            rules_passed = 0

        violations_raw = result_data.get("violations", "[]")
        if isinstance(violations_raw, list):
            violations_raw = json.dumps(violations_raw)
        elif not isinstance(violations_raw, str):
            violations_raw = "[]"

        check.verdict = result_verdict
        check.confidence = u256(conf)
        check.reasoning = str(result_data.get("reasoning", ""))
        check.violations = violations_raw
        check.rules_checked = u256(rules_checked)
        check.rules_passed = u256(rules_passed)
        if result_verdict == "UNCHECKABLE" or result_verdict == "":
            check.status = "UNCHECKABLE"
        else:
            check.status = "CHECKED"
        self.checks[check_id] = check

    @gl.public.write
    def invalidate_check(self, check_id: str) -> None:
        if check_id not in self.checks:
            raise gl.vm.UserError("Check not found")

        sender = _to_address(gl.message.sender_address)
        if sender != self.owner:
            raise gl.vm.UserError("Only owner")

        check = self.checks[check_id]
        if check.status != "PENDING":
            raise gl.vm.UserError("only PENDING")

        check.status = "UNCHECKABLE"
        check.reasoning = "Invalidated by admin"
        self.checks[check_id] = check

    @gl.public.view
    def get_check(self, check_id: str) -> str:
        if check_id not in self.checks:
            raise gl.vm.UserError("Check not found")
        return json.dumps(self._check_dict(check_id, self.checks[check_id]))

    @gl.public.view
    def get_verdict(self, check_id: str) -> str:
        if check_id not in self.checks:
            raise gl.vm.UserError("Check not found")

        check = self.checks[check_id]
        if check.status == "PENDING":
            raise gl.vm.UserError("Not yet checked")

        res = {
            "check_id": check_id,
            "contract_name": check.contract_name,
            "policy_name": check.policy_name,
            "verdict": check.verdict,
            "confidence": _as_int(check.confidence),
            "reasoning": check.reasoning,
            "violations": check.violations,
            "rules_checked": _as_int(check.rules_checked),
            "rules_passed": _as_int(check.rules_passed),
            "status": check.status,
        }
        return json.dumps(res)

    @gl.public.view
    def list_checks(self, verdict_filter: str) -> str:
        allowed = [
            "",
            "PENDING",
            "COMPLIANT",
            "NON_COMPLIANT",
            "NEEDS_REVIEW",
            "UNCHECKABLE",
        ]
        if verdict_filter not in allowed:
            raise gl.vm.UserError("Invalid verdict filter")

        results = []
        limit = int(self.next_id)
        for i in range(1, limit):
            check_id = str(i)
            if check_id in self.checks:
                check = self.checks[check_id]
                if (
                    verdict_filter == ""
                    or check.status == verdict_filter
                    or check.verdict == verdict_filter
                ):
                    results.append({
                        "check_id": check_id,
                        "contract_name": check.contract_name,
                        "policy_name": check.policy_name,
                        "status": check.status,
                        "verdict": check.verdict,
                        "rules_checked": _as_int(check.rules_checked),
                        "rules_passed": _as_int(check.rules_passed),
                    })
        return json.dumps(results)

    @gl.public.view
    def get_count(self) -> int:
        return int(self.next_id) - 1
