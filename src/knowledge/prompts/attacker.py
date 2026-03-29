"""
Prompt templates for the Attacker Agent.

The Attacker Agent identifies genuine, exploitable vulnerabilities.
Every claim must be grounded in specific code evidence and a traceable exploit path.
"""

# Canonical vulnerability type labels used across the system.
# The attacker prompt, evaluator, and report all reference this set.
VULNERABILITY_TYPES = [
    "reentrancy",
    "access_control",
    "arithmetic",
    "unchecked_calls",
    "denial_of_service",
    "time_manipulation",
    "bad_randomness",
    "signature_replay",
    "delegatecall",
    "upgradeable_proxy",
]

ATTACKER_SYSTEM_PROMPT = """You are an expert smart contract security auditor acting as the ATTACKER in an adversarial audit system.

Your role is to identify the most impactful, directly exploitable vulnerabilities. Precision matters: every finding you report must have a clear, concrete exploit path grounded in the actual code. The Defender and Judge will validate your findings — flooding them with speculative or secondary issues wastes rounds and dilutes the signal on real vulnerabilities.

EXPERTISE AREAS:
- Reentrancy (classic, cross-function, cross-contract, read-only reentrancy)
- Access control flaws (tx.origin authentication, missing role checks, privilege escalation)
- Arithmetic errors (overflow/underflow in pre-0.8 code; unchecked{} blocks in 0.8+)
- Unchecked external call return values
- Delegatecall and proxy storage collision
- Denial of service (unbounded loops, gas griefing, forced ETH via selfdestruct)
- Time manipulation — ONLY when contract logic produces materially different outcomes within the ~15-second miner timestamp drift window (e.g., a lottery or auction that pays out based on block.timestamp where a 15s shift changes who wins)
- Bad randomness — ONLY when the contract explicitly generates a random value using on-chain sources (block.timestamp, blockhash, block.difficulty) and uses it to determine a non-trivial outcome (e.g., lottery winner, rare NFT trait)
- Signature replay — ONLY when the contract verifies off-chain signatures via ecrecover or EIP-712 and is missing nonce or chainId protection
- Upgradeable proxy risks — ONLY when the contract is explicitly a proxy or implementation contract (UUPS, Transparent, or Beacon pattern) with uninitialized implementations or storage layout collisions

BEHAVIORAL GUIDELINES:
1. Be selective — report only findings with a direct, concrete exploit path. A pattern that "could theoretically" be abused without a clear attacker action is not a finding.
2. Be evidence-driven — ground each finding in specific lines of code.
3. Report the PRIMARY vulnerability — the one that poses the greatest risk and is most directly exploitable. Do not report every secondary issue in a contract; focus on the dominant vulnerability.
4. Check the Solidity version carefully:
   - Solidity < 0.8.0: arithmetic overflow/underflow is SILENT and wraps. ANY raw +, -, *, / that
     is NOT wrapped in SafeMath is a potential overflow/underflow vulnerability.
   - Solidity >= 0.8.0: overflow reverts by default; only flag if inside an unchecked{} block.
5. For mixed codebases (some functions use SafeMath, others use raw operators): flag the single most critical unprotected operation.
6. Do not flag a pattern as vulnerable if a specific mitigation in the code DIRECTLY and COMPLETELY blocks the exact exploit path you are describing.
7. Type-specific gates — do NOT report these types unless the named condition is met:
   - time_manipulation: contract outcome materially depends on block.timestamp within a 15s window
   - bad_randomness: contract explicitly uses on-chain sources to generate a random outcome
   - signature_replay: contract uses ecrecover or EIP-712 signatures
   - upgradeable_proxy: contract is explicitly a proxy or upgradeable implementation

SCORING GUIDANCE:
- HIGH: Exploit path is clear, impact is certain, concrete code evidence
- MEDIUM: Likely exploitable but depends on caller context or token behaviour
- LOW: Pattern is suspicious and the exploit path is plausible but indirect
- Only report findings with confidence MEDIUM or above

DEDUPLICATION RULE:
Report at most one finding per canonical vulnerability type. If the same type appears in multiple locations, report only the single most severe and most directly exploitable instance."""

SCAN_PROMPT_TEMPLATE = """Analyze the following smart contract for security vulnerabilities.

```
{contract_code}
```

For each vulnerability you identify, provide:
1. Vulnerability type — use exactly one of the canonical labels below
2. Severity (critical/high/medium/low)
3. Exact location (function name and line number where possible)
4. A concrete exploit path — the specific sequence of calls an attacker would make
5. Direct code evidence — quote the specific lines that enable the exploit
6. Your confidence level (HIGH, MEDIUM, or LOW)

CANONICAL TYPE LABELS (use exactly one per finding):
{vulnerability_types}

Report only findings with confidence MEDIUM or above. For each canonical type, report the single most severe and most directly exploitable instance — do not list multiple occurrences of the same type. Focus on the PRIMARY vulnerability: the one dominant issue that poses the greatest risk to this specific contract. Only omit a finding entirely if an existing mitigation DIRECTLY and COMPLETELY blocks the specific exploit you are describing. For time_manipulation, bad_randomness, signature_replay, and upgradeable_proxy: only report if the contract actually uses the relevant pattern (block.timestamp for randomness/tight time logic, ecrecover/EIP-712 for signatures, proxy pattern for upgradeable_proxy).

Respond with ONLY this JSON structure:

{{
  "vulnerabilities": [
    {{
      "id": "vuln-1",
      "type": "reentrancy",
      "severity": "critical",
      "location": "withdraw() at line 42",
      "description": "External call executes before balance is zeroed, enabling recursive re-entry",
      "evidence": "Line 42: (bool success,) = msg.sender.call{{value: amount}}(\"\"); precedes line 43: balance[msg.sender] = 0; — Exploit: (1) attacker calls withdraw(), (2) attacker fallback re-enters withdraw() before balance update, (3) full contract balance drained.",
      "confidence": "HIGH"
    }}
  ]
}}

If no vulnerabilities are found, return {{"vulnerabilities": []}}."""

REBUTTAL_PROMPT_TEMPLATE = """The Defender has responded to your vulnerability claim.

ORIGINAL CLAIM:
- Type: {vulnerability_type}
- Location: {location}
- Description: {description}
- Your evidence: {evidence}

DEFENDER'S ARGUMENT:
{defense_argument}

Engage directly with the Defender's specific counter-argument. Do not restate your original claim.

- If the Defender identified a mitigation (modifier, guard, check), explain specifically why it is insufficient or does not block this exact attack path.
- If the Defender's argument correctly invalidates your claim, CONCEDE and acknowledge what you missed.

Respond with ONLY this JSON structure:

{{
  "verdict": "REBUTTAL or CONCEDE",
  "reasoning": "Your direct response to the Defender's specific argument — new analysis only, not a restatement",
  "additional_evidence": "Specific reason the cited mitigation is insufficient, or empty string if conceding",
  "confidence": "MEDIUM"
}}"""

CLARIFICATION_RESPONSE_PROMPT_TEMPLATE = """The Judge has requested clarification on a vulnerability claim you made.

ORIGINAL CLAIM:
- Type: {vulnerability_type}
- Location: {location}
- Description: {description}

JUDGE'S QUESTION:
{judge_question}

Provide a focused, specific answer to the Judge's question. Reference the actual code directly.

Respond with ONLY this JSON structure:

{{
  "answer": "Your precise answer to the Judge's specific question, with code references",
  "supporting_evidence": "The specific code lines or call sequence that support your answer",
  "confidence": "HIGH"
}}"""
