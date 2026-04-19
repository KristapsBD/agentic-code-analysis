"""
Static analysis tool integration for smart contract vulnerability detection.

Runs Slither (if installed) on a Solidity contract file and returns structured
findings that ground agent reasoning before the debate begins.

Slither is only supported for Solidity (.sol) contracts. Non-Solidity files are
silently skipped and the agents proceed without static analysis context.

Many benchmark contracts target old Solidity versions (0.4.x – 0.7.x).  Slither
delegates compilation to the system `solc` binary, so running it with the wrong
compiler version produces a hard compilation error.
Contracts that declare no pragma are assumed to be 0.4.x-era code and receive
version 0.4.26 by default.
"""

import json
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from packaging.specifiers import SpecifierSet
from packaging.version import Version

logger = logging.getLogger(__name__)

# Map Slither detector names to our canonical vulnerability type labels.
_DETECTOR_TO_VULN_TYPE: dict[str, str] = {
    # Reentrancy
    "reentrancy-eth": "reentrancy",
    "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy",
    "reentrancy-events": "reentrancy",
    "reentrancy-unlimited-gas": "reentrancy",
    # Access control
    "suicidal": "access_control",
    "unprotected-upgrade": "access_control",
    "unprotected-ether-withdrawal": "access_control",
    "tx-origin": "access_control",
    "missing-zero-check": "access_control",
    "controlled-delegatecall": "delegatecall",
    "delegatecall-loop": "delegatecall",
    # Unchecked return values
    "unchecked-lowlevel": "unchecked_calls",
    "unchecked-send": "unchecked_calls",
    "unchecked-transfer": "unchecked_calls",
    "unused-return": "unchecked_calls",
    # Randomness / time
    "weak-prng": "bad_randomness",
    "timestamp": "time_manipulation",
    # DoS
    "controlled-array-length": "denial_of_service",
    "msgvalue-loop": "denial_of_service",
    "msg-value-loop": "denial_of_service",
    # Arithmetic
    "tautology": "arithmetic",
    "divide-before-multiply": "arithmetic",
    "integer-overflow": "arithmetic",
}

_IMPACT_RANK: dict[str, int] = {
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Informational": 1,
    "Optimization": 0,
}

_KNOWN_VERSIONS: list[str] = [
    "0.8.29", "0.8.28", "0.8.24", "0.8.20", "0.8.19",
    "0.8.13", "0.8.10", "0.8.0",
    "0.7.6", "0.7.5",
    "0.6.12", "0.6.11", "0.6.6", "0.6.0",
    "0.5.17", "0.5.16", "0.5.12",
    "0.4.26", "0.4.25", "0.4.24", "0.4.23", "0.4.22",
    "0.4.18", "0.4.16", "0.4.15", "0.4.11",
]

_NO_PRAGMA_FALLBACK = "0.4.26"


def _pragma_to_specifier(pragma_str: str) -> SpecifierSet:
    """Convert a raw `pragma solidity` expression into a packaging SpecifierSet."""
    parts: list[str] = []
    for token in pragma_str.strip().split():
        token = token.strip()
        if not token:
            continue

        # Caret with patch:  ^X.Y.Z
        m = re.match(r'^\^(\d+)\.(\d+)\.(\d+)$', token)
        if m:
            major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
            parts.append(f">={major}.{minor}.{patch}")
            if major > 0:
                parts.append(f"<{major + 1}.0.0")
            else:
                parts.append(f"<{major}.{minor + 1}.0")
            continue

        # Caret without patch:  ^X.Y
        m = re.match(r'^\^(\d+)\.(\d+)$', token)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            parts.append(f">={major}.{minor}.0")
            if major > 0:
                parts.append(f"<{major + 1}.0.0")
            else:
                parts.append(f"<{major}.{minor + 1}.0")
            continue

        # Explicit operator:  >=X.Y.Z  /  <X.Y.Z  /  !=X.Y.Z  etc.
        m = re.match(r'^(>=|<=|!=|>|<)(\d+\.\d+(?:\.\d+)?)$', token)
        if m:
            op, ver = m.group(1), m.group(2)
            if ver.count('.') == 1:
                ver += '.0'
            parts.append(f"{op}{ver}")
            continue

        # Exact with = prefix:  =X.Y.Z
        m = re.match(r'^=(\d+\.\d+\.\d+)$', token)
        if m:
            parts.append(f"=={m.group(1)}")
            continue

        # Bare version number:  X.Y.Z
        m = re.match(r'^(\d+\.\d+\.\d+)$', token)
        if m:
            parts.append(f"=={m.group(1)}")
            continue

    return SpecifierSet(','.join(parts)) if parts else SpecifierSet()


def _get_current_solc_version() -> Optional[str]:
    """Return the version string of the currently active solc binary, or None."""
    try:
        proc = subprocess.run(
            ["solc", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        m = re.search(r'(\d+\.\d+\.\d+)', proc.stdout)
        return m.group(1) if m else None
    except Exception:
        return None


def _find_best_version(spec: SpecifierSet) -> Optional[str]:
    """Return the highest version in _KNOWN_VERSIONS that satisfies spec, or None if no match is found."""
    for ver_str in _KNOWN_VERSIONS:
        if Version(ver_str) in spec:
            return ver_str
    return None


def _install_and_activate_solc(version: str) -> bool:
    """Install (if needed) and activate a solc version via solc-select."""
    if shutil.which("solc-select") is None:
        logger.warning("solc-select not found — cannot switch compiler version")
        return False

    # Install (no-op if already present)
    logger.info("Installing solc %s via solc-select...", version)
    install = subprocess.run(
        ["solc-select", "install", version],
        capture_output=True, text=True, timeout=180,
    )
    if install.returncode not in (0, 1):  # 1 = already installed on some versions
        logger.warning(
            "solc-select install %s failed (rc=%d): %s",
            version, install.returncode, install.stderr.strip()[:200],
        )
        return False

    # Activate
    use = subprocess.run(
        ["solc-select", "use", version],
        capture_output=True, text=True, timeout=10,
    )
    if use.returncode != 0:
        logger.warning(
            "solc-select use %s failed (rc=%d): %s",
            version, use.returncode, use.stderr.strip()[:200],
        )
        return False

    logger.info("Switched solc to %s", version)
    return True


def _ensure_solc_for_source(source_code: str) -> Optional[str]:
    """Inspect the pragma in source_code and ensure the correct solc version is active."""
    pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', source_code)

    if pragma_match:
        spec = _pragma_to_specifier(pragma_match.group(1))
    else:
        # No pragma → assume old 0.4.x code
        logger.info("No pragma found — defaulting to solc %s", _NO_PRAGMA_FALLBACK)
        spec = SpecifierSet(f"=={_NO_PRAGMA_FALLBACK}")

    current = _get_current_solc_version()
    if current and Version(current) in spec:
        logger.debug("Current solc %s already satisfies pragma", current)
        return None  # already correct, no switch needed

    target = _find_best_version(spec)
    if target is None:
        logger.warning(
            "No known solc version satisfies pragma '%s' — Slither may fail",
            pragma_match.group(1) if pragma_match else "(none)",
        )
        return None

    logger.info(
        "Switching solc: %s → %s (pragma requires %s)",
        current or "unknown", target,
        pragma_match.group(1) if pragma_match else "(none)",
    )
    if _install_and_activate_solc(target):
        return current  # caller should restore this
    return None

@dataclass
class StaticFinding:
    """A single finding from Slither."""
    detector: str
    vuln_type: str
    impact: str
    confidence: str
    description: str
    elements: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "detector": self.detector,
            "vuln_type": self.vuln_type,
            "impact": self.impact,
            "confidence": self.confidence,
            "description": self.description,
            "elements": self.elements,
        }


@dataclass
class StaticAnalysisResult:
    """Result from running Slither on a contract."""
    tool: str
    findings: list[StaticFinding] = field(default_factory=list)
    error: Optional[str] = None
    skipped: bool = False
    skip_reason: str = ""
    solc_version_used: Optional[str] = None

    @property
    def success(self) -> bool:
        return not self.skipped and self.error is None

    def format_for_prompt(self) -> str:
        """Return a compact string suitable for injection into an agent prompt."""
        if self.skipped:
            return ""
        if self.error:
            return f"[Slither attempted but failed: {self.error}]"
        if not self.findings:
            return "[Slither static analysis: no issues detected]"

        lines = [f"Slither detected {len(self.findings)} issue(s):"]
        for f in sorted(
            self.findings,
            key=lambda x: _IMPACT_RANK.get(x.impact, 0),
            reverse=True,
        ):
            elements_str = ", ".join(f.elements[:3]) if f.elements else "N/A"
            lines.append(
                f"  [{f.impact.upper()}] {f.detector} ({f.vuln_type}): "
                f"{f.description.strip()[:200]} | Elements: {elements_str}"
            )
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "success": self.success,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "error": self.error,
            "solc_version_used": self.solc_version_used,
            "findings": [f.to_dict() for f in self.findings],
        }

def is_slither_available() -> bool:
    return shutil.which("slither") is not None


def run_slither(contract_path: str) -> StaticAnalysisResult:
    """Run Slither on a Solidity contract and return structured findings."""
    path = Path(contract_path)

    if path.suffix.lower() != ".sol":
        logger.info("Skipping Slither — not a Solidity file (suffix: %s)", path.suffix)
        return StaticAnalysisResult(
            tool="slither",
            skipped=True,
            skip_reason=f"Slither only supports Solidity (.sol); got '{path.suffix}'",
        )

    if not is_slither_available():
        logger.warning(
            "Slither is not installed or not on PATH — skipping static analysis. "
            "Install with: pip install slither-analyzer"
        )
        return StaticAnalysisResult(
            tool="slither",
            skipped=True,
            skip_reason="Slither not installed (pip install slither-analyzer)",
        )

    # Read source to determine required solc version
    try:
        source_code = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return StaticAnalysisResult(tool="slither", error=f"Cannot read file: {exc}")

    # Switch solc version if needed; remember original to restore later
    previous_version = _ensure_solc_for_source(source_code)
    active_version = _get_current_solc_version()

    logger.info("Running Slither on: %s (solc=%s)", contract_path, active_version or "unknown")
    try:
        proc = subprocess.run(
            ["slither", str(path), "--json", "-"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        logger.error("Slither timed out after 120 seconds")
        _restore_solc(previous_version)
        return StaticAnalysisResult(tool="slither", error="Slither timed out after 120s")
    except FileNotFoundError:
        _restore_solc(previous_version)
        return StaticAnalysisResult(
            tool="slither",
            skipped=True,
            skip_reason="Slither executable not found on PATH",
        )

    _restore_solc(previous_version)

    # Slither exit codes:
    #   0   — analysis succeeded with findings
    #   255 — analysis succeeded with no findings
    #   other — error (compilation failure, etc.)
    raw_json = proc.stdout.strip()

    if not raw_json:
        if proc.returncode not in (0, 255):
            err = (proc.stderr.strip()[:500] if proc.stderr else "unknown error")
            logger.warning("Slither returned no JSON (rc=%d): %s", proc.returncode, err)
            return StaticAnalysisResult(tool="slither", error=f"Slither failed: {err}")
        return StaticAnalysisResult(
            tool="slither", findings=[], solc_version_used=active_version
        )

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        logger.warning("Failed to parse Slither JSON: %s", exc)
        return StaticAnalysisResult(tool="slither", error=f"JSON parse error: {exc}")

    findings: list[StaticFinding] = []
    for detector in data.get("results", {}).get("detectors", []):
        detector_name = detector.get("check", "unknown")
        impact = detector.get("impact", "Unknown")
        confidence = detector.get("confidence", "Unknown")
        description = detector.get("description", "").strip()

        elements: list[str] = []
        for elem in detector.get("elements", []):
            name = elem.get("name") or elem.get("type", "")
            if name:
                elements.append(name)

        vuln_type = _DETECTOR_TO_VULN_TYPE.get(detector_name, "unchecked_calls")
        findings.append(StaticFinding(
            detector=detector_name,
            vuln_type=vuln_type,
            impact=impact,
            confidence=confidence,
            description=description,
            elements=elements,
        ))

    logger.info("Slither found %d issue(s) in %s", len(findings), contract_path)
    return StaticAnalysisResult(
        tool="slither", findings=findings, solc_version_used=active_version
    )


def _restore_solc(previous_version: Optional[str]) -> None:
    """Restore the previously active solc version, if we switched away from it."""
    if previous_version is None:
        return
    try:
        subprocess.run(
            ["solc-select", "use", previous_version],
            capture_output=True, text=True, timeout=10,
        )
        logger.debug("Restored solc to %s", previous_version)
    except Exception as exc:
        logger.warning("Failed to restore solc to %s: %s", previous_version, exc)
