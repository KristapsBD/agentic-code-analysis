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


def _find_best_version(spec: SpecifierSet) -> Optional[str]:
    for ver_str in _KNOWN_VERSIONS:
        if Version(ver_str) in spec:
            return ver_str
    return None


def _resolve_solc_version(source_code: str) -> Optional[str]:
    pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', source_code)

    if pragma_match:
        spec = _pragma_to_specifier(pragma_match.group(1))
    else:
        logger.info("No pragma found — defaulting to solc %s", _NO_PRAGMA_FALLBACK)
        spec = SpecifierSet(f"=={_NO_PRAGMA_FALLBACK}")

    version = _find_best_version(spec)
    if version is None:
        logger.warning(
            "No known solc version satisfies pragma '%s' — Slither may fail",
            pragma_match.group(1) if pragma_match else "(none)",
        )
    return version


def _activate_solc(version: str) -> bool:
    if shutil.which("solc-select") is None:
        logger.warning("solc-select not found — cannot switch compiler version")
        return False

    install = subprocess.run(
        ["solc-select", "install", version],
        capture_output=True, text=True, timeout=180,
    )
    # returncode 1 = already installed on some solc-select versions
    if install.returncode not in (0, 1):
        logger.warning(
            "solc-select install %s failed (rc=%d): %s",
            version, install.returncode, install.stderr.strip()[:200],
        )
        return False

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

    logger.info("Activated solc %s", version)
    return True


@dataclass
class StaticFinding:
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
    try:
        import slither
        return True
    except ImportError:
        return False


def run_slither(contract_path: str) -> StaticAnalysisResult:
    path = Path(contract_path)

    if path.suffix.lower() != ".sol":
        logger.info("Skipping Slither — not a Solidity file (suffix: %s)", path.suffix)
        return StaticAnalysisResult(
            tool="slither",
            skipped=True,
            skip_reason=f"Slither only supports Solidity (.sol); got '{path.suffix}'",
        )

    try:
        from slither import Slither
    except ImportError:
        logger.warning(
            "slither-analyzer is not installed — skipping static analysis. "
            "Install with: pip install slither-analyzer"
        )
        return StaticAnalysisResult(
            tool="slither",
            skipped=True,
            skip_reason="Slither not installed (pip install slither-analyzer)",
        )

    try:
        source_code = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return StaticAnalysisResult(tool="slither", error=f"Cannot read file: {exc}")

    solc_version = _resolve_solc_version(source_code)
    if solc_version:
        _activate_solc(solc_version)

    logger.info("Running Slither on: %s (solc=%s)", contract_path, solc_version or "system default")

    try:
        slither_instance = Slither(str(path))
        detector_results = slither_instance.run_detectors()
    except Exception as exc:
        error_msg = str(exc).strip()[:500]
        logger.warning("Slither analysis failed for %s: %s", contract_path, error_msg)
        return StaticAnalysisResult(tool="slither", error=error_msg)

    findings: list[StaticFinding] = []
    for result in detector_results:
        detector_name = result.get("check", "unknown")
        impact = result.get("impact", "Unknown")
        confidence = result.get("confidence", "Unknown")
        description = result.get("description", "").strip()

        elements: list[str] = []
        for elem in result.get("elements", []):
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
        tool="slither", findings=findings, solc_version_used=solc_version
    )
