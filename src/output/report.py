import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from src.config import ConfidenceLevel

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


@dataclass
class Finding:
    vulnerability_type: str
    severity: str
    location: str
    description: str
    confidence: ConfidenceLevel
    recommendation: str
    attacker_evidence: str = ""
    defender_argument: str = ""
    judge_reasoning: str = ""

    def to_dict(self) -> dict:
        return {
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "location": self.location,
            "description": self.description,
            "confidence": self.confidence.value,
            "recommendation": self.recommendation,
            "attacker_evidence": self.attacker_evidence,
            "defender_argument": self.defender_argument,
            "judge_reasoning": self.judge_reasoning,
        }


@dataclass
class Report:
    contract_path: str
    contract_language: str
    analysis_timestamp: datetime
    total_claims: int
    confirmed_findings: list[Finding]
    rejected_claims: int
    debate_rounds: int
    provider: str = ""
    model: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.confirmed_findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.confirmed_findings if f.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.confirmed_findings if f.severity == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.confirmed_findings if f.severity == "low")

    def to_dict(self) -> dict:
        return {
            "contract_path": self.contract_path,
            "contract_language": self.contract_language,
            "analysis_timestamp": self.analysis_timestamp.isoformat(),
            "summary": {
                "total_claims": self.total_claims,
                "confirmed_findings": len(self.confirmed_findings),
                "rejected_claims": self.rejected_claims,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "findings": [f.to_dict() for f in self.confirmed_findings],
            "analysis_info": {
                "provider": self.provider,
                "model": self.model,
                "debate_rounds": self.debate_rounds,
            },
            "metadata": self.metadata,
        }


class ReportGenerator:
    def generate(self, result: dict, contract_path: str) -> Report:
        findings = []

        for claim_result in result.get("claim_results", []):
            verdict = claim_result.get("verdict", {})
            if verdict.get("is_valid", False):
                claim = claim_result.get("claim", {})
                findings.append(Finding(
                    vulnerability_type=claim.get("vulnerability_type", "Unknown"),
                    severity=verdict.get("severity", "medium"),
                    location=claim.get("location", "Unknown"),
                    description=claim.get("description", ""),
                    confidence=ConfidenceLevel(str(verdict.get("confidence", "MEDIUM")).upper()),
                    recommendation=verdict.get("recommendation", "Review and address"),
                    attacker_evidence=claim.get("evidence", ""),
                    judge_reasoning=verdict.get("reasoning", ""),
                ))

        return Report(
            contract_path=contract_path,
            contract_language=result.get("contract_language", "unknown"),
            analysis_timestamp=datetime.fromisoformat(
                result.get("started_at", datetime.now().isoformat())
            ),
            total_claims=result.get("total_vulnerabilities", 0),
            confirmed_findings=findings,
            rejected_claims=result.get("rejected_claims", 0),
            debate_rounds=result.get("metadata", {}).get("max_rounds", 0),
            provider=result.get("metadata", {}).get("provider", ""),
            model=result.get("metadata", {}).get("model", ""),
            metadata=result.get("metadata", {}),
        )

    def print_to_console(self, report: Report, console: Optional[Console] = None) -> None:
        console = console or Console()

        summary_text = (
            f"Contract: {report.contract_path}\n"
            f"Language: {report.contract_language}\n"
            f"Analysis Time: {report.analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"Total Claims: {report.total_claims}\n"
            f"Confirmed: {len(report.confirmed_findings)}\n"
            f"Rejected: {report.rejected_claims}"
        )
        console.print(Panel(summary_text, title="Analysis Summary", style="bold blue"))

        if report.confirmed_findings:
            breakdown = Table(show_header=True, header_style="bold")
            breakdown.add_column("Severity", style="cyan")
            breakdown.add_column("Count", justify="right")

            for label, style, count in [
                ("Critical", "red bold", report.critical_count),
                ("High", "red", report.high_count),
                ("Medium", "yellow", report.medium_count),
                ("Low", "cyan", report.low_count),
            ]:
                if count > 0:
                    breakdown.add_row(label, str(count), style=style)

            console.print(breakdown)

        if report.confirmed_findings:
            console.print("\n[bold]Confirmed Vulnerabilities:[/bold]\n")

            for i, finding in enumerate(report.confirmed_findings, 1):
                table = Table(show_header=False, show_edge=False, padding=(0, 1))
                table.add_column("Field", style="dim")
                table.add_column("Value")

                table.add_row("Type", finding.vulnerability_type)
                table.add_row("Severity", f"{finding.severity.upper()}")
                table.add_row("Location", finding.location)
                table.add_row("Confidence", finding.confidence.value)
                table.add_row("Description", finding.description[:200] + "..." if len(finding.description) > 200 else finding.description)

                console.print(Panel(
                    table,
                    title=f"Finding #{i}",
                ))

                if finding.recommendation:
                    console.print(f"  [dim]Recommendation:[/dim] {finding.recommendation[:150]}")
                console.print()

        else:
            console.print("\n[green]No confirmed vulnerabilities found.[/green]\n")

        console.print(
            f"\n[dim]Analysis performed with {report.provider}/{report.model}[/dim]"
        )

    def save_json(self, report: Report, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(report.to_dict(), f, indent=2, default=str)

    def save_markdown(self, report: Report, output_path: Path) -> None:
        md_lines = [
            f"# Security Analysis Report",
            f"",
            f"**Contract:** `{report.contract_path}`",
            f"**Language:** {report.contract_language}",
            f"**Analysis Date:** {report.analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"",
            f"## Summary",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Claims | {report.total_claims} |",
            f"| Confirmed Findings | {len(report.confirmed_findings)} |",
            f"| Rejected Claims | {report.rejected_claims} |",
            f"| Critical | {report.critical_count} |",
            f"| High | {report.high_count} |",
            f"| Medium | {report.medium_count} |",
            f"| Low | {report.low_count} |",
            f"",
            f"## Findings",
            f"",
        ]

        if report.confirmed_findings:
            for i, finding in enumerate(report.confirmed_findings, 1):
                md_lines.extend([
                    f"### {i}. {finding.vulnerability_type}",
                    f"",
                    f"- **Severity:** {finding.severity.upper()}",
                    f"- **Location:** `{finding.location}`",
                    f"- **Confidence:** {finding.confidence.value}",
                    f"",
                    f"**Description:**",
                    f"",
                    f"{finding.description}",
                    f"",
                    f"**Recommendation:**",
                    f"",
                    f"{finding.recommendation}",
                    f"",
                    f"---",
                    f"",
                ])
        else:
            md_lines.extend([
                f"No confirmed vulnerabilities found.",
                f"",
            ])

        md_lines.extend([
            f"## Analysis Details",
            f"",
            f"- **Provider:** {report.provider}",
            f"- **Model:** {report.model}",
            f"- **Debate Rounds:** {report.debate_rounds}",
        ])

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write("\n".join(md_lines))
