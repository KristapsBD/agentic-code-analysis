"""
CLI entry point for the Adversarial Agent System.

Provides commands for analyzing smart contracts, running evaluations,
and comparing results across different LLM providers.
"""

import asyncio
import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.config import LLMProvider, settings, setup_logging
from src.orchestration.debate_manager import DebateManager
from src.output.evaluator import Evaluator
from src.output.report import ReportGenerator
from src.providers.provider_factory import ProviderFactory

# Setup logging
setup_logging(settings.log_level)
logger = logging.getLogger(__name__)

app = typer.Typer(
    name="sca",
    help="Smart Contract Analyzer - Adversarial Agent System for Vulnerability Detection",
    add_completion=False,
)
console = Console()


def print_banner() -> None:
    """Print the application banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║     Smart Contract Analyzer - Adversarial Agent System        ║
║         Multi-Agent LLM Vulnerability Detection               ║
╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(Panel(banner, style="bold blue"))


@app.command()
def analyze(
    contract_path: Path = typer.Argument(
        ...,
        help="Path to the smart contract file to analyze",
        exists=True,
        readable=True,
    ),
    provider: LLMProvider = typer.Option(
        settings.default_provider,
        "--provider",
        "-p",
        help="LLM provider to use",
    ),
    rounds: int = typer.Option(
        settings.default_debate_rounds,
        "--rounds",
        "-r",
        help="Number of debate rounds",
        min=1,
        max=5,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path for the report (JSON format)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose output",
    ),
) -> None:
    """
    Analyze a smart contract for vulnerabilities using adversarial debate.

    The system uses three agents (Attacker, Defender, Judge) to identify
    and verify potential security issues in the contract.
    """
    print_banner()

    try:
        settings.validate_provider_config(provider)
    except ValueError as e:
        console.print(f"[red]Configuration Error:[/red] {e}")
        raise typer.Exit(code=1)

    logger.info(f"Starting analysis of contract: {contract_path}")
    logger.info(f"Provider: {provider.value}, Rounds: {rounds}")
    logger.debug(f"Verbose mode: {verbose}")
    
    console.print(f"[cyan]Analyzing:[/cyan] {contract_path}")
    console.print(f"[cyan]Provider:[/cyan] {provider.value}")
    console.print(f"[cyan]Debate Rounds:[/cyan] {rounds}")
    console.print()

    # Read the contract
    contract_code = contract_path.read_text()

    # Run the analysis
    with console.status("[bold green]Running adversarial analysis...") as status:
        result = asyncio.run(
            _run_analysis(contract_code, str(contract_path), provider, rounds, verbose, status)
        )

    # Generate and display report
    report_generator = ReportGenerator()
    report = report_generator.generate(result, str(contract_path))

    console.print()
    report_generator.print_to_console(report, console)

    # Save report if output path specified
    if output:
        report_generator.save_json(report, output)
        console.print(f"\n[green]Report saved to:[/green] {output}")


async def _run_analysis(
    contract_code: str,
    contract_path: str,
    provider: LLMProvider,
    rounds: int,
    verbose: bool,
    status: "rich.status.Status",
) -> dict:
    """Run the adversarial analysis asynchronously."""
    logger.debug(f"Creating LLM provider: {provider.value}")
    # Create provider
    llm_provider = ProviderFactory.create(provider)
    logger.debug(f"Provider created: {llm_provider.provider_name}")

    # Create debate manager
    logger.debug(f"Initializing DebateManager with {rounds} rounds")
    debate_manager = DebateManager(
        provider=llm_provider,
        max_rounds=rounds,
        verbose=verbose,
    )

    # Run debate
    status.update("[bold green]Attacker scanning for vulnerabilities...")
    logger.info("Starting adversarial debate...")
    result = await debate_manager.run_debate(contract_code, contract_path)
    logger.info(f"Debate complete - {len(result.get('vulnerabilities', []))} vulnerabilities found")

    return result


@app.command()
def evaluate(
    benchmark_dir: Path = typer.Argument(
        ...,
        help="Path to the benchmark directory containing smart contracts",
        exists=True,
        dir_okay=True,
        file_okay=False,
    ),
    provider: LLMProvider = typer.Option(
        settings.default_provider,
        "--provider",
        "-p",
        help="LLM provider to use",
    ),
    output: Path = typer.Option(
        Path("data/results/evaluation.json"),
        "--output",
        "-o",
        help="Output file path for evaluation results",
    ),
    rounds: int = typer.Option(
        settings.default_debate_rounds,
        "--rounds",
        "-r",
        help="Number of debate rounds per contract",
        min=1,
        max=5,
    ),
) -> None:
    """
    Evaluate the system against a benchmark dataset.

    Runs analysis on all contracts in the benchmark directory and
    calculates precision, recall, and F1 scores.
    """
    print_banner()

    try:
        settings.validate_provider_config(provider)
    except ValueError as e:
        console.print(f"[red]Configuration Error:[/red] {e}")
        raise typer.Exit(code=1)

    console.print(f"[cyan]Benchmark Directory:[/cyan] {benchmark_dir}")
    console.print(f"[cyan]Provider:[/cyan] {provider.value}")
    console.print()

    # Run evaluation
    with console.status("[bold green]Running evaluation..."):
        evaluator = Evaluator(provider=provider, max_rounds=rounds)
        results = asyncio.run(evaluator.evaluate_benchmark(benchmark_dir))

    # Display results
    evaluator.print_results(results, console)

    # Save results
    output.parent.mkdir(parents=True, exist_ok=True)
    evaluator.save_results(results, output)
    console.print(f"\n[green]Results saved to:[/green] {output}")


@app.command()
def compare(
    contract_path: Path = typer.Argument(
        ...,
        help="Path to the smart contract file to analyze",
        exists=True,
        readable=True,
    ),
    rounds: int = typer.Option(
        settings.default_debate_rounds,
        "--rounds",
        "-r",
        help="Number of debate rounds",
        min=1,
        max=5,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path for comparison results",
    ),
) -> None:
    """
    Compare vulnerability detection results across different LLM providers.

    Runs the same analysis using OpenAI, Anthropic, and Gemini, then
    presents a side-by-side comparison of the findings.
    """
    print_banner()

    # Validate all providers
    providers_to_test = []
    for provider in [LLMProvider.OPENAI, LLMProvider.ANTHROPIC, LLMProvider.GEMINI]:
        try:
            settings.validate_provider_config(provider)
            providers_to_test.append(provider)
        except ValueError:
            console.print(f"[yellow]Warning:[/yellow] {provider.value} not configured, skipping")

    if len(providers_to_test) < 2:
        console.print("[red]Error:[/red] Need at least 2 providers configured for comparison")
        raise typer.Exit(code=1)

    console.print(f"[cyan]Analyzing:[/cyan] {contract_path}")
    console.print(f"[cyan]Providers:[/cyan] {', '.join(p.value for p in providers_to_test)}")
    console.print()

    contract_code = contract_path.read_text()
    results = {}

    for provider in providers_to_test:
        with console.status(f"[bold green]Analyzing with {provider.value}..."):
            result = asyncio.run(
                _run_analysis(contract_code, str(contract_path), provider, rounds, False, None)
            )
            results[provider.value] = result

    # Display comparison
    _display_comparison(results, console)

    if output:
        import json
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(results, indent=2, default=str))
        console.print(f"\n[green]Comparison saved to:[/green] {output}")


def _display_comparison(results: dict, console: Console) -> None:
    """Display a comparison table of results from different providers."""
    table = Table(title="Provider Comparison", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan")

    for provider in results.keys():
        table.add_column(provider.title(), justify="center")

    # Add rows for key metrics
    metrics = ["total_vulnerabilities", "confirmed_vulnerabilities", "debate_rounds"]
    for metric in metrics:
        row = [metric.replace("_", " ").title()]
        for provider in results.keys():
            value = results[provider].get(metric, "N/A")
            row.append(str(value))
        table.add_row(*row)

    console.print()
    console.print(table)


@app.command()
def info() -> None:
    """Display system configuration and status."""
    print_banner()

    table = Table(title="Configuration", show_header=True, header_style="bold magenta")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Default Provider", settings.default_provider.value)
    table.add_row("OpenAI Model", settings.default_model_openai)
    table.add_row("Anthropic Model", settings.default_model_anthropic)
    table.add_row("Gemini Model", settings.default_model_gemini)
    table.add_row("Debate Rounds", str(settings.default_debate_rounds))
    table.add_row("Temperature", str(settings.default_temperature))
    table.add_row("Log Level", settings.log_level)

    # API Key status
    openai_status = "✓ Configured" if settings.openai_api_key else "✗ Not Set"
    anthropic_status = "✓ Configured" if settings.anthropic_api_key else "✗ Not Set"
    gemini_status = "✓ Configured" if settings.gemini_api_key else "✗ Not Set"
    table.add_row("OpenAI API Key", openai_status)
    table.add_row("Anthropic API Key", anthropic_status)
    table.add_row("Gemini API Key", gemini_status)

    console.print(table)


if __name__ == "__main__":
    app()
