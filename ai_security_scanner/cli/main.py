"""Main CLI interface for the AI Security Scanner."""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from ai_security_scanner.core.config import Config, load_config
from ai_security_scanner.core.llm.analyzer import VulnerabilityAnalyzer
from ai_security_scanner.core.scanner import SecurityScanner
from ai_security_scanner.integrations.github import GitHubIntegration
from ai_security_scanner.integrations.sarif import SARIFExporter
from ai_security_scanner.utils.logging import setup_logging

console = Console()


@click.group()
@click.option("--config", "-c", type=click.Path(exists=True), help="Configuration file path")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.option("--debug", is_flag=True, help="Enable debug logging")
@click.pass_context
def cli(ctx: click.Context, config: Optional[str], verbose: bool, debug: bool) -> None:
    """AI-Powered Code Security Scanner.

    An intelligent security scanner that combines traditional SAST analysis
    with AI-powered vulnerability detection and explanation.
    """
    # Ensure that ctx.obj exists and is a dict
    ctx.ensure_object(dict)

    # Load configuration
    try:
        ctx.obj["config"] = load_config(config)

        # Override debug setting if provided
        if debug:
            ctx.obj["config"].debug = True
            ctx.obj["config"].log_level = "DEBUG"
        elif verbose:
            ctx.obj["config"].log_level = "INFO"

    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        sys.exit(1)

    # Setup logging
    setup_logging(ctx.obj["config"].log_level, ctx.obj["config"].debug)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    type=click.Choice(["json", "sarif", "table"]),
    default="table",
    help="Output format",
)
@click.option("--file", "-f", type=click.Path(), help="Output file path")
@click.option(
    "--severity",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    help="Minimum severity level",
)
@click.option(
    "--language", "-l", multiple=True, help="Languages to scan (can be specified multiple times)"
)
@click.option("--no-ai", is_flag=True, help="Disable AI analysis")
@click.option("--github-repo", help="GitHub repository (owner/repo)")
@click.option("--branch", help="Git branch to scan")
@click.pass_context
def scan(
    ctx: click.Context,
    path: str,
    output: str,
    file: Optional[str],
    severity: Optional[str],
    language: tuple,
    no_ai: bool,
    github_repo: Optional[str],
    branch: Optional[str],
) -> None:
    """Scan a directory or file for security vulnerabilities."""
    config: Config = ctx.obj["config"]

    # Override AI analysis setting
    if no_ai:
        config.scanner.enable_ai_analysis = False

    # Override languages if specified
    if language:
        config.scanner.languages = list(language)

    try:
        # Run scan
        result = asyncio.run(_run_scan(config, path, github_repo, branch))

        # Filter by severity if specified
        if severity:
            from ai_security_scanner.core.models import Severity

            min_severity = Severity(severity)
            severity_order = {
                Severity.LOW: 0,
                Severity.MEDIUM: 1,
                Severity.HIGH: 2,
                Severity.CRITICAL: 3,
            }
            min_level = severity_order[min_severity]

            result.vulnerabilities = [
                vuln
                for vuln in result.vulnerabilities
                if severity_order[vuln.severity] >= min_level
            ]

        # Output results
        if output == "json":
            output_json(result, file)
        elif output == "sarif":
            output_sarif(result, file)
        else:
            output_table(result)

    except Exception as e:
        console.print(f"[red]Error during scan: {e}[/red]")
        if config.debug:
            import traceback

            console.print(traceback.format_exc())
        sys.exit(1)


async def _run_scan(
    config: Config, path: str, github_repo: Optional[str], branch: Optional[str]
) -> "ScanResult":
    """Run the security scan asynchronously."""
    scanner = SecurityScanner(config)

    # Show scan progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        scan_task = progress.add_task("Scanning for vulnerabilities...", total=None)

        # Scan directory
        if Path(path).is_dir():
            result = await scanner.scan_directory_async(path)
        else:
            vulnerabilities = scanner.scan_file(path)
            import uuid
            from datetime import datetime

            from ai_security_scanner.core.models import ScanResult

            result = ScanResult(
                scan_id=str(uuid.uuid4()),
                repository_url=None,
                repository_name=Path(path).name,
                branch=branch,
                commit_hash=None,
                scan_timestamp=datetime.now(),
                vulnerabilities=vulnerabilities,
                scan_duration=0.0,
                files_scanned=1,
                total_lines_scanned=0,
                scanner_version="0.1.0",
                configuration=config.to_dict(),
                metrics={},
            )

        progress.update(scan_task, description="Running AI analysis...")

        # Run AI analysis if enabled
        if config.scanner.enable_ai_analysis and result.vulnerabilities:
            analyzer = VulnerabilityAnalyzer(config)

            # Get source code for context
            source_code = ""
            if Path(path).is_file():
                with open(path, "r", encoding="utf-8") as f:
                    source_code = f.read()

            context = {
                "language": config.scanner.languages[0] if config.scanner.languages else "unknown",
                "file_path": path,
                "github_repo": github_repo,
                "branch": branch,
            }

            result.vulnerabilities = await analyzer.analyze_vulnerabilities(
                result.vulnerabilities, source_code, context
            )

        progress.update(scan_task, completed=True)

    return result


def output_json(result: "ScanResult", file: Optional[str]) -> None:
    """Output results in JSON format."""
    output_data = result.to_dict()

    if file:
        with open(file, "w") as f:
            json.dump(output_data, f, indent=2, default=str)
        console.print(f"[green]Results saved to {file}[/green]")
    else:
        console.print(json.dumps(output_data, indent=2, default=str))


def output_sarif(result: "ScanResult", file: Optional[str]) -> None:
    """Output results in SARIF format."""
    exporter = SARIFExporter()
    sarif_data = exporter.export(result)

    if file:
        with open(file, "w") as f:
            json.dump(sarif_data, f, indent=2)
        console.print(f"[green]SARIF report saved to {file}[/green]")
    else:
        console.print(json.dumps(sarif_data, indent=2))


def output_table(result: "ScanResult") -> None:
    """Output results in table format."""
    # Summary panel
    summary_text = Text()
    summary_text.append(f"Files Scanned: {result.files_scanned}\n")
    summary_text.append(f"Lines Scanned: {result.total_lines_scanned}\n")
    summary_text.append(f"Vulnerabilities Found: {len(result.vulnerabilities)}\n")
    summary_text.append(f"Scan Duration: {result.scan_duration:.2f}s\n")

    console.print(Panel(summary_text, title="Scan Summary", border_style="blue"))

    if not result.vulnerabilities:
        console.print("[green]No vulnerabilities found![/green]")
        return

    # Vulnerabilities table
    table = Table(title="Security Vulnerabilities")
    table.add_column("Severity", style="bold")
    table.add_column("Type", style="cyan")
    table.add_column("File", style="magenta")
    table.add_column("Line", justify="right")
    table.add_column("Description", style="white")
    table.add_column("Confidence", style="yellow")

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_vulnerabilities = sorted(
        result.vulnerabilities, key=lambda v: severity_order.get(v.severity.value, 4)
    )

    for vuln in sorted_vulnerabilities:
        # Color severity based on level
        severity_color = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "LOW": "green"}

        severity_text = Text(vuln.severity.value)
        severity_text.stylize(severity_color.get(vuln.severity.value, "white"))

        table.add_row(
            severity_text,
            vuln.vulnerability_type,
            vuln.location.file_path,
            str(vuln.location.line_number),
            vuln.description[:100] + "..." if len(vuln.description) > 100 else vuln.description,
            vuln.confidence.value,
        )

    console.print(table)

    # Show AI analysis if available
    ai_analyzed = sum(1 for vuln in result.vulnerabilities if vuln.ai_explanation)
    if ai_analyzed > 0:
        console.print(
            f"\n[blue]AI Analysis: {ai_analyzed}/{len(result.vulnerabilities)} vulnerabilities analyzed with AI[/blue]"
        )


@cli.command()
@click.argument("repo", help="GitHub repository (owner/repo)")
@click.option("--branch", help="Branch to scan (default: main)")
@click.option(
    "--output",
    "-o",
    type=click.Choice(["json", "sarif", "table"]),
    default="table",
    help="Output format",
)
@click.option("--file", "-f", type=click.Path(), help="Output file path")
@click.pass_context
def github(
    ctx: click.Context, repo: str, branch: Optional[str], output: str, file: Optional[str]
) -> None:
    """Scan a GitHub repository for vulnerabilities."""
    config: Config = ctx.obj["config"]

    try:
        # Initialize GitHub integration
        github_integration = GitHubIntegration(config)

        # Download and scan repository
        with console.status("[bold green]Downloading repository..."):
            result = asyncio.run(github_integration.scan_repository(repo, branch))

        # Output results
        if output == "json":
            output_json(result, file)
        elif output == "sarif":
            output_sarif(result, file)
        else:
            output_table(result)

    except Exception as e:
        console.print(f"[red]Error scanning GitHub repository: {e}[/red]")
        if config.debug:
            import traceback

            console.print(traceback.format_exc())
        sys.exit(1)


@cli.command()
@click.pass_context
def config_info(ctx: click.Context) -> None:
    """Display configuration information."""
    config: Config = ctx.obj["config"]

    # Configuration table
    table = Table(title="Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Debug Mode", str(config.debug))
    table.add_row("Log Level", config.log_level)
    table.add_row("LLM Provider", config.llm.provider)
    table.add_row("LLM Model", config.llm.model)
    table.add_row("Supported Languages", ", ".join(config.scanner.languages))
    table.add_row("AI Analysis", str(config.scanner.enable_ai_analysis))
    table.add_row("False Positive Reduction", str(config.scanner.false_positive_reduction))
    table.add_row("Confidence Threshold", str(config.scanner.confidence_threshold))

    console.print(table)


@cli.command()
@click.argument("code", help="Code snippet to analyze")
@click.option("--language", "-l", required=True, help="Programming language")
@click.option("--type", "-t", help="Vulnerability type to check for")
@click.pass_context
def analyze(ctx: click.Context, code: str, language: str, type: Optional[str]) -> None:
    """Analyze a code snippet for vulnerabilities."""
    config: Config = ctx.obj["config"]

    try:
        scanner = SecurityScanner(config)
        vulnerabilities = scanner.scan_code(code, language)

        if type:
            vulnerabilities = [v for v in vulnerabilities if v.vulnerability_type == type]

        if not vulnerabilities:
            console.print("[green]No vulnerabilities found in the code snippet![/green]")
            return

        # Display vulnerabilities
        for vuln in vulnerabilities:
            panel_content = Text()
            panel_content.append(f"Type: {vuln.vulnerability_type}\n")
            panel_content.append(f"Severity: {vuln.severity.value}\n")
            panel_content.append(f"Confidence: {vuln.confidence.value}\n")
            panel_content.append(f"Description: {vuln.description}\n")

            if vuln.remediation:
                panel_content.append(f"Remediation: {vuln.remediation}\n")

            if vuln.ai_explanation:
                panel_content.append(f"AI Analysis: {vuln.ai_explanation}\n")

            console.print(Panel(panel_content, title="Vulnerability Found", border_style="red"))

    except Exception as e:
        console.print(f"[red]Error analyzing code: {e}[/red]")
        if config.debug:
            import traceback

            console.print(traceback.format_exc())
        sys.exit(1)


@cli.command()
@click.pass_context
def version(ctx: click.Context) -> None:
    """Display version information."""
    from ai_security_scanner import __version__

    console.print(f"AI Security Scanner v{__version__}")


def main() -> None:
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
