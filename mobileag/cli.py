"""Command-line interface for MobileAg."""

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel

from config.settings import get_settings
from mobileag.core.orchestrator import Orchestrator

console = Console()


@click.group()
def main():
    """MobileAg — Autonomous Mobile App Penetration Testing Framework."""
    pass


@main.command()
@click.option("--apk", required=True, help="Path to target APK file", type=click.Path(exists=True))
@click.option("--output", default="./output", help="Output directory for reports", type=click.Path())
def scan(apk: str, output: str):
    """Run a full security analysis on an APK."""
    console.print(Panel.fit(f"[bold blue]MobileAg Security Scan[/]\nTarget: {apk}", border_style="blue"))
    
    settings = get_settings()
    if not settings.enabled_providers:
        console.print("[bold red]Error:[/] No LLM providers configured. Set API keys in .env")
        sys.exit(1)
        
    orchestrator = Orchestrator(settings)
    
    try:
        # Run the async scan
        state = asyncio.run(orchestrator.scan(apk, output_dir=output))
        
        if state["errors"]:
            console.print("[bold yellow]Scan completed with warnings:[/]")
            for err in state["errors"]:
                console.print(f" - {err}")
                
        console.print(f"\n[bold green]Scan Complete![/] Report saved to: {state.get('report_path')}")
        
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan aborted by user.[/]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Fatal error during scan:[/] {e}")
        sys.exit(1)


@main.command()
@click.option("--old", required=True, help="Path to older APK version", type=click.Path(exists=True))
@click.option("--new", required=True, help="Path to newer APK version", type=click.Path(exists=True))
@click.option("--output", default="./output/diff", help="Output directory", type=click.Path())
def diff(old: str, new: str, output: str):
    """Compare two APK versions for security-relevant changes."""
    from mobileag.diffing.version_diff import VersionDiff
    
    console.print(Panel.fit(f"[bold blue]MobileAg Version Diff[/]\nOld: {old}\nNew: {new}", border_style="cyan"))
    
    settings = get_settings()
    differ = VersionDiff(settings)
    
    try:
        result = asyncio.run(differ.diff(old, new, output_dir=output))
        
        console.print("\n[bold]Security Notes:[/]")
        for note in result.get("security_notes", []):
            console.print(note)
            
        console.print(f"\n[green]Diff complete![/] Output saved to {output}")
        
    except Exception as e:
        console.print(f"\n[bold red]Error during diff:[/] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
