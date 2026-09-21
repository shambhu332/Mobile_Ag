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


@main.command()
@click.option("--host", default="127.0.0.1", help="Host address to bind to")
@click.option("--port", default=8080, help="Port to listen on", type=int)
def web(host: str, port: int):
    """Launch the MobileAg Enterprise AppSec Dashboard."""
    import socket
    from mobileag.web.app import run_server

    actual_port = port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
        except OSError:
            test_port = port + 1
            while test_port < port + 50:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
                    s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    try:
                        s2.bind((host, test_port))
                        actual_port = test_port
                        break
                    except OSError:
                        test_port += 1
            console.print(f"[bold yellow]Notice:[/] Port {port} is in use. Auto-switching to port [bold green]{actual_port}[/].")

    console.print(Panel.fit(
        f"[bold cyan]MobileAg Enterprise AppSec Dashboard[/]\n"
        f"URL: [link=http://{host}:{actual_port}]http://{host}:{actual_port}[/link]",
        border_style="cyan"
    ))
    try:
        run_server(host=host, port=actual_port)
    except KeyboardInterrupt:
        console.print("\n[yellow]Web dashboard stopped.[/]")


@main.command()
@click.option("--package", required=True, help="Target package name (e.g. com.example.app)")
@click.option("--serial", default=None, help="Device or emulator serial (default: auto-select first device)")
@click.option("--apk", default=None, help="Path to APK to install before dynamic testing", type=click.Path(exists=True))
@click.option("--activities", default=None, help="Comma-separated activity component names to exercise")
@click.option("--deeplinks", default=None, help="Comma-separated deep-link URIs to test")
@click.option("--output", default="./output/dast", help="Output directory for dynamic report", type=click.Path())
def dast(package: str, serial: str | None, apk: str | None, activities: str | None, deeplinks: str | None, output: str):
    """Run dynamic application security testing (DAST) on connected emulator or device."""
    import json
    from mobileag.dast import ADBManager, IntentFuzzer

    console.print(Panel.fit(
        f"[bold green]MobileAg Dynamic Security Testing (DAST)[/]\n"
        f"Target Package: [bold]{package}[/]\n"
        f"Device: {serial or 'Auto-Detecting'}",
        border_style="green"
    ))

    adb = ADBManager()
    fuzzer = IntentFuzzer(adb=adb)

    async def _run_dast():
        # Check device
        devices = await adb.list_devices()
        if not devices:
            console.print("[bold red]Error:[/] No Android devices or emulators detected via ADB.")
            console.print("[yellow]Hint:[/] Start your rooted emulator or run [cyan]adb connect 127.0.0.1:5555[/cyan]")
            sys.exit(1)

        target_serial = serial or devices[0].serial
        dev_info = next((d for d in devices if d.serial == target_serial), devices[0])

        console.print(f"[*] Connected to: [cyan]{dev_info.model}[/] ({target_serial})")
        console.print(f"[*] Android OS:   [cyan]{dev_info.android_version}[/] (SDK {dev_info.sdk_level})")
        console.print(f"[*] Root Status:  {'[bold green]# Root Shell (uid=0)[/]' if dev_info.is_rooted else '[yellow]Non-Root[/]'}")

        act_list = [a.strip() for a in activities.split(",")] if activities else [f"{package}.MainActivity"]
        dl_list = [d.strip() for d in deeplinks.split(",")] if deeplinks else []

        console.print(f"[*] Executing dynamic intent fuzzing across {len(act_list)} component(s)...")
        report = await fuzzer.run_full_dast_suite(
            serial=target_serial,
            package_name=package,
            apk_path=apk,
            activities=act_list,
            deeplinks=dl_list,
        )

        # Output summary
        out_dir = Path(output)
        out_dir.mkdir(parents=True, exist_ok=True)
        report_file = out_dir / f"dast_report_{package}.json"
        report_file.write_text(json.dumps(report, indent=2))

        console.print(f"\n[bold green]DAST Assessment Complete![/]")
        console.print(f" - Tests Executed:     [bold]{report['tests_run']}[/]")
        console.print(f" - Unhandled Crashes:  [bold red]{report['crashes_detected']}[/]")
        console.print(f" - Logcat Leaks:       [bold yellow]{report['leaks_detected']}[/]")
        console.print(f" - Full Report:        [link={report_file.resolve()}]{report_file.resolve()}[/link]\n")

    try:
        asyncio.run(_run_dast())
    except KeyboardInterrupt:
        console.print("\n[bold red]DAST assessment aborted by user.[/]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Error during DAST execution:[/] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

