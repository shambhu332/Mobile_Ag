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
@click.option("--apk", "--app", "app_path", required=True, help="Path to target APK or IPA file", type=click.Path(exists=True))
@click.option("--output", default="./output", help="Output directory for reports", type=click.Path())
@click.option("--format", "report_format", default="markdown", type=click.Choice(["markdown", "json", "sarif"], case_sensitive=False), help="Report output format")
@click.option("--offline", is_flag=True, help="Enforce deterministic offline analysis (no cloud LLM API calls)")
def scan(app_path: str, output: str, report_format: str, offline: bool):
    """Run a full security analysis on an Android APK or iOS IPA package."""
    is_ios = app_path.lower().endswith(".ipa")
    platform_name = "iOS IPA" if is_ios else "Android APK"

    console.print(Panel.fit(
        f"[bold cyan]MobileAg Enterprise Security Scan[/]\n"
        f"Target: [bold white]{app_path}[/]\n"
        f"Platform: [bold green]{platform_name}[/]\n"
        f"Format: [bold magenta]{report_format.upper()}[/]",
        border_style="cyan"
    ))

    # If iOS IPA package
    if is_ios:
        from mobileag.analysis.ios_analyzer import IOSSecurityAnalyzer
        from mobileag.reporting.sarif_exporter import SARIFExporter
        import json

        analyzer = IOSSecurityAnalyzer()
        out_dir = Path(output)
        out_dir.mkdir(parents=True, exist_ok=True)

        console.print("[bold yellow][*][/] Running iOS static security audit (Info.plist, ATS, Mach-O flags)...")
        results = analyzer.audit_ipa(app_path, out_dir / "ios_extract")
        findings = results.get("findings", [])

        console.print(f"\n[bold green]Scan Complete![/] Found {len(findings)} iOS security findings.")
        for f in findings:
            sev_color = "red" if f.severity.value in ("CRITICAL", "HIGH") else "yellow"
            console.print(f" • [{sev_color}][{f.severity.value}][/] {f.title} ({f.cwe_id})")

        if report_format.lower() == "sarif":
            sarif_file = out_dir / "report_ios.sarif"
            SARIFExporter.export_to_file(findings, sarif_file, results.get("app_name", "ios_target"))
            console.print(f"\n[bold green]SARIF v2.1.0 Report saved to:[/] {sarif_file}")
        elif report_format.lower() == "json":
            json_file = out_dir / "report_ios.json"
            json_file.write_text(json.dumps([f.model_dump() for f in findings], indent=2))
            console.print(f"\n[bold green]JSON Report saved to:[/] {json_file}")
        return

    # Android APK Scan
    settings = get_settings()
    if not settings.enabled_providers or offline:
        console.print("[bold yellow]Offline Mode Active:[/] Running deterministic Smali bytecode call graph, AST heuristics, and rule engine (no cloud LLM required).")
    else:
        console.print(f"[bold green]LLM Hybrid Mode Active:[/] Configured providers: {', '.join(settings.enabled_providers)}")

    orchestrator = Orchestrator(settings)

    try:
        # Run the async scan
        state = asyncio.run(orchestrator.scan(app_path, output_dir=output))

        if state.get("errors"):
            console.print("[bold yellow]Scan completed with warnings:[/]")
            for err in state["errors"]:
                console.print(f" - {err}")

        if report_format.lower() == "sarif" and state.get("sarif_path"):
            console.print(f"\n[bold green]SARIF v2.1.0 Report saved to:[/] {state.get('sarif_path')}")
        else:
            console.print(f"\n[bold green]Scan Complete![/] Report saved to: {state.get('report_path')}")

    except KeyboardInterrupt:
        console.print("\n[bold red]Scan aborted by user.[/]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Fatal error during scan:[/] {e}")
        sys.exit(1)


@main.command()
@click.option("--ipa", required=True, help="Path to target iOS IPA file", type=click.Path(exists=True))
@click.option("--output", default="./output/ios", help="Output directory for reports", type=click.Path())
@click.option("--format", "report_format", default="markdown", type=click.Choice(["markdown", "json", "sarif"], case_sensitive=False))
def ios(ipa: str, output: str, report_format: str):
    """Run static security analysis on an iOS IPA application package."""
    from mobileag.analysis.ios_analyzer import IOSSecurityAnalyzer
    from mobileag.reporting.sarif_exporter import SARIFExporter
    import json

    console.print(Panel.fit(
        f"[bold cyan]MobileAg iOS Security Audit[/]\n"
        f"IPA: [bold white]{ipa}[/]\n"
        f"Format: [bold magenta]{report_format.upper()}[/]",
        border_style="cyan"
    ))

    analyzer = IOSSecurityAnalyzer()
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)

    results = analyzer.audit_ipa(ipa, out_dir / "extract")
    findings = results.get("findings", [])

    console.print(f"\n[bold green]Scan Complete![/] Found {len(findings)} iOS security findings.")
    for f in findings:
        sev_color = "red" if f.severity.value in ("CRITICAL", "HIGH") else "yellow"
        console.print(f" • [{sev_color}][{f.severity.value}][/] {f.title} ({f.cwe_id})")

    if report_format.lower() == "sarif":
        sarif_file = out_dir / "report_ios.sarif"
        SARIFExporter.export_to_file(findings, sarif_file, results.get("app_name", "ios_target"))
        console.print(f"\n[bold green]SARIF v2.1.0 Report saved to:[/] {sarif_file}")
    elif report_format.lower() == "json":
        json_file = out_dir / "report_ios.json"
        json_file.write_text(json.dumps([f.model_dump() for f in findings], indent=2))
        console.print(f"\n[bold green]JSON Report saved to:[/] {json_file}")
    else:
        md_file = out_dir / "report_ios.md"
        md_content = f"# iOS Security Audit Report: {results.get('app_name', 'App')}\n\n"
        for f in findings:
            md_content += f"## [{f.severity.value}] {f.title} ({f.cwe_id})\n- Description: {f.description}\n- File: {f.file_path}\n- Remediation: {f.remediation}\n\n"
        md_file.write_text(md_content)
        console.print(f"\n[bold green]Markdown Report saved to:[/] {md_file}")


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
@click.option("--authorities", default=None, help="Comma-separated ContentProvider authorities to audit")
@click.option("--audit-storage/--no-audit-storage", default=True, help="Audit sandbox SharedPreferences & SQLite on rooted device")
@click.option("--audit-memory/--no-audit-memory", default=True, help="Audit volatile process memory for cleartext credentials (CWE-316)")
@click.option("--crawl-ui/--no-crawl-ui", default=False, help="Autonomously explore UI views with UIAutomator")
@click.option("--output", default="./output/dast", help="Output directory for dynamic report", type=click.Path())
def dast(package: str, serial: str | None, apk: str | None, activities: str | None, deeplinks: str | None, authorities: str | None, audit_storage: bool, audit_memory: bool, crawl_ui: bool, output: str):
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
        auth_list = [p.strip() for p in authorities.split(",")] if authorities else []

        console.print(f"[*] Executing dynamic intent fuzzing across {len(act_list)} component(s)...")
        report = await fuzzer.run_full_dast_suite(
            serial=target_serial,
            package_name=package,
            apk_path=apk,
            activities=act_list,
            deeplinks=dl_list,
            authorities=auth_list,
            audit_storage=audit_storage,
            audit_memory=audit_memory,
            crawl_ui=crawl_ui,
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
        console.print(f" - Storage Flaws:      [bold magenta]{report.get('storage_flaws_detected', 0)}[/]")
        console.print(f" - Provider Flaws:     [bold red]{report.get('provider_flaws_detected', 0)}[/]")
        console.print(f" - Memory Flaws:       [bold yellow]{report.get('memory_flaws_detected', 0)}[/]")
        console.print(f" - Full Report:        [link={report_file.resolve()}]{report_file.resolve()}[/link]\n")


    try:
        asyncio.run(_run_dast())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]DAST test interrupted by user.[/]")
    except Exception as e:
        console.print(f"[bold red]DAST failed:[/] {e}")
        sys.exit(1)


@main.command()
@click.option("--src", required=True, help="Path to decompiled source directory (Java/Kotlin)", type=click.Path(exists=True))
@click.option("--output", default="./output/taint", help="Output directory for taint analysis report", type=click.Path())
def taint(src: str, output: str):
    """Run inter-procedural static source-to-sink taint analysis."""
    import json
    from mobileag.analysis import TaintEngine

    console.print(Panel.fit(
        f"[bold green]MobileAg Static Taint & Dataflow Engine[/]\n"
        f"Source Directory: [bold]{src}[/]",
        border_style="green"
    ))

    engine = TaintEngine()
    findings = engine.analyze_directory(src)

    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)
    report_file = out_dir / "taint_findings.json"
    report_file.write_text(json.dumps([f.to_dict() for f in findings], indent=2))

    console.print(f"\n[bold green]Taint Analysis Complete![/]")
    console.print(f" - Sinks Tainted: [bold red]{len(findings)}[/]")
    console.print(f" - Report Saved:  [link={report_file.resolve()}]{report_file.resolve()}[/link]\n")


if __name__ == "__main__":
    main()
