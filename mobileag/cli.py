"""Command-line interface for MobileAg."""

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel

from config.settings import get_settings
from mobileag.core.orchestrator import Orchestrator
from mobileag.reporting.artifact_writer import create_private_artifact_exclusive, write_private_artifact
from mobileag.security.privacy import redact

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
@click.option("--lookup-advisories", is_flag=True,
              help="Explicitly authorize this scan to query OSV with parsed Maven/npm dependency coordinates")
def scan(app_path: str, output: str, report_format: str, offline: bool, lookup_advisories: bool):
    """Run a full security analysis on an Android APK or iOS IPA package."""
    is_ios = app_path.lower().endswith(".ipa")
    if offline and lookup_advisories:
        raise click.ClickException("--offline prohibits all network access; omit --lookup-advisories")
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
            report_data = redact([f.model_dump(mode="json") for f in findings])
            write_private_artifact(json_file, json.dumps(report_data, indent=2, ensure_ascii=True, allow_nan=False))
            console.print(f"\n[bold green]JSON Report saved to:[/] {json_file}")
        else:
            from mobileag.core.state import create_initial_state
            from mobileag.reporting.report_engine import ReportEngine
            state = create_initial_state("ios", app_path, str(out_dir))
            state["package_name"] = results.get("app_name", "ios_target")
            state["filtered_findings"] = [f.model_dump(mode="json") for f in findings]
            asyncio.run(ReportEngine().generate_reports(state))
            console.print(f"Report saved to: {state['report_path']}")
        return

    # Android APK Scan
    settings = get_settings().model_copy(update={"offline": offline or get_settings().offline})
    if not settings.enabled_providers or offline:
        console.print("[bold yellow]Offline Mode Active:[/] Running deterministic Smali bytecode call graph, AST heuristics, and rule engine (no cloud LLM required).")
    else:
        console.print(f"[bold green]LLM Hybrid Mode Active:[/] Configured providers: {', '.join(settings.enabled_providers)}")
    if lookup_advisories:
        console.print("[bold yellow]External advisory lookup authorized:[/] parsed Maven/npm coordinates and versions may be sent to OSV.")

    orchestrator = Orchestrator(settings)

    try:
        # Run the async scan
        state = asyncio.run(orchestrator.scan(app_path, output_dir=output,
                                              allow_advisory_lookup=lookup_advisories))

        if state.get("errors"):
            console.print("[bold yellow]Scan completed with warnings:[/]")
            for err in state["errors"]:
                console.print(f" - {err}")
            raise click.ClickException("Scan failed or incomplete; inspect errors above")

        if report_format.lower() == "sarif" and state.get("sarif_path"):
            console.print(f"\n[bold green]SARIF v2.1.0 Report saved to:[/] {state.get('sarif_path')}")
        else:
            report_key = "json_report_path" if report_format.lower() == "json" else "report_path"
            console.print(f"\n[bold green]Scan Complete![/] Report saved to: {state.get(report_key)}")

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
        report_data = redact([f.model_dump(mode="json") for f in findings])
        write_private_artifact(json_file, json.dumps(report_data, indent=2, ensure_ascii=True, allow_nan=False))
        console.print(f"\n[bold green]JSON Report saved to:[/] {json_file}")
    else:
        md_file = out_dir / "report_ios.md"
        md_content = f"# iOS Security Audit Report: {results.get('app_name', 'App')}\n\n"
        for f in findings:
            md_content += f"## [{f.severity.value}] {f.title} ({f.cwe_id})\n- Description: {f.description}\n- File: {f.file_path}\n- Remediation: {f.remediation}\n\n"
        write_private_artifact(md_file, redact(md_content))
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
    """Launch the MobileAg API."""
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
        f"[bold cyan]MobileAg Web Dashboard & API[/]\n"
        f"URL: [bold green]http://{host}:{actual_port}[/]\n"
        f"Open in your browser to access the full UI/UX dashboard.",
        border_style="cyan"
    ))
    try:
        run_server(host=host, port=actual_port)
    except KeyboardInterrupt:
        console.print("\n[yellow]Web API stopped.[/]")


@main.command()
@click.option("--package", required=True, help="Target package name (e.g. com.example.app)")
@click.option("--serial", default=None, help="Legacy option; this full DAST command is disabled")
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
    raise click.ClickException(
        "Legacy full DAST suite disabled: use individually approved API actions; "
        "no device was selected or contacted."
    )


@main.command()
@click.option("--src", required=True, help="Path to decompiled source directory (Java/Kotlin)", type=click.Path(exists=True))
@click.option("--output", default="./output/taint", help="Output directory for taint analysis report", type=click.Path())
def taint(src: str, output: str):
    """Find potential straight-line source-to-sink flows for manual review."""
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
    report_data = redact([f.to_dict() for f in findings])
    write_private_artifact(report_file, json.dumps(report_data, indent=2, ensure_ascii=True, allow_nan=False))

    console.print(f"\n[bold green]Taint Analysis Complete![/]")
    console.print(f" - Sinks Tainted: [bold red]{len(findings)}[/]")
    console.print(f" - Report Saved:  [link={report_file.resolve()}]{report_file.resolve()}[/link]\n")


@main.command("import-sarif")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False),
              help="New JSON path for untrusted imported candidates; existing files are never overwritten.")
def import_sarif_command(input_path: str, output_path: str):
    """Validate SARIF 2.1.0 offline and project bounded unverified candidates."""
    import json
    from mobileag.reporting.sarif_importer import MAX_BYTES, SarifImportError, import_sarif

    try:
        with Path(input_path).open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        result = import_sarif(raw)
        create_private_artifact_exclusive(
            output_path, json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False) + "\n",
        )
    except (OSError, SarifImportError) as exc:
        raise click.ClickException(str(exc)) from None
    console.print(f"Imported {result['imported_candidates']} unverified candidate(s); "
                  f"skipped {result['duplicates_skipped']} duplicate(s) and "
                  f"{result['invalid_or_nonfinding_results_skipped']} invalid/non-finding result(s).")
    console.print(f"Candidate projection saved to: {output_path}")


@main.command("import-mobsf-json")
@click.option("--input", "input_path", required=True,
              type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False),
              help="New JSON path for untrusted imported candidates; existing files are never overwritten.")
def import_mobsf_json_command(input_path: str, output_path: str):
    """Project a bounded MobSF Android static-report subset offline as unverified candidates."""
    import json
    from mobileag.reporting.mobsf_importer import MAX_BYTES, MobSFImportError, import_mobsf_json

    try:
        with Path(input_path).open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        result = import_mobsf_json(raw)
        create_private_artifact_exclusive(
            output_path, json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False) + "\n",
        )
    except (OSError, MobSFImportError) as exc:
        raise click.ClickException(str(exc)) from None
    console.print(f"Imported {result['imported_candidates']} unverified candidate(s); "
                  f"skipped {result['duplicates_skipped']} duplicate(s) and "
                  f"{result['invalid_or_nonfinding_results_skipped']} invalid/non-finding result(s).")
    console.print(f"Candidate projection saved to: {output_path}")


@main.command("inventory-aab")
@click.option("--input", "input_path", required=True,
              type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False),
              help="New JSON path for bounded inventory; existing files are never overwritten.")
def inventory_aab_command(input_path: str, output_path: str):
    """Inventory AAB modules and DEX/native inputs without analyzing or extracting them."""
    import json
    from mobileag.ingestion.aab_inventory import inventory_android_app_bundle

    try:
        result = inventory_android_app_bundle(input_path)
        create_private_artifact_exclusive(
            output_path, json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False) + "\n",
        )
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from None
    console.print(f"Inventoried {result['module_count']} module(s), "
                  f"{result['dex_member_count']} DEX input(s), and "
                  f"{result['native_library_member_count']} native library input(s).")
    console.print("Inventory only: no manifest protobuf decoding, APK generation, or security analysis was performed.")
    console.print(f"Inventory saved to: {output_path}")


from mobileag.dashboard.commands import dashboard
main.add_command(dashboard)


if __name__ == "__main__":
    main()
