"""CLI entry point for App X-Ray."""

import os
import sys

import click

from app_xray import __version__


@click.group()
@click.version_option(version=__version__)
def main():
    """App X-Ray: Automated Android APK privacy auditor."""


@main.command()
@click.argument("apk_path", type=click.Path(exists=True))
@click.option("--format", "output_format", type=click.Choice(["terminal", "html", "json"]), default="terminal")
@click.option("--output", "-o", "output_path", type=click.Path(), help="Output file path (for html/json)")
@click.option("--trace/--no-trace", default=False, help="Trace network call paths (slower)")
def scan(apk_path: str, output_format: str, output_path: str | None, trace: bool):
    """Scan an APK file and generate a privacy audit report."""
    if not apk_path.endswith(".apk"):
        click.echo("Error: File must be an .apk file", err=True)
        sys.exit(1)

    from app_xray.analyzer import analyze_apk

    report = analyze_apk(apk_path, trace_network=trace)

    if output_format == "terminal":
        from app_xray.reporters.terminal import print_report
        print_report(report)
    elif output_format == "html":
        from app_xray.reporters.html import generate_html
        html = generate_html(report)
        dest = output_path or "report.html"
        with open(dest, "w") as f:
            f.write(html)
        click.echo(f"HTML report written to {dest}")
    elif output_format == "json":
        from app_xray.reporters.json_out import to_json
        output = to_json(report)
        if output_path:
            with open(output_path, "w") as f:
                f.write(output)
            click.echo(f"JSON report written to {output_path}")
        else:
            click.echo(output)


@main.command()
@click.argument("old_apk", type=click.Path(exists=True))
@click.argument("new_apk", type=click.Path(exists=True))
def diff(old_apk: str, new_apk: str):
    """Compare two APK versions and show privacy changes."""
    from app_xray.analyzer import analyze_apk
    from app_xray.reporters.diff import print_diff

    old_report = analyze_apk(old_apk)
    new_report = analyze_apk(new_apk)
    print_diff(old_report, new_report)


if __name__ == "__main__":
    main()
