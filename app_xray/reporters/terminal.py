"""Rich terminal report output."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from app_xray.models import AuditReport


def _format_size(size: int) -> str:
    if size >= 1_000_000:
        return f"{size / 1_000_000:.1f} MB"
    if size >= 1_000:
        return f"{size / 1_000:.1f} KB"
    return f"{size} B"


def print_report(report: AuditReport):
    """Print a colored terminal report."""
    console = Console()
    info = report.apk_info

    # Header
    console.print()
    console.print(Panel(
        f"[bold]{info.package_name}[/bold]  v{info.version_name} (code {info.version_code})\n"
        f"Target SDK: {info.target_sdk}  |  Min SDK: {info.min_sdk}  |  "
        f"Size: {_format_size(info.file_size)}\n"
        f"SHA-256: {info.sha256[:16]}...{info.sha256[-8:]}",
        title="[bold cyan]App X-Ray Report[/bold cyan]",
        border_style="cyan",
    ))

    # Privacy Score
    if report.privacy_score is not None:
        score = report.privacy_score
        if score >= 80:
            color = "green"
        elif score >= 50:
            color = "yellow"
        else:
            color = "red"
        console.print(f"\n  [{color} bold]Privacy Score: {score}/100[/{color} bold]")
        if report.score_breakdown:
            for key, val in report.score_breakdown.items():
                if val != 0:
                    sign = "+" if val > 0 else ""
                    console.print(f"    {key}: {sign}{val}")

    # Permissions
    console.print()
    perm_table = Table(title="Permissions", show_lines=False)
    perm_table.add_column("Permission", style="white")
    perm_table.add_column("Level", justify="center")
    perm_table.add_column("Used", justify="center")
    perm_table.add_column("Description")

    for p in report.permissions:
        level_style = {
            "dangerous": "bold red",
            "normal": "yellow",
            "signature": "dim",
        }.get(p.protection_level, "white")

        used = "yes" if p.used_in_code else "?"
        used_style = "green" if p.used_in_code else "dim"

        short_name = p.name.replace("android.permission.", "")
        perm_table.add_row(
            short_name,
            Text(p.protection_level, style=level_style),
            Text(used, style=used_style),
            p.description or "",
        )

    console.print(perm_table)

    # Trackers
    console.print()
    if report.trackers:
        tracker_table = Table(title=f"Trackers Found ({len(report.trackers)})", show_lines=False)
        tracker_table.add_column("Tracker", style="red bold")
        tracker_table.add_column("Category")
        tracker_table.add_column("Matched Classes", style="dim")

        for t in report.trackers:
            classes_preview = ", ".join(t.matched_classes[:3])
            if len(t.matched_classes) > 3:
                classes_preview += f" (+{len(t.matched_classes) - 3} more)"
            tracker_table.add_row(t.name, t.category, classes_preview)

        console.print(tracker_table)
    else:
        console.print("[green bold]No known trackers detected[/green bold]")

    # Endpoints
    console.print()
    if report.endpoints:
        ep_table = Table(title=f"Network Endpoints ({len(report.endpoints)})", show_lines=False)
        ep_table.add_column("Domain")
        ep_table.add_column("URL", style="dim", max_width=60)
        ep_table.add_column("HTTPS", justify="center")
        ep_table.add_column("Source", style="dim", max_width=40)

        for e in report.endpoints:
            https_indicator = "[green]yes[/green]" if e.is_https else "[red]NO[/red]"
            source = f"{e.source_class}.{e.source_method}" if e.source_class else ""
            ep_table.add_row(e.domain, e.url, https_indicator, source)

        console.print(ep_table)
    else:
        console.print("[dim]No network endpoints found[/dim]")

    # Suspicious Patterns
    if report.suspicious_patterns:
        console.print()
        pat_table = Table(title=f"Suspicious Patterns ({len(report.suspicious_patterns)})", show_lines=True)
        pat_table.add_column("Type")
        pat_table.add_column("Severity", justify="center")
        pat_table.add_column("Description")
        pat_table.add_column("Location", style="dim")

        for sp in report.suspicious_patterns:
            sev_style = {"high": "red bold", "medium": "yellow", "low": "dim"}.get(sp.severity, "white")
            pat_table.add_row(
                sp.pattern_type,
                Text(sp.severity, style=sev_style),
                sp.description,
                sp.location,
            )
        console.print(pat_table)

    # Certificate
    if report.certificate:
        console.print()
        cert = report.certificate
        debug_warning = " [red bold](DEBUG CERTIFICATE)[/red bold]" if cert.is_debug else ""
        console.print(Panel(
            f"Issuer: {cert.issuer}\n"
            f"Subject: {cert.subject}\n"
            f"Serial: {cert.serial_number}\n"
            f"Valid: {cert.valid_from} to {cert.valid_to}\n"
            f"SHA-256: {cert.sha256_fingerprint[:32]}...{debug_warning}",
            title="Certificate",
            border_style="blue",
        ))

    # Summary
    console.print()
    dangerous_count = sum(1 for p in report.permissions if p.protection_level == "dangerous")
    http_count = sum(1 for e in report.endpoints if not e.is_https)
    console.print(Panel(
        f"Permissions: {len(report.permissions)} total, [red]{dangerous_count} dangerous[/red]\n"
        f"Trackers: [red]{len(report.trackers)}[/red] detected\n"
        f"Endpoints: {len(report.endpoints)} total, [red]{http_count} HTTP (insecure)[/red]\n"
        f"Suspicious patterns: {len(report.suspicious_patterns)}",
        title="Summary",
        border_style="cyan",
    ))
    console.print()
