"""APK comparison reporter."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from app_xray.models import AuditReport


def print_diff(old: AuditReport, new: AuditReport):
    """Print a diff between two APK audit reports."""
    console = Console()

    console.print()
    console.print(Panel(
        f"[dim]{old.apk_info.package_name} v{old.apk_info.version_name}[/dim]  ->  "
        f"[bold]{new.apk_info.package_name} v{new.apk_info.version_name}[/bold]",
        title="[bold cyan]App X-Ray Diff[/bold cyan]",
        border_style="cyan",
    ))

    # Score change
    score_diff = new.privacy_score - old.privacy_score
    if score_diff > 0:
        console.print(f"\n  Privacy Score: {old.privacy_score} -> [green]{new.privacy_score}[/green] ([green]+{score_diff}[/green])")
    elif score_diff < 0:
        console.print(f"\n  Privacy Score: {old.privacy_score} -> [red]{new.privacy_score}[/red] ([red]{score_diff}[/red])")
    else:
        console.print(f"\n  Privacy Score: {old.privacy_score} -> {new.privacy_score} (unchanged)")

    # Permission diff
    old_perms = {p.name for p in old.permissions}
    new_perms = {p.name for p in new.permissions}
    added_perms = new_perms - old_perms
    removed_perms = old_perms - new_perms

    if added_perms or removed_perms:
        console.print()
        perm_table = Table(title="Permission Changes")
        perm_table.add_column("Change", justify="center")
        perm_table.add_column("Permission")
        for p in sorted(added_perms):
            short = p.replace("android.permission.", "")
            perm_table.add_row("[red]+[/red]", f"[red]{short}[/red]")
        for p in sorted(removed_perms):
            short = p.replace("android.permission.", "")
            perm_table.add_row("[green]-[/green]", f"[green]{short}[/green]")
        console.print(perm_table)

    # Tracker diff
    old_trackers = {t.name for t in old.trackers}
    new_trackers = {t.name for t in new.trackers}
    added_trackers = new_trackers - old_trackers
    removed_trackers = old_trackers - new_trackers

    if added_trackers or removed_trackers:
        console.print()
        tracker_table = Table(title="Tracker Changes")
        tracker_table.add_column("Change", justify="center")
        tracker_table.add_column("Tracker")
        for t in sorted(added_trackers):
            tracker_table.add_row("[red]+[/red]", f"[red]{t}[/red]")
        for t in sorted(removed_trackers):
            tracker_table.add_row("[green]-[/green]", f"[green]{t}[/green]")
        console.print(tracker_table)

    # Endpoint diff
    old_domains = {e.domain for e in old.endpoints}
    new_domains = {e.domain for e in new.endpoints}
    added_domains = new_domains - old_domains
    removed_domains = old_domains - new_domains

    if added_domains or removed_domains:
        console.print()
        ep_table = Table(title="Endpoint Domain Changes")
        ep_table.add_column("Change", justify="center")
        ep_table.add_column("Domain")
        for d in sorted(added_domains):
            ep_table.add_row("[red]+[/red]", f"[red]{d}[/red]")
        for d in sorted(removed_domains):
            ep_table.add_row("[green]-[/green]", f"[green]{d}[/green]")
        console.print(ep_table)

    if not (added_perms or removed_perms or added_trackers or removed_trackers or added_domains or removed_domains):
        console.print("\n[dim]No significant changes detected between versions.[/dim]")

    console.print()
