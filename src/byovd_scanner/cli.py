"""
Command-line interface for BYOVD Scanner.
"""

import json
import sys
from pathlib import Path
from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .scanner import DriverInfo, DriverScanner


console = Console(force_terminal=True, legacy_windows=False)


def print_banner():
    """Print the tool banner."""
    banner = """
============================================================
           BYOVD Scanner - Vulnerable Driver Discovery
                  Physical R/W IOCTL Finder
============================================================
"""
    console.print(banner, style="bold cyan")


def print_driver_report(info: DriverInfo):
    """Print formatted report for a single driver."""
    cap_style = {
        "READ_WRITE": "bold green",
        "READ_ONLY": "bold yellow",
        "WRITE_ONLY": "bold red",
        "NONE": "dim",
    }.get(info.capability_class, "")

    # Header panel
    header = Text()
    header.append(f"Driver: ", style="bold")
    header.append(f"{info.name}\n", style="bold cyan")
    header.append(f"Path: {info.path}\n", style="dim")
    header.append(f"SHA256: {info.sha256}\n", style="dim")
    header.append(f"Size: {info.size:,} bytes | Signed: {'Yes' if info.signed else 'No'}")

    console.print(Panel(header, title="[bold]Driver Info[/bold]", border_style="blue"))

    # Capability panel
    cap_text = Text()
    cap_text.append("Class: ", style="bold")
    cap_text.append(f"{info.capability_class}\n", style=cap_style)
    cap_text.append("Raw: ", style="bold")
    cap_text.append(str(info.capabilities))

    console.print(Panel(cap_text, title="[bold]Capabilities[/bold]", border_style=cap_style.split()[-1] if cap_style else "white"))

    # Tables for details
    if info.imports:
        table = Table(title="Dangerous Imports", show_header=True, header_style="bold magenta")
        table.add_column("Import", style="cyan")
        for imp in info.imports:
            table.add_row(imp)
        console.print(table)

    if info.intrinsics:
        table = Table(title="Dangerous Instructions", show_header=True, header_style="bold magenta")
        table.add_column("Offset", style="cyan")
        table.add_column("Instruction", style="yellow")
        for offset, insn in info.intrinsics[:15]:
            table.add_row(f"0x{offset:08X}", insn)
        if len(info.intrinsics) > 15:
            table.add_row("...", f"({len(info.intrinsics) - 15} more)")
        console.print(table)

    if info.device_names:
        table = Table(title="Device Names", show_header=True, header_style="bold magenta")
        table.add_column("Name", style="green")
        for name in info.device_names:
            table.add_row(name)
        console.print(table)

    if info.known_ioctls:
        table = Table(title="Known Vulnerable IOCTLs", show_header=True, header_style="bold red")
        table.add_column("Code", style="cyan")
        table.add_column("Description", style="yellow")
        for code, desc in info.known_ioctls:
            table.add_row(f"0x{code:08X}", desc)
        console.print(table)

    console.print()


def print_summary(results: List[DriverInfo]):
    """Print summary table of all results."""
    table = Table(title="Scan Summary", show_header=True, header_style="bold white")
    table.add_column("Driver", style="cyan", no_wrap=True)
    table.add_column("Class", justify="center")
    table.add_column("Imports", justify="right")
    table.add_column("IOCTLs", justify="right")
    table.add_column("Device", style="dim")

    for r in results:
        cap_style = {
            "READ_WRITE": "bold green",
            "READ_ONLY": "yellow",
            "WRITE_ONLY": "red",
            "NONE": "dim",
        }.get(r.capability_class, "")

        device = r.device_names[0] if r.device_names else "-"
        if len(device) > 30:
            device = device[:27] + "..."

        table.add_row(
            r.name,
            Text(r.capability_class, style=cap_style),
            str(len(r.imports)),
            str(len(r.known_ioctls)),
            device,
        )

    console.print(table)

    # Stats
    stats = {
        "READ_WRITE": len([r for r in results if r.capability_class == "READ_WRITE"]),
        "READ_ONLY": len([r for r in results if r.capability_class == "READ_ONLY"]),
        "WRITE_ONLY": len([r for r in results if r.capability_class == "WRITE_ONLY"]),
        "NONE": len([r for r in results if r.capability_class == "NONE"]),
    }

    console.print(f"\n[bold]Statistics:[/bold]")
    console.print(f"  [green]READ_WRITE[/green]: {stats['READ_WRITE']}")
    console.print(f"  [yellow]READ_ONLY[/yellow]: {stats['READ_ONLY']}")
    console.print(f"  [red]WRITE_ONLY[/red]: {stats['WRITE_ONLY']}")
    console.print(f"  [dim]NONE[/dim]: {stats['NONE']}")


def main():
    """Main CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="BYOVD Scanner - Find exploitable drivers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  byovd-scan driver.sys                    # Scan single driver
  byovd-scan C:\\Windows\\System32\\drivers  # Scan directory
  byovd-scan . --json -o results.json      # JSON output
  byovd-scan . --filter both               # Only READ_WRITE drivers
        """,
    )

    parser.add_argument("target", help="Driver file or directory to scan")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--csv", action="store_true", help="Output as CSV")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument(
        "--filter",
        choices=["read", "write", "both", "any"],
        default=None,
        help="Filter by capability",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Only show summary")
    parser.add_argument("--no-banner", action="store_true", help="Skip banner")

    args = parser.parse_args()

    if not args.no_banner and not args.json:
        print_banner()

    target = Path(args.target)
    scanner = DriverScanner(verbose=args.verbose)

    # Collect results
    if target.is_file():
        info = scanner.scan_file(target)
        results = [info] if info else []
    elif target.is_dir():
        console.print(f"[*] Scanning directory: {target}")
        results = scanner.scan_directory(target)
    else:
        console.print(f"[red][-] Invalid target: {args.target}[/red]")
        sys.exit(1)

    if not results:
        console.print("[yellow][-] No drivers found or parsed[/yellow]")
        sys.exit(1)

    console.print(f"[*] Found {len(results)} driver(s)")

    # Apply filter
    if args.filter:
        if args.filter == "read":
            results = [r for r in results if r.has_read]
        elif args.filter == "write":
            results = [r for r in results if r.has_write]
        elif args.filter == "both":
            results = [r for r in results if r.has_read and r.has_write]
        elif args.filter == "any":
            results = [r for r in results if r.is_vulnerable]

    # Output
    if args.json:
        output = {
            "scan_target": str(target),
            "result_count": len(results),
            "drivers": [r.to_dict() for r in results],
            "summary": {
                "read_write": len([r for r in results if r.capability_class == "READ_WRITE"]),
                "read_only": len([r for r in results if r.capability_class == "READ_ONLY"]),
                "write_only": len([r for r in results if r.capability_class == "WRITE_ONLY"]),
                "none": len([r for r in results if r.capability_class == "NONE"]),
            },
        }
        json_str = json.dumps(output, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(json_str)
            console.print(f"[green][+] JSON output written to {args.output}[/green]")
        else:
            print(json_str)

    elif args.csv:
        import csv
        import io

        rows = []
        for r in results:
            rows.append(
                {
                    "name": r.name,
                    "path": r.path,
                    "sha256": r.sha256,
                    "class": r.capability_class,
                    "signed": r.signed,
                    "imports": ";".join(r.imports),
                    "device_names": ";".join(r.device_names),
                }
            )

        if args.output:
            with open(args.output, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys() if rows else [])
                writer.writeheader()
                writer.writerows(rows)
            console.print(f"[green][+] CSV output written to {args.output}[/green]")
        else:
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=rows[0].keys() if rows else [])
            writer.writeheader()
            writer.writerows(rows)
            print(output.getvalue())

    else:
        if not args.quiet:
            # Group and print detailed reports
            for r in results:
                if r.is_vulnerable:
                    print_driver_report(r)

        print_summary(results)

    return 0


if __name__ == "__main__":
    sys.exit(main())
