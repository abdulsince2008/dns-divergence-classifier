#!/usr/bin/env python3
import sys
import argparse
from typing import List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from models import RecordType
from resolver import DoHResolver
from classifier import DNSClassifier
from config import load_config


console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="DNS Divergence Classifier - Detect DNS anomalies across multiple DoH resolvers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s example.com --type AAAA
  %(prog)s domains.txt --batch
        """
    )
    parser.add_argument("domain", help="Domain to analyze (or file with --batch)")
    parser.add_argument("--type", "-t", default="A", choices=["A", "AAAA", "CNAME", "TXT", "MX", "NS"],
                        help="DNS record type (default: A)")
    parser.add_argument("--batch", "-b", action="store_true",
                        help="Read domains from file (one per line)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument("--config", default="config.yaml", help="Config file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    return parser.parse_args()


async def analyze_domain(domain: str, record_type: RecordType, config_path: str, verbose: bool, json_output: bool = False) -> None:
    config = load_config(config_path)
    resolver = DoHResolver(config)
    classifier = DNSClassifier(config)

    with console.status(f"[bold cyan]Querying {len(config.resolvers)} DoH resolvers for {domain} ({record_type.value})..."):
        results = await resolver.query_all(domain, record_type)

    analysis = classifier.classify(domain, record_type, results)

    if json_output:
        print_json_output(analysis)
    elif verbose:
        print_verbose_results(analysis)
    else:
        print_summary(analysis)


def print_json_output(analysis) -> None:
    import json
    print(analysis.model_dump_json(indent=2))


def print_summary(analysis) -> None:
    score_color = "green" if analysis.trust_score >= 80 else "yellow" if analysis.trust_score >= 50 else "red"
    
    header = Text()
    header.append(f"Domain: ", style="bold")
    header.append(f"{analysis.domain} ({analysis.record_type.value})", style="cyan")
    header.append(f"  |  Trust Score: ", style="bold")
    header.append(f"{analysis.trust_score}/100", style=f"bold {score_color}")
    header.append(f"  |  ", style="dim")
    header.append(analysis.classification.value.replace("_", " ").title(), style=f"bold {score_color}")

    console.print(Panel(header, expand=False))
    console.print(f"[bold]Summary:[/bold] {analysis.summary}")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Resolver", style="cyan", width=15)
    table.add_column("Status", width=10)
    table.add_column("Answers", style="white")
    table.add_column("TTL", width=8)
    table.add_column("Latency", width=10)

    for r in analysis.resolver_results:
        if r.success:
            status = "[green]✓ OK[/green]"
            answers = ", ".join(r.answers[:3])
            if len(r.answers) > 3:
                answers += f" ... (+{len(r.answers) - 3} more)"
            ttl = str(r.ttl) if r.ttl else "N/A"
            latency = f"{r.latency_ms:.0f}ms"
        else:
            status = "[red]✗ FAIL[/red]"
            answers = r.error or "Unknown error"
            ttl = "N/A"
            latency = f"{r.latency_ms:.0f}ms" if r.latency_ms else "N/A"
        table.add_row(r.resolver_name, status, answers, ttl, latency)

    console.print(table)

    if analysis.details:
        console.print("\n[bold]Details:[/bold]")
        for d in analysis.details:
            console.print(f"  • {d}")


def print_verbose_results(analysis) -> None:
    print_summary(analysis)
    console.print("\n[bold]Full Resolver Results:[/bold]")
    for r in analysis.resolver_results:
        console.print(f"  {r.resolver_name} ({r.resolver_ip}):")
        console.print(f"    Success: {r.success}")
        console.print(f"    Answers: {r.answers}")
        console.print(f"    TTL: {r.ttl}")
        console.print(f"    Latency: {r.latency_ms:.2f}ms" if r.latency_ms else "    Latency: N/A")
        if r.error:
            console.print(f"    Error: {r.error}")


async def batch_analyze(filepath: str, record_type: RecordType, config_path: str) -> None:
    with open(filepath, "r") as f:
        domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    config = load_config(config_path)
    resolver = DoHResolver(config)
    classifier = DNSClassifier(config)

    for i, domain in enumerate(domains, 1):
        console.print(f"\n[bold cyan][{i}/{len(domains)}] Analyzing {domain}...[/bold cyan]")
        results = await resolver.query_all(domain, record_type)
        analysis = classifier.classify(domain, record_type, results)
        print_summary(analysis)


def main() -> int:
    args = parse_args()
    record_type = RecordType(args.type)

    try:
        import asyncio
        if args.batch:
            asyncio.run(batch_analyze(args.domain, record_type, args.config))
        else:
            asyncio.run(analyze_domain(args.domain, record_type, args.config, args.verbose, args.json))
        return 0
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
        return 130
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        return 1
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())
        return 1


if __name__ == "__main__":
    sys.exit(main())