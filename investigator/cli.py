"""Command-line interface: ``python -m investigator <capture>``.

Output is deliberately ASCII-only in V0 so it renders correctly on any
Windows console codepage (fancy box drawing can come later, guarded by
encoding detection).
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from investigator import __version__
from investigator.errors import InvestigatorError
from investigator.logging_setup import configure_logging
from investigator.models import CaptureSummary

if TYPE_CHECKING:  # imported lazily at runtime, see run()
    from investigator.parser import PcapLoader

LOG = logging.getLogger(__name__)

_BANNER_WIDTH = 40
_PROGRESS_EVERY = 100_000


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="investigator",
        description=(
            "Automatic PCAP Investigator - offline analysis of .pcap/.pcapng "
            "captures. Produces findings, correlated hypotheses, a timeline, "
            "an explainable risk score and JSON/HTML reports."
        ),
    )
    parser.add_argument(
        "capture",
        help="path to a .pcap/.pcapng file (gzip-compressed accepted)",
    )
    parser.add_argument(
        "--max-packets",
        type=_positive_int,
        default=None,
        metavar="N",
        help="stop after N packets (quick look at very large captures)",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        metavar="DIR",
        help="directory for generated reports (default: reports)",
    )
    parser.add_argument(
        "--top",
        type=_positive_int,
        default=10,
        metavar="N",
        help="how many hosts/conversations to show in terminal sections",
    )
    parser.add_argument(
        "--timeline-entries",
        type=_positive_int,
        default=25,
        metavar="N",
        help="how many timeline entries to print (full list goes to timeline.json)",
    )
    parser.add_argument(
        "--no-timeline",
        action="store_true",
        help="omit the timeline section from terminal output",
    )
    parser.add_argument(
        "--no-html",
        action="store_true",
        help="skip generating investigation.html",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="-v info, -vv debug, -vvv also enables scapy debug output",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


def _format_size(num_bytes: int) -> str:
    value = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    raise AssertionError("unreachable")


def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    total = int(round(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    return f"{minutes}m {secs:02d}s"


def _format_timestamp(epoch_seconds: float) -> str:
    stamp = datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
    return stamp.strftime("%Y-%m-%d %H:%M:%S UTC")


def render_summary(loader: "PcapLoader", summary: CaptureSummary) -> str:
    """Build the terminal summary as a string (pure function, easy to test)."""
    meta = loader.metadata
    lines = [
        "=" * _BANNER_WIDTH,
        "AUTOMATIC PCAP INVESTIGATOR".center(_BANNER_WIDTH).rstrip(),
        "=" * _BANNER_WIDTH,
        "",
        f"File:      {meta.path}",
        f"Format:    {meta.capture_format.value}" + (" [gzip]" if meta.gzipped else ""),
        f"Size:      {_format_size(meta.file_size)}",
    ]

    packets_line = f"Packets:   {summary.packet_count}"
    if loader.malformed_count:
        packets_line += f"  ({loader.malformed_count} malformed skipped)"
    lines.append(packets_line)

    if loader.truncated:
        lines.append("Note:      capture ends abruptly (truncated); partial results")

    if summary.first_timestamp is not None and summary.last_timestamp is not None:
        lines.append(f"Start:     {_format_timestamp(summary.first_timestamp)}")
        lines.append(f"End:       {_format_timestamp(summary.last_timestamp)}")
        lines.append(f"Duration:  {_format_duration(summary.duration or 0.0)}")

    lines.append(f"Volume:    {_format_size(summary.total_bytes)} on the wire")

    if summary.protocol_counts:
        lines.append("")
        lines.append("Protocols:")
        width = max(len(name) for name in summary.protocol_counts)
        ordered = sorted(
            summary.protocol_counts.items(), key=lambda kv: (-kv[1], kv[0])
        )
        for name, count in ordered:
            lines.append(f"  {name:<{width}}  {count}")

    return "\n".join(lines)


def run(argv: list[str] | None = None) -> int:
    """Entry point returning an exit code (0 ok, 1 investigation error)."""
    args = build_arg_parser().parse_args(argv)
    configure_logging(args.verbose)

    # Imported here, after logging is configured, so Scapy's import-time
    # warnings (irrelevant for offline file analysis) are already muted.
    # It also keeps `--help`/`--version` fast: scapy takes a while to load.
    from pathlib import Path

    from investigator.investigation import render_investigation_text
    from investigator.parser import PcapLoader
    from investigator.pipeline import analyze_capture
    from investigator.reporting import (
        build_report,
        build_timeline_report,
        render_findings_text,
        render_hypotheses_text,
        render_inventory_text,
        render_protocols_text,
        write_html,
        write_json,
    )
    from investigator.scoring import render_score_text
    from investigator.timeline import render_timeline_text

    try:
        loader = PcapLoader(args.capture, max_packets=args.max_packets)
        LOG.info(
            "loading %s (%s)", loader.path, loader.metadata.capture_format.value
        )
        result = analyze_capture(loader, progress_every=_PROGRESS_EVERY)

        report = build_report(result)
        output_dir = Path(args.output_dir)
        written = [
            write_json(report, output_dir, "investigation.json"),
            write_json(build_timeline_report(result), output_dir, "timeline.json"),
        ]
        if not args.no_html:
            try:
                written.append(write_html(report, output_dir, "investigation.html"))
            except ImportError:
                # Jinja2 is only needed for the HTML view; JSON is the source
                # of truth, so a missing optional dependency must not fail
                # the whole investigation.
                print(
                    "warning: Jinja2 not installed, skipping investigation.html "
                    "(pip install jinja2)",
                    file=sys.stderr,
                )
    except InvestigatorError as exc:
        LOG.debug("investigation aborted", exc_info=True)
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130

    print(render_summary(loader, result.summary))
    print(render_inventory_text(result.inventory, limit=args.top))
    protocol_text = render_protocols_text(result.protocols)
    if protocol_text:
        print(protocol_text)
    print(render_findings_text(result.findings, limit=args.top))
    hypotheses_text = render_hypotheses_text(result.hypotheses)
    if hypotheses_text:
        print(hypotheses_text)
    if not args.no_timeline:
        timeline_text = render_timeline_text(
            result.timeline, limit=args.timeline_entries
        )
        if timeline_text:
            print(timeline_text)
    if result.risk is not None:
        print(render_score_text(result.risk))
    if result.investigation is not None:
        print(render_investigation_text(result.investigation))

    print("\nReports:")
    for path in written:
        print(f"  {path}")
    return 0


def main() -> None:
    """Console entry point (``python -m investigator`` and the
    ``pcap-investigator`` script installed by pip)."""
    sys.exit(run())
