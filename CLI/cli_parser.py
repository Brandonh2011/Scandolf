import argparse
from datetime import datetime, timezone

now = datetime.now(timezone.utc)

class CliParser:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="Scandolf Port Scanner"
        )
        self._setup_args()

    def _setup_args(self):
        self.parser.add_argument("hosts")

        self.parser.add_argument(
            "--ai-model",
            type=str,
            default="gemma4:e4b",
            help="Change the AI Model to use (default gemma4:e4b)"
        )

        self.parser.add_argument(
            "--no-ai",
            action="store_true",
            help="Disables AI output"
        )

        self.parser.add_argument(
            "--exclude",
            type=str,
            default="",
            help="Addresses excluded from scans (comma-separated)"
        )

        self.parser.add_argument(
            "--output",
            type=str,
            default=now.strftime("host_enumeration_report_%Y%m%d_%H%M_UTC.md"),
            help="Location of the generated markdown report"
        )

    def parse(self):
        args = self.parser.parse_args()
        args.exclude = (
            args.exclude.split(",") if args.exclude else ""
        )

        return args
