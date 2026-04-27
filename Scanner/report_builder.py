"""
ReportBuilder: Assembles the final Markdown enumeration report from
per-host HostResult objects and pre-formatted AI analysis sections.
"""

import os
from datetime import datetime, timezone


class HostResult:
    """
    Stores all enumeration data for a single host and provides
    Markdown-formatting helpers so ReportBuilder stays clean.
    """

    def __init__(self, ip: str):
        # --- Verified ---
        self.ip: str = ip
        self.hostname: str | None = None
        self.domain: str | None = None           # Active Directory domain
        self.os_type: str | None = None           # Windows / Linux / Unix / Unknown
        self.open_services: list[dict] = []       # [{port, protocol, service, version}]
        self.windows_info: dict = {}              # SMB / NetBIOS / AD details

        # --- Unverified / probable ---
        self.os_detail: str | None = None         # e.g. "Windows Server 2019"
        self.probable_vulns: list[str] = []       # version-based guesses

        # --- Raw command outputs ---
        # Each entry: {"command": str, "output": str}
        self.command_outputs: list[dict] = []

        # --- AI analysis (pre-formatted Markdown block) ---
        self.ai_section: str = ""

    # ------------------------------------------------------------------
    # Markdown helpers
    # ------------------------------------------------------------------

    def verified_table_markdown(self) -> str:
        """Return the Verified Information table as Markdown."""
        services_md = (
            "\n".join(
                f"  - `{s['port']}/{s['protocol']}` – {s['service']}"
                + (f" {s['version']}" if s.get("version") else "")
                for s in self.open_services
            )
            or "  _(none detected)_"
        )

        windows_md = ""
        if self.windows_info:
            windows_md = "\n\n**Windows-Specific Information:**\n" + "\n".join(
                f"- **{k}**: {v}" for k, v in self.windows_info.items()
            )

        rows = [
            ("IP Address", self.ip),
            ("Hostname", self.hostname or "N/A"),
            ("Domain", self.domain or "N/A"),
            ("OS Type", self.os_type or "Unknown"),
        ]

        table = "| Field | Value |\n|---|---|\n"
        table += "\n".join(f"| {k} | {v} |" for k, v in rows)
        table += f"\n\n**Active Services:**\n{services_md}"
        table += windows_md
        return table

    def unverified_section_markdown(self) -> str:
        """Return the Unverified Information section as Markdown."""
        lines = []
        if self.os_detail:
            lines.append(f"- OS Version is probably: *{self.os_detail}*")
        for vuln in self.probable_vulns:
            lines.append(f"- {vuln}")
        if not lines:
            lines.append("_No unverified information recorded._")
        return "\n".join(lines)

    def command_outputs_markdown(self) -> str:
        """Return the Command Outputs section as Markdown."""
        if not self.command_outputs:
            return "_No commands recorded._"
        blocks = []
        for entry in self.command_outputs:
            cmd = entry.get("command", "")
            out = entry.get("output", "")
            blocks.append(f"Command: `{cmd}`\n```\n{out}\n```")
        return "\n\n".join(blocks)

    def to_markdown(self) -> str:
        """Render the complete host section as Markdown."""
        header = f"## Host: {self.ip}"
        if self.hostname:
            header += f" ({self.hostname})"

        return "\n\n".join([
            header,
            "### Verified Information",
            self.verified_table_markdown(),
            "### Unverified Information",
            self.unverified_section_markdown(),
            self.ai_section or "### AI Analysis\n_No AI analysis available._",
            "### Command Outputs",
            self.command_outputs_markdown(),
        ])

    def to_host_data_dict(self) -> dict:
        """Return a dict suitable for OllamaAnalyzer.build_prompt()."""
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "domain": self.domain,
            "os_type": self.os_type,
            "os_detail": self.os_detail,
            "open_ports": self.open_services,
            "smb_info": self.windows_info or None,
            "extra_info": self.probable_vulns,
        }


class ReportBuilder:
    """
    Assembles per-host HostResult objects into a single Markdown report
    and writes it to disk relative to the current working directory.
    """

    def __init__(self, output_path: str, start_time: datetime | None = None):
        self.output_path = output_path
        self.start_time = start_time or datetime.now(timezone.utc)
        self._hosts: dict[str, HostResult] = {}   # ip -> HostResult (insertion-ordered)

    # ------------------------------------------------------------------
    # Host management
    # ------------------------------------------------------------------

    def get_or_create_host(self, ip: str) -> HostResult:
        """Return the existing HostResult for ip, or create a new one."""
        if ip not in self._hosts:
            self._hosts[ip] = HostResult(ip)
        return self._hosts[ip]

    def add_host(self, result: HostResult) -> None:
        """Register a fully-populated HostResult."""
        self._hosts[result.ip] = result

    def get_hosts(self) -> dict[str, "HostResult"]:
        """Return the internal hosts dict (public accessor)."""
        return self._hosts

    # ------------------------------------------------------------------
    # Report assembly
    # ------------------------------------------------------------------

    def _build_header(self) -> str:
        ts = self.start_time.strftime("%Y-%m-%d %H:%M UTC")
        return (
            "# Host Enumeration Report\n\n"
            f"> **Generated:** {ts}  \n"
            f"> **Hosts scanned:** {len(self._hosts)}\n"
        )

    def _build_toc(self) -> str:
        if not self._hosts:
            return ""
        lines = ["## Table of Contents\n"]
        for ip, result in self._hosts.items():
            label = ip
            if result.hostname:
                label += f" ({result.hostname})"
            anchor = ip.replace(".", "").replace("/", "").replace(" ", "-").lower()
            lines.append(f"- [{label}](#{anchor})")
        return "\n".join(lines)

    def build_report(self) -> str:
        """Return the complete report as a Markdown string."""
        sections = [self._build_header(), self._build_toc()]
        for result in self._hosts.values():
            sections.append("---")
            sections.append(result.to_markdown())
        sections.append("---\n\n*End of report*")
        return "\n\n".join(sections)

    def write(self) -> str:
        """
        Write the report to self.output_path.
        Path is resolved relative to CWD (not the script's location).
        Returns the absolute path of the written file.
        """
        abs_path = (
            os.path.join(os.getcwd(), self.output_path)
            if not os.path.isabs(self.output_path)
            else self.output_path
        )
        parent = os.path.dirname(abs_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        content = self.build_report()
        with open(abs_path, "w", encoding="utf-8") as fh:
            fh.write(content)

        print(f"\n[+] Report written to: {abs_path}")
        return abs_path
