"""
OllamaAnalyzer: Handles all communication with a local Ollama instance
for AI-assisted penetration testing analysis.
"""

import json
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone


OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "gemma3:1b"   # smaller Gemma; override with --ai-model
DEFAULT_TIMEOUT = 120         # seconds


class OllamaAnalyzer:
    """
    Encapsulates all Ollama interaction: availability checking, prompt
    construction, request dispatch, timeout handling, and Markdown
    formatting of the returned analysis for the report.
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        base_url: str = OLLAMA_BASE_URL,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._available: bool | None = None  # cached after first check

    # ------------------------------------------------------------------
    # Availability checking
    # ------------------------------------------------------------------

    def check_availability(self) -> bool:
        """
        Verify the Ollama daemon is reachable and the requested model is
        pulled.  Result is cached so the network round-trip only happens
        once per session.
        """
        if self._available is not None:
            return self._available

        # 1. Is the server up?
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
        except Exception as exc:
            print(
                f"[WARNING] Ollama not reachable at {self.base_url}: {exc}",
                file=sys.stderr,
            )
            self._available = False
            return False

        # 2. Is the requested model present?
        available_models = [m.get("name", "") for m in data.get("models", [])]
        model_found = any(
            self.model == m or m.startswith(self.model)
            for m in available_models
        )

        if not model_found:
            print(
                f"[WARNING] Model '{self.model}' not found in Ollama. "
                f"Available: {available_models}",
                file=sys.stderr,
            )
            self._available = False
            return False

        self._available = True
        return True

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def build_prompt(self, host_data: dict) -> str:
        """
        Build a deterministic, structured prompt from parsed host data.

        Expected host_data keys (all optional except 'ip'):
            ip           – str
            hostname     – str | None
            domain       – str | None
            os_type      – str | None   e.g. "Windows" / "Linux"
            os_detail    – str | None   unverified version string
            open_ports   – list[dict]   {port, protocol, service, version}
            smb_info     – dict | None  Windows/SMB-specific findings
            extra_info   – list[str]    any other unverified observations
        """
        ip = host_data.get("ip", "unknown")
        hostname = host_data.get("hostname") or "N/A"
        domain = host_data.get("domain") or "N/A"
        os_type = host_data.get("os_type") or "Unknown"
        os_detail = host_data.get("os_detail") or "N/A"

        ports = host_data.get("open_ports", [])
        port_lines = (
            "\n".join(
                f"  - {p.get('port', '?')}/{p.get('protocol', 'tcp')}  "
                f"{p.get('service', 'unknown')}  "
                f"{p.get('version', '')}".rstrip()
                for p in ports
            )
            or "  (none detected)"
        )

        smb_info = host_data.get("smb_info") or {}
        smb_section = (
            "\nWindows/SMB Information:\n"
            + "\n".join(f"  {k}: {v}" for k, v in smb_info.items())
            if smb_info
            else ""
        )

        extra = host_data.get("extra_info", [])
        extra_section = (
            "\nAdditional (unverified) observations:\n"
            + "\n".join(f"  - {e}" for e in extra)
            if extra
            else ""
        )

        return (
            "You are a senior penetration tester writing a concise security analysis.\n"
            "Analyse the following enumeration data and provide:\n"
            "1. The host's likely role on the network (e.g. web server, domain controller, workstation).\n"
            "2. Potentially high-risk services or misconfigurations.\n"
            "3. Suggested follow-up enumeration steps or attack vectors.\n"
            "4. Relevant CVEs or vulnerability classes for detected service versions.\n\n"
            "Keep the response concise, structured, and actionable.\n\n"
            "--- HOST DATA ---\n"
            f"IP Address     : {ip}\n"
            f"Hostname       : {hostname}\n"
            f"Domain         : {domain}\n"
            f"OS (verified)  : {os_type}\n"
            f"OS (probable)  : {os_detail}\n"
            f"Open Ports:\n{port_lines}"
            f"{smb_section}"
            f"{extra_section}\n"
            "--- END HOST DATA ---\n"
        )

    # ------------------------------------------------------------------
    # Request dispatch
    # ------------------------------------------------------------------

    def analyze(self, host_data: dict) -> str:
        """
        Run AI analysis for a single host.

        Returns the model's response text, or a descriptive skip/error
        message suitable for embedding directly in the report.
        """
        if not self.check_availability():
            return (
                "_AI analysis skipped: Ollama is unavailable or the requested "
                f"model '{self.model}' could not be found. "
                "Ensure Ollama is running and the model is pulled (`ollama pull "
                f"{self.model}`) before re-running._"
            )

        prompt = self.build_prompt(host_data)
        payload = json.dumps(
            {"model": self.model, "prompt": prompt, "stream": False}
        ).encode("utf-8")

        req = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                result = json.loads(resp.read().decode())
            return result.get("response", "").strip()
        except urllib.error.URLError as exc:
            print(
                f"[WARNING] Ollama request failed for {host_data.get('ip')}: {exc}",
                file=sys.stderr,
            )
            return f"_AI analysis failed: {exc}_"
        except TimeoutError:
            print(
                f"[WARNING] Ollama timed out for {host_data.get('ip')}",
                file=sys.stderr,
            )
            return "_AI analysis failed: request timed out._"
        except Exception as exc:
            print(f"[WARNING] Unexpected AI error: {exc}", file=sys.stderr)
            return f"_AI analysis error: {exc}_"

    # ------------------------------------------------------------------
    # Report formatting helpers
    # ------------------------------------------------------------------

    def format_report_section(self, analysis_text: str) -> str:
        """Return a complete ### AI Analysis block ready for the report."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return (
            f"### AI Analysis\n"
            f"> Model: {self.model} | Analyzed: {timestamp}\n\n"
            f"{analysis_text}\n"
        )

    def skipped_section(self, reason: str = "--no-ai flag was provided") -> str:
        """Return an AI Analysis section explaining why analysis was skipped."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return (
            f"### AI Analysis\n"
            f"> Model: {self.model} | Analyzed: {timestamp}\n\n"
            f"_AI analysis was not performed: {reason}_\n"
        )
