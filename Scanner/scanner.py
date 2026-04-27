"""
Scanner: Wraps nmap execution and parses the output into structured
HostResult-compatible dicts for the report builder.
"""

import re
import subprocess
import ipaddress
import socket


class Scanner:
    def __init__(self, targets, excludes):
        self.targets = targets
        self.excludes = excludes
        # ip -> dict of parsed data + raw output
        self._parsed: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def scan(self):
        """Run nmap against self.targets and capture + parse the output."""
        options = ["-A", "-p-"]
        if self.excludes:
            excludes = (
                ",".join(self.excludes)
                if isinstance(self.excludes, list)
                else self.excludes
            )
            options += ["--exclude", excludes]

        if not self._is_ip_or_subnet(self.targets):
            self._dns_safety_check(self.targets)

        cmd = ["nmap", *options, self.targets]
        print("Running: ", " ".join(cmd))

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        raw_output_lines = []
        for line in process.stdout:
            print(line, end="")
            raw_output_lines.append(line)

        process.wait()
        self._last_exit_code = process.returncode

        raw_output = "".join(raw_output_lines)
        self._parse_nmap_output(raw_output, cmd=" ".join(cmd))

    def show_results(self):
        print("\nScan finished.")
        print("Exit code:", self._last_exit_code)

    def get_parsed_results(self) -> dict[str, dict]:
        """
        Return the parsed results dict.
        Keys are IP addresses; values are dicts compatible with
        OllamaAnalyzer.build_prompt() and HostResult population.
        """
        return self._parsed

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse_nmap_output(self, raw: str, cmd: str = ""):
        """
        Parse raw nmap -A output into per-host structured dicts.

        Extracts:
          - IP address & rDNS hostname
          - Open ports / services / versions
          - OS detection (verified + CPE hint for probable version)
          - Basic SMB/NetBIOS info from nmap scripts
        """
        # Split output into per-host blocks on "Nmap scan report for"
        host_blocks = re.split(r"(?=Nmap scan report for )", raw)

        for block in host_blocks:
            if not block.strip() or "Nmap scan report for" not in block:
                continue

            # ---- IP and hostname ----
            header_match = re.match(
                r"Nmap scan report for (?:(\S+) \((\d+\.\d+\.\d+\.\d+)\)|(\d+\.\d+\.\d+\.\d+))",
                block,
            )
            if not header_match:
                continue

            if header_match.group(1):          # "hostname (ip)" form
                hostname = header_match.group(1)
                ip = header_match.group(2)
            else:                               # plain IP
                hostname = None
                ip = header_match.group(3)

            # ---- Open ports ----
            open_ports = []
            for port_match in re.finditer(
                r"(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?",
                block,
            ):
                port, proto, service, version = port_match.groups()
                open_ports.append(
                    {
                        "port": int(port),
                        "protocol": proto,
                        "service": service,
                        "version": (version or "").strip(),
                    }
                )

            # ---- OS detection ----
            os_type = "Unknown"
            os_detail = None

            os_match = re.search(r"OS details?:\s*(.+)", block)
            if os_match:
                os_raw = os_match.group(1).strip()
                os_detail = os_raw
                if re.search(r"[Ww]indows", os_raw):
                    os_type = "Windows"
                elif re.search(r"[Ll]inux", os_raw):
                    os_type = "Linux"
                elif re.search(r"[Uu]nix|[Ff]ree[Bb][Ss][Dd]|[Oo]pen[Bb][Ss][Dd]|macOS|[Dd]arwin", os_raw):
                    os_type = "Unix"

            # Fallback: CPE line
            if os_type == "Unknown":
                cpe_match = re.search(r"cpe:/o:(\S+)", block)
                if cpe_match:
                    cpe = cpe_match.group(1).lower()
                    if "windows" in cpe:
                        os_type = "Windows"
                    elif "linux" in cpe:
                        os_type = "Linux"

            # ---- SMB / NetBIOS (Windows-specific) ----
            smb_info = {}
            if os_type == "Windows" or re.search(r"smb|netbios|microsoft-ds", block, re.I):
                nb_match = re.search(r"NetBIOS name:\s*(\S+)", block, re.I)
                if nb_match:
                    smb_info["NetBIOS Name"] = nb_match.group(1)

                smb_domain = re.search(r"Domain name:\s*(\S+)", block, re.I)
                if smb_domain:
                    smb_info["SMB Domain"] = smb_domain.group(1)

                workgroup = re.search(r"Workgroup:\s*(\S+)", block, re.I)
                if workgroup:
                    smb_info["Workgroup"] = workgroup.group(1)

                smb_os = re.search(r"OS:\s*(Windows[^\n]+)", block)
                if smb_os:
                    smb_info["SMB OS"] = smb_os.group(1).strip()

                # Shares listed by smb-enum-shares
                shares = re.findall(r"\\\\\S+\\(\S+)\s", block)
                if shares:
                    smb_info["Shares"] = ", ".join(set(shares))

            # ---- Domain (AD) ----
            domain = smb_info.get("SMB Domain") or None
            if not domain:
                fqdn_match = re.search(r"FQDN:\s*(\S+)", block, re.I)
                if fqdn_match:
                    parts = fqdn_match.group(1).split(".")
                    if len(parts) > 1:
                        domain = ".".join(parts[1:])

            # ---- Probable vulns (banner-based hints) ----
            probable_vulns = []
            # Old SSL/TLS versions
            if re.search(r"SSLv[23]|TLSv1\.0|TLSv1\.1", block):
                probable_vulns.append("Outdated SSL/TLS version detected – potential BEAST/POODLE exposure")
            # SMB v1
            if re.search(r"SMBv1|smb1", block, re.I):
                probable_vulns.append("SMBv1 detected – potential EternalBlue (MS17-010) exposure")
            # OpenSSL heartbleed-era
            heartbleed = re.search(r"OpenSSL (0\.[89]\.|1\.0\.[01])", block)
            if heartbleed:
                probable_vulns.append(f"Older OpenSSL version ({heartbleed.group(1)}…) – check for Heartbleed (CVE-2014-0160)")

            # ---- Store result ----
            self._parsed[ip] = {
                "hostname": hostname,
                "domain": domain,
                "os_type": os_type,
                "os_detail": os_detail,
                "open_ports": open_ports,
                "smb_info": smb_info,
                "probable_vulns": probable_vulns,
                "command_outputs": [{"command": cmd, "output": block.strip()}],
            }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_ip_or_subnet(self, target: str) -> bool:
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            return False

    def _dns_safety_check(self, target: str):
        """Resolve DNS and prompt user to confirm scope before proceeding."""
        # Show configured DNS server(s) if resolvable
        try:
            import dns.resolver  # optional; falls back gracefully
            nameservers = dns.resolver.Resolver().nameservers
            print(f"[DNS] Configured nameservers: {', '.join(nameservers)}")
        except Exception:
            pass  # dns package not installed – silently skip

        try:
            ip = socket.gethostbyname(target)
        except Exception:
            print("Error resolving address. Aborting!")
            exit(1)

        answer = input(
            f"[DNS] Record {target} → {ip} detected. "
            "Proceed with scan? (y/N): "
        )
        if answer.strip().lower() != "y":
            print("Aborting!")
            exit(1)
