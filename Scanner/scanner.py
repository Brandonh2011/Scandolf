"""
Scanner: Wraps nmap execution and parses output into structured dicts
for consumption by ReportBuilder and OllamaAnalyzer.
"""

import re
import subprocess
import ipaddress
import socket


class Scanner:
    def __init__(self, targets, excludes):
        self.targets = targets
        self.excludes = excludes
        self._parsed: dict[str, dict] = {}   # ip -> structured host data
        self._last_exit_code: int = -1

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def scan(self):
        """Run nmap against self.targets, stream output, then parse it."""
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

        raw_lines = []
        for line in process.stdout:
            print(line, end="")
            raw_lines.append(line)

        process.wait()
        self._last_exit_code = process.returncode

        raw_output = "".join(raw_lines)
        self._parse_nmap_output(raw_output, full_cmd=" ".join(cmd))

    def show_results(self):
        print("\nScan finished.")
        print("Exit code:", self._last_exit_code)

    def get_parsed_results(self) -> dict[str, dict]:
        """
        Return parsed per-host data.
        Keys = IP addresses.  Values are dicts with keys:
            hostname, domain, os_type, os_detail, open_ports,
            smb_info, probable_vulns, command_outputs
        """
        return self._parsed

    # ------------------------------------------------------------------
    # nmap output parsing
    # ------------------------------------------------------------------

    def _parse_nmap_output(self, raw: str, full_cmd: str = ""):
        """Parse raw nmap -A output into per-host structured dicts."""
        # Split into per-host blocks
        host_blocks = re.split(r"(?=Nmap scan report for )", raw)

        for block in host_blocks:
            if "Nmap scan report for" not in block:
                continue

            # ---- IP and rDNS hostname ----
            header = re.match(
                r"Nmap scan report for (?:(\S+) \((\d+\.\d+\.\d+\.\d+)\)|(\d+\.\d+\.\d+\.\d+))",
                block,
            )
            if not header:
                continue

            if header.group(1):          # "hostname (ip)" form
                hostname = header.group(1)
                ip = header.group(2)
            else:
                hostname = None
                ip = header.group(3)

            # ---- Open ports / services / versions ----
            open_ports = []
            for m in re.finditer(
                r"(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?", block
            ):
                port, proto, service, version = m.groups()
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
                os_detail = os_match.group(1).strip()
                if re.search(r"[Ww]indows", os_detail):
                    os_type = "Windows"
                elif re.search(r"[Ll]inux", os_detail):
                    os_type = "Linux"
                elif re.search(r"[Uu]nix|BSD|macOS|[Dd]arwin", os_detail):
                    os_type = "Unix"

            # Fallback: CPE line
            if os_type == "Unknown":
                cpe = re.search(r"cpe:/o:(\S+)", block)
                if cpe:
                    cpe_val = cpe.group(1).lower()
                    if "windows" in cpe_val:
                        os_type = "Windows"
                    elif "linux" in cpe_val:
                        os_type = "Linux"

            # ---- SMB / NetBIOS (Windows-specific) ----
            smb_info = {}
            if os_type == "Windows" or re.search(r"smb|netbios|microsoft-ds", block, re.I):
                for pattern, key in [
                    (r"NetBIOS name:\s*(\S+)", "NetBIOS Name"),
                    (r"Domain name:\s*(\S+)", "SMB Domain"),
                    (r"Workgroup:\s*(\S+)", "Workgroup"),
                    (r"OS:\s*(Windows[^\n]+)", "SMB OS"),
                ]:
                    m = re.search(pattern, block, re.I)
                    if m:
                        smb_info[key] = m.group(1).strip()

                shares = re.findall(r"\\\\\S+\\(\S+)\s", block)
                if shares:
                    smb_info["Shares"] = ", ".join(sorted(set(shares)))

            # ---- AD domain ----
            domain = smb_info.get("SMB Domain")
            if not domain:
                fqdn_m = re.search(r"FQDN:\s*(\S+)", block, re.I)
                if fqdn_m:
                    parts = fqdn_m.group(1).split(".")
                    if len(parts) > 1:
                        domain = ".".join(parts[1:])

            # ---- Probable vulnerabilities (banner-based) ----
            probable_vulns = []
            if re.search(r"SSLv[23]|TLSv1\.0|TLSv1\.1", block):
                probable_vulns.append(
                    "Outdated SSL/TLS version detected – potential BEAST/POODLE exposure"
                )
            if re.search(r"SMBv1|smb1", block, re.I):
                probable_vulns.append(
                    "SMBv1 detected – potential EternalBlue (MS17-010) exposure"
                )
            hl = re.search(r"OpenSSL (0\.[89]\.|1\.0\.[01])", block)
            if hl:
                probable_vulns.append(
                    f"Older OpenSSL ({hl.group(1)}…) – check for Heartbleed (CVE-2014-0160)"
                )

            # ---- Store ----
            self._parsed[ip] = {
                "hostname": hostname,
                "domain": domain,
                "os_type": os_type,
                "os_detail": os_detail,
                "open_ports": open_ports,
                "smb_info": smb_info,
                "probable_vulns": probable_vulns,
                "command_outputs": [
                    {"command": full_cmd, "output": block.strip()}
                ],
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
        """Resolve target and prompt the user to confirm before scanning."""
        # Try to show configured nameservers (requires dnspython if installed)
        try:
            import dns.resolver  # type: ignore
            ns = dns.resolver.Resolver().nameservers
            print(f"[DNS] Configured nameservers: {', '.join(ns)}")
        except Exception:
            pass

        try:
            ip = socket.gethostbyname(target)
        except Exception:
            print("Error resolving address. Aborting!")
            exit(1)

        answer = input(
            f"[DNS] Record {target} → {ip} detected. Proceed with scan? (y/N): "
        )
        if answer.strip().lower() != "y":
            print("Aborting!")
            exit(1)
