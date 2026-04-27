import subprocess
import ipaddress
import socket

class Scanner:
    def __init__(self, targets, excludes):
        self.targets = targets
        self.excludes = excludes

    def scan(self):
        options = ["-A", "-p-"]
        if self.excludes:
            excludes = (
                ",".join(self.excludes)
                if isinstance(self.excludes, list)
                else self.excludes
            )
            options += ["--exclude", excludes]

        if not self.is_ip_or_subnet(self.targets):
            try:
                ip = socket.gethostbyname(self.targets)
            except:
                print("Error resolving address. Aborting!")
                exit(1)

            if input(f"DNS Record {self.targets} {ip} detected. Proceed? (y/N): ") != "y":
                print("Aborting!")
                exit(1)

        cmd = ["nmap", *options, self.targets]

        print("Running: ", " ".join(cmd))

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        for line in process.stdout:
            print(line, end="")

        process.wait()
        self._last_exit_code = process.returncode

    def show_results(self):
            print("\nScan finished.")
            print("Exit code:", self._last_exit_code)

    def is_ip_or_subnet(self, target):
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            return False
