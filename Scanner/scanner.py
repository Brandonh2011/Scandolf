import subprocess

class Scanner:
    def __init__(self, targets, excludes):
        self.targets = targets
        self.excludes = excludes

    def scan(self):
        options = ["-A", "-p-", "-T5"]
        if self.excludes:
            excludes = (
                ",".join(self.excludes)
                if isinstance(self.excludes, list)
                else self.excludes
            )
            options += ["--exclude", excludes]

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
