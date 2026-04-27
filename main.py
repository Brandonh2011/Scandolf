from CLI.cli_parser import CliParser
from Scanner.scanner import Scanner
from Report.report_builder import ReportBuilder, HostResult
from AI.ollama_analyzer import OllamaAnalyzer
from datetime import datetime, timezone


def main():
    # ------------------------------------------------------------------ #
    # 1. Parse CLI args                                                    #
    # ------------------------------------------------------------------ #
    parser = CliParser()
    args = parser.parse()

    targets = args.hosts
    excludes = args.exclude
    no_ai = args.no_ai
    ai_model = args.ai_model
    output_path = args.output

    # Capture the scan start time for the report filename/header
    start_time = datetime.now(timezone.utc)

    # ------------------------------------------------------------------ #
    # 2. Set up report builder                                             #
    # ------------------------------------------------------------------ #
    report = ReportBuilder(output_path=output_path, start_time=start_time)

    # ------------------------------------------------------------------ #
    # 3. Run the scan                                                      #
    # ------------------------------------------------------------------ #
    scanner = Scanner(targets, excludes)
    scanner.scan()
    scanner.show_results()

    # ------------------------------------------------------------------ #
    # 4. Populate host results from scanner data                           #
    # ------------------------------------------------------------------ #
    for ip, parsed in scanner.get_parsed_results().items():
        host = report.get_or_create_host(ip)

        host.hostname = parsed.get("hostname")
        host.domain = parsed.get("domain")
        host.os_type = parsed.get("os_type")
        host.os_detail = parsed.get("os_detail")
        host.open_services = parsed.get("open_ports", [])
        host.windows_info = parsed.get("smb_info", {})
        host.probable_vulns = parsed.get("probable_vulns", [])
        host.command_outputs = parsed.get("command_outputs", [])

    # ------------------------------------------------------------------ #
    # 5. AI analysis                                                       #
    # ------------------------------------------------------------------ #
    analyzer = OllamaAnalyzer(model=ai_model)

    for ip, host in report._hosts.items():
        if no_ai:
            host.ai_section = analyzer.skipped_section("--no-ai flag was provided")
        else:
            print(f"[*] Running AI analysis for {ip} ...")
            analysis_text = analyzer.analyze(host.to_host_data_dict())
            host.ai_section = analyzer.format_report_section(analysis_text)

    # ------------------------------------------------------------------ #
    # 6. Write report                                                      #
    # ------------------------------------------------------------------ #
    report.write()


if __name__ == "__main__":
    main()
