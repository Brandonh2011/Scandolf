from CLI.cli_parser import CliParser
from Scanner.scanner import Scanner

def main():
    parser = CliParser()
    args = parser.parse()
    targets = args.hosts
    excludes = args.exclude

    scanner = Scanner(targets, excludes)
    scanner.scan()
    scanner.show_results()
if __name__ == "__main__":
    main()
