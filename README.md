# Scandolf
A Python-based network scanner with AI-powered analysis. Scandolf scans target hosts, identifies open ports and services, fingerprints operating systems, and generates detailed security reports optionally enriched with local AI analysis via Ollama.

# Dependencies
Python packages (Listed in requirements.txt)
```
DateTime==6.0
ipaddress==1.0.23
pytz==2026.1.post1
zope.interface==8.3
```

---

## System Dependencies
- [python3.12](https://www.python.org/) or higher
- [Nmap](https://nmap.org/download.html) - must be installed and available in PATH
- [Ollama](https://ollama.com/) - required for AI analysis (optional, can be skipped with --no-ai)
  - Default model: gemma4:e4b (model can be changed with --ai-model) 

---

# Installation
```bash
# Clone the repo
git clone https://github.com/Brandonh2011/Scandolf.git

# Install Python dependencies
pip install -r requirements.txt
```
Note: Nmap and Ollama must be installed on your system separately.

---

# Usage
```bash
python main.py <target(s)> [options]
```
**Available flags:**
| Flag | Description |
|------|-------------|
| `-h`,`--help` | Displays help and usage |
| `--exclude` | Comma-separated list of hosts to exclude |
| `--no-ai` | Skip AI analysis |
| `--ai-model` | Specify Ollama model to use (Default: gemma4:e4b) |
| `--output` | Change where the generated report is outputted |

## Usage Examples
```bash
# Basic scan of single host
python main.py 192.168.1.1

# Scan subnet, exclude specific host(s), change report location
python main.py 192.168.1.0/24 --exclude 192.168.1.3,192.168.1.4 --output report.md

# Scan without AI analysis
python main.py 192.168.1.1 --no-ai

# Use a specific Ollama model for analysis
python main.py 192.168.1.1 --ai-model llama3
```

---

## How It Works
1. **Scan** - Nmap scans the target(s) for open ports, services, OS info, and SMB details (if windows)
2. **Parse** - Results are parsed and structured per host (hostname, OS, open services, probable vulnerabilities)
3. **Analyze** - Each host is passed to a local Ollama model for AI-generated insights (unless --no-ai is set)
4. **Report** - A full markdown report is written to the current directory (unless changed with --output)

---

> ⚠️ Use only on networks and systems you own or have explicit permission to scan.
