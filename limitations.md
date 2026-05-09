# limitations
- cannot modify static `nmap -A -p- <target(s)>` command
- Some Unix/Linux systems may register as Unknown OS
- Will not scan hosts which block ping scans in host firewall
- AI output is 100% local and does not perform external CVE database queries or additional lookups
- Large subnets may cause significant scanning and AI analysis delays
- Potential for false positives/false negatives
- IPv6 scanning is untested and undefined
- providing a subnet and an explicit IP that falls within that subnet will cause that IP to be scanned twice
- Report Generation is markdown only
