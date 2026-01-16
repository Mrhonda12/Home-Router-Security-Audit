# Home-Router-Security-Audit
Ethical home router security audit using Nmap (ports, services, vuln scripts) with findings &amp; mitigations documented in a pentest style report.
# Home Router Security Audit (Ethical Pentest)

## Overview
This project documents a legal and ethical security assessment performed on my personally owned home router to identify exposed services, evaluate security posture, and document hardening recommendations.

## Scope / Authorization
- Target Device: Spectrum / Askey Home Router
- IP Address: 192.168.1.1
- Environment: Home LAN only
- Authorization: Personally owned device
- Assessment Type: Non-destructive scanning & enumeration (no exploitation)

## Tools Used
- Kali Linux (VirtualBox VM - Bridged Adapter)
- Nmap 7.98
- arp-scan 1.10.0

## Methodology
1. Host discovery (confirm target is online)
2. TCP port scan (identify exposed ports)
3. Service & version detection
4. Safe NSE script checks (`--script vuln`)
5. Findings + hardening recommendations

## Commands Used

### Host Discovery
sudo nmap -sn -PR 192.168.1.1

### Port Scan (Top Ports)
sudo nmap -T4 192.168.1.1

### Service + Default Scripts
sudo nmap -sV -sC 192.168.1.1

### Vulnerability Scan (Safe Scripts)
sudo nmap --script vuln 192.168.1.1

### OS Detection
sudo nmap -sV -sC -O 192.168.1.1

Open Ports Detected
Port	  State	  Service	   Details
53/tcp	open	  DNS	     Cloudflare public DNS detected
80/tcp	open	  HTTP	   lighttpd 1.4.59
443/tcp	open	  HTTPS	   lighttpd 1.4.59 (TLS/SSL enabled)
Other ports:
846 closed (reset)
151 filtered (no-response)
### Findings
1) HTTP Admin Interface Exposed on Port 80

Severity: Medium
Evidence: 80/tcp open http lighttpd 1.4.59
Risk: HTTP is unencrypted and could expose sensitive admin session traffic in unsafe scenarios.
Recommendation: Use HTTPS only (disable HTTP or redirect to HTTPS if possible).
2) Vendor Default SSL Certificate in Use

Severity: Low / Informational
Evidence: SSL cert CN: askey.com
Risk: Users may ignore browser security warnings, increasing risk of social engineering / MITM-style attacks on unsafe networks.
Recommendation: Use HTTPS only and avoid accessing router admin portal on public Wi-Fi.
3) DNS Service Exposed on TCP/53

Severity: Low
Evidence: 53/tcp open domain
Risk: DNS should not be accessible from WAN. If misconfigured, it could be abused as an open resolver.
Recommendation: Confirm DNS/admin services are LAN-only and remote management from WAN is disabled.

### Hardening Recommendations (Blue Team)

Disable WPS

Disable Remote Management (WAN admin)

Disable UPnP unless needed

Use WPA3 (or WPA2/WPA3 mixed)

Set strong router admin password

Update router firmware regularly

Restrict router admin portal to LAN only

### Evidence

Nmap output files are stored in the /scans folder:

nmap_top_ports.txt

nmap_services_scripts.txt

nmap_vuln_scripts.txt

nmap_os_detect.txt

### Disclaimer

### This project was performed only on devices I own/operate and only within my local network following ethical cybersecurity practices.
