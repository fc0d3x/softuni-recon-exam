# Reconnaissance Exam Report – SSH Key Discovery
 **Date:**  2025-06-15 Exam: Reconnaissance Fundamentals – Retake Exam

 **Student:**  Filip Jovanov

 **Target:**  http://185.218.124.165/

---

This repository contains my solution and findings for a penetration testing exam where the objective was to perform both active and passive reconnaissance on the target IP: 185.218.124.165 and identify an exposed online SSH private key.

Tools Used:
Nmap: Used for service and version scanning on the target IP to identify open ports and services. Key commands used:

nmap -sC -sV -p- 185.218.124.165: Full port scan and service version enumeration.

nmap -sV: To identify the version of services running, particularly OpenSSH.

---

Shodan and DNSDumpster: Employed for passive reconnaissance to gather metadata about the server, including IP geolocation, ISP, open ports, and services.

CrackStation: Used to crack a password hash found in a Nextcloud file.

Pastebin: Leveraged to extract a Base64-encoded SSH private key after finding a link containing the private key in a Nextcloud document.

Key Findings:
SSH Key Exposure: I identified a private SSH key after chaining multiple vulnerabilities. These included:

Credential exposure from an unprotected MariaDB database.

Lack of brute-force protection on Nextcloud, allowing for password spraying.

A sensitive file containing a password hash was located and cracked, leading to access to a Pastebin link that revealed the SSH key.

Vulnerabilities Identified:
Outdated OpenSSH (CVE-2023-51385, CVE-2023-48795): Identified via Nmap scan, the target ran OpenSSH 8.2p1, vulnerable to multiple critical CVEs, including weak SSH channel encryption and arbitrary command execution vulnerabilities.

SCP Overwrite Vulnerability (CVE-2020-12062): OpenSSH 8.2p1 was also vulnerable to an SCP issue allowing overwriting of arbitrary files on the client machine.

Insecure Nextcloud Setup: The lack of brute-force protection enabled an attacker to perform password spraying and take over accounts with weak passwords.

Exploitation Path:
I began by scanning the target with Nmap to identify open ports (22 for SSH, 80 for HTTP). I then scanned for vulnerabilities, eventually discovering that the target was using an outdated MariaDB version that was vulnerable to DoS (CVE-2025-21490) and an Apache RCE vulnerability (CVE-2021-42013).

After cracking the Nextcloud user password hashes, I found a Pastebin link embedded in the Nextcloud file, leading me to an exposed private SSH key encoded in Base64.

This combination of misconfigurations, weak password management, and exposed sensitive data led to the final goal: obtaining the SSH private key.

Conclusion:
Through a combination of active scanning, credential exploitation, and poor security hygiene (e.g., exposed SSH keys, weak password policies, and vulnerable services), I was able to retrieve the private SSH key as required by the exam objective.

The report includes full vulnerability analysis, risk assessments, and detailed steps on how the vulnerabilities were exploited to achieve the final objective.
