**CVE-ID:** EDU-PROTOPOLLUTE-2026-T03-009 

**Title:** DOM Clobbering in Global config Variable Leads to Malicious Script Execution

**Affected Lab:** Client-Side Logic & Prototype Pollution Lab 1: DOM Clobbering

**Component:** JavaScript logic that reads window.config?.scriptUrl

**Severity:** High

**CVSS Vector:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N

**CVSS Score:** 8.8

**Description:**
The application is vulnerable to DOM Clobbering because it uses window.config as a global variable without validation. 
An attacker can inject HTML to overwrite the config.scriptUrl property, forcing the application to load a malicious script

**Proof of Concept:**
<img width="873" height="627" alt="Screenshot 2026-02-19 at 06-26-22 Client-Side Logic Lab" src="https://github.com/user-attachments/assets/0e7a4dc6-a6c8-4913-b855-640f4a8ba70f" />

**Payload:**
<img width="370" height="68" alt="image" src="https://github.com/user-attachments/assets/18f53c82-34f5-4d4f-96c5-20b720da55a7" />


**Steps to Reproduce:**
1. Run sudo docker ps to list running containers and identify the container ID for the proto-pollute lab.
2. Run sudo docker inspect [containerid] to retrieve the container's network configuration and extract the IP address.
3. Perform network reconnaissance using nmap -sV -sC -T5 -p- [container-ip] to identify open ports and services.
4. Add the target IP to /etc/hosts file: 10.6.6.45 proto.local.
5. Access the application in a web browser at http://proto.local:5004.
6. Navigate to the "DOM Clobbering" lab section.
7. Enter the HTML payload shown above in the "Inject HTML" input field.
8. Click the "Inject & Reload" button to submit the payload.
9. Observe that the malicious script URL is loaded and executed.

**Remediation:**
1. Avoid using mutable global objects like window.config
2. Use a scoped and immutable configuration object instead


Discovered By: Team 3
Date: 2026-02-19
