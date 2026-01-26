**CVE-ID**: EDU-WEBLAB-2026-T03-001  
**Title**: SQL Injection in Login Form  
**Affected Lab**: WebApp-Lab-3  
**Component**: /login.php  
**Severity**: High  
**CVSS Vector**: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N  
**CVSS Score**: 9.1  

**Description**:  
The login form is vulnerable to SQL injection due to unsanitized user inputs.

**Proof of Concept**:  
Payload: `' OR 1=1 --`  
Effect: Login bypassed without valid credentials.

**Steps to Reproduce**:  
1. Navigate to /login.php  
2. Input the payload into the username field  
3. Enter any password  
4. Observe login success

**Remediation**:  
Use parameterized queries (e.g., `mysqli_prepare`)

**Discovered By**: Team 3  
**Date**: 2026-01-30
