**CVE-ID**: EDU-ENTITYSMUG-2026-T04-002
**Title**:  Local File Disclosure via XML External Entity (XXE)
**Affected Lab**:  Entity Smuggler (10.6.6.36)
**Component**:  `/parse`
**Severity**:  High 
**CVSS Vector**:  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
**CVSS Score**: 7.5
**Description**:  The application’s XML parser is vulnerable to XXE injections because it is configured to resolve external entities. An attacker can define a SYSTEM entity that points to the local filesystem. When the entity is referenced in the XML body, the server replaces it with the contents of the specified path, allowing the attacker to browse the server's directory structure.

**Proof of Concept**:

<img width="1558" height="614" alt="Image" src="https://github.com/user-attachments/assets/958fd074-8e26-4c87-ab0f-a06a71362297" />

Payload:
```
xml_data=<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f>
<!DOCTYPE+root+[
<!ENTITY+xxe+SYSTEM+"file%3a///etc/passwd">
]>
<root>
++<data>%26xxe%3b</data>
</root>

```
**Steps to Reproduce**:
1. Prepare a POST request against http://10.6.6.36:5014/parse. Can do this by capturing the request with interceptor such as Burp
2. Enter the payload to xml_data parameter
3. The output will show the content of the requested file.

**Remediation**:
1. Disable external Document Type Definition (DTD). [Guide](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#general-guidance)
2. Depending on your use case, there are several other protections that can be done. Each missing part means one more hole. [Link](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#xml-parser-security-features-matrix)

**Discovered By**:  Team 4
**Date**:  02/02/2026
