<font size="10">Aero</font>

### Difficulty:

`Medium`

Guided Mode Questions

# Enumeration

## How many TCP ports are listening on Aero?

```
nmap --vv -sS -sCV -p- --min-rate 5000 -oX 10.10.11.237.xml 10.10.11.237


PORT   STATE SERVICE REASON          VERSION
80/tcp open  http    syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Aero Theme Hub
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows	
```

---
1

## The website allows for files to be uploaded with two extensions. One is .themepack. What is the other?

inser pic#2extension.png

---
.theme

# Foothold

## What is the 2023 CVE ID for a remote code execution vulnerability in Windows themes on Windows 11?
---
﻿CVE-2023-38146

## As of the release of Aero, the best POC exploit available is from this GitHub repo. The exploit here currently launches calc.exe. What kind of file (what extension) do we need to generate to hold our payload that will provide a reverse shell?

inser pic#4extension.png
---
DLL

## According to the vulnerability disclosure and POC repo, which function needs to be exported by the malicious DLL loaded by the client?

inser #5functionname.png

---
VerifyThemeVersion 

## When ThemeBleed.exe server is run, what port does it listen on?

inser #6port.png

---
445

# Lateral Movement



# Privilege Escalation

