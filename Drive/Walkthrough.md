# Enumeration

Open Ports: 22,80 (redirects to http://drive.htb)
Filtered Port: 3000

```
echo "10.10.11.235 drive.htb" | sudo tee -a /etc/hosts
```

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



