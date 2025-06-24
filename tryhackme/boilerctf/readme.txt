first lets nmap the machine : 


this is the nmap resukt : 

//////////// 

 nmap -sC -sV 10.10.80.184             
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-29 10:02 GMT
Nmap scan report for 10.10.80.184
Host is up (0.087s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
80/tcp    open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
10000/tcp open  http    MiniServ 1.930 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.57 seconds

///////// 


lets try to access the ftp anonymously : 

ftp 10.10.80.184                                                                              
Connected to 10.10.80.184.
220 (vsFTPd 3.0.3)
Name (10.10.80.184:Abad): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
226 Directory send OK.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 .
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 ..
-rw-r--r--    1 ftp      ftp            74 Aug 21  2019 .info.txt
226 Directory send OK.
ftp>



the extention of the file is .txt 

lets download the file to see its content : 

///////// 

ftp> cat .info.txt 
?Invalid command
ftp> get .info.txt 
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for .info.txt (74 bytes).
226 Transfer complete.
74 bytes received in 0.0001 seconds (626.2620 kbytes/s)
ftp> quit
221 Goodbye.

 Thu 29 May - 10:07  ~/Desktop/work/tryhackme/boilerctf   master 11☀ 1● 
 @Abad  ls -la
drwxr-xr-x Abad users 4.0 KB Thu May 29 10:06:35 2025  .
drwxr-xr-x Abad users 4.0 KB Wed May 28 22:09:57 2025  ..
.rw-r--r-- Abad users  74 B  Thu May 29 10:07:12 2025  .info.txt
.rw-r--r-- Abad users 1.0 KB Sun Apr 13 16:33:19 2025  .jj.txt.swp
.rw-r--r-- Abad users   0 B  Sun Apr 13 16:33:19 2025  readme.txt
.rw-r--r-- Abad users 152 B  Sun Apr 13 16:33:19 2025  shell.elf


/////////// 

we also has ssh but it looks to be closed : 

///// 

nmap -p 22 10.10.80.184

Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-29 10:14 GMT
Nmap scan report for 10.10.80.184
Host is up (0.089s latency).

PORT   STATE  SERVICE
22/tcp closed ssh

Nmap done: 1 IP address (1 host up) scanned in 0.27 seconds

////// 

and this is the content of the file downloaded form the ftp : 

///// 

 cat .info.txt                      
Whfg jnagrq gb frr vs lbh svaq vg. Yby. Erzrzore: Rahzrengvba vf gur xrl!

///// 

This appears to be a ROT13 encoded message - a simple letter substitution cipher where each letter is rotated by 13 positions in the alphabet.
Decoding the message:

Let's break it down:

Original:
Whfg jnagrq gb frr vs lbh svaq vg. Yby. Erzrzore: Rahzrengvba vf gur xrl!

Decoded (ROT13):
Just wanted to see if you find it. Lol. Remember: Enumeration is the key!

lets fuzz the web server : 

////////////// 

 ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.10.80.184/FUZZ 


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.80.184/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 403, Size: 296, Words: 22, Lines: 12, Duration: 3779ms]
.htpasswd               [Status: 403, Size: 296, Words: 22, Lines: 12, Duration: 4786ms]
.hta                    [Status: 403, Size: 291, Words: 22, Lines: 12, Duration: 4792ms]
index.html              [Status: 200, Size: 11321, Words: 3503, Lines: 376, Duration: 90ms]
joomla                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 88ms]
manual                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 134ms]
robots.txt              [Status: 200, Size: 257, Words: 46, Lines: 16, Duration: 88ms]
server-status           [Status: 403, Size: 300, Words: 22, Lines: 12, Duration: 86ms]
:: Progress: [4746/4746] :: Job [1/1] :: 443 req/sec :: Duration: [0:00:17] :: Errors: 0 ::

////////////  

by ffuziing i found this repo : http://10.10.80.184/robots.txt 


which has this as contenet : 

/////////// 

User-agent: *
Disallow: /

/tmp
/.ssh
/yellow
/not
/a+rabbit
/hole
/or
/is
/it

079 084 108 105 077 068 089 050 077 071 078 107 079 084 086 104 090 071 086 104 077 122 073 051 089 122 085 048 077 084 103 121 089 109 070 104 078 084 069 049 079 068 081 075  

//////// 


we can see that this numbers above represent some asci codes let transforme each number to its ascci equivalant end concatinate them together to find thsi : 

OTliMDY2MGNkOTVhZGVhMzI3YzU0MTgyYmFhNTE1ODQK
 

 whcih is a base64 encoded string 

 let decode it via this website : https://appdevtools.com/base64-encoder-decoder 

 then we will find this strings and numbers :99b0660cd95adea327c54182baa51584
which is a hash that we can crack it via hashcat or crackstation.net 

we will find this password : kidding
/// 

Hash	Type	Result
99b0660cd95adea327c54182baa51584	md5	kidding
/// 




















