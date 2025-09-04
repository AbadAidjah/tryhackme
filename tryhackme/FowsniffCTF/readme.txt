lets start with an nmap scan 

this is the result 

nmap -sC -sV 10.10.197.152
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-22 12:53 GMT
Nmap scan report for 10.10.197.152
Host is up (0.091s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 90:35:66:f4:c6:d2:95:12:1b:e8:cd:de:aa:4e:03:23 (RSA)
|   256 53:9d:23:67:34:cf:0a:d5:5a:9a:11:74:bd:fd:de:71 (ECDSA)
|_  256 a2:8f:db:ae:9e:3d:c9:e6:a9:ca:03:b1:d7:1b:66:83 (ED25519)
80/tcp  open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Fowsniff Corp - Delivering Solutions
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/
110/tcp open  pop3    Dovecot pop3d
|_pop3-capabilities: SASL(PLAIN) USER UIDL AUTH-RESP-CODE PIPELINING RESP-CODES CAPA TOP
143/tcp open  imap    Dovecot imapd
|_imap-capabilities: post-login more Pre-login listed LOGIN-REFERRALS IDLE SASL-IR AUTH=PLAINA0001 have OK ENABLE LITERAL+ capabilities IMAP4rev1 ID
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.93 seconds


since the ip @ is attached to a website lets fuzz it 

this is the result 


///////////////////////////////////////////////////// 

 ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.10.197.152/FUZZ 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.197.152/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.hta                    [Status: 403, Size: 292, Words: 22, Lines: 12, Duration: 94ms]
.htaccess               [Status: 403, Size: 297, Words: 22, Lines: 12, Duration: 94ms]
.htpasswd               [Status: 403, Size: 297, Words: 22, Lines: 12, Duration: 94ms]
assets                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 89ms]
images                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 91ms]
index.html              [Status: 200, Size: 2629, Words: 182, Lines: 77, Duration: 90ms]
robots.txt              [Status: 200, Size: 26, Words: 3, Lines: 3, Duration: 92ms]
security.txt            [Status: 200, Size: 459, Words: 249, Lines: 22, Duration: 124ms]
server-status           [Status: 403, Size: 301, Words: 22, Lines: 12, Duration: 92ms]
:: Progress: [4746/4746] :: Job [1/1] :: 392 req/sec :: Duration: [0:00:11] :: Errors: 0 ::



///////////////////////////////////////// 


found this schetch in http://10.10.197.152/security.txt

////////////////////////////////////////// 

  WHAT SECURITY?

            ''~``
           ( o o )
+-----.oooO--(_)--Oooo.------+
|                            |
|          FOWSNIFF          |
|            got             |
|           PWN3D!!!         |
|                            |
|       .oooO                |
|        (   )   Oooo.       |
+---------\ (----(   )-------+
           \_)    ) /
                 (_/


Fowsniff Corp got pwn3d by B1gN1nj4!


No one is safe from my 1337 skillz!


///////////////////////////////////////// 



