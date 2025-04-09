the cmnds are :
prepare 
fsociety
inform 
question
wakeup
join

lets use nmap to know a couple of things about the machine 
nmap -sC -sV 10.10.248.246

this is the result 

///////

Abad㉿kali)-[~/Desktop/work/tryhackme/mrrobot]
└─$ nmap -sC -sV 10.10.248.246
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-19 22:56 GMT
Nmap scan report for 10.10.248.246
Host is up (0.41s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
443/tcp open   ssl/http Apache httpd
|_http-server-header: Apache
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03
|_http-title: Site doesn't have a title (text/html).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.60 seconds


//////


the script of the first page 

////////

<script>var USER_IP='208.185.115.6';var BASE_URL='index.html';var RETURN_URL='index.html';var REDIRECT=false;window.log=function(){log.history=log.history||[];log.history.push(arguments);if(this.console){console.log(Array.prototype.slice.call(arguments));}};</script>

  

///////
