lets use gobuster to know the directories 

gobuster dir -u http://10.10.20.232/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 

using gobuster we found this website 

http://10.10.20.232/simple/

lets use it again on the same url 

gobuster dir -u http://10.10.20.232/simple/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 

its an effective technique


/////////

if found thos repositories 

─$ gobuster dir -u http://10.10.20.232/simple/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.20.232/simple/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/modules              (Status: 301) [Size: 321] [--> http://10.10.20.232/simple/modules/]
/uploads              (Status: 301) [Size: 321] [--> http://10.10.20.232/simple/uploads/]
/doc                  (Status: 301) [Size: 317] [--> http://10.10.20.232/simple/doc/]
/admin                (Status: 301) [Size: 319] [--> http://10.10.20.232/simple/admin/]
/assets               (Status: 301) [Size: 320] [--> http://10.10.20.232/simple/assets/]
/lib                  (Status: 301) [Size: 317] [--> http://10.10.20.232/simple/lib/]
Progress: 3241 / 220560 (1.47%)




///////

using nmap i found some open ports 

