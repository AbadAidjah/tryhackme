lets scan the machine using nmap : 

the result 

////////////////////////////


nmap -sC -sV 10.10.27.205             
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-05 22:10 UTC
Nmap scan report for 10.10.27.205
Host is up (0.20s latency).
Not shown: 992 closed tcp ports (conn-refused)
PORT      STATE    SERVICE     VERSION
22/tcp    open     ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0a:78:14:04:2c:df:25:fb:4e:a2:14:34:80:0b:85:39 (RSA)
|   256 8d:56:01:ca:55:de:e1:7c:64:04:ce:e6:f1:a5:c7:ac (ECDSA)
|_  256 1f:c1:be:3f:9c:e7:8e:24:33:34:a6:44:af:68:4c:3c (ED25519)
80/tcp    open     http        Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://olympus.thm
|_http-server-header: Apache/2.4.41 (Ubuntu)
1067/tcp  filtered instl_boots
2022/tcp  filtered down
2401/tcp  filtered cvspserver
3905/tcp  filtered mupdate
49163/tcp filtered unknown
62078/tcp filtered iphone-sync
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.39 seconds


///////////////////////////////

lets put this in the etc/hosts so that we can access the web page 10.10.27.205 olympus.thm

this is the result after using gobuster on the domain :

///////////////////////////////////

gobuster dir -u http://olympus.thm -w /usr/share/seclists/Discovery/Web-Content/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://olympus.thm
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/index.php            (Status: 200) [Size: 1948]
/javascript           (Status: 301) [Size: 315] [--> http://olympus.thm/javascript/]
/phpmyadmin           (Status: 403) [Size: 276]
/server-status        (Status: 403) [Size: 276]
/static               (Status: 301) [Size: 311] [--> http://olympus.thm/static/]
Progress: 4746 / 4747 (99.98%)
/~webmaster           (Status: 301) [Size: 315] [--> http://olympus.thm/~webmaster/]
===============================================================
Finished


////////////////////////



By brute forcing we found some intresting repositories 

//////////////


 gobuster dir -u http://olympus.thm/~webmaster/ -w /usr/share/seclists/Discovery/Web-Content/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://olympus.thm/~webmaster/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 276]
/.hta                 (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/LICENSE              (Status: 200) [Size: 1070]
/admin                (Status: 301) [Size: 321] [--> http://olympus.thm/~webmaster/admin/]
/css                  (Status: 301) [Size: 319] [--> http://olympus.thm/~webmaster/css/]
/fonts                (Status: 301) [Size: 321] [--> http://olympus.thm/~webmaster/fonts/]
/img                  (Status: 301) [Size: 319] [--> http://olympus.thm/~webmaster/img/]
/includes             (Status: 301) [Size: 324] [--> http://olympus.thm/~webmaster/includes/]
/index.php            (Status: 200) [Size: 9386]
/js                   (Status: 301) [Size: 318] [--> http://olympus.thm/~webmaster/js/]
Progress: 4746 / 4747 (99.98%)
===============================================================
Finished
===============================================================



///////////////////////

intresting name we found : Victor Alagwu

and intresting sentence found : with favorite from Victor Alagwu

!-- @author 'Victor Alagwu';
//   @project 'Simple Content Management System';
//   @date    '0ctober 2016'; -->


this repository http://olympus.thm/~webmaster/includes/ has some php files 








the os scan :

/////////////////////////


sudo nmap -O 10.10.27.205
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-05 22:14 UTC
Nmap scan report for 10.10.27.205
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 2 hops

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 5.09 seconds

/////////////////////////













