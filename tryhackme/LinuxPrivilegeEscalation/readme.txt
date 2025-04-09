uname -a

Will print system information giving us additional detail about the kernel used by the system. This will be useful when searching for any potential kernel vulnerabilities that could lead to privilege escalation.



/proc/version

The proc filesystem (procfs) provides information about the target system processes. You will find proc on many different Linux flavours, making it an essential tool to have in your arsenal.

Looking at /proc/version may give you information on the kernel version and additional data such as whether a compiler (e.g. GCC) is installed.

/etc/issue

Systems can also be identified by looking at the /etc/issue file. This file usually contains some information about the operating system but can easily be customized or changed. While on the subject, any file containing system information can be customized or changed. For a clearer understanding of the system, it is always good to look at all of these.


 ps Command

The ps command is an effective way to see the running processes on a Linux system. Typing ps on your terminal will show processes for the current shell.

The output of the ps (Process Status) will show the following;

    PID: The process ID (unique to the process)
    TTY: Terminal type used by the user
    Time: Amount of CPU time used by the process (this is NOT the time this process has been running for)
    CMD: The command or executable running (will NOT display any command line parameter)
    
    
The “ps” command provides a few useful options.

    ps -A: View all running processes
    ps axjf: View process tree (see the tree formation until ps axjf is run below)


ps aux: The aux option will show processes for all users (a), display the user that launched the process (u), and show processes that are not attached to a terminal (x). Looking at the ps aux command output, we can have a better understanding of the system and potential vulnerabilities.


env
The env command will show environmental variables.



The PATH variable may have a compiler or a scripting language (e.g. Python) that could be used to run code on the target system or leveraged for privilege escalation.



sudo -l

The target system may be configured to allow users to run some (or all) commands with root privileges. The sudo -l command can be used to list all commands your user can run using sudo.


ls

One of the common commands used in Linux is probably ls.


While looking for potential privilege escalation vectors, please remember to always use the ls command with the -la parameter. The example below shows how the “secret.txt” file can easily be missed using the ls or ls -l commands.


 Id

The id command will provide a general overview of the user’s privilege level and group memberships. 


    etc/passwd

Reading the /etc/passwd file can be an easy way to discover users on the system.

While the output can be long and a bit intimidating, it can easily be cut and converted to a useful list for brute-force attacks. 


 history

Looking at earlier commands with the history command can give us some idea about the target system and, albeit rarely, have stored information such as passwords or usernames. 


 netstat

Following an initial check for existing interfaces and network routes, it is worth looking into existing communications. The netstat command can be used with several different options to gather information on existing connections.


    netstat -a: shows all listening ports and established connections.
    netstat -at or netstat -au can also be used to list TCP or UDP protocols respectively.
    netstat -l: list ports in “listening” mode. These ports are open and ready to accept incoming connections. This can be used with the “t” option to list only ports that are listening using the TCP protocol (below)
    
    
    netstat -s: list network usage statistics by protocol (below) This can also be used with the -t or -u options to limit the output to a specific protocol. 
    
    
    netstat -tp: list connections with the service name and PID information.
    
    This can also be used with the -l option to list listening ports (below)
    
    
    netstat -i: Shows interface statistics
    
    
     The netstat usage you will probably see most often in blog posts, write-ups, and courses is netstat -ano which could be broken down as follows;

    -a: Display all sockets
    -n: Do not resolve names
    -o: Display timers
    
    
    
    
    
    //////////// to know what linux is this /////////
    
    
    $ cat /etc/os-release
NAME="Ubuntu"
VERSION="14.04, Trusty Tahr"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 14.04 LTS"
VERSION_ID="14.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
$ 


///////////////////////////////////////////


/////////////////python version //////////////

$ python --version
Python 2.7.6
$ 


///////////////////////////////////////////////


///////////////kernal vulnerability for this machine ///////////


Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation
EDB-ID:
37292
CVE:
2015-1328

EDB Verified:
Author:
rebel
Type:
local

Exploit:   /  
Platform:
Linux
Date:
2015-06-16

Vulnerable App:

/////////////////////////////////////////////////////






      
    







