 Task 1
Level 1 :

using https://crackstation.net/ to crack thos 3 passwords 
48bb6e862e54f2a795ffc4e541caed4d : 

Hash	Type	Result
48bb6e862e54f2a795ffc4e541caed4d	md5	easy


///////////////////////////////////////////////


CBFDAC6008F9CAB4083784CBD1874F76618D2A97 
using crack station 

Hash	Type	Result
CBFDAC6008F9CAB4083784CBD1874F76618D2A97	sha1	password123



////////////////////////////////////////


1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032

Hash	Type	Result
1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032	sha256	letmein


//////////////////////////////////////////


$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom

Search the hashcat examples page (https://hashcat.net/wiki/doku.php?id=example_hashes) 
for $2y$. This type of hash can take a very long time to crack, 
so either filter rockyou for four character words, or use a mask for four lower case alphabetical characters.


lets create a filtered wordlist: of rockyou by extracting only 4 char : //// awk 'length($0)==4' /usr/share/wordlists/rockyou.txt > rockyou_4char.txt   ///

awk: cmd. line:1: (FILENAME=/usr/share/wordlists/rockyou.txt FNR=602043) warning: Invalid multibyte data detected. There may be a mismatch between your data and your locale


now we have created the filtered file : 

lets crack  it using this cmnd : hashcat -m 3200 -a 0 level1.txt rockyou_4char.txt

////////////////////////////////


 -m 3200

    This specifies the hash mode.

    3200 corresponds to bcrypt ($2y$, $2a$, $2b$ hashes).

    You can find this on Hashcat’s hash modes page.

🔁 -a 0

    This sets the attack mode.

    0 means a straight dictionary attack — hashcat takes each word in the wordlist and tries it directly against the hash.

    There are other modes like:

        -a 3: brute-force (mask attack),

        -a 6: combinator,

        -a 7: hybrid, etc.

📄 level1.txt

    This is the file that contains the hash you're trying to crack.

    It must contain a properly formatted hash on its own line, like:

    $2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom

📚 rockyou_4char.txt

    This is your wordlist — a filtered version of the famous rockyou.txt that contains only 4-character passwords.

    You can generate it with:

    awk 'length($0)==4' /usr/share/wordlists/rockyou.txt > rockyou_4char.txt


//////////////////////////////////////////


now that the password has cracked : 

//////////////////////////////////////////////////



$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom:bleh
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX...8wsRom
Time.Started.....: Sun May  4 15:24:44 2025 (57 secs)
Time.Estimated...: Sun May  4 15:25:41 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou_4char.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       23 H/s (13.54ms) @ Accel:1 Loops:1 Thr:16 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1280/18152 (7.05%)
Rejected.........: 0/1280 (0.00%)
Restore.Point....: 0/18152 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4095-4096
Candidate.Engine.: Device Generator
Candidates.#1....: love -> aqua

Started: Sun May  4 15:24:29 2025
Stopped: Sun May  4 15:25:41 2025

///////////////////////////////////////////////////////


as we see the password is "bleh" 

hashcat --show -m 3200 level1.txt

$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom:bleh

///////////////////////////////////////////////////



279412f945939ba78ce0758d3fd83daa

using crack station 

Hash	Type	Result
279412f945939ba78ce0758d3fd83daa	md4	Eternity22



//////////////////////////////////////////////////////////////////////////////////////////////








///////////////////////////////////////

Level 2:

This task increases the difficulty. All of the answers will be in the classic rock you password list.

You might have to start using hashcat here and not online tools. It might also be handy to look at some example hashes on hashcats page.



Hash: F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85

https://crackstation.net/

using crackstation : 

Hash	Type	Result
F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85	sha256	paule




//////////////////////////////////////////////

using crackstation


1DFECA0C002AE40B8619ECF94819CC1B

Hash	Type	Result
1DFECA0C002AE40B8619ECF94819CC1B	NTLM	n63umy8lkf4i



/////////////////////////////////////////

Hash: $6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.

Salt: aReallyHardSalt

Hash Format: $6$salt$hashed

This format means:

    $6$ → SHA-512

    aReallyHardSalt → the salt used

    The long string after that → the hashed password





    SHA-512 crypt mode in Hashcat is:

-m 1800

    From Hashcat's documentation:
    $6$ → mode 1800 → SHA512crypt



as u see the salt is alerady in the hash : 


///////////////////////////////////////////

$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.
│ │        │                          └─ Hashed password
│ │        └─ Salt used
│ └─ ID for SHA-512 (6 = SHA-512, 5 = SHA-256, 1 = MD5)
└─ Prefix to indicate hash type



since the password is 6 chars lets extract all 6 chars from rockyou 

 awk 'length($0)==6' /usr/share/wordlists/rockyou.txt > rockyou_6char.txt  
awk: cmd. line:1: (FILENAME=/usr/share/wordlists/rockyou.txt FNR=602043) warning: Invalid multibyte data detected. There may be a mismatch between your data and your locale



since hashcat is slow for me i used john and after a while i cracked it 


{{{{{{{{{{{{{{{{{{{{{{{{{




john --format=crypt --wordlist=rockyou_6char.txt level2_4th.txt

Using default input encoding: UTF-8
Loaded 1 password hash (crypt, generic crypt(3) [?/64])
Cost 1 (algorithm [1:descrypt 2:md5crypt 3:sunmd5 4:bcrypt 5:sha256crypt 6:sha512crypt]) is 6 for all loaded hashes
Cost 2 (algorithm specific iterations) is 5000 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
waka99           (?)
1g 0:00:07:12 DONE (2025-05-04 16:52) 0.002314g/s 1471p/s 1471c/s 1471C/s wakkys..wajzim
Use the "--show" option to display all of the cracked passwords reliably
Session completed

 Sun  4 May - 16:52  ~/Desktop/work/tryhackme/CrackTheHash   master 5☀ 1‒ 
 @Abad  john --show level2_4th.txt                                     
?:waka99

1 password hash cracked, 0 left




}}}}}}}}}}}}}}}}}}}}}}

the password is : waka99






//////////////////////////////////////////




for 

Hash: e5d8870e5bdd26602cab8dbe07a942c8669e56d6

Salt: tryhackme


it says that its HMAC-SHA1 : lets search for it in https://hashcat.net/wiki/doku.php?id=example_hashes


we found 2 results : 

150 	HMAC-SHA1 (key = $pass) 	c898896f3f70f61bc3fb19bef222aa860e5ea717:1234
160 	HMAC-SHA1 (key = $salt) 	d89c92b4400b15c39e462a8caa939ab40c3aeeea:1234 

lets pick the second one cause its the format that we have HMAC-SHA1 (key = $salt)  

lets crack it : hashcat -m 160 'e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme' /usr/share/wordlists/rockyou.txt

the result 

{////////////////


e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme:481616481616
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 160 (HMAC-SHA1 (key = $salt))
Hash.Target......: e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme
Time.Started.....: Sun May  4 16:32:25 2025 (7 secs)
Time.Estimated...: Sun May  4 16:32:32 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1775.5 kH/s (9.72ms) @ Accel:16 Loops:1 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 12369920/14344384 (86.24%)
Rejected.........: 0/12369920 (0.00%)
Restore.Point....: 12288000/14344384 (85.66%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 496635 -> 45090990

Started: Sun May  4 16:32:12 2025
Stopped: Sun May  4 16:32:33 2025

/////////////////}

this is the password : 481616481616 









