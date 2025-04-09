first lets use gobuster 


gobuster dir -u http://10.10.224.214 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 

we found a login here http://10.10.224.214/mbilling/

so since it is using this framework lets try 
searching for it 

{mbilling}

we found in exploits db 
https://www.exploit-db.com/exploits/50102

a Remote Code Execution (RCE) (Unauthenticated)
