when using nmap we got 2 ports 

now lets use gobuster 

gobuster dir -u http://10.21.144.196 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

nb: when copying ip@ to the browser all ways make shure that u type slash in the end of it sometimes it revealse a page 


Looks like there's a web server running, what is the title of the page we discover when browsing to it? : by using slash in the end of the ip we found a web page we inspected in and picked the titel : 10.10.145.192/ the title is 
//////////////
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />

<title>IIS Windows Server</title>
<style type="text/css">

///////////
