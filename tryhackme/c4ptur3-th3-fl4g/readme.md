
Translation & Shifting

/////////  1  ///////////// 

c4n y0u c4p7u23 7h3 f149? : 

can you capture the flag?

It's written in leet speak (1337 speak), a form of obfuscation often used online where letters are replaced by similar-looking numbers or symbols.


/////////////////////// 


////////  2  //////////

01101100 01100101 01110100 01110011 00100000 01110100 01110010 01111001 00100000 01110011 01101111 01101101 01100101 00100000 01100010 01101001 01101110 01100001 01110010 01111001 00100000 01101111 01110101 01110100 00100001
this is some binary 

the answer is : "lets try some binary out!" 

u can do this by transforming each bit into decimal then decimal into ascii letters 

////////////////////// 

////////  3  /////////////

MJQXGZJTGIQGS4ZAON2XAZLSEBRW63LNN5XCA2LOEBBVIRRHOM======

its Base32, cause base32 uses A-Z and 2-7 only.

the string only contains uppercase letters and digits 2-7 — a classic Base32 signature.

i cracked it using a python library from base64 to decode base32

{{{{{{{{{{{{{}}}}}}}}}}}}}
import base64

encoded = "MJQXGZJTGIQGS4ZAON2XAZLSEBRW63LNN5XCA2LOEBBVIRRHOM"

# Add padding to make length a multiple of 8
while len(encoded) % 8 != 0:
    encoded += '='
# Base32 encoding produces output in chunks of 8 characters.
# If the string length isn’t a multiple of 8, the decoder throws “Incorrect padding”.
# So this loop adds = until the length divisible by 8, making it valid for decoding.
decoded = base64.b32decode(encoded)
print(decoded)
}}}}}}}}}}}}}}}{{{{{{{{{{{{{{}


the decoded value : base32 is super common in CTF's

file used is crackbase32.py 
////////////////////////// 


/////////  4  /////////

RWFjaCBCYXNlNjQgZGlnaXQgcmVwcmVzZW50cyBleGFjdGx5IDYgYml0cyBvZiBkYXRhLg==

this is a base64 hash u can crack it via anywebsite that decode base64 its very populare , like this one https://appdevtools.com/base64-encoder-decoder

the result : "Each Base64 digit represents exactly 6 bits of data."


/////////////////////// 


///////////   5   /////////////

68 65 78 61 64 65 63 69 6d 61 6c 20 6f 72 20 62 61 73 65 31 36 3f

using any hash identifier tool it will tell u that this is Hex encoded string 

i used this website to crack it : https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')&input=NjggNjUgNzggNjEgNjQgNjUgNjMgNjkgNmQgNjEgNmMgMjAgNmYgNzIgMjAgNjIgNjEgNzMgNjUgMzEgMzYgM2Y

the result :  "hexadecimal or base16?"

///////////////////////////// 


//////////   6   /////////// 

Ebgngr zr 13 cynprf!

this is an english text encoded with ROT13 

u can use this website to decrypte it : https://cryptii.com/pipes/rot13-decoder 

the result : "Rotate me 13 places!"

///////////////////////// 


//////////////   7   ////////////// 

*@F DA:? >6 C:89E C@F?5 323J C:89E C@F?5 Wcf E:>6DX

if you go to https://www.dcode.fr/cipher-identifier?utm_source=chatgpt.com

it will tell u its ROT47 , u can go to cipher-identifier to crack it here https://www.dcode.fr/rot-47-cipher 

the result is : You spin me right round baby right round (47 times)


///////////////////////////////////// 


//////////////   8   ////////////////  

- . .-.. . -.-. --- -- -- ..- -. .. -.-. .- - .. --- -.

. -. -.-. --- -.. .. -. --. 

this is morse code : again u can use cipher-identifier to crack it https://www.dcode.fr/morse-code

the result : "telecommunication encoding"

//////////////////////////////// 

///////////   9   ////////////// 

85 110 112 97 99 107 32 116 104 105 115 32 66 67 68

this is decimal ascii code , u can decode it from here https://gchq.github.io/CyberChef/#recipe=From_Decimal('Space',false)&input=ODUgMTEwIDExMiA5NyA5OSAxMDcgMzIgMTE2IDEwNCAxMDUgMTE1IDMyIDY2IDY3IDY4&oeol=NEL

the result : "Unpack this BCD"


///////////////////////////// 

//////////// 10 //////////////// 


LS0tLS0gLi0tLS0gLi0tLS0gLS0tLS0gLS0tLS0gLi0tLS0gLi0tLS0gLS0tLS0KLS0tLS0gLi0tLS0gLi0tLS0gLS0tLS0gLS0tLS0gLi0tLS0gLS0tLS0gLi0tLS0KLS0tLS0gLS0tLS0gLi0tLS0gLS0tLS0gLS0tLS0gLS0tLS0gLS0tLS0gLS0tLS0 


for this u need to make shure to copy every thing to the last letter which is "=" use inspect mode for this , and then u gonna take this order to decrypte it 

base64 --> morse code --> ASCCI --> ROT47 --> decimal 


//////////////////////////////// 



Spectrograms : 


///////////////// 


this is spectogram so to get the hidden message u need to go to spectrum analyzer gives us a graph of all the frequencies that are present in a sound recording at a given time like this one https://academo.org/demos/spectrum-analyzer/ u will find that the secret code is "Super Secret Message"


////////////////// 


Steganography 

//////////////// 

u need to use steghide and extract data or hidden content in a file 

like this 

{{{{{{{{{{{{{{{{{{}}}}}}}}}}}}}}}}}}
✘  Wed  3 Sep - 19:20  ~/Desktop/DeskOld/work/tryhackme/c4ptur3-th3-fl4g   main 3☀ 1● 
 @Abad  steghide extract -sf stegosteg_1559008553457.jpg 
Enter passphrase: 
wrote extracted data to "steganopayload2248.txt".

 Wed  3 Sep - 19:22  ~/Desktop/DeskOld/work/tryhackme/c4ptur3-th3-fl4g   main 3☀ 1● 
 @Abad  ls
 crackbase32.py   secretaudio_1559007588454.wav   stegosteg_1559008553457.jpg
 readme.md        steganopayload2248.txt         󰌠 venv

 Wed  3 Sep - 19:22  ~/Desktop/DeskOld/work/tryhackme/c4ptur3-th3-fl4g   main 3☀ 1● 
 @Abad  cat steganopayload2248.txt 
SpaghettiSteg%                
{{{{{{{{{{{{{{{{{{{}}}}}}}}}}}}}}}}}}}


///////////////// 

Security through obscurity : 

//////////////////////// 

if you use binwalk on the photo u will find that it contains a RAR archive embedded, appened to the end of it 

if you extract it like this 

binwalk -e meme_1559010886025.jpg

you will find an image named : hackerchat.png 

using strings command on this png file u will find that the flag is in the end of the output "AHH_YOU_FOUND_ME!" , strings is a simple but powerful tool in Linux that extracts and prints printable text strings from a binary file

the cmnd : 

 strings hackerchat.png

The data was hidden in the metadata/strings of the image – not encrypted or securely steganographed. It was simply appended as plain text within the PNG file.
