the first flag : 

mission 1 flag :

////////////////////////////////

agent47@linuxagency:~$ grep -r "mission1" /home/agent47/
/home/agent47/.ssh/rc:echo "mission1{174dc8f191bcbb161fe25f8a5b58d1f0}"

we used the grep -r cmnd to find the keyword mission in a specific repository 


agent47@linuxagency:~$ cd .ssh
agent47@linuxagency:~/.ssh$ ls
rc
agent47@linuxagency:~/.ssh$ cd rc
-bash: cd: rc: Not a directory
agent47@linuxagency:~/.ssh$ cat rc
echo "mission1{174dc8f191bcbb161fe25f8a5b58d1f0}"


agent47@linuxagency:~/.ssh$ 

/////////////////////////////////

lets change to user mission1 using the previous flag as password agent47@linuxagency:~/.ssh$ su - mission1   
Password: 
mission1@linuxagency:~$ 


mission 2 flag : 


///////////////////////////////////


here lies the second flag mission1@linuxagency:~$ ls -l
total 0
-r-------- 1 mission1 mission1 0 Jan 12  2021 mission2{8a1b68bb11e4a35245061656b5b9fa0d}
mission1@linuxagency:~$ pwd

//////////////////////
lets change to user mission2 using the previous flag as password
mission1@linuxagency:~$ su - mission2
Password: 
mission2@linuxagency:~$ 

mission 3 flag : 

/////////////////////////

here lies the flag directly  

mission1@linuxagency:~$ su - mission2
Password: 
mission2@linuxagency:~$ ls
flag.txt
mission2@linuxagency:~$ cat flag.txt 
mission3{ab1e1ae5cba688340825103f70b0f976}

//////////////////////////////

lets change to user mission3 using the previous flag as password

mission2@linuxagency:~$ su - mission3                                  
Password: 
mission3@linuxagency:~$ 



mission4 flag : 

/////////////////////////////


looks like the flag is hidden 

mission3@linuxagency:~$ grep -r "mission4" /home/mission3/        
I am really sorry man the flag is stolen by some thief's.fb7ff92d}
mission3@linuxagency:~$ file flag.txt 
flag.txt: ASCII text, with CR, LF line terminators 

he file flag.txt command shows that flag.txt is a plain ASCII text file with CR (Carriage Return) + LF (Line Feed) line endings (common in Windows text files).
Is It Hiding Something?

Possibly! Here’s how to check for hidden data:

lets inspect using hexdump for hex/ASCII (look for anomalies)

boom there is the flag hidden 

mission3@linuxagency:~$ hexdump -C flag.txt 
00000000  6d 69 73 73 69 6f 6e 34  7b 32 36 34 61 37 65 65  |mission4{264a7ee|
00000010  62 39 32 30 66 38 30 62  33 65 65 39 36 36 35 66  |b920f80b3ee9665f|
00000020  61 66 62 37 66 66 39 32  64 7d 0d 49 20 61 6d 20  |afb7ff92d}.I am |
00000030  72 65 61 6c 6c 79 20 73  6f 72 72 79 20 6d 61 6e  |really sorry man|
00000040  20 74 68 65 20 66 6c 61  67 20 69 73 20 73 74 6f  | the flag is sto|
00000050  6c 65 6e 20 62 79 20 73  6f 6d 65 20 74 68 69 65  |len by some thie|
00000060  66 27 73 2e 0a                                    |f's..|
00000065
mission3@linuxagency:~$ 

the flag : mission4{264a7eeb920f80b3ee9665fafb7ff92d}


//////////////////////////////////////

mission5 flag :

///////////////////////////

here lies the fifth flag 

mission3@linuxagency:~$ su - mission4
Password: 
mission4@linuxagency:~$ ls
flag
mission4@linuxagency:~$ ls -la
total 20
drwxr-x---  3 mission4 mission4 4096 Jan 12  2021 .
drwxr-xr-x 45 root     root     4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission4 mission4    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission4 mission4 3771 Jan 12  2021 .bashrc
drwxr-xr-x  2 mission4 mission4 4096 Jan 12  2021 flag
-rw-r--r--  1 mission4 mission4  807 Jan 12  2021 .profile
mission4@linuxagency:~$ cd flag/
mission4@linuxagency:~/flag$ ls
flag.txt
mission4@linuxagency:~/flag$ cat flag.txt 
mission5{bc67906710c3a376bcc7bd25978f62c0}
mission4@linuxagency:~/flag$ 


///////////////////////////

missio6 flag : 

///////////////////////////////

here lies mission 6 flag 

mission4@linuxagency:~/flag$ su - mission5
Password: 
mission5@linuxagency:~$ ls
mission5@linuxagency:~$ ls -la
total 20
drwxr-x---  2 mission5 mission5 4096 Jan 12  2021 .
drwxr-xr-x 45 root     root     4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission5 mission5    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission5 mission5 3771 Jan 12  2021 .bashrc
-r--------  1 mission5 mission5   43 Jan 12  2021 .flag.txt
-rw-r--r--  1 mission5 mission5  807 Jan 12  2021 .profile
mission5@linuxagency:~$ cat .flag.txt 
mission6{1fa67e1adc244b5c6ea711f0c9675fde}
mission5@linuxagency:~$ 



/////////////////////////////////


mission 7 flag : 


/////////////////////////

here lies the mission 7 flag :

mission6@linuxagency:~$ grep -r "mission7" /home/mission6
/home/mission6/.flag/flag.txt:mission7{53fd6b2bad6e85519c7403267225def5}
mission6@linuxagency:~$ 


//////////////////////////////


mission 8 flag :


//////////////////////////


here lies the mission 8 flag : 

/////////////////////////////////

mission7@linuxagency:/home$ ls | grep "mission7"
mission7
mission7@linuxagency:/home$ cd mission7
mission7@linuxagency:/home/mission7$ ls
flag.txt
mission7@linuxagency:/home/mission7$ cat flag.txt 
mission8{3bee25ebda7fe7dc0a9d2f481d10577b}
mission7@linuxagency:/home/mission7$ 

//////////////////////////////////////

mission 9 flag : 


////////////////////////////


here lies the mission9 flag :

mission8@linuxagency:~$ ls
mission8@linuxagency:~$ ls -la
total 16
drwxr-x---  2 mission8 mission8 4096 Jan 12  2021 .
drwxr-xr-x 45 root     root     4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission8 mission8    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission8 mission8 3771 Jan 12  2021 .bashrc
-rw-r--r--  1 mission8 mission8  807 Jan 12  2021 .profile
mission8@linuxagency:~$ cd / 
mission8@linuxagency:/$ cat flag.txt 
mission9{ba1069363d182e1c114bef7521c898f5}
mission8@linuxagency:/$ 


/////////////////////////////

mission 10 flag :

////////////////////////////////

u will find the flag inside rockyou :

just grep it like this grep -r "mission" /home/mission9/

mission9@linuxagency:~$ ls -la
total 136664
drwxr-x---  2 mission9 mission9      4096 Jan 12  2021 .
drwxr-xr-x 45 root     root          4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission9 mission9         9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission9 mission9      3771 Jan 12  2021 .bashrc
-rw-r--r--  1 mission9 mission9       807 Jan 12  2021 .profile
-r--------  1 mission9 mission9 139921551 Jan 12  2021 rockyou.txt
mission9@linuxagency:~$ grep -r "mission" /home/mission9/


/home/mission9/rockyou.txt:mission10{0c9d1c7c5683a1a29b05bb67856524b6}


////////////////////////////////


mission 11 flag : /

//////////////////////


here lies the flag :

mission10@linuxagency:~$ grep -r "mission" /home/mission10/
/home/mission10/folder/L4D8/L3D7/L2D2/L1D10/flag.txt:mission11{db074d9b68f06246944b991d433180c0}
mission10@linuxagency:~$ 



//////////////////////////


mission 12 flag :


////////////////////

ull find this one in the enviremental variables :

mission11@linuxagency:/home$ env
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
LESSCLOSE=/usr/bin/lesspipe %s %s
LANG=en_US.UTF-8
OLDPWD=/
USER=mission11
PWD=/home
HOME=/home/mission11
XDG_DATA_DIRS=/usr/local/share:/usr/share:/var/lib/snapd/desktop
MAIL=/var/mail/mission11
FLAG=mission12{f449a1d33d6edc327354635967f9a720}
SHELL=/bin/bash
TERM=xterm-kitty
flag=mission12{f449a1d33d6edc327354635967f9a720}
SHLVL=1
LOGNAME=mission11
PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/snap/bin
LESSOPEN=| /usr/bin/lesspipe %s
_=/usr/bin/env
mission11@linuxagency:/home$ 


the flag mission12{f449a1d33d6edc327354635967f9a720}

////////////////////

mission 13 flag : 


/////////////////////

we found the flag file but it has no permission :

mission12@linuxagency:~$ cat flag.txt 
cat: flag.txt: Permission denied
mission12@linuxagency:~$ ls -la
total 20
drwxr-x---  2 mission12 mission12 4096 Jan 12  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission12 mission12    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission12 mission12 3771 Jan 12  2021 .bashrc
----------  1 mission12 mission12   44 Jan 12  2021 flag.txt
-rw-r--r--  1 mission12 mission12  807 Jan 12  2021 .profile
mission12@linuxagency:~$ 


since we are the owner lets change its permission :

mission12@linuxagency:~$ chmod 444 flag.txt 
mission12@linuxagency:~$ cat flag.txt 
mission13{076124e360406b4c98ecefddd13ddb1f}
mission12@linuxagency:~$ 

444 is enough we just want to read it 

///////////////////////////////////////

mission 14 flag :


/////////////////////

mission13@linuxagency:~$ ls
flag.txt
mission13@linuxagency:~$ cat flag.txt 
bWlzc2lvbjE0e2Q1OThkZTk1NjM5NTE0Yjk5NDE1MDc2MTdiOWU1NGQyfQo=
mission13@linuxagency:~$ 

ok it looks like base64 so lets give it a try , lets use this website to decode it https://appdevtools.com/base64-encoder-decoder

here is the result mission14{d598de95639514b9941507617b9e54d2}
 

////////////////////////////////////////////////


mission 15 flag : 


////////////////////

looks like the file is written in binary 

mission14@linuxagency:~$ cat flag.txt 
01101101011010010111001101110011011010010110111101101110001100010011010101111011011001100110001100110100001110010011000100110101011001000011100000110001001110000110001001100110011000010110010101100110011001100011000000110001001100010011100000110101011000110011001100110101001101000011011101100110001100100011010100110101001110010011011001111101
mission14@linuxagency:~$ 

lets go to https://gchq.github.io/CyberChef/ and decode it from binary to text :

this is the result : mission15{fc4915d818bfaeff01185c3547f25596} 





////////////////////

mission 16 flag 

/////////////////////

we found this mission15@linuxagency:~$ ls
flag.txt
mission15@linuxagency:~$ cat flag.txt 
6D697373696F6E31367B38383434313764343030333363346332303931623434643763323661393038657D
mission15@linuxagency:~$ 

which looks like 

hexadecimal (hex) encoded ASCII text from what cipher identifier says https://www.dcode.fr/cipher-identifier


lets use cyberchef to decode it from hex to text :

the result :

mission16{884417d40033c4c2091b44d7c26a908e}

////////////////////////////////////


mission 17 flag : 

///////////////////////////////////////

we found some wierd things inside the file 

mission16@linuxagency:~$ cat flag 
ELF>0@�@8	@@@@�888

 ``/lib64/ld-linux-x86-64.so.2GNUGNU/{��2�q��|�J��!g 
                                                     )?� � 0"libc.so.6puts__stack_chk_failputcharstrlen__cxa_finalize__libc_start_mainGLIBC_2.4GLIBC_2.2.5_ITM_deregisterTMCloneTable__gmon_s � � � �� _regis� � � � H�H�%leii
]��f.�]�@f.�H�=i UH��	H�5b��t UH)�H��H��H��H��?H�H��tH�!	H��t���%�	h�����%�	f�1�I��^H��H���PTL�ZH�
                                                                     ]��f�]�@f.��=	u/H�= UH��t
����H���� ]����fDUH��]�f���UH��H��PdH�%(H�E�1�H�=\����H�gcyyced;H�=q>3l2n;H�E�H�U�H�9>2k;:?9H�o88;nlo=H�E�H�U�H�ll33l?ihH�E��E�l>wH�E�H���J����E��E��0�E�H��D���
�E�H��T��E�H��D�����������E��E�;E�|�H�=�������H�M�dH3
                                                     %(t�������f.�DAWAVI��AUATL�%^ UH�-^ SA��I��L)�H�H���W���H��t 1��L��L��D��A��H��H9�u�H�[]A\A]A^A_Ðf.���H�H��
;<����h����x���X�����x��������0zR����+zR�$����PFJ
�                                                �?;*3$"D���\�����A�C
D|����eB�B�E �B(�H0�H8�M@r8A0A(B BB�����0�
���o���                                   �
�
 � GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.08Tt���h	�
X
 �
 �   ��
]q�� �  ��e� �0+� :�  +"�
                         �crtstuff.cderegister_tm_clones__do_global_dtors_auxcompleted.7698__do_global_dtors_aux_fini_array_entryframe_dummy__frame_dummy_init_array_entryflag.c__FRAME_END____init_array_end_DYNAMIC__init_array_start__GNU_EH_FRAME_HDR_GLOBAL_OFFSET_TABLE___libc_csu_finiputchar@@GLIBC_2.2.5_ITM_deregisterTMCloneTableputs@@GLIBC_2.2.5_edatastrlen@@GLIBC_2.2.5__stack_chk_fail@@GLIBC_2.4__libc_start_main@@GLIBC_2.2.5__data_start__gmon_start____dso_handle_IO_stdin_used__libc_csu_init__bss_startmain__TMC_END___ITM_registerTMCloneTable__cxa_finalize@@GLIBC_2.2.5.symtab.strtab.shstrtab.interp.note.ABI-tag.note.gnu.build-id.gnu.hash.dynsym.dynstr.gnu.version.gnu.version_r.rela.dyn.rela.plt.init.plt.got.text.fini.rodata.eh_frame_hdr.eh_frame.init_array.fini_array.dynamic.data.bss.comment88#TT 1tt$D���o�N
�� ��0)@0+      pG��mission16@linuxagency:~$ ^C                 ��V���^���oTTk���ohhz���BXX������P�00r�������




lets identify the file  : 

mission16@linuxagency:~$ file flag 
flag: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=1606102f7b80d832eabee1087180ea7ce24a96ca, not stripped

It looks like an ELF binary (executable file) named flag instead of a text-based flag

since its executable lets give it the propre permissions since it has only read and then run it : 

mission16@linuxagency:~$ ls -la
total 28
drwxr-x---  2 mission16 mission16 4096 Jan 12  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission16 mission16    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission16 mission16 3771 Jan 12  2021 .bashrc
-r--------  1 mission16 mission16 8440 Jan 12  2021 flag
-rw-r--r--  1 mission16 mission16  807 Jan 12  2021 .profile
mission16@linuxagency:~$ chmod 777 flag 


lets run it : 

mission17{49f8d1348a1053e221dfe7ff99f5cbf4}

///////////////////////////////////////////////


mission 18 flag :

/////////////////////

looks like the flag is indside a java code and its encoded 

the code looks like it decypptes the flag upon running and print it 

mission17@linuxagency:~$ ls
flag.java
mission17@linuxagency:~$ nano flag.java
Error opening terminal: xterm-kitty.
mission17@linuxagency:~$ cat flag.java 
import java.util.*;
public class flag
{
    public static void main(String[] args)
    {
        String outputString="";
        String encrypted_flag="`d~~dbc<5vk=4:;=;9445;o954nil>?=lo8k:4<:h5p";
        int length = encrypted_flag.length();
        for (int i = 0 ; i < length ; i++)
        {
            outputString = outputString + Character.toString((char) (encrypted_flag.charAt(i) ^ 13)); 
        }
        System.out.println(outputString);
    }
}
mission17@linuxagency:~$ 


so lets compile the code with javac and run it with java 


like this 


mission17@linuxagency:~$ ls
flag.java
mission17@linuxagency:~$ javac flag.java 
mission17@linuxagency:~$ java flag 
mission18{f09760649986b489cda320ab5f7917e8}
mission17@linuxagency:~$ 

 



///////////////

mission 19 flag:


//////////////////

so it looks like a ruby file that has a function that decryptes a passsed string which is currently the flag

mission18@linuxagency:~$ ls
flag.rb
mission18@linuxagency:~$ cat flag.rb 
def encryptDecrypt(string)
    key = ['K', 'C', 'Q']
    result = ""
    codepoints = string.each_codepoint.to_a
    codepoints.each_index do |i|
        result += (codepoints[i] ^ 'Z'.ord).chr
    end
    result
end

encrypted = encryptDecrypt("73))354kc!;j8<nk<ol8i;9lhh>bjb<m;nibohon8m'")
puts "#{encrypted}"


lets execute it 

mission18@linuxagency:~$ ruby flag.rb 
mission19{a0bf41f56b3ac622d808f7a4385254b7}
mission18@linuxagency:~$ 



/////////////////


mission 20 flag : 


//////////////////////////

we found this c file 

mission19@linuxagency:~$ ls
flag.c
mission19@linuxagency:~$ cat flag.c 
#include<stdio.h>
int main()
{
    char flag[] = "gcyyced8:qh:>28l3o3:i2kn8>8;hl>9?9in2oko;iw";
    int length = strlen(flag);
    for (int i = 0 ; i < length ; i++)
    {
        flag[i] = flag[i] ^ 10;
        printf("%c",flag[i]);
    }
    printf("\n\n");
    return 0;
}
mission19@linuxagency:~$ 


What the Code Does

    Stores an encrypted string:
    c

char flag[] = "gcyyced8:qh:>28l3o3:i2kn8>8;hl>9?9in2oko;iw";

Decrypts it using XOR with key 10:
c

flag[i] = flag[i] ^ 10;  // XOR each character with 10

Prints the decrypted flag:
c

printf("%c", flag[i]);


lets compile the file 

mission19@linuxagency:~$ gcc flag.c -o flag
flag.c: In function ‘main’:
flag.c:5:18: warning: implicit declaration of function ‘strlen’ [-Wimplicit-function-declaration]
     int length = strlen(flag);
                  ^~~~~~
flag.c:5:18: warning: incompatible implicit declaration of built-in function ‘strlen’
flag.c:5:18: note: include ‘<string.h>’ or provide a declaration of ‘strlen’


and then run it 

mission19@linuxagency:~$ ./flag 
mission20{b0482f9e90c8ad2421bf4353cd8eae1c}


///////////////////////////////////







mission 21 flag :



/////////////////////

we found this python file 

mission20@linuxagency:~$ ls
flag.py
mission20@linuxagency:~$ cat flag.py 
flag = ">:  :<=ab(d76dfe2210fak1gge5e61`kgbj`bk5c0."
for i in range(len(flag)):
    flag = (flag[:i] + chr(ord(flag[i]) ^ ord("S")) +flag[i + 1:]);
    print(flag[i], end = "");
print()

This Python script performs a XOR decryption on the string flag using the character "S" as the XOR key. Here's a breakdown of what it does and how to get the decrypted flag:
What the Code Does

    Takes an encrypted string:
    python

flag = ">:  :<=ab(d76dfe2210fak1gge5e61`kgbj`bk5c0."

Decrypts it character-by-character using XOR with "S":
python

chr(ord(flag[i]) ^ ord("S"))  # XOR each character with ASCII value of "S" (83)

Prints each decrypted character immediately (without storing the full decrypted string):
python

print(flag[i], end="")

here is the flag 

mission20@linuxagency:~$ python3 flag.py 
mission21{7de756aabc528b446f6eb38419318f0c}
mission20@linuxagency:~$ 

/////////////////


mission 22 flag 

////////////////



//////////////////















