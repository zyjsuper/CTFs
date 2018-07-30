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
```
┌─[root@parrot]─[~/Downloads/Policies]
└──╼ #grep -R -i "pass" | tr ' ' '\n' | grep -i pass
cpassword="PCXrmCkYWyRRx3bf+zqEydW9/trbFToMDx6fAvmeCDw"
```
i didn't know what is Cpassword at the first time but after googling ```cpassword decrypt``` i found this article : ```https://tools.kali.org/password-attacks/gpp-decrypt``` on a tool called ```gpp-decrypt```

back to terminal..
```
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

## Encrypted ZIP
we don't have to use known plain text attack, just use rockyou!

```
┌─[✗]─[root@parrot]─[/tmp]
└──╼ #fcrackzip -v -D -u -p /usr/share/wordlists/rockyou.txt flag.zip 
found file 'flag.txt', (size cp/uc     41/    29, flags 1, chk 5851)


PASSWORD FOUND!!!!: pw == testtest
```

## Is it a secure string?
after googling ```secure strings decrypt``` i found these references
```
https://blogs.msdn.microsoft.com/besidethepoint/2010/09/21/decrypt-secure-strings-in-powershell/
https://blogs.msdn.microsoft.com/timid/2009/09/10/powershell-one-liner-decrypt-securestring/
```
and it was a ```powershell``` task.

```powershell
$encrytedFlag = '76492d1116743f0423413b16050a5345MgB8AEEAYQBNAHgAZQAxAFEAVABIAEEAcABtAE4ATgBVAFoAMwBOAFIAagBIAGcAPQA9AHwAZAAyADYAMgA2ADgAMwBlADcANAA3ADIAOQA1ADIAMwA0ADMAMwBlADIAOABmADIAZABlAGMAMQBiAGMANgBjADYANAA4ADQAZgAwADAANwA1AGUAMgBlADYAMwA4AGEAZgA1AGQAYgA5ADIAMgBkAGIAYgA5AGEAMQAyADYAOAA='

$key = (3,4,2,3,56,34,254,222,205,34,2,23,42,64,33,223,1,34,2,7,6,5,35,12)

$SecureFlag = ConvertTo-SecureString -String $encrytedFlag -Key $key

[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureFlag))
```


## Crypto object

The code on the ribbon is:
```
GMODCDOOKCDBIOYDRMKDPQLDPVWYOIVRVSEOV
```
Which means nothing, so I rot13'd it 'til the letters looked right (Conatins F, L, A and G).
```
WCETSTEEASTRYEOTHCATFGBTFLMOEYLHLIUEL
```
But that didn't do much, until I stumbled on scytale coding.

With 3 turns we get:
```
WELCOMETOTHESCYTALETHEFLAGISBUTTERFLY
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

![arm](https://user-images.githubusercontent.com/22657154/43360111-f0cc44fe-92af-11e8-9872-0951635796ee.png)

# Jail Escaping
```
http://blog.dornea.nu/2016/06/20/ringzer0-ctf-jail-escaping-bash/
```

## bash jail 1

![jail1](https://user-images.githubusercontent.com/22657154/43360121-26199ee0-92b0-11e8-97f4-0e92220b8a76.png)

## bash jail 2 

```https://unix.stackexchange.com/questions/351331/how-to-send-a-command-with-arguments-without-spaces```
```
payload hello|cat${IFS%?}/home/level2/flag.txt or just hello|cat<flag.txt
```

![jail2](https://user-images.githubusercontent.com/22657154/43360122-264aa3dc-92b0-11e8-91d3-fc1282eec2a3.png)

## bash jail 3
We can no longer use cat, But there are other alternatives that will work the same way in this instance.
<br>
I opted for uniq, and since we can use spaces again why not just throw it in eval?
```
eval uniq flag.txt 
```
That passes the filter so all we need to do is figure out a way to actually make it print our result. We
have three file descriptors: 0,1,2 and only 1 and 2 are blocked!

![jail3](https://user-images.githubusercontent.com/22657154/43360268-1a5cf43c-92b3-11e8-8dc6-b44f63ee5ce8.png)

## bash jail 4

![jail5](https://user-images.githubusercontent.com/22657154/43361356-44a3fba6-92d5-11e8-9b73-4d1a5e529000.png)

## bash jail 5 

![screenshot_20180729_011221](https://user-images.githubusercontent.com/22657154/43361354-2b9f7c20-92d5-11e8-928a-c812857a2cd9.png)

