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

![arm](https://user-images.githubusercontent.com/22657154/43360111-f0cc44fe-92af-11e8-9872-0951635796ee.png)

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

Zoom in on the image and hunting around. You'll find the flag hidden in the image, obscured slightly by another piece of writing in the photo. 

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

