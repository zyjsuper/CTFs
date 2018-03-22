### Packet abomination [100p]
we have to extract the hash here, after doing a simple attempt i got a hash but it wasn't what we want
```
root@DESKTOP-NS9V6J9:~# strings Packet-abomination.pcap | grep -e "[0-9a-f]\{32\}" -w  -o | sort -u
632e1c9b593b0faf778e6de166448d93
```
so i looked again and i found this weird sort of strings
```
root@DESKTOP-NS9V6J9:~# strings Packet-abomination.pcap | tail
4?`T
E@/}
&%/U%
>W{@
<W|@
<W~@
P=C$^!
lllllllllllllllllllllllllllllllllllllllllllllll0
e'G^A
ff'G&`
root@DESKTOP-NS9V6J9:~# echo lllllllllllllllllllllllllllllllllllllllllllllll0 | wc -c
49
root@DESKTOP-NS9V6J9:~# strings Packet-abomination.pcap | grep -e "[0-9A-Za-z]\{49\}" -w -o
mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm92
iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii24
uccccccccccccccccccccccccccccccccccccccccccccccc8
2dddddddddddddddddddddddddddddddddddddddddddddddc
Geeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee7
dxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxd
vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv5h
ggggggggggggggggggggggggggggggggggggggggggggggg2r
zwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwe
```
I opened wireshark and searched for ``` lllllllllllllllllllllllllllllllllllllllllllllll0 ``` string to find 32 unknown packets, which was interesting because the length of the md5 hashes is 32 too, so I filtered and sorted them and I took each char at the end then combiend them together to get the flag
![packet-abomination-solve](https://user-images.githubusercontent.com/22657154/37759323-ed14f6a2-2dbb-11e8-933f-03a5286f8ffc.png)
``` Flag: 5a365f92d8c7f2e2c109974f5fc85ed5 ```

### JTAG Dump [100p]
![screenshot at 2018-03-22 12-20-33](https://user-images.githubusercontent.com/22657154/37764874-2a2c8dca-2d99-11e8-91a1-6718c177f7d4.png)

``` Flag : Flag{Remember_header_then_footer} ```

### Raw Disk [100p]
![screenshot at 2018-03-22 12-16-23](https://user-images.githubusercontent.com/22657154/37764704-b9db15f0-2d98-11e8-8f82-804854f83a64.png)
``` Flag : 	flag{Hello_again_:D} ```

### ADSL Modem [100p]
```
┌─[root@parrot]─[~]
└──╼ #file Adsl-modem.bin 
Adsl-modem.bin: RAR archive data, v4, os: Win32
┌─[root@parrot]─[~]
└──╼ #unrar e Adsl-modem.bin

UNRAR 5.50 freeware      Copyright (c) 1993-2017 Alexander Roshal


Extracting from Adsl-modem.bin

Flag{reversing_FW_is_interesting_but_this_is_for_fun}

Extracting  TL-MR3220 V2 _FW.bin                                      OK 
All OK
┌─[root@parrot]─[~]
└──╼ #
```
``` Flag : Flag{reversing_FW_is_interesting_but_this_is_for_fun} ```

### Cypher Anxiety [50p]

the flag was sent and captured inside the pcap file, but binwalk and foremost couldn't find anything !
```
┌─[root@parrot]─[~]
└──╼ #binwalk find\ the\ image.pcap 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------

┌─[root@parrot]─[~]
└──╼ #foremost find\ the\ image.pcap 
Processing: find the image.pcap
|*|
┌─[root@parrot]─[~]
└──╼ #ls -R output/
output/:
audit.txt

```
so i took a look at strings inside the pcap ...
```
┌─[root@parrot]─[~]
└──╼ #strings find\ the\ image.pcap  -n 10 | head -n 8
Sup supp, are we ready
yeah, u got the files?
yes but i think the channel is not secured
the UTM will block the file transfer as the DLP module is active
ok we can use cryptcat
ok what the password then
let it be P@ssawordaya
listen on 7070 and ill send you the file , bye

````
So they use cryptcat over the port ```7070``` with the secret key ```P@ssawordaya```.
With wireshark let's filter ```tcp.port == 7070```, then flow TCP stream and save it as raw file.

![screenshot at 2018-03-22 11-26-29](https://user-images.githubusercontent.com/22657154/37764924-4e83b25c-2d99-11e8-8782-f167a71b2737.png)

Then open a netcat client on localhost: ```netcat localhost 7070 < crypted.file```.
And open a cryptcat listener on localhost: ```cryptcat -l -k P@ssawordaya -p 7070 > decrypted.file```.

``` Flag : 3beef06be834f3151309037dde4714ec ```

### G&P List [25]
![screenshot at 2018-03-22 12-52-45](https://user-images.githubusercontent.com/22657154/37766646-f2d3ad86-2d9d-11e8-8baf-0d373bb216f6.png)

``` Flag : 877c1fa0445adaedc5365d9c139c5219 ```

### Lost Files [100]
```
┌─[root@parrot]─[~/Downloads]
└──╼ #strings lost_files.mem.001 | grep -i flag | head 
B.j.YFlag(You_Get_It_2)
...Flag(You_Get_It_2)
Local\{C15730E2-145C-4c5e-B005-3BC753F42475}-once-flag
Adobe APP14 marker: version %d, flags 0x%04x 0x%04x, transform %d
unknown header flags set
GlobalFlags
?GetFlags@CxImage@@QBEKXZ
?SetFlags@CxImage@@QAEXK_N@Z
U_REGEX_INVALID_FLAG
TMenuItemAutoFlag
```
``` Flag : Flag(You_Get_It_2) ```

### Partition Lost [50]
```
┌─[✗]─[root@parrot]─[~/Downloads]
└──╼ #strings partition-lost.img  | grep flag -i | tail  -n 1 | sed 's/fM//g'
FLAG(701_L@b$_DR_DFIR)
```
``` Flag : FLAG(701_L@b$_DR_DFIR) ```

### Hidden message [25]
```
┌─[root@parrot]─[~/Downloads]
└──╼ #strings hidden_message.jpg | grep "[0-9a-f]\{32\}"
 b1a1f2855d2428930e0c9c4ce10500d5
```
``` Flag : b1a1f2855d2428930e0c9c4ce10500d5 ```
