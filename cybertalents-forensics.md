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

``` Flag : Flag{Remember_header_then_footer} ```

### Raw Disk [100p]

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

``` Flag : 3beef06be834f3151309037dde4714ec ```
