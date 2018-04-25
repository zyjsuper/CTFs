# Easy Crack [100p]
![untitled](https://user-images.githubusercontent.com/22657154/37673636-6499f57c-2c79-11e8-889e-79660c64b470.png)
as they said it was easy to crack [ immunity debugger is your friend ].
```
flag : Ea5yR3versing
```
# Easy ELF [100p]
using ```plasama``` and ```radare2``` we can see that the program is taking a 5 characters as an input, xoring them then compares them to a new values, if any character is wrong it will print "wrong" and exit, if all the compared values are correct it will contiune until it prints "correct" then exits normally.
```assembly 

    frame_size = 4
    0x8048451: push ebp
    0x8048452: ebp = esp
    0x8048454: !eax = byte_804a021
    # 0x804845b: cmp al, 0x31
    # 0x804845d: je 0x8048469
    if (al != '1') {
        0x804845f: eax = 0
        0x8048464: jmp ret_0x80484f5
    } else {
        0x8048469: !eax = unk_804a020
        0x8048470: eax ^= 52
        0x8048473: *(unk_804a020) = al
        0x8048478: !eax = byte_804a022
        0x804847f: eax ^= 50
        0x8048482: *(byte_804a022) = al
        0x8048487: !eax = byte_804a023
        0x804848e: eax ^= -120
        0x8048491: *(byte_804a023) = al
        0x8048496: !eax = byte_804a024
        # 0x804849d: cmp al, 0x58
        # 0x804849f: je 0x80484a8
        if (al != 'X') {
            0x80484a1: eax = 0
            0x80484a6: jmp ret_0x80484f5
        } else {
            0x80484a8: !eax = byte_804a025
            # 0x80484af: test al, al
            # 0x80484b1: je 0x80484ba
            if (al != 0) {
                0x80484b3: eax = 0
                0x80484b8: jmp ret_0x80484f5
            } else {
                0x80484ba: !eax = byte_804a022
                # 0x80484c1: cmp al, 0x7c
                # 0x80484c3: je 0x80484cc
                if (al != '|') {
                    0x80484c5: eax = 0
                    0x80484ca: jmp ret_0x80484f5
                } else {
                    0x80484cc: !eax = unk_804a020
                    # 0x80484d3: cmp al, 0x78
                    # 0x80484d5: je 0x80484de
                    if (al != 'x') {
                        0x80484d7: eax = 0
                        0x80484dc: jmp ret_0x80484f5
                    } else {
                        0x80484de: !eax = byte_804a023
                        # 0x80484e5: cmp al, 0xdd
                        # 0x80484e7: je 0x80484f0
                        if (al != '\xdd') {
                            0x80484e9: eax = 0
                            0x80484ee: jmp ret_0x80484f5
                        } else {
                            0x80484f0: eax = 1
                        }
                    }
                }
            }
        }
    }
    ret_0x80484f5:
    0x80484f5: pop ebp
    0x80484f6: ret
}
```
![screenshot at 2018-03-22 20-04-04](https://user-images.githubusercontent.com/22657154/37817468-485b30d0-2e4d-11e8-8ea3-80cdd19b0573.png)
![screenshot at 2018-03-22 20-04-15](https://user-images.githubusercontent.com/22657154/37817481-4d43c8dc-2e4d-11e8-8e46-9c6d65c104a4.png)

i took what i need from the ELF file to reverse the algorithm 
```assembly 
byte [0x804a021] : [key[0] ^ 0x31       ] -> 1        [1] -> not modified
byte [0x804a020] : [key[1] ^ 0x34       ] -> x
byte [0x804a022] : [key[2] ^ 0x32       ] -> |
byte [0x804a023] : [key[3] ^ 0xffffff88 ] -> \xdd
byte [0x804a024] : [key[4] ^ 0x58       ] -> X        [X] -> not modified
byte [0x804a025] : [key[5]              ] -> 0

```
and built this simple script that will bruteforce our frive characters 
```python
#!/bin/python

string="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+-*/|()*&^^%$#@!~`"
char= list(string)
key = []
for i in char:
   if ord(i) ^ 0x34 == 120:
      print("[+] 0x804a020 " + i)
      key.append(i)
   if ord(i) ^ 0x31 == 0:
      print("[+] 0x804a021 " + i)
      key.append(i)
   if ord(i) ^ 0x32 == 124:
      print("[+] 0x804a022 " + i)
      key.append(i)
   if ord(i) ^ 0xffffff88 == 4294967261 : # \xdd\xff\xff\xff
      print("[+] 0x804a023 " + i)
      key.append(i)
   if ord(i) ^ 0x58 == 0:
      print("[+] 0x804a024 " + i)
      key.append(i)

print("Flag : " + key[1] + key[0] + key[2] + key[3] + key[4])

```
```assembly 
┌─[root@parrot]─[~]
└──╼ #python flag.py 
[+] 0x804a021 1
[+] 0x804a020 L
[+] 0x804a022 N
[+] 0x804a023 U
[+] 0x804a024 X
Flag : L1NUX
┌─[root@parrot]─[~/Downloads]
└──╼ #./Easy_ELF 
Reversing.Kr Easy ELF

L1NUX
Correct!
```
Flag : L1NUX

# Easy Keygen [100p]
The problem is to find the Name value whose serial value is ```5B134977135E7D13```.
there is a routine that accepts a string and then generates a specific value. This routine produces the serial value.

![25 35png](https://user-images.githubusercontent.com/22657154/39253485-42b26fe8-48a8-11e8-95ff-ce9f8a661c40.png)

As you can see in the analysis, we take the input string one by one and do xor operation with 16 32 48 and compare the hex value to the string as it is.
![how_does_it_work_1](https://user-images.githubusercontent.com/22657154/39252905-efe4154c-48a6-11e8-887e-8207bfb105cf.png)

![how_does_it_work_counter_ecx_ebp](https://user-images.githubusercontent.com/22657154/39252960-1502394e-48a7-11e8-8f9e-eb10088add7b.png)

![how_does_it_work_counter_ecx_ebp2](https://user-images.githubusercontent.com/22657154/39252963-17051162-48a7-11e8-8dd0-1aaec6ba8233.png)
And after the serial value is stored in the ESI part, it is compared with the inputted serial value, and it is outputted as correct or wrong.

I have implemented a routine in Python to generate serial values.
```python
#!/bin/python

input  = "K3yg3nm3"
input  = list(input)
xor    = [16,32,48]
x      = 0
for i in range(len(input)):
   print input[i] + " => " + hex(ord(input[i]) ^ xor[x])
   x+=1
   if x == 2:
       x=0

```
Based on this, i implemented an inverse operation algorithm to obtain the input value.
```python
#!/bin/python

encode = [16,32,48]
I =0
dic = "ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`!abcdefghijklmnopqrstuvwxyz0123456789"
Ser =  ''
Sercmp ='5B,13,49,77,13,5E,7D,13'
Sercmp = Sercmp.split(',')

for S in Sercmp:      # loop 8 times
    for d in dic:     # loop 68 times
        if encode[I]^ord(d) == int(S,16): # if 1..3^ord(d) == S.HexTOInt
            print S + " => " + d
            Ser+=d
            I+=1
            if I >= 3:
               I=0
            break
print "Flag : " + Ser
```
![encdec](https://user-images.githubusercontent.com/22657154/39253192-907f2e1a-48a7-11e8-9c75-62435c5bb0c5.png)

``` Flag : K3yg3nm3 ```

# Easy Unpack
we have to find the OEP (original entry point), using IDA pro PE universal unpacker ..

![unpack](https://user-images.githubusercontent.com/22657154/39267247-989a1b6c-48cc-11e8-9074-3178a1f9c430.png)

``` Flag : 00401150```
