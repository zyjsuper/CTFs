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
   if ord(i) ^ 0xffffff88 == 4294967261 : # 0xffffffdd -> \xdd\xff\xff\xff
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

# Music Player
The MP3 player, which can only run for one minute, gets a flag if it skips all the routines that exit when it reaches one minute, When you execute one minute, a message box will open and the song will stop .. bypass it.

``` Note, i tried to use dnspy since it is a visual basic program but it didn't work, at least i could know how functions will look like ```

![prefirst](https://user-images.githubusercontent.com/22657154/42221835-bc77d104-7ed3-11e8-949b-a3c0d961b673.png)

![first](https://user-images.githubusercontent.com/22657154/42221836-bd57ad9c-7ed3-11e8-9097-73ad1eb26138.png)

save patches and run, there is a ```run time error``` message box
<br>
back to function calls -> search for check word -> break all commands

![3](https://user-images.githubusercontent.com/22657154/42222006-47afbb1a-7ed4-11e8-9ed8-0c37fa6388e8.png)

now run again, you will clearly see the conditional jump we're looking for, flip it and run 

![4](https://user-images.githubusercontent.com/22657154/42222116-7f5ec718-7ed4-11e8-9d5d-f637703f8043.png)

```Flag : LIstenCare ```

# ImagePRC
When you run the program, you can draw a picture, and if you click the check button, a message box called wrong is displayed.

![1](https://user-images.githubusercontent.com/22657154/42239478-5779b9f8-7f04-11e8-9d70-d06fc46cf16c.png)


![2015-10-07 15_54_23-assembly manifest - chrome](https://user-images.githubusercontent.com/22657154/42239837-72735434-7f05-11e8-9baa-3075ef27dc52.png)

![2-ida](https://user-images.githubusercontent.com/22657154/42239676-ef025fe6-7f04-11e8-99d1-0aed4022175d.png)


The above code is executed when the check button is pressed.
<br>
Looking at the code, I get the images I currently have drawn and the images stored in the resources and compare them on a byte-by-byte.
<br>
In other words, you have to draw the picture equal to the byte unit so that the wrong message will not appear.
<br>
The first thing I thought was to pull out the resource used and make it in a real image.
<br>

![3-ida](https://user-images.githubusercontent.com/22657154/42239906-b18ef56a-7f05-11e8-9e22-72722f8beb3d.png)

so the image scale is 150hx200w, and since the resource file consists only FF and lower number
<br>
we can guess this image extension is BMP, so save the image we created in BMP format
<br>
![4-header_create](https://user-images.githubusercontent.com/22657154/42240123-91b54374-7f06-11e8-91a1-0cfbd4e55907.png)

Extract the resource file.

![5-save_resource](https://user-images.githubusercontent.com/22657154/42240135-9470db14-7f06-11e8-93fa-a55fd795e6c5.png)

then open it inside a hex editor like HXD and copy the header to the very first of the resource file.

![5-copy-header-1](https://user-images.githubusercontent.com/22657154/42240142-9d767caa-7f06-11e8-8085-0c8b00ec9ae9.png)

![5-copy-header-2](https://user-images.githubusercontent.com/22657154/42240159-b0a2e5d4-7f06-11e8-8b96-476f8408b7bd.png)

```FLAG : GOT ```

# Replace
The program crashes upon entering a number and hitting “Check”.

![run_program](https://user-images.githubusercontent.com/22657154/42244379-187ef8ce-7f15-11e8-9fb5-1b9b3fb8f322.png)

if we followed the program flow we will see that the correct message it not callable

![correct_is_not_callable](https://user-images.githubusercontent.com/22657154/42244428-4c38b9ca-7f15-11e8-803a-119798290505.png)

so let's just run the program without any inputs and see why does he crash..

![eip_in_eax](https://user-images.githubusercontent.com/22657154/42244514-9e2cf0fc-7f15-11e8-91de-001cb0f0631b.png)

the EIP has not a valid address and the EIP was taken from EAX with the value ```0x601605CB```

now let's try to use ```1234``` as an input

![eip_eax_plus_input](https://user-images.githubusercontent.com/22657154/42244608-fb40c390-7f15-11e8-9d0a-aee27ca9a57f.png)

the EAX now have the value ```0x60160A9D``` which is ```0x601605CB + HEX(input)```
<br>
and since the correct message is located in the address ```0x401072``` we can calculate the flag.
<br>

The simple math behind the solution..

![untitled](https://user-images.githubusercontent.com/22657154/42244961-520ffa5a-7f17-11e8-9671-6f73e554bf8f.png)


```FLAG : 2687109798 ```
# Direct3D FPS

When you start the game, you can kill a strange doll while walking around in a gun.
<br>
when I kill everything, there is no window.
<br>
instead, HP collapses with the doll and dies when it reaches zero.
<br>
first, when you look at the reference string, there is a string 'game clear'
<br>
after tracing it change the EIP to its location

![1_mod_the_eip](https://user-images.githubusercontent.com/22657154/42283615-47081640-7faa-11e8-99b8-5ede40158e2d.png)

step until the message box call and follow fps.1f7028 in DWORD in dump

![2_follow_encrypted_flag_in_dump](https://user-images.githubusercontent.com/22657154/42283783-cc017d50-7faa-11e8-859f-d00e234189cd.png)

you will see an obfuscated value of 50 chars that will apper in the MessageBox when you resum the execution
<br>
save it for later and run.

![run_with_encrypted_flag](https://user-images.githubusercontent.com/22657154/42284040-96434972-7fab-11e8-8b62-23607c536b0b.png)

now let's open ida and follow the X-references for fps.1f7028

![xrefs_to_game_over](https://user-images.githubusercontent.com/22657154/42284131-da5f6d5c-7fab-11e8-9940-d7c28d752b60.png)

![goto_flag_array](https://user-images.githubusercontent.com/22657154/42284133-dbbd8b5c-7fab-11e8-9aed-c874eab0fc93.png)

![xrefs_to_flag](https://user-images.githubusercontent.com/22657154/42284170-f958def0-7fab-11e8-95a0-316418e70ea1.png)

now lets decompile this function.

![understand_the_code](https://user-images.githubusercontent.com/22657154/42284212-18f8287e-7fac-11e8-8f18-c192e68950aa.png)

i spent sometime debugging and redirecting the execution flow
<br>
before i could get that the CL value will be incremented by 4 to decode the flag successfully with each character
<br>
after this step i could easily write a C++ program to solve the problem and reveal the flag.

```cpp
#include <iostream>
using namespace std;

int main(){

   int i,j=0;
   int flagarray[50] = {0x43 ,0x6B ,0x66 ,0x6B ,0x62 ,0x75,
            0x6C ,0x69 ,0x4C ,0x45 ,0x5C ,0x45 ,0x5F ,0x5A,
            0x46 ,0x1C ,0x07 ,0x25 ,0x25 ,0x29 ,0x70 ,0x17,
            0x34 ,0x39 ,0x01 ,0x16 ,0x49 ,0x4C ,0x20 ,0x15,
            0x0B ,0x0F ,0xF7 ,0xEB ,0xFA ,0xE8 ,0xB0 ,0xFD,
            0xEB ,0xBC ,0xF4 ,0xCC ,0xDA ,0x9F ,0xF5 ,0xF0,
            0xE8 ,0xCE ,0xF0 ,0xA9}; // 50 entries

   for(i=0; i<50; i++){
      printf("%c",flagarray[i]^j);
      j += 4;
   }
   cout << endl;
   return 0;
}
```

![write_the_script](https://user-images.githubusercontent.com/22657154/42284485-edba4ff6-7fac-11e8-915e-c901d11c9bea.png)

```Flag : Thr3EDPr0m ```

# Position 

they gave us the challenge title as a hint to bruteforce username field
<br>
go to the debugger the set a break point before the return located after 'correct' string
<br>
so when we hit the right username the program will frezz

![pb](https://user-images.githubusercontent.com/22657154/42297005-e7735c2e-7ffb-11e8-994f-91c31d5ec8c5.png)

i used pyautogui and itertools to create a bruteforce script.

```python 
import pyautogui
import itertools
import string

# pyautogui.position() -> get mouse position

pyautogui.click(1034, 335)

chrs = string.ascii_lowercase

for xs in itertools.product(chrs, repeat=3):
    pyautogui.typewrite(''.join(xs)+"p") # bruteforce the username
    pyautogui.hotkey("ctrl","a")         # select the entire line
    pyautogui.typewrite(["backspace"])   # delete it
```

after about two minutes i got the flag.

![flag](https://user-images.githubusercontent.com/22657154/42297135-5fa066dc-7ffd-11e8-9b5c-6a5946174d08.png)

```FLAG : bump```


