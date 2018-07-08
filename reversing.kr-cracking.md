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

i used pyautogui and itertools to create a bruteforce script [ youtu.be/1RE5tSPO2RI ]

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

# Ransomware
First of all, the program adds an upx shell, which is easy to take off and does not explain
<br>
i want to load ida, but I found the analysis to be very slow
<br>
using x64dbg i found that there is a function called ```401000``` full of garbage code with the same pattern
<br>
so i created a simple python script to read and replace the pattern with NOPs
<br>
first copy the offsets and use 'search -> goto' in HXD to see the bytes or just copy them from the debugger

![copy_offset](https://user-images.githubusercontent.com/22657154/42307501-eeed4262-8032-11e8-8449-4929ba57bb61.png)

the write the script..

```python
#!/bin/python
data = open('run.exe','rb').read()
data = data.replace('\x50\x58\x53\x5B\x60\x61','\x90\x90\x90\x90\x90\x90')
open('run_clean.exe','wb').write(data)
print("[+] FILE CLEANED")
```

![goto_offset_and_clean_the_file](https://user-images.githubusercontent.com/22657154/42307592-38be332e-8033-11e8-9fa9-848140f27e8d.png)

load it into ida, we're not ready yet.
<br>
you have to change the start and the end of the main function to be able to decompile [ fix the SP positive value ERR ] and to use the graph without the annoying sorry error.

```
start  :   .text:0044A775
end    :   .text:0044A983
```

![function_start_end_mod](https://user-images.githubusercontent.com/22657154/42308023-a147fbe0-8034-11e8-9c80-32f3fb522934.png)

now we're ready...

![ida_is_beuty_2](https://user-images.githubusercontent.com/22657154/42308078-d4846be2-8034-11e8-9432-69dc6a838d07.png)

open any PE file and the file we have to decrypt, copy the common offsets of ```this program can not be run in dos mode``` sentence
<br>
and recover the key..

```python
#!/bi/python

dec = "CD 21 54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20 6D 6F 64 65".replace(" ", "").decode("hex")
enc = "41 AD C7 F2 E2 FF AF E3 EC E9 FB E5 FB E1 AC F0 FB E5 E2 E0 E7 BE E4 F9 B7 E8 F9 E2 B3 F3 E5 AC CB DC CD A6 F1 F8 FE E9".replace(" ", "").decode("hex")

dec = list(dec)
enc = list(enc)

key=""

for i in range(len(enc)): # or len(dec) it doesn't matter
   enc [i] = (~ ord(enc[i])) & 255
   key += chr(ord(dec[i])^enc[i])
print key
```

![unpack_it](https://user-images.githubusercontent.com/22657154/42308324-7f246228-8035-11e8-9491-6be9c2bbcfc6.png)

after enter the key you'll successfully decrypt the PE file which will reval the flag.

```FLAG : Colle System```

# CSHOP
i'm not kidding if i said you can get the flag by open the file and hit enter XD
<br>
there is a hidden button that will show up the flag and we have to show it up in the first place
<br>
so let's assume that we can't press enter and start reversing.. 
<br>
first we have to deobfsucate the program using ```de4dot``` after this step open it up with ```dnspy```
<br>
go to ```InitializeComponent``` and change the button size from 0,0 to 50,50
<br>
then ```file -> save all``` 

![mod](https://user-images.githubusercontent.com/22657154/42322423-c2e70cfa-805c-11e8-839f-95bdf84c1fa3.png)

now just run..


![get_flag](https://user-images.githubusercontent.com/22657154/42322430-cb624c6e-805c-11e8-8b6d-3f32ba947d6a.png)

```FLAG : P4W6RP6SES```

# Flash Encrypt

This problem can be done as long as the tool is good.

Download ```ffdec``` and ```flash player debug```

open the file in ```ffdec```, look at the action scripts source
<br>
the passowrds pattern is ```1456 -> 25 -> 44 -> 8 -> 88 -> 20546```

![mod](https://user-images.githubusercontent.com/22657154/42325362-55f518e4-8066-11e8-8aa9-f32747dd775b.png)

```FLAG : 16876```

# CSharp

our algorithm  is located inside the obfuscated method ```MetMett```
<br>
the ```btnCheck_Click``` pass input string to ```sss``` variable of ```MetMetMet```
<br>
```sss``` string is converted to ```Base64``` String and saved into bytes
<br>
Then i see the comparison to show ```Wrong``` or ```Correct!!``` Nag

![couldnt_be_decompiled](https://user-images.githubusercontent.com/22657154/42353493-033fb482-80c1-11e8-93e1-d2d9f38c1e38.png)

i can confirm that the original bytes of MetMett method will be replaced at runtime to decode the method body
<br>
so we need to use dnSpy to debug this challenge to find the bb values at original and after calculate
<br>
Open dnSpy, load challenge, set breakpoints same as the picture bellow..

![go_to_ ctor_dec_metmett](https://user-images.githubusercontent.com/22657154/42353504-1c15085e-80c1-11e8-89fe-238e7aac7d99.png)

Press F5 to start, stop at the 1st bp, press F10 to step over. Go to locals window and find the value of bb (these values is the original bytes of MetMett method), and show bb array in the ```Memory Window```:

![follow_in_mem1](https://user-images.githubusercontent.com/22657154/42353514-2db21246-80c1-11e8-8e88-503294b9d55b.png)


Copy and Save all these bytes

![follow_in_mem2](https://user-images.githubusercontent.com/22657154/42353564-8caf53a8-80c1-11e8-8b65-771df07f1465.png)

Then, press F5 to continue and stop at the 2nd bp then refresh and save..

![follow_in_mem3_right_click_refresh_save](https://user-images.githubusercontent.com/22657154/42353588-bdd82e6e-80c1-11e8-8708-cec9e778df88.png)

now go to ```HxD```, find the original bytes offsets and replace them with the bytes from the second dump.


![hex1](https://user-images.githubusercontent.com/22657154/42353623-fe60173a-80c1-11e8-905a-c7781c4e1e59.png)

![hex2](https://user-images.githubusercontent.com/22657154/42353625-ff2f69f4-80c1-11e8-8d72-9b5a85f8a06b.png)

![hex3](https://user-images.githubusercontent.com/22657154/42353631-04752750-80c2-11e8-9b68-43048b5b6dd0.png)

![hex4](https://user-images.githubusercontent.com/22657154/42353632-04b621a6-80c2-11e8-8807-bcae2c199d09.png)

open the new file with ```dnspy``` and the function should me decompiled normaly..
<br>
you know what to do from this point.

```python
#!/bin/python

byte1 = [16, 17, 33, 51, 68, 102, 51, 160, 144, 181, 238, 17];
byte2 = [74, 87, 77, 70, 29, 49, 117, 238, 241, 226, 163, 44];
flag  = ""

for i in range(len(byte1)):
	print str(byte1[i]) + "^" + str(byte2[i]) + "\t = " + chr(byte1[i] ^ byte2[i])
	flag += chr(byte1[i] ^ byte2[i])

print("\n[+] ENCODED FLAG : " + flag)
print("[+] FLAG : " + flag.decode("base64"))
```

![get_the_flag](https://user-images.githubusercontent.com/22657154/42353679-632559c8-80c2-11e8-87dc-0a9ae615afe2.png)

``` FLAG : dYnaaMic ```

# HateIntel

It's like an executable running on mac, and there's no mac, so there's only static analysis.
<br>
fortunately, there is no packing, and the routines are made public in IDA.
<br>
these are functions with important routines.

![ida_code](https://user-images.githubusercontent.com/22657154/42413152-944b1728-821a-11e8-92e1-0d071fb9a2c7.png)

To summarize, we give the input and the program runs the sub_232C function, where we executes the sub_2494 function
<br>
and if the result is the same as byte_3004 then the key is correct.
<br>
here are some references for better understanding the code

![bitwise](https://user-images.githubusercontent.com/22657154/42413219-1e3f6e2e-821c-11e8-8f6e-a3e69660ea3e.png)

![ascii_char_set](https://user-images.githubusercontent.com/22657154/42413222-1f73940a-821c-11e8-80fa-4b1574875bf0.gif)

```python
import string

byte_3004 = "\x44\xF6\xF5\x57\xF5\xC6\x96\xB6\x56\xF5\x14\x25\xD4\xF5\x96\xE6\x37\x47\x27\x57\x36\x47\x96\x03\xE6\xF3\xA3\x92" 
flag = '' 
for i in range(0, len(byte_3004)):
  for j in range(0, 127): # All the ASCII characters 
    x = j 
    for z in range(0, 4):
       x *= 2
       if x & 256:
       	  v = x
          x |= 1
       x = x & 0xff       # Correction of values
    if x == ord(byte_3004[i]):
       print "[+] " + str(v) + " " + bin(v) + "  & 0xff 0b11111111\t->\t" + str(x) + "\t" + bin(x)
       flag += chr(j)

print ""
print "- " + flag
print "- NO"
```

![get_flag](https://user-images.githubusercontent.com/22657154/42413236-7ce808c8-821c-11e8-9faa-636614f22db8.png)

```FLAG : Do_u_like_ARM_instructi0n?:)```

# x64 Lotto
This question requires inputting 6 numbers. When it is equal to the randomly generated 6 numbers, it will output the flag
<br>
since it has no relationship with the input we can change ```JNE``` to ```JE``` or ```NOP``` and the flag will be outputed.

![nop](https://user-images.githubusercontent.com/22657154/42422705-8ac04ada-82eb-11e8-8d2e-ac9dd98883b1.png)

![get_flag](https://user-images.githubusercontent.com/22657154/42422704-899bf9d8-82eb-11e8-9b13-fcacb2ead30c.png)

```FLAG : from_GHL2_-_!```


# WindowsKernel
# AutoHotkey1
# PEPassword
# AutoHotkey2
# CRC1
