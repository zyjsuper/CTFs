# ELF - 0 protection
run the binary
```assembly
┌─[✗]─[root@parrot]─[~/Downloads]
└──╼ #./ch1.bin 
############################################################
##        Bienvennue dans ce challenge de cracking        ##
############################################################

Veuillez entrer le mot de passe : ^C

```
search for strings that maybe the password
```assembly
└──╼ #strings ch1.bin | grep passe -B 4
123456789
############################################################
##        Bienvennue dans ce challenge de cracking        ##
############################################################
Veuillez entrer le mot de passe : 
```
Flag is : 123456789

# ELF - x86 Basic
use the same technique
```assembly
└──╼ #strings ch2.bin  | grep ^username -B 5 -A 2
john
the ripper
############################################################
##        Bienvennue dans ce challenge de cracking        ##
############################################################
username: 
password: 
987654321
```
username : John
password : the ripper
```assembly
Bien joue, vous pouvez valider l'epreuve avec le mot de passe : 987654321 !
```
Flag : 987654321 

# PE - 0 protection
run it using wine
```assembly
┌─[root@parrot]─[~/Downloads]
└──╼ #wine ch15.exe
Usage: Z:\root\Downloads\ch15.exe pass
```
open it up with radare2 
```assembly
└──╼ #radare2 ch15.exe 
[0x004014e0]> aaaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Emulate code to find computed references (aae)
[x] Analyze consecutive function (aat)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (afta)
[0x004014e0]> s main
[0x004017b8]> pds
0x004017c1 call fcn.00402540
0x004017d4 const char * s
0x004017d7 call sub.msvcrt.dll_strlen_870
0x004017ed call sub.Wrong_password_726
0x004017fc call sub.Usage:__s_pass_700
0x00401853 call sub.KERNEL32.dll_InitializeCriticalSection_5e0
```
seek to sub.Wrong_password_726 function and disassemble it

```assembly
[0x004017b8]> s sub.Wrong_password_726
[0x00401726]> pdf
.......
 0x00401729      83ec28         sub esp, 0x28                         ; '('
 0x0040172c      c745f4000000.  mov dword [local_ch], 0
 0x00401733      837d0c07       cmp dword [ebp + 0xc], 7              ; [0x7:4]=-1 ; 7
 0x00401737      7571           jne 0x4017aa
 ----------- true: 0x004017aa  false: 0x00401739
 0x00401739      8b4508         mov eax, dword [arg_8h]               ; [0x8:4]=-1 ; 8
 0x0040173c      0fb600         movzx eax, byte [eax]
 0x0040173f      3c53           cmp al, 0x53                          ; 'S' ; 83
 0x00401741      7567           jne 0x4017aa
 ----------- true: 0x004017aa  false: 0x00401743
 0x00401743      8b4508         mov eax, dword [arg_8h]               ; [0x8:4]=-1 ; 8
 0x00401746      83c001         add eax, 1
 0x00401749      0fb600         movzx eax, byte [eax]
 0x0040174c      3c50           cmp al, 0x50                          ; 'P' ; 80
 0x0040174e      755a           jne 0x4017aa
 ----------- true: 0x004017aa  false: 0x00401750
 0x00401750      8b4508         mov eax, dword [arg_8h]               ; [0x8:4]=-1 ; 8
 0x00401753      83c002         add eax, 2
 0x00401756      0fb600         movzx eax, byte [eax]
 0x00401759      3c61           cmp al, 0x61                          ; 'a' ; 97
 0x0040175b      754d           jne 0x4017aa
 ----------- true: 0x004017aa  false: 0x0040175d
 0x0040175d      8b4508         mov eax, dword [arg_8h]               ; [0x8:4]=-1 ; 8
 0x00401760      83c003         add eax, 3
 0x00401763      0fb600         movzx eax, byte [eax]
 0x00401766      3c43           cmp al, 0x43                          ; 'C' ; 67
 0x00401768      7540           jne 0x4017aa
 ----------- true: 0x004017aa  false: 0x0040176a
 0x0040176a      8b4508         mov eax, dword [arg_8h]               ; [0x8:4]=-1 ; 8
 0x0040176d      83c004         add eax, 4
 0x00401770      0fb600         movzx eax, byte [eax]
 0x00401773      3c49           cmp al, 0x49                          ; 'I' ; 73
 0x00401775      7533           jne 0x4017aa
 ----------- true: 0x004017aa  false: 0x00401777
 0x00401777      8b4508         mov eax, dword [arg_8h]               ; [0x8:4]=-1 ; 8
 0x0040177a      83c005         add eax, 5
 0x0040177d      0fb600         movzx eax, byte [eax]
 0x00401780      3c6f           cmp al, 0x6f                          ; 'o' ; 111
 0x00401782      7526           jne 0x4017aa
 ----------- true: 0x004017aa  false: 0x00401784
 0x00401784      8b4508         mov eax, dword [arg_8h]               ; [0x8:4]=-1 ; 8
 0x00401787      83c006         add eax, 6
 0x0040178a      0fb600         movzx eax, byte [eax]
 0x0040178d      3c53           cmp al, 0x53                          ; 'S' ; 83
 0x0040178f      7519           jne 0x4017aa
 ----------- true: 0x004017aa  false: 0x00401791
 0x00401791      b853404000     mov eax, str.Gratz_man_:_             ; 0x404053 ; "Gratz man :)"
 0x00401796      890424         mov dword [esp], eax                  ; const char * format
 0x00401799      e812110000     call sub.msvcrt.dll_printf_8b0        ; int printf(const char *format)
.....
```
as you can see we have some random characters, bind them together: 'SPaCIoS'
let's try it as a password
```assembly
└──╼ #wine ch15.exe SPaCIoS
Gratz man :)
```  
Flag : SPaCIoS

# ELF C++ - 0 protection
seek to the main function and set a break point at the bottom 
```assembly
[0xf7ed8b20]> aaaa
[0xf7ed8b20]> s main
[0xf7ed8b20]> s main
[0x08048a86]> db 0x08048c92
.....
        |   0x08048c88      89d8           mov eax, ebx
        |   0x08048c8a      890424         mov dword [esp], eax
        |   0x08048c8d      e8eefbffff     call sym.imp._Unwind_Resume
|       `-> ;-- eip:
|       |      ; JMP XREF from 0x08048c1b (main)
|       `-> 0x08048c92      8d65f8         lea esp, dword [local_8h_2]
|           0x08048c95      59             pop ecx
|           0x08048c96      5b             pop ebx
|           0x08048c97      5d             pop ebp

```
```assembly
[0x08048a86]> pdf
|       `-> 0x08048c92 b    8d65f8         lea esp, dword [local_8h_2]

```
take a look at the stack:
```assembly
[0x08048c92]> pxr @ esp
0xff7fa2e0  0xff7fa2f4  .... @esp stack R W 0xa04fc8c -->  (Here_you_have_to_understand_a_little_C++_stuffs)
.......
```
try ```Here_you_have_to_understand_a_little_C++_stuffs``` as a password:
```assembly
└──╼ #./ch25.bin Here_you_have_to_understand_a_little_C++_stuffs
Bravo, tu peux valider en utilisant ce mot de passe...
Congratz. You can validate with this password...
```
Flag : Here_you_have_to_understand_a_little_C++_stuffs

# ELF - Fake Instructions
```assembly
└──╼ #radare2 -d crackme 123456
[0xf7ed8b20]> aaaa
[0xf7ed8b20]> afl 
......
0x08048554    7 368          sym.main
0x080486c4    3 104          sym.WPA
0x0804872c    5 215          sym.blowfish
0x08048803    1 30           sym.RS4
0x08048821    1 5            sym.AES
......
```
now let's disassemble the main function, we will see that there is no function calls for any of these functions ubove, but there is a call to the edx register value.
```assembly
|           0x0804869a      89442404       mov dword [local_4h], eax
|           0x0804869e      8d45d6         lea eax, dword [local_2ah]
|           0x080486a1      890424         mov dword [esp], eax
|           0x080486a4      ffd2           call edx
|           0x080486a6      8b55f4         mov edx, dword [local_ch]
|           0x080486a9      653315140000.  xor edx, dword gs:[0x14]
```
let's set a break point on it and show what inside.
```assembly
[0x08048554]> db 0x080486a4
[0xf7ed8b20]> dc
hit breakpoint at: 80486a4
[0x080486a4]> dr edx
0x080486c4
```
seek to the ```0x080486c4``` address
```assembly
[0x080486a4]> s 0x080486c4
[0x080486c4]> pdf
            ;-- edx:
/ (fcn) sym.WPA 104
|   sym.WPA (int arg_8h, int arg_ch);
|           ; arg int arg_8h @ ebp+0x8
|           ; arg int arg_ch @ ebp+0xc
|           ; var int local_4h @ esp+0x4
|           0x080486c4      55             push ebp
|           0x080486c5      89e5           mov ebp, esp
|           0x080486c7      83ec08         sub esp, 8
|           0x080486ca      8b450c         mov eax, dword [arg_ch]     ; [0xc:4]=-1 ; 12
|           0x080486cd      83c00b         add eax, 0xb
|           0x080486d0      c6000d         mov byte [eax], 0xd         ; [0xd:1]=255 ; 13
|           0x080486d3      8b450c         mov eax, dword [arg_ch]     ; [0xc:4]=-1 ; 12
|           0x080486d6      83c00c         add eax, 0xc
|           0x080486d9      c6000a         mov byte [eax], 0xa
|           0x080486dc      c704243c8904.  mov dword [esp], str.V__rification_de_votre_mot_de_passe.. ; [0x804893c:4]=0x72a9c356 ; "V\u00e9rification de votre mot de passe.." ; const char * s
|           0x080486e3      e884fdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x080486e8      8b450c         mov eax, dword [arg_ch]     ; [0xc:4]=-1 ; 12
|           0x080486eb      89442404       mov dword [local_4h], eax
|           0x080486ef      8b4508         mov eax, dword [arg_8h]     ; [0x8:4]=-1 ; 8
|           0x080486f2      890424         mov dword [esp], eax        ; const char * s2
|           0x080486f5      e882fdffff     call sym.imp.strcmp         ; int strcmp(const char *s1, const char *s2)
|           0x080486fa      85c0           test eax, eax
|       ,=< 0x080486fc      7511           jne 0x804870f
|       |   0x080486fe      e829000000     call sym.blowfish
|       |   0x08048703      c70424000000.  mov dword [esp], 0          ; int status
|       |   0x0804870a      e87dfdffff     call sym.imp.exit           ; void exit(int status)
|       `-> 0x0804870f      e8ef000000     call sym.RS4
|           0x08048714      c70424648904.  mov dword [esp], str.____L_authentification_a___chou__._n_Try_again____r ; [0x8048964:4]=0x20292128 ; "(!) L'authentification a \u00e9chou\u00e9.\n Try again ! \r" ; const char * s
|           0x0804871b      e84cfdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x08048720      c70424010000.  mov dword [esp], 1          ; int status
\           0x08048727      e860fdffff     call sym.imp.exit           ; void exit(int status)
```
here we can see that we are inside WPA function, and there is a conditional jump located at ```0x080486fc``` address
```assembly
|       ,=< 0x080486fc      7511           jne 0x804870f
|       |   0x080486fe      e829000000     call sym.blowfish
|       |   0x08048703      c70424000000.  mov dword [esp], 0          ; int status
|       |   0x0804870a      e87dfdffff     call sym.imp.exit           ; void exit(int status)
|       `-> 0x0804870f      e8ef000000     call sym.RS4
```
let's show if this jump is taken...
```assembly
[0x080486c4]> db 0x080486fa
[0x080486c4]> dc
Vérification de votre mot de passe..
hit breakpoint at: 80486fa
[0x080486c4]> dr eax
0xffffffff
[0x080486c4]> 
```
conditional jump is jump-if-not-eqaul one, eax value is ```0xffffffff``` so if we want to imagine how will code looks like in language like bash, it will be like the following:
```bash
eax="0xffffffff"
if [[ eax != 0 ]] ; then
   RS4
else
   blowfish
fi
```
now all we have to do is redirecting this jump to execute  blowfish instead of RS4 like the following:
```assembly
[0x080486c4]> s 0x080486fc
[0x080486fc]> wa jmp 0x080486fe
Written 2 bytes (jmp 0x080486fe) = wx eb00
[0x080486fc]> pdf 
.....
|           ;-- eip:
|           0x080486fa b    85c0           test eax, eax
|       ,=< 0x080486fc      eb00           jmp 0x80486fe
|       `-> 0x080486fe      e829000000     call sym.blowfish
|           0x08048703      c70424000000.  mov dword [esp], 0          ; int status
.....
```
now resume the execution...
```assembly
[0x080486fc]> dc
'+) Authentification réussie...
 U'r root! 

 sh 3.0 # password: liberté!
```
Flag: liberté!

# ELF - Ptrace
First of all you have to know that we can't debug this binary directly.
```assembly
└──╼ #gdb ch3.bin 
gdb-peda$ break main
Breakpoint 1 at 0x80483fe
gdb-peda$ run
gdb-peda$ c
Continuing.
Debugger detecté ... Exit
[Inferior 1 (process 4841) exited with code 01]
```
But we are hackers and we love breaking rules, so let's figure out what is going on.. from ``` man ptrace ``` comamand:
```C
NAME
       ptrace - process trace

SYNOPSIS
       #include <sys/ptrace.h>

       long ptrace(enum __ptrace_request request, pid_t pid,
                   void *addr, void *data);

```
so, we can tell using patrice any attempts to debug or crack the program
will be detected and then we can execute a certain number of actions like exit from the entire program, here is a simple example on how can code look like.
```C
#include <stdio.h>
#include <sys/ptrace.h>

int main(){

    if (ptrace(PTRACE_TRACEME, 0, 1, 0)) {
        puts("Debugger Detected");
        return 1;
    }

    puts("Exited Normally");
    return 0;
}
```
But, radare2 is a hexadecimal editor and disassembler, we still can use it to remove detection !.
open it up in writing mode ..
```assembly
└──╼ #radare2 -w ch3.bin 
[0x080482f0]> aaaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
....
````
seek to the main function, here we can see a conditional jump at ```0x0804841a```.
replace it with ```jmp 0x8048436```.
```assembly
[0x080483f0]> s 0x0804841a
[0x0804841a]> wa jmp 0x8048436
Written 2 bytes (jmp 0x8048436) = wx eb1a
```
and now we can debug the binary using gdb..
fire up gdb, break main and disassemble it
```assembly
gdb-peda$ set disassembly-flavor intel
gdb-peda$ break main
Breakpoint 1 at 0x80483fe
gdb-peda$ run
gdb-peda$ disassemble main
Dump of assembler code for function main:
.....
   0x0804849d <+173>:	hlt    
   0x0804849e <+174>:	add    eax,0x4
   0x080484a1 <+177>:	mov    al,BYTE PTR [eax]
   0x080484a3 <+179>:	cmp    dl,al
   0x080484a5 <+181>:	jne    0x80484e4 <main+244>
   0x080484a7 <+183>:	mov    dl,BYTE PTR [ebp-0x15]
   0x080484aa <+186>:	mov    eax,DWORD PTR [ebp-0xc]
   0x080484ad <+189>:	add    eax,0x5
   0x080484b0 <+192>:	mov    al,BYTE PTR [eax]
   0x080484b2 <+194>:	cmp    dl,al
   0x080484b4 <+196>:	jne    0x80484e4 <main+244>
   0x080484b6 <+198>:	mov    dl,BYTE PTR [ebp-0x14]
   0x080484b9 <+201>:	mov    eax,DWORD PTR [ebp-0xc]
   0x080484bc <+204>:	inc    eax
   0x080484bd <+205>:	mov    al,BYTE PTR [eax]
   0x080484bf <+207>:	cmp    dl,al
   0x080484c1 <+209>:	jne    0x80484e4 <main+244>
   0x080484c3 <+211>:	mov    dl,BYTE PTR [ebp-0x13]
   0x080484c6 <+214>:	mov    eax,DWORD PTR [ebp-0xc]
   0x080484c9 <+217>:	add    eax,0xa
   0x080484cc <+220>:	mov    al,BYTE PTR [eax]
   0x080484ce <+222>:	cmp    dl,al
   0x080484d0 <+224>:	jne    0x80484e4 <main+244>
   0x080484d2 <+226>:	sub    esp,0xc
   0x080484d5 <+229>:	push   0x80c297a
   0x080484da <+234>:	call   0x80492d0 <puts>
   0x080484df <+239>:	add    esp,0x10
   0x080484e2 <+242>:	jmp    0x80484f4 <main+260>
   0x080484e4 <+244>:	sub    esp,0xc
   0x080484e7 <+247>:	push   0x80c298e
   0x080484ec <+252>:	call   0x80492d0 <puts>
   0x080484f1 <+257>:	add    esp,0x10
   0x080484f4 <+260>:	mov    eax,0x0
   0x080484f9 <+265>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x080484fc <+268>:	leave  
   0x080484fd <+269>:	lea    esp,[ecx-0x4]
   0x08048500 <+272>:	ret    
End of assembler dump.
gdb-peda$ 

```
If we keep stepping over you will notice that the dl register will contain the characters from the string we entered and the al register will contain the characters of the real password. Each time the cmp is comparing the 2 characters and if the comparison is true it will return which will set the zero flag. In case cmp fails the JNE instruction will jump to 0x80484e4 which means wrong password.
There are 4 comparisons going on which means the password is of length 4 so first, let's set a break point on
```assembly
0x080484a3 <+179>:   cmp    dl,al
```
then  define a hook to print the 8-bit al register value and set dl value to al.
```assembly
gdb-peda$ break *0x080484a3
gdb-peda$ define hook-stop
>print/x $al
>set $dl = $al 
>end
gdb-peda$ 
```
now step over using ```n``` then keep press enter unless you get good password meesage
```assembly
gdb-peda$ n
$45 = 0x65
0x080484aa in main ()
gdb-peda$ 
$51 = 0x61
0x080484b9 in main ()
gdb-peda$ 
$57 = 0x73
0x080484c6 in main ()
gdb-peda$ 
$64 = 0x79
0x080484da in main ()
gdb-peda$ 

Good password !!!

```
convert hex to ascii and you will get 'easy'.
```assembly
└──╼ #./ch3.bin 
############################################################
##        Bienvennue dans ce challenge de cracking        ##
############################################################

Password : easy

Good password !!!
```
Flag : easy


# PYC - ByteCode
Here we have a .pyc file, decompile it to python source code
using Easy python decompiler ``` works with wine on linux ```
you will have a python file looks like this after replacing the fisrt line
with ``` !/bin/python ```
```python
!/bin/python
if __name__ == '__main__':
    print('Welcome to the RootMe python crackme')
    PASS = input('Enter the Flag: ')
    KEY = 'I know, you love decrypting Byte Code !'
    I = 5
    SOLUCE = [
        57,
        73,
        79,
        16,
        18,
        26,
        74,
        50,
        13,
        38,
        13,
        79,
        86,
        86,
        87]
    KEYOUT = []
    for X in PASS:
        KEYOUT.append((ord(X) + I ^ ord(KEY[I])) % 255)
        I = (I + 1) % len(KEY)

    if SOLUCE == KEYOUT:
        print('You Win')
    else:
        print('Try Again !')

``` 
here we have a some sort of ugly algorithms with 16 characters inside
all we need to do to get the flag is reversing this algorithm.
so, i deleted some parts of the previous script then rename it to c.py to look like this:

```python
PASS = input('Enter the Flag: ')
KEY = 'I know, you love decrypting Byte Code !'
I = 5
SOLUCE = [57,73,79,16,18,26,74,50,13,38,13,79,86,86,87]
KEYOUT = []
for X in PASS:
   KEYOUT.append((ord(X) + I ^ ord(KEY[I])) % 255)
   I = (I + 1) % len(KEY)

print(KEYOUT)
print(SOLUCE)

``` 
then i made this script to solve and print out the flag:
```bash
#!/bin/bash
var=""
x=1
dm=""
l=0
arr=("57" "73" "79" "16" "18" "26" "74" "50" "13" "38" "13" "79" "86" "86" "87")
while true; do
   for i in $( echo {A..z} {0..9} "!" ) ; do
      char=$(
              echo $dm | python3 c.py       |
              grep flag -i | tr '[' ' '     |
              tr ']' ' ' | tr ',' ' '       |
              cut -d ":" -f 2 | tr ' ' '\n' |
              awk NF | awk NR==$x
            )

     case $char in
          ${arr[$l]})
              var="$dm"
              let x++
              echo -en "$var\r"
              let l++
              if [[ $l == 15 ]] ; then
                   echo
                   exit
              fi
              ;;
          *)
              dm="${var}$i"
      esac
   done
done

```
Flag is : I_hate_RUBY_!!!

#ELF - CrackPass
first open it up with radare2

```assembly
┌─[root@parrot]─[~/Downloads]
└──╼ #radare2 -d Crack 5555
Process with PID 3224 started...
= attach 3224 3224
bin.baddr 0x08048000
Using 0x8048000
asm.bits 32
[0xf7fb1b20]> aaaa
[x] Analyze all flags starting with sym. and entry0 (aa)
TODO: esil-vm not initialized
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Emulate code to find computed references (aae)
[Cannot find section boundaries in here
[x] Analyze consecutive function (aat)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (afta)
```
bypass the antidebugger

```assembly
[0xf7fb1b20]>  s 0x0804868c
[0x0804868c]>  wa jmp 0x804869f
Written 2 bytes (jmp 0x804869f) = wx eb11
```
change the execution flow to print the password.

```assembly
[0x0804868c]> s 0x0804861e
[0x0804861e]> wa je 0x8048632
Written 2 bytes (je 0x8048632) = wx 7412
```
run.

```assembly
[0x0804861e]> dc
Good work, the password is : 

ff07031d6fb052490149f44b1d5e94f1592b6bac93c06ca9
 
```
Flag is : ff07031d6fb052490149f44b1d5e94f1592b6bac93c06ca9

### ELF - ExploitMe

first open it up with radare2

```assembly
┌─[root@parrot]─[~/Downloads]
└──╼ #radare2 -d Exploit_Me 123456

Process with PID 2958 started...
= attach 2958 2958
bin.baddr 0x08048000
Using 0x8048000
Unknown DW_FORM 0x06
asm.bits 32
[0xf7f9fb20]> aaaa
[x] Analyze all flags starting with sym. and entry0 (aa)
TODO: esil-vm not initialized
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Emulate code to find computed references (aae)
[Cannot find section boundaries in here
[x] Analyze consecutive function (aat)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (afta)
```
change the program flow
```assembly
[0xf7f9fb20]> s 0x0804871a
[0x0804871a]> wa jmp 0x0804871c
Written 2 bytes (jmp 0x0804871c) = wx eb00
[0x0804871a]> s 0x08048831
[0x08048831]> wa jmp 0x804887b
Written 2 bytes (jmp 0x804887b) = wx eb48
[0x08048831]> dc
VÃ©rification de votre mot de passe..
[+] Felicitation password de validation de l'épreuve:: 25260060504_VE_T25_*t*_
```
But, they want us to do it using an exploit so here is our payload.

```assembly
┌─[✗]─[root@parrot]─[~/Downloads]
└──╼ #./Exploit_Me\(if_you_can\) $(python -c 'print("A"*148+"\x31\x87\x04\x08")')
[+] Felicitation password de validation de l'épreuve:: 25260060504_VE_T25_*t*_

``` 
```\x31\x87\x04\x08``` is the _asm_ function address ```0x08048731```

Flag is : 25260060504_VE_T25_*t*_


### APK - Anti-debug

first of all we have to convert the apk file into a jar file which will make the code more readable.
```assembly
┌─[root@parrot]─[~/Downloads]
└──╼ #dex2jar ch16.apk 
this cmd is deprecated, use the d2j-dex2jar if possible
dex2jar version: translator-0.0.9.15
dex2jar ch16.apk -> ch16_dex2jar.jar
Done.
```
```ch16_dex2jar.jar``` in ```JD-GUI``` then select ```Validate.class``` and here is our code.
```java
package com.fortiguard.challenge.hashdays2012.challengeapp;

import android.content.Context;
import android.util.Log;
import java.lang.reflect.Array;
import java.security.MessageDigest;
import java.util.Arrays;

public class Validate
{
  private static final String[] answers;
  private static byte[][] bh;
  private static boolean computed = false;
  private static final String[] hashes = { "622a751d6d12b46ad74049cf50f2578b871ca9e9447a98b06c21a44604cab0b4", "301c4cd0097640bdbfe766b55924c0d5c5cc28b9f2bdab510e4eb7c442ca0c66", "d09e1fe7c97238c68e4be7b3cd64230c638dde1d08c656a1c9eaae30e49c4caf", "4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2" };
  public static String[] hexArray;
  private Context context;
  
  static
  {
    answers = new String[] { "Congrats from the FortiGuard team :)", "Nice try, but that would be too easy", "Ha! Ha! FortiGuard grin ;)", "Are you implying we are n00bs?", "Come on, this is a DEFCON conference!" };
    hexArray = new String[] { "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B", "0C", "0D", "0E", "0F", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1A", "1B", "1C", "1D", "1E", "1F", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2A", "2B", "2C", "2D", "2E", "2F", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3A", "3B", "3C", "3D", "3E", "3F", "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4A", "4B", "4C", "4D", "4E", "4F", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5A", "5B", "5C", "5D", "5E", "5F", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6A", "6B", "6C", "6D", "6E", "6F", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7A", "7B", "7C", "7D", "7E", "7F", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8A", "8B", "8C", "8D", "8E", "8F", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9A", "9B", "9C", "9D", "9E", "9F", "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF", "B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF", "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "CA", "CB", "CC", "CD", "CE", "CF", "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF", "E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF", "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "FA", "FB", "FC", "FD", "FE", "FF" };
    int[] arrayOfInt = { 4, 32 };
    bh = (byte[][])Array.newInstance(Byte.TYPE, arrayOfInt);
  }
  
  public Validate(Context paramContext)
  {
    this.context = paramContext;
  }
  
  public static String checkSecret(String paramString)
  {
    for (;;)
    {
      int i;
      try
      {
        MessageDigest localMessageDigest = MessageDigest.getInstance("SHA-256");
        localMessageDigest.reset();
        arrayOfByte = localMessageDigest.digest(paramString.getBytes());
        if (computed) {
          break label110;
        }
        convert2bytes();
      }
      catch (Exception localException)
      {
        byte[] arrayOfByte;
        String str;
        Log.w("Hashdays", "checkSecret: " + localException.toString());
      }
      if (i < hashes.length)
      {
        if (Arrays.equals(arrayOfByte, bh[i]))
        {
          str = answers[i];
          return str;
        }
        i++;
      }
      else
      {
        return answers[4];
        label110:
        i = 0;
      }
    }
  }
  
  public static void convert2bytes()
  {
    for (int i = 0; i < hashes.length; i++) {
      bh[i] = hexStringToByteArray(hashes[i]);
    }
    computed = true;
  }
  
  public static byte[] hexStringToByteArray(String paramString)
  {
    int i = -1 + paramString.length();
    byte[] arrayOfByte = new byte[1 + i / 2];
    for (int j = 0; j < i; j += 2) {
      arrayOfByte[(j / 2)] = ((byte)((Character.digit(paramString.charAt(j), 16) << 4) + Character.digit(paramString.charAt(j + 1), 16)));
    }
    return arrayOfByte;
  }
  
  public static boolean isEmulator()
  {
    return true;
  }
}
```
we can clearly see four SHA-256 hashes and asnwer array which contains five strings, so logically after seeing this.. 
```java
else
{
   return answers[4];
   label110:
   i = 0;
}
````
we can tell that the algorithm will take our input, hashing it, then compare it to our four hashes, then it will choose the answer depend on the hash number inside it's array so it some how looks like this
```bash
input=$(python -c "import hashlib ; print(hashlib.sha256(\"$1\").hexdigest())")
arr=("622a751d6d12b46ad74049cf50f2578b871ca9e9447a98b06c21a44604cab0b4" "301c4cd0097640bdbfe766b55924c0d5c5cc28b9f2bdab510e4eb7c442ca0c66" "d09e1fe7c97238c68e4be7b3cd64230c638dde1d08c656a1c9eaae30e49c4caf" "4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2")
ans=("Congrats from the FortiGuard team :)" "Nice try, but that would be too easy" "Ha! Ha! FortiGuard grin ;)" "Are you implying we are n00bs?" "Come on, this is a DEFCON conference!")
for i in {0..3};do
  if [[ $input == ${arr[$i]} ]] ; then
      echo "${ans[$i]}"
      exit 0;
  fi
done
echo ${ans[4]}
```
to print ```"Congrats from the FortiGuard team :)"``` all we have to do is decode the first hash ```"622a751d6d12b46ad74049cf50f2578b871ca9e9447a98b06c21a44604cab0b4"``` which will be the flag !

Flag : MayTheF0rceB3W1thU

### ELF - Random Crackme
our binary is broken for some reason, extract the binary itself using ```binwalk``` will solve this issue.
```assembly
┌─[root@parrot]─[~/Downloads]
└──╼ #./crackme_wtf 
./crackme_wtf: line 1: syntax error near unexpected token `newline'
./crackme_wtf: line 1: `!<arch>'
┌─[✗]─[root@parrot]─[~/Downloads]
└──╼ #binwalk -e crackme_wtf  ; cd _crackme_wtf.extracted/

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
424           0x1A8           ELF, 32-bit LSB executable, Intel 80386, version 1 (SYSV)
9286          0x2446          Unix path: /build-tree/i386-libc/csu/crti.S

┌─[root@parrot]─[~/Downloads/_crackme_wtf.extracted]
└──╼ #chmod +x 1A8.elf 
┌─[root@parrot]─[~/Downloads/_crackme_wtf.extracted]
└──╼ #./1A8.elf 

    ** Bienvenue dans ce challenge de cracking **    

[+] Password :12345

[!]Access Denied !  
[-] Try again 
```
Now we are ready!
I treid to keep everything simple so i just played with conditional jumps.

```assembly
┌─[root@parrot]─[~/Downloads/_crackme_wtf.extracted]
└──╼ #radare2 -d 1A8.elf 
Process with PID 3683 started...
= attach 3683 3683
bin.baddr 0x08048000
Using 0x8048000
Unknown DW_FORM 0x06
asm.bits 32
[0xf7f4bb20]> aaaa
[x] Analyze all flags starting with sym. and entry0 (aa)
TODO: esil-vm not initialized
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Emulate code to find computed references (aae)
[Cannot find section boundaries in here
[x] Analyze consecutive function (aat)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (afta)

[0x080488d5]> s 0x08048a89
[0x08048a89]> wa jmp 0x08048ad3
Written 2 bytes (jmp 0x08048ad3) = wx eb48
[0x08048a89]> 
[0x08048a89]> s 0x08048af9
[0x08048af9]> wa jmp 0x8048b2c
Written 2 bytes (jmp 0x8048b2c) = wx eb31
[0x08048af9]> 
[0x08048af9]> s 0x08048b84
[0x08048b84]> wa jmp 0x8048bce
Written 2 bytes (jmp 0x8048bce) = wx eb48
[0x08048b84]> 
[0x08048b84]> s 0x08048c1a
[0x08048c1a]> wa jmp 0x8048c50
Written 2 bytes (jmp 0x8048c50) = wx eb34
[0x08048c1a]> 
[0x08048c1a]> s 0x08048c57
[0x08048c57]> wa jmp 0x8048c8d
Written 2 bytes (jmp 0x8048c8d) = wx eb34
[0x08048c57]> 
[0x08048c57]> s 0x08048c94
[0x08048c94]> wa jmp 0x8048c9a
Written 2 bytes (jmp 0x8048c9a) = wx eb04
[0x08048c94]> 
[0x08048c94]> s 0x08048ca6
[0x08048ca6]> wa jmp 0x8048cac
Written 2 bytes (jmp 0x8048cac) = wx eb04
[0x08048ca6]> dc

    ** Bienvenue dans ce challenge de cracking **    

[+] Password :dasdasd

[+]Good password  
[+] Clee de validation du crack-me : _VQLG1160_VTEPI_AVTG_3093_

[0xf7fb8dc9]> 
```
Flag : _VQLG1160_VTEPI_AVTG_3093_


### PE DotNet - 0 protection
![pe 0 protection](https://user-images.githubusercontent.com/22657154/37649751-7852c0be-2c3b-11e8-8dba-2fddf03409c8.png)
