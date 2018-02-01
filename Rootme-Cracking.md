# ELF - 0 protection
run the binary
```
┌─[✗]─[root@parrot]─[~/Downloads]
└──╼ #./ch1.bin 
############################################################
##        Bienvennue dans ce challenge de cracking        ##
############################################################

Veuillez entrer le mot de passe : ^C

```
search for strings that maybe the password
```
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
```
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
```
Bien joue, vous pouvez valider l'epreuve avec le mot de passe : 987654321 !
```
Flag : 987654321 

```asemmbly
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
```

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
