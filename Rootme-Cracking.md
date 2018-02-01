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
