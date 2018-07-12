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
so to get the random generated value just set a break point on the instruction after it and see the ```EAX``` value.

![randm](https://user-images.githubusercontent.com/22657154/42652718-ecced984-861b-11e8-879c-80c54a0c8d60.png)

```Flag : Mommy, I thought libc random is unpredictable...```


