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


