## Using ls verbose recursively listing we can figure out the directory structure

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

