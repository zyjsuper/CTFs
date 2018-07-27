# Some martian message

![screenshot_20180727_152520](https://user-images.githubusercontent.com/22657154/43323369-1edc7914-91ba-11e8-8cc8-d5ae4470c3c9.png)


# File recovery

```
openssl rsautl -decrypt -inkey private.pem -in flag.enc -out plaintext.txt ; cat plaintext.txt
```

# Martian message part 2
decrypte with Vigenere cipher
![screenshot_20180727_151604](https://user-images.githubusercontent.com/22657154/43322849-966308a6-91b8-11e8-8e41-2b2d703389d9.png)

# Martian message part 3
```python
#!/bin/python

s = list("RU9CRC43aWdxNDsxaWtiNTFpYk9PMDs6NDFS".decode("base64"))
p = list("FLAG")

for j in range(0,4):
   for i in range(0,250):
      if chr(ord(s[j]) ^ i) == p[j]:
          print(chr(ord(s[j])) + "\tKEY\t" + str(i))
          key = i
          break

flag = ""
for i in s:
   flag += chr(ord(i) ^ key)

print("")
print(flag)

```

# I Lost my password can you find it?
to find the encrypted password
```
┌─[root@parrot]─[~/Downloads/Policies]
└──╼ #grep -R -i "pass" | tr ' ' '\n' | grep -i pass
cpassword="PCXrmCkYWyRRx3bf+zqEydW9/trbFToMDx6fAvmeCDw"
```
i didn't know what is Cpassword at the first time but after googling ```cpassword decrypt``` i found this article : ```https://tools.kali.org/password-attacks/gpp-decrypt``` on a tool called ```gpp-decrypt```

back to terminal..
```
┌─[root@parrot]─[~/Downloads]
└──╼ #gpp-decrypt PCXrmCkYWyRRx3bf+zqEydW9/trbFToMDx6fAvmeCDw 2> /dev/null
LocalRoot!
```

# Public key recovery

```
openssl rsa -in priv.rsa -pubout 2> /dev/null | grep -v "^-" | tr -d '\n' | md5sum | cut -d "-" -f 1
```
![screenshot_20180727_164800](https://user-images.githubusercontent.com/22657154/43327881-465c9400-91c5-11e8-9ff1-467fec4cd3ed.png)

# Encrypted ZIP
we don't have to use known plain text attack, just use rockyou!

```
┌─[✗]─[root@parrot]─[/tmp]
└──╼ #fcrackzip -v -D -u -p /usr/share/wordlists/rockyou.txt flag.zip 
found file 'flag.txt', (size cp/uc     41/    29, flags 1, chk 5851)


PASSWORD FOUND!!!!: pw == testtest
```

# 
after googling ```secure strings decrypt``` i found these references
```
https://blogs.msdn.microsoft.com/besidethepoint/2010/09/21/decrypt-secure-strings-in-powershell/
https://blogs.msdn.microsoft.com/timid/2009/09/10/powershell-one-liner-decrypt-securestring/
```
and it was a ```powershell``` task.
```powershell
$encrytedFlag = '76492d1116743f0423413b16050a5345MgB8AEEAYQBNAHgAZQAxAFEAVABIAEEAcABtAE4ATgBVAFoAMwBOAFIAagBIAGcAPQA9AHwAZAAyADYAMgA2ADgAMwBlADcANAA3ADIAOQA1ADIAMwA0ADMAMwBlADIAOABmADIAZABlAGMAMQBiAGMANgBjADYANAA4ADQAZgAwADAANwA1AGUAMgBlADYAMwA4AGEAZgA1AGQAYgA5ADIAMgBkAGIAYgA5AGEAMQAyADYAOAA='

$key = (3,4,2,3,56,34,254,222,205,34,2,23,42,64,33,223,1,34,2,7,6,5,35,12)

$SecureFlag = ConvertTo-SecureString -String $encrytedFlag -Key $key

[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureFlag))
```
