## Introduction

In networking and reconnaissance, a ping sweep is a network scanning method that can establish a range of IP addresses that map to live hosts. The most used tool to run a ping sweeps is **fping**, which traditionally was accompanied by **gping** to generate the list of hosts for large subnets, although the more recent version of fping includes that functionality.

Ping Sweep is also known as ICMP sweep. You can use fping command for ping sweep. This command is a ping-like program which uses the Internet Control Message Protocol (ICMP) echo request to determine if a host is up. **fping** is different from ping in that you can specify any number of hosts on the command line, or specify a file containing the lists of hosts to **ping**. If a host does not respond within a certain time limit and/or retry limit, it will be considered unreachable.

* * *

### How To Install Fping?

#### Ubuntu / Debian and other derived distribution

```html
sudo apt install fping
```

#### Redhat / Centos and other derived distribution

In **.rpm** distributions we can install **fping** from the source file using the below commands.

```html
cd /tmp/wget http://fping.org/dist/fping-4.2.tar.gztar -xvzf fping-4.2.tar.gzcd fping-4.2/./configuremake && make install
```

Or if you want **fping** to support IPv6 addresses follow next steps

```html
./configure --prefix=/usr/local --enable-ipv4 --enable-ipv6make && make install
```

* * *

### How To Use Fping?

#### Check the current Fping version

```html
fping -v
```

**Output**

```html
fping: Version 4.0fping: comments to david@schweikert.ch
```

#### Ping Multiple hosts from command line

```html
fping 192.168.1.1 192.168.1.102 localhost 8.8.8.8 8.8.4.4
```

**Output**

```html
192.168.1.1 is alive192.168.1.102 is alivelocalhost is alive8.8.8.8 is alive8.8.4.4 is alive
```

#### Ping Multiple hosts using file

```html
fping < file.txt192.168.1.1 is alive192.168.1.102 is alive192.168.1.150 is unreachablelocalhost is alive192.168.147.2 is alive8.8.8.8 is alive8.8.4.4 is alive
```

#### Ping IPs range from command line

```html
fping -s -g 192.168.1.1 192.168.1.255
```

**Output**

```html
192.168.1.1 is alive192.168.1.102 is aliveICMP Host Unreachable from 192.168.1.102 for ICMP Echo sent to 192.168.1.2ICMP Host Unreachable from 192.168.1.102 for ICMP Echo sent to 192.168.1.3ICMP Host Unreachable from 192.168.1.102 for ICMP Echo sent to 192.168.1.4ICMP Host Unreachable from 192.168.1.102 for ICMP Echo sent to 192.168.1.5[...]192.168.1.1 is unreachable192.168.1.2 is unreachable192.168.1.3 is unreachable192.168.1.4 is unreachable192.168.1.5 is unreachable[...] 255 targets 2 alive 253 unreachable 0 unknown addresses 253 timeouts (waiting for a response) 1014 ICMP Echos sent 2 ICMP Echo Replies received 1008 other ICMP received 0.05 ms (min round trip time) 1.71 ms (avg round trip time) 3.37 ms (max round trip time) 12.003 sec (elapsed real time)
```

#### Ping a complete Network

Using the below command you can ping a complete network once using the option (**\-r 1**) within the parameters. As you can easily understand you can increase this value according to your specific needs.

```html
fping -g -r 1 192.168.0.0/24
```

* * *

### How To Block Ping Sweeps?

Port scans and ping sweeps cannot be blocked without taking the risk to compromise the network capabilities. However, it's possible to block such requests without any difficulties at host levels. Ping sweeps can be stopped if **ICMP echo** and **echo-reply** are turned off.

#### Blocking Ping Sweeps on Linux System

If you are using any **Linux** environment along with **iptables** you can easily block ping sweeps on every machine connected on the network adding into your **iptables** configuration the following rule:

```html
iptables -A OUTPUT -p icmp --icmp-type echo-request -j DROP
```

#### Blocking Ping Sweeps on Windows System

On **Windows** machine it's also very easy to block ping sweeps but it's a little bit longer.

- Log into Windows using an administrator-level account.
- Press and hold the Windows key (located between the Ctrl and Alt keys) and the "R" key.
- Type "wf.msc" in the box (no quotation marks), and press "Enter."
- Right-click the "inbound rules" link in the left pane, and then click "New rule" from the context menu.
- Select the "Custom" radio button, and click "Next."
- Select "All Programs" and click "Next."
- Choose ICMPv4 as your protocol type, and click "Next."
- Click the "Customize" button.
- Choose "echo request" as the "Specific ICMP type."

**Important**: If you have enabled port forwarding, make sure that TCP port 445 is closed. Otherwise, the pings will still get through.

* * *

## Conclusion

??