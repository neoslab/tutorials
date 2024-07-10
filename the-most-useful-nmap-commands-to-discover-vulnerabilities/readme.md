## Introduction

Nmap ("Network Mapper") is an open-source tool for network exploration and security auditing. It was designed to rapidly scan large networks, although it works fine against single hosts. Nmap uses raw IP packets in novel ways to determine what hosts are available on the network, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics.

* * *

### The Nmap Keys Features

- **Flexible**: Supports dozens of advanced techniques for mapping out networks filled with IP filters, firewalls, routers, and other obstacles. This includes many port scanning mechanisms (both TCP & UDP), OS detection, version detection, ping sweeps, and more. See the documentation page.
- **Powerful**: Nmap has been used to scan huge networks of literally hundreds of thousands of machines.
- **Portable**: Most operating systems are supported, including Linux, Microsoft Windows, FreeBSD, OpenBSD, Solaris, IRIX, Mac OS X, HP-UX, NetBSD, Sun OS, Amiga, and more.
- **Easy**: While Nmap offers a rich set of advanced features for power users, you can start as simply as "nmap -v -A targethost". Both traditional command line and graphical (GUI) versions are available to suit your preference. Binaries are available for those who do not wish to compile Nmap from the source.
- **Free**: The primary goals of the Nmap Project is to help make the Internet a little more secure and to provide administrators/auditors/hackers with an advanced tool for exploring their networks. Nmap is available for free download, and also comes with full source code that you may modify and redistribute under the terms of the license.
- **Well Documented**: Significant effort has been put into comprehensive and up-to-date man pages, whitepapers, tutorials, and even a whole book!
- **Supported**: While Nmap comes with no warranty, it is well supported by a vibrant community of developers and users. Most of this interaction occurs on the Nmap mailing lists. Most bug reports and questions should be sent to the nmap-dev list, but only after you read the guidelines. We recommend that all users subscribe to the low-traffic nmap-hackers announcement list. You can also find Nmap on Facebook and Twitter. For real-time chat, join the #nmap channel on Freenode or EFNet.
- **Acclaimed**: Nmap has won numerous awards, including "Information Security Product of the Year" by Linux Journal, Info World and Codetalker Digest. It has been featured in hundreds of magazine articles, several movies, dozens of books, and one comic book series.
- **Popular**: Thousands of people download Nmap every day, and it is included with many operating systems (Redhat Linux, Debian Linux, Gentoo, FreeBSD, OpenBSD, etc). It is among the top ten (out of 30,000) programs at the Freshmeat.

**Nmap features include**

- **Host discovery**: Identifying hosts on a network.
- **Port scanning**: Enumerating the open ports on target hosts.
- **Version detection**: Interrogating network services on remote devices to determine the application name and version number.
- **OS detection**: Determining the operating system and hardware characteristics of network devices.
- **Scriptable interaction with the target**: Using Nmap Scripting Engine (NSE) and Lua programming language.

**Typical uses of Nmap**

- Auditing the security of a device or firewall by identifying the network connections which can be made to, or through it.
- Identifying open ports on a target host in preparation for auditing
- Network inventory, network mapping, maintenance, and asset management.
- Auditing the security of a network by identifying new servers.
- Generating traffic to hosts on a network, response analysis and response time measurement.
- Finding and exploiting vulnerabilities in a network.

* * *

## How to Install Nmap

**Update Package List**

Open a terminal and run the following command to ensure your package lists are up-to-date:

```html
sudo apt-get update
```

**Install Nmap**

Next, install Nmap using this command:

```html
sudo apt-get install nmap
```

**Verify Installation**

To verify that Nmap is installed, check its version:

```html
nmap --version
```

You’ll see detailed information about the installed Nmap version

* * *

## Common Network Scanning Techniques

Below, you’ll find common network scanning techniques using Nmap, for identifying devices, services, and operating systems active on a network. These techniques help you perform comprehensive penetration tests to uncover vulnerabilities. Before scanning, ensure you have permission and the correct IP addresses.

#### Scan A Single Host Or An IP Address

```html
sudo nmap 192.168.1.1
sudo nmap server1.neoslab.com
sudo nmap -v server1.neoslab.com
```

#### Scan Multiple IP Address Or Subnet

```html
sudo nmap 192.168.1.1 192.168.1.2 192.168.1.3
sudo nmap 192.168.1.1,2,3
```

You can scan a range of IP address too:

```html
sudo nmap 192.168.1.1-20
```

You can scan a range of IP address using a wildcard:

```html
sudo nmap 192.168.1.*
```

Finally, you scan an entire subnet:

```html
sudo nmap 192.168.1.0/24
```

#### Read List Of Hosts/Networks From File

The "`-iL`" option allows you to read the list of target systems using a text file.

```html
sudo nmap -iL /tmp/test.txt
```

#### Excluding Hosts/Networks

When scanning a large number of hosts/networks you can exclude hosts from a scan:

```html
sudo nmap 192.168.1.0/24 --exclude 192.168.1.5
sudo nmap 192.168.1.0/24 --exclude 192.168.1.5,192.168.1.254
```

OR exclude list from a file called /tmp/exclude.txt

```html
sudo nmap -iL /tmp/scanlist.txt --excludefile /tmp/exclude.txt
```

#### Turn On Os And Version Detection Scanning Script

```html
sudo nmap -A 192.168.1.254
sudo nmap -v -A 192.168.1.1
sudo nmap -A -iL /tmp/scanlist.txt
```

#### Find Out If A Host/Network Is Protected By A Firewall

```html
sudo nmap -sA 192.168.1.254
sudo nmap -sA server1.neoslab.com
```

#### Scan A Host When Protected By The Firewall

```html
sudo nmap -PN 192.168.1.1
sudo nmap -PN server1.neoslab.com
```

#### Scan An IPv6 Host/Address

The "`-6`" option enable IPv6 scanning. The syntax is:

```html
sudo nmap -6 server1.neoslab.com
sudo nmap -6 2607:f0d0:1002:51::4
sudo nmap -v A -6 2607:f0d0:1002:51::4
```

#### Scan A Network And Find Out Which Servers And Devices Are Up And Running

This is known as host discovery or ping scan:

```html
sudo nmap -sP 192.168.1.0/24
```

**Output**

```html
Host 192.168.1.1 is up (0.00035s latency).
MAC Address: BC:AE:C5:C3:16:93 (Unknown)
Host 192.168.1.2 is up (0.0038s latency).
MAC Address: 74:44:01:40:57:FB (Unknown)
Host 192.168.1.5 is up.
Host nas03 (192.168.1.12) is up (0.0091s latency).
MAC Address: 00:11:32:11:15:FC (Synology Incorporated)
Nmap done: 256 IP addresses (4 hosts up) scanned in 2.80 second
```

#### How Do I Perform A Fast Scan?

```html
sudo nmap -F 192.168.1.1
```

#### Display The Reason A Port Is In A Particular State

```html
sudo nmap --reason 192.168.1.1
sudo nmap --reason server1.neoslab.com
```

#### Only Show Open (Or Possibly Open) Ports

```html
sudo nmap --open 192.168.1.1
sudo nmap --open server1.neoslab.com
```

#### Show All Packets Sent And Received

```html
sudo nmap --packet-trace 192.168.1.1
sudo nmap --packet-trace server1.neoslab.com
```

#### Show Host Interfaces And Routes

This is useful for debugging (IP command or route command or "`netstat`" command like output using nmap)

```html
sudo nmap -F 192.168.1.1
```

**Output**

```html
Starting Nmap 5.00 ( http://nmap.org ) at 2012-11-27 02:01 IST
************************INTERFACES************************
DEV    (SHORT)  IP/MASK          TYPE        UP MAC
lo     (lo)     127.0.0.1/8      loopback    up
eth0   (eth0)   192.168.1.5/24   ethernet    up B8:AC:6F:65:31:E5
vmnet1 (vmnet1) 192.168.121.1/24 ethernet    up 00:50:56:C0:00:01
vmnet8 (vmnet8) 192.168.179.1/24 ethernet    up 00:50:56:C0:00:08
ppp0   (ppp0)   10.1.19.69/32    point2point up
**************************ROUTES**************************
DST/MASK         DEV    GATEWAY
10.0.31.178/32   ppp0
209.133.67.35/32 eth0   192.168.1.2
192.168.1.0/0    eth0
192.168.121.0/0  vmnet1
192.168.179.0/0  vmnet8
169.254.0.0/0    eth0
10.0.0.0/0       ppp0
0.0.0.0/0        eth0   192.168.1.2
```

#### How Do I Scan Specific Ports?

```html
sudo nmap -p 80 192.168.1.1
sudo nmap -p T:80 192.168.1.1
sudo nmap -p U:53 192.168.1.1
sudo nmap -p 80,443 192.168.1.1
sudo nmap -p 80-200 192.168.1.1
sudo nmap -p U:53,111,137,T:21-25,80,139,8080 192.168.1.1
sudo nmap -p U:53,111,137,T:21-25,80,139,8080 server1.neoslab.com
sudo nmap -v -sU -sT -p U:53,111,137,T:21-25,80,139,8080 192.168.1.254
sudo nmap -p "*" 192.168.1.1
sudo nmap --top-ports 5 192.168.1.1
sudo nmap --top-ports 10 192.168.1.1
```

**Output**

```html
Starting Nmap 5.00 ( http://nmap.org ) at 2012-11-27 01:23 IST
Interesting ports on 192.168.1.1:
PORT     STATE  SERVICE
21/tcp   closed ftp
22/tcp   open   ssh
23/tcp   closed telnet
25/tcp   closed smtp
80/tcp   open   http
110/tcp  closed pop3
139/tcp  closed netbios-ssn
443/tcp  closed https
445/tcp  closed microsoft-ds
3389/tcp closed ms-term-serv
MAC Address: BC:AE:C5:C3:16:93 (Unknown)
Nmap done: 1 IP address (1 host up) scanned in 0.51 seconds
```

#### The Fastest Way To Scan All Your Devices/Computers For Open Ports Ever

```html
sudo nmap -T5 192.168.1.0/24
```

#### How Do I Detect Remote Operating System?

You can **identify** remote host apps and OS using the "`-O`" option:

```html
sudo nmap -O 192.168.1.1
sudo nmap -O --osscan-guess 192.168.1.1
sudo nmap -v -O --osscan-guess 192.168.1.1
```

**Output**

```html
Starting Nmap 5.00 ( http://nmap.org ) at 2012-11-27 01:29 IST
NSE: Loaded 0 scripts for scanning.
Initiating ARP Ping Scan at 01:29
Scanning 192.168.1.1 [1 port]
Completed ARP Ping Scan at 01:29, 0.01s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 01:29
Completed Parallel DNS resolution of 1 host. at 01:29, 0.22s elapsed
Initiating SYN Stealth Scan at 01:29
Scanning 192.168.1.1 [1000 ports]
Discovered open port 80/tcp on 192.168.1.1
Discovered open port 22/tcp on 192.168.1.1
Completed SYN Stealth Scan at 01:29, 0.16s elapsed (1000 total ports)
Initiating OS detection (try #1) against 192.168.1.1
Retrying OS detection (try #2) against 192.168.1.1
Retrying OS detection (try #3) against 192.168.1.1
Retrying OS detection (try #4) against 192.168.1.1
Retrying OS detection (try #5) against 192.168.1.1
Host 192.168.1.1 is up (0.00049s latency).
Interesting ports on 192.168.1.1:
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: BC:AE:C5:C3:16:93 (Unknown)
Device type: WAP|general purpose|router|printer|broadband router
Running (JUST GUESSING) : Linksys Linux 2.4.X (95%), Linux 2.4.X|2.6.X (94%), MikroTik RouterOS 3.X (92%), Lexmark embedded (90%), Enterasys embedded (89%), D-Link Linux 2.4.X (89%), Netgear Linux 2.4.X (89%)
Aggressive OS guesses: OpenWrt White Russian 0.9 (Linux 2.4.30) (95%), OpenWrt 0.9 - 7.09 (Linux 2.4.30 - 2.4.34) (94%), OpenWrt Kamikaze 7.09 (Linux 2.6.22) (94%), Linux 2.4.21 - 2.4.31 (likely embedded) (92%), Linux 2.6.15 - 2.6.23 (embedded) (92%), Linux 2.6.15 - 2.6.24 (92%), MikroTik RouterOS 3.0beta5 (92%), MikroTik RouterOS 3.17 (92%), Linux 2.6.24 (91%), Linux 2.6.22 (90%)
No exact OS matches for host (If you know what OS is running on it, see http://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=5.00%D=11/27%OT=22%CT=1%CU=30609%PV=Y%DS=1%G=Y%M=BCAEC5%TM=50B3CA
OS:4B%P=x86_64-unknown-linux-gnu)SEQ(SP=C8%GCD=1%ISR=CB%TI=Z%CI=Z%II=I%TS=7
OS:)OPS(O1=M2300ST11NW2%O2=M2300ST11NW2%O3=M2300NNT11NW2%O4=M2300ST11NW2%O5
OS:=M2300ST11NW2%O6=M2300ST11)WIN(W1=45E8%W2=45E8%W3=45E8%W4=45E8%W5=45E8%W
OS:6=45E8)ECN(R=Y%DF=Y%T=40%W=4600%O=M2300NNSNW2%CC=N%Q=)T1(R=Y%DF=Y%T=40%S
OS:=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%R
OS:D=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=
OS:0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID
OS:=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)
Uptime guess: 12.990 days (since Wed Nov 14 01:44:40 2012)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=200 (Good luck!)
IP ID Sequence Generation: All zeros
Read data files from: /usr/share/nmap
OS detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.38 seconds
Raw packets sent: 1126 (53.832KB) | Rcvd: 1066 (46.100KB)
```

#### How Do I Detect Remote Services (Server/Daemon) Version Numbers?

```html
sudo nmap -sV 192.168.1.1
```

**Output**

```html
Starting Nmap 5.00 ( http://nmap.org ) at 2012-11-27 01:34 IST
Interesting ports on 192.168.1.1:
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open ssh Dropbear sshd 0.52 (protocol 2.0)
80/tcp open http?
1 service unrecognized despite returning data.
```

#### Scan A Host Using TCP Ack (PA) And TCP Syn (PS) Ping

If a firewall is blocking standard ICMP pings, try the following host discovery methods:

```html
sudo nmap -PS 192.168.1.1
sudo nmap -PS 80,21,443 192.168.1.1
sudo nmap -PA 192.168.1.1
sudo nmap -PA 80,21,200-512 192.168.1.1
```

#### Scan A Host Using IP Protocol Ping

```html
sudo nmap -PO 192.168.1.1
```

#### Scan A Host Using UDP Ping

This scan bypasses firewalls and filters that only screen TCP:

```html
sudo nmap -PU 192.168.1.1
sudo nmap -PU 2000.2001 192.168.1.1
```

#### Find Out The Most Commonly Used TCP Ports Using TCP Syn Scan

```html
sudo nmap -sS 192.168.1.1
sudo nmap -sT 192.168.1.1
sudo nmap -sA 192.168.1.1
sudo nmap -sW 192.168.1.1
sudo nmap -sM 192.168.1.1
```

#### Scan A Host For UDP Services (UDP Scan)

Most popular services on the Internet run over the TCP protocol. DNS, SNMP, and DHCP are three of the most common UDP services. Use the following syntax to find out UDP services:

```html
sudo nmap -sU nas03
sudo nmap -sU 192.168.1.1
```

**Output**

```html
Starting Nmap 5.00 ( http://nmap.org ) at 2012-11-27 00:52 IST
Stats: 0:05:29 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 32.49% done; ETC: 01:09 (0:11:26 remaining)
Interesting ports on nas03 (192.168.1.12):
Not shown: 995 closed ports
PORT     STATE         SERVICE
111/udp  open|filtered rpcbind
123/udp  open|filtered ntp
161/udp  open|filtered snmp
2049/udp open|filtered nfs
5353/udp open|filtered zeroconf
MAC Address: 00:11:32:11:15:FC (Synology Incorporated)
Nmap done: 1 IP address (1 host up) scanned in 1099.55 seconds
```

#### Scan For IP Protocol

This type of scan allows you to determine which IP protocols (TCP, ICMP, IGMP, etc.) are supported by target machines:

```html
sudo nmap -sO 192.168.1.1
```

#### Scan A Firewall For Security Weakness

The following scan types exploit a subtle loophole in the TCP and good for testing security of common attacks:

```html
sudo nmap -sN 192.168.1.254
sudo nmap -sF 192.168.1.254
sudo nmap -sX 192.168.1.254
```

#### Scan A Firewall For Packets Fragments

The "`-f`" option causes the requested scan (including ping scans) to use tiny fragmented IP packets. The idea is to split up the TCP header over several packets to make it harder for packet filters, intrusion detection systems, and other annoyances to detect what you are doing.

```html
sudo nmap -f 192.168.1.1
sudo nmap -f server1.neoslab.com
sudo nmap -f 15 server1.neoslab.com
sudo nmap --mtu 32 192.168.1.1
```

#### Cloak A Scan With Decoys

The "`-D`" option it appears to the remote host that the host(s) you specify as **decoys are scanning the target network too.** Thus their IDS might report 5-10 port scans from unique IP addresses, but they won’t know which IP was scanning them and which were innocent decoys:

```html
sudo nmap -n -Ddecoy-ip1,decoy-ip2,your-own-ip,decoy-ip3,decoy-ip4 <target domain or IP Address>
sudo nmap -n -D192.168.1.5,10.5.1.2,172.1.2.4,3.4.2.1 192.168.1.5
```

#### Scan A Firewall For Mac Address Spoofing

```html
sudo nmap --spoof-mac MAC-ADDRESS-HERE 192.168.1.1
sudo nmap -v -sT -PN --spoof-mac MAC-ADDRESS-HERE 192.168.1.1
sudo nmap -v -sT -PN --spoof-mac 0 192.168.1.1
```

#### How Do I Save Output To A Text File?

```html
sudo nmap 192.168.1.1 > output.txt
sudo nmap -oN /path/to/filename 192.168.1.1
sudo nmap -oN output.txt 192.168.1.1
```

#### Scans For Web Servers And Pipes Into Nikto For Scanning

```html
sudo nmap -p80 192.168.1.2/24 -oG - | /path/to/nikto.pl -h -
sudo nmap -p80,443 192.168.1.2/24 -oG - | /path/to/nikto.pl -h -
```

#### Speed Up Nmap

Pass the "`-T`" option:

```html
sudo nmap -v -sS -A -T4 192.168.2.5
```

**Output**

```html
Starting Nmap 7.40 ( https://nmap.org ) at 2017-05-15 01:52 IST
NSE: Loaded 143 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 01:52
Completed NSE at 01:52, 0.00s elapsed
Initiating NSE at 01:52
Completed NSE at 01:52, 0.00s elapsed
Initiating ARP Ping Scan at 01:52
Scanning 192.168.2.15 [1 port]
Completed ARP Ping Scan at 01:52, 0.01s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 01:52
Scanning dellm6700 (192.168.2.15) [1000 ports]
Discovered open port 5900/tcp on 192.168.2.15
Discovered open port 80/tcp on 192.168.2.15
Discovered open port 22/tcp on 192.168.2.15
Completed SYN Stealth Scan at 01:53, 4.62s elapsed (1000 total ports)
Initiating Service scan at 01:53
Scanning 3 services on dellm6700 (192.168.2.15)
Completed Service scan at 01:53, 6.01s elapsed (3 services on 1 host)
Initiating OS detection (try #1) against dellm6700 (192.168.2.15)
Retrying OS detection (try #2) against dellm6700 (192.168.2.15)
NSE: Script scanning 192.168.2.15.
Initiating NSE at 01:53
Completed NSE at 01:53, 30.02s elapsed
Initiating NSE at 01:53
Completed NSE at 01:53, 0.00s elapsed
Nmap scan report for dellm6700 (192.168.2.15)
Host is up (0.00044s latency).
Not shown: 996 filtered ports
PORT     STATE  SERVICE VERSION
22/tcp   open   ssh     (protocol 2.0)
| fingerprint-strings:
|   NULL:
|_    SSH-2.0-OpenSSH_7.4p1 Ubuntu-10
| ssh-hostkey:
|   2048 1d:14:84:f0:c7:21:10:0e:30:d9:f9:59:6b:c3:95:97 (RSA)
|_  256 dc:59:c6:6e:33:33:f2:d2:5d:9b:fd:b4:9c:52:c1:0a (ECDSA)
80/tcp   open   http    nginx 1.10.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
443/tcp  closed https
5900/tcp open   vnc     VNC (protocol 3.7)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port22-TCP:V=7.40%I=7%D=5/15%Time=5918BCAA%P=x86_64-apple-darwin16.3.0%
SF:r(NULL,20,"SSH-2\.0-OpenSSH_7\.4p1\x20Ubuntu-10\n");
MAC Address: F0:1F:AF:1F:2C:60 (Dell)
Device type: general purpose
Running (JUST GUESSING): Linux 3.X|4.X|2.6.X (95%), OpenBSD 4.X (85%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:2.6.32 cpe:/o:openbsd:openbsd:4.0
Aggressive OS guesses: Linux 3.11 - 4.1 (95%), Linux 4.4 (95%), Linux 3.13 (92%), Linux 4.0 (90%), Linux 2.6.32 (89%), Linux 2.6.32 or 3.10 (89%), Linux 3.2 - 3.8 (89%), Linux 3.10 - 3.12 (88%), Linux 2.6.32 - 2.6.33 (87%), Linux 2.6.32 - 2.6.35 (87%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 0.000 days (since Mon May 15 01:53:08 2017)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=252 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
TRACEROUTE
HOP RTT     ADDRESS
1   0.44 ms dellm6700 (192.168.2.15)
NSE: Script Post-scanning.
Initiating NSE at 01:53
Completed NSE at 01:53, 0.00s elapsed
Initiating NSE at 01:53
Completed NSE at 01:53, 0.00s elapsed
Read data files from: /usr/local/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/.
Nmap done: 1 IP address (1 host up) scanned in 46.02 seconds
Raw packets sent: 2075 (95.016KB) | Rcvd: 50 (3.084KB)
```

* * *

## Vulnerability Detection Techniques

The process of scanning for vulnerabilities is crucial in understanding the network environment being researched. While port scanning is a fundamental function of tools like Nmap, it provides valuable insights into the communication endpoints within a network. Each port is associated with a specific number and corresponds to the services or protocols running on it. Familiarity with common port numbers is essential for both hackers and cybersecurity professionals.

For a comprehensive list of common ports and protocols, refer to our detailed cheat sheet titled "Common Ports Cheat Sheet: The Ultimate Ports & Protocols List."

Now that we understand how Nmap scans for ports and identifies services, let's explore how this information can be leveraged for vulnerability detection using scripts. In the following sections, we will discuss three powerful techniques: the vuln flag, the vulners flag, and the installation and execution of vulscan scripts.

### How to Use Vuln

To initiate a vulnerability scan using Nmap's default script library under the "vuln" category, use the following command:

```html
sudo nmap --script vuln <target domain or IP Address> -v
```

In Linux environments, it may be necessary to run the command with elevated privileges using "sudo." The verbosity flag (-v) provides detailed information about the tests conducted and their outcomes.

It is important to note that certain vulnerability scans can be intrusive and disruptive, as they attempt to exploit vulnerabilities to verify their existence. This can potentially lead to service disruptions or crashes. To filter out vulnerabilities below a certain Common Vulnerability Scoring System (CVSS) score, use the following flag:

```html
--script-args=mincvss=x.x
```

For example, to exclude vulnerabilities below a score of 6.5, the command would be:

```html
sudo nmap --script vuln --script-args mincvss=6.5 <target>
```

Results of the scan can be exported in various formats by adding specific flags followed by the desired file name in the command. For instance:

- **XML File**: `nmap --script vuln -oX file.xml <target>`
- **Browser Friendly XML File**: `nmap --script vuln --webxml -oX file.xml <target>`

While the basic set of vulnerability scans provided by Nmap is valuable, advanced users may opt for custom scripts like Vulscan or Vulners to access a wider range of vulnerabilities.

### How to Use Vulscan

To utilize the Vulscan NSE script, clone the software from the GitHub repository using the following command:

```html
sudo git clone https://github.com/scipag/vulscan /usr/share/nmap/scripts/vulscan
```

Vulscan can be invoked using the --script flag to conduct additional vulnerability checks. The syntax is as follows:

```html
sudo nmap -sV --script=vulscan/vulscan.nse <target IP address or host name>
```

Vulscan performs non-invasive tests for vulnerabilities against the target, displaying relevant information on identified Common Vulnerabilities and Exposures (CVEs).

### How to Use Vulners

While Vulners is typically included in Nmap's standard NSE scripts, users can clone the NSE script from its GitHub repository using the following command:

```html
sudo git clone https://github.com/vulnersCom/Nmap-vulners /usr/share/nmap/scripts/vulners
```

Once cloned, Vulners can be executed using the --script flag with the following syntax:

```html
sudo nmap -sV --script Nmap-vulners/vulners.nse <target host or IP address>
```

Users can target specific ports on an IP address by adding -p<#> at the end of the command line. The results will display discovered CVEs and provide links to the Vulners website for additional information.

### Comparison of Vuln, Vulners and Vulscan

Vuln and Vulners are part of Nmap's basic script database and are updated alongside all NSE scripts. On the other hand, Vulscan must be downloaded and updated separately. Vulners leverages Common Platform Enumeration (CPE) information to actively retrieve the latest CVE data from external databases, requiring internet access. In contrast, Vuln and Vulscan utilize locally stored vulnerability databases without sharing CPE information externally.

While Vuln focuses on detecting a limited set of critical vulnerabilities with in-depth probing, Vulners and Vulscan offer a broader range of CVE detection capabilities. Vulners is typically more up-to-date, but organizations concerned about data privacy may prefer Vulscan's use of a local database.

* * *

## Nmap in Cyber Attacks

Attackers utilize Nmap to swiftly scan large networks, identifying available hosts and services to exploit vulnerabilities. By sending raw IP packets, hackers can gather critical information while concealing their tracks. Techniques like decoy scans and zombie scans add layers of complexity to evade detection and deceive intrusion detection systems.

For a comprehensive analysis of Nmap attacks, refer to the "Nmap Ultimate Guide: Pentest Product Review and Analysis."

### Detection of Nmap Scans

Defensive tools like SIEM platforms and firewalls can detect Nmap scans through alerts and log entries of TCP requests. Advanced IDS/IDP solutions can identify suspicious activities, such as stealthy requests, and respond to disruptive scans that impact system performance.

### Pros and Cons of Nmap Usage

While Nmap offers robust vulnerability scanning capabilities, its adoption may vary based on organizational needs and resources.

**Pros**

- Open source and free, suitable for various users
- Quick scans for rapid vulnerability assessment
- Lightweight TCP scans for minimal network impact
- Scriptable scans for automation and customization

**Cons**

- Less user-friendly than commercial tools
- Command line complexity may lead to errors
- Requires programming expertise for custom scripts
- Limited support compared to commercial solutions

* * *

## Conclusion

Nmap’s versatility and effectiveness position it as a valuable tool for vulnerability detection across diverse environments. Its ability to scan networks, identify open ports, and detect potential security weaknesses empowers organizations to proactively safeguard their systems. However, before integrating Nmap into their security workflows, organizations should carefully evaluate its pros and cons. Factors such as ease of use, scalability, and compatibility with existing tools should be considered to determine its suitability for their specific requirements. By conducting this assessment, organizations can make informed decisions about leveraging Nmap effectively in their cybersecurity strategies.