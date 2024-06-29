## Introduction

Network security is a critical aspect of safeguarding digital assets. One essential technique in the arsenal of security professionals is port scanning. In this article, we’ll delve into the world of port scanning, exploring its fundamentals, techniques, and how it plays a crucial role in vulnerability assessment.

* * *

## What Is Port Scanning?

Port scanning involves probing a target system’s network ports to identify which services are running and whether they are vulnerable. It serves several purposes:

- **Host Discovery**: Detecting live hosts on the network.
- **Port Enumeration**: Identifying open ports on a host.
- **Service Discovery**: Determining the software and versions associated with each open port.
- **Operating System Detection**: Inferring the operating system, hardware address, and software version.

### What is OS Fingerprinting?

Beyond port scanning, OS fingerprinting helps identify the operating system running on a target host. Nmap achieves this by analyzing network responses, examining factors like TTL values, IP ID sequences, and TCP window sizes. The accuracy of OS detection varies, but it provides valuable insights for security assessments. The term OS fingerprinting in Ethical Hacking refers to any method used to determine what operating system is running on a remote computer. This could be:

- **Active Fingerprinting** – Active fingerprinting is accomplished by sending specially crafted packets to a target machine and then noting down its response and analyzing the gathered information to determine the target OS. In the following section, we have given an example to explain how you can use NMAP tool to detect the OS of a target domain.
- **Passive Fingerprinting** − Passive fingerprinting is based on sniffer traces from the remote system (such as Wireshark). From this, you can determine the operating system of the remote host.

We have the following four important elements that we will look at to determine the operating system:

- **TTL** − What the operating system sets the **Time-To-Live** on the outbound packet.
- **Window Size** − What the operating system sets the Window Size at.
- **DF** − Does the operating system set the **Don't Fragment** bit.
- **TOS** − Does the operating system set the **Type of Service**, and if so, at what.

By analyzing these factors of a packet, you may be able to determine the remote operating system. This system is not 100% accurate and works better for some operating systems than others.

* * *

## How to Determine the Operating System?

Before attacking a system, it is required that you know what operating system is hosting a website. Once a target OS is known, then it becomes easy to determine which vulnerabilities might be present to exploit the target system.

Below is a simple **Nmap** command which can be used to identify the operating system serving a website and all the opened ports associated with the domain name, i.e., the IP address.

```html
nmap -O -v neoslab.com
```

It will show you the following sensitive information about the given domain name or IP address:

```html
Starting Nmap 5.51 ( http://nmap.org ) at 2015-10-04 09:57 CDT
Initiating Parallel DNS resolution of 1 host. at 09:57
Completed Parallel DNS resolution of 1 host. at 09:57, 0.00s elapsed
Initiating SYN Stealth Scan at 09:57
Scanning neoslab.com (66.135.33.172) [1000 ports]
Discovered open port 22/tcp on 66.135.33.172
Discovered open port 3306/tcp on 66.135.33.172
Discovered open port 80/tcp on 66.135.33.172
Discovered open port 443/tcp on 66.135.33.172
Completed SYN Stealth Scan at 09:57, 0.04s elapsed (1000 total ports)
Initiating OS detection (try #1) against neoslab.com (66.135.33.172)
Retrying OS detection (try #2) against neoslab.com (66.135.33.172)
Retrying OS detection (try #3) against neoslab.com (66.135.33.172)
Retrying OS detection (try #4) against neoslab.com (66.135.33.172)
Retrying OS detection (try #5) against neoslab.com (66.135.33.172)
Nmap scan report for neoslab.com (66.135.33.172)
Host is up (0.000038s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE
22/tcp     open    ssh
80/tcp     open    http
443/tcp    open    https
3306/tcp   open    mysql
TCP/IP fingerprint: OS:SCAN(V=5.51%D=10/4%OT=22%CT=1%CU=40379%PV=N%DS=0%DC=L%G=Y%TM=56113E6D%P= OS:x86_64-redhat-linux-gnu)SEQ(SP=106%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS OS:(O1=MFFD7ST11NW7%O2=MFFD7ST11NW7%O3=MFFD7NNT11NW7%O4=MFFD7ST11NW7%O5=MFF OS:D7ST11NW7%O6=MFFD7ST11)WIN(W1=FFCB%W2=FFCB%W3=FFCB%W4=FFCB%W5=FFCB%W6=FF OS:CB)ECN(R=Y%DF=Y%T=40%W=FFD7%O=MFFD7NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A OS:=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0% OS:Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S= OS:A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R= OS:Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N% OS:T=40%CD=S)
```

If you do not have **Nmap** command installed on your Linux system, then you can install it using the following **apt-get** command:

```html
sudo apt-get install nmap
```

You can go through **nmap** command in detail to check and understand the different features associated with a system and secure it against malicious attacks.

##### Prevent OS Detection

By strategically concealing your main system behind a robust and impenetrable proxy server or a reliable virtual private network (VPN), you can ensure that your complete digital identity remains shielded from prying eyes, safeguarding not only your personal information but also maintaining the overall security and integrity of your primary system.

### How to Perform a Port Scanning?

We have just seen the information given by **nmap** command. This command lists down all the open ports on a given server.

```html
PORT STATE SERVICE
22/tcp     open    ssh
80/tcp     open    http
443/tcp    open    https
3306/tcp   open    mysql
```

You can also check if a particular port is opened or not using the following command:

```html
nmap -sT -p 443 neoslab.com
```

It will produce the following result:

```html
Starting Nmap 5.51 ( http://nmap.org ) at 2015-10-04 10:19 CDT
Nmap scan report for neoslab.com (66.135.33.172)
Host is up (0.000067s latency).
PORT STATE SERVICE
443/tcp open    https
Nmap done: 1 IP address (1 host up) scanned in 0.04 seconds
```

Once a hacker knows about open ports, then he can plan different attack techniques through the open ports.

##### Quick Fix

Port blocking is a crucial practice for enhancing network security. By restricting or entirely denying access to specific network ports, you minimize exposure to potential cyber threats. Here are some steps to help safeguard your system:

- **Close Unused Ports**: Disable any ports that you’re not actively using. Unwanted open ports can be unsafe and provide threat actors with access to your system if not properly secured.
- **Port Traffic Filtering**: Continuously filter network packets based on their port numbers. This helps block or allow traffic to and from specific ports, protecting against cyber attacks associated with vulnerable ports.

Remember, every open port is safe unless the services running on them are vulnerable, misconfigured, or unpatched. Regularly review and manage your open ports to maintain a secure system!

* * *

## What is a Ping Sweep?

A [ping sweep](https://neoslab.com/2021/03/04/how-to-use-ping-sweeps-to-scan-networks-and-find-live-hosts/) is a network scanning technique that you can use to determine which IP address from a range of IP addresses map to live hosts. Ping Sweep is also known as **ICMP sweep**.

You can use **fping** command for ping sweep. This command is a ping-like program which uses the Internet Control Message Protocol (ICMP) **echo** request to determine if a host is up.

**fping** is different from **ping** in that you can specify any number of hosts on the command line, or specify a file containing the lists of hosts to ping. If a host does not respond within a certain time limit and/or retry limit, it will be considered unreachable.

**Quick Fix**

To disable ping sweeps on a network, you can block ICMP ECHO requests from outside sources. This can be done using the following command which will create a firewall rule in **iptable**.

```html
iptables -A OUTPUT -p icmp --icmp-type echo-request -j DROP
```

* * *

## What is DNS Enumeration?

Domain Name Server (DNS) is like a map or an address book. It is like a distributed database that is used to translate an IP address 192.111.1.120 to a name www.example.com and vice versa. DNS Enumeration involves querying DNS servers to gather information about domain names, IP addresses, mail servers, and other related records. Here's what it entails:

- **Zone Transfers**: DNS servers often store information about multiple domains within a zone. Zone transfers allow authorized parties to replicate this data across secondary DNS servers. However, misconfigured servers may inadvertently allow unauthorized zone transfers, revealing valuable information to potential attackers.
- **Brute-Force Enumeration**: Attackers attempt to discover subdomains by systematically querying common names (e.g., "www," "mail," "ftp") along with the target domain. Tools like `dnsrecon` and `sublist3r` automate this process.
- **Reverse DNS Lookup**: Given an IP address, reverse DNS lookup reveals the associated domain name. This technique helps map IP addresses back to their corresponding hosts.
- **DNS Cache Snooping**: Attackers exploit cached DNS records to extract information. By querying a DNS cache, they can retrieve domain names and IP addresses previously resolved by the server.

### Importance and Risks

DNS enumeration aids both security professionals and malicious actors:

- **Security Professionals**: They use DNS enumeration for reconnaissance, identifying potential vulnerabilities and misconfigurations.
- **Attackers**: They leverage DNS enumeration to gather intelligence for targeted attacks, such as phishing campaigns or network infiltration.

Understanding DNS enumeration is crucial for maintaining robust security practices. Responsible use ensures that legitimate purposes, such as network administration and vulnerability assessment, prevail over malicious intent. The idea is to gather as much interesting details as possible about your target before initiating an attack. You can use the following [DNSenum](https://packages.ubuntu.com/noble/dnsenum) packgage present in most Linux distribution to get detailed information about a domain:

```html
dnsenum
```

**DNSenum** script can perform the following important operations:

- Get the host's addresses
- Get the nameservers
- Get the MX record
- Perform **axfr** queries on nameservers
- Get extra names and subdomains via **Google scraping**
- Brute force subdomains from file can also perform recursion on a subdomain having NS records
- Calculate C class domain network ranges and perform **whois** queries on them
- Perform **reverse lookups** on **netranges**

##### Quick Fix

DNS Enumeration does not have a quick fix and it is really beyond the scope of this tutorial. Preventing DNS Enumeration is a big challenge.

If your DNS is not configured securely, it is possible that lots of sensitive information about the network and organization can go outside and an untrusted Internet user can perform a DNS zone transfer.

* * *

## Conclusion

In the ever-evolving landscape of cybersecurity, understanding port scanning and OS fingerprinting is essential. Whether you’re a beginner exploring the basics or an advanced practitioner fine-tuning your skills, mastering these techniques empowers you to secure networks effectively. Responsible port scanning is crucial, always obtain proper authorization and adhere to ethical guidelines when conducting security assessments.