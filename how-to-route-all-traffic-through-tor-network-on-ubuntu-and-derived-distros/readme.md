## Introduction

The Tor network, known for its ability to provide anonymity and privacy online, has become increasingly popular among users seeking to protect their digital identities. However, ensuring that your internet traffic remains secure and free from leaks is crucial. In this tutorial, we’ll explore DNS leaks, understand their implications, and learn how to route all traffic through the Tor network to enhance privacy.

* * *

## Understanding DNS Leaks

DNS (Domain Name System) leaks occur when your device inadvertently sends DNS requests to your internet service provider (ISP) instead of the DNS servers provided by your anonymity tool (such as a VPN or Tor). These leaks can reveal your browsing activities, expose your geolocation, and compromise your security. To prevent DNS leaks, we’ll explore how to configure your system to route all traffic through Tor.

If you use an anonymity tool, such as a VPN, ideally, your DNS requests should not go to your Internet service provider, but the DNS hosted by your VPN. A DNS leak occurs when a security breach forces your device to forward the DNS request to the DNS server of your Internet service provider.

Your DNS queries indicate your browsing activities, which can be used against you. If someone has access to your DNS requests, it means that your security has been compromised and that you are exposed. Besides, a DNS leak can also expose your actual geolocation and the location of your Internet service provider. This may not be a big deal, but it is the kind of information that hackers can use to find your real IP address.

[DNSLeakTest.com](https://dnsleaktest.com/) is a great tool that you can use to perform a quick and accurate DNS leak test. You can run a standard test or an extended test. But you can also try some other service such as [Browserleaks](https://browserleaks.com/), [Ipleak](https://ipleak.net/), or [Dnsleak](https://dnsleak.com/). For this tutorial, we will make a test using [DNSLeakTest.com](https://dnsleaktest.com/) website.

**Output**

![How to Route all Traffic Through Tor Network on Ubuntu and Derived Distros](https://neoslab.com/uploads/medias/2021/05/how-to-route-all-traffic-through-tor-network-on-ubuntu-and-derived-distros-1.png "How to Route all Traffic Through Tor Network on Ubuntu and Derived Distros")

As you can see, the site was able to retrieve our IP address as well as information regarding the DNS used by our connection.

* * *

## How to Route all Traffic Through Tor Network?

It’s possible to route all your local traffic, in a transparent mode, through the Tor network, including all the DNS request. Let’s see how we can achieve it using Arch GNU/Linux distribution. Before moving further, we will need to install some packages such as of course Tor but also Polipo. To do it, simply open your terminal and use the below commands.

```html
sudo apt update && sudo apt install macchanger tor
```

#### Configuration of Tor

Next, we will move on the configuration of **Tor** by replacing the configuration located in `/etc/tor/torrc` by the one I'm providing in the below example. Exactly like in the previous step, before doing it, please be sure to create a backup of your current configuration file.

```html
sudo mv /etc/tor/torrc /etc/tor/torrc.bak
sudo cat >> /etc/tor/torrc << EOL
DataDirectory /var/lib/tor
VirtualAddrNetwork 10.192.0.0/10
AutomapHostsOnResolve 1
AutomapHostsSuffixes .exit,.onion
TransPort 127.0.0.1:9040 IsolateClientAddr IsolateSOCKSAuth IsolateClientProtocol IsolateDestPort IsolateDestAddr
SocksPort 127.0.0.1:9050 IsolateClientAddr IsolateSOCKSAuth IsolateClientProtocol IsolateDestPort IsolateDestAddr
ControlPort 9051
HashedControlPassword 16:FDE8ED505C45C8BA602385E2CA5B3250ED00AC0920FEC1230813A1F86F
DNSPort 127.0.0.1:9053
HardwareAccel 1
TestSocks 1
AllowNonRFC953Hostnames 0
WarnPlaintextPorts 23,109,110,143,80
ClientRejectInternalAddresses 1
NewCircuitPeriod 40
MaxCircuitDirtiness 600
MaxClientCircuitsPending 48
UseEntryGuards 1
EnforceDistinctSubnets 1
EOL

sudo chmod 644 /etc/tor/torrc
```

#### Configuration of Resolv.conf

We will need now to configure our Network to use **Tor**. In most Unix-like operating systems and others that implement the BIND Domain Name System (DNS) resolver library, the `/etc/resolv.conf` the configuration file contains information that determines the operational parameters of the DNS resolver. As per the previous step, please be sure to create a backup of your current `resolv.conf` file before proceeding further.

```html
sudo mv /etc/resolv.conf /etc/resolv.conf.bak
sudo cat >> /etc/resolv.conf << EOL
nameserver 127.0.0.1
nameserver 1.1.1.1
nameserver 1.0.0.1
nameserver 208.67.222.222
nameserver 208.67.220.220
nameserver 8.8.8.8
nameserver 8.8.4.4
EOL

sudo chmod 644 /etc/resolv.conf
```

* * *

## How To Prevent DNS Leak?

#### Flushing current Iptables setting

We will need now to flush our current `iptables` rules. Before doing it, it's better to create a backup of our current configuration to be able to restore it once we are done.

```html
sudo iptables-save > /etc/iptables.rules.bak
sudo iptables -F
sudo iptables -t nat -F
```

#### Launch of all required services

We can now proceed and start all the required services. In the case that required services are already started, you will need to use `reload` instead of `start` as a command parameter.

```html
sudo systemctl start tor
```

#### Configuration of Iptables

This is one of the most crucial steps. What we are going to do now, is to configure our Firewall `iptables` to allow only the request made to/from **Tor** network and block any other one.

```html
## Set Iptables Nat
## ----------------
sudo iptables -t nat -A OUTPUT -m owner --uid-owner tor -j RETURN

## Set DNS Redirect
## ----------------
sudo iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 9053
sudo iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 9053
sudo iptables -t nat -A OUTPUT -p udp -m owner --uid-owner tor -m udp --dport 53 -j REDIRECT --to-ports 9053

## Resolve domains mapping 10.192.0.0/10 address space
## ---------------------------------------------------
sudo iptables -t nat -A OUTPUT -p tcp -d 10.192.0.0/10 -j REDIRECT --to-ports 9040
sudo iptables -t nat -A OUTPUT -p udp -d 10.192.0.0/10 -j REDIRECT --to-ports 9040

## Exclude Tor CIDR
## ----------------
sudo iptables -t nat -A OUTPUT -d 192.168.0.0/16 -j RETURN
sudo iptables -A OUTPUT -d 192.168.0.0/16 -j ACCEPT

sudo iptables -t nat -A OUTPUT -d 172.16.0.0/12 -j RETURN
sudo iptables -A OUTPUT -d 172.16.0.0/12 -j ACCEPT

sudo iptables -t nat -A OUTPUT -d 10.0.0.0/8 -j RETURN
sudo iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT

sudo iptables -t nat -A OUTPUT -d 127.0.0.0/9 -j RETURN
sudo iptables -A OUTPUT -d 127.0.0.0/9 -j ACCEPT

sudo iptables -t nat -A OUTPUT -d 127.128.0.0/10 -j RETURN
sudo iptables -A OUTPUT -d 127.128.0.0/10 -j ACCEPT

## Redirect all other output through Tor
## -------------------------------------
sudo iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports 9040
sudo iptables -t nat -A OUTPUT -p udp -j REDIRECT --to-ports 9040
sudo iptables -t nat -A OUTPUT -p icmp -j REDIRECT --to-ports 9040

## Accept already established connections
## --------------------------------------
sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

## Allow only Tor output
## ---------------------
sudo iptables -A OUTPUT -m owner --uid-owner tor -j ACCEPT
sudo iptables -A OUTPUT -j REJECT
```

#### Creating New System Rules

Believe me or not, we are almost done! This is going to be the final step. We will need to create new system rules to prevent anyone from outside your NAT to reach your machine while you are connecting over the Net. As we did in all the previous steps, do not forget to create a backup of your current `sysctl` configuration.

```html
sudo sysctl -a > /etc/sysctl.conf.bak

## Swappiness
## ----------
sudo sysctl -w vm.dirty_ratio=10 &>"/dev/null"
sudo sysctl -w vm.dirty_background_ratio=5 &>"/dev/null"
sudo sysctl -w vm.dirty_expire_centisecs=2000 &>"/dev/null"
sudo sysctl -w vm.dirty_writeback_centisecs=1000 &>"/dev/null"
sudo sysctl -w vm.swappiness=10 &>"/dev/null"
sudo sysctl -w vm.vfs_cache_pressure=70 &>"/dev/null"

## Disable Explicit Congestion Notification in TCP
## -----------------------------------------------
sudo sysctl -w net.ipv4.tcp_ecn=0 &>"/dev/null"

## Window scaling
## --------------
sudo sysctl -w net.ipv4.tcp_window_scaling=1 &>"/dev/null"

## Increase Linux auto-tuning TCP buffer limits
## --------------------------------------------
sudo sysctl -w net.ipv4.tcp_rmem="8192 87380 16777216" &>"/dev/null"
sudo sysctl -w net.ipv4.tcp_wmem="8192 65536 16777216" &>"/dev/null"

## Increase TCP max buffer size
## ----------------------------
sudo sysctl -w net.core.rmem_max=16777216 &>"/dev/null"
sudo sysctl -w net.core.wmem_max=16777216 &>"/dev/null"

## Increase number of incoming connections backlog
## -----------------------------------------------
sudo sysctl -w net.core.netdev_max_backlog=16384 &>"/dev/null"
sudo sysctl -w net.core.dev_weight=64 &>"/dev/null"

## Increase number of incoming connections
## ---------------------------------------
sudo sysctl -w net.core.somaxconn=32768 &>"/dev/null"

## Increase the maximum amount of option memory buffers
## ----------------------------------------------------
sudo sysctl -w net.core.optmem_max=65535 &>"/dev/null"

## Increase the TCP-time-wait buckets
## Pool sizeto prevent simple DOS attacks
## --------------------------------------
sudo sysctl -w net.ipv4.tcp_max_tw_buckets=1440000 &>"/dev/null"

## Try to reuse time-wait connections
## ----------------------------------
sudo sysctl -w net.ipv4.tcp_tw_reuse=1 &>"/dev/null"

## Limit number of allowed orphans
## Each orphan can eat up to 16M of unswappable memory
## ---------------------------------------------------
sudo sysctl -w net.ipv4.tcp_max_orphans=16384 &>"/dev/null"
sudo sysctl -w net.ipv4.tcp_orphan_retries=0 &>"/dev/null"

## Don't cache ssthresh from previous connection
## ---------------------------------------------
sudo sysctl -w net.ipv4.tcp_no_metrics_save=1 &>"/dev/null"
sudo sysctl -w net.ipv4.tcp_moderate_rcvbuf=1 &>"/dev/null"

## Increase size of RPC datagram queue length
## ------------------------------------------
sudo sysctl -w net.unix.max_dgram_qlen=50 &>"/dev/null"

## Don't allow the ARP table to become bigger than this
## ----------------------------------------------------
sudo sysctl -w net.ipv4.neigh.default.gc_thresh3=2048 &>"/dev/null"

## Tell the gc when to become aggressive with arp table cleaning
## Adjust this based on size of the LAN. 1024 is suitable for most /24 networks
## ----------------------------------------------------------------------------
sudo sysctl -w net.ipv4.neigh.default.gc_thresh2=1024 &>"/dev/null"

## Adjust where the GC will leave ARP table alone set to 32
## --------------------------------------------------------
sudo sysctl -w net.ipv4.neigh.default.gc_thresh1=32 &>"/dev/null"

## Adjust to ARP table GC to clean-up more often
## ---------------------------------------------
sudo sysctl -w net.ipv4.neigh.default.gc_interval=30 &>"/dev/null"

## Increase TCP queue length
## -------------------------
sudo sysctl -w net.ipv4.neigh.default.proxy_qlen=96 &>"/dev/null"
sudo sysctl -w net.ipv4.neigh.default.unres_qlen=6 &>"/dev/null"

## Enable Explicit Congestion Notification
## ---------------------------------------
sudo sysctl -w net.ipv4.tcp_ecn=1 &>"/dev/null"
sudo sysctl -w net.ipv4.tcp_reordering=3 &>"/dev/null"

## How many times to retry killing an alive TCP connection
## -------------------------------------------------------
sudo sysctl -w net.ipv4.tcp_retries2=15 &>"/dev/null"
sudo sysctl -w net.ipv4.tcp_retries1=3 &>"/dev/null"

## Avoid falling back to slow start after a connection goes idle
## keeps our cwnd large with the keep alive connections (kernel > 3.6)
## -------------------------------------------------------------------
sudo sysctl -w net.ipv4.tcp_slow_start_after_idle=0 &>"/dev/null"

## Allow the TCP fastopen flag to be used
## Beware some firewalls do not like TFO (kernel > 3.7)
## ----------------------------------------------------
sudo sysctl -w net.ipv4.tcp_fastopen=3 &>"/dev/null"

## This will ensure that immediatly subsequent connections use the new values
## --------------------------------------------------------------------------
sudo sysctl -w net.ipv4.route.flush=1 &>"/dev/null"
sudo sysctl -w net.ipv6.route.flush=1 &>"/dev/null"

## TCP SYN cookie protection
## -------------------------
sudo sysctl -w net.ipv4.tcp_syncookies=1 &>"/dev/null"

## TCP RFC 1337
## ------------
sudo sysctl -w net.ipv4.tcp_rfc1337=1 &>"/dev/null"

## Reverse path filtering
## ----------------------
sudo sysctl -w net.ipv4.conf.default.rp_filter=1 &>"/dev/null"
sudo sysctl -w net.ipv4.conf.all.rp_filter=1 &>"/dev/null"

## Log martian packets
## -------------------
sudo sysctl -w net.ipv4.conf.default.log_martians=1 &>"/dev/null"
sudo sysctl -w net.ipv4.conf.all.log_martians=1 &>"/dev/null"

## Disable ICMP redirecting
## ------------------------
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0 &>"/dev/null"
sudo sysctl -w net.ipv4.conf.default.accept_redirects=0 &>"/dev/null"
sudo sysctl -w net.ipv4.conf.all.secure_redirects=0 &>"/dev/null"
sudo sysctl -w net.ipv4.conf.default.secure_redirects=0 &>"/dev/null"
sudo sysctl -w net.ipv6.conf.all.accept_redirects=0 &>"/dev/null"
sudo sysctl -w net.ipv6.conf.default.accept_redirects=0 &>"/dev/null"
sudo sysctl -w net.ipv4.conf.all.send_redirects=0 &>"/dev/null"
sudo sysctl -w net.ipv4.conf.default.send_redirects=0 &>"/dev/null"

## Enable Ignoring to ICMP Request
## -------------------------------
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1 &>"/dev/null"

## Disable IPv6
## ------------
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 &>"/dev/null"
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1 &>"/dev/null"
```

* * *

## Let's Make A Test

We will now see if all this work leads us to a satisfactory result. To do this we will simply repeat a what we did at the beginning of this tutorial by going back to the site [DNSLeakTest.com](https://web.archive.org/web/20210226160537/https://dnsleaktest.com/) and conduct a new test.

**Output**

![How to Route all Traffic Through Tor Network on Ubuntu and Derived Distros](https://neoslab.com/uploads/medias/2021/05/how-to-route-all-traffic-through-tor-network-on-ubuntu-and-derived-distros-2.png "How to Route all Traffic Through Tor Network on Ubuntu and Derived Distros")

As you can see, the site was unable to determine our IP address as well as our Internet service provider DNS. We can, therefore, consider that these efforts give us a result that lives up to our expectations.

* * *

### Can We Wrap All This Together?

Yes, we can! And to make it easier, you can get all this to be done from a single command line! Why didn't I say it earlier? Because the purpose of this tutorial is to understand how Tor works and how to protect against DNS leaks.

All you have to do is clone the script we have created a few days ago and available on [Github](https://github.com/neoslab/torbridge). This script is based on [Torctl](https://github.com/BlackArch/torctl) which is available on **BlackArch** but few optimizations were made to minimize latency.

**Clone the Script**

```html
cd /tmp/
git clone https://github.com/neoslab/torbridge
chmod +x /tmp/torbridge/torbridge
sudo mv /tmp/torbridge/torbridge /usr/local/bin/
```

**Display the Help Menu**

```html
sudo torbridge -h
```

**Output**

![How to Route all Traffic Through Tor Network on Ubuntu and Derived Distros](https://neoslab.com/uploads/medias/2021/05/how-to-route-all-traffic-through-tor-network-on-ubuntu-and-derived-distros-3.png "How to Route all Traffic Through Tor Network on Ubuntu and Derived Distros")


**Start the Script**

```html
sudo torbridge --start
```

**Output**

![How to Route all Traffic Through Tor Network on Ubuntu and Derived Distros](https://neoslab.com/uploads/medias/2021/05/how-to-route-all-traffic-through-tor-network-on-ubuntu-and-derived-distros-4.png "How to Route all Traffic Through Tor Network on Ubuntu and Derived Distros")

**Stop the Script**

```html
sudo torbridge --stop
```

**Output**

![How to Route all Traffic Through Tor Network on Ubuntu and Derived Distros](https://neoslab.com/uploads/medias/2021/05/how-to-route-all-traffic-through-tor-network-on-ubuntu-and-derived-distros-5.png "How to Route all Traffic Through Tor Network on Ubuntu and Derived Distros")

* * *

## Enhancing Privacy with TorBridge

By following these steps, you can route all your traffic through the Tor network, significantly enhancing your privacy and security. Remember that TorBridge is also available by default in the latest version of [SnoopGod Linux](https://snoopgod.com). For advanced users, consider downloading the latest SnoopGod 24.04.2 release to explore TorBridge’s capabilities further.

### Automatic MAC Address Rotation

In addition to routing traffic through Tor, TorBridge includes a powerful feature: automatic MAC address rotation. This function ensures that your device remains completely anonymous by periodically changing its MAC address. By doing so, TorBridge adds an extra layer of protection against tracking and surveillance.

* * *

## Conclusion

TorBridge is a powerful tool that enhances online privacy and security. By routing internet traffic through the Tor network, it allows users to maintain anonymity and protect sensitive data. Whether you’re using Linux or another operating system, TorBridge provides a valuable solution for safeguarding your online activities.