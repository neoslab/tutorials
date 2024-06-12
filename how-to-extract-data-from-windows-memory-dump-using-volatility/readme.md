## Introduction

Digital forensics plays a critical role in uncovering evidence from computer systems, particularly by extracting information directly from volatile memory (RAM). This process allows investigators to retrieve valuable data, including user password hashes, Bitlocker volume encryption keys, and web browsing history. In this article, we delve into the tools and techniques used for memory analysis in digital forensic investigations.

* * *

## Requirements

In this article, we will see how researchers, experts in cyber-security and also hackers use **Volatility Framework** to retrieve almost everything they want from a computer memory dump. Before to move further and to be able to replicate this tutorial on your side, you will need the following to be present in your machine:

- VirtualBox 5 or 6 which will host the vulnerable Windows Server.
- A Windows or Linux system installed on a Virtual Machine
- Volatility Framework will be used to extract and read data from the RAM dump.

* * *

## Extract a Ram Dump from the Virtual Machine

As stated in the title, the first purpose of this article it's to see the best way to extract sensitive information from a computer memory dump and to do so we will use our virtual machine as a targeted system. This assumes that you have already installed a Windows operating system on your Virtual machine. For this demonstration, I use Windows Server 2008R2 as the operating system.

The first step for us will be to generate a memory dump of the target machine which is quite easy to do since we host it. This operation can be done quickly if you are using VirtualBox. To do it, you need first to start your target machine (VM) and once you are ready to use the following commands :

```html
cd /tmp/mkdir dump && cd dump# Don't forget to replace "Windows-2008-R2" with your own VM nameVBoxManage debugvm "Windows-2008-R2" dumpvmcore --filename=vm.memdumpls -la
```

**Output**

![How to Extract Data from Windows Memory Dump using Volatility](https://neoslab.com/uploads/medias/2021/01/how-to-extract-data-from-windows-memory-dump-using-volatility-1.png "How to Extract Data from Windows Memory Dump using Volatility")

Now that we are ready with our memory dump, we can start to move around and discover **Volatility Framework** and what this tool will allow us to do.

* * *

## How to use Volatility Framework

One of the most popular tools for RAM analysis is **Volatility**. This Open Source platform implemented using Python language can be used very easily on Windows, Mac, and Linux systems. It consists of several plugins that can be used for different types of queries.

The following memory format is supported by the latest Volatility release.

- Raw/Padded Physical Memory
- Firewire (IEEE 1394)
- Expert Witness (EWF)
- 32 and 64-bit Windows Crash Dump
- 32 and 64-bit Windows Hibernation
- 32 and 64-bit MachO files
- Virtualbox Core Dumps
- VMware Saved State (.vmss) and Snapshot (.vmsn)

Volatility Framework comes bundled with Kali Linux. If you do not have it yet in your machine, you can download and install it using the following instructions.

### Install Volatility on Ubuntu/Debian

```html
sudo apt -f install volatility
```

To display the help menu simply execute the following command:

```html
volatility --help
```

**Output**

![How to Extract Data from Windows Memory Dump using Volatility](https://neoslab.com/uploads/medias/2021/01/how-to-extract-data-from-windows-memory-dump-using-volatility-2.png "How to Extract Data from Windows Memory Dump using Volatility")

There is a multitude of options available that you can explore from the help. These options allow you to explore the contents of the memory and rebuild the data structures to extract the relevant information. The Volatility project [wiki](https://web.archive.org/web/20210226160416/https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) page presents each option.

**RETRIEVE THE PROFILE OF THE IMAGE WITH IMAGEINFO**

The first step to analyze a memory dump is to retrieve the information from the image that will allow Volatility to correctly parse the data to determine its profile.

Parsing the data means reading and interpreting them to understand what they mean. Depending on the type of profile you are reporting to Volatility, it will not interpret the data in the same way.

For that, we will use the "`imageinfo`" option of Volatility on our memory dump as stated in the below example.

```html
volatility -f vm.memdump imageinfo
```

**Output**

![How to Extract Data from Windows Memory Dump using Volatility](https://neoslab.com/uploads/medias/2021/01/how-to-extract-data-from-windows-memory-dump-using-volatility-3.png "How to Extract Data from Windows Memory Dump using Volatility")

**Note**: Of course the output on your side will be different according to the system image you are parsing.

The above command will allow you to get the profile information of your image. As you can see on the console output above, the "suggested profile" field offers suggestions for profiles which will then have to be specified to Volatility with the option "`--profile=`".

This profile corresponds to the operating system of your memory dump. Volatility suggests here a 64-bit system based on **Win7SP1x64** or **Win7SP0x64** or **Win2008R2SP0x64** or **Win2008R2SP1x64\_23418** or **Win2008R2SP1x64** or **Win7SP1x64\_23418**.

For this article, I did use **Windows Server 2008 R2 SP1**. We will then be able to specify later to process the dump with the option "`--profile=Win2008R2SP1x64`". Now that we have determined the profile of our image, we can start extracting information from it.

### Get the Processes List

The operating system is responsible for managing, handling, suspending and creating processes, that is, instances of a program.

When a program runs, a new process is created and associated with its own set of attributes, including a unique process ID (PID) unique to each, and an address space. The memory space of a process becomes a container for application code, shared libraries, dynamic data, and the execution stack.

An important aspect of memory analysis is enumerating the processes that run on a system and analyzing the data stored in their address space. The goal? Identify processes for potentially malicious programs, understand how they work, where they come from, and analyze them in detail.

Beware, to perform malicious actions, malware must be executed but it can hide its operation behind a legitimate process, via injection of code, for example.

To extract the list of processes, it is possible to use the "`pslist`" option.

```html
volatility -f vm.memdump --profile=Win2008R2SP1x64 pslist
```

**Output**

![How to Extract Data from Windows Memory Dump using Volatility](https://neoslab.com/uploads/medias/2021/01/how-to-extract-data-from-windows-memory-dump-using-volatility-4.png "How to Extract Data from Windows Memory Dump using Volatility")

This option allows us to display the list of the running processes at the time the dump was created. Using this, you can retrieve much information, such as :

- **offset**: the memory address of the process
- **name**: the name of the running process
- **PID**: the identification number of the process
- **PPID**: the PID of the parent process
- **start**: the date and time the process was started

During a memory analysis, it is necessary to be able to identify legitimate processes and those that are not. However, the name is not enough to identify whether a process is legitimate or not! But it's the first sign.

### List the DLLS of a Process

The DLLs, for Dynamic Link Library, are the libraries in Windows. These are functions previously coded and available on the system. To avoid re-encoding certain functions, the Windows API provides a list of DLLs for manipulating data, making network connections, or writing files.

Malware will also use these APIs to perform actions on the system. Through the memory analysis, it will be possible to list the DLL used by a process to deduce its operation on the system.

With Volatility, it is possible to extract the DLLs used for a given process, with the "`dlllist`" option. For example, if we want to find more information about the process with PID 1404 we shall use the following command:

```html
volatility -f vm.memdump --profile=Win2008R2SP1x64 dlllist -p 1824
```

**Output**

![How to Extract Data from Windows Memory Dump using Volatility](https://neoslab.com/uploads/medias/2021/01/how-to-extract-data-from-windows-memory-dump-using-volatility-5.png "How to Extract Data from Windows Memory Dump using Volatility")

### Analyze the Registry

The registry contains various settings and configurations for the Windows operating system. As the main component of Windows, it is accessed continuously during the execution time. Thus, it is logical that the system places in memory all or part of the files of the register.

Besides, the Windows registry holds a wealth of useful information for analysis purposes. For example, it will be possible to determine recently executed programs, extract hashes of passwords for audit purposes, or study the keys and values introduced by malicious code into the system.

With Volatility, it is possible to extract the information from the register and lists the corresponding files with the "`hivelist`" option.

```html
volatility -f vm.memdump --profile=Win2008R2SP1x64 hivelist
```

**Output**

![How to Extract Data from Windows Memory Dump using Volatility](https://neoslab.com/uploads/medias/2021/01/how-to-extract-data-from-windows-memory-dump-using-volatility-6.png "How to Extract Data from Windows Memory Dump using Volatility")

Using the result of the above command and the "`hashdump`" option, it will be possible to dump the password hashes of Windows accounts.

```html
volatility -f vm.memdump --profile=Win2008R2SP1x64 hashdump -y 0xfffff8a0073d4410
```

**Output**

![How to Extract Data from Windows Memory Dump using Volatility](https://neoslab.com/uploads/medias/2021/01/how-to-extract-data-from-windows-memory-dump-using-volatility-7.png "How to Extract Data from Windows Memory Dump using Volatility")

### Analyze Network Connections

Almost all malware can communicate on the network using their **Control server**, to spread themself, or set up a backdoor.

These actions use **Windows Network APIs**, which inevitably leave traces in memory. The network memory scan will recover information such as remote IP connections, connection ports, and even some data exchanged.

Volatility provides several options for retrieving login information. The connections, **sockscan**, and socket options work only on systems older than **Windows 7**.

However, active network connections can be listed on newer systems with the "`netscan`" option.

```html
volatility -f vm.memdump --profile=Win2008R2SP1x64 netscan
```

**Output**

![How to Extract Data from Windows Memory Dump using Volatility](https://neoslab.com/uploads/medias/2021/01/how-to-extract-data-from-windows-memory-dump-using-volatility-8.png "How to Extract Data from Windows Memory Dump using Volatility")

In the above screenshot, we can see that some identified processes make multiple connections to the IP addresses 56.107.77.2:0, 104.0.138.2:0 and 120.168.122.2:0.

Memory analysis can reveal a lot of things about the infected environment. A malicious process will be easier to detect and analyze a memory dump than in a running environment. In addition, it will be possible to access other crucial information about the system.

* * *

## Discover the Different Type Memory Files

There are different types of files that can be used for memory analysis. Windows uses system files to store certain information that is specific to internal features, such as hibernation or paging.

**HIBERFIL.SYS**

Hiberfil.sys is the default file used by Windows to save the **machine state** as part of the hibernation process. This process is used to restore the state of the machine. The operating system also maintains an open file descriptor on this file so that no user, including the administrator, can read the file while the system is running.

The file hiberfil.sys is compressed by default. In order to be able to analyze it with Volatility, it will first be necessary to use the "`imagecopy`" option to decompress the image.

```html
volatility -f vm.memdump --profile=Win2008R2SP1x64 imagecopy -O hiberfil.dmp
```

![How to Extract Data from Windows Memory Dump using Volatility](https://neoslab.com/uploads/medias/2021/01/how-to-extract-data-from-windows-memory-dump-using-volatility-9.png "How to Extract Data from Windows Memory Dump using Volatility")

**PAGEFILE.SYS**

Paging is a concept that **extends the available RAM** by storing RAM items that are not in use in a file. Windows uses the system file **Pagefile.sys** to store this information, which can also be exploited during the investigation.

Although Windows supports up to **16 paging files**, in practice only one is used. This file, stored in "%SystemDrive%\\pagefile.sys", is a hidden system file.

Because the operating system **keeps this file open during normal operation**, it can never be read or viewed by a user. However, it may contain interesting information once extracted.

Pagefile.sys can not be parsed by Volatility. However, it is possible to extract information with the "`strings`" command. Be careful, note that this can be extremely long and it is better to couple the command "`strings`" with the command "`grep`".

```html
strings pagefile.sys | grep “http://”
```

* * *

## Conclusion

In the ever-evolving landscape of cybersecurity, memory forensics remains a powerful method for extracting crucial evidence. By understanding the intricacies of RAM analysis, investigators can uncover hidden details that shed light on cyber incidents, criminal activities, and security breaches. As technology advances, so too do the tools at our disposal, ensuring that digital forensics continues to play a vital role in safeguarding digital environments.