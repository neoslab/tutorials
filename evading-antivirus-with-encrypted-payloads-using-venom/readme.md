## Introduction

In the realm of cybersecurity, penetration testers and ethical hackers often require tools to test the robustness of security systems. One such powerful tool is **Venom**, which utilizes **Msfvenom** from the **Metasploit** framework to generate shellcode in various formats, including "c", "python", "ruby", "dll", "msi", and "hta-psh". Venom injects the generated shellcode into a template and works with encrypted payloads to evade antivirus detection. This guide will walk you through the process of installing and using Venom to generate encrypted payloads and conduct penetration tests.

* * *

### How To Install Venom?

```html
git clone https://github.com/r00t-3xp10it/venom.git
cd venom
sudo chmod -R +x *.sh
cd aux
sudo ./setup.sh
```

* * *

### Launch Venom

```html
sudo ./venom.sh
```

Once the tool is launched, it will prompt you to press "Enter" to proceed with further options.

![Evading AntiVirus with Encrypted Payloads using Venom](https://neoslab.com/uploads/medias/2022/01/evading-antivirus-with-encrypted-payloads-using-venom-1.png "Evading AntiVirus with Encrypted Payloads using Venom")

The next screen will display information about the built options, target machine, payload format, and output. There are seven different types of shellcode options available. For this demonstration, we will use shellcode **number 4**.

![Evading AntiVirus with Encrypted Payloads using Venom](https://neoslab.com/uploads/medias/2022/01/evading-antivirus-with-encrypted-payloads-using-venom-2.png "Evading AntiVirus with Encrypted Payloads using Venom")

Simply choose the Venom shellcode **number 4** and press "Enter" to continue.

* * *

### Payload Configuration

Next, you need to choose your agent referral. Venom offers two options: **Android** and **iOS**. For this demonstration, we will select agent **number 1**.

![Evading AntiVirus with Encrypted Payloads using Venom](https://neoslab.com/uploads/medias/2022/01/evading-antivirus-with-encrypted-payloads-using-venom-3.png "Evading AntiVirus with Encrypted Payloads using Venom")

Now, set up the localhost IP address (LHOST) and the local port (LPORT) which will be used by the payload for listening. Enter your local machine IP address and local port.

![Evading AntiVirus with Encrypted Payloads using Venom](https://neoslab.com/uploads/medias/2022/01/evading-antivirus-with-encrypted-payloads-using-venom-4.png "Evading AntiVirus with Encrypted Payloads using Venom")

Finally, name your payload and define the delivery method.

![Evading AntiVirus with Encrypted Payloads using Venom](https://neoslab.com/uploads/medias/2022/01/evading-antivirus-with-encrypted-payloads-using-venom-5.png "Evading AntiVirus with Encrypted Payloads using Venom")

![Evading AntiVirus with Encrypted Payloads using Venom](https://neoslab.com/uploads/medias/2022/01/evading-antivirus-with-encrypted-payloads-using-venom-6.png "Evading AntiVirus with Encrypted Payloads using Venom")

* * *

### Launch The Attack

At this stage, you are almost done. A new terminal will automatically start a Metasploit session, allowing you to conduct your attack with the encrypted payload.

![Evading AntiVirus with Encrypted Payloads using Venom](https://neoslab.com/uploads/medias/2022/01/evading-antivirus-with-encrypted-payloads-using-venom-7.png "Evading AntiVirus with Encrypted Payloads using Venom")

* * *

## Conclusion

Using Venom, you can generate encrypted payloads that are more likely to evade antivirus detection, providing a valuable tool for penetration testing and ethical hacking. By following the steps outlined in this guide, you can install and configure Venom, generate a payload, and launch a Metasploit session to test the security of your systems.