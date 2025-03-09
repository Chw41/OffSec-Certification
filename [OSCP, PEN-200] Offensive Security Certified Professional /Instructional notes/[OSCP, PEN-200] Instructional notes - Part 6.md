---
title: '[OSCP, PEN-200] Instructional notes - Part 6'
disqus: hackmd
---

[OSCP, PEN-200] Instructional notes - Part 6
===

# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 1"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/README.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 2"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%202.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 3"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%203.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 4"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%204.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 5"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%205.md)

>[!Caution]
> 接續 [[OSCP, PEN-200] Instructional notes - Part 5](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%205.md) 內容

# Active Directory Introduction and Enumeration
[Active Directory Domain Services](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview) 通常稱為 Active Directory (AD) 允許 System Administrators 大規模更新和管理作業系統、應用程式、使用者和資料存取的服務。
## Active Directory - Introduction
Active Directory 本身就是一種服務，但它也充當 management layer。 AD 包含有關環境的關鍵資訊，儲存有關 `users`, `groups` 與 `computers` 的資訊，每個資訊稱為 objects。每個 object 上設定的權限決定了該物件在網域內的權限。
>[!Important]
>Active Directory（AD）環境高度依賴 Domain Name System（DNS） 服務。 因此，典型的 Domain Controller (DC) 通常也會同時運行 DNS 伺服器，並且 負責解析該網域的名稱（authoritative for a given domain）。

- 使用 [Organizational Units](https://en.wikipedia.org/wiki/Organizational_unit_(computing))（OU）來管理 objects
為了簡化管理，系統管理員通常會使用 Organizational Units 來分類不同的物件：\
OU 就像檔案系統的資料夾，用來存放 AD 內的物件。
    - `Computer objects` 代表 加入網域的伺服器或 workstation。
    - `User objects` 代表 可以登入網域的帳戶，並包含各種 attributes，如：
        - First Name
        - Last Name
        - Username
        - Phone Number等
- AD 運作機制: DC
當使用者嘗試登入網域時，會發送一個 request 到 Domain Controller (DC) 由 DC 來檢查該使用者是否有權限登入。
DC 是 整個網域的核心組件，存放所有：
    - OUs（組織單位）
    - Objects（物件）
    - Attributes（屬性）

因此當我們進行 AD 滲透測試時，會 特別關注 DC，因為它是 AD 最核心的目標之一。
- AD groups 與高權限帳戶
Objects 可以被分配到 AD Groups，這樣系統管理員就能夠一次性管理一組物件。例如：
某個 group member 可能會獲得 檔案伺服器存取權限。
某些 group 可能擁有 網域內的管理員權限。
     - (1) [Domain Admins](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#domain-admins)
    Domain Admins Group Member 是網域中擁有最高權限的 Objects 之一，擁有整個網域的管理權限。\
如果 attacker 成功獲取此群組內成員的帳號，就可以完全 控制整個網域。
     - (2) Enterprise Admins
    AD 環境可以擁有多個網域（Domain Tree 或 Domain Forest）。
每個網域都有自己的 Domain Admins 群組。\
     Enterprise Admins Group 則擁有「所有網域」的最高權限，能 管理整個 AD 樹狀結構中的所有網域。

Enumeration 會使用多種工具來進行手動與自動化枚舉，其中大部分工具都會透過 LDAP（[Lightweight Directory Access Protocol](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol)） 來查詢 AD 內的物件資訊。

### Enumeration - Defining our Goals
如何透過 低權限帳號進行滲透測試。
[環境範例]
- 目標 滲透 `corp.com` 網域。
- 已經透過 Phishing Attack，成功取得了一個網域使用者的帳號密碼。
- 另一種可能是：目標組織主動提供我們一組使用者帳號，以模擬實際滲透測試（假設攻擊，Assumed Breach）。這樣可以幫助企業評估：如果攻擊者獲得初始存取權限，他們可以多快進行進一步的攻擊與 Lateral Movement。
- 可用帳號：
    - 帳戶是 stephanie
    - 具有 RDP 權限，可以連線到 Windows 11 workstation，該 workstation 已加入 corp.com 網域。
    - stephanie 並不是該機器的 Local Administrator ，這可能會影響我們執行某些命令或工具的權限。

#### Enumeration 的方式
從 stephanie 低權限帳號開始進行 AD enumeration，並且 透過這個帳號找到其他潛在的攻擊機會。**一旦我們獲取新的使用者帳號或電腦存取權限，就需要重新進行枚舉**。
- Pivoting(視角轉變) & Rinse and Repeat(反覆枚舉)
當我們獲得新帳號或新的電腦存取權限時，我們需要 重新枚舉:
    - 不同使用者的權限可能不同（即使表面上屬於相同的低權限使用者群組）。
    - 某些帳號可能擁有特定資源的存取權限，但 stephanie 可能沒有。
    - 系統管理員有時會額外賦予個別帳號更多權限，例如特定伺服器的存取權限。
    
### Active Directory - Manual Enumeration
stephanie 是低權限使用者，但有 RDP 存取權限
#### 1. 透過 RDP 登入 Windows 11
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /u:stephanie /d:corp.com /v:192.168.14ㄓ.75

```
>[!Warning]
>**避免 Kerberos 雙重跳躍問題（[Kerberos Double-Hop](https://posts.slayerlabs.com/double-hop/) Issue）**:\
建議使用 RDP，而非 PowerShell Remoting（WinRM），因為透過 WinRM 可能會導致 無法執行 AD 枚舉工具。\
Kerberos 雙重跳躍（Double-Hop）問題 會影響某些遠端命令的執行權限，詳細內容可參考 PEN-300 課程。\
![image](https://hackmd.io/_uploads/rynmdbookg.png)

#### 2. 使用 net.exe 枚舉 AD 的使用者
使用 `net user /domain` 來列出 corp.com 網域內的所有使用者
```
PS C:\Users\stephanie> net user /domain
The request will be processed at a domain controller for domain corp.com.


User accounts for \\DC1.corp.com

-------------------------------------------------------------------------------
Administrator            dave                     Guest
iis_service              jeff                     jeffadmin
jen                      krbtgt                   pete
stephanie
The command completed successfully.
```
> `Administrator`：內建的網域管理員帳號。\
`krbtgt`：Kerberos 票證授權服務帳號，可能與 Kerberos 身份驗證有關。\
`jeffadmin`：帳號名稱帶有 "admin"，可能是管理員帳戶，值得調查。

#### 3. 查詢特定使用者資訊
使用 `net user` 指令，針對 jeffadmin 進行更詳細的查詢
```
PS C:\Users\stephanie> net user jeffadmin /domain
The request will be processed at a domain controller for domain corp.com.

User name                    jeffadmin
Full Name
...
Account expires              Never

...
Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/8/2024 3:47:01 AM

Logon hours allowed          All

Local Group Memberships      *Administrators
Global Group memberships     *Domain Users         *Domain Admins
The command completed successfully.
```
> jeffadmin 是 **Domain Admins** group member\
密碼不會過期
>> 如果我們能夠獲取 jeffadmin 的 credential，就能直接擁有 Domain Admin 權限。

#### 4. 使用 net.exe 查詢 AD 的群組
使用 `net group /domain` 指令，來查看網域內所有的群組
```
PS C:\Users\stephanie> net group /domain
The request will be processed at a domain controller for domain corp.com.

Group Accounts for \\DC1.corp.com

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*Debug
*Development Department
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*Key Admins
*Management Department
*Protected Users
*Read-only Domain Controllers
*Sales Department
*Schema Admins
The command completed successfully.
```
> [default Group](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)\
> `Domain Admins`: 整個網域的最高權限\
`Enterprise Admins`: 擁有多個網域的管理權限，通常在 Active Directory Forest 內才會出現\
`Sales Department`: 自訂群組，可能代表企業內部自行建立的部門群組

#### 5. 查詢特定群組的成員
針對 `Sales Department` 群組，查詢它有哪些成員
```
PS C:\Users\stephanie> net group "Sales Department" /domain
The request will be processed at a domain controller for domain corp.com.

Group name     Sales Department
Comment

Members

-------------------------------------------------------------------------------
pete                     stephanie
The command completed successfully.
```
> stephanie 及 pete 都是 Sales Department 群組

### Enumerating Active Directory using PowerShell and .NET Classes
如何利用 PowerShell 和 .NET 類別來枚舉 Active Directory（AD），並透過 LDAP 與 AD 互動

#### LDAP
>[!Note]
>LDAP（Lightweight Directory Access Protocol） 是一種用來查詢和修改目錄服務（如 Active Directory）的通訊協定。\
當使用者搜尋印表機、查詢使用者或群組資訊時，AD 會使用 LDAP 來處理查詢。\
LDAP 不僅限於 Active Directory，其他目錄服務（如 OpenLDAP）也使用 LDAP。
- LDAP 查詢路徑格式
需要特定的 [LDAP ADsPath](https://learn.microsoft.com/en-us/windows/win32/adsi/ldap-adspath?redirectedfrom=MSDN)格式 才能與 AD 溝通
```
LDAP://HostName[:PortNumber][/DistinguishedName]
```
> - `HostName`：電腦名稱、IP 地址或網域名稱。通常尋找擁有最新資訊的 DC ([Primary Domain Controller](https://learn.microsoft.com/en-gb/troubleshoot/windows-server/active-directory/fsmo-roles) (PDC))
> - `PortNumber`（可選）：預設情況下，LDAP 使用 389（非加密） 或 636（SSL/TLS 加密）。
> - `DistinguishedName`（DN）：唯一標識 AD 內 Objects 的名稱，例：`CN=Stephanie,CN=Users,DC=corp,DC=com`


#### 1. 取得 Primary Domain Controller（PDC）
>[!Tip]
>**為什麼需要 PDC？**\
AD 通常有多個 DCs，但其中只有一個 PDC 持有最新的網域資訊。\
為了確保枚舉結果最準確，我們應該查詢 PDC，而不是隨機的 DC。

使用 .NET 類別 `System.DirectoryServices.ActiveDirectory.Domain` 來獲取當前網域資訊：
```
PS C:\Users\stephanie> [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()


Forest                  : corp.com
DomainControllers       : {DC1.corp.com}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner            : DC1.corp.com
RidRoleOwner            : DC1.corp.com
InfrastructureRoleOwner : DC1.corp.com
Name                    : corp.com
```
> PdcRoleOwner 欄位顯示 DC1.corp.com，表示 DC1 是 PDC

#### 2. 取得網域的 DN（Distinguished Name）
在 AD 中，每個 Objects 都有一個唯一識別名稱（DN，Distinguished Name）\
使用 ADSI（[Active Directory Services Interface](https://learn.microsoft.com/en-us/windows/win32/adsi/active-directory-service-interfaces-adsi)） 來取得網域的 DN
```
PS C:\Users\stephanie> ([adsi]'').distinguishedName
DC=corp,DC=com
```
>  透過 LDAP 查詢所需的 Distinguished Name

#### 3. 組合完整的 LDAP 查詢路徑
現在我們已經獲取：
- PDC 名稱（DC1.corp.com）
- 網域的 DN（DC=corp,DC=com）

將這些資訊組合成 LDAP 查詢路徑：
```
PS C:\Users\stephanie> $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
PS C:\Users\stephanie> $DN = ([adsi]'').distinguishedName
PS C:\Users\stephanie> $LDAP = "LDAP://$PDC/$DN"
PS C:\Users\stephanie> $LDAP
LDAP://DC1.corp.com/DC=corp,DC=com
```

#### 4. 完整 PowerShell Enumeration 腳本
```
# 取得 PDC 名稱
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name

# 取得 DN（Distinguished Name）
$DN = ([adsi]'').distinguishedName 

# 組合 LDAP 路徑
$LDAP = "LDAP://$PDC/$DN"

# 顯示 LDAP 路徑
$LDAP
```
自動偵測 PDC 並生成正確的 LDAP 查詢路徑，使用 notepad 編輯寫成 `enumeration.ps1`
```
PS C:\Users\stephanie> powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\stephanie> notepad .\enumeration.ps1

$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName
$LDAP = "LDAP://$PDC/$DN"
$LDAP

PS C:\Users\stephanie> .\enumeration.ps1
LDAP://DC1.corp.com/DC=corp,DC=com
```

### Adding Search Functionality to our Script
已經建置了所需的 LDAP 路徑，現在可以建立搜尋功能
#### 1. 使用 .NET 類別來進行 AD 搜尋
將使用 System.DirectoryServices 命名空間中的兩個重要類別：
- [DirectoryEntry](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.directoryentry?view=dotnet-plat-ext-6.0)：
代表 AD 內的一個物件（如 CN=Users,DC=corp,DC=com）。
我們將用它來指定 搜尋的起點（[SearchRoot](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.directorysearcher.searchroot?view=dotnet-plat-ext-6.0) property）。
- [DirectorySearcher](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.directorysearcher?view=dotnet-plat-ext-6.0)：
用來 執行 LDAP 查詢。
SearchRoot 屬性會指向 DirectoryEntry，告訴它 從哪裡開始搜尋。

>[!Note]
>- The DirectoryEntry class encapsulates an object in the AD service hierarchy (LDAP path)
>- The DirectorySearcher class performs queries against AD using LDAP. When creating an instance of DirectorySearcher, we must specify the AD service we want to query in the form of the SearchRoot property.
>- The DirectorySearcher documentation lists `FindAll()`, which returns a collection of all the entries found in AD.

```
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

# 建立 DirectoryEntry 來指定搜尋的起點
$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

# 建立 DirectorySearcher 來執行 LDAP 查詢
$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.FindAll()
```
#### 2. 在腳本中實作基本搜尋
編輯腳本:
```
PS C:\Users\stephanie> powershell -ep bypass    
PS C:\Users\stephanie> notepad .\enumeration.ps1
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"
$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.FindAll()

PS C:\Users\stephanie> .\enumeration.ps1

Path
----
LDAP://DC1.corp.com/DC=corp,DC=com
LDAP://DC1.corp.com/CN=Users,DC=corp,DC=com
LDAP://DC1.corp.com/CN=Computers,DC=corp,DC=com
LDAP://DC1.corp.com/OU=Domain Controllers,DC=corp,DC=com
LDAP://DC1.corp.com/CN=System,DC=corp,DC=com
LDAP://DC1.corp.com/CN=LostAndFound,DC=corp,DC=com
LDAP://DC1.corp.com/CN=Infrastructure,DC=corp,DC=com
LDAP://DC1.corp.com/CN=ForeignSecurityPrincipals,DC=corp,DC=com
LDAP://DC1.corp.com/CN=Program Data,DC=corp,DC=com
...

```
> 執行成功，但沒有過濾，結果過於龐大。
#### 3. 過濾搜尋結果
可以使用 LDAP 過濾條件\
只想查詢 所有使用者帳戶，可以使用 samAccountType=805306368：
```
$dirsearcher.filter="samAccountType=805306368"
```
編輯腳本並執行:
```
PS C:\Users\stephanie> notepad .\enumeration.ps1
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=805306368"
$dirsearcher.FindAll()

PS C:\Users\stephanie> .\enumeration.ps1

Path                                                         Properties
----                                                         ----------
LDAP://DC1.corp.com/CN=Administrator,CN=Users,DC=corp,DC=com {logoncount, codepage, objectcategory, description...}
LDAP://DC1.corp.com/CN=Guest,CN=Users,DC=corp,DC=com         {logoncount, codepage, objectcategory, description...}
LDAP://DC1.corp.com/CN=krbtgt,CN=Users,DC=corp,DC=com        {logoncount, codepage, objectcategory, description...}
LDAP://DC1.corp.com/CN=dave,CN=Users,DC=corp,DC=com          {logoncount, codepage, objectcategory, dscorepropagatio...
LDAP://DC1.corp.com/CN=stephanie,CN=Users,DC=corp,DC=com     {logoncount, codepage, objectcategory, dscorepropagatio...
LDAP://DC1.corp.com/CN=jeff,CN=Users,DC=corp,DC=com          {logoncount, codepage, objectcategory, usnchanged...}
LDAP://DC1.corp.com/CN=jeffadmin,CN=Users,DC=corp,DC=com     {logoncount, codepage, objectcategory, dscorepropagatio...
LDAP://DC1.corp.com/CN=iis_service,CN=Users,DC=corp,DC=com   {logoncount, codepage, objectcategory, dscorepropagatio...
LDAP://DC1.corp.com/CN=pete,CN=Users,DC=corp,DC=com          {logoncount, codepage, objectcategory, dscorepropagatio...
LDAP://DC1.corp.com/CN=jen,CN=Users,DC=corp,DC=com           {logoncount, codepage, objectcategory, dscorepropagatio...
```
> 篩選出 AD 內所有的使用者帳號

我們的腳本列舉了比 net.exe 更多的群組，包括 Print Operators, IIS_IUSRS 等。這是因為我們列舉了所有 AD 對象，包括 Domain Local groups（而不僅僅是 global groups）。

#### 4. 查詢特定帳號 attribute
目前查詢中只顯示物件的 LDAP 路徑，若要列出每個使用者的詳細屬性。\
使用兩層迴圈來列出每個使用者的所有屬性：
```
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }

    Write-Host "-------------------------------"
}
```
編輯腳本並執行:
```
PS C:\Users\stephanie> type .\enumeration.ps1
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=805306368"
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }

    Write-Host "-------------------------------"
}

PS C:\Users\stephanie> .\enumeration.ps1
...
logoncount                     {173}
objectcategory                 {CN=Person,CN=Schema,CN=Configuration,DC=corp,DC=com}
name                           {jeffadmin}
pwdlastset                     {133066348088894042}
objectclass                    {top, person, organizationalPerson, user}
samaccounttype                 {805306368}
memberof                       {CN=Domain Admins,CN=Users,DC=corp,DC=com}
...
-------------------------------

```
> 可以查詢每個帳號的登入次數、密碼設定時間、所屬群組等關鍵資訊
> 只列出 `jeffadmin` 資訊

>[!Caution]
> 若遇到以下 Error，PowerShell 執行原則（Execution Policy） 禁止運行腳本，可以透過調整設定: `Set-ExecutionPolicy Unrestricted -Scope CurrentUser`
> 
>```
>PS C:\Users\stephanie> .\enumeration.ps1
>.\enumeration.ps1 : File >C:\Users\stephanie\enumeration.ps1 cannot be loaded >because running scripts is disabled on
>this system. For more information, see >about_Execution_Policies at >https:/go.microsoft.com/fwlink/?LinkID=135170.
>At line:1 char:1
>+ .\enumeration.ps1
>+ ~~~~~~~~~~~~~~~~~
>    + CategoryInfo          : SecurityError: (:) [], >PSSecurityException
>    + FullyQualifiedErrorId : UnauthorizedAccess
>PS C:\Users\stephanie> Set-ExecutionPolicy Unrestricted ->Scope CurrentUser
>```

#### 5. 查詢特定使用者的群組
若只想 查看某個特定帳號的群組，可以修改過濾條件：
```
$dirsearcher.filter="name=jeffadmin"

$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop.memberof
    }

    Write-Host "-------------------------------"
}

```
執行結果：
```
PS C:\Users\stephanie> type .\enumeration.ps1
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="name=jeffadmin"
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop.memberof
    }

    Write-Host "-------------------------------"
}
PS C:\Users\stephanie> .\enumeration.ps1
CN=Domain Admins,CN=Users,DC=corp,DC=com
CN=Administrators,CN=Builtin,DC=corp,DC=com
-------------------------------
```
> 證明 jeffadmin 是 Domain Admins 成員，擁有最高權限！

#### 6. 讓腳本更靈活
避免手動修改搜尋條件，可以將它轉換為函數（Function），並允許 命令列參數：
```
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DN = ([adsi]'').distinguishedName
    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DN")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)
    return $DirectorySearcher.FindAll()
}
```
先執行 enumeration.ps1，就可以直接使用 LDAPSearch\
`LDAPSearch -LDAPQuery "(samAccountType=805306368)"`
```
PS C:\Users\stephanie> type .\enumeration.ps1
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DN = ([adsi]'').distinguishedName
    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DN")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)
    return $DirectorySearcher.FindAll()
}
PS C:\Users\stephanie> . .\enumeration.ps1
PS C:\Users\stephanie> LDAPSearch -LDAPQuery "(samAccountType=805306368)"

Path                                                         Properties
----                                                         ----------
LDAP://DC1.corp.com/CN=Administrator,CN=Users,DC=corp,DC=com {logoncount, codepage, objectcategory, description...}
LDAP://DC1.corp.com/CN=Guest,CN=Users,DC=corp,DC=com         {logoncount, codepage, objectcategory, description...}
LDAP://DC1.corp.com/CN=krbtgt,CN=Users,DC=corp,DC=com        {logoncount, codepage, objectcategory, description...}
LDAP://DC1.corp.com/CN=dave,CN=Users,DC=corp,DC=com          {logoncount, codepage, objectcategory, dscorepropagatio...
LDAP://DC1.corp.com/CN=stephanie,CN=Users,DC=corp,DC=com     {logoncount, codepage, objectcategory, dscorepropagatio...
LDAP://DC1.corp.com/CN=jeff,CN=Users,DC=corp,DC=com          {logoncount, codepage, objectcategory, usnchanged...}
LDAP://DC1.corp.com/CN=jeffadmin,CN=Users,DC=corp,DC=com     {logoncount, codepage, objectcategory, dscorepropagatio...
LDAP://DC1.corp.com/CN=iis_service,CN=Users,DC=corp,DC=com   {logoncount, codepage, objectcategory, dscorepropagatio...
LDAP://DC1.corp.com/CN=pete,CN=Users,DC=corp,DC=com          {logoncount, codepage, objectcategory, dscorepropagatio...
LDAP://DC1.corp.com/CN=jen,CN=Users,DC=corp,DC=com           {logoncount, codepage, objectcategory, dscorepropagatio...

```
直接查詢 AD
```
LDAPSearch -LDAPQuery "(samAccountType=805306368)"  # 查詢所有使用者
LDAPSearch -LDAPQuery "(objectclass=group)"  # 查詢所有群組
LDAPSearch -LDAPQuery "(name=jeffadmin)"  # 查詢 jeffadmin
```
#### 7. foreach 每個 group 與 member
為了列舉網域中可用的每個群組並顯示使用者成員，我們可以將輸出匯入到一個新變數中，並使用 foreach 循環列印群組的每個屬性。
```
PS C:\Users\stephanie\Desktop> foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {
>> $group.properties | select {$_.cn}, {$_.member}
>> }
...
Sales Department              {CN=Development Department,DC=corp,DC=com, CN=pete,CN=Users,DC=corp,DC=com, CN=stephanie,CN=Users,DC=corp,DC=com}
Management Department         CN=jen,CN=Users,DC=corp,DC=com
Development Department        {CN=Management Department,DC=corp,DC=com, CN=pete,CN=Users,DC=corp,DC=com, CN=dave,CN=Users,DC=corp,DC=com}
...
```
上述在 Sales Department group 只看到 `pete` 與 `stephanie`
```
PS C:\Users\stephanie> $sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"
PS C:\Users\stephanie> $sales.properties.member
CN=Development Department,DC=corp,DC=com
CN=pete,CN=Users,DC=corp,DC=com
CN=stephanie,CN=Users,DC=corp,DC=com
```
> 發現 `Development Department` 也是 Sales Department group 其中一員

### AD Enumeration with PowerView
介紹了一款強大的 Active Directory 枚舉工具 — [PowerView](https://powersploit.readthedocs.io/en/latest/Recon/)，它是一個 PowerShell 腳本，提供很多內建函數

#### 1. 如何載入 PowerView？
PowerView 已安裝在 `C:\Tools` 資料夾中
```
PS C:\Tools> . .\PowerView.ps1
```
或
```
PS C:\Tools> Import-Module .\PowerView.ps1
``` 
#### 2. 取得基本網域資訊
##### 2.1  查詢網域資訊 (Get-NetDomain)
```
PS C:\Tools> Get-NetDomain


Forest                  : corp.com
DomainControllers       : {DC1.corp.com}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner            : DC1.corp.com
RidRoleOwner            : DC1.corp.com
InfrastructureRoleOwner : DC1.corp.com
Name                    : corp.com
```
##### 2.2 查詢所有網域使用者 (Get-NetUser)
```
PS C:\Tools> Get-NetUser

logoncount             : 565
badpasswordtime        : 3/1/2023 3:18:15 AM
description            : Built-in account for administering the computer/domain
distinguishedname      : CN=Administrator,CN=Users,DC=corp,DC=com
objectclass            : {top, person, organizationalPerson, user}
lastlogontimestamp     : 3/8/2025 9:00:20 AM
name                   : Administrator
objectsid              : S-1-5-21-1987370270-658905905-1781884369-500
samaccountname         : Administrator
```
> 包含：\
帳號名稱（samaccountname）\
是否是管理員（admincount）\
所屬群組（memberof）\
上次修改密碼時間（pwdlastset）\
上次登入時間（lastlogon）
##### 2.3 查詢使用者資訊 (Get-NetUser | select ..)
- 只顯示使用者名稱 (`Get-NetUser | select cn`)
```
PS C:\Tools> Get-NetUser | select cn

cn
--
Administrator
Guest
krbtgt
dave
stephanie
jeff
jeffadmin
iis_service
pete
jen
```
- 查詢使用者修改密碼與登入資訊 (`Get-NetUser | select cn,pwdlastset,lastlogon`)
```
PS C:\Tools> Get-NetUser | select cn,pwdlastset,lastlogon

cn            pwdlastset            lastlogon
--            ----------            ---------
Administrator 8/16/2022 5:27:22 PM  3/8/2025 9:04:00 AM
Guest         12/31/1600 4:00:00 PM 12/31/1600 4:00:00 PM
krbtgt        9/2/2022 4:10:48 PM   12/31/1600 4:00:00 PM
dave          9/7/2022 9:54:57 AM   3/8/2025 9:12:35 AM
stephanie     9/2/2022 4:23:38 PM   3/8/2025 9:01:06 AM
jeff          9/2/2022 4:27:20 PM   12/18/2023 11:55:16 PM
jeffadmin     9/2/2022 4:26:48 PM   1/8/2024 3:47:01 AM
iis_service   9/7/2022 5:38:43 AM   3/1/2023 3:40:02 AM
pete          9/6/2022 12:41:54 PM  2/1/2023 2:42:42 AM
jen           9/6/2022 12:43:01 PM  1/8/2024 1:26:03 AM
```
##### 2.4 查詢所有網域群組 (Get-NetGroup)
```
PS C:\Tools> Get-NetGroup | select cn

cn
--
...
Key Admins
Enterprise Key Admins
DnsAdmins
DnsUpdateProxy
Sales Department
Management Department
Development Department
Debug
```
##### 2.5 查詢特定群組的成員 (Get-NetGroup .. | select member)
查詢 Sales Department 的成員：
```
PS C:\Tools> Get-NetGroup "Sales Department" | select member

member
------
{CN=Development Department,DC=corp,DC=com, CN=pete,CN=Users,DC=corp,DC=com, CN=stephanie,CN=Users,DC=corp,DC=com}

```
> 再次證明 Development Department 也是 Sales Department 的成員

>[!Important]
>`PowerView` vs `net.exe`\
>![image](https://hackmd.io/_uploads/r1Y83xqoye.png)


## Manual Enumeration - Expanding our Repertoire
深入 Active Directory（AD）環境的手動枚舉，透過各種技術收集更多關鍵資訊，並建立一個完整的網域地圖
### Enumerating Operating Systems
使用 PowerView 查詢 Active Directory（AD）內的所有電腦資訊，並確認作業系統類型
#### 1. 使用 PowerView 查詢網域內的所有電腦 (Get-NetComputer)
```
PS C:\Tools> Set-ExecutionPolicy Unrestricted -Scope CurrentUser
PS C:\Tools> . .\PowerView.ps1
PS C:\Tools> Get-NetComputer

pwdlastset                    : 10/2/2022 10:19:40 PM
logoncount                    : 319
msds-generationid             : {89, 27, 90, 188...}
serverreferencebl             : CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=com
badpasswordtime               : 12/31/1600 4:00:00 PM
distinguishedname             : CN=DC1,OU=Domain Controllers,DC=corp,DC=com
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 10/13/2022 11:37:06 AM
name                          : DC1
objectsid                     : S-1-5-21-1987370270-658905905-1781884369-1000
samaccountname                : DC1$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
whenchanged                   : 10/13/2022 6:37:06 PM
accountexpires                : NEVER
countrycode                   : 0
operatingsystem               : Windows Server 2022 Standard
...
dnshostname                   : DC1.corp.com
...
```
#### 2. 過濾並清理輸出資訊 (Get-NetComputer | select operatingsystem,dnshostname)
```
PS C:\Tools> Get-NetComputer | select name,operatingsystem,dnshostname

name     operatingsystem              dnshostname
----     ---------------              -----------
DC1      Windows Server 2022 Standard DC1.corp.com
web04    Windows Server 2022 Standard web04.corp.com
files04  Windows Server 2022 Standard FILES04.corp.com
client74 Windows 11 Enterprise        client74.corp.com
client75 Windows 11 Enterprise        client75.corp.com
client76 Windows 10 Pro               CLIENT76.corp.com
```
>[!Note]
> Question:\
> Continue enumerating the operating systems. What is the exact operating system version for FILES04? Make sure to provide both the major and minor version number in the answer.\
> `Get-NetComputer -name files04 | select name,operatingsystem,operatingsystemversion`

### Getting an Overview - Permissions and Logged on Users
Active Directory（AD）內部的關係與潛在攻擊路徑，特別關注 使用者、電腦與權限之間的關聯性。\
找出可能的 Attack Vectors:
- 哪些使用者有較高權限？
- 哪些電腦上有可利用的已登入帳號？
- 找到一條路徑來提權？

>[!Tip]
>**為什麼權限與已登入使用者很重要？**
>- (1) 取得其他使用者的憑證
    - 當使用者登入某台電腦 時，他們的 Credentials 可能會被快取在記憶體。
    - 若竊取這些憑證，我就能冒充這些使用者，甚至進一步提權
>- (2) 建立「持久性」存取
    - 若只依賴單一帳號，一旦密碼被重設或帳號被鎖定，就會失去存取權限。
    - 應該尋找 其他擁有相同或更高權限的帳號，即使原始帳號被禁用，仍能繼續存取 AD 環境。
>- (3) 鏈式滲透（Chained Compromise）
    - 不一定要直接獲取 Domain Admins 權限。
    - 可能存在 擁有更高權限的其他帳號（例如 Service Accounts），可以利用這些帳號來存取重要系統，如：檔案伺服器, 資料庫, Web 伺服器

PowerView 的 `Find-LocalAdminAccess` 作用是 掃描網域內的所有電腦，判斷我們目前的使用者是否擁有某些電腦的本機管理員（Local Administrator）權限\
`Find-LocalAdminAccess` 依賴在 [OpenServiceW function](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openservicew) 中，Windows 提供 OpenServiceW API 來讓應用程式或管理員管理系統上的服務。例如：啟動或停止 Windows 服務、修改服務的設定、刪除或安裝服務，不需要直接嘗試登入。

SCM（Service Control Manager）是 Windows 內建系統級的資料庫，存放了所有 Windows 服務與驅動程式的資訊，負責 啟動、停止、管理服務，所有 Windows 電腦都有 SCM，且存取 SCM 需要足夠的權限。\
PowerView 會嘗試存取 SCM，並請求 `SC_MANAGER_ALL_ACCESS`，若存取成功，代表我們擁有該機器的 Local Admin 權限

#### 1. 找出我們當前帳戶的管理權限 (Find-LocalAdminAccess)
使用 PowerView 的 `Find-LocalAdminAccess` ，掃描我們目前帳戶 是否擁有其他機器的管理權限
```
PS C:\Tools> . .\PowerView.ps1
PS C:\Tools> Find-LocalAdminAccess
client74.corp.com
```
> 表示目前的帳戶 stephanie 在 client74.corp.com 上擁有本機管理員Local Admin 權限。

#### 2. 找出目前已登入的使用者 (Get-NetSession -ComputerName ...)
目前有哪些使用者已登入哪些電腦，使用 PowerView 的 `Get-NetSession` 指令
```
PS C:\Tools> Get-NetSession -ComputerName files04
PS C:\Tools> Get-NetSession -ComputerName web04
```
> 沒有結果，可能代表：
> 1. 沒有使用者登入
> 2. 帳戶沒有權限查詢

`-Verbose` 檢查錯誤
```
PS C:\Tools> Get-NetSession -ComputerName files04 -Verbose
VERBOSE: [Get-NetSession] Error: Access is denied
PS C:\Tools> Get-NetSession -ComputerName web04 -Verbose
VERBOSE: [Get-NetSession] Error: Access is denied
```
> 權限不足

##### 2.1 嘗試在擁有管理權限的機器上查詢登入使用者
上述得知 stephanie 在 client74.corp.com 是 local admin
```
PS C:\Tools> Get-NetSession -ComputerName client74


CName        : \\192.168.145.75
UserName     : stephanie
Time         : 0
IdleTime     : 0
ComputerName : client74
```
雖然這看起來像是 client74 的資訊，但實際上這個 IP 是 client75 的 IP，表示輸出結果可能有誤。\
我們需要改用其他工具來查詢已登入使用者。
>[!Tip]
>[NetSessionEnum](https://learn.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netsessionenum) API 的問題\
>PowerView 的 Get-NetSession 指令是基於 Windows 的 NetSessionEnum API，而 NetSessionEnum 有 不同的查詢層級（Query Levels）\
>![image](https://hackmd.io/_uploads/rkT_OWqiJg.png)\
>PowerView 預設是使用 NetSessionEnum Level 10，即使 NetSessionEnum Level 10 不需要管理員權限，但它依賴 Windows 註冊表（Registry）內的存取權限，這可能影響查詢結果。

以透過 PowerShell 來檢查 SrvsvcSessionInfo 註冊表的存取權限：
```
PS C:\Tools> Get-Acl -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl


Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultS
         ecurity\
Owner  : NT AUTHORITY\SYSTEM
Group  : NT AUTHORITY\SYSTEM
Access : BUILTIN\Users Allow  ReadKey
         BUILTIN\Administrators Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  FullControl
         CREATOR OWNER Allow  FullControl
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow
         ReadKey
Audit  :
Sddl   : O:SYG:SYD:AI(A;CIID;KR;;;BU)(A;CIID;KA;;;BA)(A;CIID;KA;;;SY)(A;CIIOID;KA;;;CO)(A;CIID;KR;;;AC)(A;CIID;KR;;;S-1
         -15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)

```
> `BUILTIN\Users` 只有 ReadKey 權限。`Get-NetSession` 依賴 NetSessionEnum API 來查詢已登入使用者。在 `Windows 10 版本 1709` 之後，Microsoft 加強了 NetSessionEnum 的權限，並將一般使用者的存取限制為 `ReadKey`，無法讀取完整的 session 資訊。只有 Administrators 或 SYSTEM 帳戶擁有完整控制權限，所以 普通使用者（如 stephanie）無法成功執行 Get-NetSession。

可以使用 `Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion`:\
環境運作在 Windows 10 Pro

#### 3. 使用 PsLoggedOn 來查詢已登入使用者
可以使用其他工具，例如 [SysInternals Suite](https://learn.microsoft.com/en-us/sysinternals/) 中的[PsLoggedOn](https://learn.microsoft.com/en-us/sysinternals/downloads/psloggedon) 應用程式\

由於 NetSessionEnum 受限，我們使用 SysInternals 的 PsLoggedOn 工具
>[!Note]
>PsLoggedOn 依賴 Remote Registry service
```
PS C:\Tools> cd .\PSTools\
PS C:\Tools\PSTools> .\PsLoggedon.exe \\files04

PsLoggedon v1.35 - See who's logged on
Copyright (C) 2000-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

Users logged on locally:
     <unknown time>             CORP\jeff
Unable to query resource logons
```
> 表示 jeff 這個使用者目前已登入 FILES04

```
PS C:\Tools\PSTools> .\PsLoggedon.exe \\web04

PsLoggedon v1.35 - See who's logged on
Copyright (C) 2000-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

No one is logged on locally.
Unable to query resource logons
```
> WEB04 目前沒有使用者登入\
> 也有可能是無法存取該資訊

#### 4. 查詢 client74 的已登入使用者
```
PS C:\Tools\PSTools> .\PsLoggedon.exe \\client74

PsLoggedon v1.35 - See who's logged on
Copyright (C) 2000-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

Users logged on locally:
     <unknown time>             CORP\jeffadmin

Users logged on via resource shares:
     3/8/2025 10:26:57 AM       CORP\stephanie
```
> 1. ⚠️ jeffadmin 目前已登入 client74， jeffadmin 可能是 Domain Admin！
> 2. stephanie 透過共享資源登入 client74，`PsLoggedOn 也使用 NetSessionEnum API，在這種情況下需要登入才能運作`，因此與我們之前的 PowerView 測試結果一致。
>> 💡 如果我們擁有 client74 的管理權限，我們可能可以竊取 jeffadmin 的憑證

### Enumeration Through Service Principal Names
>[!Note]
>[Service Account](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/service-accounts-on-premises)（服務帳號）:
>- 當應用程式在 Windows 上執行時，它需要 使用者帳戶來執行。
>- 一般應用程式 由 使用者帳號 執行（如 user1 開啟 Word）。
>- 系統服務（Services） 由 服務帳號（Service Account） 執行，例如：[LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account), [LocalService](https://learn.microsoft.com/en-us/windows/win32/services/localservice-account), [NetworkService](https://learn.microsoft.com/en-us/windows/win32/services/networkservice-account)
>
>但當 企業應用程式（如 SQL Server、Exchange、IIS）需要更高權限與網域整合時，通常會 使用網域帳號作為服務帳號。

>[!Note]
>**Service Principal Name（SPN）**
>當Exchange、MS SQL 或Internet 資訊服務(IIS)等應用程式 整合到 AD 中時，SPN 是 Active Directory（AD）中用來標識伺服器與服務的 identifier。\
SPN 的作用：
允許 Kerberos 驗證，正確找到對應的服務\
綁定特定帳號與服務，確保服務能夠被授權存取網域資源

如何 透過 SPN 枚舉網域內執行的應用程式與伺服器資訊

#### 1. 如何查詢 SPN？
在 AD Enumeration 時，SPN 可以幫助我們找出網域內運行的服務，甚至進一步發動 Kerberoasting 攻擊。
##### (1) 使用 `setspn.exe` 查詢 SPN
Windows 內建 setspn.exe 工具可以用來查詢 SPN\
利用先前 iterate domain users: `iis_service`
```
PS C:\Users\stephanie> setspn -L iis_service
Registered ServicePrincipalNames for CN=iis_service,CN=Users,DC=corp,DC=com:
        HTTP/web04.corp.com
        HTTP/web04
        HTTP/web04.corp.com:80
```
> `is_service` 帳戶關聯了 `HTTP/web04.corp.com`，代表是 Web 伺服器
##### (2) 使用 PowerView 查詢 SPN
使用 PowerView 來查詢 所有擁有 SPN 的帳號
```
PS C:\Tools> Get-NetUser -SPN | select samaccountname,serviceprincipalname

samaccountname serviceprincipalname
-------------- --------------------
krbtgt         kadmin/changepw
iis_service    {HTTP/web04.corp.com, HTTP/web04, HTTP/web04.corp.com:80}
```
> krbtgt 是 Kerberos 票據授權（TGT）帳號（後續章節探討）。\
iis_service 這個帳號 與 HTTP/web04.corp.com 綁定，說明這是 Web 伺服器。

#### 2. 解析 domain  IP
```
PS C:\Users\stephanie> nslookup web04.corp.com
DNS request timed out.
    timeout was 2 seconds.
Server:  UnKnown
Address:  192.168.161.70

Name:    web04.corp.com
Address:  192.168.161.72
```
> web04.corp.com 對應的內部 IP 是 192.168.161.72

透過瀏覽器瀏覽 192.168.161.72\
![image](https://hackmd.io/_uploads/BJFYf35s1g.png)
>需要密碼登入

### Enumerating Object Permissions

