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
>**避免 Kerberos 雙重跳躍問題（[Kerberos Double-Hop](https://posts.slayerlabs.com/double-hop/) Issue）**:
建議使用 RDP，而非 PowerShell Remoting（WinRM），因為透過 WinRM 可能會導致 無法執行 AD 枚舉工具。
Kerberos 雙重跳躍（Double-Hop）問題 會影響某些遠端命令的執行權限，詳細內容可參考 PEN-300 課程。
![image](https://hackmd.io/_uploads/r1botcFiye.png)

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
> [default Group](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)
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
PS C:\Users\stephanie> powershell -ep bypass.\en    
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

#### 5. 查詢特定使用者的群組
