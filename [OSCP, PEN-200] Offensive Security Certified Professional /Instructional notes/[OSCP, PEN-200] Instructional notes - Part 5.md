---
title: '[OSCP, PEN-200] Instructional notes - Part 5'
disqus: hackmd
---

[OSCP, PEN-200] Instructional notes - Part 5
===

# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 1"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/README.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 2"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%202.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 3"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%203.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 4"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%204.md)

>[!Caution]
> 接續 [[OSCP, PEN-200] Instructional notes - Part 4](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%204.md) 內容

# Port Redirection and SSH Tunneling
## … SSH Tunneling ([Instructional notes - Part 4](https://hackmd.io/@CHW/rkjNgyi51x))
## Port Forwarding with Windows Tools
上述接說明 Linux-based 的 tunnel tools。 Windows 也有幾種 port forward 與 tunnel 的方法
### ssh.exe
Windows 內建 SSH: 自 2018 年 4 月 ([1803 版本](https://devblogs.microsoft.com/commandline/windows10v1803/#openssh-based-client-and-server)) 起內建 OpenSSH client，可以在 `%systemdrive%\Windows\System32\OpenSSH` 找到：
- ssh.exe
- scp.exe
- sftp.exe

這個 SSH client 可以用來連接任何支援 SSH 的伺服器（不限於 Windows SSH Server）

[環境範例]
- MULTISERVER03（Windows 機器） 只開放了 RDP 3389 port
- 可以 RDP 進入 MULTISERVER03，但無法直接綁定其他端口到外網。

解決方案：
- 在 MULTISERVER03 上使用 `ssh.exe`，建立一個 [Remote Dynamic Port Forwarding](https://hackmd.io/@CHW/rkjNgyi51x#SSH-Remote-Dynamic-Port-Forwarding)，讓流量通過 SSH Tunnel 回到 Kali 
- 這樣可以利用 SSH Kali 存取 PGDATABASE01（PostgreSQL 資料庫）

![image](https://hackmd.io/_uploads/SkLGpmNs1l.png)
#### 1. start the Kali SSH server
```
┌──(chw㉿CHW)-[~]
└─$ sudo systemctl start ssh
[sudo] password for chw:
```

可以用 `ss -ntplu` 查看啟用狀況

#### 2. 使用 [xfreerdp](https://www.freerdp.com/) 連接到 MULTISERVER03
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:192.168.131.64
[10:55:26:199] [372805:372806] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[10:55:26:199] [372805:372806] [WARN][com.freerdp.crypto] - CN = MULTISERVER03
...
```
![image](https://hackmd.io/_uploads/HyHJQoNoJe.png)

#### 3. 檢查 Windows SSH
打開 cmd.exe `where ssh` 確認是否有 SSH
```
C:\Users\rdp_admin>where ssh
C:\Windows\System32\OpenSSH\ssh.exe

C:\Users\rdp_admin>
```
檢查 SSH version
```
C:\Users\rdp_admin>ssh.exe -V
OpenSSH_for_Windows_8.1p1, LibreSSL 3.0.2
```
> OpenSSH version 高於 7.6，代表可以使用 remote dynamic port forwarding

#### 4. 創建 remote dynamic port forward 到 Kali
Windows 創建 remote dynamic port forward 到 Kali port 9998
```
C:\Users\rdp_admin>ssh -N -R 9998 chw@192.168.45.213
The authenticity of host '192.168.45.213 (192.168.45.213)' can't be established.
ECDSA key fingerprint is SHA256:Atuf88ckgvdjD92PblnxCBvzAiN1jtxNUv6woYcEmxg.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.45.213' (ECDSA) to the list of known hosts.
chw@192.168.45.213's password:
|
```

確認連線狀況
```
┌──(chw㉿CHW)-[~]
└─$ ss -ntplu
Netid       State         Recv-Q        Send-Q               Local Address:Port                Peer Address:Port       Process       
...
tcp         LISTEN        0             128                      127.0.0.1:9998                     0.0.0.0:*                        
tcp         LISTEN        0             128                        0.0.0.0:22                       0.0.0.0:*                        
tcp         LISTEN        0             128                          [::1]:9998                        [::]:*                        
tcp         LISTEN        0             128                           [::]:22                          [::]:*
```
#### 5. 配置 Proxychains
Kali 設定 SOCKS proxy
```
┌──(chw㉿CHW)-[~]
└─$ tail /etc/proxychains4.conf   
#         * raw: The traffic is simply forwarded to the proxy without modification.
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4         127.0.0.1 9050
#socks5 192.168.147.63 9999
socks5 127.0.0.1 9998
```
#### 6. 使用 Proxychains 透過 SSH 隧道連接 PostgreSQL
```
┌──(chw㉿CHW)-[~]
└─$ proxychains psql -h 10.4.131.215 -U postgres  

[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/aarch64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:9998  ...  10.4.131.215:5432  ...  OK
Password for user postgres: 
[proxychains] Strict chain  ...  127.0.0.1:9998  ...  10.4.131.215:5432  ...  OK
psql (16.3 (Debian 16.3-1+b1), server 12.12 (Ubuntu 12.12-0ubuntu0.20.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off)
Type "help" for help.

postgres=# \l
                                                        List of databases
    Name    |  Owner   | Encoding | Locale Provider |   Collate   |    Ctype    | ICU Locale | ICU Rules |   Access privileges   
------------+----------+----------+-----------------+-------------+-------------+------------+-----------+-----------------------
 confluence | postgres | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |            |           | 
 postgres   | postgres | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |            |           | 
 template0  | postgres | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |            |           | =c/postgres          +
            |          |          |                 |             |             |            |           | postgres=CTc/postgres
 template1  | postgres | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |            |           | =c/postgres          +
            |          |          |                 |             |             |            |           | postgres=CTc/postgres
(4 rows)
```
> 成功登入 PostgreSQL database

>[!Warning]
> Question: Log in to MULTISERVER03 with the rdp_admin credentials we found in the Confluence database (rdp_admin:P@ssw0rd!). Enumerate which port forwarding techniques are available, then use the Windows OpenSSH client to create a port forward that allows you to reach port 4141 on PGDATABASE01 from your Kali machine.\
> [file: [ssh_exe_exercise_client](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-200/extras/prat2/d5a2ba960124f3cf5089951b99445af5-ssh_exe_exercise_client_aarch64)]
> 解法：
> 1. 將 4141 port Tunnel 到 Kali 4141 port: `ssh -N -R 4141:10.4.131.215:4141 chw@192.168.45.213` 
> 2. `ss -ntplu` 確認連線狀況
> 3. Kali 上 `wget {file}`
> 4. `chmod +x {file}`
> 5. `./{file} -h 127.0.0.1 -p 4141`
> ![image](https://hackmd.io/_uploads/SJLY6jViJg.png)
> 6. `./{file} -i 127.0.0.1 -p 4141`: GET FLAG

### Plink
Administrators 會避免 OpenSSH 留在 Windows machine 上，因此我們不能保證能發現 OpenSSH Client\
在 OpenSSH 之前大多使用 [PuTTY](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) 與 cmd line 工具 [Plink](https://tartarus.org/~simon/putty-snapshots/htmldoc/Chapter7.html)
>[!Tip]
Plink (PuTTY Link) 是 PuTTY 的 cmd 版本，專為 Windows 環境設計的 SSH 客戶端。\
功能類似 OpenSSH client，但 不支援 Remote Dynamic Port Forwarding。\
由於 Windows 環境常見，也較少被防毒軟體偵測為惡意程式，因此在滲透測試中很有用。

[環境範例]
- 在內網發現了一台 Windows 伺服器 MULTISERVER03，它只開放了 TCP 80 ，其他端口都被防火牆擋住。 
- 無法直接使用 RDP 或 OpenSSH client 連回 Kali 機器，但可以透過 HTTP Web Shell 來執行命令。 
- 目標透過 Plink 建立 Remote Port Forwarding，讓我們可以透過 Kali 連到內部服務 (如 PostgreSQL 伺服器)
- 首先，我們需要透過 Web Shell 取得一個更穩定的 Reverse Shell。

![image](https://hackmd.io/_uploads/SJ6Sgh4syl.png)
