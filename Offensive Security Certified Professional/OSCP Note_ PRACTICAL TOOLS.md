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


