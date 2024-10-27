---
title: 'OSCP_ Self Note'
disqus: hackmd
---

OSCP_ Self Note
===

# Table of Contents
[TOC]

# Recon

## Whois
```
whois {Target domain/ip} -h {指定WHOIS 伺服器}
```

## Google Hacking
```
👉🏻 site:
👉🏻 ext: {filetype}
👉🏻 filetype:
👉🏻 -filetype: 排除

intitle:"index of" "parent directory"
> 標題包含 index of 與 頁面上包含 parent directory

```
● [Google Hacking Database (GHDB)](https://www.exploit-db.com/google-hacking-database)

## Open-Source Code
Github search:
```
owner:megacorpone path:users
```
![image](https://hackmd.io/_uploads/B1PHC86aR.png)
> 找到 user 和 hash 過的 password

## DNS
### 1. host
```
┌──(kali㉿kali)-[~]
└─$ host -t txt megacorpone.com
megacorpone.com descriptive text "google-site-verification=U7B_b0HNeBtY4qYGQZNsEYXfCJ32hMNV3GtC0wWq5pA"
megacorpone.com descriptive text "Try Harder"
                                                                             
┌──(kali㉿kali)-[~]
└─$ host www.megacorpone.com  
www.megacorpone.com has address 149.56.244.87
                                                                             
┌──(kali㉿kali)-[~]
└─$ host -t mx megacorpone.com 
megacorpone.com mail is handled by 60 mail2.megacorpone.com.
megacorpone.com mail is handled by 20 spool.mail.gandi.net.
megacorpone.com mail is handled by 10 fb.mail.gandi.net.
megacorpone.com mail is handled by 50 mail.megacorpone.com.
                                                                             
┌──(kali㉿kali)-[~]
└─$ host -t txt megacorpone.com
megacorpone.com descriptive text "Try Harder"
megacorpone.com descriptive text "google-site-verification=U7B_b0HNeBtY4qYGQZNsEYXfCJ32hMNV3GtC0wWq5pA"

```

### 2. dnsrecon
Brute forcing hostnames using dnsrecon
```
kali@kali:~$ dnsrecon -d megacorpone.com -D ~/list.txt -t brt
[*] Using the dictionary file: /home/kali/list.txt (provided by user)
[*] brt: Performing host and subdomain brute force against megacorpone.com...
[+] 	 A www.megacorpone.com 149.56.244.87
[+] 	 A mail.megacorpone.com 51.222.169.212
[+] 	 A router.megacorpone.com 51.222.169.214
[+] 3 Records Found
```
-d 選項指定域名\
-D指定包含潛在子域字串的檔案名\
-t指定要執行的枚舉類型

### 3. dnsrecon 與 host 差異
![image](https://hackmd.io/_uploads/BkH3h9Vl1x.png)

### xfreerdp (RDP Tool)
```
brew install freerdp
xfreerdp /v:<server_ip> /u:<username>
```
`/u`: username\
`/p`: password\
`/v`: ip address

### 4. nslookup
```
C:\Users\student>nslookup -type=TXT info.megacorptwo.com 192.168.239.151
DNS request timed out.
    timeout was 2 seconds.
Server:  UnKnown
Address:  192.168.239.151

info.megacorptwo.com    text =

        "greetings from the TXT record body"
```

## Netcat
- NC 送 TCP 封包
```
┌──(kali㉿kali)-[~]
└─$ nc -nvv -w 1 -z 192.168.50.152 3388-3390
(UNKNOWN) [192.168.50.152] 3390 (?) : Connection timed out
(UNKNOWN) [192.168.50.152] 3389 (ms-wbt-server) : Connection timed out
(UNKNOWN) [192.168.50.152] 3388 (?) : Connection timed out
 sent 0, rcvd 0
```
`-n`：指示 Netcat 不進行 DNS 解析，直接使用 IP 地址。\
`-v`：設置詳細模式（verbose），輸出更多細節。\
`-v`：再次增加詳細程度，通常第二個 -v 會使輸出信息更詳細。\
`-w 1`：設定等待超時時間為 1 秒，即每個端口掃描若無回應便會中止。\
`-z`：設置 Netcat 進行掃描模式，不傳輸數據，只檢查端口開啟狀態。 (防止 IPS/IDS 偵測)

>[!Note] Wireshark capture package


- NC 送 UDP 封包
```
┌──(kali㉿kali)-[~]
└─$ nc -nv -u -z -w 1 192.168.50.149 120-123
(UNKNOWN) [192.168.50.149] 123 (ntp) open
(UNKNOWN) [192.168.50.149] 122 (?) open
(UNKNOWN) [192.168.50.149] 121 (?) open
(UNKNOWN) [192.168.50.149] 120 (?) open
```
`-u`：使用 UDP 協議進行掃描（預設為 TCP）。\


