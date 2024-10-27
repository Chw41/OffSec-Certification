
OSCP_ Self Note
===

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
`-u`：使用 UDP 協議進行掃描（預設為 TCP）。

## iptables 監控流量 (not available on macOS)
>[!Important] `iptables`: 管理 Linux 防火牆的工具
```
┌──(chw㉿CHW-kali)-[~/Desktop/Reverse]
└─$ sudo iptables -I INPUT 1 -s 192.168.218.129 -j ACCEPT 

┌──(chw㉿CHW-kali)-[~/Desktop/Reverse]
└─$ sudo iptables -I OUTPUT 1 -d 192.168.218.129 -j ACCEPT
 
┌──(chw㉿CHW-kali)-[~/Desktop/Reverse]
└─$ sudo iptables -Z 
```
`-I INPUT 1`: 在 INPUT chain 的第一個位置插入 rule。\
`-I OUTPUT 1`: 在 OUTPUT chain 的第一個位置插入 rule。\
`-s 192.168.218.129`: Source IP 為 192.168.218.129。\
`-j ACCEPT`: 如果符合規則，允許流量通過。


> 以上設定與 192.168.218.129 之間的雙向流量，同時重置counters 便於監控流量。

用 Nmap 送流量測試。
:::spoiler
![image](https://hackmd.io/_uploads/B18Io5jxyg.png)

:::

```
┌──(chw㉿CHW-kali)-[~]
└─$ sudo iptables -vn -L
Chain INPUT (policy ACCEPT 145 packets, 8531 bytes)
 pkts bytes target     prot opt in     out     source               destination         
 4008  200K ACCEPT     all  --  *      *       192.168.218.129      0.0.0.0/0           
    0     0 ACCEPT     all  --  *      *       192.168.50.149       0.0.0.0/0           
    0     0 ACCEPT     all  --  *      *       192.168.50.149       0.0.0.0/0           
    0     0 ACCEPT     all  --  *      *       192.168.50.149       0.0.0.0/0           
    0     0 ACCEPT     all  --  *      *       192.168.50.149       0.0.0.0/0           

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT 104 packets, 8454 bytes)
 pkts bytes target     prot opt in     out     source               destination         
 4008  200K ACCEPT     all  --  *      *       0.0.0.0/0            192.168.218.129     
    0     0 ACCEPT     all  --  *      *       0.0.0.0/0            192.168.50.149      
    0     0 ACCEPT     all  --  *      *       0.0.0.0/0            192.168.50.149 
```
`-v`: 詳細模式。通顯示每條規則的額外資訊，例如 pkts, bytes。\
`-n`: 不進行 DNS 解析。顯示 IP 不轉換為 Domain name，加快輸出速度。\
`-L`: 列出當前的防火牆規則。

> iptables (src: 192.168.218.129)：經過 nmap 後，
> 1. **Chain INPUT** 中 ，處理了 145 packets, 8531 bytes。
> 2. **Chain FORWARD** 預設也是 ACCEPT，沒有流量經過。
> 3. **Chain OUTPUT** 代表從本機送出的流量，處理了 104 packets, 8454 bytes

## Nmap
Nmap TCP connect scan makes use of the **Berkeley sockets API** to perform the three-way handshake, it **does not require elevated privileges**.

>[!Important]
nmap <參數> <DistIP>\
**<參數>**:\
`-sS` : 半開掃描，只送 SYN 檢測端口是否開放。\
`-sT` : 全開掃描，建立完整 TCP 三項交握進行掃描。
`-sU` : UDP 掃描，用於掃描 UDP 端口。掃描方式與 tcp 不同。\
`-A` : 全面掃描，包含系統檢測、版本檢測、服務偵測和腳本掃描等。\
`-sC` : 使用預設的 Nmap Scripting Engine (NSE) 腳本進行掃描，可以檢測漏洞、執行探測等。\
`-sV` : 嘗試識別服務的版本，提供更詳細的服務資訊。\
`-T4` : 時間模板。\
`-sn` : Ping 掃描，只掃主機，不掃任何端口。檢查哪些主機在線。\
`-Pn`: 跳過主機存活檢測，直接進行端口掃描。\
`--script <scriptname>`: 指定的 Nmap NSE 腳本。\
`-oG <filename>` : 輸出結果為 grepable 格式，便於後續分析。\
`-oN <filename>` : 輸出標準格式。\
`-oX <filename>` : 輸出 XML 格式。\
`-p <port range>` : 指定 port。\
`-iL <inputfile>` : 從檔案讀取目標 IP 或 DN。\

