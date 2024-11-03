
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
`-d` : 選項指定域名\
`-D` : 指定包含潛在子域字串的檔案名\
`-t` : 指定要執行的枚舉類型

### 3. dnsrecon 與 host 差異
![image](https://hackmd.io/_uploads/BkH3h9Vl1x.png)

### xfreerdp (RDP Tool)
```
brew install freerdp
xfreerdp /v:<server_ip> /u:<username> /p:<userpwd>
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

>[!Note] 
> Wireshark capture package


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
>[!Important] 
>`iptables`: 管理 Linux 防火牆的工具
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

用 Nmap 送流量測試。\
![image](https://hackmd.io/_uploads/B18Io5jxyg.png)


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
`-v`：verbose的縮寫，表示詳細模式。\
`-sS` : 半開掃描，只送 SYN 檢測端口是否開放。\
`-sT` : 全開掃描，建立完整 TCP 三項交握進行掃描。
`-sU` : UDP 掃描，用於掃描 UDP 端口。掃描方式與 tcp 不同。\
`-A` : 全面掃描，包含系統檢測、版本檢測、服務偵測和腳本掃描等。\
`-O` : 作業系統檢測。\
`-sC` : 使用預設的 Nmap Scripting Engine (NSE) 腳本進行掃描，可以檢測漏洞、執行探測等。\
`-sV` : 嘗試識別服務的版本，提供更詳細的服務資訊。\
`-T4` : 時間模板。\
`-sn` : Ping 掃描，只掃主機，不掃任何端口。檢查哪些主機在線。\
`-Pn`: 跳過主機存活檢測，直接進行端口掃描。\
`--top-ports=20` : 最常見的 20 個 port 。\
`--script <scriptname>`: 指定的 Nmap NSE 腳本。\
Ex. --script http-headers : **NSE scripts are located in the /usr/share/nmap/scripts**\
`-oG <filename>` : 輸出結果為 grepable 格式，便於後續分析。\
`-oN <filename>` : 輸出標準格式。\
`-oX <filename>` : 輸出 XML 格式。\
`-p <port range>` : 指定 port。\
`-iL <inputfile>` : 從檔案讀取目標 IP 或 DN。\

> --top-ports=20 最常見的 20 個 port 來自 /usr/share/nmap/nmap-services
```
┌──(chw㉿CHW-kali)-[~]
└─$ cat /usr/share/nmap/nmap-services
# ...
tcpmux  1/tcp   0.001995        # TCP Port Service Multiplexer [rfc-1078] | TCP Port Service Multiplexer
tcpmux  1/udp   0.001236        # TCP Port Service Multiplexer
compressnet     2/tcp   0.000013        # 
systat  11/udp  0.000577        # Active Users
...
```
    
>[!Note]
> 在區網快速搜尋 80 port service

```
nmap -p 80 --script http-title.nse {IP}/{MASK}
```
![image](https://hackmd.io/_uploads/SJW13qkWyx.png)


##  Test-NetConnection - Windows nmap
```
PS C:\Users\chw> Test-NetConnection -Port 445 192.168.50.151

ComputerName     : 192.168.50.151
RemoteAddress    : 192.168.50.151
RemotePort       : 445
InterfaceAlias   : Ethernet0
SourceAddress    : 192.168.50.152
TcpTestSucceeded : True
```
透過 Powershell 使用 Net.Sockets.TcpClient object。\
對於 192.168.50.151 port 1~1024，輸出對應 TCP Port 資訊，不會顯示連接失敗的錯誤。
```
PS C:\Users\chw> 1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
TCP port 88 is open
...
```
## SMB Enumeration (identifying NetBIOS)
>[!Tip]
> SMB（Server Message Block），又稱網路檔案分享系統（Common Internet File System，縮寫為CIFS），一種應用層網路傳輸協定，由微軟開發，主要功能是使網路上的機器能夠共享電腦檔案、印表機、序列埠和通訊等資源。它也提供經認證的行程間通訊機能。它主要用在裝有Microsoft Windows的機器上，在這樣的機器上被稱為 Microsoft Windows Network。\
> TCP port: 445\
> UDP ports 137, 138 & TCP ports 137, 139 (NetBIOS over TCP/IP)

### nbtscan
```
┌──(chw㉿CHW-kali)-[/usr/share/nmap/scripts]
└─$ sudo nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254
┌──(chw㉿CHW-kali)-[/usr/share/nmap/scripts]
└─$ cat smb.txt                                         
# Nmap 7.92 scan initiated Thu Mar 17 06:03:12 2022 as: nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254
# Ports scanned: TCP(2;139,445) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 192.168.50.1 ()	Status: Down
...
Host: 192.168.50.21 ()	Status: Up
Host: 192.168.50.21 ()	Ports: 139/closed/tcp//netbios-ssn///, 445/closed/tcp//microsoft-ds///
...
Host: 192.168.50.217 ()	Status: Up
Host: 192.168.50.217 ()	Ports: 139/closed/tcp//netbios-ssn///, 445/closed/tcp//microsoft-ds///
# Nmap done at Thu Mar 17 06:03:18 2022 -- 254 IP addresses (15 hosts up) scanned in 6.17 seconds
    
┌──(chw㉿CHW-kali)-[/usr/share/nmap/scripts]
└─$ sudo nbtscan -r 192.168.50.0/24
Doing NBT name scan for addresses from 192.168.50.0/24

IP address       NetBIOS Name     Server    User             MAC address
------------------------------------------------------------------------------
192.168.50.124   SAMBA            <server>  SAMBA            00:00:00:00:00:00
192.168.50.134   SAMBAWEB         <server>  SAMBAWEB         00:00:00:00:00:00
...
```

Q: Walk Through - Information Gathering - SMB Enumeration - 192.168.215.0/24 and use Nmap to create a list of the SMB servers in the VM Group 1. How many hosts have port 445 open?
```
CWei@CHW-MacBook-Pro OSCP % nmap -v -p 445 192.168.215.1/24 | grep "445/tcp open"
445/tcp open  microsoft-ds
445/tcp open  microsoft-ds
445/tcp open  microsoft-ds
445/tcp open  microsoft-ds
445/tcp open  microsoft-ds
445/tcp open  microsoft-ds
445/tcp open  microsoft-ds
445/tcp open  microsoft-ds
445/tcp open  microsoft-ds
445/tcp open  microsoft-ds
CWei@CHW-MacBook-Pro OSCP % nmap -v -p 445 192.168.215.1/24 | grep "445/tcp open" | wc -l
      10
```        

###  net view - Windows nbtscan
```
C:\Users\chw>net view \\dc01 /all
Shared resources at \\dc01

Share name  Type  Used as  Comment

-------------------------------------------------------------------------------
ADMIN$      Disk           Remote Admin
C$          Disk           Default share
IPC$        IPC            Remote IPC
NETLOGON    Disk           Logon server share
SYSVOL      Disk           Logon server share
The command completed successfully.
```
`net view`：查看網路上其他電腦的共享資源的指令。\
`\\dc01`：指定目標電腦名稱（dc01，通常是指網域控制站）來查看它上的共享資源。\
`/all`：顯示所有資源的詳細資訊，包括隱藏的共享資源。list the administrative shares ending with the dollar sign ($).
    
### enum4linux
用於列舉Windows和Samba主機中的資料。
![image](https://hackmd.io/_uploads/SyfxjK7bkl.png)

```
CWei@CHW-MacBook-Pro enum4linux % perl enum4linux.pl 192.168.215.13
"my" variable $which_output masks earlier declaration in same scope at enum4linux.pl line 280.
WARNING: polenum is not in your path.  Check that package is installed and your PATH is sane.
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sat Nov  2 19:16:04 2024

 =========================================( Target Information )=========================================

Target ........... 192.168.215.13
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 192.168.215.13 )===========================

Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it

[+] Got domain/workgroup name: WORKGROUP


 ===============================( Nbtstat Information for 192.168.215.13 )===============================

Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it
Looking up status of 192.168.215.13
	SAMBA           <00> -         B <ACTIVE>  Workstation Service
	SAMBA           <03> -         B <ACTIVE>  Messenger Service
	SAMBA           <20> -         B <ACTIVE>  File Server Service
	..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
	WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
	WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
	WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

	MAC Address = 00-00-00-00-00-00

 ==================================( Session Check on 192.168.215.13 )==================================


[+] Server 192.168.215.13 allows sessions using username '', password ''


 ===============================( Getting domain SID for 192.168.215.13 )===============================

Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it
Domain Name: WORKGROUP
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup


 ==================================( OS information on 192.168.215.13 )==================================


[E] Can't get OS info with smbclient


[+] Got OS info for 192.168.215.13 from srvinfo:
Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it
	SAMBA          Wk Sv PrQ Unx NT SNT samba server (Samba, Ubuntu)
	platform_id     :	500
	os version      :	6.1
	server type     :	0x809a03


 ======================================( Users on 192.168.215.13 )======================================

Use of uninitialized value $users in print at enum4linux.pl line 1028.
Use of uninitialized value $users in pattern match (m//) at enum4linux.pl line 1031.

Use of uninitialized value $users in print at enum4linux.pl line 1046.
Use of uninitialized value $users in pattern match (m//) at enum4linux.pl line 1048.

 ================================( Share Enumeration on 192.168.215.13 )================================

Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	files           Disk      Flag: OS{e14e252c16545cbf8f8a5f720a1f6370}
	IPC$            IPC       IPC Service (samba server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 192.168.215.13

//192.168.215.13/print$	Mapping: DENIED Listing: N/A Writing: N/A

[E] Can't understand response:

Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it
NT_STATUS_IO_TIMEOUT listing \*
//192.168.215.13/files	Mapping: N/A Listing: N/A Writing: N/A

[E] Can't understand response:

Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
//192.168.215.13/IPC$	Mapping: N/A Listing: N/A Writing: N/A

 ===========================( Password Policy Information for 192.168.215.13 )===========================


[E] Dependent program "polenum" not present.  Skipping this check.  Download polenum from http://labs.portcullis.co.uk/application/polenum/



 ======================================( Groups on 192.168.215.13 )======================================


[+] Getting builtin groups:


[+]  Getting builtin group memberships:


[+]  Getting local groups:


[+]  Getting local group memberships:


[+]  Getting domain groups:


[+]  Getting domain group memberships:


 =================( Users on 192.168.215.13 via RID cycling (RIDS: 500-550,1000-1050) )=================


[I] Found new SID:
S-1-22-1

[I] Found new SID:
S-1-5-32

[I] Found new SID:
S-1-5-32

[I] Found new SID:
S-1-5-32

[I] Found new SID:
S-1-5-32

[+] Enumerating users using SID S-1-5-21-4030004202-475240355-4120303355 and logon username '', password ''

S-1-5-21-4030004202-475240355-4120303355-501 SAMBA\nobody (Local User)
S-1-5-21-4030004202-475240355-4120303355-513 SAMBA\None (Domain Group)
```

## SMTP Enumeration
>[!Tip]
> SMTP: Simple Mail Transfer Protocol. port: 25

### Python script the SMTP user enumeration
```python=
#!/usr/bin/python

import socket
import sys

if len(sys.argv) != 3:
        print("Usage: vrfy.py <username> <target_ip>")
        sys.exit(0)

# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the Server
ip = sys.argv[2]
connect = s.connect((ip,25))

# Receive the banner
banner = s.recv(1024)

print(banner)

# VRFY a user
user = (sys.argv[1]).encode()
s.send(b'VRFY ' + user + b'\r\n')
result = s.recv(1024)

print(result)

# Close the socket
s.close()
```

```
┌──(chw㉿CHW-kali)-[/]
└─$ python3 smtp.py root 192.168.50.8
b'220 mail ESMTP Postfix (Ubuntu)\r\n'
b'252 2.0.0 root\r\n'
```
- 伺服器回應
`b'220 mail ESMTP Postfix (Ubuntu)`: 表示 SMTP 伺服器（使用 Postfix 郵件傳送代理）已經啟動並準備接受連接。220 是 SMTP 協議中的一個狀態碼，表示服務器準備好進行通信。\
- VRFY 命令結果
`b'252 2.0.0 root`: 表示用戶 root 是有效的郵件帳戶，並且服務器接受了該請求。 252 表示服務器成功識別了這個用戶名。

```
┌──(chw㉿CHW-kali)-[/]
└─$ python3 smtp.py johndoe 192.168.50.8
b'220 mail ESMTP Postfix (Ubuntu)\r\n'
b'550 5.1.1 <johndoe>: Recipient address rejected: User unknown in local recipient table\r\n'
```
- 伺服器回應
`b'220 mail ESMTP Postfix (Ubuntu)`
- VRFY 命令結果
`b'550 5.1.1 <johndoe>: Recipient address rejected: User unknown in local recipient table`: 表示用戶 johndoe 不存在。 550 表示請求的郵件地址無法接受，5.1.1 是一個具體的錯誤代碼，表示用戶地址未知。

### telnet (Windows Test-NetConnection can't interacting with SMTP)
```
PS C:\Users\chw> Test-NetConnection -Port 25 192.168.50.8

ComputerName     : 192.168.50.8
RemoteAddress    : 192.168.50.8
RemotePort       : 25
InterfaceAlias   : Ethernet0
SourceAddress    : 192.168.50.152
TcpTestSucceeded : True
```
```
PS C:\Windows\system32> dism /online /Enable-Feature /FeatureName:TelnetClient  
... (Installing the Telnet client)

C:\Windows\system32> telnet 192.168.50.8 25
220 mail ESMTP Postfix (Ubuntu)
VRFY goofy
550 5.1.1 <goofy>: Recipient address rejected: User unknown in local recipient table
VRFY root
252 2.0.0 root
```
(In MacOS/Linux)
```
CWei@CHW-MacBook-Pro SMTP user enumeration % nmap -nv -p 25 192.168.215.1/24
Starting Nmap 7.95 ( https://nmap.org ) at 2024-11-02 21:32 CST
Initiating Ping Scan at 21:32
Scanning 256 hosts [2 ports/host]
...
Nmap scan report for 192.168.215.8
Host is up (0.11s latency).

PORT   STATE SERVICE
25/tcp open  smtp
...

CWei@CHW-MacBook-Pro SMTP user enumeration % python3 SMTP_script.py root 192.168.215.8
b'220 mail ESMTP Postfix (Ubuntu)\r\n'
b'252 2.0.0 root\r\n'
CWei@CHW-MacBook-Pro SMTP user enumeration % nc 192.168.215.8 25
220 mail ESMTP Postfix (Ubuntu)
VRFY root
252 2.0.0 root
|
```

## SNMP Enumeration
>[!Tip]
> SNMP: Simple Network Management Protocol.\
> SNMP is based on UDP. 常用的 SNMP protocols 1, 2, and 2c 未加密.
> SNMPv3, which provides authentication and encryption.

![image](https://hackmd.io/_uploads/BkPK6C4ZJe.png)

### SNMP MIB Tree
>[!Tip]
> SNMP Management Information Base (MIB).
> SNMP 中用來組織和存取設備管理數據的階層式結構。它將設備的各種資訊，如網路狀態、硬體和軟體參數等，以樹狀結構組織，並使用唯一的 OID（物件標識碼，Object Identifier）來識別每個項目。

```
┌──(chw㉿CHW-kali)-[/]
└─$ sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-14 06:02 EDT
Nmap scan report for 192.168.50.151
Host is up (0.10s latency).

PORT    STATE SERVICE
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds
...
```
### onesixtyone (SNMP scanner)
>[!Tip]
>![image](https://hackmd.io/_uploads/B1gxj6NZ1l.png)

```
CWei@CHW-MacBook-Pro ~ % onesixtyone
onesixtyone 0.3.4 [options] <host> <community>
  -c <communityfile> file with community names to try
  -i <inputfile>     file with target hosts
  -o <outputfile>    output log
  -p                 specify an alternate destination SNMP port
  -d                 debug mode, use twice for more information

  -s                 short mode, only print IP addresses

  -w n               wait n milliseconds (1/1000 of a second) between sending packets (default 10)
  -q                 quiet mode, do not print log to stdout, use with -o
host is either an IPv4 address or an IPv4 address and a netmask
default community names are: public private

Max number of hosts : 		65536
Max community length: 		32
Max number of communities: 	16384


examples: onesixtyone 192.168.4.0/24 public
          onesixtyone -c dict.txt -i hosts -o my.log -w 100
```
![image](https://hackmd.io/_uploads/HJA4YTVbyx.png)

- 將三個常見的社群名稱 public、private 和 manager 寫入 community 檔案
```
CWei@CHW-MacBook-Pro onesixtyone % cat community
public
private
manager
```
- 生成 IP 範圍 192.168.50.1 至 192.168.50.254，並將結果存入 ips 檔案。
```
CWei@CHW-MacBook-Pro onesixtyone % for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
```
- 使用 -c 參數指定 community 檔案（包含社群名稱），-i 參數指定 ips 檔案（包含目標 IP list）
```
CWei@CHW-MacBook-Pro onesixtyone % onesixtyone -c community -i ips
Scanning 254 hosts, 3 communities
```
> Using onesixtyone to brute force community strings

### snmpwalk (query and retrieve SNMP)
>[!Tip]
>![image](https://hackmd.io/_uploads/S1dPsTNbkx.png)

>[!Important]
> **SNMP Object Identifier**:\
> https://advdownload.advantech.com/productfile/Downloadfile5/1-1EE6T69/Aplication_Guide_SNMP%20OID.pdf
>> SNMP MIB tree structure 是透過 OID 管理
    
#### 1. snmpwalk enumerate the entire MIB tree
> 透過查詢 MIB tree 可以知道 OID 架構，進階搜尋 Windows users, processes, installed software ..etc
```
┌──(chw㉿CHW-kali)-[/]
└─$ snmpwalk -c public -v1 -t 10 192.168.50.151
iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.311.1.1.3.1.3
iso.3.6.1.2.1.1.3.0 = Timeticks: (78235) 0:13:02.35
iso.3.6.1.2.1.1.4.0 = STRING: "admin@megacorptwo.com"
iso.3.6.1.2.1.1.5.0 = STRING: "dc01.megacorptwo.com"
iso.3.6.1.2.1.1.6.0 = ""
iso.3.6.1.2.1.1.7.0 = INTEGER: 79
iso.3.6.1.2.1.2.1.0 = INTEGER: 24
...
```
snmpwalk 輸出從 192.168.50.151 取得的 SNMP 資訊:
- `STRING: "Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)"`: 使用 Windows 作業系統，具體版本是 Windows 6.3。
- `OID: iso.3.6.1.4.1.311.1.1.3.1.3`: 設備的 MIB（管理資訊基底）物件 ID（OID），用於唯一識別此設備類型，該 OID 與特定的系統製造商相關。
- `Timeticks: (78235) 0:13:02.35`: 設備運行時間（Uptime），已開機約 13 分鐘 2 秒。
- `STRING: "admin@megacorptwo.com"`: 管理員 Email。
- `STRING: "dc01.megacorptwo.com"`: 主機名稱。
- `iso.3.6.1.2.1.1.6.0 = ""`: 設備的物理位置未設定。
- `INTEGER: 79`: sysServices 服務類型數量或指標。[RFC 定義](https://hackmd.io/_uploads/Hk9mlRVWJx.png)
- `INTEGER: 24`: ifNumber 網路介面數量。 [補充](https://hackmd.io/_uploads/rykVbCNZkg.png)

#### 2. snmpwalk enumerate Windows users
```
┌──(chw㉿CHW-kali)-[/]
└─$ snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25
iso.3.6.1.4.1.77.1.2.25.1.1.5.71.117.101.115.116 = STRING: "Guest"
iso.3.6.1.4.1.77.1.2.25.1.1.6.107.114.98.116.103.116 = STRING: "krbtgt"
iso.3.6.1.4.1.77.1.2.25.1.1.7.115.116.117.100.101.110.116 = STRING: "student"
iso.3.6.1.4.1.77.1.2.25.1.1.13.65.100.109.105.110.105.115.116.114.97.116.111.114 = STRING: "Administrator"
```
`OID 1.3.6.1.4.1.77.1.2.25` 通常與 Microsoft Windows 系統中的某些特定對象相關，特別是與用戶賬戶資訊有關。OID 是一個屬於企業私有範圍的 Object Identifier，在這裡 1.3.6.1.4.1.77 是 Microsoft 的 Identifier。

#### 3. snmpwalk enumerate Windows processes
```
┌──(chw㉿CHW-kali)-[/]
└─$ snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2
iso.3.6.1.2.1.25.4.2.1.2.1 = STRING: "System Idle Process"
iso.3.6.1.2.1.25.4.2.1.2.4 = STRING: "System"
iso.3.6.1.2.1.25.4.2.1.2.88 = STRING: "Registry"
iso.3.6.1.2.1.25.4.2.1.2.260 = STRING: "smss.exe"
iso.3.6.1.2.1.25.4.2.1.2.316 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.372 = STRING: "csrss.exe"
iso.3.6.1.2.1.25.4.2.1.2.472 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.476 = STRING: "wininit.exe"
iso.3.6.1.2.1.25.4.2.1.2.484 = STRING: "csrss.exe"
iso.3.6.1.2.1.25.4.2.1.2.540 = STRING: "winlogon.exe"
iso.3.6.1.2.1.25.4.2.1.2.616 = STRING: "services.exe"
iso.3.6.1.2.1.25.4.2.1.2.632 = STRING: "lsass.exe"
iso.3.6.1.2.1.25.4.2.1.2.680 = STRING: "svchost.exe"
...
```
查詢的 OID 1.3.6.1.2.1.25.4.2.1.2 返回了系統上正在運行的process 名稱。這個 OID 是屬於 HOST-RESOURCES-MIB 的一部分。

#### 4. snmpwalk enumerate installed software
```
┌──(chw㉿CHW-kali)-[/]
└─$ snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.6.3.1.2
iso.3.6.1.2.1.25.6.3.1.2.1 = STRING: "Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.27.29016"
iso.3.6.1.2.1.25.6.3.1.2.2 = STRING: "VMware Tools"
iso.3.6.1.2.1.25.6.3.1.2.3 = STRING: "Microsoft Visual C++ 2019 X64 Additional Runtime - 14.27.29016"
iso.3.6.1.2.1.25.6.3.1.2.4 = STRING: "Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.27.290"
iso.3.6.1.2.1.25.6.3.1.2.5 = STRING: "Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.27.290"
iso.3.6.1.2.1.25.6.3.1.2.6 = STRING: "Microsoft Visual C++ 2019 X86 Additional Runtime - 14.27.29016"
iso.3.6.1.2.1.25.6.3.1.2.7 = STRING: "Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.27.29016"
...
```

#### 5. snmpwalk enumerate open TCP ports
```
┌──(chw㉿CHW-kali)-[/]
└─$ snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.6.13.1.3
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.88.0.0.0.0.0 = INTEGER: 88
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.135.0.0.0.0.0 = INTEGER: 135
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.389.0.0.0.0.0 = INTEGER: 389
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.445.0.0.0.0.0 = INTEGER: 445
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.464.0.0.0.0.0 = INTEGER: 464
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.593.0.0.0.0.0 = INTEGER: 593
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.636.0.0.0.0.0 = INTEGER: 636
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.3268.0.0.0.0.0 = INTEGER: 3268
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.3269.0.0.0.0.0 = INTEGER: 3269
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.5357.0.0.0.0.0 = INTEGER: 5357
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.5985.0.0.0.0.0 = INTEGER: 5985
...
```
`Port 88`: Kerberos 認證服務。\
`Port 135`: Windows RPC 服務。\
`Poer 389`: LDAP。\
`Port 445`: Microsoft 文件共享協定。\
`Port 464`: Kerberos 更改密碼。\
`Port 593`: 與 Windows RPC 服務有關。
    

