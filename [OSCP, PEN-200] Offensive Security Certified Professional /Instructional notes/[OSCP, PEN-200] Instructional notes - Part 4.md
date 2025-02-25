---
title: '[OSCP, PEN-200] Instructional notes - Part 4'
disqus: hackmd
---

[OSCP, PEN-200] Instructional notes - Part 4
===


# Table of Contents
[TOC]

# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 1"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/README.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 2"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%202.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 3"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%203.md)


>[!Caution]
> 接續 [[OSCP, PEN-200] Instructional notes - Part 3](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%203.md) 內容

# Linux Privilege Escalation
如何 enumerate Linux machines 與 Linux privileges 的結構
## Enumerating Linux
manual and automated enumeration techniques
### Understanding Files and Users Privileges on Linux
每個檔案都遵循三個主要屬性的 user 和 group 權限：\
讀取（r）、寫入（w）和 執行（x)
```
┌──(chw㉿CHW)-[~]
└─$ ls -l /etc/shadow
-rw-r----- 1 root shadow 1386 Feb  3 04:21 /etc/shadow
```
### Manual Enumeration
#### - id
使用 `id` 收集使用者資訊
```
┌──(chw㉿CHW)-[~]
└─$ ssh joe@192.168.223.214 
...
joe@192.168.223.214's password: 
Linux debian-privesc 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 (2022-06-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Feb 15 04:15:11 2023 from 192.168.118.3
joe@debian-privesc:~$ id
uid=1000(joe) gid=1000(joe) groups=1000(joe),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),112(bluetooth),116(lpadmin),117(scanner)
```
#### - /etc/passwd
enumerate all users: /etc/passwd
```
joe@debian-privesc:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
...
dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:108:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
...
Debian-gdm:x:117:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
joe:x:1000:1000:joe,,,:/home/joe:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
eve:x:1001:1001:,,,:/home/eve:/bin/bash
```
> `www-data`與 `sshd`。表示系統上可能安裝了 Web Server 和 SSH Server。\
> `x`: 包含使用者密碼的雜湊版本，包含在 /etc/shadow\
> `UID` : 1000 - 除了 root 使用者的 UID 為 0 外，Linux 從 1000 開始計數普通使用者 ID。\
> `GID`： 1000 － 代表使用者特定的群組 ID。\
> `/home/joe`: 描述使用者登入時提示的主目錄\
> `/bin/bash`: － 表示預設 interactive shell
>> 另一個 user: eve ， 配置的主資料夾在 /home/eve

>[!Important]
>system services 將 `/usr/sbin/nologin` 作為登入 shell，其中nologin 用於阻止服務帳戶的任何遠端或本機登入

#### - hostname
主機名稱通常可以提供有關其功能的線索，`web` 表示 Web server，`db` 表示資料庫伺服器，`dc` 表示 domain controller
```
joe@debian-privesc:~$ hostname
debian-privesc
```
企業通常會對 hostname 命名，以便按位置、描述、作業系統和服務等級進行分類。通常由兩部分組成: `OS type` + `description`\
#### - /etc/issue & /etc/os-release
issue 和 os-release 檔案包含作業系統版本（Debian 10）和特定於發布的信息，包括 distribution codename。
```
joe@debian-privesc:~$ cat /etc/issue
Debian GNU/Linux 10 \n \l

joe@debian-privesc:~$ cat /etc/os-release
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
```
#### - uname -a
輸出作業系統核心版本（4.19.0）和架構（x86_64）
```
joe@debian-privesc:~$ uname -a
Linux debian-privesc 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 (2022-06-30)
x86_64 GNU/Linux
```

#### - ps aux
列出系統process（包括 privileged users)
```
joe@debian-privesc:~$ ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.4 169592 10176 ?        Ss   Aug16   0:02 /sbin/init
...
colord     752  0.0  0.6 246984 12424 ?        Ssl  Aug16   0:00 /usr/lib/colord/colord
Debian-+   753  0.0  0.2 157188  5248 ?        Sl   Aug16   0:00 /usr/lib/dconf/dconf-service
root       477  0.0  0.5 179064 11060 ?        Ssl  Aug16   0:00 /usr/sbin/cups-browsed
root       479  0.0  0.4 236048  9152 ?        Ssl  Aug16   0:00 /usr/lib/policykit-1/polkitd --no-debug
root      1656  0.0  0.0      0     0 ?        I    01:03   0:00 [kworker/1:2-events_power_efficient]
joe       1657  0.0  0.4  21160  8960 ?        Ss   01:03   0:00 /lib/systemd/systemd --user
joe       1658  0.0  0.1 170892  2532 ?        S    01:03   0:00 (sd-pam)
joe       1672  0.0  0.2  14932  5064 ?        S    01:03   0:00 sshd: joe@pts/0
joe       1673  0.0  0.2   8224  5020 pts/0    Ss   01:03   0:00 -bash
root      1727  0.0  0.0      0     0 ?        I    03:00   0:00 [kworker/0:0-ata_sff]
root      1728  0.0  0.0      0     0 ?        I    03:06   0:00 [kworker/0:2-ata_sff]
joe       1730  0.0  0.1  10600  3028 pts/0    R+   03:10   0:00 ps axu
```
> `a（all）`：顯示所有使用者的 process。\
`x`：顯示不與終端（[TTY](https://www.linusakesson.net/programming/tty/)）關聯的進程，例如系統守護（daemons）。\
`u（user-readable）`：較易讀的格式顯示進程資訊，包括使用者名稱、CPU 使用率、記憶體使用率等。
>> 輸出列出了以 root 身分運行的幾個 process，這些 process 值得研究可能存在的漏洞\
>> `joe       1730  0.0  0.1  10600  3028 pts/0    R+   03:10   0:00 ps axu`: 可以看到當下輸入的 ps command 也列在輸出中。可以使用適當的使用者名稱從輸出中過濾特定的使用者擁有的 process。

#### - network interfaces, routes, and open ports
使用 ifconfig 或ip列出每個網路介面卡的 TCP/IP 設定
- `ifconfig`: 顯示 interface statistics
- `ip`: compact version of the same information

```
joe@debian-privesc:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:8a:b9:fc brd ff:ff:ff:ff:ff:ff
    inet 192.168.50.214/24 brd 192.168.50.255 scope global ens192
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:fe8a:b9fc/64 scope link
       valid_lft forever preferred_lft forever
3: ens224: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:8a:72:64 brd ff:ff:ff:ff:ff:ff
    inet 172.16.60.214/24 brd 172.16.60.255 scope global ens224
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:fe8a:7264/64 scope link
       valid_lft forever preferred_lft forever
```

使用 route 或 routel 顯示網路路由表
- routel
```
joe@debian-privesc:~$ routel
         target            gateway          source    proto    scope    dev tbl
/usr/bin/routel: 48: shift: can't shift that many
        default     192.168.50.254                   static          ens192
    172.16.60.0 24                   172.16.60.214   kernel     link ens224
   192.168.50.0 24                  192.168.50.214   kernel     link ens192
      127.0.0.0          broadcast       127.0.0.1   kernel     link     lo local
      127.0.0.0 8            local       127.0.0.1   kernel     host     lo local
      127.0.0.1              local       127.0.0.1   kernel     host     lo local
127.255.255.255          broadcast       127.0.0.1   kernel     link     lo local
    172.16.60.0          broadcast   172.16.60.214   kernel     link ens224 local
  172.16.60.214              local   172.16.60.214   kernel     host ens224 local
  172.16.60.255          broadcast   172.16.60.214   kernel     link ens224 local
   192.168.50.0          broadcast  192.168.50.214   kernel     link ens192 local
 192.168.50.214              local  192.168.50.214   kernel     host ens192 local
 192.168.50.255          broadcast  192.168.50.214   kernel     link ens192 local
            ::1                                      kernel              lo
         fe80:: 64                                   kernel          ens224
         fe80:: 64                                   kernel          ens192
            ::1              local                   kernel              lo local
fe80::250:56ff:fe8a:7264              local                   kernel          ens224 local
fe80::250:56ff:fe8a:b9fc              local                   kernel          ens192 local
```
可以使用 netstat 或 ss 顯示活動的網路連接和監聽端口
- ss -anp
```
joe@debian-privesc:~$ ss -anp
Netid      State       Recv-Q      Send-Q                                        Local Address:Port                     Peer Address:Port
nl         UNCONN      0           0                                                         0:461                                  *
nl         UNCONN      0           0                                                         0:323                                  *
nl         UNCONN      0           0                                                         0:457                                  *
...
udp        UNCONN      0           0                                                      [::]:47620                            [::]:*
tcp        LISTEN      0           128                                                 0.0.0.0:22                            0.0.0.0:*
tcp        LISTEN      0           5                                                 127.0.0.1:631                           0.0.0.0:*
tcp        ESTAB       0           36                                           192.168.50.214:22                      192.168.118.2:32890
tcp        LISTEN      0           128                                                       *:80                                  *:*
tcp        LISTEN      0           128                                                    [::]:22                               [::]:*
tcp        LISTEN      0           5                                                     [::1]:631                              [::]:*
```
> `ss（Socket Statistics）`：比 `netstat` 更快更現代。\
`-a（all）`：顯示所有 socket，包含 LISTEN 和非 LISTEN 狀態的連線。\
`-n（numeric）`：以數字格式顯示地址和端口，避免解析 DNS（加快查詢速度）。\
`-p（process）`：顯示與每個 socket 關聯的 process 名稱（需要 root 權限）。
>> 可以看到目前連線的 SSH connection 和 listening socket

#### - firewall rules 
1. 主要注意評估的遠端利用階段防火牆的 state, profile, and rules，在提權也可能會使用到。
2. 收集有關 inbound 與 outbound port filtering 的資訊，以便在轉向內部網路時方便進行 port forwarding 和 tunneling 傳輸。
3. 必須具有 root 權限才能使用 iptables 列出防火牆規則，🥚 防火牆的 configured，可以作為一般使用者收集有關規則的資訊。其中也包含 `iptables-save` 創建的檔案，將 firewall configuration 轉存到 user 中

```
joe@debian-privesc:~$ cat /etc/iptables/rules.v4
# Generated by xtables-save v1.8.2 on Thu Aug 18 12:53:22 2022
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp -m tcp --dport 1999 -j ACCEPT
COMMIT
# Completed on Thu Aug 18 12:53:22 2022
```
>`-A INPUT -p tcp -m tcp --dport 1999 -j ACCEPT`: 允許所有連接到 TCP 1999 port 的流量進入 (可能是某個服務在監聽）

#### - cron ( job scheduler)
Scheduled tasks 在/etc/cron.* 目錄下，可以在/etc/cron.daily 下找到每天運行的任務。
```
joe@debian-privesc:~$ ls -lah /etc/cron*
-rw-r--r-- 1 root root 1.1K Oct 11  2019 /etc/crontab

/etc/cron.d:
total 24K
drwxr-xr-x   2 root root 4.0K Aug 16  2022 .
drwxr-xr-x 125 root root  12K Feb 15  2023 ..
-rw-r--r--   1 root root  285 May 19  2019 anacron
-rw-r--r--   1 root root  102 Oct 11  2019 .placeholder

/etc/cron.daily:
total 60K
drwxr-xr-x   2 root root 4.0K Aug 18  2022 .
drwxr-xr-x 125 root root  12K Feb 15  2023 ..
-rwxr-xr-x   1 root root  311 May 19  2019 0anacron
-rwxr-xr-x   1 root root  539 Aug  8  2020 apache2
-rwxr-xr-x   1 root root 1.5K Dec  7  2020 apt-compat
-rwxr-xr-x   1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x   1 root root  384 Dec 31  2018 cracklib-runtime
-rwxr-xr-x   1 root root 1.2K Apr 18  2019 dpkg
-rwxr-xr-x   1 root root 2.2K Feb 10  2018 locate
-rwxr-xr-x   1 root root  377 Aug 28  2018 logrotate
-rwxr-xr-x   1 root root 1.1K Feb 10  2019 man-db
-rwxr-xr-x   1 root root  249 Sep 27  2017 passwd
-rw-r--r--   1 root root  102 Oct 11  2019 .placeholder

/etc/cron.hourly:
total 20K
drwxr-xr-x   2 root root 4.0K Aug 16  2022 .
drwxr-xr-x 125 root root  12K Feb 15  2023 ..
-rw-r--r--   1 root root  102 Oct 11  2019 .placeholder

/etc/cron.monthly:
total 24K
drwxr-xr-x   2 root root 4.0K Aug 16  2022 .
drwxr-xr-x 125 root root  12K Feb 15  2023 ..
-rwxr-xr-x   1 root root  313 May 19  2019 0anacron
-rw-r--r--   1 root root  102 Oct 11  2019 .placeholder

/etc/cron.weekly:
total 28K
drwxr-xr-x   2 root root 4.0K Aug 16  2022 .
drwxr-xr-x 125 root root  12K Feb 15  2023 ..
-rwxr-xr-x   1 root root  3
```
> `/etc/crontab`, daily, hourly, monthly, weekly

系統管理員經常在 /etc/crontab 檔案中新增自己的排程任務\
檢查 /etc/crontab 檔案權限，通常需要以 root 編輯: `crontab -l`
```
joe@debian-privesc:~$ crontab -l
# Edit this file to introduce tasks to be run by cron.
#
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
#
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').
#
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
#
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
#
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
#
# For more information see the manual pages of crontab(5) and cron(8)
#
# m h  dom mon dow   command
```
> 只有 comment，這意味著 joe 沒有配置 cron 作業

嘗試使用 sudo，顯示由 root 執行的作業
```
joe@debian-privesc:~$ sudo crontab -l
[sudo] password for joe:
# Edit this file to introduce tasks to be run by cron.
...
# m h  dom mon dow   command

* * * * * /bin/bash /home/joe/.scripts/user_backups.sh
```
> 顯示了以 root 身分執行的備份腳本
> > 若這個 shell weak permissions，可以利用它來提權

#### - dpkg & rpm
package 管理器：\
Debian-based Linux distributions 使用 `dpkg`\
Red Hat-based systems 使用 `rpm`
```
joe@debian-privesc:~$ dpkg -l
Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name                                  Version                                      Architecture Description
+++-=====================================-============================================-============-===============================================================================
ii  accountsservice                       0.6.45-2                                     amd64        query and manipulate user account information
ii  acl                                   2.2.53-4                                     amd64        access control list - utilities
ii  adduser                               3.118                                        all          add and remove users and groups
ii  adwaita-icon-theme                    3.30.1-1                                     all          default icon theme of GNOME
ii  aisleriot                             1:3.22.7-2                                   amd64        GNOME solitaire card game collection
ii  alsa-utils                            1.1.8-2                                      amd64        Utilities for configuring and using ALSA
ii  anacron                               2.3-28                                       amd64        cron-like program that doesn't go by time
ii  analog                                2:6.0-22                                     amd64        web server log analyzer
ii  apache2                               2.4.38-3+deb10u7                             amd64        Apache HTTP Server
ii  apache2-bin                           2.4.38-3+deb10u7                             amd64        Apache HTTP Server (modules and other binary files)
ii  apache2-data                          2.4.38-3+deb10u7                             all          Apache HTTP Server (common files)
ii  apache2-doc                           2.4.38-3+deb10u7                             all          Apache HTTP Server (on-site documentation)
ii  apache2-utils                         2.4.38-3+deb10u7                             amd64        Apache HTTP Server (utility programs for web servers)
...
```
> 先前透過枚舉監聽 port 發現的，Debian 10 機器正在執行 Apache2 Web Server

#### - find
我們不可能手動檢查每個檔案權限，可以使用 find 來識別具有不安全權限的檔案
```
joe@debian-privesc:~$ find / -writable -type d 2>/dev/null
..
/home/joe
/home/joe/Videos
/home/joe/Templates
/home/joe/.local
/home/joe/.local/share
/home/joe/.local/share/sounds
/home/joe/.local/share/evolution
/home/joe/.local/share/evolution/tasks
/home/joe/.local/share/evolution/tasks/system
/home/joe/.local/share/evolution/tasks/trash
/home/joe/.local/share/evolution/addressbook
/home/joe/.local/share/evolution/addressbook/system
/home/joe/.local/share/evolution/addressbook/system/photos
/home/joe/.local/share/evolution/addressbook/trash
/home/joe/.local/share/evolution/mail
/home/joe/.local/share/evolution/mail/trash
/home/joe/.local/share/evolution/memos
/home/joe/.local/share/evolution/memos/system
/home/joe/.local/share/evolution/memos/trash
/home/joe/.local/share/evolution/calendar
/home/joe/.local/share/evolution/calendar/system
/home/joe/.local/share/evolution/calendar/trash
/home/joe/.local/share/icc
/home/joe/.local/share/gnome-shell
/home/joe/.local/share/gnome-settings-daemon
/home/joe/.local/share/keyrings
/home/joe/.local/share/tracker
/home/joe/.local/share/tracker/data
/home/joe/.local/share/folks
/home/joe/.local/share/gvfs-metadata
/home/joe/.local/share/applications
/home/joe/.local/share/nano
/home/joe/Downloads
/home/joe/.scripts
/home/joe/Pictures
/home/joe/.cache

...
```
> `find /`：從根目錄開始搜尋\
`-writable`：只篩選可寫入 (writable) 的檔案或目錄\
`-type d`：只顯示目錄 (directory)\
`2>/dev/null`：將錯誤訊息 (stderr) 導向到 /dev/null
>> 幾個目錄似乎是 world-writable，包括 `/home/joe/.scripts` 目錄，可以對應到之前找到的 cron 腳本的位置。

#### - mount & /etc/fstab
在大多數系統上， drives 在啟動時會自動安裝。因此，我們很容易忘記可能包含有價值資訊的 unmounted drives。如果 unmounted drives 存在，則可以檢查安裝權限。
- mount: 列出所有已掛載的檔案系統
- /etc/fstab: 列出了啟動時將安裝的所有 drives

```
joe@debian-privesc:~$ cat /etc/fstab 
...
UUID=60b4af9b-bc53-4213-909b-a2c5e090e261 /               ext4    errors=remount-ro 0       1
# swap was on /dev/sda5 during installation
UUID=86dc11f3-4b41-4e06-b923-86e78eaddab7 none            swap    sw              0       0
/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0

joe@debian-privesc:~$ mount
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
udev on /dev type devtmpfs (rw,nosuid,relatime,size=1001064k,nr_inodes=250266,mode=755)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)
tmpfs on /run type tmpfs (rw,nosuid,noexec,relatime,size=204196k,mode=755)
/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)
securityfs on /sys/kernel/security type securityfs (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
tmpfs on /run/lock type tmpfs (rw,nosuid,nodev,noexec,relatime,size=5120k)
tmpfs on /sys/fs/cgroup type tmpfs (ro,nosuid,nodev,noexec,mode=755)
cgroup2 on /sys/fs/cgroup/unified type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate)
cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
pstore on /sys/fs/pstore type pstore (rw,nosuid,nodev,noexec,relatime)
bpf on /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,relatime,mode=700)
...
systemd-1 on /proc/sys/fs/binfmt_misc type autofs (rw,relatime,fd=25,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=10550)
mqueue on /dev/mqueue type mqueue (rw,relatime)
debugfs on /sys/kernel/debug type debugfs (rw,relatime)
hugetlbfs on /dev/hugepages type hugetlbfs (rw,relatime,pagesize=2M)
tmpfs on /run/user/117 type tmpfs (rw,nosuid,nodev,relatime,size=204192k,mode=700,uid=117,gid=124)
tmpfs on /run/user/1000 type tmpfs (rw,nosuid,nodev,relatime,size=204192k,mode=700,uid=1000,gid=1000)
binfmt_misc on /proc/sys/fs/binfmt_misc type binfmt_misc (rw,relatime)
```
> `/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)`:顯示了一個交換分割區 (swap partition) 和該 Linux 系統的主 ext4 磁碟。

>[!Tip]
>System administrator might have used custom configurations or scripts to mount drives that are not listed in the `/etc/fstab` file. Because of this, it's good practice to not only scan `/etc/fstab`, but to also gather information about mounted drives using `mount`.

#### - lsblk (all available disks)
```
joe@debian-privesc:~$ lsblk
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
sda      8:0    0   32G  0 disk
|-sda1   8:1    0   31G  0 part /
|-sda2   8:2    0    1K  0 part
`-sda5   8:5    0  975M  0 part [SWAP]
sr0     11:0    1 1024M  0 rom
```
> sda drive 由三個不同編號的分割區組成，可以透過 system configuration 收集 documents 或 credentials

#### - lsmod (drivers and kernel modules)
另一種常見的提權技術利用 device drivers 和 kernel modules，可以使用 `lsmod` enumerate drivers and kernel modules

```
joe@debian-privesc:~$ lsmod
Module                  Size  Used by
binfmt_misc            20480  1
rfkill                 28672  1
sb_edac                24576  0
crct10dif_pclmul       16384  0
crc32_pclmul           16384  0
ghash_clmulni_intel    16384  0
vmw_balloon            20480  0
...
drm                   495616  5 vmwgfx,drm_kms_helper,ttm
libata                270336  2 ata_piix,ata_generic
vmw_pvscsi             28672  2
scsi_mod              249856  5 vmw_pvscsi,sd_mod,libata,sg,sr_mod
i2c_piix4              24576  0
button                 20480  0
```
> `libata                270336  2 ata_piix,ata_generic`: 以使用 modinfo 來了解有關特定模組的更多資訊: `/sbin/modinfo`

/sbin/modinfo
```
joe@debian-privesc:~$ /sbin/modinfo libata
filename:       /lib/modules/4.19.0-21-amd64/kernel/drivers/ata/libata.ko
version:        3.00
license:        GPL
description:    Library module for ATA devices
author:         Jeff Garzik
srcversion:     00E4F01BB3AA2AAF98137BF
depends:        scsi_mod
retpoline:      Y
intree:         Y
name:           libata
vermagic:       4.19.0-21-amd64 SMP mod_unload modversions
sig_id:         PKCS#7
signer:         Debian Secure Boot CA
sig_key:        4B:6E:F5:AB:CA:66:98:25:17:8E:05:2C:84:66:7C:CB:C0:53:1F:8C
...
```
> 獲得了驅動程式及版本，可以更好地找到相關的漏洞。

#### - SUID 
- setuid：當檔案的所有者是 root 且該檔案具有 setuid 權限時，任何使用者執行該檔案時，會以 root 的權限來執行該檔案。
- setgid：當檔案具有 setgid 權限時，執行該檔案的使用者會繼承檔案所屬群組的權限。
- UID/GID（eUID/eGID）：當使用者或系統腳本啟動一個具有 SUID 權限的應用程式時，這個應用程式會繼承發起該腳本的使用者或群組的 UID/GID，這被稱為**有效 UID/GID**（eUID, eGID）。

這些特殊權限會改變檔案執行的權限方式。通常，執行檔案的使用者會繼承該檔案的執行權限。但當檔案設有 SUID 權限，該檔案將會以檔案擁有者（通常是 root）的身份執行。這意味著如果一個二進位檔案（binary）設有 SUID 且由 root 擁有，那麼任何本地使用者都可以以 root 權限執行這個檔案，進而提升權限。
👉🏻 如果能夠讓一個具有 SUID 權限的 root 程式執行自己選擇的命令，則可以模擬 root 使用者的身份，獲得所有系統權限。

使用 find 搜尋帶有 SUID 標記的二進位檔案
```
joe@debian-privesc:~$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/chsh
/usr/bin/fusermount
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/ntfs-3g
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/bwrap
/usr/bin/su
/usr/bin/umount
/usr/bin/mount
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/xorg/Xorg.wrap
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/pppd
```
> `-type f`：僅搜尋檔案\
`-perm -u=s`：篩選出設有 SUID 權限的檔案

如果 /bin/cp（複製命令）是 SUID，我們可以複製並覆寫敏感文件，如 /etc/passwd。

### Automated Enumeration
