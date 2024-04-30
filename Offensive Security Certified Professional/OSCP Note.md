---
title: 'OSCP Note'
disqus: hackmd
---

OSCP Note
===

# Table of Contents
[TOC]
# GETTING COMFORTABLE WITH KALI LINUX
## The Kali menu
![image](https://hackmd.io/_uploads/B1K61lx-0.png)

## Kali documentation
● https://www.kali.org/docs/

● https://forums.kali.org/

● https://www.kali.org/tools/

● https://bugs.kali.org/

● https://kali.training/

## Finding Your Way Around KALI

### - The linux filesystem
:::spoiler
1. /bin/: basic program 
> ex. ls, cd, cat
2. /sbin/: system program
> ex. fdisk, mkfs, sysctl
3. /etc/: configuration file
4. /tmp/: temporary file
5. /usr/bin/: application
> ex. apt, ncat, nmap
6. /usr/share/: application support & data file
:::
### - Basic linux command
:::spoiler
#### Man pages
```command
man ls
```
![image](https://hackmd.io/_uploads/r1DBSlx-0.png)

Ex.
```
man passwd
```
![image](https://hackmd.io/_uploads/HkycHleb0.png)

```
man -k passwd
```
> -k: keyword search

![image](https://hackmd.io/_uploads/BkaASlxW0.png)

Quickly to find documentation
```
──(frankchang㉿CHW-Macbook)-[~]
└─$ man -k ^'passwd$'
passwd (1)           - change user password
passwd (1ssl)        - OpenSSL application commands
passwd (5)           - the password file

┌──(frankchang㉿CHW-Macbook)-[~]
└─$ man 5 passwd
```
#### apropos
Find particular command based on description
```
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ apropos partition
addpart (8)          - tell the kernel about the existence of a partition
cfdisk (8)           - display or manipulate a disk partition table
delpart (8)          - tell the kernel to forget about a partition
fdisk (8)            - manipulate disk partition table
mmcat (1)            - Output the contents of a partition to stdout
mmls (1)             - Display the partition layout of a volume system (partition tables)
mmstat (1)           - Display details about the volume system (partition tables)
parted (8)           - a partition manipulation program
partprobe (8)        - inform the OS of partition table changes
partx (8)            - tell the kernel about the presence and numbering of on-disk partitions
repart.d (5)         - Partition Definition Files for Automatic Boot-Time Repartitioning
resizepart (8)       - tell the kernel about the new size of a partition
sfdisk (8)           - display or manipulate a disk partition table
systemd-gpt-auto-generator (8) - Generator for automatically discovering and mounting root, /home/, /srv/, /var/ and /var/tmp/ partitions, as well as discovering and enabling swap partit...
systemd-repart (8)   - Automatically grow and add partitions
systemd-repart.service (8) - Automatically grow and add partitions
```
```
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ man -k partition
addpart (8)          - tell the kernel about the existence of a partition
cfdisk (8)           - display or manipulate a disk partition table
delpart (8)          - tell the kernel to forget about a partition
fdisk (8)            - manipulate disk partition table
mmcat (1)            - Output the contents of a partition to stdout
mmls (1)             - Display the partition layout of a volume system (partition tables)
mmstat (1)           - Display details about the volume system (partition tables)
parted (8)           - a partition manipulation program
partprobe (8)        - inform the OS of partition table changes
partx (8)            - tell the kernel about the presence and numbering of on-disk partitions
repart.d (5)         - Partition Definition Files for Automatic Boot-Time Repartitioning
resizepart (8)       - tell the kernel about the new size of a partition
sfdisk (8)           - display or manipulate a disk partition table
systemd-gpt-auto-generator (8) - Generator for automatically discovering and mounting root, /home/, /srv/, /var/ and /var/tmp/ partitions, as well as discovering and enabling swap partit...
systemd-repart (8)   - Automatically grow and add partitions
systemd-repart.service (8) - Automatically grow and add partitions
```

#### Listing Files
```
ls
```
```
ls -al
```
#### Moving Around
```
cd
```
```
pwd #current dir
```
```
cd ~
```
#### Creating Directories
```
mkdir [dir]
```
```
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ mkdir module one

┌──(frankchang㉿CHW-Macbook)-[~]
└─$ ls
module  one  reports
-----------------------------------
──(frankchang㉿CHW-Macbook)-[~]
└─$ mkdir "module one"

┌──(frankchang㉿CHW-Macbook)-[~]
└─$ ls
'module one'   reports
```
```
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ mkdir -p test/{recon,exploit,report}

┌──(frankchang㉿CHW-Macbook)-[~]
└─$ ls -l test/
total 12
drwxr-xr-x 2 frankchang frankchang 4096 Apr 19 21:59 exploit
drwxr-xr-x 2 frankchang frankchang 4096 Apr 19 21:59 recon
drwxr-xr-x 2 frankchang frankchang 4096 Apr 19 21:59 report
```
:::
### - Finding Files in Kali Linux
:::spoiler
Ex: find, locate, which
```
which
```
![image](https://hackmd.io/_uploads/ryiElqz-C.png)
```
locate #quickliest way
```
![image](https://hackmd.io/_uploads/S1mCg5fWR.png)
```
find #complex & flexible

┌──(frankchang㉿CHW-Macbook)-[~]
└─$ sudo find / -name fr*
/var/cache/man/fr
/home/frankchang
/home/frankchang/.local/lib/python3.11/site-packages/anyio/__pycache__/from_thread.cpython-311.pyc
/home/frankchang/.local/lib/python3.11/site-packages/anyio/from_thread.py
...
```
**Find can searched by file age, size, owner, file type, timestamp, permission and more.**
:::


## Managing Kali Linux Service
Ex. SSH, HTTTP, MySQL

### - SSH Service
:::spoiler
```
sudo systemctl start ssh
```
```
sudo ss -antlp | grep sshd
```
![image](https://hackmd.io/_uploads/S1EPq9mZ0.png)

```
sudo systemctl enable ssh
```
![image](https://hackmd.io/_uploads/BkNq59m-C.png)

:::
### - HTTP Service
:::spoiler
```
sudo systemctl start apache2
```
```
sudo ss -antlp | grep apache
```
![image](https://hackmd.io/_uploads/rklIo9m-0.png)

```
sudo systemctl enable apache2
```

**To see the table of all avaliable service**
```
systemctl list-unit-files
```
![image](https://hackmd.io/_uploads/SyKJ257ZA.png)

:::

## Searching, Installing, And Removing Tools
Apt is a set of tool that help manage package or application on a debian system.

### - APT Update
:::spoiler
update system package lists from the repositories specified in the /etc/apt/sources.list file and in the /etc/apt/sources.list.d/ directory. These lists contain information about available packages and their versions.
```
sudo apt update
```
:::
### - APT Upgrade
:::spoiler
After update the apt database, we can updgrade the installed packages and core system to the lastest version
```
sudo apt upgrade
```
upgrade the single package
```
sudo apt upgrade metasploit-framework
```
:::
### - APT-Cache Search And APT Show
:::spoiler

#### 1. 搜尋套件名稱或描述關鍵字: APT-Cache**
The APT-Cache search command display much information stored in the internal cache package database.
Ex. pure-ftpd application
(1) Find out whether or not the application is presented in Kali linux repository.
```
apt-cache search pure-ftpd
```
```
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ apt-cache search pure-ftpd
pure-ftpd - Secure and efficient FTP server
pure-ftpd-common - Pure-FTPd FTP server (Common Files)
pure-ftpd-ldap - Secure and efficient FTP server with LDAP user authentication
pure-ftpd-mysql - Secure and efficient FTP server with MySQL user authentication
pure-ftpd-postgresql - Secure and efficient FTP server with PostgreSQL user authentication
resource-agents - Cluster Resource Agents
```
> 1. pure-ftpd: 這是一個安全且效率高的FTP伺服器軟體。
> 2. pure-ftpd-common: 這是Pure-FTPd FTP伺服器的通用檔案，可能包括共享的配置檔案、日誌和其他相關資源。
> 3. pure-ftpd-ldap: 這個套件提供了使用LDAP（輕量級目錄訪問協定）進行使用者身份驗證的安全而有效的FTP伺服器。
> 4. pure-ftpd-mysql: 這個套件提供了使用MySQL進行使用者身份驗證的安全而有效的FTP伺服器。
> 5. pure-ftpd-postgresql: 這個套件提供了使用PostgreSQL進行使用者身份驗證的安全而有效的FTP伺服器。
> 6. 最後一行則是另外一個套件的名稱：resource-agents，這是一個用於群集系統的資源代理軟體，與前面列出的Pure-FTPd套件無關。

#### 2. 顯示特定套件的詳細資訊: APT Show**
```
apt show resource-agents | less
```
```
Package: resource-agents
Version: 1:4.13.0-1
Priority: optional
Section: admin
Maintainer: Debian HA Maintainers <debian-ha-maintainers@alioth-lists.debian.net>
Installed-Size: 3,087 kB
Provides: resource-agents-dev
Depends: libc6 (>= 2.34), libnet1 (>= 1.1.2.1), libplumb2, libqb100 (>= 2.0.1), python3:any, bc, cluster-glue, gawk
Recommends: libxml2-utils, net-tools, python3-googleapi
Homepage: https://github.com/ClusterLabs/resource-agents
...
```
:::

### - APT Install
:::spoiler
Use APT Install command to add a package to the system.
![image](https://hackmd.io/_uploads/BJZl2UR-A.png)

:::

### - APT Remove --purge
:::spoiler
APT Remove --purge command completely remove package from kali.
> remove all package data but leave user configuration file behind. 
> Add the --purge option: remove all the left over including configuration file.
> 

![image](https://hackmd.io/_uploads/ByYM0U0ZC.png)
:::

### - DPKG
:::spoiler
DPKG is the core tool used to install the package.
Either directly or indirectly through apt.
preferred tools that used when operating offline or not required internet connection.
```
sudo dpkg -i ./{PATH}
```
![image](https://hackmd.io/_uploads/Bk6pJvAWC.png)
> Install packages: -i
> Remove packages: -r 
> Remove packages along with their configuration files: -P
> Display details of installed packages: -s

:::

## Wrapping Up
Set a base line for the upcoming module.

# COMMAND LINE FUN
