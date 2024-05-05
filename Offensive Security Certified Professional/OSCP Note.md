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
1. /bin/: basic program 
> ex. ls, cd, cat
2. /sbin/: system program
> ex. fdisk, mkfs, sysctl
3. /etc/: configuration file
4. /tmp/: temporary file
5. /usr/bin/: application
> ex. apt, ncat, nmap
6. /usr/share/: application support & data file

### - Basic linux command

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

### - Finding Files in Kali Linux

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



## Managing Kali Linux Service
Ex. SSH, HTTTP, MySQL

### - SSH Service

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

### - HTTP Service

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

## Searching, Installing, And Removing Tools
Apt is a set of tool that help manage package or application on a debian system.

### - APT Update

update system package lists from the repositories specified in the /etc/apt/sources.list file and in the /etc/apt/sources.list.d/ directory. These lists contain information about available packages and their versions.
```
sudo apt update
```

### - APT Upgrade

After update the apt database, we can updgrade the installed packages and core system to the lastest version
```
sudo apt upgrade
```
upgrade the single package
```
sudo apt upgrade metasploit-framework
```

### - APT-Cache Search And APT Show


#### 1. 搜尋套件名稱或描述關鍵字: APT-Cache
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

#### 2. 顯示特定套件的詳細資訊: APT Show
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

### - APT Install

Use APT Install command to add a package to the system.
![image](https://hackmd.io/_uploads/BJZl2UR-A.png)

### - APT Remove --purge
APT Remove --purge command completely remove package from kali.
> remove all package data but leave user configuration file behind. 
> Add the --purge option: remove all the left over including configuration file.

![image](https://hackmd.io/_uploads/ByYM0U0ZC.png)

### - DPKG
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

## Wrapping Up
Set a base line for the upcoming module.

# COMMAND LINE FUN
Introdution of few popular linux command line programs

## The Bash Environment
Bash is a shell that allows to run complex commands and perform different tasks from the terminal window.
### - Environment Variables
```
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ echo $PATH
/home/frankchang/.local/bin:/usr/local/sbin:/usr/local/bin:/...
```
>echo $PATH 是一個在 Unix-like 系統中常見的命令。它用來顯示系統中搜尋可執行檔案的路徑。

```
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ echo $USER
frankchang
> 顯示當前使用者（登錄使用者）的使用者名稱

┌──(frankchang㉿CHW-Macbook)-[~]
└─$ echo $PWD
/home/frankchang
> 顯示當前工作目錄的路徑

┌──(frankchang㉿CHW-Macbook)-[~]
└─$ echo $HOME
/home/frankchang
> 顯示當前使用者的家目錄路徑
```
#### export command
If we're scanning a target and don't want to type in the system's IP address repeatedly.
```
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ export a=127.2.3.4

┌──(frankchang㉿CHW-Macbook)-[~]
└─$ ping -c 4 $a
PING 127.2.3.4 (127.2.3.4) 56(84) bytes of data.
64 bytes from 127.2.3.4: icmp_seq=1 ttl=64 time=5.45 ms
64 bytes from 127.2.3.4: icmp_seq=2 ttl=64 time=0.027 ms
64 bytes from 127.2.3.4: icmp_seq=3 ttl=64 time=0.022 ms
64 bytes from 127.2.3.4: icmp_seq=4 ttl=64 time=0.024 ms

--- 127.2.3.4 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3053ms
rtt min/avg/max/mdev = 0.022/1.380/5.447/2.348 ms
```
```
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ var="CHW"
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ echo $var
CHW       
> variable in the current shell

┌──(frankchang㉿CHW-Macbook)-[~]
└─$ bash              
> new bash instance
> replce the variable again

┌──(frankchang㉿CHW-Macbook)-[~]
└─$ echo $var

┌──(frankchang㉿CHW-Macbook)-[~]
└─$ exit
exit
> exit bash section, back to original section
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ echo $var
CHW
```
● Global Variables
```
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ export othervar="Global Var"

┌──(frankchang㉿CHW-Macbook)-[~]
└─$ echo $othervar
Global Var

┌──(frankchang㉿CHW-Macbook)-[~]
└─$ bash
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ echo $othervar
Global Var
```
#### env command
Enviroment Variables
```
chw@Ubuntu22:~$ env
SHELL=/bin/bash
SESSION_MANAGER=local/Ubuntu22:@/tmp/...
```

### - Tab Completion

Bash shell auto complete function allows to complete file name and directory path with the TAB key.

### - Bash History Tricks

```
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ history
  983  ssh -i "team3" root$104.199.222.116
  984  ssh -i "team3" root@104.199.222.116
  985  ssh -i "privatekey.ppk" root@104.199.222.116
  986  ping 10.101.3.2
  987  dirb http://10.102.2.20:8763/
  988  salmap http://10.102.5.20:8763/board/5?category=70 --batch --dbs
  ...
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ !1108
rm -rf git/
```
**● !!: repeat the last command**
```
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ !!
history
  983  ssh -i "team3" root$104.199.222.116
  984  ssh -i "team3" root@104.199.222.116
  985  ssh -i "privatekey.ppk" root@104.199.222.116
  986  ping 10.101.3.2
  987  dirb http://10.102.2.20:8763/
```
**● tail:用於顯示文件的末尾幾行**
> 顯示文件末尾幾行: `tail filename`
> 指定行數: `tail -n 10 filename`
> 持續顯示內容: `tail -f filename`

```
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ tail -n 3 .bash_history
exit
echo $othervar
exit
```
#### $HISTSIZE
> 用於設置命令歷史記錄的大小（也就是保存多少條歷史命令）

Size controlls the number of commands stored in memory for the current section.
```
export HISTSIZE=1000
```

#### $HISTFILESIZE
> 設置命令歷史文件的大小（也就是保存在磁盤上的歷史記錄文件的大小）

Can figureout how many command are caped in history file
```
export HISTFILESIZE=2000
```
#### Ctrl + R
invoke the Reverse-i-search facility
> 可以開始輸入你要搜索的內容。終端會根據你輸入的內容，在命令歷史中進行反向搜索，並顯示匹配的最近的命令。一旦找到符合的命令，你可以按下 Enter 鍵來執行該命令，或者按下 Ctrl + R 繼續搜索下一個匹配。


## Piping And Redirection
![image](https://hackmd.io/_uploads/B1Ga0skf0.png)
### - Redirecting To A New File

#### Right-angle brake operator 
![image](https://hackmd.io/_uploads/H1t9EnyMR.png)
![image](https://hackmd.io/_uploads/SJGQr2kzC.png)

### - Redirecting To An Existing File

#### Double Right-angle brake operator 
![image](https://hackmd.io/_uploads/HJvhH21MA.png)
```
┌──(frankchang㉿CHW-Macbook)-[/mnt/c/Users/User/Desktop]
└─$ echo "Hi L1" > test.txt
┌──(frankchang㉿CHW-Macbook)-[/mnt/c/Users/User/Desktop]
└─$ cat test.txt
Hi L1
┌──(frankchang㉿CHW-Macbook)-[/mnt/c/Users/User/Desktop]
└─$ echo "Hi L2" >> test.txt
┌──(frankchang㉿CHW-Macbook)-[/mnt/c/Users/User/Desktop]
└─$ cat test.txt
Hi L1
Hi L2
```

### - Redirecting From a File

We can use the Left-angle bracket operator to send data another way.

#### Left-angle brake operator 
Ex. We will redirect the wc command standard input with data originating from the file regenerated in the previous section.
```
┌──(frankchang㉿CHW-Macbook)-[/mnt/c/Users/User/Desktop]
└─$ cat test.txt
Hi L1
Hi L2

┌──(frankchang㉿CHW-Macbook)-[/mnt/c/Users/User/Desktop]
└─$ wc -m < test.txt
12
```
> wc 命令統計了 test.txt 文件中的字元數

### - Redirecting STDERR

According to the posix specification the file descriptors for standard input, standard output and standard error are defined as 0 1 and 2 respectively these numbers are important. 
They can be used to manipulate the corresponding data streams from the command line while **executing or joining different commands together to get a better grasp** of how the file descriptor numbers work
```
┌──(frankchang㉿CHW-Macbook)-[/mnt/c/Users/User/Desktop]
└─$ ls ./test
ls: cannot access './test': No such file or directory

┌──(frankchang㉿CHW-Macbook)-[/mnt/c/Users/User/Desktop]
└─$ ls ./test 2> error.txt

┌──(frankchang㉿CHW-Macbook)-[/mnt/c/Users/User/Desktop]
└─$ cat error.txt
ls: cannot access './test': No such file or directory
```

### - Piping

![image](https://hackmd.io/_uploads/HJFRCh1z0.png)
> 允許將一個命令的輸出作為另一個命令的輸入

## Text Searching And Manipulation
Gain efficiency with file and text tempering by introducing a few command.
Ex. GREP, SED, CUT and AWK.
### - GREP

```
┌──(frankchang㉿CHW-Macbook)-[/mnt/c/Users/User/Desktop]
└─$ ls -al /usr/bin | grep zip
-rwxr-xr-x  3 root root       39224 Sep 19  2022 bunzip2
-rwxr-xr-x  3 root root       39224 Sep 19  2022 bzip2
-rwxr-xr-x  1 root root       14568 Sep 19  2022 bzip2recover
-rwxr-xr-x  1 root root       23000 Feb 20  2023 funzip
...
```
> -i：忽略大小寫，使搜索不區分大小寫。
-v：顯示不匹配的行。
-r：遞迴地搜尋目錄。 依預設，會/不會遵循目錄的鏈結。
-n：顯示匹配行的行號。
-l：僅顯示包含匹配文本的文件名，而不顯示匹配的行內容。
```
(grep -n 差異)
┌──(frankchang㉿CHW-Macbook)-[/mnt/c/Users/User/Desktop]
└─$ ls -al /usr/bin | grep -n zip
80:-rwxr-xr-x  3 root root       39224 Sep 19  2022 bunzip2
89:-rwxr-xr-x  3 root root       39224 Sep 19  2022 bzip2
90:-rwxr-xr-x  1 root root       14568 Sep 19  2022 bzip2recover
...
┌──(frankchang㉿CHW-Macbook)-[/mnt/c/Users/User/Desktop]
└─$ ls -al /usr/bin | grep zip
-rwxr-xr-x  3 root root       39224 Sep 19  2022 bunzip2
-rwxr-xr-x  3 root root       39224 Sep 19  2022 bzip2
-rwxr-xr-x  1 root root       14568 Sep 19  2022 bzip2recover
-rwxr-xr-x  1 root root       23000 Feb 20  2023 funzip
```
● [Linux manual page: grep](https://man7.org/linux/man-pages/man1/grep.1.html)


### - SED

A powerful string editor also very complex.
![image](https://hackmd.io/_uploads/SySAdgBGR.png)
> echo "I need to try hard"
> Sed 將echo中找到的所有'hard'，更改為'harder'
```
sed 's/old_pattern/new_pattern/g' input_file
```
> 將在 input_file 中尋找所有的 old_pattern，並將其替換為 new_pattern。
```
sed '/pattern_to_delete/d' input_file
```
> 刪除 input_file 中尋找所有的 pattern_to_delete
```
sed '1i\inserted_text' input_file
```
> 將在 input_file 的第一行之前插入指定的文本(inserted_text)。


### - CUT

The cut command is simple but often comes in quite handy.
```
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ echo "I hack binaries,web apps,mobile apps, and just about anything else" | cut -f 2 -d ","
web apps
```
> -d "," 使用逗號作為分隔符，並指定 -f 2 來提取第二個字段
```
cut -d':' -f1 /etc/passwd

┌──(frankchang㉿CHW-Macbook)-[~]
└─$ cut -d':' -f1 /etc/passwd
root
daemon
bin
sys
...
```
> /etc/passwd 中提取以冒號分隔的每行的第一個字段，即使用者名稱

### - AWK

It's a programing language design for text processing. For data extraction and reporting tool.
```
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ echo "hello::there::friend" | awk -F "::" '{print $1, $3}'
hello friend
```
> -F "::" 使用::作為分隔，列印出的第一個與的第三個字串
```
awk '$3 > 100 {print $1, $3}' input_file
```
> input_file 中選擇所有第三個字段值大於 100 的行，並打印出每行的第一個和第三個字段。

```
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ cut -d':' -f1 /etc/passwd
┌──(frankchang㉿CHW-Macbook)-[~]
└─$ awk -F':' '{print $1}' /etc/passwd

#會顯示一樣的結果，awk is more flexible
```
### - Pactical Example

