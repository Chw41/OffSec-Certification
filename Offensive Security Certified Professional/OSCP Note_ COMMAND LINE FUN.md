---
title: 'OSCP Note_ COMMAND LINE FUN'
disqus: hackmd
---

OSCP Note_ COMMAND LINE FUN
===

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

