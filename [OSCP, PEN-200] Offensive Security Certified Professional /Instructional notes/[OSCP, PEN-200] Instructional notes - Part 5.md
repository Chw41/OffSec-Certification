---
title: '[OSCP, PEN-200] Instructional notes - Part 5'
disqus: hackmd
---

[OSCP, PEN-200] Instructional notes - Part 5
===

# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 1"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/README.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 2"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%202.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 3"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%203.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 4"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%204.md)

>[!Caution]
> 接續 [[OSCP, PEN-200] Instructional notes - Part 4](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%204.md) 內容

# Port Redirection and SSH Tunneling
## … SSH Tunneling ([Instructional notes - Part 4](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%204.md))
## Port Forwarding with Windows Tools
上述接說明 Linux-based 的 tunnel tools。 Windows 也有幾種 port forward 與 tunnel 的方法
### ssh.exe
Windows 內建 SSH: 自 2018 年 4 月 ([1803 版本](https://devblogs.microsoft.com/commandline/windows10v1803/#openssh-based-client-and-server)) 起內建 OpenSSH client，可以在 `%systemdrive%\Windows\System32\OpenSSH` 找到：
- ssh.exe
- scp.exe
- sftp.exe

這個 SSH client 可以用來連接任何支援 SSH 的伺服器（不限於 Windows SSH Server）

[環境範例]
MULTISERVER03（Win
