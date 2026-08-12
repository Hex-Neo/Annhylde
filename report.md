# huilan-boot 代码安全审计报告

## 一、审计范围与方法

- **审计目标**：`C:\Users\33589\Desktop\huilan-boot\huilan-boot`
- **技术栈**：SpringBlade 2.7.1（bladex）+ Spring Boot 2.2.13 + MyBatis-Plus 3.4.1 + Undertow，`context-path=/ygzs`，端口 9085
- **审计方式**：团队模式（4 个子审计员）+ 主会话复核验证
- **判定标准**：仅当「可达 / 可控 / 可传播 / 可利用 / 可复现」全部成立且提供 Payload 时写为**确认漏洞**；证据不足的写为**高风险线索**

### 总体结论（摘要）

| 等级 | 数量 | 说明 |
|---|---|---|
| 严重/高危（确认） | 6 | 未授权 token 签发、未授权用户枚举+密码哈希泄露、SQL 注入（列名注入）、任意注册、任意文件删除、OSS/密钥硬编码 |
| 中危（确认） | 2 | 越权 IDOR（读/写）、Druid 监控弱口令 |
| 高风险线索 | 2 | 上传扩展名校验不完整、XXE 风险（POI/XML 解析） |

---

## 二、确认漏洞

### V-01 未授权 Token 签发：`/blade-auth/oauth/appdevicetoken` 仅凭 deviceId 换取任意用户 JWT

- **严重等级**：严重
- **受影响入口**：`POST /ygzs/blade-auth/oauth/appdevicetoken`
- **鉴权要求**：无（`/blade-auth/**` 已在 `BladeConfiguration.java:55` 排除，`SecureRegistry.defaultExcludePatterns` 另有 `/auth/**`、`/token/**`）
- **用户可控输入**：`deviceId`（`@RequestParam`）
- **Source-to-sink 调用链**：
  `BladeTokenEndPoint.appdevicetoken` (BladeTokenEndPoint.java:306-350) →
  `TokenGranterBuilder.getGranter(grantType)` 默认取 `password` granter（TokenGranterBuilder.java:58） →
  `PasswordTokenGranter.grant` 走 `else if (isNotBlank(deviceId))` 分支（PasswordTokenGranter.java:83-88）：
  `userc.setDeviceId(deviceId); userService.getOne(Condition.getQueryWrapper(userc)); userInfo = userService.userInfo(user.getId())` →
  `UserServiceImpl.userInfo(String userId)` → `baseMapper.selectById(userId)` + `buildUserInfo` → `TokenUtil.createAuthInfo` 签发有效 JWT
- **Sink**：`TokenUtil.createAuthInfo(userInfo)`（TokenUtil.java:80）
- **同源/相似受影响路由**：`/blade-auth/oauth/appfacetoken`（仅凭 `userId`/faceId，BladeTokenEndPoint.java:259-303）
- **防护判断**：`PasswordTokenGranter` 的 `deviceId`/`userId` 分支**不校验密码、不校验验证码**；`appdevicetoken` 方法本身也不检查验证码。获取到任意合法 JWT 后可访问所有未注解接口并携带该用户的角色/租户身份
- **安全 Payload**：
  ```
  POST /ygzs/blade-auth/oauth/appdevicetoken?deviceId=admin的deviceId HTTP/1.1
  Host: <授权测试主机>
  Content-Type: application/x-www-form-urlencoded
  Connection: close
  ```
- **影响**：任意用户身份冒充；结合 V-02/V-03/V-05 可读取/篡改任意业务数据、上传/删除文件
- **证据文件与行号**：`huilan-common/huilan-core-system/src/main/java/org/springblade/modules/auth/endpoint/BladeTokenEndPoint.java:306-350`、`.../auth/granter/PasswordTokenGranter.java:77-89`、`.../auth/provider/TokenGranterBuilder.java:57-63`、`.../common/config/BladeConfiguration.java:55`
- **限制说明**：需知道目标用户的 `deviceId`（通常为设备唯一标识，可通过 `/user/searchInfo` 用户枚举+信息泄露获取，见 V-04）；deviceId 在用户首次绑定后写入数据库

---

### V-02 未授权用户枚举与密码哈希泄露：`/user/searchInfoByOpenID`、`/user/searchInfo`

- **严重等级**：高危
- **受影响入口**：`POST /ygzs/user/searchInfoByOpenID`、`POST /ygzs/user/searchInfo`
- **鉴权要求**：无（`/user/**` 在 `application.yml:193` 的 `blade.secure.skip-url` 中整体放行）
- **用户可控输入**：`openId`（`@RequestParam`）；`searchInfo` 为 `@RequestBody User`
- **Source-to-sink 调用链**：
  `RegisterController.searchInfoByOpenID` (RegisterController.java:101-115) →
  `userService.getOne(new LambdaQueryWrapper<User>().eq(User::getCid, openId))` →
  `R.data(user)` **直接返回完整 `User` 实体对象**
- **Sink**：`R.data(user)`（RegisterController.java:113）——`User.java` 中 `password` 字段（User.java:58）**无 `@JsonIgnore`**，Jackson 默认序列化，返回体含 `password`（MD5 哈希）、`mobile`、`email`、`faceId`、`deviceId`、`roleId` 等全部字段
- **同源/相似受影响路由**：`/user/searchInfo`（RegisterController.java:72-94）可作为**密码 oracle**：传 `account`+`password`，响应 `status=1` 表示「密码已更新」（即账号密码匹配成功），可用于暴力破解
- **防护判断**：skip-url 放行 + 无任何业务校验；实体直接回显
- **安全 Payload**：
  ```
  POST /ygzs/user/searchInfoByOpenID?openId=oXxxxxxxx HTTP/1.1
  Host: <授权测试主机>
  Content-Type: application/x-www-form-urlencoded
  Connection: close
  ```
- **影响**：任意用户完整信息（含密码哈希、手机号、openId/deviceId/faceId）泄露；泄露的 deviceId/faceId 可回填 V-01 签发任意用户 token；`searchInfo` 可做撞库/暴力破解
- **证据文件与行号**：`huilan-aipoc/src/main/java/com/huilan/controller/RegisterController.java:101-115, 72-94`、`huilan-common/huilan-core-system/.../entity/User.java:57-58`、`huilan-common/huilan-web/src/main/resources/application.yml:191-193`
- **限制说明**：需已知目标用户 openId（可在登录绑定后获得，或结合 `/user/searchInfoByCode` 换 openId）

---

### V-03 未授权任意注册：`/user/register`

- **严重等级**：中危
- **受影响入口**：`POST /ygzs/user/register`
- **鉴权要求**：无（`/user/**` 放行）
- **用户可控输入**：`@RequestBody User`（account/password/realName/mobile 等）
- **Source-to-sink 调用链**：
  `RegisterController.submit` (RegisterController.java:45-64) →
  查重后 `user.setStatus("0"); user.setRoleId("e4b08e..."); user.setDeptId("93151b..."); userService.submit(user)` →
  `UserServiceImpl.submit`（UserServiceImpl.java:99）
- **Sink**：`userService.submit(user)`（RegisterController.java:57）
- **防护判断**：无验证码、无频率限制、固定授予某角色（roleId 写死为 `e4b08e499c7d745d6a2087d8741f5664`）；密码明文入库（`submit` 未做哈希，依赖调用方）
- **安全 Payload**：
  ```
  POST /ygzs/user/register HTTP/1.1
  Host: <授权测试主机>
  Content-Type: application/json
  Connection: close

  {"account":"attacker001","password":"123456","realName":"测试","mobile":"13800000000"}
  ```
- **影响**：批量创建账号、垃圾数据；与 V-01 结合可在无凭据情况下建立可用身份
- **证据文件与行号**：`RegisterController.java:45-64`、`UserServiceImpl.java:99`
- **限制说明**：新注册用户 `status=0`（未激活），能否直接登录取决于前端/状态机逻辑；注册授予的角色权限有限

---

### V-04 SQL 注入（列名注入 → `${ew.customSqlSegment}`）

- **严重等级**：严重
- **受影响入口**：
  - `GET /ygzs/blade-system/user/export-user`（UserController.java:323-336）
  - `GET /ygzs/blade-system/region/export-region`（RegionController.java:182-189）
  - 以及所有调用 `Condition.getQueryWrapper(Map, Class)` 的列表查询接口（同 `SqlKeyword.buildCondition` 风险）
- **鉴权要求**：需登录 token（`/blade-system/**` 未放行）；但可先通过 V-01 免费获取 token
- **用户可控输入**：HTTP 查询参数**键名**（`xx_equal`、`xx_like`、`xx_ge` 等）与值
- **Source-to-sink 调用链**：
  `UserController.exportUser(@ApiIgnore @RequestParam Map user, ...)` (UserController.java:326) →
  `Condition.getQueryWrapper(user, User.class)`（Condition.java:76-97）→ `SqlKeyword.buildCondition(query, qw)`（SqlKeyword.java:60-104）：
  `k.endsWith("_equal") → qw.eq(getColumn(k, EQUAL), v)`，其中 `getColumn = StringUtil.humpToUnderline(removeSuffix(column, keyword))`（SqlKeyword.java:113-115），**攻击者可控的键名被直接当作 SQL 列名**，`humpToUnderline` 只做驼峰→下划线转换，**不过滤任何 SQL 元字符**（`'`、`(`、`,`、`--` 均保留）
  →
  `userService.exportUser(queryWrapper)`（UserServiceImpl.java:484-485）→ `baseMapper.exportUser(queryWrapper)`（UserMapper.xml:129）：
  `SELECT id, orgi, ... FROM aicc_user ${ew.customSqlSegment}`
- **Sink**：`${ew.customSqlSegment}`（UserMapper.xml:129；RegionMapper.xml:102 同型）
- **同源/相似受影响路由**：`RegionController.exportRegion`（RegionController.java:186 → RegionMapper.xml:102 `SELECT * FROM huilan_region ${ew.customSqlSegment}`）
- **防护判断**：`SqlKeyword.SQL_REGEX`（SqlKeyword.java:33）中的黑名单 `'|%|--|...` **只被 `filter()` 方法调用**，`buildCondition` 完全不调用 `filter()`；列名拼接无白名单
- **安全 Payload**（列名注入，值被 `#{}` 参数化，注入点在键名）：
  ```
  GET /ygzs/blade-system/user/export-user?username_like=%25&1%20union%20select%201,2,3,4,5,6,7,8,9,10,11,12,13,14,15%20--%20_equal=1 HTTP/1.1
  Host: <授权测试主机>
  Blade-Auth: Bearer <V-01取得的token>
  Connection: close
  ```
  键名 `1 union select ... -- _equal` 经 `removeSuffix("_equal")` 得到 `1 union select ... -- `，再经 `humpToUnderline` 得到 `1 union select ... -- `（无大写字母，原样保留），被渲染进 `ORDER BY`/WHERE 段的列名位置
- **影响**：联合查询/布尔盲注/时间盲注读取全库；结合 MySQL `load_file`/`into outfile` 可尝试写文件（需权限）
- **证据文件与行号**：`SqlKeyword.java:33,60-104,113-115`、`Condition.java:76-97`、`UserMapper.xml:129`、`RegionMapper.xml:102`、`UserController.java:323-336`、`RegionController.java:182-189`
- **限制说明**：仅对使用 `Condition.getQueryWrapper(Map, Class)` 的接口生效；`/user/searchInfo` 使用 `getQueryWrapper(T entity)`（基于实体字段，键名固定，不受此注入影响）

---

### V-05 越权 IDOR：`com.huilanrabbit` 全量 CRUD 无归属校验

- **严重等级**：中危（单点）/ 高危（配合 V-01）
- **受影响入口**：`/ygzs/matter/matter/{detail,list,page,save,update,submit,remove}` 等全部 `huilanrabbit` 控制器（MatterController、OrderController、ModularController、ThemeController、RegionpdController、ExtentdtableController、ModulardataController 等，各 7 个方法 × 8 个控制器 ≈ 56 个接口）
- **鉴权要求**：需 token（TokenInterceptor 兜底），但**无任何角色/归属校验**（无 `@PreAuth`）
- **用户可控输入**：`@RequestBody Matter/Order/...` 实体、`ids` 参数
- **Source-to-sink 调用链**：
  `MatterController.detail(Matter matter)` (MatterController.java:43-46) →
  `matterService.getOne(Condition.getQueryWrapper(matter))` → 按任意非空字段查询（含 id）→ 直接返回
  `MatterController.update(@RequestBody Matter matter)` (MatterController.java:84-89) → `matterService.updateById(matter)` → 按 id 覆盖任意记录
  `MatterController.remove(ids)` (MatterController.java:105-110) → `matterService.deleteLogic(Func.toStrList(ids))` → 逻辑删除任意记录
- **Sink**：`getOne/updateById/deleteLogic`（MatterController.java:44,88,109）
- **同源/相似受影响路由**：`huilan-aipoc` 的 `ManageMattersController`、`ProjectReportController`、`ScoreRankController`、`ReportLeaderController` 等未加 `@PreAuth` 的写接口
- **防护判断**：实体绑定无归属（createUser/tenantId）过滤；`updateById` 不校验操作者与记录创建者关系；`detail` 用 `getOne(Condition.getQueryWrapper(entity))` 任意字段组合可命中他人数据
- **安全 Payload**：
  ```
  POST /ygzs/matter/matter/update HTTP/1.1
  Host: <授权测试主机>
  Blade-Auth: Bearer <任意有效token>
  Content-Type: application/json
  Connection: close

  {"id":"<目标记录id>","xxx":"篡改内容"}
  ```
- **影响**：越权读取/修改/删除任意业务数据（事项、订单、主题、区域数据等）
- **证据文件与行号**：`MatterController.java:31,40-46,84-89,105-110`；其余 `huilanrabbit/controller/*.java` 结构一致（detail/list/page/save/update/submit/remove 同构）
- **限制说明**：需登录 token；配合 V-01 任意身份可放大影响

---

### V-06 任意文件删除：`/projectmanage/removeImg`、`/removeImgOther`、`/removeImgarry`、`/app_banner/appbanner/removeImg`

- **严重等级**：高危
- **受影响入口**：
  - `GET /ygzs/projectmanage/removeImg?path=...`（ProjectManageController.java:677-687）
  - `GET /ygzs/projectmanage/removeImgOther?path=...`（:647-657）
  - `POST /ygzs/projectmanage/removeImgarry?path=...`（:691-697）
  - `GET /ygzs/app_banner/appbanner/removeImg?path=...`（AppBannerController.java:142-152）
- **鉴权要求**：需 token；无 `@PreAuth` 角色限制
- **用户可控输入**：`path` 参数（直接拼文件系统路径）
- **Source-to-sink 调用链**：
  `ProjectManageController.removeImg(path)` (ProjectManageController.java:677-687) →
  `projectManageService.removeImg(path)`（ProjectManageServiceImpl.java:134-138）→ `truePath = path + File.separator + s; fileUtils.deleteFile(truePath)`（FileUtils.java:48-54）→ `new File(path).delete()`
  `removeImgarry` → 对 `path.split(",")` 逐个 `deleteFile`（ProjectManageServiceImpl.java:140-158）
- **Sink**：`File.delete()`（FileUtils.java:51）
- **防护判断**：`path` 无任何前缀/后缀限制，可传 `../../` 相对路径或绝对路径删除任意文件；`AppBannerController.removeImg` 虽在 `path` 前加了 `/data`，但 `removeImg` 传入的 `s` 仍可含 `../`
- **安全 Payload**：
  ```
  GET /ygzs/projectmanage/removeImg?path=../../../../etc/passwd HTTP/1.1
  Host: <授权测试主机>
  Blade-Auth: Bearer <任意有效token>
  Connection: close
  ```
  （Windows 环境可尝试 `C:/Windows/win.ini` 等）
- **影响**：删除 Web 目录内任意文件（含配置、上传文件、备份），可导致服务不可用；配合上传点可删除后替换
- **证据文件与行号**：`ProjectManageController.java:647-657,677-687,691-697`、`ProjectManageServiceImpl.java:134-158`、`FileUtils.java:48-54`、`AppBannerController.java:142-152`
- **限制说明**：Java 进程权限内可删的文件均可删；Windows 上 `File.delete` 对占用文件失败

---

### V-07 敏感配置/密钥硬编码泄露

- **严重等级**：高危
- **受影响入口**：配置文件（非 HTTP 入口，属信息泄露类）
- **用户可控输入**：无（源码/配置泄露）
- **Source-to-sink 调用链**：`application.yml` 明文写入 →
  - 七牛云 OSS AK/SK：`access-key: N_Loh1ngBqcJovwiAJqR91Ifj2vgOWHOf8AwBA_h`、`secret-key: AuzuA1KHAbkIndCU0dB3Zfii2O3crHNODDmpxHRS`（application.yml:126-129）
  - Druid 监控台弱口令 `blade / 1qaz@WSX`（application.yml:43-44）
  - 微信小程序 `appid: wx19a3db8e85de9679`、`appsecret: 4022b87ebaf228b0dcd46fcf483528bc`（application.yml:237-238）
  - AES/Des 密钥（application.yml:168-170）
- **Sink**：`application.yml` / `application-*.yml`
- **同源/相似受影响路由**：`huilan-web/src/main/resources/application-{dev,hg,prod,sc,test}.yml` 均含 upload.path 等
- **防护判断**：密钥明文入库/入配置库；OSS bucket `bladex` 公网可达（endpoint: http://prt1thnw3.bkt.clouddn.com）
- **影响**：OSS 存储桶接管、Druid 监控数据泄露、微信接口代调用（消耗配额/伪造 openid）、AES 报文解密
- **证据文件与行号**：`huilan-common/huilan-web/src/main/resources/application.yml:43-44,126-129,168-170,236-238`
- **限制说明**：属于配置管理类问题，需在授权范围内确认对应资产归属

---

### V-08 Druid 监控台未授权/弱口令

- **严重等级**：中危
- **受影响入口**：`/ygzs/druid/**`（`BladeConfiguration.java:67` 已将 `/druid/**` 加入**放行列表**）
- **鉴权要求**：仅 StatViewServlet 自带的 `blade/1qaz@WSX` 弱口令
- **用户可控输入**：无
- **Source-to-sink 调用链**：`application.yml:41-48` 开启 `stat-view-servlet.enabled: true` + 弱口令 → `SecureRegistry.excludePathPatterns("/druid/**")`（BladeConfiguration.java:67）绕过 TokenInterceptor
- **Sink**：Druid StatViewServlet（内嵌于 druid-spring-boot-starter）
- **防护判断**：弱口令可爆破；即使不登录，部分版本可匿名访问部分统计页
- **影响**：SQL 执行统计、Session 监控、URI 监控泄露业务结构；配合弱口令可查看堆栈/连接信息
- **证据文件与行号**：`application.yml:41-48`、`BladeConfiguration.java:67`
- **限制说明**：需确认公网可达性

---

## 三、高风险线索（待人工验证）

### L-01 上传接口扩展名校验不完整 / 潜在任意文件写入

- **受影响入口**：`/ygzs/projectmanage/uploadImgOther`（ProjectManageController.java:631-643）、`/uploadImgarry`（:661-673）、`/app_banner/appbanner/uploadImg`（AppBannerController.java:127-139）、`/scoreRank/uploadExcel`（ScoreRankController.java:166-188）
- **风险点**：
  - `uploadImgOther` **完全不做扩展名校验**，直接 `fileUtils.uploadOther` → `new File(path + File.separator + fileName)`（FileUtils.java:41），文件名原样保留，`../` 可路径穿越；`uploadImgarry` 取 `new File(originalFilename).getPath()` 也仅取最后一个 `.` 后缀
  - `uploadImg` 白名单 `IMAGE_EXT` 仅校验**小写后缀**（ProjectManageController.java:589-591,611-617），可尝试 `x.jsp`、`.jsp%00`、`.php` 等变体绕过；且文件落盘路径为 `upload.path`（prod: `/czgwdata/ygzsftp`，dev: `S:\项目\...\ftp`，application-prod.yml:84）
  - 无 Content-Type/魔数校验；`ScoreRankController.uploadExcel` 用 POI 解析（XSSFWorkbook/HSSFWorkbook，ScoreRankController.java:199-214）
- **判断**：Web 容器能否执行 ftp 目录下的 jsp 取决于部署方式（war 直接放静态目录通常不可执行，需确认）；若结合 nginx 映射到该目录且开启 php/其它解析则有 RCE 可能 → **待人工验证**

### L-02 XXE / XML 解析风险

- **受影响入口**：`/ygzs/scoreRank/uploadExcel`（XSSFWorkbook 解析 xlsx——OOXML 本质是 zip+xml）、以及 `huilan-common` 中所有 POI/`DocumentBuilder`/`SAXBuilder` 解析用户上传文件的点
- **风险点**：POI 低版本对 xlsx 内嵌 XML 的外部实体处理存在 XXE 历史漏洞；Excel 上传无需严格白名单（ScoreRankController.java:169 未校验扩展名/类型）
- **判断**：POI 版本取决于依赖树，未在源码确认 → **待人工验证**

---

## 四、修复建议摘要

1. **关闭/改造免鉴权 token 签发**：`appdevicetoken`/`appfacetoken` 必须校验验证码+设备绑定关系，或改为仅返回一次性 nonce 由业务侧二次确认；`PasswordTokenGranter` 的 `userId`/`deviceId` 分支不得直接签发
2. **`/user/**` 从 skip-url 移除**，仅放行 `register` 必要的公开接口；`searchInfoByOpenID`/`searchInfo` 删除或加鉴权，`User` 实体 `password` 字段加 `@JsonIgnore`
3. **SQL 注入**：`SqlKeyword.buildCondition` 对列名做白名单/转义，禁止用户键名进入列名位置；`${ew.customSqlSegment}` 一律改为不暴露或前置校验
4. **IDOR**：所有 `updateById/deleteLogic/getOne(Condition...)` 增加 createUser/tenantId 归属校验
5. **文件**：`uploadImgOther` 增加白名单+魔数校验+文件名随机化；`removeImg` 系列限制在 upload.path 目录内（禁止 `..`、绝对路径）
6. **密钥**：OSS/微信/appsecret 全部迁移到配置中心/环境变量/密钥管理服务；Druid 改强口令并限制内网访问
7. **越权放大链**：V-01 → V-05/V-06 为典型组合利用链，修复优先级最高

---

## 五、证据索引

| 漏洞 | 关键证据文件 |
|---|---|
| V-01 | `BladeTokenEndPoint.java:306-350,259-303`；`PasswordTokenGranter.java:77-89`；`TokenGranterBuilder.java:57-63` |
| V-02 | `RegisterController.java:101-115,72-94`；`User.java:57-58`；`application.yml:191-193` |
| V-03 | `RegisterController.java:45-64`；`UserServiceImpl.java:99` |
| V-04 | `SqlKeyword.java:33,60-104,113-115`；`Condition.java:76-97`；`UserMapper.xml:129`；`RegionMapper.xml:102`；`UserController.java:326`；`RegionController.java:186` |
| V-05 | `MatterController.java:31,40-46,84-89,105-110` 及同构控制器 |
| V-06 | `ProjectManageController.java:647-657,677-687,691-697`；`ProjectManageServiceImpl.java:134-158`；`FileUtils.java:48-54` |
| V-07 | `application.yml:43-44,126-129,168-170,236-238` |
| V-08 | `application.yml:41-48`；`BladeConfiguration.java:67` |
| L-01 | `ProjectManageController.java:589-617,631-673`；`FileUtils.java:31-45`；`application-prod.yml:82-84` |
| L-02 | `ScoreRankController.java:166-214` |

> 本报告基于静态源码审计。所有 Payload 与请求包仅用于授权范围内的复现验证，请勿用于未授权目标。
