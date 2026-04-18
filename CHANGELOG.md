# Changelog

本文档记录了 darkit/gin 框架的所有重要变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added

#### 熔断器指标导出 (2025-01-14)

- **统计信息**
  - `Stats()` - 返回熔断器统计信息（BreakerStats）
  - 包含：状态、总请求数、成功数、失败数、连续失败数、最后失败时间
  - 使用原子操作确保并发安全

- **状态变更回调**
  - `OnStateChange(fn)` - 注册状态变更回调函数
  - 支持监控熔断器状态转换（Closed ↔ Open ↔ HalfOpen）
  - `ResetStats()` - 重置统计计数器（不影响熔断器状态）

#### Cache 接口增强 (2025-01-14)

- **批量操作接口（BatchCache）**
  - `MGet(ctx, keys)` - 批量获取缓存值
  - `MSet(ctx, items, ttl)` - 批量设置缓存值
  - `MDelete(ctx, keys)` - 批量删除缓存

- **原子操作接口（AtomicCache）**
  - `GetOrSet(ctx, key, fn, ttl)` - 获取或设置（singleflight 模式）
  - `Increment(ctx, key, delta)` - 原子递增
  - `Decrement(ctx, key, delta)` - 原子递减

- **统计接口（StatsCache）**
  - `Stats()` - 返回缓存统计信息（命中率、Key 数量等）
  - `ResetStats()` - 重置统计信息

- **memoryCache 实现**
  - 实现 BatchCache 接口（MGet/MSet/MDelete）

#### 参数转换错误处理方法 (2025-01-14)

- **带错误返回的方法**
  - `ParamIntE(key)` - 获取整型参数，返回错误信息
  - `ParamInt64E(key)` - 获取 int64 参数，返回错误信息
  - `ParamFloatE(key)` - 获取 float64 参数，返回错误信息
  - `ParamBoolE(key)` - 获取布尔参数，返回错误信息
  - 可区分参数不存在（ErrParamNotFound）和格式错误（ErrParamInvalid）

- **断言式方法（Panic 版本）**
  - `MustParamInt(key)` - 获取整型参数，失败时 panic
  - `MustParamInt64(key)` - 获取 int64 参数，失败时 panic
  - `MustParamFloat(key)` - 获取 float64 参数，失败时 panic
  - `MustParamBool(key)` - 获取布尔参数，失败时 panic

#### 验证错误信息增强 (2025-01-14)

- **ValidationError 结构体扩展**
  - 新增 `Tag` 字段 - 验证标签（如 required, min, max）
  - 新增 `Value` 字段 - 实际值（调试用）
  - 新增 `Param` 字段 - 验证参数（如 min=5 中的 5）

- **人类可读错误消息**
  - `formatValidationMessage()` - 生成中文验证错误消息
  - 支持 required、min、max、len、email、url、oneof、gt、gte、lt、lte 等标签

#### WorkerPool 配置增强 (2025-01-14)

- **配置选项**
  - `WithQueueSize(size)` - 设置任务队列大小
  - `WithOverflowPolicy(policy)` - 设置队列溢出策略
  - `WithOnTaskDropped(fn)` - 设置任务丢弃回调

- **溢出策略**
  - `PolicyBlock` - 阻塞等待（默认）
  - `PolicyDrop` - 丢弃任务
  - `PolicyCallerRuns` - 由调用者执行

- **新增方法**
  - `TrySubmit(fn)` - 非阻塞提交任务
  - `Stats()` - 返回协程池统计信息
  - `ShutdownGraceful()` - 优雅关闭（等待所有任务完成）

- **统计信息（PoolStats）**
  - Workers、QueueSize、Queued、Submitted、Completed、Dropped

### Changed

#### 正则路由性能优化 (2025-01-14)

- **按 HTTP 方法分组存储**
  - 新增 `routesByMethod` 字段，按方法索引路由
  - 匹配时先查找方法特定路由，再查找通用路由（Any）
  - 从 O(n) 优化到 O(n/m)，其中 m 为 HTTP 方法数

- **参数 map 复用优化**
  - 使用 `clear(params)` 内置函数（Go 1.21+）替代遍历删除
  - 减少 GC 压力

#### IdempotentStore 分片优化 (2025-01-14)

- **32 分片设计**
  - 使用 FNV-1a 哈希算法分配 key 到分片
  - 每个分片独立锁，降低高并发锁竞争
  - 清理协程按分片并行执行

### Fixed

#### Context 池复用机制 (2025-01-14)

- 移除 `acquireContext` 中冗余的 `ctx.Keys = nil` 操作
- `gin.Context.Keys` 由 Gin 框架管理，每次请求都是新的 gin.Context
- 避免不必要的字段重置

### Added

#### 数据脱敏功能 (2024-12-24)

- **核心功能**
  - `MaskValue(value, opts...)` - 对任意数据结构进行脱敏（返回副本）
  - `RegisterMaskFunc(tag, fn)` - 注册自定义脱敏规则
  - 基于 struct tag 的声明式脱敏（`mask:"mobile"`, `mask:"idcard"` 等）

- **内置脱敏规则**
  - `mobile` - 手机号脱敏（保留前3后4位）
  - `email` - 邮箱脱敏（用户名部分）
  - `idcard` - 身份证脱敏（保留前6后4位）
  - `name` - 姓名脱敏（保留姓氏）
  - `bankcard` - 银行卡脱敏（保留后4位）
  - `address` - 地址脱敏（保留省市）

- **配置选项**
  - `WithMaskChar(char)` - 设置脱敏字符（默认 `*`）
  - `WithMaskRules(rules)` - 添加自定义脱敏规则

- **高级特性**
  - 支持嵌套结构体递归脱敏
  - 支持切片、数组、Map 类型
  - 支持指针和接口类型
  - 零侵入设计，返回新副本不修改原数据

#### 数据验证增强（中国特色验证）(2024-12-24)

- **中国特色验证器**
  - `ValidateMobile(mobile)` - 手机号验证（11位，1开头）
  - `ValidateIDCard(idcard)` - 身份证验证（15/18位，含校验位算法）
  - `ValidateBankCard(cardNo)` - 银行卡验证（Luhn 算法）
  - `ValidateUSCC(code)` - 统一社会信用代码验证（18位，含校验位）

- **验证特性**
  - 符合中国国家标准算法
  - 身份证支持 15/18 位格式
  - 银行卡采用标准 Luhn 校验
  - 统一社会信用代码按 GB 32100 标准

#### 图片处理功能 (2024-12-24)

- **核心处理方法**
  - `Process(srcPath, dstPath, originalName, opts...)` - 处理图片并保存
  - 返回详细的处理结果（ImageResult：宽高、大小、格式等）

- **缩放模式**
  - `Resize(width, height)` - 指定宽高缩放
  - `ResizeWidth(width)` - 按宽度等比缩放
  - `ResizeHeight(height)` - 按高度等比缩放
  - `Crop(width, height, anchor)` - 裁剪（支持9个锚点位置）
  - `Thumbnail(width, height)` - 缩略图模式

- **水印功能**
  - `WithWatermark(imagePath, position, opacity)` - 添加图片水印
  - 支持9个位置（top-left, top, top-right, left, center, right, bottom-left, bottom, bottom-right）
  - 支持透明度调整

- **格式与质量**
  - 支持格式：JPG, PNG, WebP
  - `WithQuality(quality)` - 设置输出质量（JPEG/WebP）
  - `WithFormat(format)` - 指定输出格式
  - 自动 EXIF 方向校正

#### 数据导出功能 (Excel/CSV) (2024-12-24)

- **Excel 导出**
  - `ExportExcel(data, opts...)` - 导出 Excel 文件（返回字节）
  - `StreamExcel(dataChan, writer, opts...)` - 流式导出（大数据量）
  - 支持多 Sheet 导出
  - 支持样式定制（表头样式、数据行样式）
  - 自动类型转换和日期格式化

- **CSV 导出**
  - `ExportCSV(data, opts...)` - 导出 CSV 文件
  - `StreamCSV(dataChan, writer, opts...)` - 流式导出
  - 支持 GBK/UTF-8 编码（兼容 Excel 打开）
  - 自定义分隔符（逗号、制表符等）

- **配置选项**
  - `WithHeaders(headers...)` - 设置表头
  - `WithSheetName(name)` - 设置 Sheet 名称
  - `WithEncoding(encoding)` - 设置编码（GBK/UTF-8）
  - `WithDelimiter(delimiter)` - 设置 CSV 分隔符
  - `WithDateFormat(format)` - 设置日期格式
  - `WithDateLocation(location)` - 设置时区

- **高级特性**
  - 自动处理结构体切片
  - 支持流式导出（避免内存溢出）
  - 支持嵌套结构体展开
  - Excel 支持多 Sheet 和样式

#### 请求限流增强 (2024-12-24)

- **限流中间件**
  - `RateLimitByUser(limit, opts...)` - 按用户 ID 限流
  - `RateLimitByKey(keyFunc, limit, opts...)` - 按自定义 Key 限流
  - `RateLimitTier(tiers, tierFunc, opts...)` - 分级限流（不同用户等级不同限制）

- **限流格式**
  - 灵活的限流表达式：`"100-1m"` (100次/分钟), `"10-1h"` (10次/小时), `"1000-1d"` (1000次/天)
  - 支持秒（s）、分钟（m）、小时（h）、天（d）

- **配置选项**
  - `WithRateLimitStore(store)` - 自定义存储（支持 Redis 等）
  - `WithRateLimitBurst(burst)` - 设置突发容量
  - `WithRateLimitOnLimit(fn)` - 自定义限流回调

- **高级特性**
  - 基于 Token Bucket 算法（golang.org/x/time/rate）
  - 支持分布式限流（自定义 Store）
  - 分级限流支持（VIP/普通用户不同限制）
  - 自动从 Context 或 Header 提取用户标识

#### 幂等性中间件 (2024-12-24)

- **核心功能**
  - `Idempotent(opts...)` - 幂等性保护中间件
  - `IdempotentWithTTL(ttl)` - 带自定义 TTL 的幂等性中间件
  - 基于 `Idempotency-Key` Header 实现

- **配置选项**
  - `WithIdempotentTTL(ttl)` - 设置缓存时效（默认5分钟）
  - `WithIdempotentStore(store)` - 自定义存储后端
  - `WithIdempotentKeyFunc(fn)` - 自定义 Key 提取函数
  - `WithIdempotentSkipFunc(fn)` - 设置跳过条件

- **工作原理**
  - 首次请求：执行并缓存响应（状态码+响应体）
  - 重复请求：直接返回缓存的响应，不执行业务逻辑
  - 防止重复提交、重复扣款等场景

- **存储支持**
  - 内置内存存储（MemoryIdempotentStore）
  - 支持自定义存储（实现 IdempotentStore 接口）
  - 适配 Redis 等分布式缓存

#### 分页查询助手 (2024-12-24)

- **Context 分页方法**
  - `ParsePagination(defaults...)` - 解析分页参数（返回 page, perPage）
  - `PaginationParams(opts...)` - 解析并返回 PaginationParams 结构体
  - `Paginated(data, page, perPage, total)` - 返回分页响应

- **参数解析特性**
  - 支持多种参数名：`page`, `per_page`, `page_size`, `limit`
  - 自动计算 `offset`（用于数据库查询）
  - 参数校验（确保 > 0）
  - 默认值：page=1, per_page=20

- **配置选项**
  - `WithDefaultPage(page)` - 设置默认页码
  - `WithDefaultPerPage(perPage)` - 设置默认每页数量
  - `WithMaxPerPage(max)` - 设置每页最大数量（防止滥用）

- **返回结构**
  - PaginationParams 包含：Page, PerPage, Offset
  - Paginated 响应包含：data, pagination（page, per_page, total, total_pages）

#### 便捷文件上传功能 (2024-12-24)

- **全局配置选项**
  - `WithUploadDir(dir)` - 设置默认上传目录
  - `WithMaxFileSize(size)` - 设置单个文件最大大小
  - `WithMaxMultipartMemory(size)` - 设置 multipart 内存限制
  - `WithAllowedExts(exts...)` - 设置允许的文件扩展名
  - `WithUploadConfig(config)` - 设置完整上传配置

- **Context 上传方法**
  - `SaveFile(formKey, opts...)` - 保存单个文件（一行代码）
  - `SaveFiles(formKey, opts...)` - 批量保存多个文件
  - `ValidateFile(formKey, opts...)` - 验证文件但不保存
  - `StreamFile(filepath, filename...)` - 文件下载（attachment）
  - `StreamFileInline(filepath)` - 文件预览（inline）

- **上传选项函数**
  - `ToDir(dir)` - 指定上传目录（覆盖全局配置）
  - `MaxSize(size)` - 指定最大文件大小（覆盖全局配置）
  - `AllowExts(exts...)` - 指定允许的扩展名（覆盖全局配置）
  - `AsName(name)` - 指定保存文件名

- **安全特性**
  - 文件大小验证
  - 文件类型白名单
  - UUID 自动文件名生成
  - 完整的错误处理

#### 静态文件服务系统 (2024-12-23)

- **Engine 和 Router 静态文件方法**
  - `Static(relativePath, root)` - 服务本地文件系统目录
  - `StaticFS(relativePath, fs)` - 服务自定义 http.FileSystem
  - `StaticFile(relativePath, filepath)` - 服务单个文件

- **嵌入式文件系统支持**
  - `Router.EmbedFS(relativePath, embedFS, subPath...)` - 服务 embed.FS 文件系统
  - `Router.EmbedFile(relativePath, embedFS, filePath)` - 服务单个嵌入文件
  - 支持 Go 1.16+ 的 embed.FS

- **Zip 文件系统**
  - `static.NewZipFileSystem(config)` - 创建 Zip 文件系统
  - `static.NewZipFile(zipPath, filePath, config)` - 创建单文件服务
  - `static.RegisterZipFS(router, path, zfs)` - 注册 Zip 文件系统到路由
  - `static.RegisterZipFile(router, path, zf)` - 注册单个 Zip 文件
  - 支持密码保护的 Zip 文件
  - 支持 Zip 文件热更新（自动检测文件变化）
  - 支持子路径限制（安全控制）

#### 核心 API 完善 (2024-12-23)

- **Engine 方法**
  - `Any(path, handlers...)` - 注册所有 HTTP 方法的路由
  - `Match(methods, path, handlers...)` - 注册指定多个 HTTP 方法的路由
  - `Routes()` - 返回所有注册的路由信息
  - `SetTrustedProxies(proxies)` - 设置可信代理 IP 列表
  - `NoMethod(handlers...)` - 设置 405 Method Not Allowed 处理器

- **Router 方法**
  - `Any(path, handler)` - 注册所有 HTTP 方法的路由
  - `Match(methods, path, handler)` - 注册指定多个 HTTP 方法的路由
  - `BasePath()` - 返回路由组的基础路径

#### RegexRouter 改进 (2024-12-23)

- **调用顺序无关性**
  - `Engine.NoRoute()` 和 `Engine.RegexRouter()` 可以以任意顺序调用
  - 用户自定义 404 处理器自动同步到 RegexRouter
  - 改进的内部调度机制，确保正确的执行流程

#### 路由自动注册 (2024-12-23)

- **自动路由映射**
  - `Router.AutoRegister(controller, opts...)` - 自动将控制器方法映射到路由
  - 零配置的约定式路由（方法名 → HTTP 路由）
  - 支持标准路由和正则路由的自动识别

- **正则路由模式配置**
  - 接口级配置（`RegexPatterns()` 方法）
  - 注册时选项覆盖（最高优先级）
  - 默认推断机制（回退）

- **配置选项**
  - `WithPrefix(prefix)` - 设置路由前缀
  - `WithRegexPattern(methodName, pattern)` - 自定义正则模式
  - `WithMiddleware(middlewares...)` - 添加中间件

#### Chi 框架集成 (2024-12-XX)

- **Router.Use() 原生支持 Chi 中间件**
  - 自动识别并适配 Chi 风格中间件 `func(http.Handler) http.Handler`
  - 无需手动调用适配器函数
  - 保留向后兼容的 `chicompat.Adapt()` 方法（已废弃）

- **移植的 Chi 中间件**
  - `Throttle(maxConcurrent)` - 并发请求限流 + 积压队列
  - `URLFormat()` - URL 扩展名解析 (`.json`, `.xml`)
  - `NoCache()` - HTTP 缓存禁用
  - `RealIP()` - 真实 IP 提取（X-Forwarded-For）
  - `Maybe(mw, shouldApply)` - 条件性中间件执行
  - `Sunset(date, link)` - API 废弃通知 (RFC 8594)
  - `RouteHeaders(pairs...)` - 基于 Header 的路由分发
  - `ValidateParam(param, pattern, errorMsg)` - 路由参数正则验证

#### Context 方法补充 (2024-12-XX)

- **参数解析方法**
  - `ParamFloat(key, def...)` - 获取 float64 参数
  - `ParamBool(key, def...)` - 获取 bool 参数
  - 与现有的 `ParamInt`、`ParamInt64` 形成完整体系

#### 文档完善 (2024-12-23)

- 新增静态文件服务完整文档
  - `examples/static/README.md` - 静态文件服务示例和最佳实践
  - `docs/api-reference.md` - 完整的 API 参考文档（新增 Static 模块）
  - `docs/usage.md` - 新增静态文件服务章节

- 更新核心文档
  - `README.md` - 添加静态文件服务特性说明
  - API 参考文档 - 补充所有新增方法的详细说明
  - 使用指南 - 添加实用的示例和最佳实践

- RegexRouter 和 Chi 中间件文档
  - 调用顺序无关性说明
  - Chi 中间件使用注意事项
  - 工作原理和最佳实践

### Fixed

#### 代码质量改进 (2024-12-XX)

- 修复 5 个代码评审发现的问题
  - 类型转换安全性
  - 错误处理完整性
  - 资源清理
  - 代码一致性

### Changed

#### API 兼容性

- 完全兼容 gin-gonic/gin API
  - 通过 `gin_compat.go` 实现 100% API 映射
  - 所有 Gin 常量、类型和函数可直接使用
  - 零迁移成本

## [0.1.0] - 2024-12-XX

### Added

- 基于 gin-gonic/gin 的增强型框架
- 增强型 Context（RESTful 响应辅助方法）
- 生产级中间件（RequestID, Recovery, Logger, CORS, RateLimit, Timeout, Secure）
- 资源路由（RESTful API 快速构建）
- API 版本管理
- 生命周期管理（优雅停机）
- 缓存接口和内存缓存实现
- 日志接口
- 诊断工具
- 完整的文档和示例

---

## 版本说明

### 版本号规则

- **主版本号（Major）**：不兼容的 API 变更
- **次版本号（Minor）**：向后兼容的功能新增
- **修订号（Patch）**：向后兼容的问题修正

### 变更类型

- **Added** - 新增功能
- **Changed** - 功能变更
- **Deprecated** - 即将废弃的功能
- **Removed** - 已移除的功能
- **Fixed** - 问题修复
- **Security** - 安全性改进

---

## 贡献指南

如果您想为本项目做出贡献，请：

1. 遵循 [Conventional Commits](https://www.conventionalcommits.org/zh-hans/) 规范
2. 在 PR 中简要说明变更内容
3. 重大变更请在 Issue 中先讨论

---

**Star ⭐ 本项目支持我们的工作！**
