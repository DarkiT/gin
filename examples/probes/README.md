# 健康探针示例

本示例演示以下能力：

- `routes.HealthCheck()`
- `routes.Liveness()`
- `routes.Readiness()`
- `routes.Startup()`
- `routes.NamedProbe(...)`

## 运行示例

```bash
cd examples/probes
go run main.go
```

服务默认监听 `http://localhost:8080`。

## 默认探针端点

```bash
curl http://localhost:8080/health
curl http://localhost:8080/livez
curl http://localhost:8080/readyz
curl http://localhost:8080/startupz
```

说明：

- `/health`：最轻量的健康检查
- `/livez`：存活探针，只回答进程是否活着
- `/readyz`：就绪探针，检查 `database` 和 `cache`
- `/startupz`：启动探针，示例中服务启动 5 秒后才会返回成功

## 查看当前状态

```bash
curl http://localhost:8080/status
```

返回示例：

```json
{
  "code": 200,
  "message": "success",
  "data": {
    "cache_ready": true,
    "database_ready": true,
    "started": true
  }
}
```

## 模拟依赖异常

让数据库探针失败：

```bash
curl -X POST http://localhost:8080/admin/database/down
curl http://localhost:8080/readyz
```

恢复数据库：

```bash
curl -X POST http://localhost:8080/admin/database/up
```

让缓存探针失败：

```bash
curl -X POST http://localhost:8080/admin/cache/down
curl http://localhost:8080/readyz
```

手动切换启动状态：

```bash
curl -X POST http://localhost:8080/admin/startup/down
curl http://localhost:8080/startupz
curl -X POST http://localhost:8080/admin/startup/up
```

当某个探针失败时，接口会返回 `503 Service Unavailable`，并在 `checks` 字段中列出失败原因。
