package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/darkit/gin"
	"github.com/darkit/gin/middleware"
)

func main() {
	r := gin.Default()

	// 示例 1: 简单缓存
	r.GET("/articles/:id", middleware.Cache(5*time.Minute), func(c *gin.Context) {
		// 这个响应会被缓存 5 分钟
		id := c.Param("id")
		c.JSON(http.StatusOK, gin.H{
			"id":      id,
			"title":   "示例文章",
			"content": "这是文章内容",
		})
	})

	// 示例 2: 条件缓存
	r.GET("/api/data", middleware.CacheIf(func(c *gin.Context) bool {
		// 当没有 nocache 参数时才缓存
		return c.Query("nocache") == ""
	}, 10*time.Minute), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"data":      "some data",
			"timestamp": time.Now().Unix(),
		})
	})

	// 示例 3: ETag 支持
	r.GET("/static/data", middleware.ETag(), func(c *gin.Context) {
		// 响应会自动生成 ETag，客户端可以使用 If-None-Match 头来获取 304 响应
		c.JSON(http.StatusOK, gin.H{
			"data": "static data that doesn't change often",
		})
	})

	// 示例 4: 自定义缓存键
	r.GET("/user/profile", middleware.Cache(5*time.Minute,
		middleware.WithCacheKey(func(c *gin.Context) string {
			// 根据用户 ID 生成缓存键
			userID, _ := c.Get("user_id")
			return "profile:" + fmt.Sprint(userID)
		}),
	), func(c *gin.Context) {
		userID, _ := c.Get("user_id")
		c.JSON(http.StatusOK, gin.H{
			"user_id": userID,
			"name":    "张三",
			"email":   "zhangsan@example.com",
		})
	})

	// 示例 5: 自定义 Cache-Control 和 Vary 头
	r.GET("/api/content", middleware.Cache(time.Minute,
		middleware.WithCacheControl("public, max-age=60"),
		middleware.WithCacheVary("Accept-Language", "Accept-Encoding"),
	), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"content": "localized content",
		})
	})

	// 示例 6: 分布式缓存（需要外部 Redis）
	// redisCache := cache.NewRedisCache(redisClient)
	// r.GET("/hot/data", middleware.Cache(time.Minute,
	// 	middleware.WithCacheStore(redisCache),
	// ), func(c *gin.Context) {
	// 	c.JSON(http.StatusOK, gin.H{
	// 		"data": "frequently accessed data",
	// 	})
	// })

	// 示例 7: 组合使用 ETag 和缓存
	// 注意：通常不需要同时使用，选择其中一种即可
	r.GET("/combined",
		middleware.ETag(),
		middleware.Cache(time.Minute),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"data": "combined example",
			})
		},
	)

	// 测试路由
	r.GET("/test/cache", func(c *gin.Context) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, `
		<!DOCTYPE html>
		<html>
		<head>
			<title>缓存测试</title>
			<meta charset="utf-8">
		</head>
		<body>
			<h1>响应缓存中间件测试</h1>
			<h2>测试缓存功能</h2>
			<button onclick="testCache()">测试基础缓存</button>
			<button onclick="testConditionalCache()">测试条件缓存</button>
			<button onclick="testETag()">测试 ETag</button>
			<pre id="result"></pre>

			<script>
				async function testCache() {
					const result = document.getElementById('result');
					result.textContent = '测试中...\n\n';

					// 第一次请求
					const resp1 = await fetch('/articles/123');
					const data1 = await resp1.json();
					result.textContent += '第一次请求:\n';
					result.textContent += 'X-Cache: ' + resp1.headers.get('X-Cache') + '\n';
					result.textContent += 'Data: ' + JSON.stringify(data1) + '\n\n';

					// 第二次请求（应该从缓存获取）
					const resp2 = await fetch('/articles/123');
					const data2 = await resp2.json();
					result.textContent += '第二次请求:\n';
					result.textContent += 'X-Cache: ' + resp2.headers.get('X-Cache') + ' (应该是 HIT)\n';
					result.textContent += 'Data: ' + JSON.stringify(data2) + '\n';
				}

				async function testConditionalCache() {
					const result = document.getElementById('result');
					result.textContent = '测试中...\n\n';

					// 不带 nocache 参数
					const resp1 = await fetch('/api/data');
					const data1 = await resp1.json();
					result.textContent += '不带 nocache 参数:\n';
					result.textContent += 'X-Cache: ' + resp1.headers.get('X-Cache') + '\n';
					result.textContent += 'Data: ' + JSON.stringify(data1) + '\n\n';

					// 带 nocache 参数
					const resp2 = await fetch('/api/data?nocache=1');
					const data2 = await resp2.json();
					result.textContent += '带 nocache 参数:\n';
					result.textContent += 'X-Cache: ' + (resp2.headers.get('X-Cache') || '无缓存') + '\n';
					result.textContent += 'Data: ' + JSON.stringify(data2) + '\n';
				}

				async function testETag() {
					const result = document.getElementById('result');
					result.textContent = '测试中...\n\n';

					// 第一次请求，获取 ETag
					const resp1 = await fetch('/static/data');
					const etag = resp1.headers.get('ETag');
					const data1 = await resp1.json();
					result.textContent += '第一次请求:\n';
					result.textContent += 'Status: ' + resp1.status + '\n';
					result.textContent += 'ETag: ' + etag + '\n';
					result.textContent += 'Data: ' + JSON.stringify(data1) + '\n\n';

					// 第二次请求，带 If-None-Match 头
					const resp2 = await fetch('/static/data', {
						headers: {
							'If-None-Match': etag
						}
					});
					result.textContent += '第二次请求（带 If-None-Match）:\n';
					result.textContent += 'Status: ' + resp2.status + ' (应该是 304 Not Modified)\n';
					result.textContent += 'ETag: ' + resp2.headers.get('ETag') + '\n';
				}
			</script>
		</body>
		</html>
		`)
	})

	fmt.Println("服务器启动在 http://localhost:8080")
	fmt.Println("访问 http://localhost:8080/test/cache 进行测试")
	if err := r.Run(":8080"); err != nil {
		panic(err)
	}
}
