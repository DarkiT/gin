# 项目名称
APP_NAME := $(shell echo $$CNB_REPO_NAME_LOWERCASE || echo $${APP_NAME:-app})
# 版本信息
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "v1.0.0-dev")
# 构建时间
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
# Git commit hash
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# 编译参数
LDFLAGS := -s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)
BUILD_FLAGS := -trimpath -ldflags "$(LDFLAGS)"

# 源文件路径 - 根据项目架构调整
MAIN_PATH := .
# 输出目录
BIN_DIR := ./bin

# Go 相关工具
GOLINT := golangci-lint
GOTEST := go test
GOVET := go vet
GOFMT := gofmt
SWAG := swag

# 数据库迁移工具
MIGRATE := migrate

# 创建bin目录
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# 清理构建文件
clean:
	rm -rf $(BIN_DIR)
	rm -rf ./coverage

# 代码格式化
fmt:
	$(GOFMT) -s -w .

# 代码静态检查
lint:
	$(GOLINT) run ./...

# 代码安全检查
vet:
	$(GOVET) ./...

# 生成API文档
swagger:
	$(SWAG) init -g $(MAIN_PATH) -o ./api/docs

# 数据库迁移
migrate-up:
	$(MIGRATE) -path ./migrations -database "$(DB_URL)" up

migrate-down:
	$(MIGRATE) -path ./migrations -database "$(DB_URL)" down

# 本地构建 (当前架构)
build: $(BIN_DIR)
	CGO_ENABLED=0 go build $(BUILD_FLAGS) -o $(BIN_DIR)/$(APP_NAME) $(MAIN_PATH)

# Linux amd64 构建
build-linux-amd64: $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o $(BIN_DIR)/$(APP_NAME)-linux-amd64 $(MAIN_PATH)

# Linux arm64 构建
build-linux-arm64: $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(BUILD_FLAGS) -o $(BIN_DIR)/$(APP_NAME)-linux-arm64 $(MAIN_PATH)

# Linux arm 构建
build-linux-arm: $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm go build $(BUILD_FLAGS) -o $(BIN_DIR)/$(APP_NAME)-linux-arm $(MAIN_PATH)

# Windows amd64 构建
build-windows-amd64: $(BIN_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(BUILD_FLAGS) -o $(BIN_DIR)/$(APP_NAME)-windows-amd64.exe $(MAIN_PATH)

# Windows arm64 构建
build-windows-arm64: $(BIN_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build $(BUILD_FLAGS) -o $(BIN_DIR)/$(APP_NAME)-windows-arm64.exe $(MAIN_PATH)

# macOS amd64 构建
build-darwin-amd64: $(BIN_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(BUILD_FLAGS) -o $(BIN_DIR)/$(APP_NAME)-darwin-amd64 $(MAIN_PATH)

# macOS arm64 构建 (Apple Silicon)
build-darwin-arm64: $(BIN_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(BUILD_FLAGS) -o $(BIN_DIR)/$(APP_NAME)-darwin-arm64 $(MAIN_PATH)

# FreeBSD amd64 构建
build-freebsd-amd64: $(BIN_DIR)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build $(BUILD_FLAGS) -o $(BIN_DIR)/$(APP_NAME)-freebsd-amd64 $(MAIN_PATH)

# 构建所有平台
build-all: build-linux-amd64 build-linux-arm64 build-linux-arm build-windows-amd64 build-windows-arm64 build-darwin-amd64 build-darwin-arm64 build-freebsd-amd64
	@echo "所有平台构建完成！"
	@ls -la $(BIN_DIR)/

# 构建常用平台 (Linux, Windows, macOS)
build-common: build-linux-amd64 build-windows-amd64 build-darwin-amd64 build-darwin-arm64
	@echo "常用平台构建完成！"
	@ls -la $(BIN_DIR)/

# 显示构建信息
info:
	@echo "项目名称: $(APP_NAME)"
	@echo "版本信息: $(VERSION)"
	@echo "构建时间: $(BUILD_TIME)"
	@echo "Git提交: $(GIT_COMMIT)"
	@echo "编译参数: $(BUILD_FLAGS)"

# 本地开发运行 (直接运行源码)
dev:
	go run $(MAIN_PATH)

# 构建并运行
run: build
	@echo "运行 $(APP_NAME)..."
	@$(BIN_DIR)/$(APP_NAME)

# Docker 开发环境
docker-dev:
	docker-compose -f ./configs/docker-compose.dev.yml up --build

# Docker 生产环境
docker-prod:
	docker-compose -f ./configs/docker-compose.yml up -d

# 安装开发依赖
install-dev-deps:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/swaggo/swag/cmd/swag@latest
	go install -tags 'postgres,mysql,sqlite' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	go install github.com/cosmtrek/air@latest

# 测试
test:
	$(GOTEST) -v ./... -coverprofile=./coverage/coverage.out
	$(GOTEST) -json ./... 2>&1 | tdd-guard-go -project-root /workspace

# 测试（带竞态检测）
test-race:
	$(GOTEST) -v -race ./... -coverprofile=./coverage/coverage.out

# 显示测试覆盖率
cover:
	go tool cover -html=./coverage/coverage.out

# 性能基准测试
benchmark:
	$(GOTEST) -bench=. ./... -benchmem

# 初始化项目结构
init-project:
	mkdir -p api/handlers api/middleware cmd/server configs internal/app internal/domain internal/infra pkg/auth pkg/config pkg/logger pkg/utils migrations scripts test

# 帮助信息
help:
	@echo "可用的构建目标："
	@echo "  build                - 构建当前架构的可执行文件"
	@echo "  build-linux-amd64    - 构建Linux x86_64版本"
	@echo "  build-linux-arm64    - 构建Linux ARM64版本"
	@echo "  build-linux-arm      - 构建Linux ARM版本"
	@echo "  build-windows-amd64  - 构建Windows x86_64版本"
	@echo "  build-windows-arm64  - 构建Windows ARM64版本"
	@echo "  build-darwin-amd64   - 构建macOS x86_64版本"
	@echo "  build-darwin-arm64   - 构建macOS ARM64版本 (Apple Silicon)"
	@echo "  build-freebsd-amd64  - 构建FreeBSD x86_64版本"
	@echo "  build-all            - 构建所有支持的架构"
	@echo "  build-common         - 构建常用架构 (Linux, Windows, macOS)"
	@echo "  clean                - 清理构建文件"
	@echo "  info                 - 显示构建信息"
	@echo ""
	@echo "开发工具："
	@echo "  fmt                  - 格式化代码"
	@echo "  lint                 - 运行代码静态检查"
	@echo "  vet                  - 运行代码安全检查"
	@echo "  swagger              - 生成API文档"
	@echo "  dev                  - 本地运行开发环境 (直接运行源码)"
	@echo "  run                  - 构建并运行程序"
	@echo "  docker-dev           - 使用Docker运行开发环境"
	@echo "  docker-prod          - 使用Docker运行生产环境"
	@echo "  install-dev-deps     - 安装开发依赖工具"
	@echo ""
	@echo "测试相关："
	@echo "  test                 - 运行测试"
	@echo "  test-race            - 运行竞态检测测试"
	@echo "  cover                - 显示测试覆盖率"
	@echo "  benchmark            - 运行性能基准测试"
	@echo "  mock                 - 生成模拟数据"
	@echo ""
	@echo "数据库相关："
	@echo "  migrate-up           - 执行数据库迁移"
	@echo "  migrate-down         - 回滚数据库迁移"
	@echo ""
	@echo "项目管理："
	@echo "  init-project         - 初始化项目目录结构"
	@echo "  help                 - 显示此帮助信息"

.PHONY: build build-linux-amd64 build-linux-arm64 build-linux-arm build-windows-amd64 build-windows-arm64 build-darwin-amd64 build-darwin-arm64 build-freebsd-amd64 build-all build-common clean info help dev run docker-dev docker-prod fmt lint vet swagger test test-race cover benchmark mock migrate-up migrate-down install-dev-deps init-project