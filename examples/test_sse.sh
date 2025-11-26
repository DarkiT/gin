#!/bin/bash

# SSE 功能测试脚本
set -e

SERVER_PID=""
BASE_URL="http://localhost:8080"
CLIENT_ID="test_client_$(date +%s)"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 清理函数
cleanup() {
    log_info "清理资源..."
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
    
    # 清理临时文件
    rm -f sse_output.txt sse_error.txt server_output.txt
    
    # 确保端口释放
    pkill -f "go run examples/main.go" 2>/dev/null || true
    pkill -f "examples/main.go" 2>/dev/null || true
    sleep 1
}

# 设置信号处理
trap cleanup EXIT INT TERM

# 启动服务器
start_server() {
    log_info "启动测试服务器..."
    
    # 确保端口没有被占用
    lsof -ti:8080 | xargs kill -9 2>/dev/null || true
    sleep 1
    
    # 启动服务器并捕获输出
    go run examples/main.go > server_output.txt 2>&1 &
    SERVER_PID=$!
    
    log_info "服务器PID: $SERVER_PID"
    
    # 等待服务器启动
    local timeout=15
    local count=0
    while [ $count -lt $timeout ]; do
        if curl -s "$BASE_URL/" > /dev/null 2>&1; then
            log_success "服务器启动成功"
            return 0
        fi
        sleep 1
        ((count++))
        echo -n "."
    done
    
    log_error "服务器启动超时"
    if [ -f server_output.txt ]; then
        log_error "服务器输出:"
        cat server_output.txt
    fi
    return 1
}

# 测试基本连接
test_basic_connection() {
    log_info "测试基本HTTP连接..."
    
    # 测试首页
    if curl -s "$BASE_URL/" > /dev/null; then
        log_success "首页连接正常"
    else
        log_error "首页连接失败"
        return 1
    fi
    
    # 测试SSE状态端点
    local status_response=$(curl -s "$BASE_URL/sse-api/status")
    log_info "SSE状态: $status_response"
    
    # 测试客户端列表端点
    local clients_response=$(curl -s "$BASE_URL/sse-api/clients")
    log_info "客户端列表: $clients_response"
}

# 测试SSE连接
test_sse_connection() {
    log_info "测试SSE连接..."
    
    local sse_url="$BASE_URL/sse-api/events?client_id=$CLIENT_ID&filter=user.created,user.updated,system.notice,ping,custom.test"
    log_info "SSE URL: $sse_url"
    
    # 启动SSE连接（后台运行）
    timeout 15s curl -N -s "$sse_url" > sse_output.txt 2> sse_error.txt &
    local curl_pid=$!
    
    log_info "SSE连接PID: $curl_pid"
    sleep 2
    
    # 检查连接是否成功建立
    if kill -0 $curl_pid 2>/dev/null; then
        log_success "SSE连接进程存在"
    else
        log_error "SSE连接进程不存在"
        if [ -f sse_error.txt ]; then
            log_error "连接错误:"
            cat sse_error.txt
        fi
        return 1
    fi
    
    # 发送测试消息
    sleep 1
    log_info "发送广播消息..."
    local broadcast_response=$(curl -s -X POST "$BASE_URL/sse-api/broadcast" \
        -H "Content-Type: application/json" \
        -d '{"event": "system.notice", "message": "测试广播消息"}')
    
    log_info "广播响应: $broadcast_response"
    
    # 再发送一条测试消息
    sleep 1
    log_info "发送自定义事件..."
    curl -s -X POST "$BASE_URL/sse-api/broadcast" \
        -H "Content-Type: application/json" \
        -d '{"event": "custom.test", "message": "自定义测试事件"}' > /dev/null
    
    # 等待一段时间收集数据
    sleep 3
    
    # 结束SSE连接
    if kill -0 $curl_pid 2>/dev/null; then
        kill $curl_pid 2>/dev/null || true
        wait $curl_pid 2>/dev/null || true
    fi
    
    # 分析SSE输出
    analyze_sse_output
}

# 分析SSE输出
analyze_sse_output() {
    log_info "分析SSE输出..."
    
    if [ ! -f sse_output.txt ]; then
        log_error "SSE输出文件不存在"
        return 1
    fi
    
    local output_size=$(wc -c < sse_output.txt)
    log_info "SSE输出文件大小: $output_size 字节"
    
    if [ $output_size -eq 0 ]; then
        log_error "SSE输出为空"
        if [ -f sse_error.txt ]; then
            log_error "错误输出:"
            cat sse_error.txt
        fi
        return 1
    fi
    
    log_info "SSE输出内容:"
    echo "----------------------------------------"
    cat sse_output.txt
    echo "----------------------------------------"
    
    # 检查输出中是否包含预期的SSE格式
    if grep -q "data:" sse_output.txt; then
        log_success "检测到SSE数据格式"
    else
        log_warning "未检测到标准SSE数据格式"
    fi
    
    if grep -q "event:" sse_output.txt; then
        log_success "检测到SSE事件格式"
    else
        log_warning "未检测到SSE事件格式"
    fi
    
    # 统计接收到的消息数量
    local message_count=$(grep -c "data:" sse_output.txt || echo "0")
    log_info "接收到的消息数量: $message_count"
    
    return 0
}

# 测试不同的SSE端点
test_different_endpoints() {
    log_info "测试不同的SSE端点..."
    
    # 测试原始端点
    log_info "测试 /events 端点..."
    timeout 5s curl -N -s "$BASE_URL/events?client_id=test_legacy" > sse_legacy.txt 2>&1 &
    local legacy_pid=$!
    
    sleep 2
    kill $legacy_pid 2>/dev/null || true
    wait $legacy_pid 2>/dev/null || true
    
    if [ -f sse_legacy.txt ] && [ -s sse_legacy.txt ]; then
        log_info "Legacy端点响应:"
        head -10 sse_legacy.txt
    else
        log_warning "Legacy端点无响应"
    fi
    
    rm -f sse_legacy.txt
}

# 测试服务器日志
check_server_logs() {
    log_info "检查服务器日志..."
    
    if [ -f server_output.txt ]; then
        log_info "服务器输出:"
        echo "----------------------------------------"
        tail -20 server_output.txt
        echo "----------------------------------------"
        
        # 检查是否有SSE相关的日志
        if grep -q "SSE" server_output.txt; then
            log_success "发现SSE相关日志"
        else
            log_warning "未发现SSE相关日志"
        fi
    else
        log_warning "服务器输出文件不存在"
    fi
}

# 主测试流程
main() {
    log_info "开始SSE功能测试..."
    log_info "客户端ID: $CLIENT_ID"
    
    # 启动服务器
    if ! start_server; then
        log_error "服务器启动失败，测试终止"
        exit 1
    fi
    
    # 测试基本连接
    if ! test_basic_connection; then
        log_error "基本连接测试失败"
        exit 1
    fi
    
    # 测试SSE连接
    if ! test_sse_connection; then
        log_error "SSE连接测试失败"
    fi
    
    # 测试不同端点
    test_different_endpoints
    
    # 检查服务器日志
    check_server_logs
    
    log_info "测试完成"
}

# 运行主程序
main "$@"