#!/bin/bash

# SSE 性能测试脚本
set -e

SERVER_PID=""
BASE_URL="http://localhost:8080"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
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
    pkill -f "go run examples/main.go" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

# 启动服务器
start_server() {
    log_info "启动测试服务器..."
    lsof -ti:8080 | xargs kill -9 2>/dev/null || true
    sleep 1
    
    go run examples/main.go > /dev/null 2>&1 &
    SERVER_PID=$!
    
    # 等待服务器启动
    local count=0
    while [ $count -lt 15 ]; do
        if curl -s "$BASE_URL/" > /dev/null 2>&1; then
            log_success "服务器启动成功 (PID: $SERVER_PID)"
            return 0
        fi
        sleep 1
        ((count++))
    done
    
    log_error "服务器启动超时"
    return 1
}

# 测试性能指标
test_performance_metrics() {
    log_info "测试性能监控功能..."
    
    # 获取初始统计
    local initial_stats=$(curl -s "$BASE_URL/sse-api/stats" | jq -r '.data')
    log_info "初始统计: $initial_stats"
    
    # 建立多个SSE连接
    log_info "建立10个并发SSE连接..."
    for i in {1..10}; do
        timeout 8s curl -N -s "$BASE_URL/sse-api/events?client_id=perf_client_$i&filter=system.notice" > /dev/null &
    done
    
    sleep 2
    
    # 发送多条广播消息
    log_info "发送20条广播消息..."
    for i in {1..20}; do
        curl -s -X POST "$BASE_URL/sse-api/broadcast" \
            -H "Content-Type: application/json" \
            -d "{\"event\": \"system.notice\", \"message\": \"性能测试消息 $i\"}" > /dev/null
        sleep 0.1
    done
    
    sleep 3
    
    # 获取最终统计
    local final_stats=$(curl -s "$BASE_URL/sse-api/stats")
    local final_metrics=$(curl -s "$BASE_URL/sse-api/metrics")
    
    log_success "最终统计信息:"
    echo "$final_stats" | jq '.data'
    
    log_success "性能指标:"
    echo "$final_metrics" | jq '.data'
    
    # 检查关键指标
    local total_messages=$(echo "$final_stats" | jq -r '.data.total_messages')
    local total_broadcasts=$(echo "$final_stats" | jq -r '.data.total_broadcasts')
    local current_clients=$(echo "$final_stats" | jq -r '.data.current_clients')
    
    log_info "总消息数: $total_messages"
    log_info "总广播数: $total_broadcasts"  
    log_info "当前客户端数: $current_clients"
    
    if [ "$total_messages" -gt 0 ] && [ "$total_broadcasts" -gt 0 ]; then
        log_success "性能监控功能正常工作"
        return 0
    else
        log_error "性能监控可能存在问题"
        return 1
    fi
}

# 测试SSE重启功能
test_restart_functionality() {
    log_info "测试SSE重启功能..."
    
    # 获取重启前状态
    local before_restart=$(curl -s "$BASE_URL/sse-api/status")
    log_info "重启前状态: $(echo "$before_restart" | jq -r '.data.running')"
    
    # 执行重启
    local restart_result=$(curl -s "$BASE_URL/sse-api/restart")
    log_info "重启结果: $(echo "$restart_result" | jq -r '.msg')"
    
    sleep 1
    
    # 获取重启后状态
    local after_restart=$(curl -s "$BASE_URL/sse-api/status")
    log_info "重启后状态: $(echo "$after_restart" | jq -r '.data.running')"
    
    if [ "$(echo "$after_restart" | jq -r '.data.running')" = "true" ]; then
        log_success "SSE重启功能正常工作"
        return 0
    else
        log_error "SSE重启功能可能存在问题"
        return 1
    fi
}

# 主测试流程
main() {
    log_info "开始SSE性能测试..."
    
    if ! start_server; then
        log_error "服务器启动失败，测试终止"
        exit 1
    fi
    
    if ! test_performance_metrics; then
        log_error "性能监控测试失败"
        exit 1
    fi
    
    if ! test_restart_functionality; then
        log_error "重启功能测试失败"
        exit 1
    fi
    
    log_success "所有测试通过！"
}

main "$@"