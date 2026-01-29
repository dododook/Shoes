#!/bin/bash

# ================== 颜色代码 ==================
RED='\033[0;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
RESET='\033[0m'

# ================== 常量定义 ==================
SCRIPT_URL="https://raw.githubusercontent.com/dododook/Shoes/refs/heads/main/Shoes.sh"

# 真实二进制文件位置
REAL_BIN="/usr/local/bin/shoes-core"
# Alpine 专用兼容启动器位置
ALPINE_WRAPPER="/usr/local/bin/shoes-run"

MENU_BIN="/usr/local/bin/sho"
SHORTCUT_BIN="/usr/bin/sho"

SHOES_CONF_DIR="/etc/shoes"
SHOES_CONF_FILE="${SHOES_CONF_DIR}/config.yaml"
SHOES_SERVICE="/etc/systemd/system/shoes.service"
SHOES_RC_FILE="/etc/init.d/shoes"
SHOES_LOG_FILE="/var/log/shoes.log"
LINK_FILE="/root/proxy_links.txt"
TMP_DIR="/tmp/proxydl"

# 动态决定最终调用的命令（初始化为空）
SHOES_CMD=""

# 缓存 IP
CURRENT_IPV4=""
CURRENT_IPV6=""

# ================== 1. 智能环境检测与依赖 ==================
install_dependencies() {
    if command -v apt >/dev/null; then
        # Debian/Ubuntu
        apt update -q && apt install -y -q curl wget tar openssl jq iproute2 iptables sed grep
    elif command -v yum >/dev/null; then
        # CentOS/RHEL
        yum install -y -q curl wget tar openssl jq iproute iptables sed grep
    elif command -v apk >/dev/null; then
        # Alpine (特殊照顾)
        echo -e "${YELLOW}>>> 检测到 Alpine 系统，正在安装兼容层...${RESET}"
        apk update && apk add --no-cache bash curl wget tar openssl jq iproute2 coreutils grep sed gcompat libc6-compat
    fi
}

check_env_and_set_cmd() {
    # 检查依赖
    local need_install=0
    if ! command -v jq >/dev/null; then need_install=1; fi
    if ! command -v curl >/dev/null; then need_install=1; fi
    if [ -f /etc/alpine-release ] && ! command -v shuf >/dev/null; then need_install=1; fi # Alpine缺shuf
    
    if [ "$need_install" -eq 1 ]; then
        echo -e "${YELLOW}>>> 系统环境初始化...${RESET}"
        install_dependencies
    fi

    # === 核心逻辑：决定使用哪个命令 ===
    if [ -f /etc/alpine-release ]; then
        # Alpine 模式：使用兼容启动器
        SHOES_CMD="$ALPINE_WRAPPER"
    else
        # 普通模式：直接使用二进制
        SHOES_CMD="$REAL_BIN"
    fi
}

# ================== 2. 核心下载与 Alpine 适配 ==================
download_shoes_core() {
    echo -e "${GREEN}>>> 正在获取最新 Shoes 版本信息...${RESET}"
    # 架构检测
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) SHOES_ARCH="x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) SHOES_ARCH="aarch64-unknown-linux-gnu" ;;
        *) echo -e "${RED}不支持的架构: ${ARCH}${RESET}"; exit 1 ;;
    esac

    SHOES_VER=$(curl -s https://api.github.com/repos/cfal/shoes/releases/latest | grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/')
    [[ -z "$SHOES_VER" ]] && { echo -e "${RED}获取版本失败${RESET}"; return 1; }
    
    mkdir -p "${TMP_DIR}"
    cd "${TMP_DIR}" || exit 1
    
    # 下载
    wget -O shoes.tar.gz "https://github.com/cfal/shoes/releases/download/v${SHOES_VER}/shoes-${SHOES_ARCH}.tar.gz" || { echo -e "${RED}下载失败${RESET}"; return 1; }
    
    tar -xzf shoes.tar.gz
    FIND_SHOES=$(find . -type f -name "shoes" | head -n 1)
    [[ -z "$FIND_SHOES" ]] && { echo -e "${RED}解压失败${RESET}"; return 1; }
    
    # 停止旧进程
    killall shoes-core >/dev/null 2>&1
    
    # 移动真实二进制
    cp "$FIND_SHOES" "${REAL_BIN}"
    chmod +x "${REAL_BIN}"
    
    # === Alpine 专属逻辑 ===
    if [ -f /etc/alpine-release ]; then
        echo -e "${YELLOW}>>> 正在构建 Alpine 兼容启动器...${RESET}"
        # 寻找 musl 解释器
        LOADER=$(ls /lib/ld-musl-*.so.1 2>/dev/null | head -n 1)
        if [[ -z "$LOADER" ]]; then LOADER=$(ls /lib/libc.musl-*.so.1 2>/dev/null | head -n 1); fi
        
        if [[ -n "$LOADER" ]]; then
            # 创建包装器：强行指定解释器运行
            echo '#!/bin/bash' > "$ALPINE_WRAPPER"
            echo "exec $LOADER \"$REAL_BIN\" \"\$@\"" >> "$ALPINE_WRAPPER"
            chmod +x "$ALPINE_WRAPPER"
            echo -e "${GREEN}>>> 兼容启动器已建立: $ALPINE_WRAPPER${RESET}"
        else
            echo -e "${RED}>>> 严重警告: 未找到 musl 解释器，Alpine 可能无法运行！${RESET}"
            # 这种情况下只能死马当活马医，直接复制
            cp "${REAL_BIN}" "$ALPINE_WRAPPER"
        fi
        SHOES_CMD="$ALPINE_WRAPPER"
    else
        # 非 Alpine，清理可能残留的 wrapper，确保纯净
        rm -f "$ALPINE_WRAPPER"
        SHOES_CMD="$REAL_BIN"
    fi
    
    return 0
}

# ================== 3. 服务配置 (自动适配) ==================
setup_service() {
    # 场景 A: Systemd (Ubuntu/Debian/CentOS) - 使用纯净模式
    if command -v systemctl >/dev/null; then
        cat > "${SHOES_SERVICE}" <<EOF
[Unit]
Description=Shoes Proxy Server
After=network.target
[Service]
Type=simple
User=root
ExecStart=${SHOES_CMD} ${SHOES_CONF_FILE}
Restart=on-failure
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now shoes
        
    # 场景 B: OpenRC (Alpine) - 使用兼容模式+日志修正
    elif [ -f "/sbin/openrc-run" ]; then
        cat > "${SHOES_RC_FILE}" <<EOF
#!/sbin/openrc-run
name="shoes"
description="Shoes Proxy Server"
command="${SHOES_CMD}"
command_args="${SHOES_CONF_FILE}"
command_background=true
pidfile="/run/shoes.pid"
output_log="${SHOES_LOG_FILE}"
error_log="${SHOES_LOG_FILE}"
EOF
        chmod +x "${SHOES_RC_FILE}"
        rc-update add shoes default
        rc-service shoes restart
    
    # 场景 C: 容器/其他
    else
        nohup ${SHOES_CMD} ${SHOES_CONF_FILE} > "${SHOES_LOG_FILE}" 2>&1 &
    fi
}

# ================== 4. 辅助功能 ==================
get_ipv4() {
    local ip=$(curl -s -4 --max-time 1 http://www.cloudflare.com/cdn-cgi/trace | grep ip | awk -F= '{print $2}')
    if [[ -z "$ip" ]]; then echo "检测中..."; else echo "$ip"; fi
}
get_ipv6() {
    local ip=$(curl -s -6 --max-time 1 http://www.cloudflare.com/cdn-cgi/trace | grep ip | awk -F= '{print $2}')
    if [[ -z "$ip" ]]; then echo "${GRAY}未检测到 IPv6${RESET}"; else echo "$ip"; fi
}

open_port() {
    local port=$1
    local protocol=$2
    if command -v iptables >/dev/null; then iptables -I INPUT -p $protocol --dport $port -j ACCEPT 2>/dev/null; fi
    if command -v ufw >/dev/null; then if ufw status | grep -q "Status: active"; then ufw allow $port/$protocol >/dev/null; fi; fi
    if command -v firewall-cmd >/dev/null; then if firewall-cmd --state 2>/dev/null | grep -q "running"; then firewall-cmd --zone=public --add-port=$port/$protocol --permanent >/dev/null; firewall-cmd --reload >/dev/null; fi; fi
}

create_shortcut() {
    local current_file=$(readlink -f "$0")
    if [[ -f "$current_file" && ! -L "$current_file" && "$0" != "-bash" ]]; then cp -f "$current_file" "$MENU_BIN"; chmod +x "$MENU_BIN"; 
    else if curl -s --head --request GET "$SCRIPT_URL" | grep "200 OK" > /dev/null; then curl -sL "$SCRIPT_URL" -o "$MENU_BIN"; chmod +x "$MENU_BIN"; fi; fi
    ln -sf "$MENU_BIN" "$SHORTCUT_BIN"
}

ask_port() {
    local prompt=$1; local default_port=$2; local port_var=""
    while true; do
        read -rp "$prompt [默认随机: $default_port]: " port_var
        if [[ -z "$port_var" ]]; then echo "$default_port"; return; fi
        if [[ "$port_var" =~ ^[0-9]+$ ]] && [ "$port_var" -ge 1 ] && [ "$port_var" -le 65535 ]; then echo "$port_var"; return; else echo -e "${RED}无效端口${RESET}" >&2; fi
    done
}

# ================== 5. 安装流程 ==================
install_shoes() {
    local mode=$1
    check_env_and_set_cmd # 初始化环境和 CMD 变量
    download_shoes_core
    if [[ $? -ne 0 ]]; then return; fi

    # 验证运行能力
    if ! ${SHOES_CMD} --help >/dev/null 2>&1; then
        echo -e "${RED}错误: shoes-core 无法运行。${RESET}"
        if [ -f /etc/alpine-release ]; then echo -e "Alpine用户请尝试手动运行: apk add gcompat libc6-compat"; fi
    fi

    mkdir -p "${SHOES_CONF_DIR}"
    
    local rnd_vless=$(shuf -i 20001-30000 -n 1); local rnd_any=$(shuf -i 30001-35000 -n 1)
    local rnd_ss=$(shuf -i 35001-40000 -n 1); local rnd_ss22=$(shuf -i 40001-50000 -n 1)
    VLESS_PORT=$rnd_vless; ANYTLS_PORT=$rnd_any; SS_PORT=$rnd_ss; SS22_PORT=$rnd_ss22

    if [[ "$mode" == "custom" ]]; then
        echo -e "\n${CYAN}=== NAT/自定义端口模式 ===${RESET}"
        VLESS_PORT=$(ask_port "请输入 VLESS Reality 端口" $rnd_vless)
        ANYTLS_PORT=$(ask_port "请输入 AnyTLS (HTTPS) 端口" $rnd_any)
        SS_PORT=$(ask_port "请输入 SS-Legacy 端口" $rnd_ss)
        SS22_PORT=$(ask_port "请输入 SS-2022 端口" $rnd_ss22)
    fi

    SNI_LIST=("www.microsoft.com" "itunes.apple.com" "gateway.icloud.com" "www.amazon.com" "dl.google.com")
    SNI=${SNI_LIST[$RANDOM % ${#SNI_LIST[@]}]}
    SHID=$(openssl rand -hex 8)
    UUID=$(cat /proc/sys/kernel/random/uuid)
    
    echo -e "${YELLOW}>>> 正在生成密钥...${RESET}"
    # 使用正确的 CMD 生成密钥
    KEYPAIR=$(${SHOES_CMD} generate-reality-keypair)
    PRIVATE_KEY=$(echo "$KEYPAIR" | grep "private key" | awk '{print $4}')
    PUBLIC_KEY=$(echo "$KEYPAIR" | grep "public key" | awk '{print $4}')
    
    if [[ -z "$PRIVATE_KEY" ]]; then
        echo -e "${RED}密钥生成失败，使用 OpenSSL 备用生成...${RESET}"
        PRIVATE_KEY=$(openssl genpkey -algorithm x25519 -out /tmp/k.pem && openssl pkey -in /tmp/k.pem -text | grep "priv:" -A 3 | tail -n +2 | tr -d ' \n:' | xxd -r -p | base64)
    fi

    open_port "$VLESS_PORT" "tcp"; open_port "$VLESS_PORT" "udp"
    ANYTLS_USER="anytls"; ANYTLS_PASS=$(openssl rand -hex 8); ANYTLS_SNI="www.bing.com"; open_port "$ANYTLS_PORT" "tcp"
    SS_CIPHER="aes-256-gcm"; SS_PASSWORD=$(openssl rand -base64 16); open_port "$SS_PORT" "tcp"; open_port "$SS_PORT" "udp"
    SS22_CIPHER="2022-blake3-aes-256-gcm"; SS22_PASSWORD=$(openssl rand -base64 32); open_port "$SS22_PORT" "tcp"; open_port "$SS22_PORT" "udp"

    openssl ecparam -genkey -name prime256v1 -out "${SHOES_CONF_DIR}/key.pem"
    openssl req -new -x509 -days 3650 -key "${SHOES_CONF_DIR}/key.pem" -out "${SHOES_CONF_DIR}/cert.pem" -subj "/CN=${ANYTLS_SNI}"

    cat > "${SHOES_CONF_FILE}" <<EOF
- address: "0.0.0.0:${VLESS_PORT}"
  protocol: { type: tls, reality_targets: { "${SNI}": { private_key: "${PRIVATE_KEY}", short_ids: ["${SHID}"], dest: "${SNI}:443", vision: true, protocol: { type: vless, user_id: "${UUID}", udp_enabled: true } } } }
- address: "0.0.0.0:${ANYTLS_PORT}"
  protocol: { type: tls, tls_targets: { "${ANYTLS_SNI}": { cert: "/etc/shoes/cert.pem", key: "/etc/shoes/key.pem", protocol: { type: anytls, users: [{ name: "${ANYTLS_USER}", password: "${ANYTLS_PASS}" }], udp_enabled: true } } } }
- address: "0.0.0.0:${SS_PORT}"
  protocol: { type: shadowsocks, cipher: "${SS_CIPHER}", password: "${SS_PASSWORD}", udp_enabled: true }
- address: "0.0.0.0:${SS22_PORT}"
  protocol: { type: shadowsocks, cipher: "${SS22_CIPHER}", password: "${SS22_PASSWORD}", udp_enabled: true }
EOF

    setup_service
    create_shortcut
    echo -e "${GREEN}Shoes 安装完成！${RESET}"
    
    # 生成链接部分
    local ip=$(curl -s -4 http://www.cloudflare.com/cdn-cgi/trace | grep ip | awk -F= '{print $2}')
    echo -e "\n${YELLOW}====== 配置信息汇总 ======${RESET}" > "${LINK_FILE}"
    echo -e "\n--- [1] VLESS Reality (SNI: ${SNI}) ---" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}vless://${UUID}@${ip}:${VLESS_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=random&pbk=${PUBLIC_KEY}&sid=${SHID}&type=tcp#Shoes_${SNI}${RESET}" | tee -a "${LINK_FILE}"
    
    local ss_base=$(echo -n "${SS_CIPHER}:${SS_PASSWORD}" | base64 -w 0)
    echo -e "\n--- [2] SS-2022 (抗重放/推荐) ---" | tee -a "${LINK_FILE}"
    local ss22_base=$(echo -n "${SS22_CIPHER}:${SS22_PASSWORD}" | base64 -w 0)
    echo -e "链接: ${GREEN}ss://${ss22_base}@${ip}:${SS22_PORT}#Shoes_2022${RESET}" | tee -a "${LINK_FILE}"
    
    echo -e "\n--- [3] SS-Legacy (传统/游戏) ---" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}ss://${ss_base}@${ip}:${SS_PORT}#Shoes_Legacy${RESET}" | tee -a "${LINK_FILE}"
    
    echo -e "\n--- [4] AnyTLS (HTTPS Proxy) ---" | tee -a "${LINK_FILE}"
    echo -e "端口: ${RED}${ANYTLS_PORT}${RESET}" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}anytls://${ANYTLS_PASS}@${ip}:${ANYTLS_PORT}?security=tls&insecure=1&type=tcp&sni=${ANYTLS_SNI}#Shoes_AnyTLS${RESET}" | tee -a "${LINK_FILE}"
}

# ================== Menu 6 功能函数 ==================
sub_switch_ipv6_exit() {
    clear
    echo -e "${CYAN}=== 系统级 IPv6 出口 IP 切换 ===${RESET}"
    echo -e "${GREEN}➜ ${RESET}正在扫描网卡上的公网 IPv6 地址..."
    echo -e "${GREEN}➜ ${RESET}正在进行 地区解析 与 延迟测试 (Cloudflare)..."
    echo -e "${GRAY}(如果 IP 较多，测试可能需要几秒钟，请耐心等待)${RESET}"
    echo ""
    local ip_with_prefix=(); mapfile -t ip_with_prefix < <(ip -6 addr show scope global | grep "inet6 " | awk '{print $2}')
    if [[ ${#ip_with_prefix[@]} -eq 0 ]]; then echo -e "${RED}未检测到可用的公网 IPv6 地址。${RESET}"; read -rp "按回车返回..." _; return; fi
    local current_exit_ip=$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | grep -oP 'src \K\S+')
    echo -e "${GREEN}请选择要设为默认出口的 IP:${RESET}\n"
    local i=1; local ping_cmd="ping -6"; command -v ping >/dev/null 2>&1 || ping_cmd="ping6"
    for item in "${ip_with_prefix[@]}"; do
        local addr=${item%/*}; local status_mark=""
        if [[ "$addr" == "$current_exit_ip" ]]; then status_mark="${GREEN}✔${RESET} ${YELLOW}(当前活跃)${RESET}";
        elif ip -6 addr show | grep -F "$item" | grep -q "deprecated"; then status_mark="${GRAY}(备用)${RESET}";
        else status_mark="${GRAY}(可选)${RESET}"; fi
        local loc_str=""; if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then local api_res=$(curl -s --max-time 1 "http://ip-api.com/json/${addr}?lang=zh-CN&fields=country,city" 2>/dev/null); if [[ -n "$api_res" ]]; then local country=$(echo "$api_res" | jq -r '.country // empty'); local city=$(echo "$api_res" | jq -r '.city // empty'); [[ -n "$country" ]] && loc_str="${BLUE}[${country} ${city}]${RESET}" || loc_str="${GRAY}[未知]${RESET}"; else loc_str="${GRAY}[超时]${RESET}"; fi; fi
        local lat_val=$($ping_cmd -c 1 -w 1 -I "$addr" 2606:4700:4700::1111 2>/dev/null | grep -o 'time=[0-9.]*' | cut -d= -f2)
        local lat_str=""; if [[ -n "$lat_val" ]]; then local lat_num=${lat_val%.*}; if [[ "$lat_num" -lt 100 ]]; then lat_str="${GREEN}[${lat_val}ms]${RESET}"; elif [[ "$lat_num" -lt 200 ]]; then lat_str="${YELLOW}[${lat_val}ms]${RESET}"; else lat_str="${RED}[${lat_val}ms]${RESET}"; fi; else lat_str="${RED}[超时]${RESET}"; fi
        echo -e " ${GREEN}[$i]${RESET} ${PURPLE}${addr}${RESET} ${loc_str} ${lat_str} ${status_mark}"; ((i++))
    done
    echo -e " ${GREEN}[0]${RESET} 取消返回"; read -rp "请输入序号 [0-$((i-1))]: " choice
    [[ "$choice" == "0" || -z "$choice" ]] && return
    local target_item="${ip_with_prefix[$((choice-1))]}"
    local target_ip="${target_item%/*}"; [[ -z "$target_ip" ]] && return
    echo -e "\n正在切换出口 IP 至: $target_ip ..."
    local gateway=$(ip -6 route show default | awk '/via/ {print $3}' | head -n1)
    local dev_name=$(ip -6 route show default | awk '/dev/ {print $5}' | head -n1); [[ -z "$dev_name" ]] && dev_name="eth0"
    for item in "${ip_with_prefix[@]}"; do ip addr change "$item" dev "$dev_name" preferred_lft 0 >/dev/null 2>&1; done
    ip addr change "$target_item" dev "$dev_name" preferred_lft forever >/dev/null 2>&1
    if [[ -n "$gateway" ]]; then ip -6 route replace default via "$gateway" dev "$dev_name" src "$target_ip" onlink >/dev/null 2>&1; else ip -6 route replace default dev "$dev_name" src "$target_ip" onlink >/dev/null 2>&1; fi
    echo -e "${GREEN}切换成功！${RESET}"; read -rp "按回车继续..." _
}

sub_set_preference() {
    clear; echo -e "${CYAN}=== IPv4/v6 优先级 ===${RESET}"
    grep -q "^precedence ::ffff:0:0/96 100" /etc/gai.conf 2>/dev/null && echo -e "当前: ${GREEN}IPv4 优先${RESET}" || echo -e "当前: ${BLUE}IPv6 优先${RESET}"
    echo -e "\n${GREEN}[1]${RESET} 设为 IPv4 优先\n${GREEN}[2]${RESET} 设为 IPv6 优先\n${GREEN}[0]${RESET} 返回\n"
    read -rp "选择: " c; case "$c" in 1) echo "precedence ::ffff:0:0/96 100" >> /etc/gai.conf ;; 2) sed -i '/^precedence ::ffff:0:0\/96 100/d' /etc/gai.conf ;; esac
    echo -e "${GREEN}设置完成${RESET}"; read -rp "..." _
}

sub_check_ports() {
    clear; echo -e "${CYAN}=== 端口监听状态 (ss -tulpn) ===${RESET}"
    echo -e "${GRAY}重点关注 Process 为 ${GREEN}shoes-core${RESET}${GRAY} 的行，那些就是你的代理端口。${RESET}"
    echo -e "${YELLOW}Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name${RESET}"
    echo -e "${GRAY}-----------------------------------------------------------------------------------------${RESET}"
    ss -tulpn | grep -E "^(udp|tcp)" | while read -r line; do
        if [[ "$line" == *"shoes-core"* ]]; then echo -e "${PURPLE}${line//shoes-core/${GREEN}shoes-core${PURPLE}}${RESET}"; else echo -e "${PURPLE}${line}${RESET}"; fi
    done
    echo -e "${GRAY}-----------------------------------------------------------------------------------------${RESET}"
    echo -e "未见 ${GREEN}shoes-core${RESET} 则服务未启动"; echo ""; read -rp "按回车返回..." _
}

menu_advanced_network() {
    while true; do
        clear; echo -e "${CYAN}=== 高级网络设置 ===${RESET}"
        echo -e "${GREEN}[1]${RESET} 切换 IPv6 出口 IP\n${GREEN}[2]${RESET} 设置 IPv4/IPv6 优先级\n${GREEN}[3]${RESET} 查询端口监听 (美化版)\n${GREEN}[0]${RESET} 返回"
        read -rp "选择: " c; case "$c" in 1) sub_switch_ipv6_exit;; 2) sub_set_preference;; 3) sub_check_ports;; 0) return;; esac
    done
}

update_shoes_only() { echo -e "${CYAN}更新内核...${RESET}"; check_env_and_set_cmd; download_shoes_core; if [[ $? -eq 0 ]]; then if command -v systemctl >/dev/null; then systemctl restart shoes; else rc-service shoes restart; fi; echo -e "${GREEN}更新成功${RESET}"; fi }
enable_bbr() { if grep -q "bbr" /etc/sysctl.conf; then echo -e "${GREEN}BBR 已开启${RESET}"; else echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf; echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf; sysctl -p; echo -e "${GREEN}BBR 已开启${RESET}"; fi; read -p "..." _; }
view_realtime_log() {
    echo -e "${CYAN}Ctrl+C 退出${RESET}"
    if command -v journalctl >/dev/null; then journalctl -u shoes -f; elif [ -f "${SHOES_LOG_FILE}" ]; then tail -f "${SHOES_LOG_FILE}"; else echo -e "${RED}无日志文件${RESET}"; read -p "..."; fi
}

show_menu() {
    clear
    local cpu_usage=$(awk '{print $1}' /proc/loadavg)
    local mem_usage=$(free -m | awk 'NR==2{printf "%sMB/%sMB (%.0f%%)", $3, $2, $3*100/$2 }')
    if [[ -z "$CURRENT_IPV4" ]]; then CURRENT_IPV4=$(get_ipv4); fi
    if [[ -z "$CURRENT_IPV6" ]]; then CURRENT_IPV6=$(get_ipv6); fi
    
    echo -e "${GREEN}=== Shoes 全协议管理脚本 (V46.0 智能双核版) ===${RESET}"
    echo ""
    echo -e "${CYAN}┌──[ 系统监控 ]────────────────────────────────────────────────┐${RESET}"
    echo -e "${CYAN}│                                                              │${RESET}"
    echo -e "${CYAN}│   ${RESET}CPU负载: ${GREEN}${cpu_usage}${RESET}  |  内存使用: ${GREEN}${mem_usage}${RESET}"
    echo -e "${CYAN}│   ${RESET}IPv4: ${GREEN}${CURRENT_IPV4}${RESET}"
    echo -e "${CYAN}│   ${RESET}IPv6: ${GREEN}${CURRENT_IPV6}${RESET}"
    echo -e "${CYAN}│                                                              │${RESET}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    echo -e "${GRAY}输入 'sho' 再次打开 | 状态: $(pidof shoes-core >/dev/null && echo "${GREEN}运行中" || echo "${RED}未运行")${RESET}"
    echo "------------------------"
    echo "1. 安装 / 重置 Shoes (随机端口)"
    echo -e "${RED}2. 自定义端口重装 (NAT/高级专用)${RESET}"
    echo "3. 停止服务"
    echo "4. 重启服务"
    echo "5. 查看所有链接"
    echo "6. 卸载服务"
    echo "------------------------"
    echo -e "${CYAN}7. 高级网络设置 (IPv6 / 优先级 / 端口)${RESET}"
    echo -e "${YELLOW}8. 开启 BBR 加速 (优化网络速度)${RESET}"
    echo -e "${BLUE}9. 更新 Shoes 内核 (保留配置文件)${RESET}"
    echo "------------------------"
    echo -e "${GRAY}10. 查看实时日志${RESET}"
    echo "0. 退出"
    read -p "选项: " choice
}

check_and_install_deps
check_env_and_set_cmd # 启动时判断模式
create_shortcut
check_arch
CURRENT_IPV4=$(get_ipv4)
CURRENT_IPV6=$(get_ipv6)

while true; do
    show_menu
    case "$choice" in
        1) install_shoes "random" ;;
        2) install_shoes "custom" ;;
        3) if command -v systemctl >/dev/null; then systemctl stop shoes; elif command -v rc-service >/dev/null; then rc-service shoes stop; else killall shoes-core; fi; echo "停用";; 
        4) if command -v systemctl >/dev/null; then systemctl restart shoes; elif command -v rc-service >/dev/null; then rc-service shoes restart; else killall shoes-core; nohup ${SHOES_CMD} ${SHOES_CONF_FILE} > "${SHOES_LOG_FILE}" 2>&1 & fi; echo "重启";;
        5) if [[ -f "${LINK_FILE}" ]]; then cat "${LINK_FILE}"; else echo -e "${RED}无配置${RESET}"; fi ;;
        6) if command -v systemctl >/dev/null; then systemctl disable shoes >/dev/null 2>&1; else rc-update del shoes default >/dev/null 2>&1; fi; rm -f "${SHOES_SERVICE}" "${SHOES_RC_FILE}" "${SHOES_CONF_DIR}" "${REAL_BIN}" "${ALPINE_WRAPPER}" "/usr/local/bin/sho" "/usr/bin/sho"; echo "卸载完毕";;
        7) menu_advanced_network ;;
        8) enable_bbr ;;       
        9) update_shoes_only ;; 
        10) view_realtime_log ;;
        0) exit 0 ;;
        *) echo "无效" ;;
    esac
    read -p "回车继续..."
done
