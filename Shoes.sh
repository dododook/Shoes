#!/bin/bash

# ================== 颜色代码 ==================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
RESET='\033[0m'

# ================== 常量定义 ==================
SHOES_BIN="/usr/local/bin/shoes"
SHOES_CONF_DIR="/etc/shoes"
SHOES_CONF_FILE="${SHOES_CONF_DIR}/config.yaml"
SHOES_SERVICE="/etc/systemd/system/shoes.service"
LINK_FILE="/root/proxy_links.txt"
TMP_DIR="/tmp/proxydl"
CURRENT_SCRIPT_PATH=$(readlink -f "$0") # 获取当前脚本路径

# ================== 依赖检查 ==================
install_dependencies() {
    if command -v apt >/dev/null; then
        apt update && apt install -y curl wget tar openssl jq iproute2
    elif command -v yum >/dev/null; then
        yum install -y curl wget tar openssl jq iproute
    fi
}

# ================== 架构检测 ==================
check_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) SHOES_ARCH="x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) SHOES_ARCH="aarch64-unknown-linux-gnu" ;;
        *) echo -e "${RED}不支持的架构: ${ARCH}${RESET}"; exit 1 ;;
    esac
}

# ================== 获取 IP ==================
get_public_ip() {
    curl -s -4 http://www.cloudflare.com/cdn-cgi/trace | grep ip | awk -F= '{print $2}'
}

# ================== 功能：创建快捷指令 ==================
create_shortcut() {
    # 将当前脚本复制到 /usr/local/bin 并重命名
    cp -f "$CURRENT_SCRIPT_PATH" /usr/local/bin/shoes-menu
    chmod +x /usr/local/bin/shoes-menu
    
    # 创建软链接到 /usr/bin/shoes
    ln -sf /usr/local/bin/shoes-menu /usr/bin/shoes
    
    echo -e "${GREEN}>>> 快捷指令已创建！${RESET}"
    echo -e "以后只需在终端输入 ${YELLOW}shoes${RESET} 即可打开此菜单。"
}

# ================== 功能：开启 BBR 加速 ==================
enable_bbr() {
    echo -e "${CYAN}=== 正在开启 BBR 加速 ===${RESET}"
    if grep -q "bbr" /etc/sysctl.conf; then
        echo -e "${GREEN}BBR 似乎已经开启，跳过配置。${RESET}"
    else
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
        echo -e "${GREEN}BBR 加速已开启！${RESET}"
    fi
    read -rp "按回车继续..." _
}

# ================== 功能：实时日志监控 ==================
view_realtime_log() {
    echo -e "${CYAN}=== 正在打开实时日志 (按 Ctrl+C 退出) ===${RESET}"
    echo -e "${GRAY}请现在尝试用客户端连接，如果连通，下方会滚动日志...${RESET}"
    sleep 2
    journalctl -u shoes -f
}

# ================== 核心功能: 下载二进制 ==================
download_shoes_core() {
    echo -e "${GREEN}>>> 正在获取最新 Shoes 版本信息...${RESET}"
    check_arch
    
    SHOES_VER=$(curl -s https://api.github.com/repos/cfal/shoes/releases/latest | grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/')
    [[ -z "$SHOES_VER" ]] && { echo -e "${RED}获取 Shoes 版本失败${RESET}"; return 1; }
    
    echo -e "${GREEN}>>> 最新版本: v${SHOES_VER}${RESET}"
    
    mkdir -p "${TMP_DIR}"
    cd "${TMP_DIR}" || exit 1
    
    SHOES_URL="https://github.com/cfal/shoes/releases/download/v${SHOES_VER}/shoes-${SHOES_ARCH}.tar.gz"
    echo -e "下载: $SHOES_URL"
    wget -O shoes.tar.gz "$SHOES_URL" || { echo -e "${RED}下载失败${RESET}"; return 1; }
    
    tar -xzf shoes.tar.gz
    FIND_SHOES=$(find . -type f -name "shoes" | head -n 1)
    [[ -z "$FIND_SHOES" ]] && { echo -e "${RED}解压后未找到 shoes${RESET}"; return 1; }
    
    systemctl stop shoes >/dev/null 2>&1
    cp "$FIND_SHOES" "${SHOES_BIN}"
    chmod +x "${SHOES_BIN}"
    return 0
}

# ================== 安装/重置 Shoes ==================
install_shoes() {
    install_dependencies
    
    download_shoes_core
    if [[ $? -ne 0 ]]; then return; fi

    mkdir -p "${SHOES_CONF_DIR}"
    
    # 随机 SNI
    SNI_LIST=("www.microsoft.com" "itunes.apple.com" "gateway.icloud.com" "www.amazon.com" "www.tesla.com" "dl.google.com" "www.yahoo.com")
    SNI=${SNI_LIST[$RANDOM % ${#SNI_LIST[@]}]}
    echo -e "${GREEN}>>> 随机伪装域名: ${YELLOW}${SNI}${RESET}"
    
    SHID=$(openssl rand -hex 8)
    VLESS_PORT=$(shuf -i 20001-30000 -n 1)
    UUID=$(cat /proc/sys/kernel/random/uuid)
    
    KEYPAIR=$(${SHOES_BIN} generate-reality-keypair)
    PRIVATE_KEY=$(echo "$KEYPAIR" | grep "private key" | awk '{print $4}')
    PUBLIC_KEY=$(echo "$KEYPAIR" | grep "public key" | awk '{print $4}')

    ANYTLS_PORT=$(shuf -i 30001-40000 -n 1)
    SS_PORT=$(shuf -i 40001-50000 -n 1)
    SS_CIPHER="aes-256-gcm"
    SS_PASSWORD=$(openssl rand -base64 16)

    openssl ecparam -genkey -name prime256v1 -out "${SHOES_CONF_DIR}/key.pem"
    openssl req -new -x509 -days 3650 -key "${SHOES_CONF_DIR}/key.pem" -out "${SHOES_CONF_DIR}/cert.pem" -subj "/CN=bing.com"

    cat > "${SHOES_CONF_FILE}" <<EOF
- address: "0.0.0.0:${VLESS_PORT}"
  protocol:
    type: tls
    reality_targets:
      "${SNI}":
        private_key: "${PRIVATE_KEY}"
        short_ids: ["${SHID}"]
        dest: "${SNI}:443"
        vision: true
        protocol:
          type: vless
          user_id: "${UUID}"
          udp_enabled: true
- address: "0.0.0.0:${ANYTLS_PORT}"
  protocol:
    type: tls
    tls_targets:
      "www.bing.com":
        cert: "/etc/shoes/cert.pem"
        key: "/etc/shoes/key.pem"
        protocol:
          type: anytls
          users:
            - name: anylts
              password: "${PUBLIC_KEY}"
          udp_enabled: true
- address: "0.0.0.0:${SS_PORT}"
  protocol:
    type: shadowsocks
    cipher: "${SS_CIPHER}"
    password: "${SS_PASSWORD}"
    udp_enabled: true
EOF

    cat > "${SHOES_SERVICE}" <<EOF
[Unit]
Description=Shoes Proxy Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=${SHOES_BIN} ${SHOES_CONF_FILE}
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now shoes
    
    # 自动创建快捷指令
    create_shortcut
    
    echo -e "${GREEN}Shoes 安装并配置完成！${RESET}"
    generate_links_content "$UUID" "$VLESS_PORT" "$SNI" "$PUBLIC_KEY" "$SHID" "$SS_PORT" "$SS_PASSWORD" "$SS_CIPHER"
}

# ================== 单独更新内核 ==================
update_shoes_only() {
    echo -e "${CYAN}=== 正在更新 Shoes 内核 (保留配置) ===${RESET}"
    if [[ ! -f "${SHOES_CONF_FILE}" ]]; then echo -e "${RED}未安装！${RESET}"; return; fi
    download_shoes_core
    if [[ $? -eq 0 ]]; then 
        systemctl restart shoes
        echo -e "${GREEN}更新成功！节点信息未变更。${RESET}"
    fi
}

# ================== 生成链接函数 ==================
generate_links_content() {
    local uuid=$1
    local vless_port=$2
    local sni=$3
    local pbk=$4
    local sid=$5
    local ss_port=$6
    local ss_pass=$7
    local ss_cipher=$8
    HOST_IP=$(get_public_ip)
    
    VLESS_LINK="vless://${uuid}@${HOST_IP}:${vless_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=random&pbk=${pbk}&sid=${sid}&type=tcp#Shoes_${sni}"
    SS_BASE=$(echo -n "${ss_cipher}:${ss_pass}" | base64 -w 0)
    SS_LINK="ss://${SS_BASE}@${HOST_IP}:${ss_port}#Shoes_SS"

    echo -e "\n${YELLOW}====== 配置信息汇总 ======${RESET}" > "${LINK_FILE}"
    echo -e "\n--- VLESS Reality (SNI: ${sni}) ---" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}${VLESS_LINK}${RESET}" | tee -a "${LINK_FILE}"
    echo -e "\n--- Shadowsocks ---" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}${SS_LINK}${RESET}" | tee -a "${LINK_FILE}"
}

# ================== IPv6 切换 ==================
switch_system_ipv6() {
    clear
    echo -e "${CYAN}=== 系统级 IPv6 出口 IP 切换 ===${RESET}"
    local ip_with_prefix=()
    mapfile -t ip_with_prefix < <(ip -6 addr show scope global | grep "inet6 " | awk '{print $2}')
    if [[ ${#ip_with_prefix[@]} -eq 0 ]]; then echo -e "${RED}无 IPv6${RESET}"; read -p "..." _; return; fi
    
    echo -e "可用 IP 列表："
    local i=1
    for item in "${ip_with_prefix[@]}"; do
        echo -e " ${GREEN}[$i]${RESET} ${YELLOW}${item}${RESET}"
        ((i++))
    done
    echo -e " ${GREEN}[0]${RESET} 取消"
    read -rp "选择: " choice
    [[ "$choice" == "0" || -z "$choice" ]] && return
    
    local target_item="${ip_with_prefix[$((choice-1))]}"
    [[ -z "$target_item" ]] && return
    
    local dev_name=$(ip -6 route show default | awk '/dev/ {print $5}' | head -n1)
    [[ -z "$dev_name" ]] && dev_name="eth0"
    
    for item in "${ip_with_prefix[@]}"; do
        ip addr change "$item" dev "$dev_name" preferred_lft 0 >/dev/null 2>&1
    done
    ip addr change "$target_item" dev "$dev_name" preferred_lft forever >/dev/null 2>&1
    
    echo -e "${GREEN}切换成功！${RESET}"
    read -rp "按回车继续..." _
}

# ================== 菜单 ==================
show_menu() {
    clear
    echo -e "${GREEN}=== Shoes 全能管理脚本 (V8.0) ===${RESET}"
    echo -e "${GRAY}提示：任意位置输入 'shoes' 即可再次打开${RESET}"
    
    if systemctl is-active --quiet shoes; then
        echo -e "状态: ${GREEN}运行中${RESET}"
    else
        echo -e "状态: ${RED}未运行${RESET}"
    fi
    echo "------------------------"
    echo "1. 安装 / 重置 Shoes"
    echo "2. 停止服务"
    echo "3. 重启服务"
    echo "4. 查看节点链接"
    echo "5. 卸载服务"
    echo "------------------------"
    echo -e "${CYAN}6. 高级网络设置 (IPv6 出口管理)${RESET}"
    echo -e "${YELLOW}7. 更新 Shoes 内核 (保留配置)${RESET}"
    echo -e "${BLUE}8. 开启 BBR 加速 (推荐)${RESET}"
    echo -e "${BLUE}9. 查看实时运行日志 (排错用)${RESET}"
    echo "------------------------"
    echo "0. 退出"
    read -p "请输入选项: " choice
}

# ================== 主逻辑 ==================
# 首次运行时自动建立快捷指令
if [[ ! -f /usr/bin/shoes ]]; then
    cp -f "$0" /usr/local/bin/shoes-menu
    chmod +x /usr/local/bin/shoes-menu
    ln -sf /usr/local/bin/shoes-menu /usr/bin/shoes
fi

check_arch
while true; do
    show_menu
    case "$choice" in
        1) install_shoes ;;
        2) systemctl stop shoes; echo "已停止" ;;
        3) systemctl restart shoes; echo "已重启" ;;
        4) if [[ -f "${LINK_FILE}" ]]; then cat "${LINK_FILE}"; else echo -e "${RED}无记录${RESET}"; fi ;;
        5) systemctl stop shoes; systemctl disable shoes; rm -f "${SHOES_SERVICE}" "${SHOES_CONF_DIR}" "${SHOES_BIN}" "/usr/bin/shoes"; systemctl daemon-reload; echo "卸载完成";;
        6) switch_system_ipv6 ;;
        7) update_shoes_only ;;
        8) enable_bbr ;;
        9) view_realtime_log ;;
        0) exit 0 ;;
        *) echo "无效选项" ;;
    esac
    read -p "按回车继续..."
done
