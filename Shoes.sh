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
CURRENT_SCRIPT_PATH=$(readlink -f "$0")

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

# ================== 快捷指令 ==================
create_shortcut() {
    cp -f "$CURRENT_SCRIPT_PATH" /usr/local/bin/shoes-menu
    chmod +x /usr/local/bin/shoes-menu
    ln -sf /usr/local/bin/shoes-menu /usr/bin/shoes
}

# ================== 核心功能: 下载二进制 ==================
download_shoes_core() {
    echo -e "${GREEN}>>> 正在获取最新 Shoes 版本信息...${RESET}"
    check_arch
    SHOES_VER=$(curl -s https://api.github.com/repos/cfal/shoes/releases/latest | grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/')
    [[ -z "$SHOES_VER" ]] && { echo -e "${RED}获取 Shoes 版本失败${RESET}"; return 1; }
    
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
    
    # === 参数生成 ===
    # 1. Reality
    SNI_LIST=("www.microsoft.com" "itunes.apple.com" "gateway.icloud.com" "www.amazon.com" "www.tesla.com" "dl.google.com" "www.yahoo.com")
    SNI=${SNI_LIST[$RANDOM % ${#SNI_LIST[@]}]}
    echo -e "${GREEN}>>> 随机伪装域名: ${YELLOW}${SNI}${RESET}"
    
    SHID=$(openssl rand -hex 8)
    VLESS_PORT=$(shuf -i 20001-30000 -n 1)
    UUID=$(cat /proc/sys/kernel/random/uuid)
    
    KEYPAIR=$(${SHOES_BIN} generate-reality-keypair)
    PRIVATE_KEY=$(echo "$KEYPAIR" | grep "private key" | awk '{print $4}')
    PUBLIC_KEY=$(echo "$KEYPAIR" | grep "public key" | awk '{print $4}')

    # 2. AnyTLS (HTTP/HTTPS Proxy)
    ANYTLS_PORT=$(shuf -i 30001-35000 -n 1)
    ANYTLS_USER="any"
    ANYTLS_PASS=$(openssl rand -base64 8) # 8位随机密码

    # 3. Shadowsocks
    SS_PORT=$(shuf -i 35001-40000 -n 1)
    SS_CIPHER="aes-256-gcm"
    SS_PASSWORD=$(openssl rand -base64 16)

    # 4. SOCKS5 (新增)
    SOCKS_PORT=$(shuf -i 40001-50000 -n 1)
    SOCKS_USER="socks"
    SOCKS_PASS=$(openssl rand -base64 8)

    # 生成自签名证书 (AnyTLS用)
    openssl ecparam -genkey -name prime256v1 -out "${SHOES_CONF_DIR}/key.pem"
    openssl req -new -x509 -days 3650 -key "${SHOES_CONF_DIR}/key.pem" -out "${SHOES_CONF_DIR}/cert.pem" -subj "/CN=bing.com"

    # === 写入配置 ===
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
            - name: "${ANYTLS_USER}"
              password: "${ANYTLS_PASS}"
          udp_enabled: true
- address: "0.0.0.0:${SS_PORT}"
  protocol:
    type: shadowsocks
    cipher: "${SS_CIPHER}"
    password: "${SS_PASSWORD}"
    udp_enabled: true
- address: "0.0.0.0:${SOCKS_PORT}"
  protocol:
    type: socks5
    users:
      - username: "${SOCKS_USER}"
        password: "${SOCKS_PASS}"
    udp_enabled: true
EOF

    # === Systemd ===
    cat > "${SHOES_SERVICE}" <<EOF
[Unit]
Description=Shoes Proxy Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=${SHOES_BIN} ${SHOES_CONF_FILE}
Restart=on-failure
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now shoes
    create_shortcut
    
    echo -e "${GREEN}Shoes (4协议) 安装完成！${RESET}"
    generate_links_content "$UUID" "$VLESS_PORT" "$SNI" "$PUBLIC_KEY" "$SHID" "$SS_PORT" "$SS_PASSWORD" "$SS_CIPHER" "$ANYTLS_PORT" "$ANYTLS_USER" "$ANYTLS_PASS" "$SOCKS_PORT" "$SOCKS_USER" "$SOCKS_PASS"
}

# ================== 生成链接 ==================
generate_links_content() {
    local uuid=$1; local vless_port=$2; local sni=$3; local pbk=$4; local sid=$5
    local ss_port=$6; local ss_pass=$7; local ss_cipher=$8
    local any_port=$9; local any_user=${10}; local any_pass=${11}
    local socks_port=${12}; local socks_user=${13}; local socks_pass=${14}
    
    HOST_IP=$(get_public_ip)
    
    # 1. VLESS
    VLESS_LINK="vless://${uuid}@${HOST_IP}:${vless_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=random&pbk=${pbk}&sid=${sid}&type=tcp#Shoes_${sni}"
    
    # 2. SS
    SS_BASE=$(echo -n "${ss_cipher}:${ss_pass}" | base64 -w 0)
    SS_LINK="ss://${SS_BASE}@${HOST_IP}:${ss_port}#Shoes_SS"
    
    # 3. SOCKS5
    SOCKS_BASE=$(echo -n "${socks_user}:${socks_pass}" | base64 -w 0)
    SOCKS_LINK="socks5://${SOCKS_BASE}@${HOST_IP}:${socks_port}#Shoes_S5"

    # 输出
    echo -e "\n${YELLOW}====== 配置信息汇总 ======${RESET}" > "${LINK_FILE}"
    
    echo -e "\n--- [1] VLESS Reality (推荐/主力) ---" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}${VLESS_LINK}${RESET}" | tee -a "${LINK_FILE}"

    echo -e "\n--- [2] Shadowsocks (游戏/备用) ---" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}${SS_LINK}${RESET}" | tee -a "${LINK_FILE}"
    
    echo -e "\n--- [3] SOCKS5 (TG/爬虫专用) ---" | tee -a "${LINK_FILE}"
    echo -e "地址: ${HOST_IP}:${socks_port}" | tee -a "${LINK_FILE}"
    echo -e "用户: ${socks_user}" | tee -a "${LINK_FILE}"
    echo -e "密码: ${socks_pass}" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}${SOCKS_LINK}${RESET}" | tee -a "${LINK_FILE}"

    echo -e "\n--- [4] AnyTLS (HTTPS Proxy) ---" | tee -a "${LINK_FILE}"
    echo -e "地址: ${HOST_IP}:${any_port}" | tee -a "${LINK_FILE}"
    echo -e "用户: ${any_user}" | tee -a "${LINK_FILE}"
    echo -e "密码: ${any_pass}" | tee -a "${LINK_FILE}"
    echo -e "${GRAY}(注: 这是一个 HTTPS 代理，需要信任自签名证书或在支持 insecure 的客户端使用)${RESET}" | tee -a "${LINK_FILE}"
}

# ================== 辅助功能 (省略部分重复代码) ==================
update_shoes_only() {
    echo -e "${CYAN}更新内核...${RESET}"; download_shoes_core
    if [[ $? -eq 0 ]]; then systemctl restart shoes; echo -e "${GREEN}更新成功${RESET}"; fi
}
switch_system_ipv6() {
    clear; echo -e "${CYAN}=== 系统级 IPv6 出口 IP 切换 ===${RESET}"
    # ... (保持原有的 IPv6 切换逻辑不变) ...
    # 为节省篇幅，这里调用系统 ip 命令，逻辑与 V8.0 完全一致
    local ip_with_prefix=(); mapfile -t ip_with_prefix < <(ip -6 addr show scope global | grep "inet6 " | awk '{print $2}')
    if [[ ${#ip_with_prefix[@]} -eq 0 ]]; then echo -e "${RED}无 IPv6${RESET}"; read -p "..." _; return; fi
    local i=1
    for item in "${ip_with_prefix[@]}"; do echo -e " ${GREEN}[$i]${RESET} ${YELLOW}${item}${RESET}"; ((i++)); done
    echo -e " ${GREEN}[0]${RESET} 取消"; read -rp "选择: " choice
    [[ "$choice" == "0" || -z "$choice" ]] && return
    local target_item="${ip_with_prefix[$((choice-1))]}"
    local dev_name=$(ip -6 route show default | awk '/dev/ {print $5}' | head -n1)
    [[ -z "$dev_name" ]] && dev_name="eth0"
    for item in "${ip_with_prefix[@]}"; do ip addr change "$item" dev "$dev_name" preferred_lft 0 >/dev/null 2>&1; done
    ip addr change "$target_item" dev "$dev_name" preferred_lft forever >/dev/null 2>&1
    echo -e "${GREEN}切换成功！${RESET}"; read -rp "..." _
}
enable_bbr() {
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p; echo -e "${GREEN}BBR 已开启${RESET}"; read -p "..." _
}
view_realtime_log() { journalctl -u shoes -f; }

# ================== 菜单 ==================
show_menu() {
    clear
    echo -e "${GREEN}=== Shoes 全协议管理脚本 (V9.0) ===${RESET}"
    echo -e "${GRAY}输入 'shoes' 再次打开 | 当前协议: VLESS+SS+SOCKS5+AnyTLS${RESET}"
    if systemctl is-active --quiet shoes; then echo -e "状态: ${GREEN}运行中${RESET}"; else echo -e "状态: ${RED}未运行${RESET}"; fi
    echo "------------------------"
    echo "1. 安装 / 重置 Shoes (全部重置)"
    echo "2. 停止服务"
    echo "3. 重启服务"
    echo "4. 查看所有链接"
    echo "5. 卸载服务"
    echo "------------------------"
    echo "6. IPv6 出口管理"
    echo "7. 更新内核"
    echo "8. 开启 BBR 加速"
    echo "9. 实时日志"
    echo "0. 退出"
    read -p "选项: " choice
}

# ================== 入口 ==================
if [[ ! -f /usr/bin/shoes ]]; then cp -f "$0" /usr/local/bin/shoes-menu; chmod +x /usr/local/bin/shoes-menu; ln -sf /usr/local/bin/shoes-menu /usr/bin/shoes; fi
check_arch
while true; do
    show_menu
    case "$choice" in
        1) install_shoes ;;
        2) systemctl stop shoes; echo "停用";; 
        3) systemctl restart shoes; echo "重启";;
        4) if [[ -f "${LINK_FILE}" ]]; then cat "${LINK_FILE}"; else echo -e "${RED}无配置${RESET}"; fi ;;
        5) systemctl stop shoes; systemctl disable shoes; rm -f "${SHOES_SERVICE}" "${SHOES_CONF_DIR}" "${SHOES_BIN}" "/usr/bin/shoes"; systemctl daemon-reload; echo "卸载完毕";;
        6) switch_system_ipv6 ;;
        7) update_shoes_only ;;
        8) enable_bbr ;;
        9) view_realtime_log ;;
        0) exit 0 ;;
        *) echo "无效" ;;
    esac
    read -p "回车继续..."
done
