#!/bin/bash

# ================== 颜色代码 ==================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
RESET='\033[0m'

# ================== 常量定义 ==================
SCRIPT_URL="https://raw.githubusercontent.com/dododook/Shoes/refs/heads/main/Shoes.sh"

SHOES_BIN="/usr/local/bin/shoes-core"
MENU_BIN="/usr/local/bin/sho"
SHORTCUT_BIN="/usr/bin/sho"

SHOES_CONF_DIR="/etc/shoes"
SHOES_CONF_FILE="${SHOES_CONF_DIR}/config.yaml"
SHOES_SERVICE="/etc/systemd/system/shoes.service"
LINK_FILE="/root/proxy_links.txt"
TMP_DIR="/tmp/proxydl"

# ================== 依赖检查 ==================
install_dependencies() {
    if command -v apt >/dev/null; then
        apt update && apt install -y curl wget tar openssl jq iproute2 iptables sed
    elif command -v yum >/dev/null; then
        yum install -y curl wget tar openssl jq iproute iptables sed
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
    local current_file=$(readlink -f "$0")
    if [[ -f "$current_file" && ! -L "$current_file" && "$0" != "-bash" ]]; then
        cp -f "$current_file" "$MENU_BIN"
        chmod +x "$MENU_BIN"
        echo -e "${GREEN}>>> 快捷指令安装成功！以后输入 'sho' 即可使用。${RESET}"
    else
        echo -e "${YELLOW}>>> 检测到非本地文件运行，正在尝试从 GitHub 拉取以安装快捷键...${RESET}"
        if curl -s --head --request GET "$SCRIPT_URL" | grep "200 OK" > /dev/null; then
            curl -sL "$SCRIPT_URL" -o "$MENU_BIN"
            chmod +x "$MENU_BIN"
            echo -e "${GREEN}>>> 快捷指令已从 GitHub 恢复。${RESET}"
        else
            echo -e "${RED}⚠️  无法创建快捷指令 'sho' (网络或文件问题)。${RESET}"
        fi
    fi
    if [[ -f "/usr/bin/shoes" ]]; then rm -f "/usr/bin/shoes"; fi
    hash -r 2>/dev/null
    ln -sf "$MENU_BIN" "$SHORTCUT_BIN"
}

# ================== 端口放行 ==================
open_port() {
    local port=$1
    local protocol=$2
    if command -v iptables >/dev/null; then iptables -I INPUT -p $protocol --dport $port -j ACCEPT 2>/dev/null; fi
    if command -v ufw >/dev/null; then if ufw status | grep -q "Status: active"; then ufw allow $port/$protocol >/dev/null; fi; fi
    if command -v firewall-cmd >/dev/null; then if firewall-cmd --state 2>/dev/null | grep -q "running"; then firewall-cmd --zone=public --add-port=$port/$protocol --permanent >/dev/null; firewall-cmd --reload >/dev/null; fi; fi
}

# ================== 核心下载 ==================
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
    
    # === 1. Reality ===
    SNI_LIST=("www.microsoft.com" "itunes.apple.com" "gateway.icloud.com" "www.amazon.com" "dl.google.com")
    SNI=${SNI_LIST[$RANDOM % ${#SNI_LIST[@]}]}
    SHID=$(openssl rand -hex 8)
    VLESS_PORT=$(shuf -i 20001-30000 -n 1)
    UUID=$(cat /proc/sys/kernel/random/uuid)
    KEYPAIR=$(${SHOES_BIN} generate-reality-keypair)
    PRIVATE_KEY=$(echo "$KEYPAIR" | grep "private key" | awk '{print $4}')
    PUBLIC_KEY=$(echo "$KEYPAIR" | grep "public key" | awk '{print $4}')
    open_port "$VLESS_PORT" "tcp"
    open_port "$VLESS_PORT" "udp"

    # === 2. AnyTLS ===
    ANYTLS_PORT=$(shuf -i 30001-35000 -n 1)
    ANYTLS_USER="anytls"
    ANYTLS_PASS=$(openssl rand -hex 8)
    ANYTLS_SNI="www.bing.com"
    open_port "$ANYTLS_PORT" "tcp"

    # === 3. Shadowsocks (Legacy) ===
    SS_PORT=$(shuf -i 35001-40000 -n 1)
    SS_CIPHER="aes-256-gcm"
    SS_PASSWORD=$(openssl rand -base64 16)
    open_port "$SS_PORT" "tcp"
    open_port "$SS_PORT" "udp"

    # === 4. SS-2022 ===
    SS22_PORT=$(shuf -i 45001-55000 -n 1)
    SS22_CIPHER="2022-blake3-aes-256-gcm"
    SS22_PASSWORD=$(openssl rand -base64 32)
    open_port "$SS22_PORT" "tcp"
    open_port "$SS22_PORT" "udp"

    # 证书
    openssl ecparam -genkey -name prime256v1 -out "${SHOES_CONF_DIR}/key.pem"
    openssl req -new -x509 -days 3650 -key "${SHOES_CONF_DIR}/key.pem" -out "${SHOES_CONF_DIR}/cert.pem" -subj "/CN=${ANYTLS_SNI}"

    # 写入配置
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
      "${ANYTLS_SNI}":
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
- address: "0.0.0.0:${SS22_PORT}"
  protocol:
    type: shadowsocks
    cipher: "${SS22_CIPHER}"
    password: "${SS22_PASSWORD}"
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
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now shoes
    create_shortcut
    echo -e "${GREEN}Shoes (4协议安全版) 安装完成！${RESET}"
    
    generate_links_content "$UUID" "$VLESS_PORT" "$SNI" "$PUBLIC_KEY" "$SHID" "$SS_PORT" "$SS_PASSWORD" "$SS_CIPHER" "$ANYTLS_PORT" "$ANYTLS_USER" "$ANYTLS_PASS" "$ANYTLS_SNI" "$SS22_PORT" "$SS22_PASSWORD" "$SS22_CIPHER"
}

# ================== 生成链接 ==================
generate_links_content() {
    local uuid=$1; local vless_port=$2; local sni=$3; local pbk=$4; local sid=$5
    local ss_port=$6; local ss_pass=$7; local ss_cipher=$8
    local any_port=$9; local any_user=${10}; local any_pass=${11}; local any_sni=${12}
    local ss22_port=${13}; local ss22_pass=${14}; local ss22_cipher=${15}
    HOST_IP=$(get_public_ip)
    
    VLESS_LINK="vless://${uuid}@${HOST_IP}:${vless_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=random&pbk=${pbk}&sid=${sid}&type=tcp#Shoes_${sni}"
    SS_BASE=$(echo -n "${ss_cipher}:${ss_pass}" | base64 -w 0)
    SS_LINK="ss://${SS_BASE}@${HOST_IP}:${ss_port}#Shoes_Legacy"
    SS22_BASE=$(echo -n "${ss22_cipher}:${ss22_pass}" | base64 -w 0)
    SS22_LINK="ss://${SS22_BASE}@${HOST_IP}:${ss22_port}#Shoes_2022"
    ANYTLS_LINK="anytls://${any_pass}@${HOST_IP}:${any_port}?security=tls&insecure=1&type=tcp&sni=${any_sni}#Shoes_AnyTLS"

    echo -e "\n${YELLOW}====== 配置信息汇总 ======${RESET}" > "${LINK_FILE}"
    echo -e "\n--- [1] VLESS Reality (SNI: ${sni}) ---" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}${VLESS_LINK}${RESET}" | tee -a "${LINK_FILE}"
    echo -e "\n--- [2] SS-2022 (抗重放/推荐) ---" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}${SS22_LINK}${RESET}" | tee -a "${LINK_FILE}"
    echo -e "\n--- [3] SS-Legacy (传统/游戏) ---" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}${SS_LINK}${RESET}" | tee -a "${LINK_FILE}"
    echo -e "\n--- [4] AnyTLS (HTTPS Proxy) ---" | tee -a "${LINK_FILE}"
    echo -e "端口: ${RED}${any_port}${RESET}" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}${ANYTLS_LINK}${RESET}" | tee -a "${LINK_FILE}"
}

# ================== 子菜单: IPv6 切换 ==================
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
        if [[ "$addr" == "$current_exit_ip" ]]; then status_mark="${GREEN}✔${RESET} ${YELLOW}(当前默认)${RESET}";
        elif ip -6 addr show | grep -F "$item" | grep -q "deprecated"; then status_mark="${GRAY}(备用)${RESET}";
        else status_mark="${GRAY}(可选)${RESET}"; fi
        local loc_str=""; if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then local api_res=$(curl -s --max-time 1 "http://ip-api.com/json/${addr}?lang=zh-CN&fields=country,city" 2>/dev/null); if [[ -n "$api_res" ]]; then local country=$(echo "$api_res" | jq -r '.country // empty'); local city=$(echo "$api_res" | jq -r '.city // empty'); [[ -n "$country" ]] && loc_str="${BLUE}[${country} ${city}]${RESET}" || loc_str="${GRAY}[未知]${RESET}"; else loc_str="${GRAY}[超时]${RESET}"; fi; fi
        local lat_val=$($ping_cmd -c 1 -w 1 -I "$addr" 2606:4700:4700::1111 2>/dev/null | grep -o 'time=[0-9.]*' | cut -d= -f2)
        local lat_str=""; if [[ -n "$lat_val" ]]; then local lat_num=${lat_val%.*}; if [[ "$lat_num" -lt 100 ]]; then lat_str="${GREEN}[${lat_val}ms]${RESET}"; elif [[ "$lat_num" -lt 200 ]]; then lat_str="${YELLOW}[${lat_val}ms]${RESET}"; else lat_str="${RED}[${lat_val}ms]${RESET}"; fi; else lat_str="${RED}[超时]${RESET}"; fi
        echo -e " ${GREEN}[$i]${RESET} ${PURPLE}${addr}${RESET} ${loc_str} ${lat_str} ${status_mark}"; ((i++))
    done
    echo -e " ${GREEN}[0]${RESET} 取消返回"
    echo ""; read -rp "请输入序号 [0-$((i-1))]: " choice
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

# ================== 子菜单: 优先级切换 ==================
sub_set_preference() {
    clear
    echo -e "${CYAN}=== 系统网络优先级设置 (IPv4 vs IPv6) ===${RESET}"
    local current_pref=""
    if grep -q "^precedence ::ffff:0:0/96 100" /etc/gai.conf 2>/dev/null; then
        current_pref="${GREEN}IPv4 优先${RESET}"
    else
        current_pref="${BLUE}IPv6 优先 (默认)${RESET}"
    fi
    echo -e "当前状态: ${current_pref}"
    echo -e "说明: 修改此项可以解决部分网站解析慢或连接失败的问题。"
    echo ""
    echo -e "${GREEN}[1]${RESET} 设置为 IPv4 优先 (推荐,兼容性好)"
    echo -e "${GREEN}[2]${RESET} 设置为 IPv6 优先 (系统默认)"
    echo -e "${GREEN}[0]${RESET} 返回"
    echo ""
    read -rp "请选择: " sub_choice
    case "$sub_choice" in
        1)
            if [[ ! -f /etc/gai.conf ]]; then echo "precedence ::ffff:0:0/96 100" > /etc/gai.conf; else sed -i '/^precedence ::ffff:0:0\/96 100/d' /etc/gai.conf; echo "precedence ::ffff:0:0/96 100" >> /etc/gai.conf; fi
            echo -e "${GREEN}已设置为 IPv4 优先！${RESET}"
            ;;
        2)
            if [[ -f /etc/gai.conf ]]; then sed -i '/^precedence ::ffff:0:0\/96 100/d' /etc/gai.conf; fi
            echo -e "${GREEN}已恢复为 IPv6 优先！${RESET}"
            ;;
        0) return ;;
        *) echo "无效选项" ;;
    esac
    read -rp "按回车继续..." _
}

# ================== 子菜单: 端口查询 (NEW) ==================
sub_check_ports() {
    clear
    echo -e "${CYAN}=== 系统端口监听查询 (ss -tulpn) ===${RESET}"
    echo -e "${GRAY}下表显示了当前正在监听的端口。${RESET}"
    echo -e "重点关注 Process 为 ${YELLOW}shoes-core${RESET} 的行，那些就是你的代理端口。"
    echo -e "${GRAY}------------------------------------------------------------${RESET}"
    echo -e "${YELLOW}Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name${RESET}"
    
    # 执行命令并高亮 shoes-core
    # 使用 grep -E 过滤 tcp/udp，然后用 sed 给 shoes-core 上色
    ss -tulpn | grep -E "^(udp|tcp)" | sed --unbuffered "s/shoes-core/${GREEN}shoes-core${RESET}/g"
    
    echo -e "${GRAY}------------------------------------------------------------${RESET}"
    echo -e "如果上面没有看到 ${GREEN}shoes-core${RESET}，说明服务未启动。"
    echo ""
    read -rp "按回车返回..." _
}

# ================== 主菜单 ==================
menu_advanced_network() {
    while true; do
        clear
        echo -e "${CYAN}=== 高级网络设置 ===${RESET}"
        echo "------------------------"
        echo -e "${GREEN}[1]${RESET} 切换 IPv6 出口 IP (多 IP 管理)"
        echo -e "${GREEN}[2]${RESET} 设置 IPv4/IPv6 优先级"
        echo -e "${GREEN}[3]${RESET} 查询当前监听端口 (Port Check)"
        echo "------------------------"
        echo -e "${GREEN}[0]${RESET} 返回主菜单"
        echo ""
        read -rp "请输入选项: " adv_choice
        case "$adv_choice" in
            1) sub_switch_ipv6_exit ;;
            2) sub_set_preference ;;
            3) sub_check_ports ;;
            0) return ;;
            *) echo "无效选项"; sleep 1 ;;
        esac
    done
}

show_menu() {
    clear
    echo -e "${GREEN}=== Shoes 全协议管理脚本 (V30.0 端口侦探版) ===${RESET}"
    echo -e "${GRAY}输入 'sho' 再次打开 | 状态: $(systemctl is-active --quiet shoes && echo "${GREEN}运行中" || echo "${RED}未运行")${RESET}"
    echo "------------------------"
    echo "1. 安装 / 重置 Shoes (全部重置)"
    echo "2. 停止服务"
    echo "3. 重启服务"
    echo "4. 查看所有链接"
    echo "5. 卸载服务"
    echo "------------------------"
    echo -e "${CYAN}6. 高级网络设置 (IPv6 / 优先级 / 端口)${RESET}"
    echo -e "${YELLOW}7. 开启 BBR 加速 (优化网络速度)${RESET}"
    echo -e "${BLUE}8. 更新 Shoes 内核 (保留配置文件)${RESET}"
    echo "------------------------"
    echo -e "${GRAY}9. 查看实时日志${RESET}"
    echo "0. 退出"
    read -p "选项: " choice
}

create_shortcut
check_arch

while true; do
    show_menu
    case "$choice" in
        1) install_shoes ;;
        2) systemctl stop shoes; echo "停用";; 
        3) systemctl restart shoes; echo "重启";;
        4) if [[ -f "${LINK_FILE}" ]]; then cat "${LINK_FILE}"; else echo -e "${RED}无配置${RESET}"; fi ;;
        5) systemctl stop shoes; systemctl disable shoes; rm -f "${SHOES_SERVICE}" "${SHOES_CONF_DIR}" "${SHOES_BIN}" "/usr/local/bin/sho" "/usr/bin/sho"; systemctl daemon-reload; echo "卸载完毕";;
        6) menu_advanced_network ;;
        7) enable_bbr ;;       
        8) update_shoes_only ;; 
        9) view_realtime_log ;;
        0) exit 0 ;;
        *) echo "无效" ;;
    esac
    read -p "回车继续..."
done
