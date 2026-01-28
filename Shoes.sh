#!/bin/bash

# ================== 颜色代码 ==================
RED='\033[0;31m'
GREEN='\033[1;32m' # 亮绿色
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
            echo -e "${RED}⚠️  无法创建快捷指令 'sho'。${RESET}"
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

# ================== 辅助函数：询问端口 ==================
ask_port() {
    local prompt=$1
    local default_port=$2
    local port_var=""
    while true; do
        read -rp "$prompt [默认随机: $default_port]: " port_var
        if [[ -z "$port_var" ]]; then echo "$default_port"; return; fi
        if [[ "$port_var" =~ ^[0-9]+$ ]] && [ "$port_var" -ge 1 ] && [ "$port_var" -le 65535 ]; then echo "$port_var"; return; else echo -e "${RED}无效端口${RESET}" >&2; fi
    done
}

# ================== 安装/重置 Shoes ==================
install_shoes() {
    local mode=$1
    install_dependencies
    download_shoes_core
    if [[ $? -ne 0 ]]; then return; fi

    mkdir -p "${SHOES_CONF_DIR}"
    
    local rnd_vless=$(shuf -i 20001-30000 -n 1)
    local rnd_any=$(shuf -i 30001-35000 -n 1)
    local rnd_ss=$(shuf -i 35001-40000 -n 1)
    local rnd_ss22=$(shuf -i 40001-50000 -n 1)

    VLESS_PORT=$rnd_vless; ANYTLS_PORT=$rnd_any; SS_PORT=$rnd_ss; SS22_PORT=$rnd_ss22

    if [[ "$mode" == "custom" ]]; then
        echo -e "\n${CYAN}=== NAT/自定义端口模式 ===${RESET}"
        VLESS_PORT=$(ask_port "请输入 VLESS Reality 端口" $rnd_vless)
        ANYTLS_PORT=$(ask_port "请输入 AnyTLS (HTTPS) 端口" $rnd_any)
        SS_PORT=$(ask_port "请输入 SS-Legacy 端口" $rnd_ss)
        SS22_PORT=$(ask_port "请输入 SS-2022 端口" $rnd_ss22)
    fi

    # === 1. Reality ===
    SNI_LIST=("www.microsoft.com" "itunes.apple.com" "gateway.icloud.com" "www.amazon.com" "dl.google.com")
    SNI=${SNI_LIST[$RANDOM % ${#SNI_LIST[@]}]}
    SHID=$(openssl rand -hex 8)
    UUID=$(cat /proc/sys/kernel/random/uuid)
    KEYPAIR=$(${SHOES_BIN} generate-reality-keypair)
    PRIVATE_KEY=$(echo "$KEYPAIR" | grep "private key" | awk '{print $4}')
    PUBLIC_KEY=$(echo "$KEYPAIR" | grep "public key" | awk '{print $4}')
    open_port "$VLESS_PORT" "tcp"; open_port "$VLESS_PORT" "udp"

    # === 2. AnyTLS ===
    ANYTLS_USER="anytls"; ANYTLS_PASS=$(openssl rand -hex 8); ANYTLS_SNI="www.bing.com"
    open_port "$ANYTLS_PORT" "tcp"

    # === 3. Shadowsocks ===
    SS_CIPHER="aes-256-gcm"; SS_PASSWORD=$(openssl rand -base64 16)
    open_port "$SS_PORT" "tcp"; open_port "$SS_PORT" "udp"

    # === 4. SS-2022 ===
    SS22_CIPHER="2022-blake3-aes-256-gcm"; SS22_PASSWORD=$(openssl rand -base64 32)
    open_port "$SS22_PORT" "tcp"; open_port "$SS22_PORT" "udp"

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

    systemctl daemon-reload; systemctl enable --now shoes; create_shortcut
    echo -e "${GREEN}Shoes 安装完成！${RESET}"
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

# ================== 网络设置子菜单 ==================
sub_switch_ipv6_exit() {
    clear; echo -e "${CYAN}=== IPv6 出口切换 ===${RESET}"; echo -e "${GREEN}➜ ${RESET}扫描中..."
    local ip_with_prefix=(); mapfile -t ip_with_prefix < <(ip -6 addr show scope global | grep "inet6 " | awk '{print $2}')
    if [[ ${#ip_with_prefix[@]} -eq 0 ]]; then echo -e "${RED}无 IPv6${RESET}"; read -rp "..." _; return; fi
    local current_exit_ip=$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | grep -oP 'src \K\S+')
    echo -e "${GREEN}请选择默认出口:${RESET}\n"; local i=1
    for item in "${ip_with_prefix[@]}"; do
        local addr=${item%/*}; local status_mark=""
        if [[ "$addr" == "$current_exit_ip" ]]; then status_mark="${GREEN}✔${RESET} ${YELLOW}(当前默认)${RESET}"; else status_mark="${GRAY}(可选)${RESET}"; fi
        local loc_str=""; if command -v curl >/dev/null; then local api=$(curl -s --max-time 1 "http://ip-api.com/json/${addr}?lang=zh-CN&fields=country,city"); if [[ -n "$api" ]]; then local c=$(echo "$api"|jq -r '.country//empty'); local t=$(echo "$api"|jq -r '.city//empty'); [[ -n "$c" ]] && loc_str="${BLUE}[${c} ${t}]${RESET}"; fi; fi
        echo -e " ${GREEN}[$i]${RESET} ${PURPLE}${addr}${RESET} ${loc_str} ${status_mark}"; ((i++))
    done
    echo -e " ${GREEN}[0]${RESET} 返回"; read -rp "选择: " choice; [[ "$choice" == "0" || -z "$choice" ]] && return
    local target=${ip_with_prefix[$((choice-1))]}
    local dev=$(ip -6 route show default|awk '/dev/{print $5}'|head -n1); [[ -z "$dev" ]] && dev="eth0"
    for item in "${ip_with_prefix[@]}"; do ip addr change "$item" dev "$dev" preferred_lft 0 >/dev/null 2>&1; done
    ip addr change "$target" dev "$dev" preferred_lft forever >/dev/null 2>&1
    echo -e "${GREEN}切换成功${RESET}"; read -rp "..." _
}

sub_set_preference() {
    clear; echo -e "${CYAN}=== IPv4/v6 优先级 ===${RESET}"
    grep -q "^precedence ::ffff:0:0/96 100" /etc/gai.conf 2>/dev/null && echo -e "当前: ${GREEN}IPv4 优先${RESET}" || echo -e "当前: ${BLUE}IPv6 优先${RESET}"
    echo -e "\n${GREEN}[1]${RESET} 设为 IPv4 优先\n${GREEN}[2]${RESET} 设为 IPv6 优先\n${GREEN}[0]${RESET} 返回\n"
    read -rp "选择: " c
    case "$c" in 1) echo "precedence ::ffff:0:0/96 100" >> /etc/gai.conf ;; 2) sed -i '/^precedence ::ffff:0:0\/96 100/d' /etc/gai.conf ;; esac
    echo -e "${GREEN}设置完成${RESET}"; read -rp "..." _
}

sub_check_ports() {
    clear
    echo -e "${CYAN}=== 端口监听状态 (ss -tulpn) ===${RESET}"
    echo -e "${GRAY}Local/Foreign 地址部分保持紫色/灰色，PID Name 部分高亮绿色${RESET}"
    echo -e "${PURPLE}Proto Recv-Q Send-Q Local Address           Foreign Address         State       ${RESET}${YELLOW}PID/Program name${RESET}"
    echo -e "${GRAY}-----------------------------------------------------------------------------------------${RESET}"
    
    # 关键修改：使用 bash 字符串替换，精准高亮 shoes-core，不影响前面
    ss -tulpn | grep -E "^(udp|tcp)" | while read -r line; do
        # 统一把前面的部分设为淡紫色/灰色
        local colored_line="${PURPLE}${line}${RESET}"
        
        # 如果包含 shoes-core，把这个关键词换成亮绿色，并重置回紫色或结束颜色
        if [[ "$line" == *"shoes-core"* ]]; then
            # 替换 shoes-core 为 绿色shoes-core，注意 sed 这里只替换匹配到的部分
            # 使用 echo 输出，将 shoes-core 替换为带颜色的版本
            echo -e "${PURPLE}${line//shoes-core/${GREEN}shoes-core${PURPLE}}${RESET}"
        else
            echo -e "${PURPLE}${line}${RESET}"
        fi
    done
    
    echo -e "${GRAY}-----------------------------------------------------------------------------------------${RESET}"
    echo -e "未见 ${GREEN}shoes-core${RESET} 则服务未启动"
    echo ""
    read -rp "按回车返回..." _
}

menu_advanced_network() {
    while true; do
        clear; echo -e "${CYAN}=== 高级网络设置 ===${RESET}"
        echo -e "${GREEN}[1]${RESET} 切换 IPv6 出口 IP\n${GREEN}[2]${RESET} 设置 IPv4/IPv6 优先级\n${GREEN}[3]${RESET} 查询端口监听 (美化版)\n${GREEN}[0]${RESET} 返回"
        read -rp "选择: " c
        case "$c" in 1) sub_switch_ipv6_exit;; 2) sub_set_preference;; 3) sub_check_ports;; 0) return;; esac
    done
}

# ================== 主菜单 ==================
show_menu() {
    clear
    echo -e "${GREEN}=== Shoes 全协议管理脚本 (V32.0 端口显示美化版) ===${RESET}"
    echo -e "${GRAY}输入 'sho' 再次打开 | 状态: $(systemctl is-active --quiet shoes && echo "${GREEN}运行中" || echo "${RED}未运行")${RESET}"
    echo "------------------------"
    echo "1. 安装 / 重置 Shoes (随机端口)"
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
    echo -e "${RED}10. 自定义端口重装 (NAT/高级专用)${RESET}"
    echo "0. 退出"
    read -p "选项: " choice
}

create_shortcut
check_arch

while true; do
    show_menu
    case "$choice" in
        1) install_shoes "random" ;;
        2) systemctl stop shoes; echo "停用";; 
        3) systemctl restart shoes; echo "重启";;
        4) if [[ -f "${LINK_FILE}" ]]; then cat "${LINK_FILE}"; else echo -e "${RED}无配置${RESET}"; fi ;;
        5) systemctl stop shoes; systemctl disable shoes; rm -f "${SHOES_SERVICE}" "${SHOES_CONF_DIR}" "${SHOES_BIN}" "/usr/local/bin/sho" "/usr/bin/sho"; systemctl daemon-reload; echo "卸载完毕";;
        6) menu_advanced_network ;;
        7) enable_bbr ;;       
        8) update_shoes_only ;; 
        9) view_realtime_log ;;
        10) install_shoes "custom" ;;
        0) exit 0 ;;
        *) echo "无效" ;;
    esac
    read -p "回车继续..."
done
