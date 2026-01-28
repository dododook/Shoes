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

# === 关键修改：菜单命令改为 sho ===
SHOES_BIN="/usr/local/bin/shoes-core"  # 内核名字
MENU_BIN="/usr/local/bin/sho"          # 菜单脚本名字 (实体)
SHORTCUT_BIN="/usr/bin/sho"            # 系统快捷键 (软链接)

SHOES_CONF_DIR="/etc/shoes"
SHOES_CONF_FILE="${SHOES_CONF_DIR}/config.yaml"
SHOES_SERVICE="/etc/systemd/system/shoes.service"
LINK_FILE="/root/proxy_links.txt"
TMP_DIR="/tmp/proxydl"

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

# ================== 快捷指令 (sho) ==================
create_shortcut() {
    local current_file=$(readlink -f "$0")
    
    # 强制覆盖菜单脚本
    if [[ -f "$current_file" && ! -L "$current_file" ]]; then
        cp -f "$current_file" "$MENU_BIN"
        echo -e "${GREEN}>>> 已安装菜单到: ${MENU_BIN}${RESET}"
    else
        echo -e "${YELLOW}>>> 在线模式，正在下载脚本...${RESET}"
        if curl -s --head --request GET "$SCRIPT_URL" | grep "200 OK" > /dev/null; then
            curl -sL "$SCRIPT_URL" -o "$MENU_BIN"
            echo -e "${GREEN}>>> 菜单已修复。${RESET}"
        else
            echo -e "${RED}>>> 无法下载脚本，快捷键可能失效。${RESET}"
            return
        fi
    fi
    
    chmod +x "$MENU_BIN"
    # 创建 /usr/bin/sho 链接
    ln -sf "$MENU_BIN" "$SHORTCUT_BIN"
    
    # === 顺手清理掉旧的 shoes 命令，防止冲突 ===
    if [[ -L "/usr/bin/shoes" || -f "/usr/bin/shoes" ]]; then
        rm -f "/usr/bin/shoes"
        echo -e "${YELLOW}>>> 已清理旧的 'shoes' 命令，现在请使用 'sho'。${RESET}"
    fi
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
    
    # 移动并重命名为 shoes-core
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

    # 2. AnyTLS (UUID)
    ANYTLS_PORT=$(shuf -i 30001-35000 -n 1)
    ANYTLS_USER="anytls"
    ANYTLS_PASS=$(cat /proc/sys/kernel/random/uuid) 

    # 3. Shadowsocks (Legacy)
    SS_PORT=$(shuf -i 35001-40000 -n 1)
    SS_CIPHER="aes-256-gcm"
    SS_PASSWORD=$(openssl rand -base64 16)

    # 4. SOCKS5
    SOCKS_PORT=$(shuf -i 40001-45000 -n 1)
    SOCKS_USER="socks"
    SOCKS_PASS=$(openssl rand -base64 8)

    # 5. SS-2022
    SS22_PORT=$(shuf -i 45001-55000 -n 1)
    SS22_CIPHER="2022-blake3-aes-256-gcm"
    SS22_PASSWORD=$(${SHOES_BIN} generate-shadowsocks-2022-password "${SS22_CIPHER}" | grep -v "\-\-\-" | grep -v "${SS22_CIPHER}" | awk '{$1=$1;print}' | head -n 1)

    openssl ecparam -genkey -name prime256v1 -out "${SHOES_CONF_DIR}/key.pem"
    openssl req -new -x509 -days 3650 -key "${SHOES_CONF_DIR}/key.pem" -out "${SHOES_CONF_DIR}/cert.pem" -subj "/CN=bing.com"

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
- address: "0.0.0.0:${SS22_PORT}"
  protocol:
    type: shadowsocks
    cipher: "${SS22_CIPHER}"
    password: "${SS22_PASSWORD}"
    udp_enabled: true
EOF

    # Systemd 指向 shoes-core
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
    echo -e "${GREEN}Shoes (5协议) 安装完成！${RESET}"
    generate_links_content "$UUID" "$VLESS_PORT" "$SNI" "$PUBLIC_KEY" "$SHID" "$SS_PORT" "$SS_PASSWORD" "$SS_CIPHER" "$ANYTLS_PORT" "$ANYTLS_USER" "$ANYTLS_PASS" "$SOCKS_PORT" "$SOCKS_USER" "$SOCKS_PASS" "$SS22_PORT" "$SS22_PASSWORD" "$SS22_CIPHER"
}

# ================== 生成链接 ==================
generate_links_content() {
    local uuid=$1; local vless_port=$2; local sni=$3; local pbk=$4; local sid=$5
    local ss_port=$6; local ss_pass=$7; local ss_cipher=$8
    local any_port=$9; local any_user=${10}; local any_pass=${11}
    local socks_port=${12}; local socks_user=${13}; local socks_pass=${14}
    local ss22_port=${15}; local ss22_pass=${16}; local ss22_cipher=${17}
    HOST_IP=$(get_public_ip)
    
    VLESS_LINK="vless://${uuid}@${HOST_IP}:${vless_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=random&pbk=${pbk}&sid=${sid}&type=tcp#Shoes_${sni}"
    SS_BASE=$(echo -n "${ss_cipher}:${ss_pass}" | base64 -w 0)
    SS_LINK="ss://${SS_BASE}@${HOST_IP}:${ss_port}#Shoes_Legacy"
    SOCKS_BASE=$(echo -n "${socks_user}:${socks_pass}" | base64 -w 0)
    SOCKS_LINK="socks5://${SOCKS_BASE}@${HOST_IP}:${socks_port}#Shoes_S5"
    SS22_BASE=$(echo -n "${ss22_cipher}:${ss22_pass}" | base64 -w 0)
    SS22_LINK="ss://${SS22_BASE}@${HOST_IP}:${ss22_port}#Shoes_2022"
    ANYTLS_LINK="anytls://${any_pass}@${HOST_IP}:${any_port}?security=tls&insecure=1&type=tcp#Shoes_AnyTLS"

    echo -e "\n${YELLOW}====== 配置信息汇总 ======${RESET}" > "${LINK_FILE}"
    echo -e "\n--- [1] VLESS Reality (SNI: ${sni}) ---" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}${VLESS_LINK}${RESET}" | tee -a "${LINK_FILE}"
    echo -e "\n--- [2] SS-2022 (抗重放/推荐) ---" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}${SS22_LINK}${RESET}" | tee -a "${LINK_FILE}"
    echo -e "\n--- [3] SS-Legacy (传统/游戏) ---" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}${SS_LINK}${RESET}" | tee -a "${LINK_FILE}"
    echo -e "\n--- [4] SOCKS5 (TG专用) ---" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}${SOCKS_LINK}${RESET}" | tee -a "${LINK_FILE}"
    echo -e "\n--- [5] AnyTLS (HTTPS Proxy) ---" | tee -a "${LINK_FILE}"
    echo -e "地址: ${HOST_IP}:${any_port}" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}${ANYTLS_LINK}${RESET}" | tee -a "${LINK_FILE}"
}

# ================== 高级 IPv6 切换 (1:1 UI复刻版) ==================
switch_system_ipv6() {
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

# ================== 辅助功能 ==================
update_shoes_only() { echo -e "${CYAN}更新内核...${RESET}"; download_shoes_core; if [[ $? -eq 0 ]]; then systemctl restart shoes; echo -e "${GREEN}更新成功${RESET}"; fi }
enable_bbr() { if grep -q "bbr" /etc/sysctl.conf; then echo -e "${GREEN}BBR 已开启${RESET}"; else echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf; echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf; sysctl -p; echo -e "${GREEN}BBR 已开启${RESET}"; fi; read -p "..." _; }
view_realtime_log() { echo -e "${CYAN}Ctrl+C 退出${RESET}"; journalctl -u shoes -f; }

# ================== 菜单 ==================
show_menu() {
    clear
    echo -e "${GREEN}=== Shoes 全协议管理脚本 (V22.0 极简指令 sho 版) ===${RESET}"
    echo -e "${GRAY}输入 'sho' 再次打开 | 状态: $(systemctl is-active --quiet shoes && echo "${GREEN}运行中" || echo "${RED}未运行")${RESET}"
    echo "------------------------"
    echo "1. 安装 / 重置 Shoes (全部重置)"
    echo "2. 停止服务"
    echo "3. 重启服务"
    echo "4. 查看所有链接"
    echo "5. 卸载服务"
    echo "------------------------"
    echo -e "${CYAN}6. 高级网络设置 (IPv6 出口管理)${RESET}"
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
        6) switch_system_ipv6 ;;
        7) enable_bbr ;;       
        8) update_shoes_only ;; 
        9) view_realtime_log ;;
        0) exit 0 ;;
        *) echo "无效" ;;
    esac
    read -p "回车继续..."
done
