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

# ================== 依赖检查 ==================
install_dependencies() {
    # 融合功能需要 jq 和 curl
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

# ================== 核心功能: IPv6 出口切换 (融合代码) ==================
switch_system_ipv6() {
    clear
    echo -e "${CYAN}=== 系统级 IPv6 出口 IP 切换 ===${RESET}"
    echo -e "正在扫描网卡上的公网 IPv6 地址..."
    
    # 1. 提取所有全局 IPv6 地址 (带CIDR)
    local ip_with_prefix=()
    mapfile -t ip_with_prefix < <(ip -6 addr show scope global | grep "inet6 " | awk '{print $2}')

    if [[ ${#ip_with_prefix[@]} -eq 0 ]]; then
        echo -e "${RED}未检测到可用的公网 IPv6 地址。${RESET}"
        read -rp "按回车返回..." _
        return
    fi

    echo -e "正在进行 地区解析 与 延迟测试 (Cloudflare)..."
    echo -e "${GRAY}(如果 IP 较多，测试可能需要几秒钟，请耐心等待)${RESET}\n"
    
    # 2. 显示列表并标记当前状态
    echo -e "请选择要设为默认出口的 IP：\n"
    local i=1
    
    # 检测 Ping 命令
    local ping_cmd="ping -6"
    if ! command -v ping >/dev/null 2>&1; then ping_cmd="ping6"; fi

    for item in "${ip_with_prefix[@]}"; do
        local addr=${item%/*} # 提取纯 IP
        
        # --- 状态判断 ---
        local status_mark=""
        if ip -6 addr show | grep -F "$item" | grep -q "deprecated"; then
            status_mark="${GRAY}(备用)${RESET}"
        else
            status_mark="${GREEN}✔ (当前活跃)${RESET}"
        fi
        
        # --- A. 地区检测 (1秒超时) ---
        local loc_str=""
        if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
            local api_res
            api_res=$(curl -s --max-time 1 "http://ip-api.com/json/${addr}?lang=zh-CN&fields=country,city" 2>/dev/null)
            if [[ -n "$api_res" ]]; then
                local country=$(echo "$api_res" | jq -r '.country // empty')
                local city=$(echo "$api_res" | jq -r '.city // empty')
                [[ -n "$country" ]] && loc_str="${BLUE}[${country} ${city}]${RESET}" || loc_str="${GRAY}[位置未知]${RESET}"
            else
                loc_str="${GRAY}[位置超时]${RESET}"
            fi
        fi
        
        # --- B. 延迟检测 (1秒超时) ---
        local lat_val
        lat_val=$($ping_cmd -c 1 -w 1 -I "$addr" 2606:4700:4700::1111 2>/dev/null | grep -o 'time=[0-9.]*' | cut -d= -f2)
        local lat_str=""
        if [[ -n "$lat_val" ]]; then
            local lat_num=${lat_val%.*}
            if [[ "$lat_num" -lt 100 ]]; then
                lat_str="${GREEN}[${lat_val}ms]${RESET}"
            elif [[ "$lat_num" -lt 200 ]]; then
                lat_str="${YELLOW}[${lat_val}ms]${RESET}"
            else
                lat_str="${RED}[${lat_val}ms]${RESET}"
            fi
        else
            lat_str="${RED}[超时]${RESET}"
        fi

        # 组合显示
        echo -e " ${GREEN}[$i]${RESET} ${YELLOW}${addr}${RESET} ${loc_str} ${lat_str} ${status_mark}"
        ((i++))
    done
    echo -e " ${GREEN}[0]${RESET} 取消返回"
    echo ""

    read -rp "请输入序号 [0-$((i-1))]: " choice
    [[ "$choice" == "0" || -z "$choice" ]] && return

    local target_item="${ip_with_prefix[$((choice-1))]}"
    local target_ip="${target_item%/*}"

    if [[ -z "$target_ip" ]]; then
        echo -e "${RED}无效选择。${RESET}"
        sleep 1
        return
    fi

    # 3. 执行切换
    echo -e "正在切换出口 IP 至: $target_ip ..."
    
    local gateway=$(ip -6 route show default | awk '/via/ {print $3}' | head -n1)
    local dev_name=$(ip -6 route show default | awk '/dev/ {print $5}' | head -n1)
    [[ -z "$dev_name" ]] && dev_name="eth0"

    # 重置所有 IPv6 寿命 (deprecate others)
    for item in "${ip_with_prefix[@]}"; do
        ip addr change "$item" dev "$dev_name" preferred_lft 0 >/dev/null 2>&1
    done
    # 激活目标 IP (forever)
    ip addr change "$target_item" dev "$dev_name" preferred_lft forever >/dev/null 2>&1

    # 强制刷新路由表 src
    if [[ -n "$gateway" ]]; then
        ip -6 route replace default via "$gateway" dev "$dev_name" src "$target_ip" onlink >/dev/null 2>&1
    else
        ip -6 route replace default dev "$dev_name" src "$target_ip" onlink >/dev/null 2>&1
    fi

    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}切换成功！${RESET}"
        echo -e "正在复核外网 IP..."
        local test_res=$(curl -6 -s --max-time 3 ip.sb || echo "验证超时")
        echo -e "当前外网 IP: ${YELLOW}${test_res}${RESET}"
        
        echo -e "\n${RED}注意：此修改重启后会失效。如果需要永久生效，请将 ip route 命令加入 rc.local${RESET}"
    else
        echo -e "${RED}切换失败，请检查权限或网络。${RESET}"
    fi
    
    read -rp "按回车继续..." _
}

# ================== 安装 Shoes (集成 SS) ==================
install_shoes() {
    echo -e "${GREEN}>>> 开始安装 Shoes (集成 Shadowsocks)...${RESET}"
    install_dependencies
    check_arch
    
    SHOES_VER=$(curl -s https://api.github.com/repos/cfal/shoes/releases/latest | grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/')
    [[ -z "$SHOES_VER" ]] && { echo -e "${RED}获取 Shoes 版本失败${RESET}"; return; }
    
    mkdir -p "${TMP_DIR}"
    cd "${TMP_DIR}" || exit 1
    
    SHOES_URL="https://github.com/cfal/shoes/releases/download/v${SHOES_VER}/shoes-${SHOES_ARCH}.tar.gz"
    echo -e "下载: $SHOES_URL"
    wget -O shoes.tar.gz "$SHOES_URL" || { echo -e "${RED}下载失败${RESET}"; return; }
    
    tar -xzf shoes.tar.gz
    FIND_SHOES=$(find . -type f -name "shoes" | head -n 1)
    if [[ -z "$FIND_SHOES" ]]; then
        echo -e "${RED}解压后未找到 shoes 二进制文件${RESET}"; return;
    fi
    cp "$FIND_SHOES" "${SHOES_BIN}"
    chmod +x "${SHOES_BIN}"

    # 配置生成
    mkdir -p "${SHOES_CONF_DIR}"
    SNI="www.ua.edu"
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

    # YAML 配置
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
    echo -e "${GREEN}Shoes (含SS) 安装完成！${RESET}"
    
    generate_links_content "$UUID" "$VLESS_PORT" "$SNI" "$PUBLIC_KEY" "$SHID" "$SS_PORT" "$SS_PASSWORD" "$SS_CIPHER"
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
    
    VLESS_LINK="vless://${uuid}@${HOST_IP}:${vless_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=random&pbk=${pbk}&sid=${sid}&type=tcp#Shoes_Reality"
    SS_BASE=$(echo -n "${ss_cipher}:${ss_pass}" | base64 -w 0)
    SS_LINK="ss://${SS_BASE}@${HOST_IP}:${ss_port}#Shoes_SS"

    echo -e "\n${YELLOW}====== 配置信息汇总 ======${RESET}" > "${LINK_FILE}"
    echo -e "\n--- VLESS Reality ---" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}${VLESS_LINK}${RESET}" | tee -a "${LINK_FILE}"
    echo -e "\n--- Shadowsocks ---" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}${SS_LINK}${RESET}" | tee -a "${LINK_FILE}"
}

# ================== 菜单 ==================
show_menu() {
    clear
    echo -e "${GREEN}=== Shoes 一键管理脚本 (V5.0 融合版) ===${RESET}"
    
    if systemctl is-active --quiet shoes; then
        echo -e "运行状态: ${GREEN}运行中${RESET}"
    else
        echo -e "运行状态: ${RED}未运行${RESET}"
    fi

    echo "------------------------"
    echo "1. 安装 / 重置 Shoes 服务"
    echo "2. 停止服务"
    echo "3. 重启服务"
    echo "4. 查看当前链接"
    echo "5. 卸载服务"
    echo "------------------------"
    echo -e "${CYAN}6. 高级网络设置 (IPv6 出口管理)${RESET}"
    echo "------------------------"
    echo "0. 退出"
    read -p "请输入选项: " choice
}

# ================== 主逻辑 ==================
install_dependencies
check_arch

while true; do
    show_menu
    case "$choice" in
        1) install_shoes ;;
        2) systemctl stop shoes; echo "已停止" ;;
        3) systemctl restart shoes; echo "已重启" ;;
        4) 
            if [[ -f "${LINK_FILE}" ]]; then cat "${LINK_FILE}"; else echo -e "${RED}无链接记录${RESET}"; fi 
            ;;
        5)
            systemctl stop shoes
            systemctl disable shoes
            rm -f "${SHOES_SERVICE}" "${SHOES_CONF_DIR}" "${SHOES_BIN}"
            systemctl daemon-reload
            echo -e "${GREEN}卸载完成${RESET}"
            ;;
        6) switch_system_ipv6 ;;
        0) exit 0 ;;
        *) echo "无效选项" ;;
    esac
    read -p "按回车继续..."
done
