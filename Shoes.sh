#!/bin/bash

# ================== 颜色代码 ==================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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
    if command -v apt >/dev/null; then
        apt update && apt install -y curl wget tar openssl jq
    elif command -v yum >/dev/null; then
        yum install -y curl wget tar openssl jq
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

# ================== 安装 Shoes (集成 SS) ==================
install_shoes() {
    echo -e "${GREEN}>>> 开始安装 Shoes (集成 Shadowsocks)...${RESET}"
    install_dependencies
    check_arch
    
    # 1. 获取版本 & 下载
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

    # 2. 生成配置参数
    mkdir -p "${SHOES_CONF_DIR}"
    
    # --- VLESS Reality 参数 ---
    SNI="www.ua.edu"
    SHID=$(openssl rand -hex 8)
    VLESS_PORT=$(shuf -i 20001-30000 -n 1)
    UUID=$(cat /proc/sys/kernel/random/uuid)
    
    # 生成 Reality 密钥对
    KEYPAIR=$(${SHOES_BIN} generate-reality-keypair)
    PRIVATE_KEY=$(echo "$KEYPAIR" | grep "private key" | awk '{print $4}')
    PUBLIC_KEY=$(echo "$KEYPAIR" | grep "public key" | awk '{print $4}')

    # --- AnyTLS 参数 ---
    ANYTLS_PORT=$(shuf -i 30001-40000 -n 1)
    
    # --- Shadowsocks 参数 (修正字段名) ---
    SS_PORT=$(shuf -i 40001-50000 -n 1)
    SS_CIPHER="aes-256-gcm"
    SS_PASSWORD=$(openssl rand -base64 16)

    # 生成自签名证书 (AnyTLS用)
    openssl ecparam -genkey -name prime256v1 -out "${SHOES_CONF_DIR}/key.pem"
    openssl req -new -x509 -days 3650 -key "${SHOES_CONF_DIR}/key.pem" -out "${SHOES_CONF_DIR}/cert.pem" -subj "/CN=bing.com"

    # 3. 写入配置文件 (已修正 method -> cipher)
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

    # 4. Systemd 服务
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
    
    # 5. 生成并保存链接
    generate_links_content "$UUID" "$VLESS_PORT" "$SNI" "$PUBLIC_KEY" "$SHID" "$SS_PORT" "$SS_PASSWORD" "$SS_CIPHER"
}

# ================== 生成链接函数 ==================
generate_links_content() {
    # 接收参数
    local uuid=$1
    local vless_port=$2
    local sni=$3
    local pbk=$4
    local sid=$5
    local ss_port=$6
    local ss_pass=$7
    local ss_cipher=$8
    
    HOST_IP=$(get_public_ip)
    
    # VLESS Link
    VLESS_LINK="vless://${uuid}@${HOST_IP}:${vless_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=random&pbk=${pbk}&sid=${sid}&type=tcp#Shoes_Reality"

    # SS Link (Base64编码 cipher:password)
    SS_BASE=$(echo -n "${ss_cipher}:${ss_pass}" | base64 -w 0)
    SS_LINK="ss://${SS_BASE}@${HOST_IP}:${ss_port}#Shoes_SS"

    echo -e "\n${YELLOW}====== 配置信息汇总 ======${RESET}" > "${LINK_FILE}"
    
    echo -e "\n--- VLESS Reality ---" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}${VLESS_LINK}${RESET}" | tee -a "${LINK_FILE}"

    echo -e "\n--- Shadowsocks ---" | tee -a "${LINK_FILE}"
    echo -e "端口: ${ss_port}" | tee -a "${LINK_FILE}"
    echo -e "密码: ${ss_pass}" | tee -a "${LINK_FILE}"
    echo -e "加密: ${ss_cipher}" | tee -a "${LINK_FILE}"
    echo -e "链接: ${GREEN}${SS_LINK}${RESET}" | tee -a "${LINK_FILE}"
}

# ================== 菜单 ==================
show_menu() {
    clear
    echo -e "${GREEN}=== Shoes 一键管理脚本 (V4.0 修复版) ===${RESET}"
    
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
    echo "0. 退出"
    echo "------------------------"
    read -p "请输入选项: " choice
}

# ================== 主逻辑 ==================
check_arch

while true; do
    show_menu
    case "$choice" in
        1) install_shoes ;;
        2) systemctl stop shoes; echo "已停止" ;;
        3) systemctl restart shoes; echo "已重启" ;;
        4) 
            if [[ -f "${LINK_FILE}" ]]; then
                cat "${LINK_FILE}"
            else
                echo -e "${RED}无链接记录，请先安装。${RESET}"
            fi 
            ;;
        5)
            systemctl stop shoes
            systemctl disable shoes
            rm -f "${SHOES_SERVICE}" "${SHOES_CONF_DIR}" "${SHOES_BIN}"
            systemctl daemon-reload
            echo -e "${GREEN}卸载完成${RESET}"
            ;;
        0) exit 0 ;;
        *) echo "无效选项" ;;
    esac
    read -p "按回车继续..."
done
