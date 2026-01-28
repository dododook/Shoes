#!/bin/bash

# ================== 颜色代码 ==================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RESET='\033[0m'

# ================== 常量定义 ==================
# --- Shoes 变量 ---
SHOES_BIN="/usr/local/bin/shoes"
SHOES_CONF_DIR="/etc/shoes"
SHOES_CONF_FILE="${SHOES_CONF_DIR}/config.yaml"
SHOES_SERVICE="/etc/systemd/system/shoes.service"

# --- Shadowsocks 变量 ---
SS_BIN="/usr/local/bin/ssserver"
SS_CONF_DIR="/etc/shadowsocks-rust"
SS_CONF_FILE="${SS_CONF_DIR}/config.json"
SS_SERVICE="/etc/systemd/system/shadowsocks-rust.service"

# --- 公共变量 ---
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
        x86_64)
            SHOES_ARCH="x86_64-unknown-linux-gnu"
            SS_ARCH="x86_64-unknown-linux-gnu"
            ;;
        aarch64|arm64)
            SHOES_ARCH="aarch64-unknown-linux-gnu"
            SS_ARCH="aarch64-unknown-linux-gnu"
            ;;
        *)
            echo -e "${RED}不支持的 CPU 架构: ${ARCH}${RESET}"
            exit 1
            ;;
    esac
}

# ================== 辅助函数: 获取 IP ==================
get_public_ip() {
    curl -s -4 http://www.cloudflare.com/cdn-cgi/trace | grep ip | awk -F= '{print $2}'
}

# ================== 模块: Shadowsocks-Rust ==================
install_ss() {
    echo -e "${GREEN}>>> 开始安装 Shadowsocks-Rust...${RESET}"
    
    # 1. 获取最新版本并下载
    SS_LATEST=$(curl -s https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest | grep "tag_name" | cut -d '"' -f 4)
    if [[ -z "$SS_LATEST" ]]; then
        echo -e "${RED}无法获取 SS 最新版本${RESET}"
        return
    fi
    echo -e "${GREEN}SS 版本: ${SS_LATEST}${RESET}"

    mkdir -p "${TMP_DIR}"
    cd "${TMP_DIR}" || exit 1
    
    # 构建下载链接 (shadowsocks-v1.15.0.x86_64-unknown-linux-gnu.tar.xz)
    SS_URL="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${SS_LATEST}/shadowsocks-${SS_LATEST}.${SS_ARCH}.tar.xz"
    
    echo -e "下载: $SS_URL"
    wget -O ss.tar.xz "$SS_URL" || { echo -e "${RED}下载失败${RESET}"; return; }
    
    tar -xf ss.tar.xz
    # 智能查找 ssserver (防止目录结构变化)
    FIND_SS=$(find . -type f -name "ssserver" | head -n 1)
    if [[ -z "$FIND_SS" ]]; then
        echo -e "${RED}解压后未找到 ssserver 二进制文件${RESET}"
        return
    fi
    cp "$FIND_SS" "${SS_BIN}"
    chmod +x "${SS_BIN}"

    # 2. 配置生成
    mkdir -p "${SS_CONF_DIR}"
    SS_PORT=$(shuf -i 10000-20000 -n 1)
    SS_PASSWORD=$(openssl rand -base64 16)
    SS_METHOD="aes-256-gcm"

    cat > "${SS_CONF_FILE}" <<EOF
{
    "server": "0.0.0.0",
    "server_port": ${SS_PORT},
    "password": "${SS_PASSWORD}",
    "method": "${SS_METHOD}",
    "timeout": 300,
    "fast_open": true
}
EOF

    # 3. Systemd 服务
    cat > "${SS_SERVICE}" <<EOF
[Unit]
Description=Shadowsocks-Rust Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=${SS_BIN} -c ${SS_CONF_FILE}
Restart=on-failure
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now shadowsocks-rust
    
    echo -e "${GREEN}Shadowsocks 安装完成！端口: ${SS_PORT}${RESET}"
}

# ================== 模块: Shoes ==================
install_shoes() {
    echo -e "${GREEN}>>> 开始安装 Shoes...${RESET}"
    check_arch
    
    # 1. 获取版本 (这里假设仓库地址有效，如果无效请替换)
    SHOES_VER=$(curl -s https://api.github.com/repos/cfal/shoes/releases/latest | grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/')
    [[ -z "$SHOES_VER" ]] && { echo -e "${RED}获取 Shoes 版本失败${RESET}"; return; }
    
    mkdir -p "${TMP_DIR}"
    cd "${TMP_DIR}" || exit 1
    
    # 默认尝试 GNU 版本
    SHOES_URL="https://github.com/cfal/shoes/releases/download/v${SHOES_VER}/shoes-${SHOES_ARCH}.tar.gz"
    echo -e "下载: $SHOES_URL"
    wget -O shoes.tar.gz "$SHOES_URL" || { echo -e "${RED}下载失败${RESET}"; return; }
    
    tar -xzf shoes.tar.gz
    
    # 修复：智能查找 shoes 二进制文件
    FIND_SHOES=$(find . -type f -name "shoes" | head -n 1)
    if [[ -z "$FIND_SHOES" ]]; then
        echo -e "${RED}解压后未找到 shoes 二进制文件${RESET}"
        return
    fi
    cp "$FIND_SHOES" "${SHOES_BIN}"
    chmod +x "${SHOES_BIN}"

    # 2. 配置生成
    mkdir -p "${SHOES_CONF_DIR}"
    
    SNI="www.ua.edu"
    SHID=$(openssl rand -hex 8)
    VLESS_PORT=$(shuf -i 20001-40000 -n 1)
    ANYTLS_PORT=$(shuf -i 40001-60000 -n 1)
    UUID=$(cat /proc/sys/kernel/random/uuid)
    KEYPAIR=$(${SHOES_BIN} generate-reality-keypair)
    PRIVATE_KEY=$(echo "$KEYPAIR" | grep "private key" | awk '{print $4}')
    PUBLIC_KEY=$(echo "$KEYPAIR" | grep "public key" | awk '{print $4}')

    # 生成自签名证书
    openssl ecparam -genkey -name prime256v1 -out "${SHOES_CONF_DIR}/key.pem"
    openssl req -new -x509 -days 3650 -key "${SHOES_CONF_DIR}/key.pem" -out "${SHOES_CONF_DIR}/cert.pem" -subj "/CN=bing.com"

    # 修复：严格的 YAML 缩进
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
EOF

    # 3. Systemd
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
    echo -e "${GREEN}Shoes 安装完成！${RESET}"
}

# ================== 生成链接 ==================
generate_links() {
    HOST_IP=$(get_public_ip)
    
    echo -e "\n${YELLOW}====== 配置信息汇总 ======${RESET}" > "${LINK_FILE}"
    
    # Shoes Link
    if [[ -f "${SHOES_CONF_FILE}" ]]; then
        # 从配置文件反向读取变量（简单粗暴版）
        UUID=$(grep "user_id" ${SHOES_CONF_FILE} | awk -F'"' '{print $2}')
        VLESS_PORT=$(grep -B 10 "type: vless" ${SHOES_CONF_FILE} | grep -oP '0.0.0.0:\K\d+' | head -n1)
        # 注意：这里重新读取有些复杂，建议安装时保存变量。这里为了脚本简洁，假设还是刚才安装的变量。
        # 如果是重新运行查看配置，需要从文件解析，这里简化处理，仅在安装后显示。
    fi

    # SS Link
    if [[ -f "${SS_CONF_FILE}" ]]; then
        SS_PORT=$(jq -r .server_port ${SS_CONF_FILE})
        SS_PASS=$(jq -r .password ${SS_CONF_FILE})
        SS_METH=$(jq -r .method ${SS_CONF_FILE})
        
        # Base64 编码 (method:password)
        SS_BASE=$(echo -n "${SS_METH}:${SS_PASS}" | base64 -w 0)
        SS_LINK="ss://${SS_BASE}@${HOST_IP}:${SS_PORT}#SS_Rust_${HOST_IP}"
        
        echo -e "\n--- Shadowsocks ---" | tee -a "${LINK_FILE}"
        echo -e "端口: ${SS_PORT}" | tee -a "${LINK_FILE}"
        echo -e "密码: ${SS_PASS}" | tee -a "${LINK_FILE}"
        echo -e "加密: ${SS_METH}" | tee -a "${LINK_FILE}"
        echo -e "链接: ${GREEN}${SS_LINK}${RESET}" | tee -a "${LINK_FILE}"
    fi
}

# ================== 菜单 ==================
show_menu() {
    clear
    echo -e "${GREEN}=== 全能代理安装脚本 (Shoes + SS) ===${RESET}"
    
    if systemctl is-active --quiet shoes; then
        echo -e "Shoes 状态: ${GREEN}运行中${RESET}"
    else
        echo -e "Shoes 状态: ${RED}未运行/未安装${RESET}"
    fi

    if systemctl is-active --quiet shadowsocks-rust; then
        echo -e "SS-Rust状态: ${GREEN}运行中${RESET}"
    else
        echo -e "SS-Rust状态: ${RED}未运行/未安装${RESET}"
    fi

    echo "------------------------"
    echo "1. 安装/重装 全部服务"
    echo "2. 单独安装 Shadowsocks"
    echo "3. 停止所有服务"
    echo "4. 重启所有服务"
    echo "5. 查看连接信息 (安装后有效)"
    echo "6. 卸载所有服务"
    echo "0. 退出"
    echo "------------------------"
    read -p "请输入选项: " choice
}

# ================== 主逻辑 ==================
install_dependencies
check_arch

while true; do
    show_menu
    case "$choice" in
        1)
            install_shoes
            install_ss
            generate_links
            ;;
        2)
            install_ss
            generate_links
            ;;
        3)
            systemctl stop shoes shadowsocks-rust
            echo "服务已停止"
            ;;
        4)
            systemctl restart shoes shadowsocks-rust
            echo "服务已重启"
            ;;
        5)
            if [[ -f "${LINK_FILE}" ]]; then
                cat "${LINK_FILE}"
            else
                echo -e "${RED}暂无链接信息，请先执行安装。${RESET}"
                # 尝试重新生成（针对已安装但没保存的情况，这里简化处理，只生成SS的）
                generate_links
            fi
            ;;
        6)
            systemctl stop shoes shadowsocks-rust
            systemctl disable shoes shadowsocks-rust
            rm -f "${SHOES_SERVICE}" "${SS_SERVICE}"
            rm -rf "${SHOES_CONF_DIR}" "${SS_CONF_DIR}" "${SHOES_BIN}" "${SS_BIN}"
            systemctl daemon-reload
            echo -e "${GREEN}卸载完成${RESET}"
            ;;
        0) exit 0 ;;
        *) echo "无效选项" ;;
    esac
    read -p "按回车继续..."

done
