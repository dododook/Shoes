#!/bin/bash
set -euo pipefail

# ================== 颜色代码 ==================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

# ================== 常量定义 ==================
SHOES_BIN="/usr/local/bin/shoes"
SHOES_CONF_DIR="/etc/shoes"
SHOES_CONF_FILE="${SHOES_CONF_DIR}/config.yaml"
SHOES_LINK_FILE="${SHOES_CONF_DIR}/config.txt"
SYSTEMD_FILE="/etc/systemd/system/shoes.service"
TMP_DIR="/tmp/shoesdl"

# ================== Root 检查 ==================
require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo -e "${RED}必须使用 root 权限运行此脚本！${RESET}"
    exit 1
  fi
}

# ================== 依赖检查 ==================
need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo -e "${RED}缺少依赖: ${YELLOW}$1${RESET}"
    exit 1
  }
}

check_deps() {
  need_cmd curl
  need_cmd wget
  need_cmd tar
  need_cmd openssl
  need_cmd systemctl
  need_cmd awk
  need_cmd sed
  need_cmd grep
  need_cmd uname
  need_cmd shuf
  need_cmd base64
}

# ================== glibc / musl 检测 ==================
get_libc_info() {
  # 默认值
  LIBC_KIND="glibc"
  GLIBC_VERSION=""
  GLIBC_MAJOR=0
  GLIBC_MINOR=0

  if ! command -v ldd >/dev/null 2>&1; then
    # 极端情况：没有 ldd，保守用 musl 版
    LIBC_KIND="unknown"
    echo -e "${YELLOW}未找到 ldd，无法判断 libc，后续将优先使用 MUSL 版本${RESET}"
    return
  fi

  local ldd_out
  ldd_out="$(ldd --version 2>&1 | head -n1 || true)"

  if echo "$ldd_out" | grep -qi "musl"; then
    LIBC_KIND="musl"
    echo -e "${GREEN}系统 libc：${YELLOW}musl${RESET}"
    return
  fi

  # glibc 常见输出：ldd (Debian GLIBC 2.36-9+deb12u4) 2.36
  GLIBC_VERSION="$(echo "$ldd_out" | awk '{print $NF}' | tr -d '()' || true)"
  if [[ -n "${GLIBC_VERSION}" && "${GLIBC_VERSION}" =~ ^[0-9]+\.[0-9]+ ]]; then
    GLIBC_MAJOR="$(echo "$GLIBC_VERSION" | cut -d. -f1)"
    GLIBC_MINOR="$(echo "$GLIBC_VERSION" | cut -d. -f2)"
    echo -e "${GREEN}系统 libc：${YELLOW}glibc ${GLIBC_VERSION}${RESET}"
  else
    LIBC_KIND="unknown"
    echo -e "${YELLOW}无法解析 glibc 版本，后续将优先使用 MUSL 版本${RESET}"
  fi
}

# ================== 架构检测 ==================
check_arch() {
  case "$(uname -m)" in
    x86_64)
      GNU_FILE="shoes-x86_64-unknown-linux-gnu.tar.gz"
      MUSL_FILE="shoes-x86_64-unknown-linux-musl.tar.gz"
      ;;
    aarch64|arm64)
      GNU_FILE="shoes-aarch64-unknown-linux-gnu.tar.gz"
      MUSL_FILE="shoes-aarch64-unknown-linux-musl.tar.gz"
      ;;
    *)
      echo -e "${RED}不支持的 CPU 架构：$(uname -m)${RESET}"
      exit 1
      ;;
  esac
}

# ================== 最新版本 ==================
get_latest_version() {
  LATEST_VER="$(curl -s https://api.github.com/repos/cfal/shoes/releases/latest \
    | grep '"tag_name":' \
    | sed -E 's/.*"v?([^"]+)".*/\1/' || true)"
  if [[ -z "${LATEST_VER}" ]]; then
    echo -e "${RED}无法获取 Shoes 最新版本！${RESET}"
    exit 1
  fi
  echo -e "${GREEN}Shoes 最新版本：${YELLOW}v${LATEST_VER}${RESET}"
}

# ================== 运行测试 ==================
test_shoes_binary() {
  "${SHOES_BIN}" generate-reality-keypair >/dev/null 2>&1
}

# ================== 下载并安装 Shoes ==================
download_shoes() {
  check_arch
  get_latest_version
  get_libc_info

  local DOWNLOAD_FILE DOWNLOAD_TYPE DOWNLOAD_URL

  # 选择 GNU / MUSL
  if [[ "${LIBC_KIND}" == "musl" || "${LIBC_KIND}" == "unknown" ]]; then
    echo -e "${GREEN}优先使用 MUSL 版本${RESET}"
    DOWNLOAD_FILE="${MUSL_FILE}"
    DOWNLOAD_TYPE="MUSL"
  else
    # glibc >= 2.38 才优先 GNU，否则用 MUSL
    if (( GLIBC_MAJOR < 2 )) || (( GLIBC_MAJOR == 2 && GLIBC_MINOR < 38 )); then
      echo -e "${GREEN}glibc < 2.38，使用 MUSL 版本${RESET}"
      DOWNLOAD_FILE="${MUSL_FILE}"
      DOWNLOAD_TYPE="MUSL"
    else
      echo -e "${GREEN}glibc >= 2.38，优先 GNU 版本${RESET}"
      DOWNLOAD_FILE="${GNU_FILE}"
      DOWNLOAD_TYPE="GNU"
    fi
  fi

  mkdir -p "${TMP_DIR}"
  cd "${TMP_DIR}" || exit 1

  DOWNLOAD_URL="https://github.com/cfal/shoes/releases/download/v${LATEST_VER}/${DOWNLOAD_FILE}"
  echo -e "${GREEN}下载 ${DOWNLOAD_TYPE}: ${CYAN}${DOWNLOAD_URL}${RESET}"

  if ! wget -O shoes.tar.gz "$DOWNLOAD_URL"; then
    if [[ "$DOWNLOAD_TYPE" == "GNU" ]]; then
      echo -e "${YELLOW}GNU 下载失败，尝试 MUSL${RESET}"
      DOWNLOAD_URL="https://github.com/cfal/shoes/releases/download/v${LATEST_VER}/${MUSL_FILE}"
      wget -O shoes.tar.gz "$DOWNLOAD_URL"
      DOWNLOAD_TYPE="MUSL"
    else
      echo -e "${RED}MUSL 下载失败${RESET}"
      exit 1
    fi
  fi

  tar -xzf shoes.tar.gz
  if [[ ! -f "shoes" ]]; then
    echo -e "${RED}解压后未找到 shoes 二进制文件${RESET}"
    exit 1
  fi

  mv -f shoes "${SHOES_BIN}"
  chmod +x "${SHOES_BIN}"

  if test_shoes_binary; then
    echo -e "${GREEN}(${DOWNLOAD_TYPE}) 正常运行${RESET}"
    return 0
  fi

  # GNU 可能因 glibc 不匹配而无法运行，再切 MUSL 兜底
  if [[ "$DOWNLOAD_TYPE" == "GNU" ]]; then
    echo -e "${YELLOW}GNU 无法运行，切换 MUSL 版本兜底${RESET}"
    wget -O shoes.tar.gz "https://github.com/cfal/shoes/releases/download/v${LATEST_VER}/${MUSL_FILE}"
    tar -xzf shoes.tar.gz
    mv -f shoes "${SHOES_BIN}"
    chmod +x "${SHOES_BIN}"
    if test_shoes_binary; then
      echo -e "${GREEN}(MUSL) 正常运行${RESET}"
      return 0
    fi
    echo -e "${RED}MUSL 仍无法运行，安装失败${RESET}"
    exit 1
  fi

  echo -e "${RED}安装失败：二进制无法运行${RESET}"
  exit 1
}

# ================== 获取公网 IPv4（简单版） ==================
get_public_ipv4() {
  curl -s -4 https://api64.ipify.org 2>/dev/null || true
}

# ================== 安装 ==================
install_shoes() {
  echo -e "${GREEN}开始安装 Shoes + VLESS/Reality + AnyTLS + Shadowsocks(2022)${RESET}"
  download_shoes
  mkdir -p "${SHOES_CONF_DIR}"

  # ------- VLESS/Reality -------
  SNI="www.ua.edu"
  SHID="$(openssl rand -hex 8)"
  VLESS_PORT="$(shuf -i 20000-60000 -n 1)"
  UUID="$(cat /proc/sys/kernel/random/uuid)"

  KEYPAIR="$("${SHOES_BIN}" generate-reality-keypair)"
  PRIVATE_KEY="$(echo "$KEYPAIR" | awk '/private key/ {print $4}')"
  PUBLIC_KEY="$(echo "$KEYPAIR"  | awk '/public key/  {print $4}')"

  # ------- AnyTLS（TLS + 自签证书）-------
  ANYTLS_PORT="$(shuf -i 20000-60000 -n 1)"
  ANYTLS_PWD="$(openssl rand -base64 18 | tr -d '=+/')"

  openssl ecparam -genkey -name prime256v1 -out "${SHOES_CONF_DIR}/key.pem"
  openssl req -new -x509 -days 3650 -key "${SHOES_CONF_DIR}/key.pem" \
    -out "${SHOES_CONF_DIR}/cert.pem" -subj "/CN=bing.com"

  # ------- Shadowsocks 2022 -------
  SS_PORT="$(shuf -i 20000-60000 -n 1)"
  SS_CIPHER="2022-blake3-aes-256-gcm"
  # 用 shoes 自带命令生成 2022 密码/PSK
  SS_PSK="$("${SHOES_BIN}" generate-shadowsocks-2022-password "${SS_CIPHER}")"

  # ------- 写配置 -------
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
            - name: anytls
              password: "${ANYTLS_PWD}"
          udp_enabled: true

- address: "0.0.0.0:${SS_PORT}"
  protocol:
    type: shadowsocks
    cipher: ${SS_CIPHER}
    password: "${SS_PSK}"
    udp_enabled: true
EOF

  # ------- systemd -------
  cat > "${SYSTEMD_FILE}" <<EOF
[Unit]
Description=Shoes Proxy Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${SHOES_CONF_DIR}
ExecStart=${SHOES_BIN} ${SHOES_CONF_FILE}
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now shoes
  systemctl --no-pager status shoes || true

  # ------- 输出链接 -------
  HOST_IP="$(get_public_ipv4)"
  if [[ -z "${HOST_IP}" ]]; then
    HOST_IP="YOUR_SERVER_IP"
  fi
  COUNTRY="$( [ "${HOST_IP}" != "YOUR_SERVER_IP" ] && curl -s "https://ipinfo.io/${HOST_IP}/country" 2>/dev/null || echo "ZZ" )"

  # SS URI：ss://BASE64(method:password)@host:port#tag
  SS_USERINFO_B64="$(printf "%s:%s" "${SS_CIPHER}" "${SS_PSK}" | base64 -w 0)"

  cat > "${SHOES_LINK_FILE}" <<EOF
vless://${UUID}@${HOST_IP}:${VLESS_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=random&pbk=${PUBLIC_KEY}&sid=${SHID}&type=tcp#${COUNTRY}
anytls://${ANYTLS_PWD}@${HOST_IP}:${ANYTLS_PORT}?security=tls&sni=www.bing.com&allowInsecure=1&type=tcp#${COUNTRY}
ss://${SS_USERINFO_B64}@${HOST_IP}:${SS_PORT}#${COUNTRY}-SS2022
EOF

  echo -e "${GREEN}Shoes 安装完成！${RESET}"
  echo -e "${CYAN}配置文件：${SHOES_CONF_FILE}${RESET}"
  echo -e "${CYAN}链接文件：${SHOES_LINK_FILE}${RESET}"
  echo ""
  cat "${SHOES_LINK_FILE}"
}

# ================== 卸载 ==================
uninstall_shoes() {
  systemctl stop shoes >/dev/null 2>&1 || true
  systemctl disable shoes >/dev/null 2>&1 || true
  rm -f "${SYSTEMD_FILE}"
  rm -rf "${SHOES_CONF_DIR}"
  rm -f "${SHOES_BIN}"
  systemctl daemon-reload
  echo -e "${GREEN}Shoes 已卸载${RESET}"
}

# ================== 状态 ==================
check_installed() { command -v shoes >/dev/null 2>&1 || [[ -x "${SHOES_BIN}" ]]; }
check_running() { systemctl is-active --quiet shoes; }

# ================== 菜单 ==================
show_menu() {
  clear
  echo -e "${GREEN}=== Shoes 管理工具 (VLESS/Reality + AnyTLS + SS2022) ===${RESET}"
  echo -e "安装状态: $(check_installed && echo -e "${GREEN}已安装${RESET}" || echo -e "${RED}未安装${RESET}")"
  echo -e "运行状态: $(check_running && echo -e "${GREEN}运行中${RESET}" || echo -e "${RED}未运行${RESET}")"
  echo ""
  echo "1. 安装 Shoes 服务"
  echo "2. 卸载 Shoes 服务"
  echo "3. 启动 Shoes 服务"
  echo "4. 停止 Shoes 服务"
  echo "5. 重启 Shoes 服务"
  echo "6. 查看 Shoes 链接"
  echo "7. 查看 Shoes 日志"
  echo "0. 退出"
  echo -e "${GREEN}===============================================${RESET}"
  echo ""
  read -r -p "请输入选项: " choice
}

# ================== 主循环 ==================
require_root
check_deps

while true; do
  show_menu
  case "${choice}" in
    1) install_shoes ;;
    2) uninstall_shoes ;;
    3) systemctl start shoes ;;
    4) systemctl stop shoes ;;
    5) systemctl restart shoes ;;
    6) [[ -f "${SHOES_LINK_FILE}" ]] && cat "${SHOES_LINK_FILE}" || echo -e "${YELLOW}未找到链接文件：${SHOES_LINK_FILE}${RESET}" ;;
    7) journalctl -u shoes -f ;;
    0) exit 0 ;;
    *) echo -e "${RED}无效选项！${RESET}" ;;
  esac
  read -r -p "按 Enter 继续..."
done
