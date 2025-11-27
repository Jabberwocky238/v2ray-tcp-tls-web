#!/bin/bash
# Ubuntu 22.04 专用安装脚本
export LC_ALL=C
export LANG=en_US
export LANGUAGE=en_US.UTF-8

# 颜色定义
RED="31m"
GREEN="32m"
YELLOW="33m"
BLUE="36m"

colorEcho(){
  echo -e "\033[${1}${@:2}\033[0m" 1>& 2
}

# 检查 root 权限
if [[ $(/usr/bin/id -u) -ne 0 ]]; then
  sudoCmd="sudo"
else
  sudoCmd=""
fi

colorEcho ${BLUE} "==================== Ubuntu 22.04 安装脚本 ===================="

# 全局变量
DOMAIN_NAME=""

# ========== 步骤 1: 下载 Trojan-Go ==========
step1_install_trojan_go() {
  colorEcho ${GREEN} "步骤 1: 安装 Trojan-Go"
  
  # 创建必要的目录
  ${sudoCmd} mkdir -p /etc/trojan-go
  ${sudoCmd} mkdir -p /usr/bin
  
  # 下载 trojan-go
  colorEcho ${BLUE} "正在下载 Trojan-Go..."
  local latest_version="v20250924_033135"
  local trojango_link="https://github.com/jabberwocky238/trojan-go/releases/download/${latest_version}/trojan-go-linux-amd64.zip"
  
  cd /tmp
  ${sudoCmd} rm -rf trojan-go trojan-go.zip
  wget -nv "${trojango_link}" -O trojan-go.zip
  
  if [ ! -f "trojan-go.zip" ]; then
    colorEcho ${RED} "下载 Trojan-Go 失败"
    exit 1
  fi
  
  # 解压并复制文件
  unzip -q trojan-go.zip -d trojan-go
  ${sudoCmd} cp trojan-go/trojan-go /usr/bin/trojan-go
  ${sudoCmd} chmod +x /usr/bin/trojan-go
  
  # 下载并安装 geoip 和 geosite 数据
  colorEcho ${BLUE} "下载 geoip.dat 和 geosite.dat..."
  ${sudoCmd} wget -q https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip.dat -O /usr/bin/geoip.dat
  ${sudoCmd} wget -q https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat -O /usr/bin/geosite.dat
  
  # 创建 systemd 服务文件
  colorEcho ${BLUE} "创建 Trojan-Go systemd 服务..."
  ${sudoCmd} cp trojan-go/example/trojan-go.service /etc/systemd/system/trojan-go.service
  
  # 下载配置文件
  colorEcho ${BLUE} "下载 Trojan-Go 配置文件..."
  ${sudoCmd} wget -q https://raw.githubusercontent.com/jabberwocky238/v2ray-tcp-tls-web/master/config/trojan-go_plain.json -O /tmp/trojan-go.json
  
  # 生成随机密码
  local trojan_password="$(cat '/proc/sys/kernel/random/uuid' | sed -e 's/-//g' | tr '[:upper:]' '[:lower:]' | head -c 12)"
  sed -i "s/FAKETROJANPWD/${trojan_password}/g" /tmp/trojan-go.json
  ${sudoCmd} cp /tmp/trojan-go.json /etc/trojan-go/config.json
  
  # 设置定时更新 geoip 和 geosite
  (${sudoCmd} crontab -l 2>/dev/null | grep -v 'geoip.dat'; echo "0 7 * * * wget -q https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip.dat -O /usr/bin/geoip.dat >/dev/null 2>&1") | ${sudoCmd} crontab -
  (${sudoCmd} crontab -l 2>/dev/null | grep -v 'geosite.dat'; echo "0 7 * * * wget -q https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat -O /usr/bin/geosite.dat >/dev/null 2>&1") | ${sudoCmd} crontab -
  
  colorEcho ${GREEN} "✓ Trojan-Go 安装完成"
  echo "Trojan-Go 密码: ${trojan_password}"
}

# ========== 步骤 2: 下载 Hysteria2 ==========
step2_install_hysteria2() {
  colorEcho ${GREEN} "步骤 2: 安装 Hysteria2"
  
  # 创建必要的目录
  ${sudoCmd} mkdir -p /etc/hysteria2
  ${sudoCmd} mkdir -p /usr/bin
  
  # 下载 hysteria2 二进制文件
  colorEcho ${BLUE} "正在下载 Hysteria2..."
  ${sudoCmd} curl -fsSL https://download.hysteria.network/app/latest/hysteria-linux-amd64 -o /usr/bin/hysteria2
  
  if [ ! -f "/usr/bin/hysteria2" ]; then
    colorEcho ${RED} "下载 Hysteria2 失败"
    exit 1
  fi
  
  ${sudoCmd} chmod +x /usr/bin/hysteria2
  
  # 下载服务文件
  colorEcho ${BLUE} "下载 Hysteria2 systemd 服务文件..."
  ${sudoCmd} wget -q https://raw.githubusercontent.com/jabberwocky238/v2ray-tcp-tls-web/master/config/hysteria2.service -O /etc/systemd/system/hysteria2.service
  
  # 下载配置文件
  colorEcho ${BLUE} "下载 Hysteria2 配置文件..."
  ${sudoCmd} wget -q https://raw.githubusercontent.com/jabberwocky238/v2ray-tcp-tls-web/master/config/hysteria2.yml -O /etc/hysteria2/config.yml
  
  colorEcho ${GREEN} "✓ Hysteria2 安装完成"
}

# ========== 步骤 3: 安装 TLS-Shunt-Proxy ==========
step3_install_tls_shunt_proxy() {
  colorEcho ${GREEN} "步骤 3: 安装 TLS-Shunt-Proxy"
  
  # 创建必要的目录
  ${sudoCmd} mkdir -p /etc/tls-shunt-proxy
  ${sudoCmd} mkdir -p /usr/local/bin
  
  if [ ! -f "/usr/local/bin/tls-shunt-proxy" ]; then
    colorEcho ${BLUE} "正在安装 TLS-Shunt-Proxy..."
    curl -sL https://raw.githubusercontent.com/liberal-boy/tls-shunt-proxy/master/dist/install.sh | ${sudoCmd} bash
  else
    colorEcho ${BLUE} "更新 TLS-Shunt-Proxy..."
    local DOWNLOAD_URL="https://github.com/liberal-boy/tls-shunt-proxy/releases/download/0.6.1/tls-shunt-proxy-linux-amd64.zip"
    ${sudoCmd} curl -L -H "Cache-Control: no-cache" -o "/tmp/tls-shunt-proxy.zip" "${DOWNLOAD_URL}"
    ${sudoCmd} unzip -o -d /usr/local/bin/ "/tmp/tls-shunt-proxy.zip"
    ${sudoCmd} chmod +x /usr/local/bin/tls-shunt-proxy
  fi
  
  # 下载配置文件
  colorEcho ${BLUE} "下载 TLS-Shunt-Proxy 配置文件..."
  ${sudoCmd} wget -q https://raw.githubusercontent.com/jabberwocky238/v2ray-tcp-tls-web/master/config/tls-shunt-proxy.yaml -O /tmp/tls-shunt-proxy.yaml
  
  # 询问域名
  while true; do
    read -rp "请输入解析到本 VPS 的域名: " DOMAIN_NAME
    if [ -z "${DOMAIN_NAME}" ]; then
      colorEcho ${RED} "域名不能为空"
      continue
    else
      break
    fi
  done
  
  # 替换配置文件中的域名占位符
  sed -i "s/FAKETJDOMAIN/${DOMAIN_NAME}/g" /tmp/tls-shunt-proxy.yaml
  sed -i "s/FAKEV2DOMAIN/${DOMAIN_NAME}/g" /tmp/tls-shunt-proxy.yaml
  sed -i "s/##TROJAN@//g" /tmp/tls-shunt-proxy.yaml
  
  # 替换 hysteria2 配置文件中的域名
  if [ -f "/etc/hysteria2/config.yml" ]; then
    ${sudoCmd} sed -i "s/DOMAINNAME/${DOMAIN_NAME}/g" /etc/hysteria2/config.yml
  fi
  
  ${sudoCmd} cp /tmp/tls-shunt-proxy.yaml /etc/tls-shunt-proxy/config.yaml
  
  # 创建虚拟网站目录
  colorEcho ${BLUE} "创建虚拟网站..."
  if [ ! -f "/var/www/html/index.html" ]; then
    local template="$(curl -s https://raw.githubusercontent.com/phlinhng/web-templates/master/list.txt | shuf -n 1)"
    wget -q https://raw.githubusercontent.com/phlinhng/web-templates/master/${template} -O /tmp/template.zip
    ${sudoCmd} mkdir -p /var/www/html
    ${sudoCmd} unzip -q /tmp/template.zip -d /var/www/html
    ${sudoCmd} wget -q https://raw.githubusercontent.com/phlinhng/v2ray-tcp-tls-web/master/custom/robots.txt -O /var/www/html/robots.txt
  fi
  
  colorEcho ${GREEN} "✓ TLS-Shunt-Proxy 安装完成"
  echo "域名: ${DOMAIN_NAME}"
}

# ========== 步骤 4: 启动 Trojan-Go ==========
step4_start_trojan_go() {
  colorEcho ${GREEN} "步骤 4: 启动 Trojan-Go"
  
  ${sudoCmd} systemctl daemon-reload
  ${sudoCmd} systemctl enable trojan-go
  ${sudoCmd} systemctl restart trojan-go
  
  # 检查状态
  sleep 2
  if ${sudoCmd} systemctl is-active --quiet trojan-go; then
    colorEcho ${GREEN} "✓ Trojan-Go 启动成功"
  else
    colorEcho ${RED} "✗ Trojan-Go 启动失败"
    ${sudoCmd} systemctl status trojan-go --no-pager
  fi
}

# ========== 步骤 5: 启动 Hysteria2 ==========
step5_start_hysteria2() {
  colorEcho ${GREEN} "步骤 5: 启动 Hysteria2"
  
  ${sudoCmd} systemctl daemon-reload
  ${sudoCmd} systemctl enable hysteria2
  ${sudoCmd} systemctl restart hysteria2
  
  # 检查状态
  sleep 2
  if ${sudoCmd} systemctl is-active --quiet hysteria2; then
    colorEcho ${GREEN} "✓ Hysteria2 启动成功"
  else
    colorEcho ${RED} "✗ Hysteria2 启动失败"
    ${sudoCmd} systemctl status hysteria2 --no-pager
  fi
}

# ========== 步骤 6: 启动 TLS-Shunt-Proxy 并等待证书申请 ==========
step6_start_tls_shunt_proxy() {
  colorEcho ${GREEN} "步骤 6: 启动 TLS-Shunt-Proxy 并申请证书"
  
  ${sudoCmd} systemctl daemon-reload
  ${sudoCmd} systemctl enable tls-shunt-proxy
  ${sudoCmd} systemctl restart tls-shunt-proxy
  
  # 检查状态
  sleep 2
  if ${sudoCmd} systemctl is-active --quiet tls-shunt-proxy; then
    colorEcho ${GREEN} "✓ TLS-Shunt-Proxy 启动成功"
  else
    colorEcho ${RED} "✗ TLS-Shunt-Proxy 启动失败"
    ${sudoCmd} systemctl status tls-shunt-proxy --no-pager
    return 1
  fi
  
  # 等待证书申请完成
  colorEcho ${BLUE} "等待 Let's Encrypt 证书申请..."
  local cert_path="/etc/ssl/tls-shunt-proxy/certificates/acme-v02.api.letsencrypt.org-directory/${DOMAIN_NAME}/${DOMAIN_NAME}.crt"
  local max_wait=60
  local waited=0
  
  while [ ! -f "${cert_path}" ] && [ ${waited} -lt ${max_wait} ]; do
    echo -n "."
    sleep 2
    waited=$((waited + 2))
  done
  echo ""
  
  if [ -f "${cert_path}" ]; then
    colorEcho ${GREEN} "✓ 证书申请成功！"
    colorEcho ${BLUE} "证书路径: ${cert_path}"
  else
    colorEcho ${YELLOW} "⚠ 警告：证书文件未在 ${max_wait} 秒内生成"
    colorEcho ${YELLOW} "请检查域名解析是否正确，以及 80/443 端口是否开放"
    colorEcho ${YELLOW} "可以使用以下命令查看日志："
    echo "  sudo journalctl -u tls-shunt-proxy -n 50"
  fi
}

# ========== 显示服务状态 ==========
show_status() {
  colorEcho ${BLUE} "==================== 服务状态 ===================="
  echo ""
  
  colorEcho ${YELLOW} "Trojan-Go 状态:"
  ${sudoCmd} systemctl status trojan-go --no-pager -l | head -n 10
  echo ""
  
  colorEcho ${YELLOW} "Hysteria2 状态:"
  ${sudoCmd} systemctl status hysteria2 --no-pager -l | head -n 10
  echo ""
  
  colorEcho ${YELLOW} "TLS-Shunt-Proxy 状态:"
  ${sudoCmd} systemctl status tls-shunt-proxy --no-pager -l | head -n 10
  echo ""
  
  colorEcho ${BLUE} "==================== 配置信息 ===================="
  if [ -f "/etc/trojan-go/config.json" ]; then
    echo "Trojan-Go 配置文件: /etc/trojan-go/config.json"
    echo "Trojan-Go 密码可在配置文件中查看"
  fi
  
  if [ -f "/etc/hysteria2/config.yml" ]; then
    echo "Hysteria2 配置文件: /etc/hysteria2/config.yml"
  fi
  
  if [ -f "/etc/tls-shunt-proxy/config.yaml" ]; then
    echo "TLS-Shunt-Proxy 配置文件: /etc/tls-shunt-proxy/config.yaml"
  fi
}

# ========== 主流程 ==========
main() {
  # 检查并安装必要工具
  colorEcho ${BLUE} "检查并安装必要工具..."
  ${sudoCmd} apt-get update
  ${sudoCmd} apt-get install -y wget curl unzip jq
  
  # 执行各个步骤
  step1_install_trojan_go
  echo ""
  
  step2_install_hysteria2
  echo ""
  
  step3_install_tls_shunt_proxy
  echo ""

step6_start_tls_shunt_proxy
  echo ""
  
  step4_start_trojan_go
  echo ""
  
  step5_start_hysteria2
  echo ""
  

  
  # 显示状态
  show_status
  
  colorEcho ${GREEN} "==================== 安装完成 ===================="
}

# 运行主函数
main

