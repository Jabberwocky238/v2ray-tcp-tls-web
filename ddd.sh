#!/bin/bash
export LC_ALL=C
export LANG=en_US
export LANGUAGE=en_US.UTF-8

branch="master"

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
  sudoCmd="sudo"
else
  sudoCmd=""
fi

# colour code
RED="31m"
GREEN="32m"
YELLOW="33m"
BLUE="36m"

# colour function
colorEcho(){
  echo -e "\033[${1}${@:2}\033[0m" 1>& 2
}

red="\033[0;${RED}"
green="\033[0;${GREEN}"
nocolor="\033[0m"

# 检测操作系统
if [[ -f /etc/redhat-release ]]; then
  release="centos"
  systemPackage="yum"
elif cat /etc/issue | grep -Eqi "debian"; then
  release="debian"
  systemPackage="apt-get"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
  release="ubuntu"
  systemPackage="apt-get"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
  release="centos"
  systemPackage="yum"
elif cat /proc/version | grep -Eqi "debian"; then
  release="debian"
  systemPackage="apt-get"
elif cat /proc/version | grep -Eqi "ubuntu"; then
  release="ubuntu"
  systemPackage="apt-get"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
  release="centos"
  systemPackage="yum"
fi

# 检查并安装必要的工具
check_dependencies() {
  if ! command -v jq &> /dev/null; then
    colorEcho ${BLUE} "jq 未安装，正在安装..."
    ${sudoCmd} ${systemPackage} install jq -y -qq
    colorEcho ${GREEN} "jq 安装完成"
  fi
  
  if ! command -v curl &> /dev/null; then
    colorEcho ${BLUE} "curl 未安装，正在安装..."
    ${sudoCmd} ${systemPackage} install curl -y -qq
    colorEcho ${GREEN} "curl 安装完成"
  fi
  
  if ! command -v wget &> /dev/null; then
    colorEcho ${BLUE} "wget 未安装，正在安装..."
    ${sudoCmd} ${systemPackage} install wget -y -qq
    colorEcho ${GREEN} "wget 安装完成"
  fi
}

urlEncode() {
  printf %s "$1" | jq -s -R -r @uri
}

get_proxy() {
  if [ ! -f "/usr/local/bin/tls-shunt-proxy" ]; then
    colorEcho ${BLUE} "tls-shunt-proxy 未安装，开始安装"
    curl -sL https://raw.githubusercontent.com/liberal-boy/tls-shunt-proxy/master/dist/install.sh | ${sudoCmd} bash
    colorEcho ${GREEN} "tls-shunt-proxy 安装完成"
  else
    colorEcho ${BLUE} "tls-shunt-proxy 已安装，跳过"
  fi
}

set_proxy() {
  local DOMAIN=$1
  
  colorEcho ${BLUE} "创建 tls-shunt-proxy 配置文件"
  ${sudoCmd} mkdir -p /etc/tls-shunt-proxy
  ${sudoCmd} /bin/cp /etc/tls-shunt-proxy/config.yaml /etc/tls-shunt-proxy/config.yaml.bak 2>/dev/null
  
  # 直接创建配置文件，强制使用指定的配置
  ${sudoCmd} cat > /etc/tls-shunt-proxy/config.yaml <<-EOF
listen: 0.0.0.0:443
redirecthttps: true
inboundbuffersize: 4
outboundbuffersize: 32
vhosts:
  - name: ${DOMAIN}
    tlsoffloading: true
    managedcert: true
    keytype: p256
    alpn: h2,http/1.1
    protocols: tls12,tls13
    http:
      handler: fileServer
      args: /var/www/html
    trojan:
      handler: proxyPass
      args: 127.0.0.1:3567
EOF
  
  colorEcho ${GREEN} "tls-shunt-proxy 配置完成"
}

build_web() {
  if [ ! -f "/var/www/html/index.html" ]; then
    colorEcho ${BLUE} "构建伪装网站"
    local template="$(curl -s https://raw.githubusercontent.com/phlinhng/web-templates/master/list.txt | shuf -n 1)"
    wget -q https://raw.githubusercontent.com/phlinhng/web-templates/master/${template} -O /tmp/template.zip
    ${sudoCmd} mkdir -p /var/www/html
    ${sudoCmd} unzip -q /tmp/template.zip -d /var/www/html
    ${sudoCmd} wget -q https://raw.githubusercontent.com/jabberwocky238/v2ray-tcp-tls-web/${branch}/custom/robots.txt -O /var/www/html/robots.txt
    colorEcho ${GREEN} "伪装网站构建完成"
  else
    colorEcho ${BLUE} "伪装网站已存在，跳过"
  fi
}

checkIP() {
  local realIP="$(curl -s `curl -s https://raw.githubusercontent.com/jabberwocky238/v2ray-tcp-tls-web/master/custom/ip_api`)"
  local resolvedIP="$(ping $1 -c 1 | head -n 1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)"

  if [[ "${realIP}" == "${resolvedIP}" ]]; then
    return 0
  else
    return 1
  fi
}

get_trojan() {
  if [ ! -f "/usr/bin/trojan-go" ]; then
    colorEcho ${BLUE} "trojan-go 未安装，开始安装"
    colorEcho ${BLUE} "获取 trojan-go 最新版本"
    local latest_version="v20250924_033135"
    echo "${latest_version}"
    local trojango_link="https://github.com/jabberwocky238/trojan-go/releases/download/${latest_version}/trojan-go-linux-amd64.zip"

    ${sudoCmd} mkdir -p "/etc/trojan-go"

    cd $(mktemp -d)
    wget -nv "${trojango_link}" -O trojan-go.zip
    unzip -q trojan-go.zip && rm -rf trojan-go.zip
    ${sudoCmd} mv trojan-go /usr/bin/trojan-go

    colorEcho ${BLUE} "创建 trojan-go.service"
    ${sudoCmd} mv example/trojan-go.service /etc/systemd/system/trojan-go.service

    ${sudoCmd} wget -q https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip.dat -O /usr/bin/geoip.dat
    ${sudoCmd} wget -q https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat -O /usr/bin/geosite.dat

    # 设置定时任务自动更新 geoip.dat 和 geosite.dat
    (crontab -l 2>/dev/null; echo "0 7 * * * wget -q https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip.dat -O /usr/bin/geoip.dat >/dev/null 2>&1") | ${sudoCmd} crontab -
    (crontab -l 2>/dev/null; echo "0 7 * * * wget -q https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat -O /usr/bin/geosite.dat >/dev/null 2>&1") | ${sudoCmd} crontab -

    colorEcho ${GREEN} "trojan-go 安装完成"
  else
    colorEcho ${BLUE} "trojan-go 已安装，跳过"
  fi
}

install_trojan() {
  local TJ_DOMAIN=""
  
  while true; do
    read -rp "解析到本 VPS 的域名: " TJ_DOMAIN
    if checkIP "${TJ_DOMAIN}"; then
      colorEcho ${GREEN} "域名 ${TJ_DOMAIN} 解析正确, 即将开始安装"
      break
    else
      colorEcho ${RED} "域名 ${TJ_DOMAIN} 解析有误"
      read -rp "若您确定域名解析正确, 可以继续进行安装. 强制继续? (yes/no/quit) " forceConfirm
      case "${forceConfirm}" in
        [yY]|[yY][eE][sS] ) break ;;
        [qQ]|[qQ][uU][iI][tT] ) return 0 ;;
      esac
    fi
  done

  # 将域名存储到临时文件，供 hysteria2 使用
  echo "${TJ_DOMAIN}" > /tmp/trojan_domain.txt

  get_trojan

  # 创建 trojan-go 配置文件
  if [ ! -f "/etc/trojan-go/config.json" ]; then
    colorEcho ${BLUE} "配置 trojan-go"
    wget -q https://raw.githubusercontent.com/jabberwocky238/v2ray-tcp-tls-web/${branch}/config/trojan-go_plain.json -O /tmp/trojan-go.json
    local TROJAN_PWD="$(cat '/proc/sys/kernel/random/uuid' | sed -e 's/-//g' | tr '[:upper:]' '[:lower:]' | head -c 12)"
    sed -i "s/FAKETROJANPWD/${TROJAN_PWD}/g" /tmp/trojan-go.json
    ${sudoCmd} /bin/cp -f /tmp/trojan-go.json /etc/trojan-go/config.json
    
    # 保存密码到文件
    echo "${TROJAN_PWD}" > /tmp/trojan_password.txt
  fi

  get_proxy
  set_proxy "${TJ_DOMAIN}"
  build_web

  # 激活服务
  colorEcho ${BLUE} "启动服务"
  ${sudoCmd} systemctl enable trojan-go
  ${sudoCmd} systemctl restart trojan-go 2>/dev/null
  ${sudoCmd} systemctl enable tls-shunt-proxy
  ${sudoCmd} systemctl restart tls-shunt-proxy
  ${sudoCmd} systemctl daemon-reload
  ${sudoCmd} systemctl reset-failed

  colorEcho ${GREEN} "trojan-go 安装成功!"
}

install_hysteria2() {
  # 从临时文件读取域名
  if [ ! -f "/tmp/trojan_domain.txt" ]; then
    colorEcho ${RED} "未找到 Trojan 域名配置, 请先安装 Trojan"
    return 1
  fi
  
  local TJ_DOMAIN="$(cat /tmp/trojan_domain.txt)"
  
  if [ -z "${TJ_DOMAIN}" ]; then
    colorEcho ${RED} "域名为空, 请先安装 Trojan"
    return 1
  fi
  
  colorEcho ${BLUE} "使用域名: ${TJ_DOMAIN}"
  
  export HYSTERIA_USER=root
  ${sudoCmd} bash <(curl -fsSL https://get.hy2.sh/)

  # 下载并配置 hysteria2
  ${sudoCmd} rm -f /etc/hysteria/config.yml
  ${sudoCmd} wget -q https://raw.githubusercontent.com/jabberwocky238/v2ray-tcp-tls-web/${branch}/config/hysteria2.yml -O /etc/hysteria/config.yml
  ${sudoCmd} sed -i "s/DOMAINNAME/${TJ_DOMAIN}/g" /etc/hysteria/config.yml

  echo ""
  colorEcho ${BLUE} "请手动执行以下命令配置防火墙:"
  colorEcho ${YELLOW} "  ifconfig"
  colorEcho ${YELLOW} "  iptables -t nat -A PREROUTING -i eth0 -p udp --dport 10000:30000 -j REDIRECT --to-ports 443"
  echo ""

  # 检查证书是否存在
  local cert_path="/etc/ssl/tls-shunt-proxy/certificates/acme-v02.api.letsencrypt.org-directory/${TJ_DOMAIN}/${TJ_DOMAIN}.crt"
  if [ ! -f "${cert_path}" ]; then
    colorEcho ${RED} "证书 ${cert_path} 不存在"
    colorEcho ${YELLOW} "证书会在 trojan-go 首次运行时自动申请"
    colorEcho ${YELLOW} "请等待证书申请完成后，手动重启 hysteria-server:"
    colorEcho ${YELLOW} "  systemctl restart hysteria-server"
    return 0
  fi
  
  ${sudoCmd} systemctl enable hysteria-server
  ${sudoCmd} systemctl restart hysteria-server

  colorEcho ${GREEN} "hysteria2 安装完成!"
}

# 主程序
main() {
  colorEcho ${BLUE} "=========================================="
  colorEcho ${BLUE} "Trojan-Go + Hysteria2 安装脚本"
  colorEcho ${BLUE} "=========================================="
  echo ""
  
  # 检查并安装依赖工具
  check_dependencies
  
  # 安装 trojan
  install_trojan
  
  # 安装 hysteria2
  install_hysteria2
  
  echo ""
  colorEcho ${GREEN} "=========================================="
  colorEcho ${GREEN} "安装完成!"
  colorEcho ${GREEN} "=========================================="
}

# 执行主程序
main
