#!/bin/bash
export LC_ALL=C
export LANG=en_US
export LANGUAGE=en_US.UTF-8

branch="master"

# /usr/local/bin/v2script ##main
# /usr/local/bin/v2sub ##subscription manager
# /usr/local/etc/v2script/config.json ##config

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
  sudoCmd="sudo"
else
  sudoCmd=""
fi

# copied from v2ray official script
# colour code
RED="31m"      # Error message
GREEN="32m"    # Success message
YELLOW="33m"   # Warning message
BLUE="36m"     # Info message
# colour function
colorEcho(){
  echo -e "\033[${1}${@:2}\033[0m" 1>& 2
}

red="\033[0;${RED}"
green="\033[0;${GREEN}"
nocolor="\033[0m"

#copied & modified from atrandys trojan scripts
#copy from 秋水逸冰 ss scripts
if [[ -f /etc/redhat-release ]]; then
  release="centos"
  systemPackage="yum"
  #colorEcho ${RED} "unsupported OS"
  #exit 0
elif cat /etc/issue | grep -Eqi "debian"; then
  release="debian"
  systemPackage="apt-get"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
  release="ubuntu"
  systemPackage="apt-get"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
  release="centos"
  systemPackage="yum"
  #colorEcho ${RED} "unsupported OS"
  #exit 0
elif cat /proc/version | grep -Eqi "debian"; then
  release="debian"
  systemPackage="apt-get"
elif cat /proc/version | grep -Eqi "ubuntu"; then
  release="ubuntu"
  systemPackage="apt-get"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
  release="centos"
  systemPackage="yum"
  #colorEcho ${RED} "unsupported OS"
  #exit 0
fi

VERSION="$(${sudoCmd} jq --raw-output '.version' /usr/local/etc/v2script/config.json 2>/dev/null | tr -d '\n')"

read_json() {
  # jq [key] [path-to-file]
  ${sudoCmd} jq --raw-output $2 $1 2>/dev/null | tr -d '\n'
} ## read_json [path-to-file] [key]

write_json() {
  # jq [key = value] [path-to-file]
  jq -r "$2 = $3" $1 > tmp.$$.json && ${sudoCmd} mv tmp.$$.json $1 && sleep 1
} ## write_json [path-to-file] [key = value]

urlEncode() {
  printf %s "$1" | jq -s -R -r @uri
}

urlDecode() {
  printf "${_//%/\\x}"
}

continue_prompt() {
  read -rp "继续其他操作 (yes/no)? " choice
  case "${choice}" in
    [yY]|[yY][eE][sS] ) return 0 ;;
    * ) exit 0;;
  esac
}

display_vmess() {
  if [[ "$(read_json /usr/local/etc/v2script/config.json '.v2ray.installed')" == "true" ]]; then
    printf '%s\n' "$(read_json /usr/local/etc/v2script/config.json '.sub.nodesList.tcp')"
  fi

  if [[ "$(read_json /usr/local/etc/v2script/config.json '.v2ray.cloudflare')" == "true" ]]; then
    printf '%s\n' "$(read_json /usr/local/etc/v2script/config.json '.sub.nodesList.wss')"
  fi

  if [[ "$(read_json /usr/local/etc/v2script/config.json '.trojan.installed')" == "true" ]]; then
    printf '%s\n' "$(read_json /usr/local/etc/v2script/config.json '.sub.nodesList.trojan')"
  fi
}

display_link_main() {
  local V2_DOMAIN="$(read_json /usr/local/etc/v2script/config.json '.v2ray.tlsHeader')"
  local TJ_DOMAIN="$(read_json /usr/local/etc/v2script/config.json '.trojan.tlsHeader')"
  if [[ "$(read_json /usr/local/etc/v2script/config.json '.v2ray.installed')" == "true" ]] && [[ "$(read_json /usr/local/etc/v2script/config.json '.trojan.installed')" == "true" ]]; then
    printf '%s\n' "https://${V2_DOMAIN}/$(read_json /usr/local/etc/v2script/config.json '.sub.uri')"
    printf '%s\n\n' "二维码: https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=sub://$(printf %s "https://${V2_DOMAIN}/$(read_json /usr/local/etc/v2script/config.json '.sub.uri')" | base64 --wrap=0)"
    printf '%s\n' "https://${TJ_DOMAIN}/$(read_json /usr/local/etc/v2script/config.json '.sub.uri')"
    printf '%s\n' "二维码: https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=sub://$(printf %s "https://${TJ_DOMAIN}/$(read_json /usr/local/etc/v2script/config.json '.sub.uri')" | base64 --wrap=0)"
  elif [[ "$(read_json /usr/local/etc/v2script/config.json '.v2ray.installed')" == "true" ]]; then
    printf '%s\n' "https://${V2_DOMAIN}/$(read_json /usr/local/etc/v2script/config.json '.sub.uri')"
    printf '%s\n' "二维码: https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=sub://$(printf %s "https://${V2_DOMAIN}/$(read_json /usr/local/etc/v2script/config.json '.sub.uri')" | base64 --wrap=0)"
  elif [[ "$(read_json /usr/local/etc/v2script/config.json '.trojan.installed')" == "true" ]]; then
    printf '%s\n' "https://${TJ_DOMAIN}/$(read_json /usr/local/etc/v2script/config.json '.sub.uri')"
    printf '%s\n' "二维码: https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=sub://$(printf %s "https://${TJ_DOMAIN}/$(read_json /usr/local/etc/v2script/config.json '.sub.uri')" | base64 --wrap=0)"
  fi
}

sync_nodes() {
  local v2_remark=$1
  local tj_remark=$2

  local V2_DOMAIN="$(read_json /usr/local/etc/v2script/config.json '.v2ray.tlsHeader')"
  local TJ_DOMAIN="$(read_json /usr/local/etc/v2script/config.json '.trojan.tlsHeader')"

  if [[ "$(read_json /usr/local/etc/v2script/config.json '.v2ray.installed')" == "true" ]]; then
    local uuid_tcp="$(read_json /usr/local/etc/v2ray/config.json '.inbounds[0].settings.clients[0].id')"
    local json_tcp="{\"add\":\"${V2_DOMAIN}\",\"aid\":\"0\",\"host\":\"\",\"id\":\"${uuid_tcp}\",\"net\":\"\",\"path\":\"\",\"port\":\"443\",\"ps\":\"${v2_remark}\",\"tls\":\"tls\",\"type\":\"none\",\"v\":\"2\"}"
    local uri_tcp="$(printf %s "${json_tcp}" | base64 --wrap=0)"
    write_json /usr/local/etc/v2script/config.json '.sub.nodesList.tcp' "$(printf %s "\"vmess://${uri_tcp}\"")"
  fi

  if [[ "$(read_json /usr/local/etc/v2script/config.json '.v2ray.cloudflare')" == "true" ]]; then
    #local cfUrl="www.digitalocean.com"
    local cfUrl="amp.cloudflare.com"
    local wssPath="$(read_json /usr/local/etc/v2ray/config.json '.inbounds[1].streamSettings.wsSettings.path' | tr -d '/')"
    local uuid_wss="$(read_json /usr/local/etc/v2ray/config.json '.inbounds[1].settings.clients[0].id')"
    local json_wss="{\"add\":\"${cfUrl}\",\"aid\":\"1\",\"host\":\"${V2_DOMAIN}\",\"id\":\"${uuid_wss}\",\"net\":\"ws\",\"path\":\"/${wssPath}\",\"port\":\"443\",\"ps\":\"${v2_remark} (CDN)\",\"tls\":\"tls\",\"type\":\"none\",\"v\":\"2\"}"
    local uri_wss="$(printf %s "${json_wss}" | base64 --wrap=0)"
    write_json /usr/local/etc/v2script/config.json '.sub.nodesList.wss' "$(printf %s "\"vmess://${uri_wss}\"")"
  fi

  if [[ "$(read_json /usr/local/etc/v2script/config.json '.trojan.installed')" == "true" ]]; then
    local uuid_trojan="$(read_json /etc/trojan-go/config.json '.password[0]')"
    local uri_trojan="${uuid_trojan}@${TJ_DOMAIN}:443?peer=${TJ_DOMAIN}&sni=${TJ_DOMAIN}#$(urlEncode "${TJ_DOMAIN}")"
    write_json /usr/local/etc/v2script/config.json '.sub.nodesList.trojan' "$(printf %s "\"trojan://${uri_trojan}\"")"
  fi

  if [[ "$(read_json /usr/local/etc/v2script/config.json '.v2ray.installed')" == "true" ]] && [[ "$(read_json /usr/local/etc/v2script/config.json '.v2ray.cloudflare')" == "true" ]] && [[ "$(read_json /usr/local/etc/v2script/config.json '.trojan.installed')" == "true" ]]; then
    local sub="$(printf '%s\n%s\n%s' "vmess://${uri_tcp}" "vmess://${uri_wss}"  "trojan://${uri_trojan}" | base64 --wrap=0)"
    printf %s "${sub}" | ${sudoCmd} tee /var/www/html/$(read_json /usr/local/etc/v2script/config.json '.sub.uri') >/dev/null
  elif [[ "$(read_json /usr/local/etc/v2script/config.json '.v2ray.installed')" == "true" ]] && [[ "$(read_json /usr/local/etc/v2script/config.json '.v2ray.cloudflare')" == "true" ]]; then
    local sub="$(printf '%s\n%s' "vmess://${uri_tcp}" "vmess://${uri_wss}" | base64 --wrap=0)"
    printf %s "${sub}" | ${sudoCmd} tee /var/www/html/$(read_json /usr/local/etc/v2script/config.json '.sub.uri') >/dev/null
  elif [[ "$(read_json /usr/local/etc/v2script/config.json '.v2ray.installed')" == "true" ]] && [[ "$(read_json /usr/local/etc/v2script/config.json '.trojan.installed')" == "true" ]]; then
    local sub="$(printf '%s\n%s' "vmess://${uri_tcp}" "trojan://${uri_trojan}" | base64 --wrap=0)"
    printf %s "${sub}" | ${sudoCmd} tee /var/www/html/$(read_json /usr/local/etc/v2script/config.json '.sub.uri') >/dev/null
  elif [[ "$(read_json /usr/local/etc/v2script/config.json '.v2ray.installed')" == "true" ]]; then
    local sub="$(printf '%s' "vmess://${uri_tcp}" | base64 --wrap=0)"
    printf %s "${sub}" | ${sudoCmd} tee /var/www/html/$(read_json /usr/local/etc/v2script/config.json '.sub.uri') >/dev/null
  elif [[ "$(read_json /usr/local/etc/v2script/config.json '.trojan.installed')" == "true" ]]; then
    local sub="$(printf '%s' "trojan://${uri_trojan}" | base64 --wrap=0)"
    printf %s "${sub}" | ${sudoCmd} tee /var/www/html/$(read_json /usr/local/etc/v2script/config.json '.sub.uri') >/dev/null
  fi
}

generate_link() {
  if [[ $(read_json /usr/local/etc/v2script/config.json '.sub.enabled') != "true" ]]; then
    write_json /usr/local/etc/v2script/config.json '.sub.enabled' "true"
  fi

  if [[ "$(read_json /usr/local/etc/v2script/config.json '.sub.uri')" != "" ]]; then
    ${sudoCmd} rm -f /var/www/html/$(read_json /usr/local/etc/v2script/config.json '.sub.uri')
    write_json /usr/local/etc/v2script/config.json '.sub.uri' "\"\""
  fi

  local randomName="$(cat '/proc/sys/kernel/random/uuid' | sed -e 's/-//g' | tr '[:upper:]' '[:lower:]' | head -c 16)" #random file name for subscription
  write_json /usr/local/etc/v2script/config.json '.sub.uri' "\"${randomName}\""

  local V2_DOMAIN="$(read_json /usr/local/etc/v2script/config.json '.v2ray.tlsHeader')"
  local TJ_DOMAIN="$(read_json /usr/local/etc/v2script/config.json '.trojan.tlsHeader')"

  if [[ $(read_json /usr/local/etc/v2script/config.json '.v2ray.installed') == "true" ]]; then
    read -rp "输入 V2Ray 节点名称 [留空则使用默认值]: " v2_remark
    if [ -z "${v2_remark}" ]; then
      v2_remark="${V2_DOMAIN}"
    fi
  else
    v2_remark="null"
  fi

  if [[ $(read_json /usr/local/etc/v2script/config.json '.trojan.installed') == "true" ]]; then
    read -rp "输入 Trojan 节点名称 [留空则使用默认值]: " tj_remark
    if [ -z "${tj_remark}" ]; then
      tj_remark="${TJ_DOMAIN}"
    fi
  else
    tj_remark="null"
  fi

  sync_nodes "${v2_remark}" "${tj_remark}"
  colorEcho ${GREEN} "己生成订阅"
}

subscription_prompt() {
  if [[ $(read_json /usr/local/etc/v2script/config.json '.sub.enabled') != "true" ]]; then
    read -rp "生成订阅链接 (yes/no)? " linkConfirm
    case "${linkConfirm}" in
      y|Y|[yY][eE][sS] ) generate_link && display_link_main ;;
      * ) return 0 ;;
    esac
  else
    if [[ $(read_json /usr/local/etc/v2script/config.json '.v2ray.installed') == "true" ]]; then
      local v2_currentRemark="$(read_json /usr/local/etc/v2script/config.json '.sub.nodesList.tcp' | sed 's/^vmess:\/\///g' | base64 -d | jq --raw-output '.ps' | tr -d '\n')"
    else
      local v2_currentRemark="null"
    fi

    if [[ $(read_json /usr/local/etc/v2script/config.json '.trojan.installed') == "true" ]]; then
      local tj_currentRemark="$(read_json /usr/local/etc/v2script/config.json '.sub.nodesList.trojan' | sed 's/^trojan:\/\/.+#//g' | urlDecode)"
    else
      local tj_currentRemark="null"
    fi

    sync_nodes "${v2_currentRemark}" "${tj_currentRemark}"
  fi
}

get_proxy() {
  if [ ! -f "/usr/local/bin/tls-shunt-proxy" ]; then
    colorEcho ${BLUE} "tls-shunt-proxy is not installed. start installation"
    curl -sL https://raw.githubusercontent.com/liberal-boy/tls-shunt-proxy/master/dist/install.sh | ${sudoCmd} bash
    colorEcho ${GREEN} "tls-shunt-proxy is installed."
  else
    local API_URL="https://api.github.com/repos/liberal-boy/tls-shunt-proxy/releases/latest"
    #local DOWNLOAD_URL="$(curl -H "Accept: application/json" -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:74.0) Gecko/20100101 Firefox/74.0" -s "${API_URL}" --connect-timeout 10| grep 'browser_download_url' | cut -d\" -f4)"
    local DOWNLOAD_URL="https://github.com/liberal-boy/tls-shunt-proxy/releases/download/0.6.1/tls-shunt-proxy-linux-amd64.zip"
    ${sudoCmd} curl -L -H "Cache-Control: no-cache" -o "/tmp/tls-shunt-proxy.zip" "${DOWNLOAD_URL}"
    ${sudoCmd} unzip -o -d /usr/local/bin/ "/tmp/tls-shunt-proxy.zip"
    ${sudoCmd} chmod +x /usr/local/bin/tls-shunt-proxy
  fi
}

set_proxy() {
  ${sudoCmd} /bin/cp /etc/tls-shunt-proxy/config.yaml /etc/tls-shunt-proxy/config.yaml.bak 2>/dev/null
  wget -q https://raw.githubusercontent.com/phlinhng/v2ray-tcp-tls-web/${branch}/config/tls-shunt-proxy.yaml -O /tmp/config_new.yaml

  if [[ $(read_json /usr/local/etc/v2script/config.json '.v2ray.installed') == "true" ]]; then
    sed -i "s/FAKEV2DOMAIN/$(read_json /usr/local/etc/v2script/config.json '.v2ray.tlsHeader')/g" /tmp/config_new.yaml
    sed -i "s/##V2RAY@//g" /tmp/config_new.yaml
  fi

  if [[ $(read_json /usr/local/etc/v2script/config.json '.v2ray.cloudflare') == "true" ]]; then
    sed -i "s/FAKECDNPATH/$(read_json /usr/local/etc/v2ray/config.json '.inbounds[1].streamSettings.wsSettings.path' | tr -d '/')/g" /tmp/config_new.yaml
    sed -i "s/##CDN@//g" /tmp/config_new.yaml
  fi

  if [[ $(read_json /usr/local/etc/v2script/config.json '.trojan.installed') == "true" ]]; then
    sed -i "s/FAKETJDOMAIN/$(read_json /usr/local/etc/v2script/config.json '.trojan.tlsHeader')/g" /tmp/config_new.yaml
    sed -i "s/##TROJAN@//g" /tmp/config_new.yaml
  fi

  if [[ $(read_json /usr/local/etc/v2script/config.json '.sub.api.installed') == "true" ]]; then
    sed -i "s/FAKEAPIDOMAIN/$(read_json /usr/local/etc/v2script/config.json '.sub.api.tlsHeader')/g" /tmp/config_new.yaml
    sed -i "s/##SUBAPI@//g" /tmp/config_new.yaml
  fi

  if [[ $(read_json /usr/local/etc/v2script/config.json '.mtproto.installed') == "true" ]]; then
    sed -i "s/FAKEMTDOMAIN/$(read_json /usr/local/etc/v2script/config.json '.mtproto.fakeTlsHeader')/g" /tmp/config_new.yaml
    sed -i "s/##MTPROTO@//g" /tmp/config_new.yaml
  fi

  ${sudoCmd} /bin/cp -f /tmp/config_new.yaml /etc/tls-shunt-proxy/config.yaml
}

build_web() {
  if [ ! -f "/var/www/html/index.html" ]; then
    # choose and copy a random  template for dummy web pages
    local template="$(curl -s https://raw.githubusercontent.com/phlinhng/web-templates/master/list.txt | shuf -n  1)"
    wget -q https://raw.githubusercontent.com/phlinhng/web-templates/master/${template} -O /tmp/template.zip
    ${sudoCmd} mkdir -p /var/www/html
    ${sudoCmd} unzip -q /tmp/template.zip -d /var/www/html
    ${sudoCmd} wget -q https://raw.githubusercontent.com/phlinhng/v2ray-tcp-tls-web/${branch}/custom/robots.txt -O /var/www/html/robots.txt
  else
    echo "Dummy website existed. Skip building."
  fi
}

checkIP() {
  local realIP="$(curl -s `curl -s https://raw.githubusercontent.com/phlinhng/v2ray-tcp-tls-web/master/custom/ip_api`)"
  local resolvedIP="$(ping $1 -c 1 | head -n 1 | grep  -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)"

  if [[ "${realIP}" == "${resolvedIP}" ]]; then
    return 0
  else
    return 1
  fi
}

set_v2ray_wss() {
  if [[ $(read_json /usr/local/etc/v2script/config.json '.v2ray.cloudflare') != "true" ]]; then
    local uuid_wss="$(cat '/proc/sys/kernel/random/uuid')"
    local wssPath="$(cat '/proc/sys/kernel/random/uuid' | sed -e 's/-//g' | tr '[:upper:]' '[:lower:]' | head -c 12)"
    local sni="$(read_json /usr/local/etc/v2script/config.json '.v2ray.tlsHeader')"
    local wssInbound="{\"protocol\": \"vmess\",
  \"port\": 3566,
  \"settings\": {
    \"clients\": [{
      \"id\": \"${uuid_wss}\",
      \"alterId\": 2
      }]
    },
  \"streamSettings\": {
      \"network\": \"ws\",
      \"wsSettings\": {
        \"path\": \"/${wssPath}\"
      }
    },
    \"sniffing\": {
      \"enabled\": true,
      \"destOverride\": [ \"http\", \"tls\" ]
    }
  }"

    # setting v2ray
    ${sudoCmd} /bin/cp /usr/local/etc/v2ray/config.json /usr/local/etc/v2ray/config.json.bak 2>/dev/null
    jq -r ".inbounds += [${wssInbound}]" /usr/local/etc/v2ray/config.json  > tmp.$$.json && ${sudoCmd} mv tmp.$$.json /usr/local/etc/v2ray/config.json
    write_json /usr/local/etc/v2script/config.json '.v2ray.cloudflare' "true"

    set_proxy

    ${sudoCmd} systemctl restart v2ray 2>/dev/null
    ${sudoCmd} systemctl restart tls-shunt-proxy 2>/dev/null
    ${sudoCmd} systemctl daemon-reload

    colorEcho ${GREEN} "设置CDN成功!"
    #local cfUrl="www.digitalocean.com"
    local cfUrl="amp.cloudflare.com"
    local uuid_wss="$(read_json /usr/local/etc/v2ray/config.json '.inbounds[1].settings.clients[0].id')"
    local currentRemark="$(read_json /usr/local/etc/v2script/config.json '.sub.nodesList.tcp' | sed 's/^vmess:\/\///g' | base64 -d | jq --raw-output '.ps' | tr -d '\n')"
    local json_wss="{\"add\":\"${cfUrl}\",\"aid\":\"1\",\"host\":\"${sni}\",\"id\":\"${uuid_wss}\",\"net\":\"ws\",\"path\":\"/${wssPath}\",\"port\":\"443\",\"ps\":\"${currentRemark} (CDN)\",\"tls\":\"tls\",\"type\":\"none\",\"v\":\"2\"}"
    local uri_wss="$(printf %s "${json_wss}" | base64 --wrap=0)"

    echo "${cfUrl}:443"
    echo "${uuid_wss} (aid: 1)"
    echo "Header: ${sni}, Path: /${wssPath}" && echo ""
    echo "vmess://${uri_wss}" | tr -d '\n' && printf "\n"
    write_json /usr/local/etc/v2script/config.json '.sub.nodesList.wss' "$(printf %s "\"vmess://${uri_wss}\"" | tr -d '\n')"

    subscription_prompt
  else
    display_vmess
  fi
}

get_trojan() {
  if [ ! -d "/usr/bin/trojan-go" ]; then
    colorEcho ${BLUE} "trojan-go is not installed. start installation"

    colorEcho ${BLUE} "Getting the latest version of trojan-go"
    #local latest_version="$(curl -s "https://api.github.com/repos/jabberwocky238/trojan-go/releases" | jq '.[0].tag_name' --raw-output)"
    latest_version="v20250924_033135"
    echo "${latest_version}"
    local trojango_link="https://github.com/jabberwocky238/trojan-go/releases/download/${latest_version}/trojan-go-linux-amd64.zip"

    ${sudoCmd} mkdir -p "/etc/trojan-go"
    #${sudoCmd} mkdir -p "/etc/ssl/trojan--go"

    cd $(mktemp -d)
    wget -nv "${trojango_link}" -O trojan-go.zip
    unzip -q trojan-go.zip && rm -rf trojan-go.zip
    ${sudoCmd} mv trojan-go /usr/bin/trojan-go
    write_json /usr/local/etc/v2script/config.json ".trojan.installed" "true"

    colorEcho ${BLUE} "Building trojan-go.service"
    ${sudoCmd} mv example/trojan-go.service /etc/systemd/system/trojan-go.service

    ${sudoCmd} wget -q https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip.dat -O /usr/bin/geoip.dat
    ${sudoCmd} wget -q https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat -O /usr/bin/geosite.dat

    # set crontab to auto update geoip.dat and geosite.dat
    (crontab -l 2>/dev/null; echo "0 7 * * * wget -q https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip.dat -O /usr/bin/geoip.dat >/dev/null >/dev/null") | ${sudoCmd} crontab -
    (crontab -l 2>/dev/null; echo "0 7 * * * wget -q https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat -O /usr/bin/geosite.dat >/dev/null >/dev/null") | ${sudoCmd} crontab -

    colorEcho ${GREEN} "trojan-go is installed."
  else
    colorEcho ${BLUE} "Getting the latest version of trojan-go"
    local latest_version="$(curl -s "https://api.github.com/repos/jabberwocky238/trojan-go/releases" | jq '.[0].tag_name' --raw-output)"
    echo "${latest_version}"
    local trojango_link="https://github.com/jabberwocky238/trojan-go/releases/download/${latest_version}/trojan-go-linux-amd64.zip"

    cd $(mktemp -d)
    wget -nv "${trojango_link}" -O trojan-go.zip
    unzip trojan-go.zip
    ${sudoCmd} mv trojan-go /usr/bin/trojan-go

    # migrate from v0.6.0 to v0.7+
    if [ -d "/usr/bin/trojan-go" ];then
      ${sudoCmd} mv /usr/bin/trojan-go/geoip.dat /usr/bin/geoip.dat
      ${sudoCmd} mv /usr/bin/trojan-go/geosite.dat /usr/bin/geosite.dat
      ${sudoCmd} rm -rf /usr/bin/trojan-go

      ${sudoCmd} crontab -l | grep -v 'trojan-go/geoip.dat' | ${sudoCmd} crontab -
      ${sudoCmd} crontab -l | grep -v 'trojan-go/geosite.dat' | ${sudoCmd} crontab -

      (crontab -l 2>/dev/null; echo "0 7 * * * wget -q https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip.dat -O /usr/bin/geoip.dat >/dev/null >/dev/null") | ${sudoCmd} crontab -
      (crontab -l 2>/dev/null; echo "0 7 * * * wget -q https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat -O /usr/bin/geosite.dat >/dev/null >/dev/null") | ${sudoCmd} crontab -

      ${sudoCmd} mv example/trojan-go.service /etc/systemd/system/trojan-go.service
      ${sudoCmd} systemctl daemon-reload
      ${sudoCmd} systemctl enable trojan-go
      ${sudoCmd} systemctl restart trojan-go
    fi
  fi
}


get_hysteria2() {
  if [ ! -f "/usr/local/bin/hysteria2" ]; then
    colorEcho ${BLUE} "hysteria2 is not installed. start installation"
    ${sudoCmd} curl -fsSL https://download.hysteria.network/app/latest/hysteria-linux-amd64 -o /usr/local/bin/hysteria2
    ${sudoCmd} chmod +x /usr/local/bin/hysteria2
    wget -q https://raw.githubusercontent.com/jabberwocky238/v2ray-tcp-tls-web/${branch}/config/hysteria2.service -O /etc/systemd/system/hysteria2.service
    wget -q https://raw.githubusercontent.com/jabberwocky238/v2ray-tcp-tls-web/${branch}/config/hysteria2.yml -O /etc/hysteria2/config.yml
  else
    colorEcho ${BLUE} "Getting the latest version of hysteria2"
    ${sudoCmd} curl -fsSL https://download.hysteria.network/app/latest/hysteria-linux-amd64 -o /usr/local/bin/hysteria2
    ${sudoCmd} chmod +x /usr/local/bin/hysteria2
  fi
}

install_trojan() {
  while true; do
    read -rp "解析到本 VPS 的域名: " TJ_DOMAIN
    if [[ $(read_json /usr/local/etc/v2script/config.json '.v2ray.tlsHeader') == "${TJ_DOMAIN}" ]] || [[ $(read_json /usr/local/etc/v2script/config.json '.sub.api.tlsHeader') == "${TJ_DOMAIN}" ]]; then
      colorEcho ${RED} "域名 ${TJ_DOMAIN} 与现有域名重复,  请使用别的域名"
    elif checkIP "${TJ_DOMAIN}"; then
      colorEcho ${GREEN} "域名 ${TJ_DOMAIN} 解析正确, 即将开始安装"
      break
    else
      colorEcho ${RED} "域名 ${TJ_DOMAIN} 解析有误 (yes: 强制继续, no: 重新输入, quit: 离开)"
      read -rp "若您确定域名解析正确, 可以继续进行安装作业. 强制继续? (yes/no/quit) " forceConfirm
      case "${forceConfirm}" in
        [yY]|[yY][eE][sS] ) break ;;
        [qQ]|[qQ][uU][iI][tT] ) return 0 ;;
      esac
    fi
  done
  write_json /usr/local/etc/v2script/config.json ".trojan.tlsHeader" "\"${TJ_DOMAIN}\""

  get_trojan
  get_hysteria2

    # 如果存在 hysteria.yml 配置文件，替换域名
  if [ -f "/etc/hysteria2/config.yml" ]; then
    ${sudoCmd} sed -i "s/DOMAINNAME/${TJ_DOMAIN}/g" /etc/hysteria2/config.yml
  fi

  # create config files
  if [ ! -f "/etc/trojan-go/config.json" ]; then
    colorEcho ${BLUE} "Setting trojan-go"
    wget -q https://raw.githubusercontent.com/jabberwocky238/v2ray-tcp-tls-web/${branch}/config/trojan-go_plain.json -O /tmp/trojan-go.json
    sed -i "s/FAKETROJANPWD/$(cat '/proc/sys/kernel/random/uuid' | sed -e 's/-//g' | tr '[:upper:]' '[:lower:]' | head -c 12)/g" /tmp/trojan-go.json
    ${sudoCmd} /bin/cp -f /tmp/trojan-go.json /etc/trojan-go/config.json
  fi

#   

  get_proxy

  colorEcho ${BLUE} "Setting tls-shunt-proxy"
  set_proxy

  colorEcho ${BLUE} "Building dummy web site"
  build_web

  # activate services
  colorEcho ${BLUE} "Activating services"
  ${sudoCmd} systemctl enable trojan-go
  ${sudoCmd} systemctl restart trojan-go 2>/dev/null ## restart trojan-go to enable new config
  ${sudoCmd} systemctl enable tls-shunt-proxy
  ${sudoCmd} systemctl restart tls-shunt-proxy ## restart tls-shunt-proxy to enable new config
  #${sudoCmd} systemctl enable caddy
  #${sudoCmd} systemctl restart caddy
  ${sudoCmd} systemctl daemon-reload
  ${sudoCmd} systemctl reset-failed

  colorEcho ${GREEN} "安装 trojan-go 成功!"

  local uuid_trojan="$(read_json /etc/trojan-go/config.json '.password[0]')"
  local uri_trojan="${uuid_trojan}@${TJ_DOMAIN}:443?peer=${TJ_DOMAIN}&sni=${TJ_DOMAIN}#$(urlEncode "${TJ_DOMAIN}")"
  write_json /usr/local/etc/v2script/config.json '.sub.nodesList.trojan' "$(printf %s "\"trojan://${uri_trojan}\"")"

  printf '%s\n\n' "trojan://${uri_trojan}"

  subscription_prompt
}

install_trojan