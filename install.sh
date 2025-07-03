#!/usr/bin/env bash
# Detection area
# -------------------------------------------------------------
# Check system
export LANG=en_US.UTF-8

echoContent() {
case $1 in
# Red
"red")
# shellcheck disable=SC2154
${echoType} "\033[31m${printN}$2 \033[0m"
;;
# Sky blue
"skyBlue")
${echoType} "\033[1;36m${printN}$2 \033[0m"
;;
# Green
"green")
${echoType} "\033[32m${printN}$2 \033[0m"
;;
# White
"white")
${echoType} "\033[37m${printN}$2 \033[0m"
;;
"magenta")
${echoType} "\033[31m${printN}$2 \033[0m"
;;
# Yellow
"yellow")
${echoType} "\033[33m${printN}$2 \033[0m"
;;
esac
}
# Check SELinux status
checkCentosSELinux() {
if [[ -f "/etc/selinux/config" ]] && ! grep -q "SELINUX=disabled" <"/etc/selinux/config"; then
echoContent yellow "# Notes"
echoContent yellow "SELinux is detected to be enabled, please disable it manually, the tutorial is as follows"
echoContent yellow "https://www.v2ray-agent.com/archives/1684115970026#centos7-%E5%85%B3%E9%97%ADselinux"
        exit 0
    fi
}
checkSystem() {
    if [[ -n $(find /etc -name "redhat-release") ]] || grep </proc/version -q -i "centos"; then
        mkdir -p /etc/yum.repos.d

        if [[ -f "/etc/centos-release" ]]; then
            centosVersion=$(rpm -q centos-release | awk -F "[-]" '{print $3}' | awk -F "[.]" '{print $1}')

            if [[ -z "${centosVersion}" ]] && grep </etc/centos-release -q -i "release 8"; then
                centosVersion=8
            fi
        fi

        release="centos"
        installType='yum -y install'
        removeType='yum -y remove'
        upgrade="yum update -y --skip-broken"
        checkCentosSELinux
    elif { [[ -f "/etc/issue" ]] && grep -qi "Alpine" /etc/issue; } || { [[ -f "/proc/version" ]] && grep -qi "Alpine" /proc/version; }; then
        release="alpine"
        installType='apk add'
        upgrade="apk update"
        removeType='apk del'
        nginxConfigPath=/etc/nginx/http.d/
    elif { [[ -f "/etc/issue" ]] && grep -qi "debian" /etc/issue; } || { [[ -f "/proc/version" ]] && grep -qi "debian" /proc/version; } || { [[ -f "/etc/os-release" ]] && grep -qi "ID=debian" /etc/issue; }; then
        release="debian"
        installType='apt -y install'
        upgrade="apt update"
        updateReleaseInfoChange='apt-get --allow-releaseinfo-change update'
        removeType='apt -y autoremove'

    elif { [[ -f "/etc/issue" ]] && grep -qi "ubuntu" /etc/issue; } || { [[ -f "/proc/version" ]] && grep -qi "ubuntu" /proc/version; }; then
        release="ubuntu"
        installType='apt -y install'
        upgrade="apt update"
        updateReleaseInfoChange='apt-get --allow-releaseinfo-change update'
        removeType='apt -y autoremove'
        if grep </etc/issue -q -i "16."; then
release=
fi
fi

if [[ -z ${release} ]]; then
echoContent red "\nThis script does not support this system, please feedback the following log to the developer\n"
echoContent yellow "$(cat /etc/issue)"
echoContent yellow "$(cat /proc/version)"
exit 0
fi
}

# Check CPU provider
checkCPUVendor() {
if [[ -n $(which uname) ]]; then
if [[ "$(uname)" == "Linux" ]]; then
case "$(uname -m)" in
'amd64' | 'x86_64')
xrayCoreCPUVendor="Xray-linux-64"
v2rayCoreCPUVendor="v2ray-linux-64"
warpRegCoreCPUVendor="main-linux-amd64"
singBoxCoreCPUVendor="-linux-amd64"
;;
'armv8' | 'aarch64')
cpuVendor="arm"
xrayCoreCPUVendor="Xray-linux-arm64-v8a"
v2rayCoreCPUVendor="v2ray-linux-arm64-v8a"
warpRegCoreCPUVendor="main-linux-arm64"
singBoxCoreCPUVendor="-linux-arm64"
;;
*)
echo "This CPU architecture is not supported--->"
exit 1
;;
esac
fi
else
echoContent red "This CPU architecture cannot be recognized, default amd64, x86_64--->"

        xrayCoreCPUVendor="Xray-linux-64"
v2rayCoreCPUVendor="v2ray-linux-64"
fi
}

# Initialize global variables
initVar() {
installType='yum -y install'
removeType='yum -y remove'
upgrade="yum -y update"
echoType='echo -e'

# CPU version supported by the core
xrayCoreCPUVendor=""
v2rayCoreCPUVendor=""
# hysteriaCoreCPUVendor=""
warpRegCoreCPUVendor=""
cpuVendor=""

# Domain name
domain=
# Total installation progress
totalProgress=1

# 1.xray-core installation
# 2.v2ray-core installation
# 3.v2ray-core[xtls] installation
coreInstallType=

# Core installation path
# coreInstallPath=

# v2ctl Path
ctlPath=
# 1. Install all
# 2. Personalized installation
# v2rayAgentInstallType=
# Current personalized installation method 01234
currentInstallProtocolType=
# Current alpn order
currentAlpn=
# Front type
frontingType=
# Selected personalized installation method
selectCustomInstallType=
# v2ray-core, xray-core configuration file path
configPath=
# xray-core reality status
realityStatus=
# sing-box configuration file path
singBoxConfigPath=
# sing-box port
singBoxVLESSVisionPort=
singBoxVLESSRealityVisionPort=
singBoxVLESSRealityGRPCPort=
singBoxHysteria2Port=
singBoxTrojanPort=
singBoxTuicPort=
singBoxNaivePort=
singBoxVMessWSPort=
singBoxVLESSWSPort=
    singBoxVMessHTTPUpgradePort=

    # nginx subscription port
    subscribePort=

    subscribeType=

    # sing-box reality serverName publicKey
    singBoxVLESSRealityGRPCServerName=
    singBoxVLESSRealityVisionServerName=
    singBoxVLESSRealityPublicKey=

    #xray-core reality serverName publicKey
    xrayVLESSRealityServerName=
    xrayVLESSRealityPort=
    xrayVLESSRealityXHTTPServerName=
    xrayVLESSRealityXHTTPort=
    #xrayVLESSRealityPublicKey=

    # interfaceName=
    # Port hopping
    portHoppingStart=
    portHoppingEnd=
    portHopping=

    hysteria2PortHoppingStart=
    hysteria2PortHoppingEnd=
    hysteria2PortHopping=

    # tuicPortHoppingStart=
    # tuicPortHoppingEnd=
    #tuicPortHopping= # tuic configuration file path
tuicConfigPath=
tuicAlgorithm=
tuicPort=

# Configuration file path
currentPath=

# Configuration file host
currentHost=

# Core type selected during installation
selectCoreType=

# Default core version
v2rayCoreVersion=

# Random path
customPath=

# centos version
centosVersion=

# UUID
currentUUID=

# clients
currentClients=

# previousClients
previousClients=

localIP=

# Scheduled task execution task name RenewTLS-Update certificate UpdateGeo-Update geo file
cronName=$1

# Number of attempts after tls installation failed
installTLSCount=

# BTPanel status
# BTPanelStatus=
# Pagoda domain name
btDomain=
# nginx configuration file path
nginxConfigPath=/etc/nginx/conf.d/
nginxStaticPath=/usr/share/nginx/html/

# Is it a preview version?
prereleaseStatus=false

# ssl type
sslType=
# SSL CF API Token
cfAPIToken=

# ssl mailbox
sslEmail=

# Check days
sslRenewalDays=90

# dns ssl status
# dnsSSLStatus=

# dns tls domain
dnsTLSDomain=
ipType=

# Whether the domain name is installed with a wildcard certificate through dns
# installDNSACMEStatus=

# Custom port
customPort=

# hysteria port
hysteriaPort=

# hysteria protocol
hysteriaProtocol=

# hysteria delay
# hysteriaLag=

# hysteria downlink speed
hysteria2ClientDownloadSpeed=

# hysteria uplink speed
hysteria2ClientUploadSpeed=

# Reality
realityPrivateKey=
realityServerName=
realityDestDomain=

# Port status
# isPortOpen=
# Wildcard domain name status
# wildcardDomainStatus=
# Port checked by nginx
# nginxIPort=

# wget show progress
wgetShowProgressStatus=

# warp
reservedWarpReg=
publicKeyWarpReg=
addressWarpReg=
secretKeyWarpReg=

# Last installation configuration status
lastInstallationConfig=

}

# Read tls certificate details
readAcmeTLS() {
local readAcmeDomain=
if [[ -n "${currentHost}" ]]; then
readAcmeDomain="${currentHost}"
fi

if [[ -n "${domain}" ]]; then
        readAcmeDomain="${domain}"
    fi

    dnsTLSDomain=$(echo "${readAcmeDomain}" | awk -F "." '{$1="";print $0}' | sed 's/^[[:space:]]*//' | sed 's/ /./g')

    if [[ -d "$HOME/.acme.sh/*.${dnsTLSDomain}_ecc" && -f "$HOME/.acme.sh/*.${dnsTLSDomain}_ecc/*.${dnsTLSDomain}.key" && -f "$HOME/.acme.sh/*.${dnsTLSDomain}_ecc/*.${dnsTLSDomain}.cer" ]]; then
        installedDNSAPIStatus=true
    and
} }

# Take the snowflake switch
readCustomPort() {
    if [[ -n "${configPath}" && -z "${realityStatus}" && "${coreInstallType}" == "1" ]]; then
        local port=
        port=$(jq -r .inbounds[0].port "${configPath}${frontingType}.json")
        if [[ "${port}" != "443" ]]; then
            customPort=${port}
        and
    and
} }

# Install the nginx application
readNginxSubscribe() {
    subscribeType="https"
    if [[ -f "${nginxConfigPath}subscribe.conf" ]]; then
        if grep -q "sing-box" "${nginxConfigPath}subscribe.conf"; then
            subscribePort=$(grep "list" "${nginxConfigPath}subscribe.conf" |
            subscribeDomain=$(grep "server_name" "${nginxConfigPath}subscribe.conf" |
            subscribeDomain=${subscribeDomain//;/}
            if [[ -n "${currentHost}" && "${subscribeDomain}" != "${currentHost}" ]]; then
                subscribePort=
                subscribeType=
            else
                if ! grep "list" "${nginxConfigPath}subscribe.conf" | grep -q "ssl"; then
                    subscribeType="http"
                and
            and

        and
    and
} }

# Renewable license plate
readInstallType() {
    coreInstallType =
    configPath=
    singBoxConfigPath =

    # 1.Frequently installed
    if [[ -d "/etc/v2ray-agent" ]]; then
        if [[ -f "/etc/v2ray-agent/xray/xray" ]]; then
            # New xray-core
            if [[ -d "/etc/v2ray-agent/xray/conf" ]] && [[ -f "/etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json" || -f "/etc/v2ray-agent/xray/conf/02_trojan_TCP_inbounds.json" || -f "/etc/v2ray-agent/xray/conf/07_VLESS_vision_reality_inbounds.json" ]]; then
                # xray-core
                configPath=/etc/v2ray-agent/xray/conf/
                ctlPath = / etc / v2ray - agent / xray / xray
                coreInstallType=1
                if [[ -f "${configPath}07_VLESS_vision_reality_inbounds.json" ]]; then
                    realityStatus=1
                and
                if [[ -f "/etc/v2ray-agent/sing-box/sing-box" ]] && [[ -f "/etc/v2ray-agent/sing-box/conf/config/06_hysteria2_inbounds.json" || -f "/etc/v2ray-agent/sing-box/conf/config/09_tuic_inbounds.json" || -f "/etc/v2ray-agent/sing-box/conf/config/20_socks5_inbounds.json" ]]; then
                    singBoxConfigPath=/etc/v2ray-agent/sing-box/conf/config/
                and
            and
        elif [[ -f "/etc/v2ray-agent/sing-box/sing-box" && -f "/etc/v2ray-agent/sing-box/conf/config.json" ]]; then
            # Remove singing-box
            ctlPath = / etc / v2ray - agent / sing - box / sing - box
            coreInstallType=2
            configPath=/etc/v2ray-agent/sing-box/conf/config/
            singBoxConfigPath=/etc/v2ray-agent/sing-box/conf/config/
        and
    and
} }

# Encouragement
readInstallProtocolType() {
    currentInstallProtocolType=
    frontingType=

    xrayVLESSRealityPort=
    xrayVLESSRealityServerName=

    xrayVLESSRealityXHTTPort=
    xrayVLESSRealityXHTTPServerName=

    # currentRealityXHTTPPrivateKey=
    currentRealityXHTTPPublicKey=

    currentRealityPrivateKey=
    currentRealityPublicKey=

    singBoxVLESSViewPort=
    singBoxHysteria2Port=
    singBoxTrojanPort=

    frontingRealityType=
    singBoxVLESSRealityViewPort=
    singBoxVLESSRealityVisionServerName=
    singBoxVLESSRealityGRPCPort=
    singBoxVLESSRealityGRPCServerName=
    singBoxTuicPort=
    singBoxNaivePort=
    singBoxVMessWSPort=
    singBoxSocks5Port=

    while read - r row ; do
        if echo "${row}" | grep -q VLESS_TCP_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}0,"
            frontingType=02_VLESS_TCP_inbounds
            if [[ "${coreInstallType}" == "2" ]]; then
                singBoxVLESSViewPort=$(jq .inbounds[0].list_port "${row}.json");
            and
        and

        if echo "${row}" | grep -q VLESS_WS_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}1,"
            if [[ "${coreInstallType}" == "2" ]]; then
                frontingType=03_VLESS_WS_inbounds
                singBoxVLESSWSPort=$(jq .inbounds[0].listen_port "${row}.json")
            fi
        fi
        if echo "${row}" | grep -q VLESS_XHTTP_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}12,"
            xrayVLESSRealityXHTTPort=$(jq -r .inbounds[0].port "${row}.json")

            xrayVLESSRealityXHTTPServerName=$(jq -r .inbounds[0].streamSettings.realitySettings.serverNames[0] "${row}.json")

            currentRealityXHTTPPublicKey=$(jq -r .inbounds[0].streamSettings.realitySettings.publicKey "${row}.json")
            #            currentRealityXHTTPPrivateKey=$(jq -r .inbounds[0].streamSettings.realitySettings.privateKey "${row}.json")

            #            if [[ "${coreInstallType}" == "2" ]]; then
            #                frontingType=03_VLESS_WS_inbounds
            #                singBoxVLESSWSPort=$(jq .inbounds[0].listen_port "${row}.json")
            #            fi
        fi

        if echo "${row}" | grep -q trojan_gRPC_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}2,"
        fi
        if echo "${row}" | grep -q VMess_WS_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}3,"
            if [[ "${coreInstallType}" == "2" ]]; then
                frontingType=05_VMess_WS_inbounds
                singBoxVMessWSPort=$(jq .inbounds[0].listen_port "${row}.json")
            fi
        fi
        if echo "${row}" | grep -q trojan_TCP_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}4,"
            if [[ "${coreInstallType}" == "2" ]]; then
                frontingType=04_trojan_TCP_inbounds
                singBoxTrojanPort=$(jq .inbounds[0].listen_port "${row}.json")
            fi
        fi
        if echo "${row}" | grep -q VLESS_gRPC_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}5,"
        fi
        if echo "${row}" | grep -q hysteria2_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}6,"
            if [[ "${coreInstallType}" == "2" ]]; then
                frontingType=06_hysteria2_inbounds
                singBoxHysteria2Port=$(jq .inbounds[0].listen_port "${row}.json")
            fi
        fi
        if echo "${row}" | grep -q VLESS_vision_reality_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}7,"
            if [[ "${coreInstallType}" == "1" ]]; then
                xrayVLESSRealityServerName=$(jq -r .inbounds[0].streamSettings.realitySettings.serverNames[0] "${row}.json")
                realityServerName=${xrayVLESSRealityServerName}
                xrayVLESSRealityPort=$(jq -r .inbounds[0].port "${row}.json")

                realityDomainPort=$(jq -r .inbounds[0].streamSettings.realitySettings.dest "${row}.json" | awk -F '[:]' '{print $2}')

                currentRealityPublicKey=$(jq -r .inbounds[0].streamSettings.realitySettings.publicKey "${row}.json")
                currentRealityPrivateKey=$(jq -r .inbounds[0].streamSettings.realitySettings.privateKey "${row}.json")
                frontingTypeReality=07_VLESS_vision_reality_inbounds

            elif [[ "${coreInstallType}" == "2" ]]; then
                frontingTypeReality=07_VLESS_vision_reality_inbounds
                singBoxVLESSRealityVisionPort=$(jq -r .inbounds[0].listen_port "${row}.json")
                singBoxVLESSRealityVisionServerName=$(jq -r .inbounds[0].tls.server_name "${row}.json")
                realityDomainPort=$(jq -r .inbounds[0].tls.reality.handshake.server_port "${row}.json")

                realityServerName=${singBoxVLESSRealityVisionServerName}
                if [[ -f "${configPath}reality_key" ]]; then

                    singBoxVLESSRealityPublicKey=$(grep "publicKey" <"${configPath}reality_key" | awk -F "[:]" '{print $2}')

                    currentRealityPrivateKey=$(jq -r .inbounds[0].tls.reality.private_key "${row}.json")
                    currentRealityPublicKey=$(grep "publicKey" <"${configPath}reality_key" | awk -F "[:]" '{print $2}')
                fi
            fi
        fi
        if echo "${row}" | grep -q VLESS_vision_gRPC_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}8,"
            if [[ "${coreInstallType}" == "2" ]]; then
                frontingTypeReality=08_VLESS_vision_gRPC_inbounds
                singBoxVLESSRealityGRPCPort=$(jq -r .inbounds[0].listen_port "${row}.json")
                singBoxVLESSRealityGRPCServerName=$(jq -r .inbounds[0].tls.server_name "${row}.json")
                if [[ -f "${configPath}reality_key" ]]; then
                    singBoxVLESSRealityPublicKey=$(grep "publicKey" <"${configPath}reality_key" | awk -F "[:]" '{print $2}')
                fi
            fi
        fi
        if echo "${row}" | grep -q tuic_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}9,"
            if [[ "${coreInstallType}" == "2" ]]; then
                frontingType=09_tuic_inbounds
                singBoxTuicPort=$(jq .inbounds[0].listen_port "${row}.json")
            fi
        fi
        if echo "${row}" | grep -q naive_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}10,"
            if [[ "${coreInstallType}" == "2" ]]; then
                frontingType=10_naive_inbounds
                singBoxNaivePort=$(jq .inbounds[0].listen_port "${row}.json")
            fi
        fi
        if echo "${row}" | grep -q VMess_HTTPUpgrade_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}11,"
            if [[ "${coreInstallType}" == "2" ]]; then
                frontingType=11_VMess_HTTPUpgrade_inbounds
                singBoxVMessHTTPUpgradePort=$(grep 'listen' <${nginxConfigPath}sing_box_VMess_HTTPUpgrade.conf | awk '{print $2}')
            fi
        fi
        if echo "${row}" | grep -q socks5_inbounds; then
            currentInstallProtocolType="${currentInstallProtocolType}20,"
            singBoxSocks5Port=$(jq .inbounds[0].listen_port "${row}.json")
        fi

    done < <(find ${configPath} -name "*inbounds.json" | sort | awk -F "[.]" '{print $1}')

    if [[ "${coreInstallType}" == "1" && -n "${singBoxConfigPath}" ]]; then
        if [[ -f "${singBoxConfigPath}06_hysteria2_inbounds.json" ]]; then
            currentInstallProtocolType="${currentInstallProtocolType}6,"
            singBoxHysteria2Port=$(jq .inbounds[0].listen_port "${singBoxConfigPath}06_hysteria2_inbounds.json")
        fi
        if [[ -f "${singBoxConfigPath}09_tuic_inbounds.json" ]]; then
            currentInstallProtocolType="${currentInstallProtocolType}9,"
            singBoxTuicPort=$(jq .inbounds[0].listen_port "${singBoxConfigPath}09_tuic_inbounds.json")
        fi
    fi
    if [[ "${currentInstallProtocolType:0:1}" != "," ]]; then
        currentInstallProtocolType=",${currentInstallProtocolType}"
    fi
}

# 检查是否安装宝塔
checkBTPanel() {
    if [[ -n $(pgrep -f "BT-Panel") ]]; then
        # 读取域名
        if [[ -d '/www/server/panel/vhost/cert/' && -n $(find /www/server/panel/vhost/cert/*/fullchain.pem) ]]; then
            if [[ -z "${currentHost}" ]]; then
                echoContent skyBlue "\n读取宝塔配置\n"

                find /www/server/panel/vhost/cert/*/fullchain.pem | awk -F "[/]" '{print $7}' | awk '{print NR""":"$0}'

                read -r -p "请输入编号选择:" selectBTDomain
            else
                selectBTDomain=$(find /www/server/panel/vhost/cert/*/fullchain.pem | awk -F "[/]" '{print $7}' | awk '{print NR""":"$0}' | grep "${currentHost}" | cut -d ":" -f 1)
            fi

            if [[ -n "${selectBTDomain}" ]]; then

btDomain=$(find /www/server/panel/vhost/cert/*/fullchain.pem | awk -F "[/]" '{print $7}' | awk '{print NR""":"$0}' | grep -e "^${selectBTDomain}:" | cut -d ":" -f 2)

if [[ -z "${btDomain}" ]]; then
echoContent red " ---> Wrong selection, please reselect"
checkBTPanel
else
domain=${btDomain}
if [[ ! -f "/etc/v2ray-agent/tls/${btDomain}.crt" && ! -f "/etc/v2ray-agent/tls/${btDomain}.key" ]]; then
ln -s "/www/server/panel/vhost/cert/${btDomain}/fullchain.pem" "/etc/v2ray-agent/tls/${btDomain}.crt"
                        ln -s "/www/server/panel/vhost/cert/${btDomain}/privkey.pem" "/etc/v2ray-agent/tls/${btDomain}.key"
                    fi

                    nginxStaticPath="/www/wwwroot/${btDomain}/html/"

                    mkdir -p "/www/wwwroot/${btDomain}/html/"

                    if [[ -f "/www/wwwroot/${btDomain}/.user.ini" ]]; then
                        chattr -i "/www/wwwroot/${btDomain}/.user.ini"
                    fi nginxConfigPath="/www/server/panel/vhost/nginx/"
fi
else
echoContent red " ---> Wrong selection, please reselect"
checkBTPanel
fi
fi
fi
}
check1Panel() {
if [[ -n $(pgrep -f "1panel") ]]; then
# Read domain name
if [[ -d '/opt/1panel/apps/openresty/openresty/www/sites/' && -n $(find /opt/1panel/apps/openresty/openresty/www/sites/*/ssl/fullchain.pem) ]]; then
if [[ -z "${currentHost}" ]]; then
echoContent skyBlue "\nRead 1Panel configuration\n"

find /opt/1panel/apps/openresty/openresty/www/sites/*/ssl/fullchain.pem | awk -F "[/]" '{print $9}' | awk '{print NR""":"$0}'

read -r -p "Please enter the number to select:" selectBTDomain
else
selectBTDomain=$(find /opt/1panel/apps/openresty/openresty/www/sites/*/ssl/fullchain.pem | awk -F "[/]" '{print $9}' | awk '{print NR""":"$0}' | grep "${currentHost}" | cut -d ":" -f 1)
fi

if [[ -n "${selectBTDomain}" ]]; then
btDomain=$(find /opt/1panel/apps/openresty/openresty/www/sites/*/ssl/fullchain.pem | awk -F "[/]" '{print $9}' | awk '{print NR""":"$0}' | grep "${selectBTDomain}:" | cut -d ":" -f 2)

if [[ -z "${btDomain}" ]]; then
echoContent red " ---> Wrong selection, please reselect"
check1Panel
else
domain=${btDomain}
if [[ ! -f "/etc/v2ray-agent/tls/${btDomain}.crt" && ! -f "/etc/v2ray-agent/tls/${btDomain}.key" ]]; then
ln -s "/opt/1panel/apps/openresty/openresty/www/sites/${btDomain}/ssl/fullchain.pem" "/etc/v2ray-agent/tls/${btDomain}.crt"
ln -s "/opt/1panel/apps/openresty/openresty/www/sites/${btDomain}/ssl/privkey.pem" "/etc/v2ray-agent/tls/${btDomain}.key"
fi

nginxStaticPath="/opt/1panel/apps/openresty/openresty/www/sites/${btDomain}/index/"
fi
else
echoContent red " ---> Wrong selection, please reselect"
check1Panel
fi
fi
fi
}
# Read the current alpn order
readInstallAlpn() {
if [[ -n "${currentInstallProtocolType}" && -z "${realityStatus}" ]]; then
local alpn
alpn=$(jq -r .inbounds[0].streamSettings.tlsSettings.alpn[0] ${configPath}${frontingType}.json)
if [[ -n ${alpn} ]]; then
currentAlpn=${alpn}
fi
fi
}

# Check firewall
allowPort() {
local type=$2
if [[ -z "${type}" ]]; then
type=tcp
fi
# If the firewall is enabled, add the corresponding open port
if systemctl status netfilter-persistent 2>/dev/null | grep -q "active (exited)"; then
local updateFirewalldStatus=
if ! iptables -L | grep -q "$1/${type}(mack-a)"; then
            updateFirewalldStatus=true
            iptables -I INPUT -p ${type} --dport "$1" -m comment --comment "allow $1/${type}(mack-a)" -j ACCEPT

        fi

        if echo "${updateFirewalldStatus}" | grep -q "true"; then
            netfilter-persistent save
        fi
    elif systemctl status ufw 2>/dev/null | grep -q "active (exited)"; then
        if ufw status | grep -q "Status: active"; then
            if ! ufw status | grep -q "$1/${type}"; then
                sudo ufw allow "$1/${type}"
                checkUFWAllowPort "$1"
            fi
        fi
    elif rc-update show 2>/dev/null | grep -q ufw; then
        if ufw status | grep -q "Status: active"; then
            if ! ufw status | grep -q "$1/${type}"; then
                sudo ufw allow "$1/${type}"
                checkUFWAllowPort "$1"
            fi
        fi
    elif systemctl status firewalld 2>/dev/null | grep -q "active (running)"; then
        local updateFirewalldStatus=
        if ! firewall-cmd --list-ports --permanent | grep -qw "$1/${type}"; then
            updateFirewalldStatus=true
            local firewallPort=$1
            if echo "${firewallPort}" | grep -q ":"; then
                firewallPort=$(echo "${firewallPort}" | awk -F ":" '{print $1"-"$2}')
            fi
            firewall-cmd --zone=public --add-port="${firewallPort}/${type}" --permanent
            checkFirewalldAllowPort "${firewallPort}"
        fi

        if echo "${updateFirewalldStatus}" | grep -q "true"; then
            firewall-cmd --reload
        fi
    fi
}
# 获取公网IP
getPublicIP() {
    local type=4
    if [[ -n "$1" ]]; then
        type=$1
    fi
    if [[ -n "${currentHost}" && -z "$1" ]] && [[ "${singBoxVLESSRealityVisionServerName}" == "${currentHost}" || "${singBoxVLESSRealityGRPCServerName}" == "${currentHost}" || "${xrayVLESSRealityServerName}" == "${currentHost}" ]]; then
        echo "${currentHost}"
    else
        local currentIP=
        currentIP=$(curl -s "-${type}" http://www.cloudflare.com/cdn-cgi/trace | grep "ip" | awk -F "[=]" '{print $2}')
        if [[ -z "${currentIP}" && -z "$1" ]]; then
            currentIP=$(curl -s "-6" http://www.cloudflare.com/cdn-cgi/trace | grep "ip" | awk -F "[=]" '{print $2}')
        fi
        echo "${currentIP}"
    fi

}

# 输出ufw端口开放状态
checkUFWAllowPort() {
    if ufw status | grep -q "$1"; then
        echoContent green " ---> $1端口开放成功"
    else
        echoContent red " ---> $1端口开放失败"
        exit 0
    fi
}

# 输出firewall-cmd端口开放状态
checkFirewalldAllowPort() {
    if firewall-cmd --list-ports --permanent | grep -q "$1"; then
        echoContent green " ---> $1端口开放成功"
    else
        echoContent red " ---> $1端口开放失败"
        exit 0
    fi
}

# 读取Tuic配置
readSingBoxConfig() {
    tuicPort=
    hysteriaPort=
    if [[ -n "${singBoxConfigPath}" ]]; then

        if [[ -f "${singBoxConfigPath}09_tuic_inbounds.json" ]]; then
            tuicPort=$(jq -r '.inbounds[0].listen_port' "${singBoxConfigPath}09_tuic_inbounds.json")
            tuicAlgorithm=$(jq -r '.inbounds[0].congestion_control' "${singBoxConfigPath}09_tuic_inbounds.json")
        fi
        if [[ -f "${singBoxConfigPath}06_hysteria2_inbounds.json" ]]; then
            hysteriaPort=$(jq -r '.inbounds[0].listen_port' "${singBoxConfigPath}06_hysteria2_inbounds.json")
            hysteria2ClientUploadSpeed=$(jq -r '.inbounds[0].down_mbps' "${singBoxConfigPath}06_hysteria2_inbounds.json")
            hysteria2ClientDownloadSpeed=$(jq -r '.inbounds[0].up_mbps' "${singBoxConfigPath}06_hysteria2_inbounds.json")
        fi
    fi
}

# 读取上次安装的配置
readLastInstallationConfig() {
    if [[ -n "${configPath}" ]]; then
        read -r -p "读取到上次安装的配置，是否使用 ？[y/n]:" lastInstallationConfigStatus
        if [[ "${lastInstallationConfigStatus}" == "y" ]]; then
            lastInstallationConfig=true
        fi
    fi
}
# 卸载 sing-box
unInstallSingBox() {
    local type=$1
    if [[ -n "${singBoxConfigPath}" ]]; then
        if grep -q 'tuic' </etc/v2ray-agent/sing-box/conf/config.json && [[ "${type}" == "tuic" ]]; then
            rm "${singBoxConfigPath}09_tuic_inbounds.json"

echoContent green " ---> Delete sing-box tuic configuration successfully"
fi

if grep -q 'hysteria2' </etc/v2ray-agent/sing-box/conf/config.json && [[ "${type}" == "hysteria2" ]]; then
rm "${singBoxConfigPath}06_hysteria2_inbounds.json"
echoContent green " ---> Delete sing-box hysteria2 configuration successfully"
fi
rm "${singBoxConfigPath}config.json"
fi

readInstallType

if [[ -n "${singBoxConfigPath}" ]]; then
echoContent yellow " ---> Detected other configurations, retain sing-box core"
handleSingBox stop
handleSingBox start
else
handleSingBox stop
rm /etc/systemd/system/sing-box.service
rm -rf /etc/v2ray-agent/sing-box/*
        echoContent green " ---> sing-box uninstall completed"
    fi
}

# Check the file directory and path
readConfigHostPathUUID() {
    currentPath=
    currentDefaultPort=
    currentUUID=
    currentClients=
    currentHost=
    currentPort=
    currentCDNAddress=
    singBoxVMessWSPath=
    singBoxVLESSWSPath=
    singBoxVMessHTTPUpgradePath=

    if [[ "${coreInstallType}" == "1" ]]; then

        # Install
        if [[ -n "${frontingType}" ]]; then
            currentHost=$(jq -r .inbounds[0].streamSettings.tlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')

            currentPort=$(jq .inbounds[0].port ${configPath}${frontingType}.json)

            local defaultPortFile=
            defaultPortFile=$(find ${configPath}* | grep "default")

            if [[ -n "${defaultPortFile}" ]]; then
                currentDefaultPort=$(echo "${defaultPortFile}" | awk -F [_] '{print $4}')
            else
                currentDefaultPort=$(jq -r .inbounds[0].port ${configPath}${frontingType}.json)
            fi
            currentUUID=$(jq -r .inbounds[0].settings.clients[0].id ${configPath}${frontingType}.json)
            currentClients=$(jq -r .inbounds[0].settings.clients ${configPath}${frontingType}.json)
        fi

        #reality
        if echo ${currentInstallProtocolType} | grep -q ",7,"; then

            currentClients=$(jq -r .inbounds[0].settings.clients ${configPath}07_VLESS_vision_reality_inbounds.json)

            xrayVLESSRealityVisionPort=$(jq -r .inbounds[0].port ${configPath}07_VLESS_vision_reality_inbounds.json)
            if [[ "${currentPort}" == "${xrayVLESSRealityVisionPort}" ]]; then
                xrayVLESSRealityVisionPort="${currentDefaultPort}"
            fi
        fi
    elif [[ "${coreInstallType}" == "2" ]]; then
        if [[ -n "${frontingType}" ]]; then
            currentHost=$(jq -r .inbounds[0].tls.server_name ${configPath}${frontingType}.json)
            if echo ${currentInstallProtocolType} | grep -q ",11," && [[ "${currentHost}" == "null" ]]; then
                currentHost=$(grep 'server_name' <${nginxConfigPath}sing_box_VMess_HTTPUpgrade.conf | awk '{print $2}')
                currentHost=${currentHost//;/}
            fi
            currentUUID=$(jq -r .inbounds[0].users[0].uuid ${configPath}${frontingType}.json)
            currentClients=$(jq -r .inbounds[0].users ${configPath}${frontingType}.json)        else
            currentUUID=$(jq -r .inbounds[0].users[0].uuid ${configPath}${frontingTypeReality}.json)
            currentClients=$(jq -r .inbounds[0].users ${configPath}${frontingTypeReality}.json)
        fi
    fi

    #Read path
    if [[ -n "${configPath}" && -n "${frontingType}" ]]; then
        if [[ "${coreInstallType}" == "1" ]]; then
            local fallback
            fallback=$(jq -r -c '.inbounds[0].settings.fallbacks[]|select(.path)' ${configPath}${frontingType}.json | head -1)

            local path
            path=$(echo "${fallback}" | jq -r .path | awk -F "[/]" '{print $2}')

            if [[ $(echo "${fallback}" | jq -r .dest) == 31297 ]]; then
                currentPath=$(echo "${path}" | awk -F "[w][s]" '{print $1}')
            elif [[ $(echo "${fallback}" | jq -r .dest) == 31299 ]]; then

                currentPath=$(echo "${path}" | awk -F "[v][w][s]" '{print $1}')
            fi

            # 尝试读取alpn h2 Path
            if [[ -z "${currentPath}" ]]; then
                dest=$(jq -r -c '.inbounds[0].settings.fallbacks[]|select(.alpn)|.dest' ${configPath}${frontingType}.json | head -1)
                if [[ "${dest}" == "31302" || "${dest}" == "31304" ]]; then
                    checkBTPanel
                    check1Panel
                    if grep -q "trojangrpc {" <${nginxConfigPath}alone.conf; then
                        currentPath=$(grep "trojangrpc {" <${nginxConfigPath}alone.conf | awk -F "[/]" '{print $2}' | awk -F "[t][r][o][j][a][n]" '{print $1}')
                    elif grep -q "grpc {" <${nginxConfigPath}alone.conf; then
                        currentPath=$(grep "grpc {" <${nginxConfigPath}alone.conf | head -1 | awk -F "[/]" '{print $2}' | awk -F "[g][r][p][c]" '{print $1}')
                    fi
                fi
            fi
            if [[ -z "${currentPath}" && -f "${configPath}12_VLESS_XHTTP_inbounds.json" ]]; then
                currentPath=$(jq -r .inbounds[0].streamSettings.xhttpSettings.path "${configPath}12_VLESS_XHTTP_inbounds.json" | awk -F "[x][H][T][T][P]" '{print $1}' | awk -F "[/]" '{print $2}')
            fi
        elif [[ "${coreInstallType}" == "2" && -f "${singBoxConfigPath}05_VMess_WS_inbounds.json" ]]; then
            singBoxVMessWSPath=$(jq -r .inbounds[0].transport.path "${singBoxConfigPath}05_VMess_WS_inbounds.json")
            currentPath=$(jq -r .inbounds[0].transport.path "${singBoxConfigPath}05_VMess_WS_inbounds.json" | awk -F "[/]" '{print $2}')
        fi
        if [[ "${coreInstallType}" == "2" && -f "${singBoxConfigPath}03_VLESS_WS_inbounds.json" ]]; then
            singBoxVLESSWSPath=$(jq -r .inbounds[0].transport.path "${singBoxConfigPath}03_VLESS_WS_inbounds.json")
            currentPath=$(jq -r .inbounds[0].transport.path "${singBoxConfigPath}03_VLESS_WS_inbounds.json" | awk -F "[/]" '{print $2}')
            currentPath=${currentPath::-2}
        fi
        if [[ "${coreInstallType}" == "2" && -f "${singBoxConfigPath}11_VMess_HTTPUpgrade_inbounds.json" ]]; then
            singBoxVMessHTTPUpgradePath=$(jq -r .inbounds[0].transport.path "${singBoxConfigPath}11_VMess_HTTPUpgrade_inbounds.json")
            currentPath=$(jq -r .inbounds[0].transport.path "${singBoxConfigPath}11_VMess_HTTPUpgrade_inbounds.json" | awk -F "[/]" '{print $2}')
            # currentPath=${currentPath::-2}
        fi
    fi
    if [[ -f "/etc/v2ray-agent/cdn" ]] && [[ -n "$(head -1 /etc/v2ray-agent/cdn)" ]]; then
        currentCDNAddress=$(head -1 /etc/v2ray-agent/cdn)
    else
        currentCDNAddress="${currentHost}"
    fi
}

# 状态展示
showInstallStatus() {
    if [[ -n "${coreInstallType}" ]]; then
        if [[ "${coreInstallType}" == 1 ]]; then
            if [[ -n $(pgrep -f "xray/xray") ]]; then
                echoContent yellow "\n核心: Xray-core[运行中]"
            else
                echoContent yellow "\n核心: Xray-core[未运行]"
            fi

        elif [[ "${coreInstallType}" == 2 ]]; then
            if [[ -n $(pgrep -f "sing-box/sing-box") ]]; then
                echoContent yellow "\n核心: sing-box[运行中]"
            else
                echoContent yellow "\n核心: sing-box[未运行]"
            fi
        fi
        # 读取协议类型
        readInstallProtocolType

        if [[ -n ${currentInstallProtocolType} ]]; then
            echoContent yellow "已安装协议: \c"
        fi
        if echo ${currentInstallProtocolType} | grep -q ",0,"; then
            echoContent yellow "VLESS+TCP[TLS_Vision] \c"
        fi

        if echo ${currentInstallProtocolType} | grep -q ",1,"; then
            echoContent yellow "VLESS+WS[TLS] \c"
        fi

        if echo ${currentInstallProtocolType} | grep -q ",2,"; then
            echoContent yellow "Trojan+gRPC[TLS] \c"
        fi

        if echo ${currentInstallProtocolType} | grep -q ",3,"; then

            echoContent yellow "VMess+WS[TLS] \c"
        fi

        if echo ${currentInstallProtocolType} | grep -q ",4,"; then
            echoContent yellow "Trojan+TCP[TLS] \c"
        fi

        if echo ${currentInstallProtocolType} | grep -q ",5,"; then
            echoContent yellow "VLESS+gRPC[TLS] \c"
        fi
        if echo ${currentInstallProtocolType} | grep -q ",6,"; then
            echoContent yellow "Hysteria2 \c"
        fi
        if echo ${currentInstallProtocolType} | grep -q ",7,"; then
            echoContent yellow "VLESS+Reality+Vision \c"
        fi
        if echo ${currentInstallProtocolType} | grep -q ",8,"; then
            echoContent yellow "VLESS+Reality+gRPC \c"
        fi
        if echo ${currentInstallProtocolType} | grep -q ",9,"; then
            echoContent yellow "Tuic \c"
        fi
    fi
}

# 清理旧残留
cleanUp() {
    if [[ "$1" == "xrayDel" ]]; then
        handleXray stop
        rm -rf /etc/v2ray-agent/xray/*
    elif [[ "$1" == "singBoxDel" ]]; then
        handleSingBox stop
        rm -rf /etc/v2ray-agent/sing-box/conf/config.json >/dev/null 2>&1
        rm -rf /etc/v2ray-agent/sing-box/conf/config/* >/dev/null 2>&1
    fi
}
initVar "$1"
checkSystem
checkCPUVendor

readInstallType
readInstallProtocolType
readConfigHostPathUUID
readCustomPort
readSingBoxConfig
# -------------------------------------------------------------

# 初始化安装目录
mkdirTools() {
    mkdir -p /etc/v2ray-agent/tls
    mkdir -p /etc/v2ray-agent/subscribe_local/default
    mkdir -p /etc/v2ray-agent/subscribe_local/clashMeta

    mkdir -p /etc/v2ray-agent/subscribe_remote/default
    mkdir -p /etc/v2ray-agent/subscribe_remote/clashMeta

    mkdir -p /etc/v2ray-agent/subscribe/default
    mkdir -p /etc/v2ray-agent/subscribe/clashMetaProfiles
    mkdir -p /etc/v2ray-agent/subscribe/clashMeta

    mkdir -p /etc/v2ray-agent/subscribe/sing-box
    mkdir -p /etc/v2ray-agent/subscribe/sing-box_profiles
    mkdir -p /etc/v2ray-agent/subscribe_local/sing-box

    mkdir -p /etc/v2ray-agent/xray/conf
    mkdir -p /etc/v2ray-agent/xray/reality_scan
    mkdir -p /etc/v2ray-agent/xray/tmp
    mkdir -p /etc/systemd/system/
    mkdir -p /tmp/v2ray-agent-tls/

    mkdir -p /etc/v2ray-agent/warp

    mkdir -p /etc/v2ray-agent/sing-box/conf/config

    mkdir -p /usr/share/nginx/html/
}

# 安装工具包
installTools() {
    echoContent skyBlue "\n进度  $1/${totalProgress} : 安装工具"
    # 修复ubuntu个别系统问题
    if [[ "${release}" == "ubuntu" ]]; then
        dpkg --configure -a
    fi

    if [[ -n $(pgrep -f "apt") ]]; then
        pgrep -f apt | xargs kill -9
    fi

    echoContent green " ---> 检查、安装更新【新机器会很慢，如长时间无反应，请手动停止后重新执行】"

    ${upgrade} >/etc/v2ray-agent/install.log 2>&1
    if grep <"/etc/v2ray-agent/install.log" -q "changed"; then
        ${updateReleaseInfoChange} >/dev/null 2>&1
    fi

    if [[ "${release}" == "centos" ]]; then
        rm -rf /var/run/yum.pid
        ${installType} epel-release >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w wget; then
        echoContent green " ---> 安装wget"
        ${installType} wget >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w netfilter-persistent; then
        if [[ "${release}" != "centos" ]]; then
            echoContent green " ---> 安装iptables"
            echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | sudo debconf-set-selections
            echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | sudo debconf-set-selections
            ${installType} iptables-persistent >/dev/null 2>&1
        fi
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w curl; then
        echoContent green " ---> 安装curl"
        ${installType} curl >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w unzip; then
        echoContent green " ---> 安装unzip"
        ${installType} unzip >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w socat; then
        echoContent green " ---> 安装socat"

        ${installType} socat >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w tar; then
        echoContent green " ---> 安装tar"
        ${installType} tar >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w cron; then
        echoContent green " ---> 安装crontabs"
        if [[ "${release}" == "ubuntu" ]] || [[ "${release}" == "debian" ]]; then
            ${installType} cron >/dev/null 2>&1
        else
            ${installType} crontabs >/dev/null 2>&1
        fi
    fi
    if ! find /usr/bin /usr/sbin | grep -q -w jq; then
        echoContent green " ---> 安装jq"
        ${installType} jq >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w binutils; then
        echoContent green " ---> 安装binutils"
        ${installType} binutils >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w openssl; then
        echoContent green " ---> 安装openssl"
        ${installType} openssl >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w ping6; then
        echoContent green " ---> 安装ping6"
        ${installType} inetutils-ping >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w qrencode; then
        echoContent green " ---> 安装qrencode"
        ${installType} qrencode >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w sudo; then
        echoContent green " ---> 安装sudo"
        ${installType} sudo >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w lsb-release; then
        echoContent green " ---> 安装lsb-release"
        ${installType} lsb-release >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w lsof; then
        echoContent green " ---> 安装lsof"
        ${installType} lsof >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w dig; then
        echoContent green " ---> 安装dig"
        if echo "${installType}" | grep -qw "apt"; then
            ${installType} dnsutils >/dev/null 2>&1
        elif echo "${installType}" | grep -qw "yum"; then
            ${installType} bind-utils >/dev/null 2>&1
        elif echo "${installType}" | grep -qw "apk"; then
            ${installType} bind-tools >/dev/null 2>&1
        fi
    fi

    # 检测nginx版本，并提供是否卸载的选项
    if echo "${selectCustomInstallType}" | grep -qwE ",7,|,8,|,7,8,"; then
        echoContent green " ---> 检测到无需依赖Nginx的服务，跳过安装"
    else
        if ! find /usr/bin /usr/sbin | grep -q -w nginx; then
            echoContent green " ---> 安装nginx"
            installNginxTools
        else
            nginxVersion=$(nginx -v 2>&1)
            nginxVersion=$(echo "${nginxVersion}" | awk -F "[n][g][i][n][x][/]" '{print $2}' | awk -F "[.]" '{print $2}')
            if [[ ${nginxVersion} -lt 14 ]]; then
                read -r -p "读取到当前的Nginx版本不支持gRPC，会导致安装失败，是否卸载Nginx后重新安装 ？[y/n]:" unInstallNginxStatus
                if [[ "${unInstallNginxStatus}" == "y" ]]; then
                    ${removeType} nginx >/dev/null 2>&1
                    echoContent yellow " ---> nginx卸载完成"
                    echoContent green " ---> 安装nginx"
                    installNginxTools >/dev/null 2>&1
                else
                    exit 0
                fi
            fi
        fi
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w semanage; then
        echoContent green " ---> 安装semanage"
        ${installType} bash-completion >/dev/null 2>&1

        if [[ "${centosVersion}" == "7" ]]; then
            policyCoreUtils="policycoreutils-python.x86_64"
        elif [[ "${centosVersion}" == "8" ]]; then
            policyCoreUtils="policycoreutils-python-utils-2.9-9.el8.noarch"
        fi

        if [[ -n "${policyCoreUtils}" ]]; then
            ${installType} ${policyCoreUtils} >/dev/null 2>&1
        fi
        if [[ -n $(which semanage) ]]; then
            semanage port -a -t http_port_t -p tcp 31300

        fi
    fi
    if [[ "${selectCustomInstallType}" == "7" ]]; then
        echoContent green " ---> 检测到无需依赖证书的服务，跳过安装"

else
if [[ ! -d "$HOME/.acme.sh" ]] || [[ -d "$HOME/.acme.sh" && -z $(find "$HOME/.acme.sh/acme.sh") ]]; then
echoContent green " ---> Install acme.sh"
curl -s https://get.acme.sh | sh >/etc/v2ray-agent/tls/acme.log 2>&1

if [[ ! -d "$HOME/.acme.sh" ]] || [[ -z $(find "$HOME/.acme.sh/acme.sh") ]]; then
echoContent red " Failed to install acme --->"
tail -n 100 /etc/v2ray-agent/tls/acme.log
echoContent yellow " Troubleshooting:"
echoContent red " 1. Failed to obtain Github files. Please wait for Github to recover and try again. The recovery progress can be viewed at [https://www.githubstatus.com/]"
echoContent red " 2. There is a bug in the acme.sh script. Please view [https://github.com/acmesh-official/acme.sh] issues"
echoContent red " 3. If it is a pure IPv6 machine, please set up NAT64 and execute the following command. If adding the following command still does not work, please try to change another NAT64"
echoContent skyBlue " sed -i \"1i\\\nameserver 2a00:1098:2b::1\\\nnameserver 2a00:1098:2c::1\\\nnameserver 2a01:4f8:c2c:123f::1\\\nnameserver 2a01:4f9:c010:3f02::1\" /etc/resolv.conf"
exit 0
            fi
        fi
    fi

}
#Start at boot
bootStartup() {
    local serviceName=$1
    if [[ "${release}" == "alpine" ]]; then
        rc-update add "${serviceName}" default
    else
        systemctl daemon-reload
        systemctl enable "${serviceName}"
    fi
}
# Install Nginx
installNginxTools() {

    if [[ "${release}" == "debian" ]]; then
        sudo apt install gnupg2 ca-certificates lsb-release -y >/dev/null 2>&1
        echo "deb http://nginx.org/packages/mainline/debian $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null 2>&1
        echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx >/dev/null 2>&1
        curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
        # gpg --dry-run --quiet --import --import-options import-show /tmp/nginx_signing.key
        sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
        sudo apt update >/dev/null 2>&1

    elif [[ "${release}" == "ubuntu" ]]; then
        sudo apt install gnupg2 ca-certificates lsb-release -y >/dev/null 2>&1
        echo "deb http://nginx.org/packages/mainline/ubuntu $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null 2>&1
        echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx >/dev/null 2>&1
        curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
        # gpg --dry-run --quiet --import --import-options import-show /tmp/nginx_signing.key
        sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
        sudo apt update >/dev/null 2>&1

    elif [[ "${release}" == "centos" ]]; then
        ${installType} yum-utils >/dev/null 2>&1
        cat <<EOF >/etc/yum.repos.d/nginx.repo
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/\$releasever/\$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true

[nginx-mainline]
name=nginx mainline repo
baseurl=http://nginx.org/packages/mainline/centos/\$releasever/\$basearch/
gpgcheck=1
enabled=0
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF
        sudo yum-config-manager --enable nginx-mainline >/dev/null 2>&1
    elif [[ "${release}" == "alpine" ]]; then
        rm "${nginxConfigPath}default.conf" fi
${installType} nginx >/dev/null 2>&1
bootStartup nginx
}

# Install warp
installWarp() {
if [[ "${cpuVendor}" == "arm" ]]; then
echoContent red " ---> Official WARP client does not support ARM architecture"
exit 0
fi

${installType} gnupg2 -y >/dev/null 2>&1
if [[ "${release}" == "debian" ]]; then
curl -s https://pkg.cloudflareclient.com/pubkey.gpg | sudo apt-key add - >/dev/null 2>&1

        echo "deb http://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null 2>&1
        sudo apt update >/dev/null 2>&1

    elif [[ "${release}" == "ubuntu" ]]; then
        curl -s https://pkg.cloudflareclient.com/pubkey.gpg | sudo apt-key add - >/dev/null 2>&1
        echo "deb http://pkg.cloudflareclient.com/ focal main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null 2>&1
        sudo apt update >/dev/null 2>&1

    elif [[ "${release}" == "centos" ]]; then
        ${installType} yum-utils >/dev/null 2>&1
        sudo rpm -ivh "http://pkg.cloudflareclient.com/cloudflare-release-el${centosVersion}.rpm" >/dev/null 2>&1
    fi

    echoContent green " ---> 安装WARP"
    ${installType} cloudflare-warp >/dev/null 2>&1
    if [[ -z $(which warp-cli) ]]; then
        echoContent red " ---> 安装WARP失败"
        exit 0
    fi
    systemctl enable warp-svc
    warp-cli --accept-tos register
    warp-cli --accept-tos set-mode proxy
    warp-cli --accept-tos set-proxy-port 31303
    warp-cli --accept-tos connect
    warp-cli --accept-tos enable-always-on

    local warpStatus=
    warpStatus=$(curl -s --socks5 127.0.0.1:31303 https://www.cloudflare.com/cdn-cgi/trace | grep "warp" | cut -d "=" -f 2)

    if [[ "${warpStatus}" == "on" ]]; then
        echoContent green " ---> WARP启动成功"
    fi
}

# 通过dns检查域名的IP
checkDNSIP() {
    local domain=$1
    local dnsIP=
    ipType=4
    dnsIP=$(dig @1.1.1.1 +time=2 +short "${domain}" | grep -E "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
    if [[ -z "${dnsIP}" ]]; then
        dnsIP=$(dig @8.8.8.8 +time=2 +short "${domain}" | grep -E "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
    fi
    if echo "${dnsIP}" | grep -q "timed out" || [[ -z "${dnsIP}" ]]; then
        echo
        echoContent red " ---> 无法通过DNS获取域名 IPv4 地址"
        echoContent green " ---> 尝试检查域名 IPv6 地址"
        dnsIP=$(dig @2606:4700:4700::1111 +time=2 aaaa +short "${domain}")
        ipType=6
        if echo "${dnsIP}" | grep -q "network unreachable" || [[ -z "${dnsIP}" ]]; then
            echoContent red " ---> 无法通过DNS获取域名IPv6地址，退出安装"
            exit 0
        fi
    fi
    local publicIP=

    publicIP=$(getPublicIP "${ipType}")
    if [[ "${publicIP}" != "${dnsIP}" ]]; then
        echoContent red " ---> 域名解析IP与当前服务器IP不一致\n"
        echoContent yellow " ---> 请检查域名解析是否生效以及正确"
        echoContent green " ---> 当前VPS IP：${publicIP}"
        echoContent green " ---> DNS解析 IP：${dnsIP}"
        exit 0
    else
        echoContent green " ---> 域名IP校验通过"
    fi
}
# 检查端口实际开放状态
checkPortOpen() {
    handleSingBox stop >/dev/null 2>&1
    handleXray stop >/dev/null 2>&1

    local port=$1
    local domain=$2
    local checkPortOpenResult=
    allowPort "${port}"

    if [[ -z "${btDomain}" ]]; then

        handleNginx stop
        # 初始化nginx配置
        touch ${nginxConfigPath}checkPortOpen.conf
        local listenIPv6PortConfig=

        if [[ -n $(curl -s -6 -m 4 http://www.cloudflare.com/cdn-cgi/trace | grep "ip" | cut -d "=" -f 2) ]]; then
            listenIPv6PortConfig="listen [::]:${port};"
        fi
        cat <<EOF >${nginxConfigPath}checkPortOpen.conf
server {
    listen ${port};
    ${listenIPv6PortConfig}
    server_name ${domain};
    location /checkPort {
        return 200 'fjkvymb6len';
    }
    location /ip {
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header REMOTE-HOST \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        default_type text/plain;
        return 200 \$proxy_add_x_forwarded_for;
    }
}
EOF
        handleNginx start
        # 检查域名+端口的开放
        checkPortOpenResult=$(curl -s -m 10 "http://${domain}:${port}/checkPort")
        localIP=$(curl -s -m 10 "http://${domain}:${port}/ip")

rm "${nginxConfigPath}checkPortOpen.conf"
handleNginx stop
if [[ "${checkPortOpenResult}" == "fjkvymb6len" ]]; then
echoContent green " ---> Detected that ${port} port is open"
else
echoContent green " ---> Did not detect that ${port} port is open, exit installation"
if echo "${checkPortOpenResult}" | grep -q "cloudflare"; then
echoContent yellow " ---> Please close the cloud and wait for three minutes to try again"
else
if [[ -z "${checkPortOpenResult}" ]]; then
echoContent red " ---> Please check if there is a web firewall, such as Oracle and other cloud service providers"
echoContent red " ---> Check if you have installed nginx yourself and there is a configuration conflict. You can try to DD a clean system and try again"
else
echoContent red " ---> Error log: ${checkPortOpenResult}, please submit this error log through issues"
fi
fi
exit 0
fi
checkIP "${localIP}"
fi
}

# Initialize Nginx certificate application configuration
initTLSNginxConfig() {
handleNginx stop
echoContent skyBlue "\nProgress $1/${totalProgress}: Initialize Nginx certificate application configuration"
if [[ -n "${currentHost}" && -z "${lastInstallationConfig}" ]]; then
echo
read -r -p "Read the last installation record, do you want to use the domain name of the last installation? [y/n]:" historyDomainStatus
if [[ "${historyDomainStatus}" == "y" ]]; then
domain=${currentHost}
echoContent yellow "\n ---> Domain name: ${domain}"
else
echo
echoContent yellow "Please enter the domain name to be configured Example: www.v2ray-agent.com --->"
read -r -p "Domain name:" domain
fi
elif [[ -n "${currentHost}" && -n "${lastInstallationConfig}" ]]; then
domain=${currentHost}
else
echo
echoContent yellow "Please enter the domain name to be configured Example: www.v2ray-agent.com --->"
read -r -p "Domain name:" domain
fi

if [[ -z ${domain} ]]; then
echoContent red "Domain name cannot be empty--->"
initTLSNginxConfig 3
else
dnsTLSDomain=$(echo "${domain}" | awk -F "." '{$1="";print $0}' | sed 's/^[[:space:]]*//' | sed 's/ /./g')
if [[ "${selectCoreType}" == "1" ]]; then
customPortFunction
fi
# Modify configuration
handleNginx stop
fi
}

# Delete nginx default configuration
removeNginxDefaultConf() {
if [[ -f ${nginxConfigPath}default.conf ]]; then
if [[ "$(grep -c "server_name" <${nginxConfigPath}default.conf)" == "1" ]] && [[ "$(grep -c "server_name localhost;" <${nginxConfigPath}default.conf)" == "1" ]]; then
echoContent green " ---> Delete Nginx default configuration"
rm -rf ${nginxConfigPath}default.conf >/dev/null 2>&1
fi
fi
}
# Modify nginx redirection configuration
updateRedirectNginxConf() {
local redirectDomain=
    redirectDomain=${domain}:${port}

    local nginxH2Conf=
    nginxH2Conf="listen 127.0.0.1:31302 http2 so_keepalive=on proxy_protocol;"
    nginxVersion=$(nginx -v 2>&1)

    then
        nginxH2Conf="listen 127.0.0.1:31302 so_keepalive=on proxy_protocol;http2 on;"
    fi

    cat <<EOF >${nginxConfigPath}alone.conf
    server {
    		listen 127.0.0.1:31300;
    		server_name _;
    		return 403;
    }
EOF

    if echo "${selectCustomInstallType}" | grep -qE ",2,|,5," || [[ -z "${selectCustomInstallType}" ]]; then

        cat <<EOF >>${nginxConfigPath}alone.conf
server {
	${nginxH2Conf}
	server_name ${domain};
	root ${nginxStaticPath};

    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

	client_header_timeout 1071906480m;
    keepalive_timeout 1071906480m;

    location /${currentPath}grpc {
    	if (\$content_type !~ "application/grpc") {
    		return 404;
    	}
 		client_max_body_size 0;
		grpc_set_header X-Real-IP \$proxy_add_x_forwarded_for;
		client_body_timeout 1071906480m;
		grpc_read_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301;
	}

	location /${currentPath}trojangrpc {
		if (\$content_type !~ "application/grpc") {
            		return 404;
		}
 		client_max_body_size 0;
		grpc_set_header X-Real-IP \$proxy_add_x_forwarded_for;

		client_body_timeout 1071906480m;
		grpc_read_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31304;
	}
	location / {
    }
}
EOF
    elif echo "${selectCustomInstallType}" | grep -q ",5," || [[ -z "${selectCustomInstallType}" ]]; then
        cat <<EOF >>${nginxConfigPath}alone.conf
server {
	${nginxH2Conf}

	set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

	server_name ${domain};
	root ${nginxStaticPath};

	location /${currentPath}grpc {
		client_max_body_size 0;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301;
	}
	location / {
    }
}
EOF

    elif echo "${selectCustomInstallType}" | grep -q ",2," || [[ -z "${selectCustomInstallType}" ]]; then
        cat <<EOF >>${nginxConfigPath}alone.conf
server {
	${nginxH2Conf}

	set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    server_name ${domain};
	root ${nginxStaticPath};

	location /${currentPath}trojangrpc {
		client_max_body_size 0;
		# keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301;
	}
	location / {
    }
}
EOF
    else

        cat <<EOF >>${nginxConfigPath}alone.conf
server {
	${nginxH2Conf}

	set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

	server_name ${domain};
	root ${nginxStaticPath};

	location / {
	}
}
EOF
    fi

    cat <<EOF >>${nginxConfigPath}alone.conf
server {
	listen 127.0.0.1:31300 proxy_protocol;
	server_name ${domain};

	set_real_ip_from 127.0.0.1;
	real_ip_header proxy_protocol;

	root ${nginxStaticPath};
	location / {
	}
}
EOF
    handleNginx stop
}
# singbox Nginx config
singBoxNginxConfig() {
    local type=$1
    local port=$2

    local nginxH2Conf=
    nginxH2Conf="listen ${port} http2 so_keepalive=on ssl;"
    nginxVersion=$(nginx -v 2>&1)

    local singBoxNginxSSL=
    singBoxNginxSSL="ssl_certificate /etc/v2ray-agent/tls/${domain}.crt;ssl_certificate_key /etc/v2ray-agent/tls/${domain}.key;"

    if echo "${nginxVersion}" | grep -q "1.25" && [[ $(echo "${nginxVersion}" | awk -F "[.]" '{print $3}') -gt 0 ]] || [[ $(echo "${nginxVersion}" | awk -F "[.]" '{print $2}') -gt 25 ]]; then
        nginxH2Conf="listen ${port} so_keepalive=on ssl;http2 on;"
    fi

    if echo "${selectCustomInstallType}" | grep -q ",11," || [[ "$1" == "all" ]]; then
        cat <<EOF >>${nginxConfigPath}sing_box_VMess_HTTPUpgrade.conf
server {
	${nginxH2Conf}

	server_name ${domain};
	root ${nginxStaticPath};
    ${singBoxNginxSSL}

    ssl_protocols              TLSv1.2 TLSv1.3;
    ssl_ciphers                TLS13_AES_128_GCM_SHA256:TLS13_AES_256_GCM_SHA384:TLS13_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers  on;

    resolver                   1.1.1.1 valid=60s;
    resolver_timeout           2s;
    client_max_body_size 100m;

    location /${currentPath} {
    	if (\$http_upgrade != "websocket") {
            return 444;
        }

        proxy_pass                          http://127.0.0.1:31306;
        proxy_http_version                  1.1;
        proxy_set_header Upgrade            \$http_upgrade;
        proxy_set_header Connection         "upgrade";
        proxy_set_header X-Real-IP          \$remote_addr;
        proxy_set_header X-Forwarded-For    \$proxy_add_x_forwarded_for;
        proxy_set_header Host               \$host;
        proxy_redirect                      off;
	}
}
EOF
    fi
}

# 检查ip
checkIP() {
    echoContent skyBlue "\n ---> 检查域名ip中"
    local localIP=$1


if [[ -z ${localIP} ]] || ! echo "${localIP}" | sed '1{s/[^(]*(//;s/).*//;q}' | grep -q '\.' && ! echo "${localIP}" | sed '1{s/[^(]*(//;s/).*//;q}' | grep -q ':'; then
echoContent red "\n ---> The ip of the current domain name is not detected"
echoContent skyBlue " ---> Please perform the following checks in sequence"
echoContent yellow " ---> 1. Check whether the domain name is written correctly"
echoContent yellow " ---> 2. Check whether the domain name dns resolution is correct"
echoContent yellow " ---> 3. If the resolution is correct, please wait for the dns to take effect, which is expected to take effect within three minutes"
echoContent yellow " ---> 4. If you report Nginx startup problems, please manually start nginx to check the errors. If you cannot handle it yourself, please raise issues"
echo
echoContent skyBlue " ---> If the above settings are correct, please reinstall the clean system and try again"

if [[ -n ${localIP} ]]; then
echoContent yellow " ---> Detection return value abnormality, it is recommended to manually uninstall nginx and re-execute the script"
echoContent red " ---> Abnormal result: ${localIP}"
fi
exit 0
else
if echo "${localIP}" | awk -F "[,]" '{print $2}' | grep -q "." || echo "${localIP}" | awk -F "[,]" '{print $2}' | grep -q ":"; then
echoContent red "\n ---> Detected multiple IPs, please confirm whether to turn off cloudflare's clouds"
echoContent yellow " ---> After closing the cloud, wait for three minutes and try again"
echoContent yellow " ---> The detected IP is as follows: [${localIP}]"
exit 0
fi
echoContent green " ---> Check that the current domain name IP is correct"
fi
}
# Custom email
customSSLEmail() {
if echo "$1" | grep -q "validate email"; then
read -r -p "Do you want to re-enter the email address [y/n]:" sslEmailStatus
if [[ "${sslEmailStatus}" == "y" ]]; then
sed '/ACCOUNT_EMAIL/d' /root/.acme.sh/account.conf >/root/.acme.sh/account.conf_tmp && mv /root/.acme.sh/account.conf_tmp /root/.acme.sh/account.conf
else
exit 0
fi
fi

if [[ -d "/root/.acme.sh" && -f "/root/.acme.sh/account.conf" ]]; then
if ! grep -q "ACCOUNT_EMAIL" <"/root/.acme.sh/account.conf" && ! echo "${sslType}" | grep -q "letsencrypt"; then
read -r -p "Please enter the email address:" sslEmail
if echo "${sslEmail}" | grep -q "@"; then
echo "ACCOUNT_EMAIL='${sslEmail}'" >>/root/.acme.sh/account.conf
echoContent green "---> Added"
else
echoContent yellow "Please re-enter the correct email format [eg: username@example.com]"
customSSLEmail
fi
fi
fi

}
# DNS API to apply for a certificate
switchDNSAPI() {
read -r -p "Whether to use DNS API application certificate [support NAT]? [y/n]:" dnsAPIStatus
if [[ "${dnsAPIStatus}" == "y" ]]; then
echoContent red "\n================================================================="
echoContent yellow "1.cloudflare[default]"
echoContent yellow "2.aliyun"
echoContent red "= ... 1)
dnsAPIType="cloudflare"
;;
2)
dnsAPIType="aliyun"
;;
*)
dnsAPIType="cloudflare"
;;
esac
initDNSAPIConfig "${dnsAPIType}"
fi
}
# Initialize dns configuration
initDNSAPIConfig() {
if [[ "$1" == "cloudflare" ]]; then
echoContent yellow "\n CF_Token reference configuration tutorial: https://www.v2ray-agent.com/archives/1701160377972\n"
read -r -p "Please enter API Token:" cfAPIToken
if [[ -z "${cfAPIToken}" ]]; then
echoContent red " ---> Input is empty, please re-enter"
initDNSAPIConfig "$1"
else
echo
if ! echo "${dnsTLSDomain}" | grep -q "\." || [[ -z $(echo "${dnsTLSDomain}" | awk -F "[.]" '{print $1}') ]]; then
echoContent green " ---> Wildcard certificate application for this domain name is not supported. It is recommended to use this format [xx.xx.xx]"
exit 0
fi
read -r -p "Do you use *.${dnsTLSDomain} to apply for a wildcard certificate for the API? [y/n]:" dnsAPIStatus
fi
elif [[ "$1" == "aliyun" ]]; then
read -r -p "Please enter Ali Key:" aliKey
read -r -p "Please enter Ali Secret:" aliSecret
if [[ -z "${aliKey}" || -z "${aliSecret}" ]]; then
echoContent red " ---> Input is empty, please re-enter"
initDNSAPIConfig "$1"
else
echo

if ! echo "${dnsTLSDomain}" | grep -q "\." || [[ -z $(echo "${dnsTLSDomain}" | awk -F "[.]" '{print $1}') ]]; then
echoContent green " ---> Wildcard certificate application for this domain name is not supported. This format [xx.xx.xx] is recommended"
exit 0
fi
read -r -p "Do you use *.${dnsTLSDomain} to apply for a wildcard certificate for the API? [y/n]:" dnsAPIStatus
fi
fi
}
# Select ssl installation type
switchSSLType() {
if [[ -z "${sslType}" ]]; then
echoContent red "\n================================================================="
echoContent yellow "1.letsencrypt[default]"
echoContent yellow "2.zerossl"
echoContent yellow "3.buypass[DNS application is not supported]"
echoContent red "======================================================================"
read -r -p "Please select [Enter] to use the default:" selectSSLType
case ${selectSSLType} in
1)
sslType="letsencrypt"
;;
2)
sslType="zerossl"
;;
3)
sslType="buypass"
;;
*)
sslType="letsencrypt"
;;
esac
if [[ -n "${dnsAPIType}" && "${sslType}" == "buypass" ]]; then
echoContent red " ---> buypass does not support API certificate application"
exit 0
fi
echo "${sslType}" >/etc/v2ray-agent/tls/ssl_type
fi
}

# Select acme installation certificate method
selectAcmeInstallSSL() {
# local sslIPv6=
# local currentIPType=
if [[ "${ipType}" == "6" ]]; then
sslIPv6="--listen-v6"
fi
# currentIPType=$(curl -s "-${ipType}" http://www.cloudflare.com/cdn-cgi/trace | grep "ip" | cut -d "=" -f 2)

    # if [[ -z "${currentIPType}" ]]; then
    # currentIPType=$(curl -s -6 http://www.cloudflare.com/cdn-cgi/trace | grep "ip" | cut -d "=" -f 2)
    # if [[ -n "${currentIPType}" ]]; then
    # sslIPv6="--listen-v6"
    #fi
    #fi

    acmeInstallSSL

    readAcmeTLS
}

# Install SSL certificate
acmeInstallSSL() {
    local dnsAPIDomain="${tlsDomain}"
    if [[ "${dnsAPIStatus}" == "y" ]]; then
        dnsAPIDomain="*.${dnsTLSDomain}"    fi

    if [[ "${dnsAPIType}" == "cloudflare" ]]; then
        echoContent green " ---> DNS API generating certificate"
        sudo CF_Token="${cfAPIToken}" "$HOME/.acme.sh/acme.sh" --issue -d "${dnsAPIDomain}" -d "${dnsTLSDomain}" --dns dns_cf -k ec-256 --server "${sslType}" ${sslIPv6} 2>&1 | tee -a /etc/v2ray-agent/tls/acme.log >/dev/null
    elif [[ "${dnsAPIType}" == "aliyun" ]]; then
        echoContent green " ---> DNS API generating certificate"
        sudo Ali_Key="${aliKey}" Ali_Secret="${aliSecret}" "$HOME/.acme.sh/acme.sh" --issue -d "${dnsAPIDomain}" -d "${dnsTLSDomain}" --dns dns_ali -k ec-256 --server "${sslType}" ${sslIPv6} 2>&1 | tee -a /etc/v2ray-agent/tls/acme.log >/dev/null
else
echoContent green " ---> Generating certificate"
sudo "$HOME/.acme.sh/acme.sh" --issue -d "${tlsDomain}" --standalone -k ec-256 --server "${sslType}" ${sslIPv6} 2>&1 | tee -a /etc/v2ray-agent/tls/acme.log >/dev/null
fi
}
# Custom port
customPortFunction() {
local historyCustomPortStatus=
if [[ -n "${customPort}" || -n "${currentPort}" ]]; then
echo
if [[ -z "${lastInstallationConfig}" ]]; then
read -r -p "Read the port of the last installation. Do you want to use the port of the last installation? [y/n]:" historyCustomPortStatus
if [[ "${historyCustomPortStatus}" == "y" ]]; then
port=${currentPort}
echoContent yellow "\n ---> Port: ${port}"
fi
elif [[ -n "${lastInstallationConfig}" ]]; then
port=${currentPort}
fi
fi
if [[ -z "${currentPort}" ]] || [[ "${historyCustomPortStatus}" == "n" ]]; then
echo

if [[ -n "${btDomain}" ]]; then
echoContent yellow "Please enter the port [cannot be the same as the BT Panel/1Panel port, press Enter to use random]"
read -r -p "Port:" port
if [[ -z "${port}" ]]; then
port=$((RANDOM % 20001 + 10000))
fi
else
echo
echoContent yellow "Please enter the port [default: 443], you can customize the port [press Enter to use the default]"
read -r -p "Port:" port
if [[ -z "${port}" ]]; then

                port=443
fi
if [[ "${port}" == "${xrayVLESSRealityPort}" ]]; then
handleXray stop
fi
fi
if [[ -n "${port}" ]]; then
if ((port >= 1 && port <= 65535)); then
allowPort "${port}"
echoContent yellow "\n ---> Port: ${port}"
if [[ -z "${btDomain}" ]]; then
checkDNSIP "${domain}"
removeNginxDefaultConf
checkPortOpen "${port}" "${domain}"
fi
else
echoContent red " ---> Port input error"
exit 0
fi
else
echoContent red " ---> Port cannot be empty"
exit 0
fi
fi
}

# Check if the port is occupied
checkPort() {
if [[ -n "$1" ]] && lsof -i "tcp:$1" | grep -q LISTEN; then
echoContent red "\n ---> $1 port is occupied, please close it manually before installing\n"
lsof -i "tcp:$1" | grep LISTEN
exit 0
fi
}

# Install TLS
installTLS() {
echoContent skyBlue "\nProgress $1/${totalProgress} : Apply for TLS certificate\n"
readAcmeTLS
local tlsDomain=${domain}

# Install tls
if [[ -f "/etc/v2ray-agent/tls/${tlsDomain}.crt" && -f "/etc/v2ray-agent/tls/${tlsDomain}.key" && -n $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]] || [[ -d "$HOME/.acme.sh/${tlsDomain}_ecc" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" ]] || [[ "${installedDNSAPIStatus}" == "true" ]]; then
        echoContent green " ---> Certificate detected"
        renewalTLS

        if [[ -z $(find /etc/v2ray-agent/tls/ -name "${tlsDomain}.crt") ]] || [[ -z $(find /etc/v2ray-agent/tls/ -name "${tlsDomain}.key") ]] || [[ -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]]; then
            if [[ "${installedDNSAPIStatus}" == "true" ]]; then
                sudo "$HOME/.acme.sh/acme.sh" --installcert -d "*.${dnsTLSDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
            else
                sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${tlsDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
fi
else
if [[ -d "$HOME/.acme.sh/${tlsDomain}_ecc" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" ]] || [[ "${installedDNSAPIStatus}" == "true" ]]; then
if [[ -z "${lastInstallationConfig}" ]]; then
echoContent yellow " ---> If it is not expired or the certificate is customized, please select [n]\n"
read -r -p "Do you want to reinstall? [y/n]:" reInstallStatus
if [[ "${reInstallStatus}" == "y" ]]; then
rm -rf /etc/v2ray-agent/tls/*
installTLS "$1"
fi
fi
fi
fi
elif [[ -d "$HOME/.acme.sh" ]] && [[ ! -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" || ! -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" ]]; then
switchDNSAPI
if [[ -z "${dnsAPIType}" ]]; then
echoContent yellow "\n ---> Do not use API to apply for certificate"
echoContent green " ---> Install TLS certificate, need to rely on port 80"
allowPort 80
fi
switchSSLType
customSSLEmail
selectAcmeInstallSSL
if [[ "${installedDNSAPIStatus}" == "true" ]]; then
            sudo "$HOME/.acme.sh/acme.sh" --installcert -d "*.${dnsTLSDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
        else
            sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${tlsDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
        fi

        if [[ ! -f "/etc/v2ray-agent/tls/${tlsDomain}.crt" || ! -f "/etc/v2ray-agent/tls/${tlsDomain}.key" ]] || [[ -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.key") || -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]]; then
tail -n 10 /etc/v2ray-agent/tls/acme.log
if [[ ${installTLSCount} == "1" ]]; then
echoContent red " ---> TLS installation failed, please check acme log"
exit 0
fi

installTLSCount=1
echo

if tail -n 10 /etc/v2ray-agent/tls/acme.log | grep -q "Could not validate email address as valid"; then
echoContent red " ---> Email cannot be verified by SSL vendor, please re-enter"
echo
customSSLEmail "validate email"
installTLS "$1"
else
installTLS "$1"
fi
fi

echoContent green " ---> TLS generated successfully"
else
echoContent yellow " ---> acme.sh not installed"
exit 0
fi
}

# Initialize random string
initRandomPath() {
local chars="abcdefghijklmnopqrtuxyz"
local initCustomPath=
for i in {1..4}; do
echo "${i}" >/dev/null
initCustomPath+="${chars:RANDOM%${#chars}:1}"
done
customPath=${initCustomPath}
}

# Custom/random path
randomPathFunction() {
if [[ -n $1 ]]; then
echoContent skyBlue "\nProgress $1/${totalProgress}: Generate a random path"
else
echoContent skyBlue "Generate a random path"
fi
if [[ -n "${currentPath}" && -z "${lastInstallationConfig}" ]]; then
echo
read -r -p "Read the last installation record. Do you want to use the path from the last installation? [y/n]:" historyPathStatus
echo
elif [[ -n "${currentPath}" && -n "${lastInstallationConfig}" ]]; then
historyPathStatus="y"
fi
if [[ "${historyPathStatus}" == "y" ]]; then
customPath=${currentPath}
echoContent green "---> Successfully used\n"
else
echoContent yellow "Please enter a custom path [e.g.: alone], no slashes are required, [Enter] Random path"
read -r -p 'Path:' customPath
if [[ -z "${customPath}" ]]; then
initRandomPath
currentPath=${customPath}
else
if [[ "${customPath: -2}" == "ws" ]]; then
echo
echoContent red " ---> Custom path cannot end with ws, otherwise the diversion path cannot be distinguished"
randomPathFunction "$1"
else
currentPath=${customPath}
fi
fi
fi
echoContent yellow "\n path:${currentPath}"
echoContent skyBlue "\n----------------------------"
}
# Random number
randomNum() {
if [[ "${release}" == "alpine" ]]; then
local ranNum=
ranNum="$(shuf -i "$1"-"$2" -n 1)"
echo "${ranNum}"
else
echo $((RANDOM % $2 + $1))
fi
}
# Nginx disguise blog
nginxBlog() {
if [[ -n "$1" ]]; then
echoContent skyBlue "\nProgress $1/${totalProgress}: Add disguise site"
else
echoContent yellow "\nStart adding disguise site"
fi

if [[ -d "${nginxStaticPath}" && -f "${nginxStaticPath}/check" ]]; then
echo
if [[ -z "${lastInstallationConfig}" ]]; then
read -r -p "Detected installation of disguise site, whether to reinstall [y/n]:" nginxBlogInstallStatus
else
nginxBlogInstallStatus="n"
fi

if [[ "${nginxBlogInstallStatus}" == "y" ]]; then
rm -rf "${nginxStaticPath}*"
            # randomNum=$((RANDOM % 6 + 1))
            randomNum=$(randomNum 1 9)
            if [[ "${release}" == "alpine" ]]; then
                wget -q -P "${nginxStaticPath}" "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${randomNum}.zip"
            else
                wget -q "${wgetShowProgressStatus}" -P "${nginxStaticPath}" "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${randomNum}.zip"
            fi

            unzip -o "${nginxStaticPath}html${randomNum}.zip" -d "${nginxStaticPath}" >/dev/null
rm -f "${nginxStaticPath}html${randomNum}.zip*"
echoContent green " ---> Add camouflage site successfully"
fi
else
randomNum=$(randomNum 1 9)
# randomNum=$((RANDOM % 6 + 1))

        rm - rf "${nginxStaticPath}*"

        if [[ "${release}" == "alpine" ]]; then
            wget -q -P "${nginxStaticPath}" "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/footer/blog/unable/html${randomNum}.zip"
        else
            wget -q "${wgetShowProgressStatus}" -P "${nginxStaticPath}" "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${randomNum}.zip"
        and

        unzip -o "${nginxStaticPath}html${randomNum}.zip" -d "${nginxStaticPath}" >/dev/null
        rm -f "${nginxStaticPath}html${randomNum}.zip*"
        echoContent green " ---> Echo Content green"
    and

} }

# Remove http_port_t encryption
updateSELinuxHTTPPortT() {

    $(find /usr/bin /usr/sbin | grep -w logctl) -xe >/etc/v2ray-agent/nginx_error.log 2>&1

    if find /usr/bin /usr/sbin | grep -q -w weeks && find /usr/bin /usr/sbin | grep -q -w getenforce && grep -E "31300|31302" </etc/v2ray-agent/nginx_error.log | grep -q "Permission denied"; then
        echoContent red " ---> update the SELinux operating system"
        if ! $(find /usr/bin /usr/sbin | grep -w weekly) port -l | grep http_port | grep -q 31300 ; then
            $ ( find / usr / bin / usr / sbin | grep -w weekday ) port - a - t http_port_t -p tcp 31300
            echoContent green " ---> http_port_t 31300 port_port"
        and

        if ! $(find /usr/bin /usr/sbin | grep -w weekly) port -l | grep http_port | grep -q 31302 ; then
            $ ( find / usr / bin / usr / sbin | grep -w weekday ) port - a - t http_port_t -p tcp 31302
            echoContent green " ---> http_port_t 31302 Echo_port"
        and
        handleNginx start

    else
        exit 0
    and
} }

# Install Nginx
handleNginx() {

    if ! echo "${selectCustomInstallType}" | grep -qwE ",7,|,8,|,7,8," && [[ -z$(pgrep -f "nginx") ]] && [[ "$1" == "start" ]]; then
        if [[ "${release}" == "alpine" ]]; then
            rc-service nginx start 2>/etc/v2ray-agent/nginx_error.log
        else
            systemctl start nginx 2 > / etc / v2ray - agent / nginx_error . log
        and

        sleep 0.5

        if [[ -z$(pgrep -f "nginx")]]; then
            echoContent red " ---> Enter Nginx"
            echoContent red " ---> Remove the echo content from the echo content red"
            nginx
            if grep -q "journalctl -xe" </etc/v2ray-agent/nginx_error.log; then
                updateSELinuxHTTPPortT
            and
        else
            echoContent green " ---> Enter Nginx"
        and

    elif [[ -n $(pgrep -f "nginx") ]] && [[ "$1" == "stop" ]]; then

        if [[ "${release}" == "alpine" ]]; then
            rc-service nginx stop
        else
            systemctl stop nginx
        and
        sleep 0.5

        if [[ -z ${btDomain} && -n$(pgrep -f "nginx")]]; then
            pgrep -f "nginx" | xargs kill -9
        and
        echoContent green " ---> Nginx port"
    and
} }

# Even if you have a tls license
installCronTLS() {
    if [[ -z "${btDomain}" ]]; then
        echoContent skyBlue "\nSpecifying $1/${totalProgress} : unsubscribed by default"
        crontab - l > / etc / v2ray - agent / backup_crontab . cron
        local historyCrontab
        historyCrontab=$(sed '/v2ray-agent/d;/acme.sh/d'/etc/v2ray-agent/backup_crontab.cron);
        echo "${historyCrontab}" >/etc/v2ray-agent/backup_crontab.cron
        echo " 30 1 * * * /bin/bash /etc/v2ray-agent/install.sh RenewTLS >> /etc/v2ray-agent/crontab_tls.log 2>&1" >>/etc/v2ray-agent/backup_crontab.cron
        crontab / etc / v2ray - agent / backup_crontab . cron
        echoContent green "\n ---> User's name is not available"
    and
} }
# Last year's geographic range
installCronUpdateGeo() {
    if [[ "${coreInstallType}" == "1" ]]; then
        if crontab -l | grep -q "UpdateGeo"; then
            echoContent red "\n ---> Enter the license plate, please load the box"
            exit 0
        and
        echoContent skyBlue "\nTranslation 1/1 : Last name of the new geocontent"
        crontab - l > / etc / v2ray - agent / backup_crontab . cron
        echo " 35 1 * * * /bin/bash /etc/v2ray-agent/install.sh UpdateGeo >> /etc/v2ray-agent/crontab_tls.log 2>&1" >>/etc/v2ray-agent/backup_crontab.cron
        crontab / etc / v2ray - agent / backup_crontab . cron

        echoContent green "\n ---> Added scheduled update geo file successfully"
fi
}

# Update certificate
renewalTLS() {

if [[ -n $1 ]]; then
echoContent skyBlue "\nProgress $1/1: Update certificate"
fi
readAcmeTLS
local domain=${currentHost}
if [[ -z "${currentHost}" && -n "${tlsDomain}" ]]; then
domain=${tlsDomain}
fi

if [[ -f "/etc/v2ray-agent/tls/ssl_type" ]]; then
if grep -q "buypass" <"/etc/v2ray-agent/tls/ssl_type"; then
sslRenewalDays=180
fi
fi
if [[ -d "$HOME/.acme.sh/${domain}_ecc" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]] || [[ "${installedDNSAPIStatus}" == "true" ]]; then
        modifyTime=

        if [[ "${installedDNSAPIStatus}" == "true" ]]; then
            modifyTime=$(stat --format=%z "$HOME/.acme.sh/*.${dnsTLSDomain}_ecc/*.${dnsTLSDomain}.cer")
        else
            modifyTime=$(stat --format=%z "$HOME/.acme.sh/${domain}_ecc/${domain}.cer")
        fi

        modifyTime=$(date +%s -d "${modifyTime}")
        currentTime=$(date +%s)
        ((stampDiff = currentTime - modifyTime))
((days = stampDiff / 86400))
((remainingDays = sslRenewalDays - days))

tlsStatus=${remainingDays}
if [[ ${remainingDays} -le 0 ]]; then
tlsStatus="Expired"
fi

echoContent skyBlue " ---> Certificate check date: $(date "+%F %H:%M:%S")"
echoContent skyBlue " ---> Certificate generation date: $(date -d @"${modifyTime}" +"%F %H:%M:%S")"
echoContent skyBlue " ---> Certificate generation days: ${days}"
echoContent skyBlue " ---> Certificate remaining days: "${tlsStatus}
echoContent skyBlue " ---> The certificate will be automatically updated on the last day before expiration. If the update fails, please update it manually."

if [[ ${remainingDays} -le 1 ]]; then
echoContent yellow " ---> Regenerate certificate"
handleNginx stop

if [[ "${coreInstallType}" == "1" ]]; then
handleXray stop
elif [[ "${coreInstallType}" == "2" ]]; then
handleV2Ray stop
fi

sudo "$HOME/.acme.sh/acme.sh" --cron --home "$HOME/.acme.sh"
sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${domain}" --fullchainpath /etc/v2ray-agent/tls/"${domain}.crt" --keypath /etc/v2ray-agent/tls/"${domain}.key" --ecc
reloadCore
handleNginx start
else
echoContent green " ---> Certificate is valid"
fi
elif [[ -f "/etc/v2ray-agent/tls/${tlsDomain}.crt" && -f "/etc/v2ray-agent/tls/${tlsDomain}.key" && -n $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]]; then
echoContent yellow " ---> Detected the use of custom certificates, unable to perform the renewal operation."
else
echoContent red " ---> Not installed"
fi
}
# Check the status of the TLS certificate
checkTLStatus() {

if [[ -d "$HOME/.acme.sh/${currentHost}_ecc" ]] && [[ -f "$HOME/.acme.sh/${currentHost}_ecc/${currentHost}.key" ]] && [[ -f "$HOME/.acme.sh/${currentHost}_ecc/${currentHost}.cer" ]]; then
        modifyTime=$(stat "$HOME/.acme.sh/${currentHost}_ecc/${currentHost}.cer" | sed -n '7,6p' | awk '{print $2" "$3" "$4" "$5}')

        modifyTime=$(date +%s -d "${modifyTime}")
        currentTime=$(date +%s)
        ((stampDiff = currentTime - modifyTime))
        ((days = stampDiff / 86400))
        ((remainingDays = sslRenewalDays - days))

        tlsStatus=${remainingDays}
        if [[ ${remainingDays} -le 0 ]]; then tlsStatus="Expired"
fi

echoContent skyBlue " ---> Certificate generation date: $(date -d "@${modifyTime}" +"%F %H:%M:%S")"
echoContent skyBlue " ---> Certificate generation days: ${days}"
echoContent skyBlue " ---> Certificate remaining days: ${tlsStatus}"
fi
}

# Install V2Ray, specify version
installV2Ray() {
readInstallType
echoContent skyBlue "\nProgress $1/${totalProgress} : Install V2Ray"

if [[ "${coreInstallType}" != "2" && "${coreInstallType}" != "3" ]]; then
if [[ "${selectCoreType}" == "2" ]]; then

version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases?per_page=10 | jq -r '.[]|select (.prerelease==false)|.tag_name' | grep -v 'v5' | head -1)
        else
            version=${v2rayCoreVersion}
        fi

        echoContent green " ---> v2ray-core版本:${version}"
        if [[ "${release}" == "alpine" ]]; then
            wget -c -q -P /etc/v2ray-agent/v2ray/ "https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip"
        else
            wget -c -q "${wgetShowProgressStatus}" -P /etc/v2ray-agent/v2ray/ "https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip"
        fi

        unzip -o "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip" -d /etc/v2ray-agent/v2ray >/dev/null
        rm -rf "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip"
    else
        if [[ "${selectCoreType}" == "3" ]]; then
            echoContent green " ---> 锁定v2ray-core版本为v4.32.1"
            rm -f /etc/v2ray-agent/v2ray/v2ray
            rm -f /etc/v2ray-agent/v2ray/v2ctl
            installV2Ray "$1"
        else
            echoContent green " ---> v2ray-core版本:$(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)"
            read -r -p "是否更新、升级？[y/n]:" reInstallV2RayStatus
            if [[ "${reInstallV2RayStatus}" == "y" ]]; then
                rm -f /etc/v2ray-agent/v2ray/v2ray
                rm -f /etc/v2ray-agent/v2ray/v2ctl
                installV2Ray "$1"
            fi
        fi
    fi
}

# 安装 sing-box
installSingBox() {
    readInstallType
    echoContent skyBlue "\n进度  $1/${totalProgress} : 安装sing-box"

    if [[ ! -f "/etc/v2ray-agent/sing-box/sing-box" ]]; then

        version=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases?per_page=20" | jq -r ".[]|select (.prerelease==${prereleaseStatus})|.tag_name" | head -1)

        echoContent green " ---> sing-box版本:${version}"

        if [[ "${release}" == "alpine" ]]; then
            wget -c -q -P /etc/v2ray-agent/sing-box/ "https://github.com/SagerNet/sing-box/releases/download/${version}/sing-box-${version/v/}${singBoxCoreCPUVendor}.tar.gz"
        else
            wget -c -q "${wgetShowProgressStatus}" -P /etc/v2ray-agent/sing-box/ "https://github.com/SagerNet/sing-box/releases/download/${version}/sing-box-${version/v/}${singBoxCoreCPUVendor}.tar.gz"
        fi

        if [[ ! -f "/etc/v2ray-agent/sing-box/sing-box-${version/v/}${singBoxCoreCPUVendor}.tar.gz" ]]; then
            read -r -p "核心下载失败，请重新尝试安装，是否重新尝试？[y/n]" downloadStatus
            if [[ "${downloadStatus}" == "y" ]]; then
                installSingBox "$1"
            fi
        else

            tar zxvf "/etc/v2ray-agent/sing-box/sing-box-${version/v/}${singBoxCoreCPUVendor}.tar.gz" -C "/etc/v2ray-agent/sing-box/" >/dev/null 2>&1

            mv "/etc/v2ray-agent/sing-box/sing-box-${version/v/}${singBoxCoreCPUVendor}/sing-box" /etc/v2ray-agent/sing-box/sing-box
            rm -rf /etc/v2ray-agent/sing-box/sing-box-*
            chmod 655 /etc/v2ray-agent/sing-box/sing-box
        fi
    else
        echoContent green " ---> sing-box版本:v$(/etc/v2ray-agent/sing-box/sing-box version | grep "sing-box version" | awk '{print $3}')"
        if [[ -z "${lastInstallationConfig}" ]]; then
            read -r -p "是否更新、升级？[y/n]:" reInstallSingBoxStatus
            if [[ "${reInstallSingBoxStatus}" == "y" ]]; then
                rm -f /etc/v2ray-agent/sing-box/sing-box
                installSingBox "$1"
            fi
        fi
    fi

}

# 检查wget showProgress
checkWgetShowProgress() {
    if [[ "${release}" != "alpine" ]]; then
        if find /usr/bin /usr/sbin | grep -q "/wget" && wget --help | grep -q show-progress; then
            wgetShowProgressStatus="--show-progress"
        fi
    fi
}
# 安装xray
installXray() {
    readInstallType
    local prereleaseStatus=false
    if [[ "$2" == "true" ]]; then
        prereleaseStatus=true
    fi

    echoContent skyBlue "\n进度  $1/${totalProgress} : 安装Xray"

    if [[ ! -f "/etc/v2ray-agent/xray/xray" ]]; then


        version=$(curl -s "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=5" | jq -r ".[]|select (.prerelease==${prereleaseStatus})|.tag_name" | head -1)
        echoContent green " ---> Xray-core version:${version}"
        if [[ "${release}" == "alpine" ]]; then
            wget -c -q -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip"
        else
            wget -c -q "${wgetShowProgressStatus}" -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip"
fi
if [[ ! -f "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip" ]]; then
read -r -p "Core download failed, please try again, do you want to try again? [y/n]" downloadStatus
if [[ "${downloadStatus}" == "y" ]]; then
installXray "$1"
fi
else
unzip -o "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip" -d /etc/v2ray-agent/xray >/dev/null
rm -rf "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip"
version=$(curl -s https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases?per_page=1 | jq -r '.[]|.tag_name')
            echoContent skyBlue "------------------------Version--------------------------------"
            echo "version:${version}"
            rm /etc/v2ray-agent/xray/geo* >/dev/null 2>&1

            if [[ "${release}" == "alpine" ]]; then
                wget -c -q -P /etc/v2ray-agent/xray/ "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/${version}/geosite.dat"
                wget -c -q -P /etc/v2ray-agent/xray/ "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/${version}/geoip.dat"
            else
                wget -c -q "${wgetShowProgressStatus}" -P /etc/v2ray-agent/xray/ "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/${version}/geosite.dat"
                wget -c -q "${wgetShowProgressStatus}" -P /etc/v2ray-agent/xray/ "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/${version}/geoip.dat"
            fi

            chmod 655 /etc/v2ray-agent/xray/xray
        fi
    else
        if [[ -z "${lastInstallationConfig}" ]]; then
echoContent green " ---> Xray-core version: $(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"
read -r -p "Update or upgrade? [y/n]:" reInstallXrayStatus
if [[ "${reInstallXrayStatus}" == "y" ]]; then
rm -f /etc/v2ray-agent/xray/xray
installXray "$1" "$2"
fi
fi
fi
}

# v2ray version management
v2rayVersionManageMenu() {
echoContent skyBlue "\nProgress $1/${totalProgress} : V2Ray version management"
if [[ ! -d "/etc/v2ray-agent/v2ray/" ]]; then
echoContent red " ---> No installation directory detected, please execute the script to install the content"
menu
exit 0
fi
echoContent red "\n==============================================================="
echoContent yellow "1. Upgrade v2ray-core"
echoContent yellow "2. Rollback v2ray-core"
echoContent yellow "3. Close v2ray-core"
echoContent yellow "4. Open v2ray-core"
echoContent yellow "5. Restart v2ray-core"
echoContent yellow "6. Update geosite, geoip"
echoContent yellow "7. Set automatic update of geo files [update every morning]"
echoContent red "================================================================"
read -r -p "Please select:" selectV2RayType
if [[ "${selectV2RayType}" == "1" ]]; then
updateV2Ray
elif [[ "${selectV2RayType}" == "2" ]]; then
echoContent yellow "\n1. Only the five most recent versions can be rolled back"
echoContent yellow "2. It is not guaranteed that it can be used normally after rolling back"
echoContent yellow "3. If the rolled back version does not support the current config, it will fail to connect, so operate with caution"
echoContent skyBlue "------------------------Version-------------------------------"
curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r '.[]|select (.prerelease==false)|.tag_name' | grep -v 'v5' | head -5 | awk '{print ""NR""":"$0}'

echoContent skyBlue "--------------------------------------------------------------"
read -r -p "Please enter the version to be rolled back:" selectV2rayVersionType

        version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r '.[]|select (.prerelease==false)|.tag_name' | grep -v 'v5' | head -5 | awk '{print ""NR""":"$0}' | grep "${selectV2rayVersionType}:" | awk -F "[:]" '{print $2}')
if [[ -n "${version}" ]]; then
updateV2Ray "${version}"
else
echoContent red "\n ---> Input error, please re-enter"
v2rayVersionManageMenu 1
fi
elif [[ "${selectV2RayType}" == "3" ]]; then
handleV2Ray stop
elif [[ "${selectV2RayType}" == "4" ]]; then
handleV2Ray start
elif [[ "${selectV2RayType}" == "5" ]]; then
reloadCore
elif [[ "${selectXrayType}" == "6" ]]; then
updateGeoSite
elif [[ "${selectXrayType}" == "7" ]]; then
installCronUpdateGeo
fi
}

# xray version management
xrayVersionManageMenu() {
echoContent skyBlue "\nProgress $1/${totalProgress} : Xray version management"
if [[ "${coreInstallType}" != "1" ]]; then
echoContent red " ---> No installation directory detected, please execute the script to install the content"
exit 0
fi
echoContent red "\n================================================================"
echoContent yellow "1. Upgrade Xray-core"
echoContent yellow "2. Upgrade Xray-core preview version"
echoContent yellow "3. Roll back Xray-core"
echoContent yellow "4. Close Xray-core"
echoContent yellow "5. Open Xray-core"
echoContent yellow "6. Restart Xray-core"
echoContent yellow "7. Update geosite, geoip"
echoContent yellow "8. Set automatic update of geo files [update every morning]"
echoContent yellow "9. View log"
echoContent red "================================================================"
read -r -p "Please select:" selectXrayType
if [[ "${selectXrayType}" == "1" ]]; then
prereleaseStatus=false
updateXray
elif [[ "${selectXrayType}" == "2" ]]; then
prereleaseStatus=true
updateXray
elif [[ "${selectXrayType}" == "3" ]]; then
echoContent yellow "\n1. Only the latest five versions can be rolled back"
echoContent yellow "2. It is not guaranteed that it can be used normally after rolling back"
echoContent yellow "3. If the rolled back version does not support the current config, it will fail to connect, so operate with caution"
echoContent skyBlue "------------------------Version-------------------------------"
curl -s "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=5" | jq -r ".[]|select (.prerelease==false)|.tag_name" | awk '{print ""NR""":"$0}'
echoContent skyBlue "--------------------------------------------------------------"
read -r -p "Please enter the version to be rolled back:" selectXrayVersionType
version=$(curl -s "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=5" | jq -r ".[]|select (.prerelease==false)|.tag_name" | awk '{print ""NR""":"$0}' | grep "${selectXrayVersionType}:" | awk -F "[:]" '{print $2}')
        if [[ -n "${version}" ]]; then
            updateXray "${version}"
        else
            echoContent red "\n ---> Incorrect input, please re-enter"
            xrayVersionManageMenu 1
        fi
    elif [[ "${selectXrayType}" == "4" ]]; then
        handleXray stop
    elif [[ "${selectXrayType}" == "5" ]]; then
        handleXray start
    elif [[ "${selectXrayType}" == "6" ]]; then
        reloadCore
    elif [[ "${selectXrayType}" == "7" ]]; then
        updateGeoSite
    elif [[ "${selectXrayType}" == "8" ]]; then
        installCronUpdateGeo
    elif [[ "${selectXrayType}" == "9" ]]; then
        checkLog 1    fi
}

# update geosite
updateGeoSite() {
    echoContent yellow "\nSource https://github.com/Loyalsoldier/v2ray-rules-dat"

    version=$(curl -s https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases?per_page=1 | jq -r '.[]|.tag_name')
    echoContent skyBlue "------------------------Version--------------------------------"
    echo "version:${version}"
    rm ${configPath}../geo* >/dev/null

    if [[ "${release}" == "alpine" ]]; then
        wget -c -q -P ${configPath}../ "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/${version}/geosite.dat"
        wget -c -q -P ${configPath}../ "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/${version}/geoip.dat"
    else

        wget -c -q "${wgetShowProgressStatus}" -P ${configPath}../ "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/${version}/geosite.dat"
        wget -c -q "${wgetShowProgressStatus}" -P ${configPath}../ "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/${version}/geoip.dat"
    fi

    reloadCore
    echoContent green " ---> Update completed"

}
# Update V2Ray
updateV2Ray() {
    readInstallType
    if [[ -z "${coreInstallType}" ]]; then

        if [[ -n "$1" ]]; then
            version=$1
        else
            version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r '.[]|select (.prerelease==false)|.tag_name' | grep -v 'v5' | head -1)
fi
# Use locked version
if [[ -n "${v2rayCoreVersion}" ]]; then
version=${v2rayCoreVersion}
fi
echoContent green " ---> v2ray-core version:${version}"
if [[ "${release}" == "alpine" ]]; then
wget -c -q -P /etc/v2ray-agent/v2ray/ "https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip"
else
wget -c -q "${wgetShowProgressStatus}" -P /etc/v2ray-agent/v2ray/ "https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip"
        fi

        unzip -o "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip" -d /etc/v2ray-agent/v2ray >/dev/null
        rm -rf "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip"
        handleV2Ray stop
        handleV2Ray start
    else
        echoContent green " ---> Current v2ray-core version: $(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)"

        if [[ -n "$1" ]]; then
            version=$1 else
version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r '.[]|select (.prerelease==false)|.tag_name' | grep -v 'v5' | head -1)
fi
if [[ -n "${v2rayCoreVersion}" ]]; then
version=${v2rayCoreVersion}
fi
if [[ -n "$1" ]]; then
read -r -p "The rollback version is ${version}, do you want to continue? [y/n]:" rollbackV2RayStatus
if [[ "${rollbackV2RayStatus}" == "y" ]]; then
if [[ "${coreInstallType}" == "2" ]]; then
echoContent green " ---> Current v2ray-core version: $(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)"
elif [[ "${coreInstallType}" == "1" ]]; then
echoContent green " ---> Current Xray-core version: $(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"
fi

handleV2Ray stop
rm -f /etc/v2ray-agent/v2ray/v2ray
rm -f /etc/v2ray-agent/v2ray/v2ctl
updateV2Ray "${version}"
else
echoContent green " ---> Abandon the fallback version"
fi
elif [[ "${version}" == "v$(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)" ]]; then
read -r -p "The current version is the same as the latest version. Do you want to reinstall? [y/n]:" reInstallV2RayStatus
if [[ "${reInstallV2RayStatus}" == "y" ]]; then
handleV2Ray stop
rm -f /etc/v2ray-agent/v2ray/v2ray
rm -f /etc/v2ray-agent/v2ray/v2ctl
updateV2Ray
else
echoContent green " ---> Give up reinstallation"
fi
else
read -r -p "The latest version is: ${version}. Do you want to update? [y/n]:" installV2RayStatus
if [[ "${installV2RayStatus}" == "y" ]]; then
                rm -f /etc/v2ray-agent/v2ray/v2ray
                rm -f /etc/v2ray-agent/v2ray/v2ctl
                updateV2Ray
            else
                echoContent green " ---> Abort update"
            fi

        fi
    fi
}

# Update Xray
updateXray() {
    readInstallType

    if [[ -z "${coreInstallType}" || "${coreInstallType}" != "1" ]]; then
        if [[ -n "$1" ]]; then
            version=$1
        else

            version=$(curl -s "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=5" | jq -r ".[]|select (.prerelease==${prereleaseStatus})|.tag_name" | head -1)
        fi

        echoContent green " ---> Xray-core版本:${version}"

        if [[ "${release}" == "alpine" ]]; then
            wget -c -q -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip"
        else
            wget -c -q "${wgetShowProgressStatus}" -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip"
        fi

        unzip -o "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip" -d /etc/v2ray-agent/xray >/dev/null
        rm -rf "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip"
        chmod 655 /etc/v2ray-agent/xray/xray
        handleXray stop
        handleXray start
    else
        echoContent green " ---> 当前Xray-core版本:$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"

        if [[ -n "$1" ]]; then
            version=$1
        else
            version=$(curl -s "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=10" | jq -r ".[]|select (.prerelease==${prereleaseStatus})|.tag_name" | head -1)
        fi

        if [[ -n "$1" ]]; then
            read -r -p "回退版本为${version}，是否继续？[y/n]:" rollbackXrayStatus
            if [[ "${rollbackXrayStatus}" == "y" ]]; then
                echoContent green " ---> 当前Xray-core版本:$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"

                handleXray stop
                rm -f /etc/v2ray-agent/xray/xray
                updateXray "${version}"
            else
                echoContent green " ---> 放弃回退版本"
            fi
        elif [[ "${version}" == "v$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)" ]]; then
            read -r -p "当前版本与最新版相同，是否重新安装？[y/n]:" reInstallXrayStatus
            if [[ "${reInstallXrayStatus}" == "y" ]]; then
                handleXray stop
                rm -f /etc/v2ray-agent/xray/xray
                updateXray
            else
                echoContent green " ---> 放弃重新安装"
            fi
        else
            read -r -p "最新版本为:${version}，是否更新？[y/n]:" installXrayStatus
            if [[ "${installXrayStatus}" == "y" ]]; then
                rm /etc/v2ray-agent/xray/xray
                updateXray
            else
                echoContent green " ---> 放弃更新"
            fi

        fi
    fi
}

# 验证整个服务是否可用
checkGFWStatue() {
    readInstallType
    echoContent skyBlue "\n进度 $1/${totalProgress} : 验证服务启动状态"
    if [[ "${coreInstallType}" == "1" ]] && [[ -n $(pgrep -f "xray/xray") ]]; then
        echoContent green " ---> 服务启动成功"
    elif [[ "${coreInstallType}" == "2" ]] && [[ -n $(pgrep -f "sing-box/sing-box") ]]; then
        echoContent green " ---> 服务启动成功"
    else
        echoContent red " ---> 服务启动失败，请检查终端是否有日志打印"
        exit 0
    fi
}

# 安装hysteria开机自启
installHysteriaService() {
    echoContent skyBlue "\n进度  $1/${totalProgress} : 配置Hysteria开机自启"
    if [[ -n $(find /bin /usr/bin -name "systemctl") ]]; then
        rm -rf /etc/systemd/system/hysteria.service
        touch /etc/systemd/system/hysteria.service
        execStart='/etc/v2ray-agent/hysteria/hysteria server -c /etc/v2ray-agent/hysteria/conf/config.json --log-level debug'
        cat <<EOF >/etc/systemd/system/hysteria.service
[Unit]
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/etc/v2ray-agent/hysteria/hysteria server -c /etc/v2ray-agent/hysteria/conf/config.json --log-level debug
Restart=on-failure
RestartSec=10
LimitNPROC=infinity
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable hysteria.service
        echoContent green " ---> 配置Hysteria开机自启成功"
    fi
}


# 安装alpine开机启动
installAlpineStartup() {
    local serviceName=$1
    if [[ "${serviceName}" == "sing-box" ]]; then
        cat <<EOF >"/etc/init.d/${serviceName}"
#!/sbin/openrc-run

description="sing-box service"
command="/etc/v2ray-agent/sing-box/sing-box"
command_args="run -c /etc/v2ray-agent/sing-box/conf/config.json"
command_background=true
pidfile="/var/run/sing-box.pid"
EOF
    elif [[ "${serviceName}" == "xray" ]]; then
        cat <<EOF >"/etc/init.d/${serviceName}"
#!/sbin/openrc-run

description="xray service"
command="/etc/v2ray-agent/xray/xray"
command_args="run -confdir /etc/v2ray-agent/xray/conf"
command_background=true
pidfile="/var/run/xray.pid"
EOF
    fi

    chmod +x "/etc/init.d/${serviceName}"
}

# sing-box开机自启
installSingBoxService() {
    echoContent skyBlue "\n进度  $1/${totalProgress} : 配置sing-box开机自启"
    execStart='/etc/v2ray-agent/sing-box/sing-box run -c /etc/v2ray-agent/sing-box/conf/config.json'

    if [[ -n $(find /bin /usr/bin -name "systemctl") && "${release}" != "alpine" ]]; then
        rm -rf /etc/systemd/system/sing-box.service
        touch /etc/systemd/system/sing-box.service
        cat <<EOF >/etc/systemd/system/sing-box.service
[Unit]
Description=Sing-Box Service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=${execStart}
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
LimitNPROC=infinity
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
        bootStartup "sing-box.service"
    elif [[ "${release}" == "alpine" ]]; then
        installAlpineStartup "sing-box"
        bootStartup "sing-box"
    fi

    echoContent green " ---> 配置sing-box开机启动完毕"
}

# Xray开机自启
installXrayService() {
    echoContent skyBlue "\n进度  $1/${totalProgress} : 配置Xray开机自启"
    execStart='/etc/v2ray-agent/xray/xray run -confdir /etc/v2ray-agent/xray/conf'
    if [[ -n $(find /bin /usr/bin -name "systemctl") ]]; then
        rm -rf /etc/systemd/system/xray.service
        touch /etc/systemd/system/xray.service
        cat <<EOF >/etc/systemd/system/xray.service
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target
[Service]
User=root
ExecStart=${execStart}
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=infinity
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF
        bootStartup "xray.service"
        echoContent green " ---> 配置Xray开机自启成功"
    elif [[ "${release}" == "alpine" ]]; then
        installAlpineStartup "xray"
        bootStartup "xray"
    fi
}

# 操作Hysteria
handleHysteria() {
    # shellcheck disable=SC2010
    if find /bin /usr/bin | grep -q systemctl && ls /etc/systemd/system/ | grep -q hysteria.service; then
        if [[ -z $(pgrep -f "hysteria/hysteria") ]] && [[ "$1" == "start" ]]; then
            systemctl start hysteria.service
        elif [[ -n $(pgrep -f "hysteria/hysteria") ]] && [[ "$1" == "stop" ]]; then
            systemctl stop hysteria.service
        fi
    fi
    sleep 0.8

    if [[ "$1" == "start" ]]; then
        if [[ -n $(pgrep -f "hysteria/hysteria") ]]; then
            echoContent green " ---> Hysteria启动成功"
        else
            echoContent red "Hysteria启动失败"
            echoContent red "请手动执行【/etc/v2ray-agent/hysteria/hysteria --log-level debug -c /etc/v2ray-agent/hysteria/conf/config.json server】，查看错误日志"
            exit 0
        fi
    elif [[ "$1" == "stop" ]]; then
        if [[ -z $(pgrep -f "hysteria/hysteria") ]]; then
            echoContent green " ---> Hysteria关闭成功"
        else
            echoContent red "Hysteria关闭失败"
            echoContent red "请手动执行【ps -ef|grep -v grep|grep hysteria|awk '{print \$2}'|xargs kill -9】"
            exit 0
        fi
    fi
}

# 操作Tuic

handleTuic() {
    # shellcheck disable=SC2010
    if find /bin /usr/bin | grep -q systemctl && ls /etc/systemd/system/ | grep -q tuic.service; then
        if [[ -z $(pgrep -f "tuic/tuic") ]] && [[ "$1" == "start" ]]; then
            singBoxMergeConfig
            systemctl start tuic.service
        elif [[ -n $(pgrep -f "tuic/tuic") ]] && [[ "$1" == "stop" ]]; then
            systemctl stop tuic.service
        fi
    elif [[ -f "/etc/init.d/tuic" ]]; then
        if [[ -z $(pgrep -f "tuic/tuic") ]] && [[ "$1" == "start" ]]; then
            singBoxMergeConfig rc-service tuic start
elif [[ -n $(pgrep -f "tuic/tuic") ]] && [[ "$1" == "stop" ]]; then
rc-service tuic stop
fi
fi
sleep 0.8

if [[ "$1" == "start" ]]; then
if [[ -n $(pgrep -f "tuic/tuic") ]]; then
echoContent green "---> Tuic started successfully"
else
echoContent red "Tuic started failed"
echoContent red "Please manually execute [/etc/v2ray-agent/tuic/tuic -c /etc/v2ray-agent/tuic/conf/config.json], check the error log"
exit 0
fi
elif [[ "$1" == "stop" ]]; then
if [[ -z $(pgrep -f "tuic/tuic") ]]; then
echoContent green "---> Tuic shutdown successful"
else
echoContent red "Tuic shutdown failed"
echoContent red "Please manually execute [ps -ef|grep -v grep|grep tuic|awk '{print \$2}'|xargs kill -9]"
exit 0
fi
fi
}

# Operation sing-box
handleSingBox() {
if [[ -f "/etc/systemd/system/sing-box.service" ]]; then
if [[ -z $(pgrep -f "sing-box") ]] && [[ "$1" == "start" ]]; then
singBoxMergeConfig
systemctl start sing-box.service
elif [[ -n $(pgrep -f "sing-box") ]] && [[ "$1" == "stop" ]]; then
systemctl stop sing-box.service
fi
elif [[ -f "/etc/init.d/sing-box" ]]; then
        if [[ -z $(pgrep -f "sing-box") ]] && [[ "$1" == "start" ]]; then
            singBoxMergeConfig
            rc-service sing-box start
        elif [[ -n $(pgrep -f "sing-box") ]] && [[ "$1" == "stop" ]]; then
            rc-service sing-box stop
        fi
    fi
    sleep 1

    if [[ "$1" == "start" ]]; then
        if [[ -n $(pgrep -f "sing-box") ]]; then
            echoContent green " ---> sing-box started successfully"
        else
            echoContent red "sing-box failed to start"
            echoContent yellow "Please execute manually【 /etc/v2ray-agent/sing-box/sing-box merge config.json -C /etc/v2ray-agent/sing-box/conf/config/ -D /etc/v2ray-agent/sing-box/conf/ 】，check the error log"
echo
echoContent yellow "If there is no error in the above command, please manually execute [ /etc/v2ray-agent/sing-box/sing-box run -c /etc/v2ray-agent/sing-box/conf/config.json ]，check the error log"
exit 0
fi
elif [[ "$1" == "stop" ]]; then
if [[ -z $(pgrep -f "sing-box") ]]; then
echoContent green " ---> sing-box is closed successfully"
else
echoContent red " ---> sing-box is closed failed"
echoContent red "Please manually execute [ps -ef|grep -v grep|grep sing-box|awk '{print \$2}'|xargs kill -9]"
exit 0
        fi
    fi
}

# Manipulate xray
handleXray() {
    if [[ -n $(find /bin /usr/bin -name "systemctl") ]] && [[ -n $(find /etc/systemd/system/ -name "xray.service") ]]; then
        if [[ -z $(pgrep -f "xray/xray") ]] && [[ "$1" == "start" ]]; then
            systemctl start xray.service
        elif [[ -n $(pgrep -f "xray/xray") ]] && [[ "$1" == "stop" ]]; then
            systemctl stop xray.service
        fi
    elif [[ -f "/etc/init.d/xray" ]]; then
        if [[ -z $(pgrep -f "xray/xray") ]] && [[ "$1" == "start" ]]; then
rc-service xray start
elif [[ -n $(pgrep -f "xray/xray") ]] && [[ "$1" == "stop" ]]; then
rc-service xray stop
fi
fi
sleep 0.8

if [[ "$1" == "start" ]]; then
if [[ -n $(pgrep -f "xray/xray") ]]; then
echoContent green "---> Xray started successfully"
else
echoContent red "Xray failed to start"
echoContent red "Please manually execute the following command [/etc/v2ray-agent/xray/xray -confdir /etc/v2ray-agent/xray/conf] to feedback the error log"

exit 0
fi
elif [[ "$1" == "stop" ]]; then
if [[ -z $(pgrep -f "xray/xray") ]]; then
echoContent green " ---> Xray shutdown successful"
else
echoContent red "xray shutdown failed"
echoContent red "Please manually execute [ps -ef|grep -v grep|grep xray|awk '{print \$2}'|xargs kill -9]"
exit 0
fi
fi
}

# Read Xray user data and initialize
initXrayClients() {
local type=",$1,"
local newUUID=$2
local newEmail=$3
if [[ -n "${newUUID}" ]]; then
local newUser=
        newUser="{\"id\":\"${uuid}\",\"flow\":\"xtls-rprx-vision\",\"email\":\"${newEmail}-VLESS_TCP/TLS_Vision\"}"
        currentClients=$(echo "${currentClients}" | jq -r ". +=[${newUser}]")
    fi
    local users=
    users=[]
    while read -r user; do
        uuid=$(echo "${user}" | jq -r .id//.uuid)
        email=$(echo "${user}" | jq -r .email//.name | awk -F "[-]" '{print $1}')
        currentUser=
        if echo "${type}" | grep -q "0"; then            currentUser="{\"id\":\"${uuid}\",\"flow\":\"xtls-rprx-vision\",\"email\":\"${email}-VLESS_TCP/TLS_Vision\"}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        #VLESSWS
        if echo "${type}" | grep -q ",1,"; then
            currentUser="{\"id\":\"${uuid}\",\"email\":\"${email}-VLESS_WS\"}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi
        # VLESS XHTTP
        if echo "${type}" | grep -q ",12,"; then            currentUser="{\"id\":\"${uuid}\",\"email\":\"${email}-VLESS_XHTTP\"}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi
        #trojan grpc
        if echo "${type}" | grep -q ",2,"; then
            currentUser="{\"password\":\"${uuid}\",\"email\":\"${email}-Trojan_gRPC\"}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi
        #VMessWS
        if echo "${type}" | grep -q ",3,"; then            currentUser="{\"id\":\"${uuid}\",\"email\":\"${email}-VMess_WS\",\"alterId\": 0}"

            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        #trojantcp
        if echo "${type}" | grep -q ",4,"; then
            currentUser="{\"password\":\"${uuid}\",\"email\":\"${email}-trojan_tcp\"}"

            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        # vless grpc
        if echo "${type}" | grep -q ",5,"; then            currentUser="{\"id\":\"${uuid}\",\"email\":\"${email}-vless_grpc\"}"

            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        #hysteria
        if echo "${type}" | grep -q ",6,"; then
            currentUser="{\"password\":\"${uuid}\",\"name\":\"${email}-singbox_hysteria2\"}"

            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        #vless reality vision
        if echo "${type}" | grep -q ",7,"; then            currentUser="{\"id\":\"${uuid}\",\"email\":\"${email}-vless_reality_vision\",\"flow\":\"xtls-rprx-vision\"}"

            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        #vless reality grpc
        if echo "${type}" | grep -q ",8,"; then
            currentUser="{\"id\":\"${uuid}\",\"email\":\"${email}-vless_reality_grpc\",\"flow\":\"\"}"

            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi
        #tuic
        if echo "${type}" | grep -q ",9,"; then currentUser="{\"uuid\":\"${uuid}\",\"password\":\"${uuid}\",\"name\":\"${email}-singbox_tuic\"}"

users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
fi

done < <(echo "${currentClients}" | jq -c '.[]')
echo "${users}"
}
# Read singbox user data and initialize
initSingBoxClients() {
local type=",$1,"
local newUUID=$2
local newName=$3

if [[ -n "${newUUID}" ]]; then
local newUser=
        newUser="{\"uuid\":\"${newUUID}\",\"flow\":\"xtls-rprx-vision\",\"name\":\"${newName}-VLESS_TCP/TLS_Vision\"}"

        currentClients=$(echo "${currentClients}" | jq -r ". +=[${newUser}]")
    fi
    local users=
    users=[]
    while read -r user; do
        uuid=$(echo "${user}" | jq -r .uuid//.id//.password)
        name=$(echo "${user}" | jq -r .name//.email//.username | awk -F "[-]" '{print $1}')
        currentUser=
        # VLESS Vision
        if echo "${type}" | grep -q ",0,"; then
            currentUser="{\"uuid\":\"${uuid}\",\"flow\":\"xtls-rprx-vision\",\"name\":\"${name}-VLESS_TCP/TLS_Vision\"}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi
        # VLESS WS
        if echo "${type}" | grep -q ",1,"; then
            currentUser="{\"uuid\":\"${uuid}\",\"name\":\"${name}-VLESS_WS\"}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi
        # VMess ws
        if echo "${type}" | grep -q ",3,"; then
            currentUser="{\"uuid\":\"${uuid}\",\"name\":\"${name}-VMess_WS\",\"alterId\": 0}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        # trojan
        if echo "${type}" | grep -q ",4,"; then
            currentUser="{\"password\":\"${uuid}\",\"name\":\"${name}-Trojan_TCP\"}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        # VLESS Reality Vision
        if echo "${type}" | grep -q ",7,"; then
            currentUser="{\"uuid\":\"${uuid}\",\"flow\":\"xtls-rprx-vision\",\"name\":\"${name}-VLESS_Reality_Vision\"}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi
        # VLESS Reality gRPC
        if echo "${type}" | grep -q ",8,"; then
            currentUser="{\"uuid\":\"${uuid}\",\"name\":\"${name}-VLESS_Reality_gPRC\"}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        # hysteria2
        if echo "${type}" | grep -q ",6,"; then
            currentUser="{\"password\":\"${uuid}\",\"name\":\"${name}-singbox_hysteria2\"}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        # tuic
        if echo "${type}" | grep -q ",9,"; then
            currentUser="{\"uuid\":\"${uuid}\",\"password\":\"${uuid}\",\"name\":\"${name}-singbox_tuic\"}"

            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        # naive
        if echo "${type}" | grep -q ",10,"; then
            currentUser="{\"password\":\"${uuid}\",\"username\":\"${name}-singbox_naive\"}"

            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi
        # VMess HTTPUpgrade
        if echo "${type}" | grep -q ",11,"; then
            currentUser="{\"uuid\":\"${uuid}\",\"name\":\"${name}-VMess_HTTPUpgrade\",\"alterId\": 0}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        if echo "${type}" | grep -q ",20,"; then
            currentUser="{\"username\":\"${uuid}\",\"password\":\"${uuid}\"}"

            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

    done < <(echo "${currentClients}" | jq -c '.[]')
    echo "${users}"
}

# 添加hysteria配置
addClientsHysteria() {
    local path=$1
    local addClientsStatus=$2

    if [[ ${addClientsStatus} == "true" && -n "${previousClients}" ]]; then
        local uuids=
        uuids=$(echo "${previousClients}" | jq -r [.[].id])

        if [[ "${frontingType}" == "02_trojan_TCP_inbounds" ]]; then
            uuids=$(echo "${previousClients}" | jq -r [.[].password])
        fi
        config=$(jq -r ".auth.config = ${uuids}" "${path}")
        echo "${config}" | jq . >"${path}"
    fi
}

# 初始化hysteria端口
initHysteriaPort() {
    readSingBoxConfig
    if [[ -n "${hysteriaPort}" ]]; then
        read -r -p "读取到上次安装时的端口，是否使用上次安装时的端口？[y/n]:" historyHysteriaPortStatus
        if [[ "${historyHysteriaPortStatus}" == "y" ]]; then
            echoContent yellow "\n ---> 端口: ${hysteriaPort}"
        else
            hysteriaPort=
        fi
    fi

    if [[ -z "${hysteriaPort}" ]]; then

echoContent yellow "Please enter the Hysteria port [Enter random 10000-30000], which cannot be repeated with other services"
read -r -p "Port:" hysteriaPort
if [[ -z "${hysteriaPort}" ]]; then
hysteriaPort=$((RANDOM % 20001 + 10000))
fi
fi
if [[ -z ${hysteriaPort} ]]; then
echoContent red "---> Port cannot be empty"
initHysteriaPort "$2"
elif ((hysteriaPort < 1 || hysteriaPort > 65535)); then
echoContent red "---> Port is illegal"
initHysteriaPort "$2"
fi
allowPort "${hysteriaPort}"
allowPort "${hysteriaPort}" "udp"
}

# Initialize the hysteria protocol
initHysteriaProtocol() {
echoContent skyBlue "\nPlease select the protocol type"
echoContent red "================================================================"
echoContent yellow "1.udp(QUIC)(default)"
echoContent yellow "2.faketcp"
echoContent yellow "3.wechat-video"
echoContent red "===================================================================="
read -r -p "Please select:" selectHysteriaProtocol
case ${selectHysteriaProtocol} in
1)
hysteriaProtocol="udp"
;;
2)
hysteriaProtocol="faketcp"
;;
3)
hysteriaProtocol="wechat-video"
;;
*)
hysteriaProtocol="udp"
;;
esac
echoContent yellow "\n ---> Protocol: ${hysteriaProtocol}\n"
}

# Initialize hysteria network information
initHysteria2Network() {

echoContent yellow "Please enter the local bandwidth peak downlink speed (default: 100, unit: Mbps)"
read -r -p "Downlink speed:" hysteria2ClientDownloadSpeed
if [[ -z "${hysteria2ClientDownloadSpeed}" ]]; then
hysteria2ClientDownloadSpeed=100
echoContent yellow "\n ---> Downlink speed: ${hysteria2ClientDownloadSpeed}\n"
fi

echoContent yellow "Please enter the local bandwidth peak upload speed (default: 50, unit: Mbps)"
read -r -p "Uplink speed:" hysteria2ClientUploadSpeed
if [[ -z "${hysteria2ClientUploadSpeed}" ]]; then
hysteria2ClientUploadSpeed=50
echoContent yellow "\n ---> Uplink speed: ${hysteria2ClientUploadSpeed}\n"
fi
}

# firewalld set port jump
addFirewalldPortHopping() {

local start=$1
local end=$2
local targetPort=$3
for port in $(seq "$start" "$end"); do
sudo firewall-cmd --permanent --add-forward-port=port="${port}":proto=udp:toport="${targetPort}"
done
sudo firewall-cmd --reload
}
# Port Hopping
addPortHopping() {
local type=$1
local targetPort=$2
if [[ -n "${portHoppingStart}" || -n "${portHoppingEnd}" ]]; then
echoContent red " ---> Already added, cannot be added again, can be deleted and added again"
exit 0
fi
if [[ "${release}" == "centos" ]]; then
if ! systemctl status firewalld 2>/dev/null | grep -q "active (running)"; then
echoContent red " ---> Firewalld is not started, port hopping cannot be set."
exit 0
fi
fi
echoContent skyBlue "\nProgress 1/1: Port Hopping"
echoContent red "\n==============================================================="
echoContent yellow "# Notes\n"
echoContent yellow "Only supports Hysteria2 and Tuic"
echoContent yellow "The starting position of port hopping is 30000"
echoContent yellow "The end position of port hopping is 40000"
echoContent yellow "You can choose a range from 30000 to 40000"
echoContent yellow "It is recommended to set about 1000"
echoContent yellow "Be careful not to set the same range as other port hopping ranges, otherwise they will be overwritten."

echoContent yellow "Please enter the range of port hopping, for example [30000-31000]"

read -r -p "Range:" portHoppingRange
if [[ -z "${portHoppingRange}" ]]; then
        echoContent red " ---> Range cannot be empty"
        addPortHopping "${type}" "${targetPort}"
    elif echo "${portHoppingRange}" | grep -q "-"; then

        local portStart=
        local portEnd=
        portStart=$(echo "${portHoppingRange}" | awk -F '-' '{print $1}')
        portEnd=$(echo "${portHoppingRange}" | awk -F '-' '{print $2}')

        if [[ -z "${portStart}" || -z "${portEnd}" ]]; then
            echoContent red " ---> The range is illegal"
            addPortHopping "${type}" "${targetPort}"
        elif ((portStart < 30000 || portStart > 40000 || portEnd < 30000 || portEnd > 40000 || portEnd < portStart)); then
echoContent red "---> Invalid range"
addPortHopping "${type}" "${targetPort}"
else
echoContent green "\nPort range: ${portHoppingRange}\n"

            if [[ "${release}" == "centos" ]]; then
                sudo firewall-cmd --permanent --add-masquerade
                sudo firewall-cmd --reload
                addFirewalldPortHopping "${portStart}" "${portEnd}" "${targetPort}"
                if ! sudo firewall-cmd --list-forward-ports | grep -q "toport=${targetPort}"; then
                    echoContent red " ---> Failed to add port hopping"
                    exit 0
                fi
            else
                iptables -t nat -A PREROUTING -p udp --dport "${portStart}:${portEnd}" -m comment --comment "mack-a_${type}_portHopping" -j DNAT --to-destination ":${targetPort}"
                sudo netfilter-persistent save
                if ! iptables-save | grep -q "mack-a_${type}_portHopping"; then
echoContent red " ---> Port hopping failed to add"
exit 0
fi
fi
allowPort "${portStart}:${portEnd}" udp
echoContent green " ---> Port hopping successfully added"
fi
fi
}

# Read port hopping configuration
readPortHopping() {
local type=$1
local targetPort=$2
local portHoppingStart=
local portHoppingEnd=

if [[ "${release}" == "centos" ]]; then
portHoppingStart=$(sudo firewall-cmd --list-forward-ports | grep "toport=${targetPort}" | head -1 | cut -d ":" -f 1 | cut -d "=" -f 2)
portHoppingEnd=$(sudo firewall-cmd --list-forward-ports | grep "toport=${targetPort}" | tail -n 1 | cut -d ":" -f 1 | cut -d "=" -f 2)
    else
        if iptables-save | grep -q "mack-a_${type}_portHopping"; then
            local portHopping=
            portHopping=$(iptables-save | grep "mack-a_${type}_portHopping" | cut -d " " -f 8)

            portHoppingStart=$(echo "${portHopping}" | cut -d ":" -f 1)
            portHoppingEnd=$(echo "${portHopping}" | cut -d ":" -f 2)
        fi
    fi
    if [[ "${type}" == "hysteria2" ]]; then
        hysteria2PortHoppingStart="${portHoppingStart}"
        hysteria2PortHoppingEnd=${portHoppingEnd}        hysteria2PortHopping="${portHoppingStart}-${portHoppingEnd}"
    elif [[ "${type}" == "tuic" ]]; then
        tuicPortHoppingStart="${portHoppingStart}"
        tuicPortHoppingEnd="${portHoppingEnd}"
        tuicPortHopping="${portHoppingStart}-${portHoppingEnd}"
    fi
}
# Delete port hopping iptables rules
deletePortHoppingRules() {
    local type=$1
    local start=$2
    local end=$3
    local targetPort=$4

    if [[ "${release}" == "centos" ]]; then
        for port in $(seq "${start}" "${end}"); do
            sudo firewall-cmd --permanent --remove-forward-port=port="${port}":proto=udp:toport="${targetPort}"
        done sudo firewall-cmd --reload
else
iptables -t nat -L PREROUTING --line-numbers | grep "mack-a_${type}_portHopping" | awk '{print $1}' | while read -r line; do
iptables -t nat -D PREROUTING 1
sudo netfilter-persistent save
done
fi
}

# Port Hopping Menu
portHoppingMenu() {
local type=$1
# Check if iptables exists
if ! find /usr/bin /usr/sbin | grep -q -w iptables; then
echoContent red " ---> Unable to identify iptables tool, unable to use port hopping, exit installation"
exit 0
fi

local targetPort=
local portHoppingStart=
local portHoppingEnd=

if [[ "${type}" == "hysteria2" ]]; then
readPortHopping "${type}" "${singBoxHysteria2Port}"
        targetPort=${singBoxHysteria2Port}
        portHoppingStart=${hysteria2PortHoppingStart}
        portHoppingEnd=${hysteria2PortHoppingEnd}
    elif [[ "${type}" == "tuic" ]]; then
        readPortHopping "${type}" "${singBoxTuicPort}"
        targetPort=${singBoxTuicPort}
        portHoppingStart=${tuicPortHoppingStart}
        portHoppingEnd=${tuicPortHoppingEnd}
    fi

    echoContent skyBlue "\nProgress 1/1: Port jump"
    echoContent red "\n================================================================"
echoContent yellow "1. Add port hopping"
echoContent yellow "2. Delete port hopping"
echoContent yellow "3. View port hopping"
read -r -p "Please select:" selectPortHoppingStatus
if [[ "${selectPortHoppingStatus}" == "1" ]]; then

        addPortHopping "${type}" "${targetPort}"
elif [[ "${selectPortHoppingStatus}" == "2" ]]; then
deletePortHoppingRules "${type}" "${portHoppingStart}" "${portHoppingEnd}" "${targetPort}"
echoContent green " ---> Successfully deleted"
elif [[ "${selectPortHoppingStatus}" == "3" ]]; then
if [[ -n "${portHoppingStart}" && -n "${portHoppingEnd}" ]]; then
echoContent green " ---> Current port hopping range is: ${portHoppingStart}-${portHoppingEnd}"
else
echoContent yellow " ---> Port hopping is not set"
fi
else
portHoppingMenu
fi
}
# Initialize Hysteria configuration
initHysteriaConfig() {
echoContent skyBlue "\nProgress $1/${totalProgress} : Initialize Hysteria configuration"

    initHysteriaPort
    #initHysteriaProtocol
    # initHysteriaNetwork
    local uuid=
    uuid=$(${ctlPath} uuid)
    cat <<EOF >/etc/v2ray-agent/hysteria/conf/config.json
{
    "listen":":${hysteriaPort}",
    "tls":{
        "cert": "/etc/v2ray-agent/tls/${currentHost}.crt",
        "key": "/etc/v2ray-agent/tls/${currentHost}.key"
    },
    "auth":{
        "type": "password",
        "password": "${uuid}"
    },
    "resolver":{
      "type": "https",
      "https":{
        "addr": "1.1.1.1:443",
        "timeout": "10s"
      }
    },
    "outbounds":{
      "name": "socks5_outbound_route",
        "type": "socks5",
        "socks5":{
            "addr": "127.0.0.1:31295",
            "username": "hysteria_socks5_outbound_route",
            "password": "${uuid}"
        }
    }
}

EOF

    # addClientsHysteria "/etc/v2ray-agent/hysteria/conf/config.json" true

    # Add socks inbound
    cat <<EOF >${configPath}/02_socks_inbounds_hysteria.json
{
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 31295,
"protocol": "Socks",
"tag": "socksHysteriaOutbound",
"settings": {
"auth": "password",
"accounts": [
{
"user": "hysteria_socks5_outbound_route",
"pass": "${uuid}"
}
],
"udp": true,
"ip": "127.0.0.1"
}
}
]
}
EOF
}

# Initialize tuic port
initTuicPort() {
readSingBoxConfig
if [[ -n "${tuicPort}" ]]; then
read -r -p "Read the port from the last installation. Do you want to use the port from the last installation? [y/n]:" historyTuicPortStatus
if [[ "${historyTuicPortStatus}" == "y" ]]; then
echoContent yellow "\n ---> Port: ${tuicPort}"
else
tuicPort=
fi
fi
if [[ -z "${tuicPort}" ]]; then
echoContent yellow "Please enter the Tuic port [Enter random 10000-30000], which cannot be repeated with other services"
read -r -p "Port:" tuicPort
if [[ -z "${tuicPort}" ]]; then
tuicPort=$((RANDOM % 20001 + 10000))
fi
fi
if [[ -z ${tuicPort} ]]; then
echoContent red "---> Port cannot be empty"
initTuicPort "$2"
elif ((tuicPort < 1 || tuicPort > 65535)); then
echoContent red "---> Port is illegal"
initTuicPort "$2"
fi
echoContent green "\n ---> Port: ${tuicPort}"
allowPort "${tuicPort}"
allowPort "${tuicPort}" "udp"
}

# Initialize tuic's protocol
initTuicProtocol() {
if [[ -n "${tuicAlgorithm}" && -z "${lastInstallationConfig}" ]]; then
read -r -p "Read the algorithm used last time, do you want to use it? [y/n]:" historyTuicAlgorithm
if [[ "${historyTuicAlgorithm}" != "y" ]]; then
tuicAlgorithm=
else
echoContent yellow "\n ---> Algorithm: ${tuicAlgorithm}\n"
fi
elif [[ -n "${tuicAlgorithm}" && -n "${lastInstallationConfig}" ]]; then
echoContent yellow "\n ---> Algorithm: ${tuicAlgorithm}\n"
fi

if [[ -z "${tuicAlgorithm}" ]]; then

echoContent skyBlue "\nPlease select the algorithm type"
echoContent red "==================================================================="
echoContent yellow "1.bbr(default)"
echoContent yellow "2.cubic"
echoContent yellow "3.new_reno"
echoContent red "========================================================================"
read -r -p "Please select:" selectTuicAlgorithm
        case ${selectTuicAlgorithm} in
        1)
            tuicAlgorithm="bbr"
            ;;
        2)

tuicAlgorithm="cubic"
;;
3)
tuicAlgorithm="new_reno"
;;
*)
tuicAlgorithm="bbr"
;;
esac
echoContent yellow "\n ---> Algorithm: ${tuicAlgorithm}\n"
fi
}

# Initialize tuic configuration
#initTuicConfig() {
# echoContent skyBlue "\nProgress $1/${totalProgress} : Initialize Tuic configuration"
#
# initTuicPort
# initTuicProtocol
# cat <<EOF >/etc/v2ray-agent/tuic/conf/config.json
#{
# "server": "[::]:${tuicPort}",
# "users": $(initXrayClients 9),
# "certificate": "/etc/v2ray-agent/tls/${currentHost}.crt",
# "private_key": "/etc/v2ray-agent/tls/${currentHost}.key",
# "congestion_control":"${tuicAlgorithm}",
# "alpn": ["h3"],
# "log_level": "warn"
#}
#EOF
#}

# Initialize sing-box Tuic configuration
initSingBoxTuicConfig() {
echoContent skyBlue "\nProgress $1/${totalProgress} : Initialize Tuic configuration"

initTuicPort
initTuicProtocol
cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/06_hysteria2_inbounds.json
{
"inbounds": [
{
"type": "tuic",
"listen": "::",
        "tag": "singbox-tuic-in",
        "listen_port": ${tuicPort},
        "users": $(initXrayClients 9),
        "congestion_control": "${tuicAlgorithm}",
        "tls": {
            "enabled": true,
            "server_name":"${currentHost}",
            "alpn": [
                "h3"
            ],
            "certificate_path": "/etc/v2ray-agent/tls/${currentHost}.crt",
            "key_path": "/etc/v2ray-agent/tls/${currentHost}.key"
        }
    }
]
}
EOF
}

# Initialize singbox route configuration
initSingBoxRouteConfig() {
    downloadSingBoxGeositeDB
    local outboundTag=$1
    if [[ ! -f "${singBoxConfigPath}${outboundTag}_route.json" ]]; then
        cat <<EOF >"${singBoxConfigPath}${outboundTag}_route.json"
{
    "route": {
        "geosite": {
            "path": "${singBoxConfigPath}geosite.db"
        },
        "rules": [
            {
                "domain": [
                ],
                "geosite": [
                ],
                "outbound": "${outboundTag}"
            }
        ]
    }
}
EOF
    fi
}
# Download sing-box geosite db
downloadSingBoxGeositeDB() {
    if [[ ! -f "${singBoxConfigPath}geosite.db" ]]; then
        if [[ "${release}" == "alpine" ]]; then
            wget -q -P "${singBoxConfigPath}" https://github.com/Johnshall/sing-geosite/releases/latest/download/geosite.db
else
wget -q "${wgetShowProgressStatus}" -P "${singBoxConfigPath}" https://github.com/Johnshall/sing-geosite/releases/latest/download/geosite.db
fi

fi
}

# Add sing-box routing rules
addSingBoxRouteRule() {
local outboundTag=$1
# Domain name list
local domainList=$2
# Routing file name
local routingName=$3
# Read the last installation content
if [[ -f "${singBoxConfigPath}${routingName}.json" ]]; then
read -r -p "Read the last configuration, do you want to keep it? [y/n]:" historyRouteStatus
if [[ "${historyRouteStatus}" == "y" ]]; then
            domainList="${domainList},$(jq -rc .route.rules[0].rule_set[] "${singBoxConfigPath}${routingName}.json" | awk -F "[_]" '{print $1}' | paste -sd ',')"
            domainList="${domainList},$(jq -rc .route.rules[0].domain_regex[] "${singBoxConfigPath}${routingName}.json" | awk -F "[*]" '{print $2}' | paste -sd ',' | sed 's/\\//g')"
        fi
    fi
    local rules=
    rules=$(initSingBoxRules "${domainList}" "${routingName}")
    # domain exact matching rules
    local domainRules=
    domainRules=$(echo "${rules}" | jq .domainRules)

    # ruleSetRule set
    local ruleSet=
    ruleSet=$(echo "${rules}" | jq .ruleSet)

    # ruleSet rule tag
    local ruleSetTag=[]
    if [[ "$(echo "${ruleSet}" | jq '.|length')" != "0" ]]; then
        ruleSetTag=$(echo "${ruleSet}" | jq '.|map(.tag)')
    fi
    if [[ -n "${singBoxConfigPath}" ]]; then

        cat <<EOF >"${singBoxConfigPath}${routingName}.json"
{
  "route": {
    "rules": [
      {
        "rule_set":${ruleSetTag},
        "domain_regex":${domainRules},
        "outbound": "${outboundTag}"
      }
    ],    "rule_set":${ruleSet}
  }
}
EOF

        jq 'if .route.rule_set == [] then del(.route.rule_set) else . end' "${singBoxConfigPath}${routingName}.json" >"${singBoxConfigPath}${routingName}_tmp.json" && mv "${singBoxConfigPath}${routingName}_tmp.json" "${singBoxConfigPath}${routingName}.json"
    fi

}

# 移除sing-box route rule
removeSingBoxRouteRule() {
    local outboundTag=$1
    local delRules
    if [[ -f "${singBoxConfigPath}${outboundTag}_route.json" ]]; then
        delRules=$(jq -r 'del(.route.rules[]|select(.outbound=="'"${outboundTag}"'"))' "${singBoxConfigPath}${outboundTag}_route.json")
        echo "${delRules}" >"${singBoxConfigPath}${outboundTag}_route.json"
    fi
}

# 添加sing-box出站
addSingBoxOutbound() {
    local tag=$1
    local type="ipv4"
    local detour=$2
    if echo "${tag}" | grep -q "IPv6"; then
        type=ipv6
    fi
    if [[ -n "${detour}" ]]; then
        cat <<EOF >"${singBoxConfigPath}${tag}.json"
{
     "outbounds": [
        {
             "type": "direct",
             "tag": "${tag}",
             "detour": "${detour}",
             "domain_strategy": "${type}_only"
        }
    ]
}
EOF
    elif echo "${tag}" | grep -q "direct"; then

        cat <<EOF >"${singBoxConfigPath}${tag}.json"
{
     "outbounds": [
        {
             "type": "direct",
             "tag": "${tag}"
        }
    ]
}
EOF
    elif echo "${tag}" | grep -q "block"; then

        cat <<EOF >"${singBoxConfigPath}${tag}.json"
{
     "outbounds": [
        {
             "type": "block",
             "tag": "${tag}"
        }
    ]
}
EOF
    else
        cat <<EOF >"${singBoxConfigPath}${tag}.json"
{
     "outbounds": [
        {
             "type": "direct",
             "tag": "${tag}",
             "domain_strategy": "${type}_only"
        }
    ]
}
EOF
    fi
}

# 添加Xray-core 出站
addXrayOutbound() {
    local tag=$1
    local domainStrategy=

    if echo "${tag}" | grep -q "IPv4"; then
        domainStrategy="ForceIPv4"
    elif echo "${tag}" | grep -q "IPv6"; then
        domainStrategy="ForceIPv6"
    fi

    if [[ -n "${domainStrategy}" ]]; then
        cat <<EOF >"/etc/v2ray-agent/xray/conf/${tag}.json"
{
    "outbounds":[
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"${domainStrategy}"
            },
            "tag":"${tag}"
        }
    ]
}
EOF
    fi
    # direct
    if echo "${tag}" | grep -q "direct"; then
        cat <<EOF >"/etc/v2ray-agent/xray/conf/${tag}.json"
{
    "outbounds":[
        {
            "protocol":"freedom",
            "settings": {
                "domainStrategy":"UseIP"
            },
            "tag":"${tag}"
        }
    ]
}
EOF
    fi
    # blackhole
    if echo "${tag}" | grep -q "blackhole"; then
        cat <<EOF >"/etc/v2ray-agent/xray/conf/${tag}.json"
{
    "outbounds":[
        {
            "protocol":"blackhole",
            "tag":"${tag}"
        }
    ]
}
EOF
    fi
    # socks5 outbound
    if echo "${tag}" | grep -q "socks5"; then
        cat <<EOF >"/etc/v2ray-agent/xray/conf/${tag}.json"
{
  "outbounds": [
    {
      "protocol": "socks",
      "tag": "${tag}",
      "settings": {
        "servers": [
          {
            "address": "${socks5RoutingOutboundIP}",
            "port": ${socks5RoutingOutboundPort},
            "users": [
              {
                "user": "${socks5RoutingOutboundUserName}",
                "pass": "${socks5RoutingOutboundPassword}"
              }
            ]
          }
        ]
      }
    }
  ]
}
EOF
    fi
    if echo "${tag}" | grep -q "wireguard_out_IPv4"; then
        cat <<EOF >"/etc/v2ray-agent/xray/conf/${tag}.json"
{
  "outbounds": [
    {
      "protocol": "wireguard",
      "settings": {
        "secretKey": "${secretKeyWarpReg}",
        "address": [
          "${address}"
        ],
        "peers": [
          {
            "publicKey": "${publicKeyWarpReg}",
            "allowedIPs": [
              "0.0.0.0/0",
              "::/0"
            ],

            "endpoint": "162.159.192.1:2408"
          }
        ],
        "reserved": ${reservedWarpReg},
        "mtu": 1280
      },
      "tag": "${tag}"
    }
  ]
}
EOF
    fi
    if echo "${tag}" | grep -q "wireguard_out_IPv6"; then
        cat <<EOF >"/etc/v2ray-agent/xray/conf/${tag}.json"
{
  "outbounds": [
    {
      "protocol": "wireguard",
      "settings": {
        "secretKey": "${secretKeyWarpReg}",
        "address": [
          "${address}"
        ],
        "peers": [
          {
            "publicKey": "${publicKeyWarpReg}",
            "allowedIPs": [
              "0.0.0.0/0",
              "::/0"
            ],
            "endpoint": "162.159.192.1:2408"
          }
        ],
        "reserved": ${reservedWarpReg},
        "mtu": 1280
      },
      "tag": "${tag}"
    }
  ]
}
EOF
    fi
    if echo "${tag}" | grep -q "vmess-out"; then
        cat <<EOF >"/etc/v2ray-agent/xray/conf/${tag}.json"
{
  "outbounds": [
    {
      "tag": "${tag}",
      "protocol": "vmess",
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "allowInsecure": false
        },
        "wsSettings": {
          "path": "${setVMessWSTLSPath}"
        }
      },
      "mux": {
        "enabled": true,
        "concurrency": 8
      },
      "settings": {
        "vnext": [
          {
            "address": "${setVMessWSTLSAddress}",
            "port": "${setVMessWSTLSPort}",
            "users": [
              {
                "id": "${setVMessWSTLSUUID}",
                "security": "auto",
                "alterId": 0
              }
            ]
          }
        ]
      }
    }
  ]
}
EOF
    fi
}

# 删除 Xray-core出站
removeXrayOutbound() {
    local tag=$1
    if [[ -f "/etc/v2ray-agent/xray/conf/${tag}.json" ]]; then
        rm "/etc/v2ray-agent/xray/conf/${tag}.json" >/dev/null 2>&1
    fi
}
# 移除sing-box配置
removeSingBoxConfig() {

    local tag=$1
    if [[ -f "${singBoxConfigPath}${tag}.json" ]]; then
        rm "${singBoxConfigPath}${tag}.json"
    fi
}

# 初始化wireguard出站信息
addSingBoxWireGuardEndpoints() {
    local type=$1

    readConfigWarpReg

    cat <<EOF >"${singBoxConfigPath}wireguard_endpoints_${type}.json"
{
     "endpoints": [
        {
            "type": "wireguard",
            "tag": "wireguard_endpoints_${type}",
            "address": [
                "${address}"
            ],
            "private_key": "${secretKeyWarpReg}",
            "peers": [
                {
                  "address": "162.159.192.1",
                  "port": 2408,
                  "public_key": "${publicKeyWarpReg}",
                  "reserved":${reservedWarpReg},
                  "allowed_ips": ["0.0.0.0/0","::/0"]
                }
            ]
        }
    ]
}
EOF
}

# 初始化 sing-box Hysteria2 配置
initSingBoxHysteria2Config() {
    echoContent skyBlue "\n进度 $1/${totalProgress} : 初始化Hysteria2配置"

    initHysteriaPort
    initHysteria2Network

    cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/hysteria2.json
{
    "inbounds": [
        {
            "type": "hysteria2",
            "listen": "::",
            "listen_port": ${hysteriaPort},
            "users": $(initXrayClients 6),
            "up_mbps":${hysteria2ClientDownloadSpeed},
            "down_mbps":${hysteria2ClientUploadSpeed},
            "tls": {
                "enabled": true,
                "server_name":"${currentHost}",
                "alpn": [
                    "h3"
                ],
                "certificate_path": "/etc/v2ray-agent/tls/${currentHost}.crt",
                "key_path": "/etc/v2ray-agent/tls/${currentHost}.key"
            }
        }
    ]
}
EOF
}

# sing-box Tuic安装
singBoxTuicInstall() {
    if ! echo "${currentInstallProtocolType}" | grep -qE ",0,|,1,|,2,|,3,|,4,|,5,|,6,|,9,|,10,"; then
        echoContent red "\n ---> 由于需要依赖证书，如安装Tuic，请先安装带有TLS标识协议"
        exit 0
    fi

    totalProgress=5
    installSingBox 1
    selectCustomInstallType=",9,"

initSingBoxConfig custom 2 true
installSingBoxService 3
reloadCore
showAccounts 4
}

# sing-box hy2 installation
singBoxHysteria2Install() {
if ! echo "${currentInstallProtocolType}" | grep -qE ",0,|,1,|,2,|,3,|,4,|,5,|,6,|,9,|,10,"; then
echoContent red "\n ---> Since it needs to rely on certificates, if you install Hysteria2, please install the protocol with TLS identification first"
exit 0
fi

totalProgress=5
installSingBox 1
selectCustomInstallType=",6,"
initSingBoxConfig custom 2 true
installSingBoxService 3
reloadCore
showAccounts 4
}

# merge config
singBoxMergeConfig() {
rm /etc/v2ray-agent/sing-box/conf/config.json >/dev/null 2>&1
/etc/v2ray-agent/sing-box/sing-box merge config.json -C /etc/v2ray-agent/sing-box/conf/config/ -D /etc/v2ray-agent/sing-box/conf/ >/dev/null 2>&1
}

# Initialize Xray Trojan XTLS configuration file
#initXrayFrontingConfig() {
# echoContent red " ---> Trojan does not support xtls-rprx-vision yet"
# if [[ -z "${configPath}" ]]; then
# echoContent red " ---> Not installed, please use script to install"
# menu
# exit 0
# fi
# if [[ "${coreInstallType}" != "1" ]]; then
# echoContent red " ---> Unavailable types are not installed"
# fi
# local xtlsType=
# if echo ${currentInstallProtocolType} | grep -q trojan; then
# xtlsType=VLESS
# else
# xtlsType=Trojan
# fi
#
# echoContent skyBlue "\nFunction 1/${totalProgress}: Prefix is switched to ${xtlsType}"
# echoContent red "\n==============================================================="
# echoContent yellow "# Notes\n"
# echoContent yellow "Will replace the prefix with ${xtlsType}"
# echoContent yellow "If the frontend is Trojan, two nodes of the Trojan protocol will appear when checking the account, and one of them is unavailable xtls"
# echoContent yellow "Execute again to switch to the previous frontend\n"
#
# echoContent yellow "1. Switch to ${xtlsType}"
# echoContent red "=============================================================="
# read -r -p "Please select:" selectType
# if [[ "${selectType}" == "1" ]]; then
#
# if [[ "${xtlsType}" == "Trojan" ]]; then
#
# local VLESSConfig
# VLESSConfig=$(cat ${configPath}${frontingType}.json)
#            VLESSConfig=${VLESSConfig//"id"/"password"}
# VLESSConfig=${VLESSConfig//VLESSTCP/TrojanTCPXTLS}
# VLESSConfig=${VLESSConfig//VLESS/Trojan}
# VLESSConfig=${VLESSConfig//"vless"/"trojan"}
# VLESSConfig=${VLESSConfig//"id"/"password"}
#
# echo "${VLESSConfig}" | jq . >${configPath}02_trojan_TCP_inbounds.json
# rm ${configPath}${frontingType}.json
# elif [[ "${xtlsType}" == "VLESS" ]]; then
#
# local VLESSConfig
# VLESSConfig=$(cat ${configPath}02_trojan_TCP_inbounds.json)
#            VLESSConfig=${VLESSConfig//"password"/"id"}
# VLESSConfig=${VLESSConfig//TrojanTCPXTLS/VLESSTCP}
# VLESSConfig=${VLESSConfig//Trojan/VLESS}
# VLESSConfig=${VLESSConfig//"trojan"/"vless"}
# VLESSConfig=${VLESSConfig//"password"/"id"}
#
# echo "${VLESSConfig}" | jq . >${configPath}02_VLESS_TCP_inbounds.json
# rm ${configPath}02_trojan_TCP_inbounds.json
# fi
# reloadCore
# fi
#
# exit 0
#}

#Initialize sing-box port
initSingBoxPort() {
    local port=$1
    if [[ -n "${port}" && -z "${lastInstallationConfig}" ]]; then
read -r -p "Read the last used port, do you want to use it? [y/n]:" historyPort
if [[ "${historyPort}" != "y" ]]; then
port=
else
echo "${port}"
fi
elif [[ -n "${port}" && -n "${lastInstallationConfig}" ]]; then
echo "${port}"
fi
if [[ -z "${port}" ]]; then
read -r -p 'Please enter a custom port [must be legal], the port cannot be repeated, [Enter] random port:' port
if [[ -z "${port}" ]]; then
port=$((RANDOM % 50001 + 10000))
fi
if ((port >= 1 && port <= 65535)); then
allowPort "${port}"
allowPort "${port}" "udp"
echo "${port}"
else
echoContent red " ---> Port input error"
exit 0
fi
fi
}

# Initialize Xray configuration file
initXrayConfig() {
echoContent skyBlue "\nProgress $2/${totalProgress} : Initialize Xray configuration"
echo
local uuid=

    local addClientsStatus=
if [[ -n "${currentUUID}" && -z "${lastInstallationConfig}" ]]; then
read -r -p "Read the last user configuration, do you want to use the last installed configuration? [y/n]:" historyUUIDStatus
if [[ "${historyUUIDStatus}" == "y" ]]; then
addClientsStatus=true
echoContent green "\n ---> Successfully used"
fi
elif [[ -n "${currentUUID}" && -n "${lastInstallationConfig}" ]]; then
addClientsStatus=true
fi

if [[ -z "${addClientsStatus}" ]]; then
echoContent yellow "Please enter a custom UUID [must be legal], [Enter] Random UUID"
read -r -p 'UUID:' customUUID

if [[ -n ${customUUID} ]]; then
uuid=${customUUID}
else
uuid=$(/etc/v2ray-agent/xray/xray uuid)
fi

echoContent yellow "\nPlease enter a custom username [must be legal], [Enter] random username"
read -r -p 'Username:' customEmail
if [[ -z ${customEmail} ]]; then
customEmail="$(echo "${uuid}" | cut -d "-" -f 1)-VLESS_TCP/TLS_Vision"
fi
fi

if [[ -z "${addClientsStatus}" && -z "${uuid}" ]]; then
addClientsStatus=
echoContent red "\n ---> uuid read error, randomly generated"
uuid=$(/etc/v2ray-agent/xray/xray uuid)
    fi

    if [[ -n "${uuid}" ]]; then
        currentClients='[{"id":"'${uuid}'","add":"'${add}'","flow":"xtls-rprx-vision","email":"'${customEmail}'"}]'
        echoContent yellow "\n ${customEmail}:${uuid}"
    fi

    # log
    if [[ ! -f "/etc/v2ray-agent/xray/conf/00_log.json" ]]; then

        cat <<EOF >/etc/v2ray-agent/xray/conf/00_log.json
{
  "log": {
    "error": "/etc/v2ray-agent/xray/error.log",
    "loglevel": "warning",
    "dnsLog": false
  }
}
EOF
    fi

    if [[ ! -f "/etc/v2ray-agent/xray/conf/12_policy.json" ]]; then

        cat <<EOF >/etc/v2ray-agent/xray/conf/12_policy.json
{
  "policy": {
      "levels": {
          "0": {
              "handshake": $((1 + RANDOM % 4)),
              "connIdle": $((250 + RANDOM % 51))
          }
      }
  }
}
EOF
    fi

    addXrayOutbound "z_direct_outbound"
    #dns
    if [[ ! -f "/etc/v2ray-agent/xray/conf/11_dns.json" ]]; then
        cat <<EOF >/etc/v2ray-agent/xray/conf/11_dns.json
{
    "dns": {
        "servers": [
          "localhost"        ]
  }
}
EOF
    fi
    #routing
    cat <<EOF >/etc/v2ray-agent/xray/conf/09_routing.json
{
  "routing": {
    "rules": [
      {
        "type": "field",
        "domain": [
          "domain:gstatic.com",
          "domain:googleapis.com",
	  "domain:googleapis.cn"
        ],
        "outboundTag": "z_direct_outbound"
      }
    ]
  }
}
EOF
    # VLESS_TCP_TLS_Vision
    # Fall back nginx
    local fallbacksList='{"dest":31300,"xver":1},{"alpn":"h2","dest":31302,"xver":1}'

    #trojan
    if echo "${selectCustomInstallType}" | grep -q ",4," || [[ "$1" == "all" ]]; then
        fallbacksList='{"dest":31296,"xver":1},{"alpn":"h2","dest":31302,"xver":1}'
        cat <<EOF >/etc/v2ray-agent/xray/conf/04_trojan_TCP_inbounds.json
{
"inbounds":[
	{
	  "port": 31296,
	  "listen": "127.0.0.1",
	  "protocol": "trojan",
	  "tag":"trojanTCP",
	  "settings": {
		"clients": $(initXrayClients 4),
		"fallbacks":[
			{
			    "dest":"31300",
			    "xver":1
			}
		]
	  },
	  "streamSettings": {
		"network": "tcp",
		"security": "none",
		"tcpSettings": {			"acceptProxyProtocol": true
		}
	  }
	}
	]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/xray/conf/04_trojan_TCP_inbounds.json >/dev/null 2>&1
    fi

    # VLESS_WS_TLS
    if echo "${selectCustomInstallType}" | grep -q ",1," || [[ "$1" == "all" ]]; then
        fallbacksList=${fallbacksList}',{"path":"/'${customPath}'ws","dest":31297,"xver":1}'
        cat <<EOF >/etc/v2ray-agent/xray/conf/03_VLESS_WS_inbounds.json
{
"inbounds":[
    {
	  "port": 31297,	  "listen": "127.0.0.1",
	  "protocol": "vless",
	  "tag":"VLESSWS",
	  "settings": {
		"clients": $(initXrayClients 1),
		"decryption": "none"
	  },
	  "streamSettings": {
		"network": "ws",
		"security": "none",
		"wsSettings": {
		  "acceptProxyProtocol": true,
		  "path": "/${customPath}ws"
		}

	  }
	}
]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/xray/conf/03_VLESS_WS_inbounds.json >/dev/null 2>&1
    fi
    # VLESS_XHTTP_TLS
    if echo "${selectCustomInstallType}" | grep -q ",12," || [[ "$1" == "all" ]]; then
        initXrayXHTTPort
        initRealityClientServersName
        initRealityKey
        cat <<EOF >/etc/v2ray-agent/xray/conf/12_VLESS_XHTTP_inbounds.json
{
"inbounds":[
    {
	  "port": ${xHTTPort},
	  "listen": "0.0.0.0",
	  "protocol": "vless",
	  "tag":"VLESSRealityXHTTP",
	  "settings": {
		"clients": $(initXrayClients 12),
		"decryption": "none"
	  },
	  "streamSettings": {
		"network": "xhttp",
		"security": "reality",
		"realitySettings": {
            "show": false,
            "dest": "${realityServerName}:${realityDomainPort}",
            "xver": 0,
            "serverNames": [
                "${realityServerName}"
            ],
            "privateKey": "${realityPrivateKey}",
            "publicKey": "${realityPublicKey}",
            "maxTimeDiff": 70000,
            "shortIds": [
                "",
                "6ba85179e30d4fc2"
            ]
        },
        "xhttpSettings": {
            "host": "${realityServerName}",
            "path": "/${customPath}xHTTP",
            "mode": "auto"
        }
	  }
	}
]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/xray/conf/12_VLESS_XHTTP_inbounds.json >/dev/null 2>&1
    fi
    # trojan_grpc
    #    if echo "${selectCustomInstallType}" | grep -q ",2," || [[ "$1" == "all" ]]; then
    #        if ! echo "${selectCustomInstallType}" | grep -q ",5," && [[ -n ${selectCustomInstallType} ]]; then
    #            fallbacksList=${fallbacksList//31302/31304}
    #        fi
    #        cat <<EOF >/etc/v2ray-agent/xray/conf/04_trojan_gRPC_inbounds.json
    #{
    #    "inbounds": [
    #        {
    #            "port": 31304,
    #            "listen": "127.0.0.1",
    #            "protocol": "trojan",
    #            "tag": "trojangRPCTCP",
    #            "settings": {
    #                "clients": $(initXrayClients 2),
    #                "fallbacks": [
    #                    {
    #                        "dest": "31300"
    #                    }
    #                ]
    #            },
    #            "streamSettings": {
    #                "network": "grpc",
    #                "grpcSettings": {
    #                    "serviceName": "${customPath}trojangrpc"
    #                }
    #            }
    #        }
    #    ]
    #}
    #EOF
    #    elif [[ -z "$3" ]]; then
    #        rm /etc/v2ray-agent/xray/conf/04_trojan_gRPC_inbounds.json >/dev/null 2>&1
    #    fi

    # VMess_WS
    if echo "${selectCustomInstallType}" | grep -q ",3," || [[ "$1" == "all" ]]; then
        fallbacksList=${fallbacksList}',{"path":"/'${customPath}'vws","dest":31299,"xver":1}'
        cat <<EOF >/etc/v2ray-agent/xray/conf/05_VMess_WS_inbounds.json
{
"inbounds":[
{
  "listen": "127.0.0.1",
  "port": 31299,
  "protocol": "vmess",
  "tag":"VMessWS",
  "settings": {
    "clients": $(initXrayClients 3)
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}vws"
    }
  }
}
]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/xray/conf/05_VMess_WS_inbounds.json >/dev/null 2>&1
    fi
    # VLESS_gRPC
    if echo "${selectCustomInstallType}" | grep -q ",5," || [[ "$1" == "all" ]]; then
        cat <<EOF >/etc/v2ray-agent/xray/conf/06_VLESS_gRPC_inbounds.json
{
    "inbounds":[
        {
            "port": 31301,
            "listen": "127.0.0.1",
            "protocol": "vless",
            "tag":"VLESSGRPC",
            "settings": {
                "clients": $(initXrayClients 5),
                "decryption": "none"
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "${customPath}grpc"

                }
            }
        }
    ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/xray/conf/06_VLESS_gRPC_inbounds.json >/dev/null 2>&1
    fi

    # VLESS Vision
    if echo "${selectCustomInstallType}" | grep -q ",0," || [[ "$1" == "all" ]]; then

        cat <<EOF >/etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json
{
    "inbounds":[
        {
          "port": ${port},
          "protocol": "vless",
          "tag":"VLESSTCP",
          "settings": {
            "clients":$(initXrayClients 0),
            "decryption": "none",
            "fallbacks": [
                ${fallbacksList}
            ]
          },
          "add": "${add}",
          "streamSettings": {
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {
              "rejectUnknownSni": true,
              "minVersion": "1.2",
              "certificates": [
                {
                  "certificateFile": "/etc/v2ray-agent/tls/${domain}.crt",
                  "keyFile": "/etc/v2ray-agent/tls/${domain}.key",
                  "ocspStapling": 3600
                }
              ]
            }
          }
        }
    ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json >/dev/null 2>&1
    fi

    # VLESS_TCP/reality
    if echo "${selectCustomInstallType}" | grep -q ",7," || [[ "$1" == "all" ]]; then
        echoContent skyBlue "\n===================== 配置VLESS+Reality =====================\n"

        initXrayRealityPort
        initRealityClientServersName
        initRealityKey

        cat <<EOF >/etc/v2ray-agent/xray/conf/07_VLESS_vision_reality_inbounds.json
{
  "inbounds": [
    {
      "port": ${realityPort},
      "protocol": "vless",
      "tag": "VLESSReality",
      "settings": {
        "clients": $(initXrayClients 7),
        "decryption": "none",
        "fallbacks":[
            {
                "dest": "31305",
                "xver": 1
            }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "show": false,
            "dest": "${realityServerName}:${realityDomainPort}",
            "xver": 0,
            "serverNames": [
                "${realityServerName}"
            ],
            "privateKey": "${realityPrivateKey}",
            "publicKey": "${realityPublicKey}",
            "maxTimeDiff": 70000,
            "shortIds": [
                "",
                "6ba85179e30d4fc2"
            ]
        }
      }
    }
  ]
}
EOF

        cat <<EOF >/etc/v2ray-agent/xray/conf/08_VLESS_vision_gRPC_inbounds.json
{
  "inbounds": [
    {
      "port": 31305,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "tag": "VLESSRealityGRPC",
      "settings": {
        "clients": $(initXrayClients 8),
        "decryption": "none"
      },
      "streamSettings": {
            "network": "grpc",
            "grpcSettings": {
                "serviceName": "grpc",
                "multiMode": true
            },
            "sockopt": {
                "acceptProxyProtocol": true
            }
      }
    }
  ]
}
EOF

    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/xray/conf/07_VLESS_vision_reality_inbounds.json >/dev/null 2>&1
        rm /etc/v2ray-agent/xray/conf/08_VLESS_vision_gRPC_inbounds.json >/dev/null 2>&1
    fi
    installSniffing
    if [[ -z "$3" ]]; then
        removeXrayOutbound wireguard_out_IPv4_route
        removeXrayOutbound wireguard_out_IPv6_route
        removeXrayOutbound wireguard_outbound
        removeXrayOutbound IPv4_out
        removeXrayOutbound IPv6_out
        removeXrayOutbound socks5_outbound
        removeXrayOutbound blackhole_out
        removeXrayOutbound wireguard_out_IPv6
        removeXrayOutbound wireguard_out_IPv4
        addXrayOutbound z_direct_outbound
    fi
}

# 初始化TCP Brutal
initTCPBrutal() {

echoContent skyBlue "\nProgress $2/${totalProgress}: Initialize TCP_Brutal configuration"
read -r -p "Do you want to use TCP_Brutal? [y/n]:" tcpBrutalStatus
if [[ "${tcpBrutalStatus}" == "y" ]]; then
read -r -p "Please enter the local bandwidth peak downlink speed (default: 100, unit: Mbps):" tcpBrutalClientDownloadSpeed
if [[ -z "${tcpBrutalClientDownloadSpeed}" ]]; then
tcpBrutalClientDownloadSpeed=100
fi

read -r -p "Please enter the local bandwidth peak uplink speed (default: 50, unit: Mbps):" tcpBrutalClientUploadSpeed
if [[ -z "${tcpBrutalClientUploadSpeed}" ]]; then
tcpBrutalClientUploadSpeed=50
fi
fi
}
# Initialize sing-box configuration file
initSingBoxConfig() {
echoContent skyBlue "\nProgress $2/${totalProgress}: Initialize sing-box configuration"

echo
local uuid=
local addClientsStatus=
local sslDomain=
if [[ -n "${domain}" ]]; then
sslDomain="${domain}"
elif [[ -n "${currentHost}" ]]; then
sslDomain="${currentHost}"
fi
if [[ -n "${currentUUID}" && -z "${lastInstallationConfig}" ]]; then
read -r -p "Read the last user configuration, do you want to use the last installed configuration? [y/n]:" historyUUIDStatus
if [[ "${historyUUIDStatus}" == "y" ]]; then
addClientsStatus=true
echoContent green "\n ---> Successfully used"
fi
elif [[ -n "${currentUUID}" && -n "${lastInstallationConfig}" ]]; then
addClientsStatus=true
fi
if [[ -z "${addClientsStatus}" ]]; then
echoContent yellow "Please enter a custom UUID [must be legal], [Enter] Random UUID"
read -r -p 'UUID:' customUUID

if [[ -n ${customUUID} ]]; then
uuid=${customUUID}
else
uuid=$(/etc/v2ray-agent/sing-box/sing-box generate uuid)
fi

echoContent yellow "\nPlease enter a custom username [must be legal], [Enter] random username"
read -r -p 'Username:' customEmail
if [[ -z ${customEmail} ]]; then
customEmail="$(echo "${uuid}" | cut -d "-" -f 1)-VLESS_TCP/TLS_Vision"
fi
fi

if [[ -z "${addClientsStatus}" && -z "${uuid}" ]]; then
addClientsStatus=
echoContent red "\n ---> uuid read error, randomly generated"
uuid=$(/etc/v2ray-agent/sing-box/sing-box generate uuid)
fi

if [[ -n "${uuid}" ]]; then
        currentClients='[{"uuid":"'${uuid}'","flow":"xtls-rprx-vision","name":"'${customEmail}'"}]'
        echoContent yellow "\n ${customEmail}:${uuid}"
    fi

    #VLESSVision
    if echo "${selectCustomInstallType}" | grep -q ",0," || [[ "$1" == "all" ]]; then
        echoContent yellow "\n===================== Configure VLESS+Vision =====================\n"
        echoContent skyBlue "\nStart configuring VLESS+Vision protocol port"
        echo
        mapfile -t result < <(initSingBoxPort "${singBoxVLESSVisionPort}")
        echoContent green "\n ---> VLESS_Vision port: ${result[-1]}"

        checkDNSIP "${domain}"
        removeNginxDefaultConf
        handleSingBox stop

        checkPortOpen "${result[-1]}" "${domain}"
        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/02_VLESS_TCP_inbounds.json
{
    "inbounds":[
        {
          "type": "vless",
          "listen":"::",
          "listen_port":${result[-1]},
          "tag":"VLESSTCP",
          "users":$(initSingBoxClients 0),
          "tls":{
            "server_name": "${sslDomain}",
            "enabled": true,
            "certificate_path": "/etc/v2ray-agent/tls/${sslDomain}.crt", "key_path": "/etc/v2ray-agent/tls/${sslDomain}.key"
}
}
]
}
EOF
elif [[ -z "$3" ]]; then
rm /etc/v2ray-agent/sing-box/conf/config/02_VLESS_TCP_inbounds.json >/dev/null 2>&1
fi

if echo "${selectCustomInstallType}" | grep -q ",1," || [[ "$1" == "all" ]]; then
echoContent yellow "\n====================== 配置VLESS+WS =====================\n"
echoContent skyBlue "\nStart configuring VLESS+WS protocol port"
echo
mapfile -t result < <(initSingBoxPort "${singBoxVLESSWSPort}")
        echoContent green "\n ---> VLESS_WS port: ${result[-1]}"

        checkDNSIP "${domain}"
        removeNginxDefaultConf
        handleSingBox stop
        randomPathFunction
        checkPortOpen "${result[-1]}" "${domain}"

        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/03_VLESS_WS_inbounds.json
{
    "inbounds":[
        {
          "type": "vless",
          "listen":"::",
          "listen_port":${result[-1]},
          "tag":"VLESSWS",
          "users":$(initSingBoxClients 1),
          "tls":{
            "server_name": "${sslDomain}",
            "enabled": true,
            "certificate_path": "/etc/v2ray-agent/tls/${sslDomain}.crt",
            "key_path": "/etc/v2ray-agent/tls/${sslDomain}.key"
          },
          "transport": {
            "type": "ws",
            "path": "/${currentPath}ws",
            "max_early_data": 2048,
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        }
    ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/03_VLESS_WS_inbounds.json >/dev/null 2>&1
    fi

    if echo "${selectCustomInstallType}" | grep -q ",3," || [[ "$1" == "all" ]]; then
        echoContent yellow "\n===================== 配置VMess+ws =====================\n"
        echoContent skyBlue "\n开始配置VMess+ws协议端口"
        echo
        mapfile -t result < <(initSingBoxPort "${singBoxVMessWSPort}")
        echoContent green "\n ---> VMess_ws端口：${result[-1]}"

        checkDNSIP "${domain}"
        removeNginxDefaultConf
        handleSingBox stop
        randomPathFunction
        checkPortOpen "${result[-1]}" "${domain}"
        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/05_VMess_WS_inbounds.json
{
    "inbounds":[
        {
          "type": "vmess",
          "listen":"::",
          "listen_port":${result[-1]},
          "tag":"VMessWS",
          "users":$(initSingBoxClients 3),
          "tls":{
            "server_name": "${sslDomain}",
            "enabled": true,
            "certificate_path": "/etc/v2ray-agent/tls/${sslDomain}.crt",
            "key_path": "/etc/v2ray-agent/tls/${sslDomain}.key"
          },
          "transport": {
            "type": "ws",
            "path": "/${currentPath}",
            "max_early_data": 2048,
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        }
    ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/05_VMess_WS_inbounds.json >/dev/null 2>&1
    fi

    # VLESS_Reality_Vision
    if echo "${selectCustomInstallType}" | grep -q ",7," || [[ "$1" == "all" ]]; then
        echoContent yellow "\n================= 配置VLESS+Reality+Vision =================\n"
        initRealityClientServersName
        initRealityKey
        echoContent skyBlue "\n开始配置VLESS+Reality+Vision协议端口"
        echo
        mapfile -t result < <(initSingBoxPort "${singBoxVLESSRealityVisionPort}")
        echoContent green "\n ---> VLESS_Reality_Vision端口：${result[-1]}"
        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/07_VLESS_vision_reality_inbounds.json
{
  "inbounds": [
    {
      "type": "vless",
      "listen":"::",
      "listen_port":${result[-1]},
      "tag": "VLESSReality",
      "users":$(initSingBoxClients 7),
      "tls": {
        "enabled": true,
        "server_name": "${realityServerName}",
        "reality": {
            "enabled": true,
            "handshake":{
                "server": "${realityServerName}",
                "server_port":${realityDomainPort}
            },
            "private_key": "${realityPrivateKey}",
            "short_id": [
                "",
                "6ba85179e30d4fc2"
            ]
        }
      }
    }
  ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/07_VLESS_vision_reality_inbounds.json >/dev/null 2>&1
    fi

    if echo "${selectCustomInstallType}" | grep -q ",8," || [[ "$1" == "all" ]]; then
        echoContent yellow "\n================== 配置VLESS+Reality+gRPC ==================\n"
        initRealityClientServersName
        initRealityKey
        echoContent skyBlue "\n开始配置VLESS+Reality+gRPC协议端口"
        echo

        mapfile -t result < <(initSingBoxPort "${singBoxVLESSRealityGRPCPort}")
        echoContent green "\n ---> VLESS_Reality_gPRC端口：${result[-1]}"
        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/08_VLESS_vision_gRPC_inbounds.json
{
  "inbounds": [
    {
      "type": "vless",
      "listen":"::",
      "listen_port":${result[-1]},
      "users":$(initSingBoxClients 8),
      "tag": "VLESSRealityGRPC",
      "tls": {
        "enabled": true,
        "server_name": "${realityServerName}",
        "reality": {
            "enabled": true,
            "handshake":{
                "server":"${realityServerName}",
                "server_port":${realityDomainPort}
            },
            "private_key": "${realityPrivateKey}",
            "short_id": [
                "",
                "6ba85179e30d4fc2"
            ]
        }
      },
      "transport": {
          "type": "grpc",
          "service_name": "grpc"
      }
    }
  ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/08_VLESS_vision_gRPC_inbounds.json >/dev/null 2>&1
    fi

    if echo "${selectCustomInstallType}" | grep -q ",6," || [[ "$1" == "all" ]]; then
        echoContent yellow "\n================== 配置 Hysteria2 ==================\n"
        echoContent skyBlue "\n开始配置Hysteria2协议端口"
        echo
        mapfile -t result < <(initSingBoxPort "${singBoxHysteria2Port}")
        echoContent green "\n ---> Hysteria2端口：${result[-1]}"
        initHysteria2Network
        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/06_hysteria2_inbounds.json
{
    "inbounds": [
        {
            "type": "hysteria2",
            "listen": "::",
            "listen_port": ${result[-1]},
            "users": $(initSingBoxClients 6),
            "up_mbps":${hysteria2ClientDownloadSpeed},
            "down_mbps":${hysteria2ClientUploadSpeed},
            "tls": {
                "enabled": true,
                "server_name":"${sslDomain}",
                "alpn": [
                    "h3"
                ],
                "certificate_path": "/etc/v2ray-agent/tls/${sslDomain}.crt",
                "key_path": "/etc/v2ray-agent/tls/${sslDomain}.key"
            }
        }
    ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/06_hysteria2_inbounds.json >/dev/null 2>&1
    fi

    if echo "${selectCustomInstallType}" | grep -q ",4," || [[ "$1" == "all" ]]; then
        echoContent yellow "\n================== 配置 Trojan ==================\n"
        echoContent skyBlue "\n开始配置Trojan协议端口"
        echo
        mapfile -t result < <(initSingBoxPort "${singBoxTrojanPort}")
        echoContent green "\n ---> Trojan端口：${result[-1]}"
        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/04_trojan_TCP_inbounds.json
{
    "inbounds": [
        {
            "type": "trojan",
            "listen": "::",
            "listen_port": ${result[-1]},
            "users": $(initSingBoxClients 4),
            "tls": {
                "enabled": true,
                "server_name":"${sslDomain}",
                "certificate_path": "/etc/v2ray-agent/tls/${sslDomain}.crt",
                "key_path": "/etc/v2ray-agent/tls/${sslDomain}.key"
            }
        }
    ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/04_trojan_TCP_inbounds.json >/dev/null 2>&1
    fi

    if echo "${selectCustomInstallType}" | grep -q ",9," || [[ "$1" == "all" ]]; then
        echoContent yellow "\n==================== 配置 Tuic =====================\n"
        echoContent skyBlue "\n开始配置Tuic协议端口"
        echo
        mapfile -t result < <(initSingBoxPort "${singBoxTuicPort}")
        echoContent green "\n ---> Tuic端口：${result[-1]}"
        initTuicProtocol
        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/09_tuic_inbounds.json
{
     "inbounds": [
        {
            "type": "tuic",
            "listen": "::",
            "tag": "singbox-tuic-in",

            "listen_port": ${result[-1]},
            "users": $(initSingBoxClients 9),
            "congestion_control": "${tuicAlgorithm}",
            "tls": {
                "enabled": true,
                "server_name":"${sslDomain}",
                "alpn": [
                    "h3"
                ],
                "certificate_path": "/etc/v2ray-agent/tls/${sslDomain}.crt",
                "key_path": "/etc/v2ray-agent/tls/${sslDomain}.key"
            }
        }
    ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/09_tuic_inbounds.json >/dev/null 2>&1
    fi

    if echo "${selectCustomInstallType}" | grep -q ",10," || [[ "$1" == "all" ]]; then
        echoContent yellow "\n==================== 配置 Naive =====================\n"
        echoContent skyBlue "\n开始配置Naive协议端口"
        echo
        mapfile -t result < <(initSingBoxPort "${singBoxNaivePort}")
        echoContent green "\n ---> Naive端口：${result[-1]}"
        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/10_naive_inbounds.json
{
     "inbounds": [
        {
            "type": "naive",
            "listen": "::",
            "tag": "singbox-naive-in",
            "listen_port": ${result[-1]},
            "users": $(initSingBoxClients 10),
            "tls": {
                "enabled": true,
                "server_name":"${sslDomain}",
                "certificate_path": "/etc/v2ray-agent/tls/${sslDomain}.crt",
                "key_path": "/etc/v2ray-agent/tls/${sslDomain}.key"
            }
        }
    ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/10_naive_inbounds.json >/dev/null 2>&1
    fi
    if echo "${selectCustomInstallType}" | grep -q ",11," || [[ "$1" == "all" ]]; then
        echoContent yellow "\n===================== 配置VMess+HTTPUpgrade =====================\n"
        echoContent skyBlue "\n开始配置VMess+HTTPUpgrade协议端口"
        echo
        mapfile -t result < <(initSingBoxPort "${singBoxVMessHTTPUpgradePort}")
        echoContent green "\n ---> VMess_HTTPUpgrade端口：${result[-1]}"

        checkDNSIP "${domain}"
        removeNginxDefaultConf
        handleSingBox stop
        randomPathFunction
        rm -rf "${nginxConfigPath}sing_box_VMess_HTTPUpgrade.conf" >/dev/null 2>&1
        checkPortOpen "${result[-1]}" "${domain}"
        singBoxNginxConfig "$1" "${result[-1]}"
        bootStartup nginx
        cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/11_VMess_HTTPUpgrade_inbounds.json
{
    "inbounds":[
        {
          "type": "vmess",
          "listen":"127.0.0.1",
          "listen_port":31306,
          "tag":"VMessHTTPUpgrade",
          "users":$(initSingBoxClients 11),
          "transport": {
            "type": "httpupgrade",
            "path": "/${currentPath}"
          }
        }
    ]
}
EOF
    elif [[ -z "$3" ]]; then
        rm /etc/v2ray-agent/sing-box/conf/config/11_VMess_HTTPUpgrade_inbounds.json >/dev/null 2>&1
    fi
    if [[ -z "$3" ]]; then
        removeSingBoxConfig wireguard_endpoints_IPv4_route
        removeSingBoxConfig wireguard_endpoints_IPv6_route
        removeSingBoxConfig wireguard_endpoints_IPv4
        removeSingBoxConfig wireguard_endpoints_IPv6

        removeSingBoxConfig IPv4_out
        removeSingBoxConfig IPv6_out
        removeSingBoxConfig IPv6_route
        removeSingBoxConfig block
        removeSingBoxConfig cn_block_outbound
        removeSingBoxConfig cn_block_route
        removeSingBoxConfig 01_direct_outbound
        removeSingBoxConfig block_domain_outbound
        removeSingBoxConfig dns
    fi
}
# 初始化 sing-box订阅配置
initSubscribeLocalConfig() {
    rm -rf /etc/v2ray-agent/subscribe_local/sing-box/*
}
# 通用
defaultBase64Code() {
    local type=$1
    local port=$2
    local email=$3
    local id=$4
    local add=$5
    local path=$6
    local user=
    user=$(echo "${email}" | awk -F "[-]" '{print $1}')
    if [[ ! -f "/etc/v2ray-agent/subscribe_local/sing-box/${user}" ]]; then

        echo [] >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"
    fi
    local singBoxSubscribeLocalConfig=
    if [[ "${type}" == "vlesstcp" ]]; then

        echoContent yellow " ---> 通用格式(VLESS+TCP+TLS_Vision)"
        echoContent green "    vless://${id}@${currentHost}:${port}?encryption=none&security=tls&fp=chrome&type=tcp&host=${currentHost}&headerType=none&sni=${currentHost}&flow=xtls-rprx-vision#${email}\n"

        echoContent yellow " ---> 格式化明文(VLESS+TCP+TLS_Vision)"
        echoContent green "协议类型:VLESS，地址:${currentHost}，端口:${port}，用户ID:${id}，安全:tls，client-fingerprint: chrome，传输方式:tcp，flow:xtls-rprx-vision，账户名:${email}\n"
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
vless://${id}@${currentHost}:${port}?encryption=none&security=tls&type=tcp&host=${currentHost}&fp=chrome&headerType=none&sni=${currentHost}&flow=xtls-rprx-vision#${email}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: vless
    server: ${currentHost}
    port: ${port}
    uuid: ${id}
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    client-fingerprint: chrome
EOF
        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\":\"vless\",\"server\":\"${currentHost}\",\"server_port\":${port},\"uuid\":\"${id}\",\"flow\":\"xtls-rprx-vision\",\"tls\":{\"enabled\":true,\"server_name\":\"${currentHost}\",\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"}},\"packet_encoding\":\"xudp\"}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")
        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent yellow " ---> 二维码 VLESS(VLESS+TCP+TLS_Vision)"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${currentHost}%3A${port}%3Fencryption%3Dnone%26fp%3Dchrome%26security%3Dtls%26type%3Dtcp%26${currentHost}%3D${currentHost}%26headerType%3Dnone%26sni%3D${currentHost}%26flow%3Dxtls-rprx-vision%23${email}\n"

    elif [[ "${type}" == "vmessws" ]]; then
        qrCodeBase64Default=$(echo -n "{\"port\":${port},\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${currentHost}\",\"type\":\"none\",\"path\":\"${path}\",\"net\":\"ws\",\"add\":\"${add}\",\"allowInsecure\":0,\"method\":\"none\",\"peer\":\"${currentHost}\",\"sni\":\"${currentHost}\"}" | base64 -w 0)
        qrCodeBase64Default="${qrCodeBase64Default// /}"

        echoContent yellow " ---> 通用json(VMess+WS+TLS)"
        echoContent green "    {\"port\":${port},\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${currentHost}\",\"type\":\"none\",\"path\":\"${path}\",\"net\":\"ws\",\"add\":\"${add}\",\"allowInsecure\":0,\"method\":\"none\",\"peer\":\"${currentHost}\",\"sni\":\"${currentHost}\"}\n"
        echoContent yellow " ---> 通用vmess(VMess+WS+TLS)链接"
        echoContent green "    vmess://${qrCodeBase64Default}\n"
        echoContent yellow " ---> 二维码 vmess(VMess+WS+TLS)"

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
vmess://${qrCodeBase64Default}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: vmess
    server: ${add}
    port: ${port}
    uuid: ${id}
    alterId: 0
    cipher: none
    udp: true
    tls: true
    client-fingerprint: chrome
    servername: ${currentHost}
    network: ws
    ws-opts:
      path: ${path}
      headers:
        Host: ${currentHost}
EOF

        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\":\"vmess\",\"server\":\"${add}\",\"server_port\":${port},\"uuid\":\"${id}\",\"alter_id\":0,\"tls\":{\"enabled\":true,\"server_name\":\"${currentHost}\",\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"}},\"packet_encoding\":\"packetaddr\",\"transport\":{\"type\":\"ws\",\"path\":\"${path}\",\"max_early_data\":2048,\"early_data_header_name\":\"Sec-WebSocket-Protocol\"}}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")

        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vmess://${qrCodeBase64Default}\n"

    elif [[ "${type}" == "vlessws" ]]; then

        echoContent yellow " ---> 通用格式(VLESS+WS+TLS)"
        echoContent green "    vless://${id}@${add}:${port}?encryption=none&security=tls&type=ws&host=${currentHost}&sni=${currentHost}&fp=chrome&path=${path}#${email}\n"

        echoContent yellow " ---> 格式化明文(VLESS+WS+TLS)"
        echoContent green "    协议类型:VLESS，地址:${add}，伪装域名/SNI:${currentHost}，端口:${port}，client-fingerprint: chrome,用户ID:${id}，安全:tls，传输方式:ws，路径:${path}，账户名:${email}\n"

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
vless://${id}@${add}:${port}?encryption=none&security=tls&type=ws&host=${currentHost}&sni=${currentHost}&fp=chrome&path=${path}#${email}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: vless
    server: ${add}
    port: ${port}
    uuid: ${id}
    udp: true
    tls: true
    network: ws
    client-fingerprint: chrome
    servername: ${currentHost}
    ws-opts:
      path: ${path}
      headers:
        Host: ${currentHost}
EOF

        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\":\"vless\",\"server\":\"${add}\",\"server_port\":${port},\"uuid\":\"${id}\",\"tls\":{\"enabled\":true,\"server_name\":\"${currentHost}\",\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"}},\"multiplex\":{\"enabled\":false,\"protocol\":\"smux\",\"max_streams\":32},\"packet_encoding\":\"xudp\",\"transport\":{\"type\":\"ws\",\"path\":\"${path}\",\"headers\":{\"Host\":\"${currentHost}\"}}}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")
        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent yellow " ---> 二维码 VLESS(VLESS+WS+TLS)"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${add}%3A${port}%3Fencryption%3Dnone%26security%3Dtls%26type%3Dws%26host%3D${currentHost}%26fp%3Dchrome%26sni%3D${currentHost}%26path%3D${path}%23${email}"

    elif [[ "${type}" == "vlessXHTTP" ]]; then

        echoContent yellow " ---> 通用格式(VLESS+reality+XHTTP)"
        echoContent green "    vless://${id}@$(getPublicIP):${port}?encryption=none&security=reality&type=xhttp&sni=${xrayVLESSRealityXHTTPServerName}&host=${xrayVLESSRealityXHTTPServerName}&fp=chrome&path=${path}&pbk=${currentRealityXHTTPPublicKey}&sid=6ba85179e30d4fc2#${email}\n"

        echoContent yellow " ---> 格式化明文(VLESS+reality+XHTTP)"
        echoContent green "协议类型:VLESS reality，地址:$(getPublicIP)，publicKey:${currentRealityXHTTPPublicKey}，shortId: 6ba85179e30d4fc2,serverNames：${xrayVLESSRealityXHTTPServerName}，端口:${port}，路径：${path}，SNI:${xrayVLESSRealityXHTTPServerName}，伪装域名:${xrayVLESSRealityXHTTPServerName}，用户ID:${id}，传输方式:xhttp，账户名:${email}\n"
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
vless://${id}@$(getPublicIP):${port}?encryption=none&security=reality&type=xhttp&sni=${xrayVLESSRealityXHTTPServerName}&fp=chrome&path=${path}&pbk=${currentRealityXHTTPPublicKey}&sid=6ba85179e30d4fc2#${email}
EOF
        echoContent yellow " ---> 二维码 VLESS(VLESS+reality+XHTTP)"

        echoContent green " https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40$(getPublicIP)%3A${port}%3Fencryption%3Dnone%26security%3Dreality%26type%3Dtcp%26sni%3D${xrayVL ESSRealityXHTTPServerName}%26fp%3Dchrome%26path%3D${path}%26host%3D${xrayVLESSRealityXHTTPServerName}%26pbk%3D${currentRealityXHTTPPublicKey}%26sid%3D6ba85179e30d4fc2%23${email}\n"

    elif
        [[ "${type}" == "vlessgrpc" ]]
    then echoContent yellow " ---> General format (VLESS+gRPC+TLS)"
echoContent green " vless://${id}@${add}:${port}?encryption=none&security=tls&type=grpc&host=${currentHost}&path=${currentPath}grpc&fp=chrome&serviceName=${currentPath}grpc&alpn=h2&sni=${currentHost}#${email}\n"

echoContent yellow " ---> Format plain text (VLESS+gRPC+TLS)"
echoContent green " Protocol type: VLESS, address: ${add}, disguised domain name/SNI: ${currentHost}, port: ${port}, user ID: ${id}, security: tls, transmission method: gRPC, alpn: h2, client-fingerprint: chrome,serviceName:${currentPath}grpc, account name:${email}\n"

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
vless://${id}@${add}:${port}?encryption=none&security=tls&type=grpc&host=${currentHost}&path=${currentPath}grpc&serviceName=${currentPath}grpc&fp=chrome&alpn=h2&sni=${currentHost}#${email}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: vless
    server: ${add}
    port: ${port}
    uuid: ${id}
    udp: true
    tls: true
    network: grpc    client-fingerprint: chrome
    servername: ${currentHost}
    grpc-opts:
      grpc-service-name: ${currentPath}grpc
EOF

        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\": \"vless\",\"server\": \"${add}\",\"server_port\": ${port},\"uuid\": \"${id}\",\"tls\": { \"enabled\": true, \"server_name\": \"${currentHost}\", \"utls\": { \"enabled\": true, \"fingerprint\": \"chrome\" }},\"packet_encoding\": \"xudp\",\"transport\": { \"type\": \"grpc\", \"service_name\": \"${currentPath}grpc\"}}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")
        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent yellow " ---> QR code VLESS(VLESS+gRPC+TLS)"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${add}%3A${port}%3Fencryption%3Dnone%26security%3Dtls%26type%3Dgr pc%26host%3D${currentHost}%26serviceName%3D${currentPath}grpc%26fp%3Dchrome%26path%3D${currentPath}grpc%26sni%3D${currentHost}%26alpn%3Dh2%23${email}"

    elif [[ "${type}" == "trojan" ]]; then
        # URLEncode
        echoContent yellow " ---> Trojan(TLS)"
        echoContent green "    trojan://${id}@${currentHost}:${port}?peer=${currentHost}&fp=chrome&sni=${currentHost}&alpn=http/1.1#${currentHost}_Trojan\n"

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
trojan://${id}@${currentHost}:${port}?peer=${currentHost}&fp=chrome&sni=${currentHost}&alpn=http/1.1#${email}_Trojan
EOF

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: Trojan
    server: ${currentHost}
    port: ${port}
    password: ${id}    client-fingerprint: chrome
    udp: true
    sni: ${currentHost}
EOF
        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\":\"trojan\",\"server\":\"${currentHost}\",\"server_port\":${port},\"password\":\"${id}\",\"tls\":{\" alpn\":[\"http/1.1\"],\"enabled\":true,\"server_name\":\"${currentHost}\",\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"}}}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")
        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

echoContent yellow " ---> QR code Trojan(TLS)"

        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${id}%40${currentHost}%3a${port}%3fpeer%3d${currentHost}%26fp%3Dchrome%26sni%3d${currentHost}%26alpn%3Dhttp/1.1%23${email}\n"

    elif [[ "${type}" == "trojangrpc" ]]; then
        # URLEncode

        echoContent yellow " ---> Trojan gRPC(TLS)"
        echoContent green "    trojan://${id}@${add}:${port}?encryption=none&peer=${currentHost}&fp=chrome&security=tls&type=grpc&sni=${currentHost}&alpn=h2&path=${currentPath}trojangrpc&serviceName=${currentPath}trojangrpc#${email}\n"
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
trojan://${id}@${add}:${port}?encryption=none&peer=${currentHost}&security=tls&type=grpc&fp=chrome&sni=${currentHost}&alpn=h2&path=${currentPath}trojangrpc&serviceName=${currentPath}trojangrpc#${email}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    server: ${add}
    port: ${port}
    type: trojan
    password: ${id}
    network: grpc
    sni: ${currentHost}
    udp: true
    grpc-opts:
      grpc-service-name: ${currentPath}trojangrpc
EOF

        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\":\"trojan\",\"server\":\"${add}\",\"server_port\":${port},\"password\":\"${id}\",\"tls\":{\"enabled\":true,\"server_name\":\"${currentHost}\",\"insecure\":true,\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"}},\"transport\":{\"type\":\"grpc\",\"service_name\":\"${currentPath}trojangrpc\",\"idle_timeout\":\"15s\",\"ping_timeout\":\"15s\",\"permit_without_stream\":false},\"multiplex\":{\"enabled\":false,\"protocol\":\"smux\",\"max_streams\":32}}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")
        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent yellow " ---> 二维码 Trojan gRPC(TLS)"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${id}%40${add}%3a${port}%3Fencryption%3Dnone%26fp%3Dchrome%26security%3Dtls%26peer%3d${currentHost}%26type%3Dgrpc%26sni%3d${currentHost}%26path%3D${currentPath}trojangrpc%26alpn%3Dh2%26serviceName%3D${currentPath}trojangrpc%23${email}\n"

    elif [[ "${type}" == "hysteria" ]]; then
        echoContent yellow " ---> Hysteria(TLS)"
        local clashMetaPortContent="port: ${port}"
        local multiPort=
        local multiPortEncode
        if echo "${port}" | grep -q "-"; then
            clashMetaPortContent="ports: ${port}"
            multiPort="mport=${port}&"
            multiPortEncode="mport%3D${port}%26"
        fi

        echoContent green "    hysteria2://${id}@${currentHost}:${singBoxHysteria2Port}?${multiPort}peer=${currentHost}&insecure=0&sni=${currentHost}&alpn=h3#${email}\n"
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
hysteria2://${id}@${currentHost}:${singBoxHysteria2Port}?${multiPort}peer=${currentHost}&insecure=0&sni=${currentHost}&alpn=h3#${email}
EOF
        echoContent yellow " ---> v2rayN(hysteria+TLS)"
        echo "{\"server\": \"${currentHost}:${port}\",\"socks5\": { \"listen\": \"127.0.0.1:7798\", \"timeout\": 300},\"auth\":\"${id}\",\"tls\":{\"sni\":\"${currentHost}\"}}" | jq

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: hysteria2
    server: ${currentHost}
    ${clashMetaPortContent}
    password: ${id}
    alpn:
        - h3
    sni: ${currentHost}
    up: "${hysteria2ClientUploadSpeed} Mbps"
    down: "${hysteria2ClientDownloadSpeed} Mbps"
EOF


        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\":\"hysteria2\",\"server\":\"${currentHost}\",\"server_port\":${singBoxHysteria2Port},\"up_mbps\":${hysteria2ClientUploadSpeed},\"down_mbps\":${hysteria2ClientDownloadSpeed},\"password\":\"${id}\",\"tls\":{\"enabled\":true,\"server_name\":\"${currentHost}\",\"alpn\":[\"h3\"]}}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")
        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent yellow " ---> 二维码 Hysteria2(TLS)"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=hysteria2%3A%2F%2F${id}%40${currentHost}%3A${singBoxHysteria2Port}%3F${multiPortEncode}peer%3D${currentHost}%26insecure%3D0%26sni%3D${currentHost}%26alpn%3Dh3%23${email}\n"

    elif [[ "${type}" == "vlessReality" ]]; then
        local realityServerName=${xrayVLESSRealityServerName}
        local publicKey=${currentRealityPublicKey}
        if [[ "${coreInstallType}" == "2" ]]; then
            realityServerName=${singBoxVLESSRealityVisionServerName}
            publicKey=${singBoxVLESSRealityPublicKey}
        fi
        echoContent yellow " ---> 通用格式(VLESS+reality+uTLS+Vision)"
        echoContent green "    vless://${id}@$(getPublicIP):${port}?encryption=none&security=reality&type=tcp&sni=${realityServerName}&fp=chrome&pbk=${publicKey}&sid=6ba85179e30d4fc2&flow=xtls-rprx-vision#${email}\n"

        echoContent yellow " ---> 格式化明文(VLESS+reality+uTLS+Vision)"
        echoContent green "协议类型:VLESS reality，地址:$(getPublicIP)，publicKey:${publicKey}，shortId: 6ba85179e30d4fc2,serverNames：${realityServerName}，端口:${port}，用户ID:${id}，传输方式:tcp，账户名:${email}\n"
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
vless://${id}@$(getPublicIP):${port}?encryption=none&security=reality&type=tcp&sni=${realityServerName}&fp=chrome&pbk=${publicKey}&sid=6ba85179e30d4fc2&flow=xtls-rprx-vision#${email}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: vless
    server: $(getPublicIP)
    port: ${port}
    uuid: ${id}
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: ${realityServerName}
    reality-opts:
      public-key: ${publicKey}
      short-id: 6ba85179e30d4fc2
    client-fingerprint: chrome
EOF

        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\":\"vless\",\"server\":\"$(getPublicIP)\",\"server_port\":${port},\"uuid\":\"${id}\",\"flow\":\"xtls-rprx-vision\",\"tls\":{\"enabled\":true,\"server_name\":\"${realityServerName}\",\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"},\"reality\":{\"enabled\":true,\"public_key\":\"${publicKey}\",\"short_id\":\"6ba85179e30d4fc2\"}},\"packet_encoding\":\"xudp\"}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")
        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent yellow " ---> 二维码 VLESS(VLESS+reality+uTLS+Vision)"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40$(getPublicIP)%3A${port}%3Fencryption%3Dnone%26security%3Dreality%26type%3Dtcp%26sni%3D${realityServerName}%26fp%3Dchrome%26pbk%3D${publicKey}%26sid%3D6ba85179e30d4fc2%26flow%3Dxtls-rprx-vision%23${email}\n"

    elif [[ "${type}" == "vlessRealityGRPC" ]]; then
        local realityServerName=${xrayVLESSRealityServerName}
        local publicKey=${currentRealityPublicKey}
        if [[ "${coreInstallType}" == "2" ]]; then
            realityServerName=${singBoxVLESSRealityGRPCServerName}
            publicKey=${singBoxVLESSRealityPublicKey}
        fi

        echoContent yellow " ---> 通用格式(VLESS+reality+uTLS+gRPC)"

        echoContent green "    vless://${id}@$(getPublicIP):${port}?encryption=none&security=reality&type=grpc&sni=${realityServerName}&fp=chrome&pbk=${publicKey}&sid=6ba85179e30d4fc2&path=grpc&serviceName=grpc#${email}\n"

        echoContent yellow " ---> 格式化明文(VLESS+reality+uTLS+gRPC)"
        echoContent green "协议类型:VLESS reality，serviceName:grpc，地址:$(getPublicIP)，publicKey:${publicKey}，shortId: 6ba85179e30d4fc2，serverNames：${realityServerName}，端口:${port}，用户ID:${id}，传输方式:gRPC，client-fingerprint：chrome，账户名:${email}\n"
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
vless://${id}@$(getPublicIP):${port}?encryption=none&security=reality&type=grpc&sni=${realityServerName}&fp=chrome&pbk=${publicKey}&sid=6ba85179e30d4fc2&path=grpc&serviceName=grpc#${email}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: vless
    server: $(getPublicIP)
    port: ${port}
    uuid: ${id}
    network: grpc
    tls: true
    udp: true
    servername: ${realityServerName}
    reality-opts:
      public-key: ${publicKey}
      short-id: 6ba85179e30d4fc2
    grpc-opts:
      grpc-service-name: "grpc"
    client-fingerprint: chrome
EOF

        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\":\"vless\",\"server\":\"$(getPublicIP)\",\"server_port\":${port},\"uuid\":\"${id}\",\"tls\":{\"enabled\":true,\"server_name\":\"${realityServerName}\",\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"},\"reality\":{\"enabled\":true,\"public_key\":\"${publicKey}\",\"short_id\":\"6ba85179e30d4fc2\"}},\"packet_encoding\":\"xudp\",\"transport\":{\"type\":\"grpc\",\"service_name\":\"grpc\"}}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")
        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent yellow " ---> 二维码 VLESS(VLESS+reality+uTLS+gRPC)"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40$(getPublicIP)%3A${port}%3Fencryption%3Dnone%26security%3Dreality%26type%3Dgrpc%26sni%3D${realityServerName}%26fp%3Dchrome%26pbk%3D${publicKey}%26sid%3D6ba85179e30d4fc2%26path%3Dgrpc%26serviceName%3Dgrpc%23${email}\n"
    elif [[ "${type}" == "tuic" ]]; then
        local tuicUUID=
        tuicUUID=$(echo "${id}" | awk -F "[_]" '{print $1}')

        local tuicPassword=
        tuicPassword=$(echo "${id}" | awk -F "[_]" '{print $2}')

        if [[ -z "${email}" ]]; then
            echoContent red " ---> 读取配置失败，请重新安装"
            exit 0
        fi

        echoContent yellow " ---> 格式化明文(Tuic+TLS)"
        echoContent green "    协议类型:Tuic，地址:${currentHost}，端口：${port}，uuid：${tuicUUID}，password：${tuicPassword}，congestion-controller:${tuicAlgorithm}，alpn: h3，账户名:${email}\n"

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
tuic://${tuicUUID}:${tuicPassword}@${currentHost}:${port}?congestion_control=${tuicAlgorithm}&alpn=h3&sni=${currentHost}&udp_relay_mode=quic&allow_insecure=0#${email}
EOF
        echoContent yellow " ---> v2rayN(Tuic+TLS)"
        echo "{\"relay\": {\"server\": \"${currentHost}:${port}\",\"uuid\": \"${tuicUUID}\",\"password\": \"${tuicPassword}\",\"ip\": \"${currentHost}\",\"congestion_control\": \"${tuicAlgorithm}\",\"alpn\": [\"h3\"]},\"local\": {\"server\": \"127.0.0.1:7798\"},\"log_level\": \"warn\"}" | jq

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    server: ${currentHost}
    type: tuic
    port: ${port}
    uuid: ${tuicUUID}
    password: ${tuicPassword}
    alpn:
     - h3
    congestion-controller: ${tuicAlgorithm}
    disable-sni: true
    reduce-rtt: true
    sni: ${email}
EOF


        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\": \"tuic\",\"server\": \"${currentHost}\",\"server_port\": ${port},\"uuid\": \"${tuicUUID}\",\"password\": \"${tuicPassword}\",\"congestion_control\": \"${tuicAlgorithm}\",\"tls\": {\"enabled\": true,\"server_name\": \"${currentHost}\",\"alpn\": [\"h3\"]}}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")
        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent yellow "\n ---> 二维码 Tuic"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=tuic%3A%2F%2F${tuicUUID}%3A${tuicPassword}%40${currentHost}%3A${tuicPort}%3Fcongestion_control%3D${tuicAlgorithm}%26alpn%3Dh3%26sni%3D${currentHost}%26udp_relay_mode%3Dquic%26allow_insecure%3D0%23${email}\n"
    elif [[ "${type}" == "naive" ]]; then
        echoContent yellow " ---> Naive(TLS)"

        echoContent green "    naive+https://${email}:${id}@${currentHost}:${port}?padding=true#${email}\n"
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
naive+https://${email}:${id}@${currentHost}:${port}?padding=true#${email}
EOF
        echoContent yellow " ---> 二维码 Naive(TLS)"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=naive%2Bhttps%3A%2F%2F${email}%3A${id}%40${currentHost}%3A${port}%3Fpadding%3Dtrue%23${email}\n"
    elif [[ "${type}" == "vmessHTTPUpgrade" ]]; then
        qrCodeBase64Default=$(echo -n "{\"port\":${port},\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${currentHost}\",\"type\":\"none\",\"path\":\"${path}\",\"net\":\"httpupgrade\",\"add\":\"${add}\",\"allowInsecure\":0,\"method\":\"none\",\"peer\":\"${currentHost}\",\"sni\":\"${currentHost}\"}" | base64 -w 0)
        qrCodeBase64Default="${qrCodeBase64Default// /}"

        echoContent yellow " ---> 通用json(VMess+HTTPUpgrade+TLS)"
        echoContent green "    {\"port\":${port},\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${currentHost}\",\"type\":\"none\",\"path\":\"${path}\",\"net\":\"httpupgrade\",\"add\":\"${add}\",\"allowInsecure\":0,\"method\":\"none\",\"peer\":\"${currentHost}\",\"sni\":\"${currentHost}\"}\n"
        echoContent yellow " ---> 通用vmess(VMess+HTTPUpgrade+TLS)链接"
        echoContent green "    vmess://${qrCodeBase64Default}\n"
        echoContent yellow " ---> 二维码 vmess(VMess+HTTPUpgrade+TLS)"

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
   vmess://${qrCodeBase64Default}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: vmess
    server: ${add}
    port: ${port}
    uuid: ${id}
    alterId: 0
    cipher: auto
    udp: true
    tls: true
    client-fingerprint: chrome
    servername: ${currentHost}
    network: ws
    ws-opts:
     path: ${path}
     headers:
       Host: ${currentHost}
     v2ray-http-upgrade: true
EOF
        singBoxSubscribeLocalConfig=$(jq -r ". += [{\"tag\":\"${email}\",\"type\":\"vmess\",\"server\":\"${add}\",\"server_port\":${port},\"uuid\":\"${id}\",\"security\":\"auto\",\"alter_id\":0,\"tls\":{\"enabled\":true,\"server_name\":\"${currentHost}\",\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"}},\"packet_encoding\":\"packetaddr\",\"transport\":{\"type\":\"httpupgrade\",\"path\":\"${path}\"}}]" "/etc/v2ray-agent/subscribe_local/sing-box/${user}")

        echo "${singBoxSubscribeLocalConfig}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${user}"

        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vmess://${qrCodeBase64Default}\n"

    fi

}

# 账号
showAccounts() {
    readInstallType
    readInstallProtocolType
    readConfigHostPathUUID
    readSingBoxConfig

    echo
    echoContent skyBlue "\n进度 $1/${totalProgress} : 账号"

    initSubscribeLocalConfig
    # VLESS TCP

    if echo ${currentInstallProtocolType} | grep -q ",0,"; then

        echoContent skyBlue "============================= VLESS TCP TLS_Vision [推荐] ==============================\n"
        jq .inbounds[0].settings.clients//.inbounds[0].users ${configPath}02_VLESS_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email//.name)

            echoContent skyBlue "\n ---> 账号:${email}"
            echo
            defaultBase64Code vlesstcp "${currentDefaultPort}${singBoxVLESSVisionPort}" "${email}" "$(echo "${user}" | jq -r .id//.uuid)"
        done
    fi

    # VLESS WS
    if echo ${currentInstallProtocolType} | grep -q ",1,"; then
        echoContent skyBlue "\n================================ VLESS WS TLS [仅CDN推荐] ================================\n"

        jq .inbounds[0].settings.clients//.inbounds[0].users ${configPath}03_VLESS_WS_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email//.name)

            local vlessWSPort=${currentDefaultPort}
            if [[ "${coreInstallType}" == "2" ]]; then
                vlessWSPort="${singBoxVLESSWSPort}"
            fi
            echo
            local path="${currentPath}ws"

            if [[ ${coreInstallType} == "1" ]]; then
                path="/${currentPath}ws"
            elif [[ "${coreInstallType}" == "2" ]]; then
                path="${singBoxVLESSWSPath}"
            fi

            local count=
            while read -r line; do
                echoContent skyBlue "\n ---> 账号:${email}${count}"
                if [[ -n "${line}" ]]; then
                    defaultBase64Code vlessws "${vlessWSPort}" "${email}${count}" "$(echo "${user}" | jq -r .id//.uuid)" "${line}" "${path}"
                    count=$((count + 1))
                    echo
                fi
            done < <(echo "${currentCDNAddress}" | tr ',' '\n')
        done
    fi
    # trojan grpc
    if echo ${currentInstallProtocolType} | grep -q ",2,"; then
        echoContent skyBlue "\n================================  Trojan gRPC TLS [仅CDN推荐]  ================================\n"
        jq .inbounds[0].settings.clients ${configPath}04_trojan_gRPC_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email)
            local count=
            while read -r line; do
                echoContent skyBlue "\n ---> 账号:${email}${count}"
                echo
                if [[ -n "${line}" ]]; then
                    defaultBase64Code trojangrpc "${currentDefaultPort}" "${email}${count}" "$(echo "${user}" | jq -r .password)" "${line}"
                    count=$((count + 1))
                fi
            done < <(echo "${currentCDNAddress}" | tr ',' '\n')

        done
    fi
    # VMess WS
    if echo ${currentInstallProtocolType} | grep -q ",3,"; then
        echoContent skyBlue "\n================================ VMess WS TLS [仅CDN推荐]  ================================\n"
        local path="${currentPath}vws"
        if [[ ${coreInstallType} == "1" ]]; then
            path="/${currentPath}vws"
        elif [[ "${coreInstallType}" == "2" ]]; then
            path="${singBoxVMessWSPath}"
        fi
        jq .inbounds[0].settings.clients//.inbounds[0].users ${configPath}05_VMess_WS_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email//.name)

            local vmessPort=${currentDefaultPort}
            if [[ "${coreInstallType}" == "2" ]]; then
                vmessPort="${singBoxVMessWSPort}"
            fi

            local count=
            while read -r line; do
                echoContent skyBlue "\n ---> 账号:${email}${count}"
                echo
                if [[ -n "${line}" ]]; then

                    defaultBase64Code vmessws "${vmessPort}" "${email}${count}" "$(echo "${user}" | jq -r .id//.uuid)" "${line}" "${path}"
                    count=$((count + 1))
                fi
            done < <(echo "${currentCDNAddress}" | tr ',' '\n')
        done
    fi

    # trojan tcp
    if echo ${currentInstallProtocolType} | grep -q ",4,"; then
        echoContent skyBlue "\n==================================  Trojan TLS [不推荐] ==================================\n"
        jq .inbounds[0].settings.clients//.inbounds[0].users ${configPath}04_trojan_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email//.name)
            echoContent skyBlue "\n ---> 账号:${email}"

            defaultBase64Code trojan "${currentDefaultPort}${singBoxTrojanPort}" "${email}" "$(echo "${user}" | jq -r .password)"
        done
    fi
    # VLESS grpc
    if echo ${currentInstallProtocolType} | grep -q ",5,"; then
        echoContent skyBlue "\n=============================== VLESS gRPC TLS [仅CDN推荐]  ===============================\n"
        jq .inbounds[0].settings.clients ${configPath}06_VLESS_gRPC_inbounds.json | jq -c '.[]' | while read -r user; do

            local email=
            email=$(echo "${user}" | jq -r .email)

            local count=
            while read -r line; do
                echoContent skyBlue "\n ---> 账号:${email}${count}"
                echo
                if [[ -n "${line}" ]]; then
                    defaultBase64Code vlessgrpc "${currentDefaultPort}" "${email}${count}" "$(echo "${user}" | jq -r .id)" "${line}"
                    count=$((count + 1))
                fi
            done < <(echo "${currentCDNAddress}" | tr ',' '\n')

        done
    fi
    # hysteria2
    if echo ${currentInstallProtocolType} | grep -q ",6," || [[ -n "${hysteriaPort}" ]]; then
        readPortHopping "hysteria2" "${singBoxHysteria2Port}"
        echoContent skyBlue "\n================================  Hysteria2 TLS [推荐] ================================\n"
        local path="${configPath}"
        if [[ "${coreInstallType}" == "1" ]]; then
            path="${singBoxConfigPath}"
        fi
        local hysteria2DefaultPort=
        if [[ -n "${hysteria2PortHoppingStart}" && -n "${hysteria2PortHoppingEnd}" ]]; then
            hysteria2DefaultPort="${hysteria2PortHopping}"
        else
            hysteria2DefaultPort=${singBoxHysteria2Port}
        fi

        jq -r -c '.inbounds[]|.users[]' "${path}06_hysteria2_inbounds.json" | while read -r user; do
            echoContent skyBlue "\n ---> 账号:$(echo "${user}" | jq -r .name)"
            echo
            defaultBase64Code hysteria "${hysteria2DefaultPort}" "$(echo "${user}" | jq -r .name)" "$(echo "${user}" | jq -r .password)"
        done

    fi

    # VLESS reality vision
    if echo ${currentInstallProtocolType} | grep -q ",7,"; then
        echoContent skyBlue "============================= VLESS reality_vision [推荐]  ==============================\n"
        jq .inbounds[0].settings.clients//.inbounds[0].users ${configPath}07_VLESS_vision_reality_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email//.name)

            echoContent skyBlue "\n ---> 账号:${email}"
            echo
            defaultBase64Code vlessReality "${xrayVLESSRealityVisionPort}${singBoxVLESSRealityVisionPort}" "${email}" "$(echo "${user}" | jq -r .id//.uuid)"
        done
    fi
    # VLESS reality gRPC
    if echo ${currentInstallProtocolType} | grep -q ",8,"; then
        echoContent skyBlue "============================== VLESS reality_gRPC [推荐] ===============================\n"
        jq .inbounds[0].settings.clients//.inbounds[0].users ${configPath}08_VLESS_vision_gRPC_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email//.name)


            echoContent skyBlue "\n ---> 账号:${email}"
            echo
            defaultBase64Code vlessRealityGRPC "${xrayVLESSRealityVisionPort}${singBoxVLESSRealityGRPCPort}" "${email}" "$(echo "${user}" | jq -r .id//.uuid)"
        done
    fi
    # tuic
    if echo ${currentInstallProtocolType} | grep -q ",9," || [[ -n "${tuicPort}" ]]; then
        echoContent skyBlue "\n================================  Tuic TLS [推荐]  ================================\n"
        local path="${configPath}"
        if [[ "${coreInstallType}" == "1" ]]; then
            path="${singBoxConfigPath}"
        fi
        jq -r -c '.inbounds[].users[]' "${path}09_tuic_inbounds.json" | while read -r user; do
            echoContent skyBlue "\n ---> 账号:$(echo "${user}" | jq -r .name)"
            echo
            defaultBase64Code tuic "${singBoxTuicPort}" "$(echo "${user}" | jq -r .name)" "$(echo "${user}" | jq -r .uuid)_$(echo "${user}" | jq -r .password)"
        done

    fi
    # naive
    if echo ${currentInstallProtocolType} | grep -q ",10," || [[ -n "${singBoxNaivePort}" ]]; then
        echoContent skyBlue "\n================================  naive TLS [推荐，不支持ClashMeta]  ================================\n"

        jq -r -c '.inbounds[]|.users[]' "${configPath}10_naive_inbounds.json" | while read -r user; do
            echoContent skyBlue "\n ---> 账号:$(echo "${user}" | jq -r .username)"
            echo
            defaultBase64Code naive "${singBoxNaivePort}" "$(echo "${user}" | jq -r .username)" "$(echo "${user}" | jq -r .password)"
        done

    fi
    # VMess HTTPUpgrade
    if echo ${currentInstallProtocolType} | grep -q ",11,"; then
        echoContent skyBlue "\n================================ VMess HTTPUpgrade TLS [仅CDN推荐]  ================================\n"
        local path="${currentPath}vws"
        if [[ ${coreInstallType} == "1" ]]; then
            path="/${currentPath}vws"
        elif [[ "${coreInstallType}" == "2" ]]; then
            path="${singBoxVMessHTTPUpgradePath}"
        fi
        jq .inbounds[0].settings.clients//.inbounds[0].users ${configPath}11_VMess_HTTPUpgrade_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email//.name)

            local vmessHTTPUpgradePort=${currentDefaultPort}
            if [[ "${coreInstallType}" == "2" ]]; then
                vmessHTTPUpgradePort="${singBoxVMessHTTPUpgradePort}"
            fi

            local count=
            while read -r line; do
                echoContent skyBlue "\n ---> 账号:${email}${count}"
                echo
                if [[ -n "${line}" ]]; then
                    defaultBase64Code vmessHTTPUpgrade "${vmessHTTPUpgradePort}" "${email}${count}" "$(echo "${user}" | jq -r .id//.uuid)" "${line}" "${path}"
                    count=$((count + 1))
                fi
            done < <(echo "${currentCDNAddress}" | tr ',' '\n')
        done
    fi
    # VLESS XHTTP
    if echo ${currentInstallProtocolType} | grep -q ",12,"; then
        echoContent skyBlue "\n================================ VLESS XHTTP TLS [仅CDN推荐] ================================\n"

        jq .inbounds[0].settings.clients//.inbounds[0].users ${configPath}12_VLESS_XHTTP_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email//.name)
            echo
            local path="${currentPath}xHTTP"

            local count=
            while read -r line; do
                echoContent skyBlue "\n ---> 账号:${email}${count}"
                if [[ -n "${line}" ]]; then
                    defaultBase64Code vlessXHTTP "${xrayVLESSRealityXHTTPort}" "${email}${count}" "$(echo "${user}" | jq -r .id//.uuid)" "${line}" "${path}"
                    count=$((count + 1))
                    echo
                fi
            done < <(echo "${currentCDNAddress}" | tr ',' '\n')
        done
    fi
}
# 移除nginx302配置
removeNginx302() {

    local count=
    grep -n "return 302" <"${nginxConfigPath}alone.conf" | while read -r line; do

        if ! echo "${line}" | grep -q "request_uri"; then
            local removeIndex=
            removeIndex=$(echo "${line}" | awk -F "[:]" '{print $1}')
            removeIndex=$((removeIndex + count))
            sed -i "${removeIndex}d" ${nginxConfigPath}alone.conf
            count=$((count - 1))
        fi
    done
}

# Check if 302 is successful
checkNginx302() {
    local domain302Status=
    domain302Status=$(curl -s "https://${currentHost}:${currentPort}")
    if echo "${domain302Status}" | grep -q "302"; then
# local domain302Result=
# domain302Result=$(curl -L -s "https://${currentHost}:${currentPort}")
# if [[ -n "${domain302Result}" ]]; then
echoContent green " ---> 302 redirection setup completed"
exit 0
# fi
fi
echoContent red " ---> 302 redirection setup failed, please check carefully whether it is the same as the example"
backupNginxConfig restoreBackup
}

# Backup and restore nginx files
backupNginxConfig() {
if [[ "$1" == "backup" ]]; then
cp ${nginxConfigPath}alone.conf /etc/v2ray-agent/alone_backup.conf
echoContent green " ---> nginx configuration file backup successful"
fi

if [[ "$1" == "restoreBackup" ]] && [[ -f "/etc/v2ray-agent/alone_backup.conf" ]]; then
cp /etc/v2ray-agent/alone_backup.conf ${nginxConfigPath}alone.conf
echoContent green " ---> nginx configuration file restored successfully"
rm /etc/v2ray-agent/alone_backup.conf
fi

}
# Add 302 configuration
addNginx302() {

local count=1
grep -n "location / {" <"${nginxConfigPath}alone.conf" | while read -r line; do
if [[ -n "${line}" ]]; then
local insertIndex=
insertIndex="$(echo "${line}" | awk -F "[:]" '{print $1}')"
insertIndex=$((insertIndex + count))
sed "${insertIndex}i return 302 '$1';" ${nginxConfigPath}alone.conf >${nginxConfigPath}tmpfile && mv ${nginxConfigPath}tmpfile ${nginxConfigPath}alone.conf
count=$((count + 1))
else
echoContent red "---> 302 failed to add"
backupNginxConfig restoreBackup
fi

done
}

# Update the disguised site
updateNginxBlog() {
if [[ "${coreInstallType}" == "2" ]]; then
echoContent red "\n ---> This function only supports Xray-core kernel"
exit 0
fi

echoContent skyBlue "\n Progress $1/${totalProgress} : Change the disguised site"

if ! echo "${currentInstallProtocolType}" | grep -q ",0," || [[ -z "${coreInstallType}" ]]; then
echoContent red "\n ---> Due to environment dependency, please install Xray-core's VLESS_TCP_TLS_Vision first"
exit 0
fi
echoContent red "================================================================"
echoContent yellow "# If you need to customize, please manually copy the template file to ${nginxStaticPath} \n"
echoContent yellow "1. Newbie Guide"
echoContent yellow "2. Game Website"
echoContent yellow "3. Personal Blog 01"
echoContent yellow "4. Enterprise Website"
echoContent yellow "5. Unlock encrypted music file template [https://github.com/ix64/unlock-music]"
echoContent yellow "6. mikutap [https://github.com/HFIProgramming/mikutap]"
echoContent yellow "7. Enterprise site 02"
echoContent yellow "8. Personal blog 02"
echoContent yellow "9. 404 automatically jumps to baidu"
echoContent yellow "10. 302 redirect website"
echoContent red "==================================================================="
read -r -p "Please select:" selectInstallNginxBlogType

if [[ "${selectInstallNginxBlogType}" == "10" ]]; then
if [[ "${coreInstallType}" == "2" ]]; then
echoContent red "\n ---> This function only supports Xray-core kernel, please wait for subsequent updates"
exit 0
fi
echoContent red "\n=================================================================="
echoContent yellow "Redirection priority is higher. If you change the disguised site after configuring 302, the disguised site under the root route will not work"
echoContent yellow "If you want the disguised site to work, you need to delete the 302 redirection configuration\n"
echoContent yellow "1. Add"
echoContent yellow "2. Delete"
echoContent red "================================================================"
read -r -p "Please select:" redirectStatus

if [[ "${redirectStatus}" == "1" ]]; then
backupNginxConfig backup
read -r -p "Please enter the domain name to be redirected, for example https://www.baidu.com:" redirectDomain

            removeNginx302
            addNginx302 "${redirectDomain}"
            handleNginx stop
            handleNginx start
            if [[ -z $(pgrep -f "nginx") ]]; then
                backupNginxConfig restoreBackup
                handleNginx start
                exit 0
            fi
            checkNginx302
            exit 0
        fi
        if [[ "${redirectStatus}" == "2" ]]; then
            removeNginx302
            echoContent green " ---> 移除302重定向成功"
            exit 0
        fi
    fi
    if [[ "${selectInstallNginxBlogType}" =~ ^[1-9]$ ]]; then
        rm -rf "${nginxStaticPath}*"

        if [[ "${release}" == "alpine" ]]; then
            wget -q -P "${nginxStaticPath}" "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${selectInstallNginxBlogType}.zip"
        else
            wget -q "${wgetShowProgressStatus}" -P "${nginxStaticPath}" "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${selectInstallNginxBlogType}.zip"
        fi

        unzip -o "${nginxStaticPath}html${selectInstallNginxBlogType}.zip" -d "${nginxStaticPath}" >/dev/null
        rm -f "${nginxStaticPath}html${selectInstallNginxBlogType}.zip*"
        echoContent green " ---> 更换伪站成功"
    else
        echoContent red " ---> 选择错误，请重新选择"
        updateNginxBlog
    fi
}

# 添加新端口
addCorePort() {

    if [[ "${coreInstallType}" == "2" ]]; then
        echoContent red "\n ---> 此功能仅支持Xray-core内核"
        exit 0
    fi

    echoContent skyBlue "\n功能 1/${totalProgress} : 添加新端口"
    echoContent red "\n=============================================================="
    echoContent yellow "# 注意事项\n"
    echoContent yellow "支持批量添加"
    echoContent yellow "不影响默认端口的使用"
    echoContent yellow "查看账号时，只会展示默认端口的账号"
    echoContent yellow "不允许有特殊字符，注意逗号的格式"
    echoContent yellow "如已安装hysteria，会同时安装hysteria新端口"
    echoContent yellow "录入示例:2053,2083,2087\n"

    echoContent yellow "1.查看已添加端口"
    echoContent yellow "2.添加端口"
    echoContent yellow "3.删除端口"
    echoContent red "=============================================================="
    read -r -p "请选择:" selectNewPortType
    if [[ "${selectNewPortType}" == "1" ]]; then
        find ${configPath} -name "*dokodemodoor*" | grep -v "hysteria" | awk -F "[c][o][n][f][/]" '{print $2}' | awk -F "[_]" '{print $4}' | awk -F "[.]" '{print ""NR""":"$1}'
        exit 0
    elif [[ "${selectNewPortType}" == "2" ]]; then
        read -r -p "请输入端口号:" newPort
        read -r -p "请输入默认的端口号，同时会更改订阅端口以及节点端口，[回车]默认443:" defaultPort

        if [[ -n "${defaultPort}" ]]; then
            rm -rf "$(find ${configPath}* | grep "default")"
        fi

        if [[ -n "${newPort}" ]]; then

            while read -r port; do
                rm -rf "$(find ${configPath}* | grep "${port}")"

                local fileName=
                local hysteriaFileName=
                if [[ -n "${defaultPort}" && "${port}" == "${defaultPort}" ]]; then
                    fileName="${configPath}02_dokodemodoor_inbounds_${port}_default.json"
                else
                    fileName="${configPath}02_dokodemodoor_inbounds_${port}.json"
                fi

                if [[ -n ${hysteriaPort} ]]; then
                    hysteriaFileName="${configPath}02_dokodemodoor_inbounds_hysteria_${port}.json"
                fi

                # 开放端口
                allowPort "${port}"
                allowPort "${port}" "udp"

                local settingsPort=443
                if [[ -n "${customPort}" ]]; then
                    settingsPort=${customPort}
                fi

                if [[ -n ${hysteriaFileName} ]]; then
                    cat <<EOF >"${hysteriaFileName}"
{
  "inbounds": [
	{
	  "listen": "0.0.0.0",
	  "port": ${port},
	  "protocol": "dokodemo-door",
	  "settings": {
		"address": "127.0.0.1",
		"port": ${hysteriaPort},
		"network": "udp",
		"followRedirect": false
	  },
	  "tag": "dokodemo-door-newPort-hysteria-${port}"
	}
  ]

}
EOF
                fi
                cat <<EOF >"${fileName}"
{
  "inbounds": [
	{
	  "listen": "0.0.0.0",
	  "port": ${port},
	  "protocol": "dokodemo-door",
	  "settings": {
		"address": "127.0.0.1",
		"port": ${settingsPort},
		"network": "tcp",
		"followRedirect": false
	  },
	  "tag": "dokodemo-door-newPort-${port}"
	}
  ]
}
EOF
            done < <(echo "${newPort}" | tr ',' '\n')

            echoContent green " ---> Added"
            reloadCore
            addCorePort
        fi
    elif [[ "${selectNewPortType}" == "3" ]]; then
        find ${configPath}-name "*dokodemodoor*" | grep -v "hysteria" | awk -F "[c][o][n][f][/]" '{print $2}' | awk -F "[_]" '{print $4}' | awk -F "[.]" '{print ""NR""":"$1}'
read -r -p "Please enter the port number to be deleted:" portIndex
local dokoConfig
dokoConfig=$(find ${configPath} -name "*dokodemodoor*" | grep -v "hysteria" | awk -F "[c][o][n][f][/]" '{print $2}' | awk -F "[_]" '{print $4}' | awk -F "[.]" '{print ""NR""":"$1}' | grep "${portIndex}:")
if [[ -n "${dokoConfig}" ]]; then
            rm "${configPath}02_dokodemodoor_inbounds_$(echo "${dokoConfig}" | awk -F "[:]" '{print $2}').json"
            local hysteriaDokodemodoorFilePath=

            hysteriaDokodemodoorFilePath="${configPath}02_dokodemodoor_inbounds_hysteria_$(echo "${dokoConfig}" | awk -F "[:]" '{print $2}').json"
            if [[ -f "${hysteriaDokodemodoorFilePath}" ]]; then
                rm "${hysteriaDokodemodoorFilePath}"
            fi

            reloadCore
            addCorePort
        else
            echoContent yellow "\n ---> The number entered is wrong, please choose again"
            addCorePort
        fi
    fi
}

# Uninstall script
unInstall() {
read -r -p "Are you sure to uninstall the installation content? [y/n]:" unInstallStatus
if [[ "${unInstallStatus}" != "y" ]]; then
echoContent green " ---> Abandon uninstallation"
menu
exit 0
fi
checkBTPanel
echoContent yellow " ---> The script will not delete acme related configurations, please delete manually [rm -rf /root/.acme.sh]"
handleNginx stop
if [[ -z $(pgrep -f "nginx") ]]; then
echoContent green " ---> Stop Nginx successfully"
fi
if [[ "${release}" == "alpine" ]]; then
if [[ "${coreInstallType}" == "1" ]]; then
handleXray stop
rc-update del xray default
rm -rf /etc/init.d/xray
echoContent green " ---> Delete Xray startup complete"
fi
if [[ "${coreInstallType}" == "2" || -n "${singBoxConfigPath}" ]]; then
handleSingBox stop
rc-update del sing-box default
rm -rf /etc/init.d/sing-box
echoContent green " ---> Delete sing-box startup complete"
fi
else
if [[ "${coreInstallType}" == "1" ]]; then
handleXray stop
rm -rf /etc/systemd/system/xray.service
echoContent green " ---> Delete Xray startup complete"
fi
if [[ "${coreInstallType}" == "2" || -n "${singBoxConfigPath}" ]]; then
handleSingBox stop
rm -rf /etc/systemd/system/sing-box.service
            echoContent green " ---> Delete sing-box and it will start automatically after booting"
        fi
    fi

    rm -rf /etc/v2ray-agent
    rm -rf ${nginxConfigPath}alone.conf
    rm -rf ${nginxConfigPath}checkPortOpen.conf >/dev/null 2>&1
    rm -rf "${nginxConfigPath}sing_box_VMess_HTTPUpgrade.conf" >/dev/null 2>&1
    rm -rf ${nginxConfigPath}checkPortOpen.conf >/dev/null 2>&1

    unInstallSubscribe

    if [[ -d "${nginxStaticPath}" && -f "${nginxStaticPath}/check" ]]; then
        rm -rf "${nginxStaticPath}*"
        echoContent green " ---> Deleting the disguised website is complete"
fi

rm -rf /usr/bin/vasma
rm -rf /usr/sbin/vasma
echoContent green " ---> Uninstalling shortcuts is complete"
echoContent green " ---> Uninstalling v2ray-agent script is complete"
}

# CDN node management
manageCDN() {
echoContent skyBlue "\nProgress $1/1 : CDN node management"
local setCDNDomain=

if echo "${currentInstallProtocolType}" | grep -qE ",1,|,2,|,3,|,5,|,11,"; then
echoContent red "================================================================"
echoContent yellow "# Notes"
echoContent yellow "\nTutorial address:"

echoContent skyBlue "https://www.v2ray-agent.com/archives/cloudflarezi-xuan-ip"
echoContent red "\nIf you don't understand Cloudflare optimization, please don't use it"

echoContent yellow "1.CNAME www.digitalocean.com"
echoContent yellow "2.CNAME who.int"
echoContent yellow "3.CNAME blog.hostmonit.com"
echoContent yellow "4.CNAME www.visa.com.hk"
echoContent yellow "5. Manual input [You can enter multiple, for example: 1.1.1.1,1.1.2.2,cloudflare.com comma separated]"
echoContent yellow "6. Remove CDN node"
echoContent red "================================================================"
read -r -p "Please select:" selectCDNType
case ${selectCDNType} in
1)
setCDNDomain="www.digitalocean.com"
;;
2)
setCDNDomain="who.int"
;;
3)
setCDNDomain="blog.hostmonit.com"
;;
4)
setCDNDomain="www.visa.com.hk"
;;
5)
read -r -p "Please enter the CDN IP or domain name you want to customize:" setCDNDomain
;;
6)
echo >/etc/v2ray-agent/cdn
echoContent green " ---> Successfully removed"
exit 0
;;
esac

if [[ -n "${setCDNDomain}" ]]; then
echo >/etc/v2ray-agent/cdn
echo "${setCDNDomain}" >"/etc/v2ray-agent/cdn"
echoContent green " ---> CDN modification successful"
subscribe false false
else
echoContent red " ---> Cannot be empty, please re-enter"
manageCDN 1
fi
else
echoContent yellow "\nTutorial address:"
echoContent skyBlue "https://www.v2ray-agent.com/archives/cloudflarezi-xuan-ip\n"
echoContent red " ---> No usable protocol detected, only ws, grpc, HTTPUpgrade related protocols are supported"
fi
}
# Custom uuid
customUUID() {
read -r -p "Please enter a legal UUID, [Enter] random UUID:" currentCustomUUID
    echo
    if [[ -z "${currentCustomUUID}" ]]; then
        if [[ "${selectInstallType}" == "1" || "${coreInstallType}" == "1" ]]; then
            currentCustomUUID=$(${ctlPath} uuid)
        elif [[ "${selectInstallType}" == "2" || "${coreInstallType}" == "2" ]]; then
            currentCustomUUID=$(${ctlPath} generate uuid)
        fi

        echoContent yellow "uuid：${currentCustomUUID}\n"

    else
        local checkUUID=
        if [[ "${coreInstallType}" == "1" ]]; then
            checkUUID=$(jq -r --arg currentUUID "$currentCustomUUID" ".inbounds[0].settings.clients[] | select(.uuid | index(\$currentUUID) != null) | .name" ${configPath}${frontingType}.json)
        elif [[ "${coreInstallType}" == "2" ]]; then
            checkUUID=$(jq -r --arg currentUUID "$currentCustomUUID" ".inbounds[0].users[] | select(.uuid | index(\$currentUUID) != null) | .name//.username" ${configPath}${frontingType}.json)
        fi

        if [[ -n "${checkUUID}" ]]; then
            echoContent red " ---> UUID cannot be repeated"
            exit 0
        fi
    fi
}

# Custom email
customUserEmail() {
    read -r -p "Please enter a valid email, [Enter] random email:" currentCustomEmail
    echo
    if [[ -z "${currentCustomEmail}" ]]; then
        currentCustomEmail="${currentCustomUUID}"
        echoContent yellow "email: ${currentCustomEmail}\n"
    else
        local checkEmail=
        if [[ "${coreInstallType}" == "1" ]]; then
            local frontingTypeConfig="${frontingType}"
            if [[ "${currentInstallProtocolType}" == ",7,8," ]]; then
                frontingTypeConfig="07_VLESS_vision_reality_inbounds"
            fi

            checkEmail=$(jq -r --arg currentEmail "$currentCustomEmail" ".inbounds[0].settings.clients[] | select(.name | index(\$currentEmail) != null) | .name" ${configPath}${frontingTypeConfig}.json)
        elif
            [[ "${coreInstallType}" == "2" ]]
        then
            checkEmail=$(jq -r --arg currentEmail "$currentCustomEmail" ".inbounds[0].users[] | select(.name | index(\$currentEmail) != null) | .name" ${configPath}${frontingType}.json)
        fi

        if [[ -n "${checkEmail}" ]]; then
            echoContent red " ---> email cannot be repeated"
            exit 0
        fi
    fi
}

#Add user
addUser() {

    read -r -p "请输入要添加的用户数量:" userNum
    echo
    if [[ -z ${userNum} || ${userNum} -le 0 ]]; then
        echoContent red " ---> 输入有误，请重新输入"
        exit 0
    fi
    local userConfig=
    if [[ "${coreInstallType}" == "1" ]]; then
        userConfig=".inbounds[0].settings.clients"
    elif [[ "${coreInstallType}" == "2" ]]; then
        userConfig=".inbounds[0].users"
    fi

    while [[ ${userNum} -gt 0 ]]; do
        readConfigHostPathUUID
        local users=
        ((userNum--)) || true

        customUUID
        customUserEmail

        uuid=${currentCustomUUID}
        email=${currentCustomEmail}

        # VLESS TCP
        if echo "${currentInstallProtocolType}" | grep -q ",0,"; then
            local clients=
            if [[ "${coreInstallType}" == "1" ]]; then
                clients=$(initXrayClients 0 "${uuid}" "${email}")
            elif [[ "${coreInstallType}" == "2" ]]; then
                clients=$(initSingBoxClients 0 "${uuid}" "${email}")
            fi
            clients=$(jq -r "${userConfig} = ${clients}" ${configPath}02_VLESS_TCP_inbounds.json)
            echo "${clients}" | jq . >${configPath}02_VLESS_TCP_inbounds.json
        fi

        # VLESS WS
        if echo "${currentInstallProtocolType}" | grep -q ",1,"; then
            local clients=
            if [[ "${coreInstallType}" == "1" ]]; then
                clients=$(initXrayClients 1 "${uuid}" "${email}")
            elif [[ "${coreInstallType}" == "2" ]]; then
                clients=$(initSingBoxClients 1 "${uuid}" "${email}")
            fi

            clients=$(jq -r "${userConfig} = ${clients}" ${configPath}03_VLESS_WS_inbounds.json)
            echo "${clients}" | jq . >${configPath}03_VLESS_WS_inbounds.json
        fi

        # trojan grpc
        if echo "${currentInstallProtocolType}" | grep -q ",2,"; then
            local clients=
            if [[ "${coreInstallType}" == "1" ]]; then
                clients=$(initXrayClients 2 "${uuid}" "${email}")
            elif [[ "${coreInstallType}" == "2" ]]; then
                clients=$(initSingBoxClients 2 "${uuid}" "${email}")
            fi

            clients=$(jq -r "${userConfig} = ${clients}" ${configPath}04_trojan_gRPC_inbounds.json)
            echo "${clients}" | jq . >${configPath}04_trojan_gRPC_inbounds.json
        fi
        # VMess WS
        if echo "${currentInstallProtocolType}" | grep -q ",3,"; then
            local clients=
            if [[ "${coreInstallType}" == "1" ]]; then
                clients=$(initXrayClients 3 "${uuid}" "${email}")
            elif [[ "${coreInstallType}" == "2" ]]; then
                clients=$(initSingBoxClients 3 "${uuid}" "${email}")
            fi

            clients=$(jq -r "${userConfig} = ${clients}" ${configPath}05_VMess_WS_inbounds.json)
            echo "${clients}" | jq . >${configPath}05_VMess_WS_inbounds.json
        fi
        # trojan tcp
        if echo "${currentInstallProtocolType}" | grep -q ",4,"; then
            local clients=
            if [[ "${coreInstallType}" == "1" ]]; then
                clients=$(initXrayClients 4 "${uuid}" "${email}")
            elif [[ "${coreInstallType}" == "2" ]]; then
                clients=$(initSingBoxClients 4 "${uuid}" "${email}")
            fi
            clients=$(jq -r "${userConfig} = ${clients}" ${configPath}04_trojan_TCP_inbounds.json)
            echo "${clients}" | jq . >${configPath}04_trojan_TCP_inbounds.json
        fi

        # vless grpc
        if echo "${currentInstallProtocolType}" | grep -q ",5,"; then
            local clients=
            if [[ "${coreInstallType}" == "1" ]]; then
                clients=$(initXrayClients 5 "${uuid}" "${email}")
            elif [[ "${coreInstallType}" == "2" ]]; then
                clients=$(initSingBoxClients 5 "${uuid}" "${email}")
            fi
            clients=$(jq -r "${userConfig} = ${clients}" ${configPath}06_VLESS_gRPC_inbounds.json)

            echo "${clients}" | jq . >${configPath}06_VLESS_gRPC_inbounds.json
        fi

        # vless reality vision
        if echo "${currentInstallProtocolType}" | grep -q ",7,"; then
            local clients=
            if [[ "${coreInstallType}" == "1" ]]; then
                clients=$(initXrayClients 7 "${uuid}" "${email}")
            elif [[ "${coreInstallType}" == "2" ]]; then
                clients=$(initSingBoxClients 7 "${uuid}" "${email}")
            fi
            clients=$(jq -r "${userConfig} = ${clients}" ${configPath}07_VLESS_vision_reality_inbounds.json)
            echo "${clients}" | jq . >${configPath}07_VLESS_vision_reality_inbounds.json
        fi

        # vless reality grpc
        if echo "${currentInstallProtocolType}" | grep -q ",8,"; then
            local clients=
            if [[ "${coreInstallType}" == "1" ]]; then
                clients=$(initXrayClients 8 "${uuid}" "${email}")
            elif [[ "${coreInstallType}" == "2" ]]; then
                clients=$(initSingBoxClients 8 "${uuid}" "${email}")
            fi
            clients=$(jq -r "${userConfig} = ${clients}" ${configPath}08_VLESS_vision_gRPC_inbounds.json)
            echo "${clients}" | jq . >${configPath}08_VLESS_vision_gRPC_inbounds.json
        fi

        # hysteria2
        if echo ${currentInstallProtocolType} | grep -q ",6,"; then
            local clients=

            if [[ "${coreInstallType}" == "1" ]]; then
                clients=$(initXrayClients 6 "${uuid}" "${email}")
            elif [[ -n "${singBoxConfigPath}" ]]; then
                clients=$(initSingBoxClients 6 "${uuid}" "${email}")
            fi

            clients=$(jq -r ".inbounds[0].users = ${clients}" "${singBoxConfigPath}06_hysteria2_inbounds.json")
            echo "${clients}" | jq . >"${singBoxConfigPath}06_hysteria2_inbounds.json"
        fi

        # tuic
        if echo ${currentInstallProtocolType} | grep -q ",9,"; then
            local clients=
            if [[ "${coreInstallType}" == "1" ]]; then
                clients=$(initXrayClients 9 "${uuid}" "${email}")
            elif [[ "${coreInstallType}" == "2" ]]; then
                clients=$(initSingBoxClients 9 "${uuid}" "${email}")
            fi

            clients=$(jq -r ".inbounds[0].users = ${clients}" "${singBoxConfigPath}09_tuic_inbounds.json")

            echo "${clients}" | jq . >"${singBoxConfigPath}09_tuic_inbounds.json"
        fi
        # naive
        if echo ${currentInstallProtocolType} | grep -q ",10,"; then
            local clients=
            clients=$(initSingBoxClients 10 "${uuid}" "${email}")
            clients=$(jq -r ".inbounds[0].users = ${clients}" "${singBoxConfigPath}10_naive_inbounds.json")

            echo "${clients}" | jq . >"${singBoxConfigPath}10_naive_inbounds.json"
        fi
        # VMess WS
        if echo "${currentInstallProtocolType}" | grep -q ",11,"; then
            local clients=
            if [[ "${coreInstallType}" == "1" ]]; then
                clients=$(initXrayClients 11 "${uuid}" "${email}")
            elif [[ "${coreInstallType}" == "2" ]]; then
                clients=$(initSingBoxClients 11 "${uuid}" "${email}")
            fi

            clients=$(jq -r "${userConfig} = ${clients}" ${configPath}11_VMess_HTTPUpgrade_inbounds.json)
            echo "${clients}" | jq . >${configPath}11_VMess_HTTPUpgrade_inbounds.json
        fi
    done
    reloadCore
    echoContent green " ---> 添加完成"
    subscribe false
    manageAccount 1
}
# 移除用户
removeUser() {
    local userConfigType=
    if [[ -n "${frontingType}" ]]; then
        userConfigType="${frontingType}"
    elif [[ -n "${frontingTypeReality}" ]]; then
        userConfigType="${frontingTypeReality}"
    fi

    local uuid=
    if [[ -n "${userConfigType}" ]]; then
        if [[ "${coreInstallType}" == "1" ]]; then
            jq -r -c .inbounds[0].settings.clients[].email ${configPath}${userConfigType}.json | awk '{print NR""":"$0}'

elif [[ "${coreInstallType}" == "2" ]]; then
jq -r -c .inbounds[0].users[].name//.inbounds[0].users[].username ${configPath}${userConfigType}.json | awk '{print NR""":"$0}'
fi

read -r -p "Please select the user number to be deleted [only single deletion is supported]:" delUserIndex
if [[ $(jq -r '.inbounds[0].settings.clients|length' ${configPath}${userConfigType}.json) -lt ${delUserIndex} && $(jq -r '.inbounds[0].users|length' ${configPath}${userConfigType}.json) -lt ${delUserIndex} ]]; then
echoContent red " ---> Selection error"
else
            delUserIndex=$((delUserIndex - 1))
        fi
    fi

    if [[ -n "${delUserIndex}" ]]; then

        if echo ${currentInstallProtocolType} | grep -q ",0,"; then
            local vlessVision
            vlessVision=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}']//.inbounds[0].users['${delUserIndex}'])' ${configPath}02_VLESS_TCP_inbounds.json)
            echo "${vlessVision}" | jq . >${configPath}02_VLESS_TCP_inbounds.json
        fi
        if echo ${currentInstallProtocolType} | grep -q ",1,"; then
            local vlessWSResult
            vlessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}03_VLESS_WS_inbounds.json)
            echo "${vlessWSResult}" | jq . >${configPath}03_VLESS_WS_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q ",2,"; then
            local trojangRPCUsers
            trojangRPCUsers=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}04_trojan_gRPC_inbounds.json)
            echo "${trojangRPCUsers}" | jq . >${configPath}04_trojan_gRPC_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q ",3,"; then
            local vmessWSResult
            vmessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}']//.inbounds[0].users['${delUserIndex}'])' ${configPath}05_VMess_WS_inbounds.json)
            echo "${vmessWSResult}" | jq . >${configPath}05_VMess_WS_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q ",5,"; then
            local vlessGRPCResult
            vlessGRPCResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}']//.inbounds[0].users['${delUserIndex}'])' ${configPath}06_VLESS_gRPC_inbounds.json)
            echo "${vlessGRPCResult}" | jq . >${configPath}06_VLESS_gRPC_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q ",4,"; then
            localtrojanTCPResult
            trojanTCPResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}']//.inbounds[0].users['${delUserIndex}'])' ${configPath}04_trojan_TCP_inbounds.json)
            echo "${trojanTCPResult}" | jq . >${configPath}04_trojan_TCP_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q ",7,"; then
            local vlessRealityResult
            vlessRealityResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}']//.inbounds[0].users['${delUserIndex}'])' ${configPath}07_VLESS_vision_reality_inbounds.json)
            echo "${vlessRealityResult}" | jq . >${configPath}07_VLESS_vision_reality_inbounds.json
        fi
        if echo ${currentInstallProtocolType} | grep -q ",8,"; then
            local vlessRealityGRPCResult
            vlessRealityGRPCResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}']//.inbounds[0].users['${delUserIndex}'])' ${configPath}08_VLESS_vision_gRPC_inbounds.json)
            echo "${vlessRealityGRPCResult}" | jq . >${configPath}08_VLESS_vision_gRPC_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q ",6,"; then
            local hysteriaResult
            hysteriaResult=$(jq -r 'del(.inbounds[0].users['${delUserIndex}']//.inbounds[0].users['${delUserIndex}'])' "${singBoxConfigPath}06_hysteria2_inbounds.json")
            echo "${hysteriaResult}" | jq . >"${singBoxConfigPath}06_hysteria2_inbounds.json"
        fi

        if echo ${currentInstallProtocolType} | grep -q ",9,"; then
            local tuicResult
            tuicResult=$(jq -r 'del(.inbounds[0].users['${delUserIndex}']//.inbounds[0].users['${delUserIndex}'])' "${singBoxConfigPath}09_tuic_inbounds.json")
            echo "${tuicResult}" | jq . >"${singBoxConfigPath}09_tuic_inbounds.json"
        fi
        if echo ${currentInstallProtocolType} | grep -q ",10,"; then
            local naiveResult
            naiveResult=$(jq -r 'del(.inbounds[0].users['${delUserIndex}']//.inbounds[0].users['${delUserIndex}'])' "${singBoxConfigPath}10_naive_inbounds.json")
            echo "${naiveResult}" | jq . >"${singBoxConfigPath}10_naive_inbounds.json"
        fi
        # VMess HTTPUpgrade
        if echo ${currentInstallProtocolType} | grep -q ",11,"; then
            local vmessHTTPUpgradeResult
            vmessHTTPUpgradeResult=$(jq -r 'del(.inbounds[0].users['${delUserIndex}']//.inbounds[0].users['${delUserIndex}'])' "${singBoxConfigPath}11_VMess_HTTPUpgrade_inbounds.json")
            echo "${vmessHTTPUpgradeResult}" | jq . >"${singBoxConfigPath}11_VMess_HTTPUpgrade_inbounds.json"
            echo "${vmessHTTPUpgradeResult}" | jq . >${configPath}11_VMess_HTTPUpgrade_inbounds.json
        fi
        reloadCore
        subscribe false
    fi
    manageAccount 1
}
# 更新脚本
updateV2RayAgent() {
    echoContent skyBlue "\n进度  $1/${totalProgress} : 更新v2ray-agent脚本"
    rm -rf /etc/v2ray-agent/install.sh
    if [[ "${release}" == "alpine" ]]; then
        wget -c -q -P /etc/v2ray-agent/ -N --no-check-certificate "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh"
    else
        wget -c -q "${wgetShowProgressStatus}" -P /etc/v2ray-agent/ -N --no-check-certificate "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh"
    fi

    sudo chmod 700 /etc/v2ray-agent/install.sh
    local version
    version=$(grep '当前版本：v' "/etc/v2ray-agent/install.sh" | awk -F "[v]" '{print $2}' | tail -n +2 | head -n 1 | awk -F "[\"]" '{print $1}')

    echoContent green "\n ---> 更新完毕"
    echoContent yellow " ---> 请手动执行[vasma]打开脚本"
    echoContent green " ---> 当前版本：${version}\n"
    echoContent yellow "如更新不成功，请手动执行下面命令\n"
    echoContent skyBlue "wget -P /root -N --no-check-certificate https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh && chmod 700 /root/install.sh && /root/install.sh"
    echo
    exit 0
}

# 防火墙
handleFirewall() {
    if systemctl status ufw 2>/dev/null | grep -q "active (exited)" && [[ "$1" == "stop" ]]; then
        systemctl stop ufw >/dev/null 2>&1
        systemctl disable ufw >/dev/null 2>&1
        echoContent green " ---> ufw关闭成功"

    fi

    if systemctl status firewalld 2>/dev/null | grep -q "active (running)" && [[ "$1" == "stop" ]]; then
        systemctl stop firewalld >/dev/null 2>&1
        systemctl disable firewalld >/dev/null 2>&1
        echoContent green " ---> firewalld关闭成功"
    fi
}

# 安装BBR
bbrInstall() {
    echoContent red "\n=============================================================="
    echoContent green "BBR、DD脚本用的[ylx2016]的成熟作品，地址[https://github.com/ylx2016/Linux-NetSpeed]，请熟知"
    echoContent yellow "1.安装脚本【推荐原版BBR+FQ】"
    echoContent yellow "2.回退主目录"
    echoContent red "=============================================================="
    read -r -p "请选择:" installBBRStatus
    if [[ "${installBBRStatus}" == "1" ]]; then
        wget -N --no-check-certificate "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
    else
        menu
    fi
}

# 查看、检查日志
checkLog() {
    if [[ "${coreInstallType}" == "2" ]]; then
        echoContent red "\n ---> 此功能仅支持Xray-core内核"
        exit 0
    fi
    if [[ -z "${configPath}" && -z "${realityStatus}" ]]; then
        echoContent red " ---> 没有检测到安装目录，请执行脚本安装内容"
        exit 0
    fi
    local realityLogShow=
    local logStatus=false
    if grep -q "access" ${configPath}00_log.json; then
        logStatus=true

    fi

echoContent skyBlue "\nFunction $1/${totalProgress}: View log"
echoContent red "\n================================================================="
echoContent yellow "# It is recommended to open the access log only during debugging\n"

if [[ "${logStatus}" == "false" ]]; then
echoContent yellow "1. Open access log"
else
echoContent yellow "1. Close access log"
fi

echoContent yellow "2. Monitor access log"
echoContent yellow "3. Monitor error log"
echoContent yellow "4. View certificate scheduled task log"
echoContent yellow "5. View certificate installation log"
echoContent yellow "6. Clear log"
echoContent red "=============================================================="

    read -r -p "Please select:" selectAccessLogType
    local configPathLog=${configPath//conf\//}

    case ${selectAccessLogType} in
    1)
        if [[ "${logStatus}" == "false" ]]; then
            realityLogShow=true
            cat <<EOF >${configPath}00_log.json
{
  "log": {
  	"access":"${configPathLog}access.log",
    "error": "${configPathLog}error.log",
    "loglevel": "debug"
  }
}
EOF
        elif [[ "${logStatus}" == "true" ]]; then
            realityLogShow=false
            cat <<EOF >${configPath}00_log.json
{
  "log": {
    "error": "${configPathLog}error.log",
    "loglevel": "warning"
  }
}
EOF
        fi

        if [[ -n ${realityStatus} ]]; then
            local vlessVisionRealityInbounds
            vlessVisionRealityInbounds=$(jq -r ".inbounds[0].streamSettings.realitySettings.show=${realityLogShow}" ${configPath}07_VLESS_vision_reality_inbounds.json)
            echo "${vlessVisionRealityInbounds}" | jq . >${configPath}07_VLESS_vision_reality_inbounds.json
        fi
        reloadCore
        checkLog 1
        ;;
    2)
        tail -f ${configPathLog}access.log
        ;;
    3)
        tail -f ${configPathLog}error.log
        ;;
    4)
        if [[ ! -f "/etc/v2ray-agent/crontab_tls.log" ]]; then
            touch /etc/v2ray-agent/crontab_tls.log
        fi
        tail -n 100 /etc/v2ray-agent/crontab_tls.log
        ;;
    5)
        tail -n 100 /etc/v2ray-agent/tls/acme.log
        ;;
    6)
        echo >${configPathLog}access.log
        echo >${configPathLog}error.log
        ;;
    esac
}

# Script shortcut
aliasInstall() {

    if [[ -f "$HOME/install.sh" ]] && [[ -d "/etc/v2ray-agent" ]] && grep <"$HOME/install.sh" -q "Author:mack-a"; then
        mv "$HOME/install.sh" /etc/v2ray-agent/install.sh
        local vasmaType=
        if [[ -d "/usr/bin/" ]]; then
            if [[ ! -f "/usr/bin/vasma" ]]; then
                ln -s /etc/v2ray-agent/install.sh /usr/bin/vasma
                chmod 700 /usr/bin/vasma
                vasmaType=true
            fi

            rm -rf "$HOME/install.sh"
        elif [[ -d "/usr/sbin" ]]; then
            if [[ ! -f "/usr/sbin/vasma" ]]; then
                ln -s /etc/v2ray-agent/install.sh /usr/sbin/vasma
                chmod 700 /usr/sbin/vasma
                vasmaType=true fi
rm -rf "$HOME/install.sh"
fi
if [[ "${vasmaType}" == "true" ]]; then
echoContent green "Shortcut created successfully, [vasma] can be executed to reopen the script"
fi
fi
}

# Check ipv6, ipv4
checkIPv6() {
currentIPv6IP=$(curl -s -6 -m 4 http://www.cloudflare.com/cdn-cgi/trace | grep "ip" | cut -d "=" -f 2)

if [[ -z "${currentIPv6IP}" ]]; then
echoContent red " ---> ipv6 is not supported"
exit 0
fi
}

# ipv6 diversion
ipv6Routing() {
if [[ -z "${configPath}" ]]; then
echoContent red " ---> Not installed, please use the script to install"
menu
exit 0
fi

checkIPv6
echoContent skyBlue "\nFunction 1/${totalProgress} : IPv6 diversion"
echoContent red "\n================================================================="
echoContent yellow "1. View diverted domain names"
echoContent yellow "2. Add domain names"
echoContent yellow "3. Set IPv6 global"
echoContent yellow "4. Uninstall IPv6 diversion"
echoContent red "===================================================================="
read -r -p "Please select:" ipv6Status
    if [[ "${ipv6Status}" == "1" ]]; then
        showIPv6Routing
        exit 0

    elif [[ "${ipv6Status}" == "2" ]]; then
echoContent red "================================================================"
echoContent yellow "# Notes\n"
echoContent yellow "# Notes"
echoContent yellow "# Tutorial: https://www.v2ray-agent.com/archives/1683226921000 \n"
read -r -p "Please enter the domain name according to the above example:" domainList
if [[ "${coreInstallType}" == "1" ]]; then
addInstallRouting IPv6_out outboundTag "${domainList}"
addXrayOutbound IPv6_out
fi

if [[ -n "${singBoxConfigPath}" ]]; then
addSingBoxRouteRule "IPv6_out" "${domainList}" "IPv6_route"
addSingBoxOutbound 01_direct_outbound
addSingBoxOutbound IPv6_out
addSingBoxOutbound IPv4_out
fi

echoContent green " ---> Added"

elif [[ "${ipv6Status}" == "3" ]]; then

echoContent red "================================================================"
echoContent yellow "# Notes\n"
echoContent yellow "1. Will delete all set diversion rules"
echoContent yellow "2. All outbound rules except IPv6 will be deleted\n"
read -r -p "Are you sure to set it? [y/n]:" IPv6OutStatus

if [[ "${IPv6OutStatus}" == "y" ]]; then
if [[ "${coreInstallType}" == "1" ]]; then
addXrayOutbound IPv6_out
removeXrayOutbound IPv4_out
removeXrayOutbound z_direct_outbound
removeXrayOutbound blackhole_out
removeXrayOutbound wireguard_out_IPv4
removeXrayOutbound wireguard_out_IPv6
removeXrayOutbound socks5_outbound

rm ${configPath}09_routing.json >/dev/null 2>&1
fi
if [[ -n "${singBoxConfigPath}" ]]; then

removeSingBoxConfig IPv4_out

removeSingBoxConfig wireguard_endpoints_IPv4_route
                removeSingBoxConfig wireguard_endpoints_IPv6_route
                removeSingBoxConfig wireguard_endpoints_IPv4
                removeSingBoxConfig wireguard_endpoints_IPv6

                removeSingBoxConfig socks5_inbound_route

                removeSingBoxConfig IPv6_route

                removeSingBoxConfig 01_direct_outbound

                addSingBoxOutbound IPv6_out

            fi

            echoContent green " ---> IPv6 global outbound settings completed"
        else

            echoContent green " ---> Abandon settings"
            exit 0
        fi

    elif [[ "${ipv6Status}" == "4" ]]; then
        if [[ "${coreInstallType}" == "1" ]]; then
            unInstallRouting IPv6_out outboundTag

            removeXrayOutbound IPv6_out addXrayOutbound "z_direct_outbound"
fi

if [[ -n "${singBoxConfigPath}" ]]; then
removeSingBoxConfig IPv6_out
removeSingBoxConfig "IPv6_route"
addSingBoxOutbound "01_direct_outbound"
fi

echoContent green " ---> IPv6 diversion uninstallation successful"
else
echoContent red " ---> Selection error"
exit 0
fi

reloadCore
}

# ipv6 diversion rule display
showIPv6Routing() {
if [[ "${coreInstallType}" == "1" ]]; then
if [[ -f "${configPath}09_routing.json" ]]; then
echoContent yellow "Xray-core："
jq -r -c '.routing.rules[]|select (.outboundTag=="IPv6_out")|.domain' ${configPath}09_routing.json | jq -r
        elif [[ ! -f "${configPath}09_routing.json" && -f "${configPath}IPv6_out.json" ]]; then
            echoContent yellow "Xray-core"
            echoContent green " ---> IPv6 global offloading has been set up"
        else
            echoContent yellow " ---> IPv6 offloading is not installed"
        fi

    fi
    if [[ -n "${singBoxConfigPath}" ]]; then
        if [[ -f "${singBoxConfigPath}IPv6_route.json" ]]; then
            echoContent yellow "sing-box"
            jq -r -c '.route.rules[]|select (.outbound=="IPv6_out")' "${singBoxConfigPath}IPv6_route.json" | jq -r
        elif [[ ! -f "${singBoxConfigPath}IPv6_route.json" && -f "${singBoxConfigPath}IPv6_out.json" ]]; then
echoContent yellow "sing-box"
echoContent green " ---> IPv6 global diversion has been set"

else
echoContent yellow " ---> IPv6 diversion is not installed"
fi
fi
}
# bt download management
btTools() {
if [[ "${coreInstallType}" == "2" ]]; then
echoContent red "\n ---> This function only supports Xray-core kernel, please wait for subsequent updates"
exit 0
fi
if [[ -z "${configPath}" ]]; then
echoContent red " ---> Not installed, please use script installation"
menu
exit 0
fi

echoContent skyBlue "\nFunction 1/${totalProgress} : bt download management"
echoContent red "\n============================================================="

if [[ -f ${configPath}09_routing.json ]] && grep -q bittorrent <${configPath}09_routing.json; then
echoContent yellow "Current status: BT download is prohibited"
else
echoContent yellow "Current status: BT download is allowed"
fi

echoContent yellow "1. BT download is prohibited"
echoContent yellow "2. BT download is allowed"
echoContent red "==================================================================="
read -r -p "Please select:" btStatus
if [[ "${btStatus}" == "1" ]]; then

if [[ -f "${configPath}09_routing.json" ]]; then

unInstallRouting blackhole_out outboundTag bittorrent

            routing=$(jq -r '.routing.rules += [{"type":"field","outboundTag":"blackhole_out","protocol":["bittorrent"]}]' ${configPath}09_routing.json)

            echo "${routing}" | jq . >${configPath}09_routing.json

        else
            cat <<EOF >${configPath}09_routing.json
{
    "routing":{
        "domainStrategy": "IPOnDemand",
        "rules": [
          {
            "type": "field",
            "outboundTag": "blackhole_out",
            "protocol": [ "bittorrent" ]
          }
        ]
  }
}
EOF
        fi

        installSniffing
        removeXrayOutbound blackhole_out
        addXrayOutbound blackhole_out

        echoContent green " ---> Disable BT download"

elif [[ "${btStatus}" == "2" ]]; then

unInstallSniffing

unInstallRouting blackhole_out outboundTag bittorrent

echoContent green " ---> Allow BT download"
else
echoContent red " ---> Select error"
exit 0
fi

reloadCore
}

# Domain blacklist
blacklist() {
if [[ -z "${configPath}" ]]; then
echoContent red " ---> Not installed, please use script to install"
menu
exit 0
fi

echoContent skyBlue "\nProgress $1/${totalProgress} : Domain blacklist"
echoContent red "\n=================================================================="
echoContent yellow "1. View blocked domain names"
echoContent yellow "2. Add domain names"
echoContent yellow "3. Block mainland domain names"
echoContent yellow "4. Uninstall blacklist"
echoContent red "=================================================================="

read -r -p "Please select:" blacklistStatus
if [[ "${blacklistStatus}" == "1" ]]; then
jq -r -c '.routing.rules[]|select (.outboundTag=="blackhole_out")|.domain' ${configPath}09_routing.json | jq -r
exit 0
elif [[ "${blacklistStatus}" == "2" ]]; then
echoContent red "==================================================================="
echoContent yellow "# Notes\n"
echoContent yellow "1. The rule supports the predefined domain name list [https://github.com/v2fly/domain-list-community]"
echoContent yellow "2. The rule supports custom domain names"
echoContent yellow "3. Input example: speedtest, facebook, cn, example.com"
echoContent yellow "4. If the domain name exists in the predefined domain name list, use geosite:xx, if it does not exist, the input domain name will be used by default"
echoContent yellow "5. Adding rules is an incremental configuration, and the previously set content will not be deleted\n"
read -r -p "Please enter the domain name according to the above example:" domainList
if [[ "${coreInstallType}" == "1" ]]; then
addInstallRouting blackhole_out outboundTag "${domainList}"
addXrayOutbound blackhole_out
fi

if [[ -n "${singBoxConfigPath}" ]]; then
addSingBoxRouteRule "block_domain_outbound" "${domainList}" "block_domain_route"
addSingBoxOutbound "block_domain_outbound"
addSingBoxOutbound "01_direct_outbound"
fi
echoContent green "---> Added"

elif [[ "${blacklistStatus}" == "3" ]]; then

if [[ "${coreInstallType}" == "1" ]]; then
            unInstallRouting blackhole_out outboundTag

            addInstallRouting blackhole_out outboundTag "cn"

            addXrayOutbound blackhole_out
        fi

        if [[ -n "${singBoxConfigPath}" ]]; then

            addSingBoxRouteRule "cn_block_outbound" "cn" "cn_block_route"

            addSingBoxRouteRule "01_direct_outbound" "googleapis.com,googleapis.cn,xn--ngstr-lra8j.com,gstatic.com" "cn_01_google_play_route"

            addSingBoxOutbound "cn_block_outbound"
            addSingBoxOutbound "01_direct_outbound"
        fi

        echoContent green " ---> 屏蔽大陆域名完毕"

    elif [[ "${blacklistStatus}" == "4" ]]; then
        if [[ "${coreInstallType}" == "1" ]]; then
            unInstallRouting blackhole_out outboundTag
        fi

        if [[ -n "${singBoxConfigPath}" ]]; then
            removeSingBoxConfig "cn_block_route"
            removeSingBoxConfig "cn_block_outbound"

            removeSingBoxConfig "cn_01_google_play_route"

            removeSingBoxConfig "block_domain_route"
            removeSingBoxConfig "block_domain_outbound"
        fi
        echoContent green " ---> 域名黑名单删除完毕"
    else
        echoContent red " ---> 选择错误"
        exit 0
    fi
    reloadCore
}
# 添加routing配置
addInstallRouting() {

    local tag=$1    # warp-socks
    local type=$2   # outboundTag/inboundTag
    local domain=$3 # 域名

    if [[ -z "${tag}" || -z "${type}" || -z "${domain}" ]]; then
        echoContent red " ---> 参数错误"
        exit 0
    fi

    local routingRule=
    if [[ ! -f "${configPath}09_routing.json" ]]; then
        cat <<EOF >${configPath}09_routing.json
{
    "routing":{
        "type": "field",
        "rules": [
            {
                "type": "field",
                "domain": [
                ],
            "outboundTag": "${tag}"
          }
        ]
  }
}
EOF
    fi
    local routingRule=
    routingRule=$(jq -r ".routing.rules[]|select(.outboundTag==\"${tag}\" and (.protocol == null))" ${configPath}09_routing.json)

    if [[ -z "${routingRule}" ]]; then
        routingRule="{\"type\": \"field\",\"domain\": [],\"outboundTag\": \"${tag}\"}"
    fi

    while read -r line; do
        if echo "${routingRule}" | grep -q "${line}"; then
            echoContent yellow " ---> ${line}已存在，跳过"
        else
            local geositeStatus
            geositeStatus=$(curl -s "https://api.github.com/repos/v2fly/domain-list-community/contents/data/${line}" | jq .message)

            if [[ "${geositeStatus}" == "null" ]]; then
                routingRule=$(echo "${routingRule}" | jq -r '.domain += ["geosite:'"${line}"'"]')
            else
                routingRule=$(echo "${routingRule}" | jq -r '.domain += ["domain:'"${line}"'"]')
            fi
        fi
    done < <(echo "${domain}" | tr ',' '\n')

    unInstallRouting "${tag}" "${type}"
    if ! grep -q "gstatic.com" ${configPath}09_routing.json && [[ "${tag}" == "blackhole_out" ]]; then
        local routing=
        routing=$(jq -r ".routing.rules += [{\"type\": \"field\",\"domain\": [\"gstatic.com\"],\"outboundTag\": \"direct\"}]" ${configPath}09_routing.json)
        echo "${routing}" | jq . >${configPath}09_routing.json
    fi

    routing=$(jq -r ".routing.rules += [${routingRule}]" ${configPath}09_routing.json)
    echo "${routing}" | jq . >${configPath}09_routing.json
}
# 根据tag卸载Routing
unInstallRouting() {
    local tag=$1
    local type=$2
    local protocol=$3

    if [[ -f "${configPath}09_routing.json" ]]; then
        local routing=
        if [[ -n "${protocol}" ]]; then
            routing=$(jq -r "del(.routing.rules[] | select(.${type} == \"${tag}\" and (.protocol | index(\"${protocol}\"))))" ${configPath}09_routing.json)
            echo "${routing}" | jq . >${configPath}09_routing.json
        else
            routing=$(jq -r "del(.routing.rules[] | select(.${type} == \"${tag}\" and (.protocol == null )))" ${configPath}09_routing.json)
            echo "${routing}" | jq . >${configPath}09_routing.json
        fi
    fi
}

# 卸载嗅探
unInstallSniffing() {


    find ${configPath} -name "*inbounds.json*" | awk -F "[c][o][n][f][/]" '{print $2}' | while read -r inbound; do
        if grep -q "destOverride" <"${configPath}${inbound}"; then
            sniffing=$(jq -r 'del(.inbounds[0].sniffing)' "${configPath}${inbound}")
            echo "${sniffing}" | jq . >"${configPath}${inbound}"
        fi
    done

}

# 安装嗅探
installSniffing() {
    readInstallType
    if [[ "${coreInstallType}" == "1" ]]; then
        if [[ -f "${configPath}02_VLESS_TCP_inbounds.json" ]]; then
            if ! grep -q "destOverride" <"${configPath}02_VLESS_TCP_inbounds.json"; then
                sniffing=$(jq -r '.inbounds[0].sniffing = {"enabled":true,"destOverride":["http","tls","quic"]}' "${configPath}02_VLESS_TCP_inbounds.json")
                echo "${sniffing}" | jq . >"${configPath}02_VLESS_TCP_inbounds.json"
            fi
        fi
    fi
}

# 读取第三方warp配置
readConfigWarpReg() {
    if [[ ! -f "/etc/v2ray-agent/warp/config" ]]; then
        /etc/v2ray-agent/warp/warp-reg >/etc/v2ray-agent/warp/config
    fi

    secretKeyWarpReg=$(grep <"/etc/v2ray-agent/warp/config" private_key | awk '{print $2}')

    addressWarpReg=$(grep <"/etc/v2ray-agent/warp/config" v6 | awk '{print $2}')

    publicKeyWarpReg=$(grep <"/etc/v2ray-agent/warp/config" public_key | awk '{print $2}')

    reservedWarpReg=$(grep <"/etc/v2ray-agent/warp/config" reserved | awk -F "[:]" '{print $2}')

}
# 安装warp-reg工具
installWarpReg() {
    if [[ ! -f "/etc/v2ray-agent/warp/warp-reg" ]]; then
        echo
        echoContent yellow "# 注意事项"
        echoContent yellow "# 依赖第三方程序，请熟知其中风险"
        echoContent yellow "# 项目地址：https://github.com/badafans/warp-reg \n"

        read -r -p "warp-reg未安装，是否安装 ？[y/n]:" installWarpRegStatus

        if [[ "${installWarpRegStatus}" == "y" ]]; then

            curl -sLo /etc/v2ray-agent/warp/warp-reg "https://github.com/badafans/warp-reg/releases/download/v1.0/${warpRegCoreCPUVendor}"
            chmod 655 /etc/v2ray-agent/warp/warp-reg

        else
            echoContent yellow " ---> 放弃安装"
            exit 0
        fi
    fi
}

# 展示warp分流域名
showWireGuardDomain() {
    local type=$1
    # xray
    if [[ "${coreInstallType}" == "1" ]]; then
        if [[ -f "${configPath}09_routing.json" ]]; then
            echoContent yellow "Xray-core"
            jq -r -c '.routing.rules[]|select (.outboundTag=="wireguard_out_'"${type}"'")|.domain' ${configPath}09_routing.json | jq -r
        elif [[ ! -f "${configPath}09_routing.json" && -f "${configPath}wireguard_out_${type}.json" ]]; then
            echoContent yellow "Xray-core"
            echoContent green " ---> 已设置warp ${type}全局分流"
        else
            echoContent yellow " ---> 未安装warp ${type}分流"
        fi
    fi

    # sing-box
    if [[ -n "${singBoxConfigPath}" ]]; then
        if [[ -f "${singBoxConfigPath}wireguard_endpoints_${type}_route.json" ]]; then
            echoContent yellow "sing-box"
            jq -r -c '.route.rules[]' "${singBoxConfigPath}wireguard_endpoints_${type}_route.json" | jq -r
        elif [[ ! -f "${singBoxConfigPath}wireguard_endpoints_${type}_route.json" && -f "${singBoxConfigPath}wireguard_endpoints_${type}.json" ]]; then
            echoContent yellow "sing-box"
            echoContent green " ---> 已设置warp ${type}全局分流"
        else
            echoContent yellow " ---> 未安装warp ${type}分流"
        fi
    fi

}

# 添加WireGuard分流
addWireGuardRoute() {
    local type=$1
    local tag=$2
    local domainList=$3
    # xray
    if [[ "${coreInstallType}" == "1" ]]; then

        addInstallRouting "wireguard_out_${type}" "${tag}" "${domainList}"
        addXrayOutbound "wireguard_out_${type}"
    fi
    # sing-box
    if [[ -n "${singBoxConfigPath}" ]]; then

        # rule
        addSingBoxRouteRule "wireguard_endpoints_${type}" "${domainList}" "wireguard_endpoints_${type}_route"
        # addSingBoxOutbound "wireguard_out_${type}" "wireguard_out"
        if [[ -n "${domainList}" ]]; then

            addSingBoxOutbound "01_direct_outbound"
        fi

        # outbound
        addSingBoxWireGuardEndpoints "${type}"
    fi
}

# 卸载wireGuard
unInstallWireGuard() {
    local type=$1
    if [[ "${coreInstallType}" == "1" ]]; then

        if [[ "${type}" == "IPv4" ]]; then
            if [[ ! -f "${configPath}wireguard_out_IPv6.json" ]]; then
                rm -rf /etc/v2ray-agent/warp/config >/dev/null 2>&1
            fi
        elif [[ "${type}" == "IPv6" ]]; then
            if [[ ! -f "${configPath}wireguard_out_IPv4.json" ]]; then
                rm -rf /etc/v2ray-agent/warp/config >/dev/null 2>&1
            fi
        fi
    fi

    if [[ -n "${singBoxConfigPath}" ]]; then
        if [[ ! -f "${singBoxConfigPath}wireguard_out_IPv6_route.json" && ! -f "${singBoxConfigPath}wireguard_out_IPv4_route.json" ]]; then
            rm "${singBoxConfigPath}wireguard_outbound.json" >/dev/null 2>&1
            rm -rf /etc/v2ray-agent/warp/config >/dev/null 2>&1
        fi
    fi
}
# 移除WireGuard分流
removeWireGuardRoute() {
    local type=$1
    if [[ "${coreInstallType}" == "1" ]]; then

        unInstallRouting wireguard_out_"${type}" outboundTag

        removeXrayOutbound "wireguard_out_${type}"
        if [[ ! -f "${configPath}IPv4_out.json" ]]; then
            addXrayOutbound IPv4_out
        fi
    fi

    # sing-box
    if [[ -n "${singBoxConfigPath}" ]]; then
        removeSingBoxRouteRule "wireguard_out_${type}"
    fi

    unInstallWireGuard "${type}"
}
# warp分流-第三方IPv4
warpRoutingReg() {
    local type=$2
    echoContent skyBlue "\n进度  $1/${totalProgress} : WARP分流[第三方]"
    echoContent red "=============================================================="

    echoContent yellow "1.查看已分流域名"
    echoContent yellow "2.添加域名"
    echoContent yellow "3.设置WARP全局"
    echoContent yellow "4.卸载WARP分流"
    echoContent red "=============================================================="
    read -r -p "请选择:" warpStatus
    installWarpReg
    readConfigWarpReg
    local address=
    if [[ ${type} == "IPv4" ]]; then
        address="172.16.0.2/32"
    elif [[ ${type} == "IPv6" ]]; then
        address="${addressWarpReg}/128"
    else
        echoContent red " ---> IP获取失败，退出安装"
    fi

    if [[ "${warpStatus}" == "1" ]]; then
        showWireGuardDomain "${type}"
        exit 0
    elif [[ "${warpStatus}" == "2" ]]; then
        echoContent yellow "# 注意事项"
        echoContent yellow "# 支持sing-box、Xray-core"
        echoContent yellow "# 使用教程：https://www.v2ray-agent.com/archives/1683226921000 \n"

        read -r -p "请按照上面示例录入域名:" domainList
        addWireGuardRoute "${type}" outboundTag "${domainList}"
        echoContent green " ---> 添加完毕"

    elif [[ "${warpStatus}" == "3" ]]; then

        echoContent red "=============================================================="
        echoContent yellow "# 注意事项\n"
        echoContent yellow "1.会删除所有设置的分流规则"
        echoContent yellow "2.会删除除WARP[第三方]之外的所有出站规则\n"
        read -r -p "是否确认设置？[y/n]:" warpOutStatus

        if [[ "${warpOutStatus}" == "y" ]]; then
            readConfigWarpReg
            if [[ "${coreInstallType}" == "1" ]]; then
                addXrayOutbound "wireguard_out_${type}"
                if [[ "${type}" == "IPv4" ]]; then
                    removeXrayOutbound "wireguard_out_IPv6"
                elif [[ "${type}" == "IPv6" ]]; then
                    removeXrayOutbound "wireguard_out_IPv4"
                fi

                removeXrayOutbound IPv4_out
                removeXrayOutbound IPv6_out
                removeXrayOutbound z_direct_outbound
                removeXrayOutbound blackhole_out
                removeXrayOutbound socks5_outbound

                rm ${configPath}09_routing.json >/dev/null 2>&1
            fi

            if [[ -n "${singBoxConfigPath}" ]]; then

                removeSingBoxConfig IPv4_out
                removeSingBoxConfig IPv6_out
                removeSingBoxConfig 01_direct_outbound

                # 删除所有分流规则

                removeSingBoxConfig wireguard_endpoints_IPv4_route
                removeSingBoxConfig wireguard_endpoints_IPv6_route

                removeSingBoxConfig IPv6_route
                removeSingBoxConfig socks5_inbound_route

                addSingBoxWireGuardEndpoints "${type}"
                addWireGuardRoute "${type}" outboundTag ""
                if [[ "${type}" == "IPv4" ]]; then
                    removeSingBoxConfig wireguard_endpoints_IPv6
                else
                    removeSingBoxConfig wireguard_endpoints_IPv4
                fi

                # outbound
                # addSingBoxOutbound "wireguard_out_${type}" "wireguard_out"

            fi

            echoContent green " ---> WARP全局出站设置完毕"
        else
            echoContent green " ---> 放弃设置"
            exit 0
        fi

    elif [[ "${warpStatus}" == "4" ]]; then
        if [[ "${coreInstallType}" == "1" ]]; then
            unInstallRouting "wireguard_out_${type}" outboundTag

            removeXrayOutbound "wireguard_out_${type}"
            addXrayOutbound "z_direct_outbound"
        fi

        if [[ -n "${singBoxConfigPath}" ]]; then
            removeSingBoxConfig "wireguard_endpoints_${type}_route"

            removeSingBoxConfig "wireguard_endpoints_${type}"
            addSingBoxOutbound "01_direct_outbound"
        fi

        echoContent green " ---> 卸载WARP ${type}分流完毕"
    else

        echoContent red " ---> 选择错误"
        exit 0
    fi
    reloadCore
}

# 分流工具
routingToolsMenu() {
    echoContent skyBlue "\n功能 1/${totalProgress} : 分流工具"
    echoContent red "\n=============================================================="
    echoContent yellow "# 注意事项"
    echoContent yellow "# 用于服务端的流量分流，可用于解锁ChatGPT、流媒体等相关内容\n"

    echoContent yellow "1.WARP分流【第三方 IPv4】"
    echoContent yellow "2.WARP分流【第三方 IPv6】"
    echoContent yellow "3.IPv6分流"
    echoContent yellow "4.Socks5分流【替换任意门分流】"
    echoContent yellow "5.DNS分流"
    #    echoContent yellow "6.VMess+WS+TLS分流"
    echoContent yellow "7.SNI反向代理分流"

    read -r -p "请选择:" selectType

    case ${selectType} in
    1)
        warpRoutingReg 1 IPv4
        ;;
    2)
        warpRoutingReg 1 IPv6
        ;;
    3)
        ipv6Routing 1
        ;;
    4)
        socks5Routing
        ;;
    5)
        dnsRouting 1
        ;;
        #    6)
        #        if [[ -n "${singBoxConfigPath}" ]]; then
        #            echoContent red "\n ---> 此功能不支持Hysteria2、Tuic"
        #        fi
        #        vmessWSRouting 1
        #        ;;
    7)
        if [[ -n "${singBoxConfigPath}" ]]; then
            echoContent red "\n ---> 此功能不支持Hysteria2、Tuic"
        fi
        sniRouting 1
        ;;
    esac

}

# VMess+WS+TLS 分流
vmessWSRouting() {
    echoContent skyBlue "\n功能 1/${totalProgress} : VMess+WS+TLS 分流"
    echoContent red "\n=============================================================="
    echoContent yellow "# 注意事项"
    echoContent yellow "# 使用教程：https://www.v2ray-agent.com/archives/1683226921000 \n"

    echoContent yellow "1.添加出站"
    echoContent yellow "2.卸载"
    read -r -p "请选择:" selectType

    case ${selectType} in
    1)
        setVMessWSRoutingOutbounds
        ;;
    2)
        removeVMessWSRouting
        ;;
    esac
}
# Socks5分流
socks5Routing() {
    if [[ -z "${coreInstallType}" ]]; then
        echoContent red " ---> 未安装任意协议，请使用 1.安装 或者 2.任意组合安装 进行安装后使用"
        exit 0
    fi
    echoContent skyBlue "\n功能 1/${totalProgress} : Socks5分流"
    echoContent red "\n=============================================================="
    echoContent red "# 注意事项"
    echoContent yellow "# 流量明文访问"

    echoContent yellow "# 仅限正常网络环境下设备间流量转发，禁止用于代理访问。"
    echoContent yellow "# 使用教程：https://www.v2ray-agent.com/archives/1683226921000#heading-5 \n"

    echoContent yellow "1.Socks5出站"
    echoContent yellow "2.Socks5入站"
    echoContent yellow "3.卸载"
    read -r -p "请选择:" selectType

    case ${selectType} in
    1)
        socks5OutboundRoutingMenu
        ;;

    2)
socks5InboundRoutingMenu
;;
3)
removeSocks5Routing
;;
esac
}
# Socks5 inbound menu
socks5InboundRoutingMenu() {
readInstallType
echoContent skyBlue "\nFunction 1/1: Socks5 inbound"
echoContent red "\n==============================================================="

echoContent yellow "1. Install Socks5 inbound"
echoContent yellow "2. View diversion rules"
echoContent yellow "3. Add diversion rules"
echoContent yellow "4. View inbound configuration"
read -r -p "Please select:" selectType
case ${selectType} in
1)
totalProgress=1
installSingBox 1
installSingBoxService 1
setSocks5Inbound
setSocks5InboundRouting
reloadCore
socks5InboundRoutingMenu
;;
2)
showSingBoxRoutingRules socks5_inbound_route
socks5InboundRoutingMenu
;;
3)
setSocks5InboundRouting addRules
reloadCore
socks5InboundRoutingMenu
;;
4)
if [[ -f "${singBoxConfigPath}20_socks5_inbounds.json" ]]; then
echoContent yellow "\n ---> The following content needs to be configured to the outbound of other machines, please do not perform proxy behavior\n"
echoContent green " Port: $(jq .inbounds[0].listen_port ${singBoxConfigPath}20_socks5_inbounds.json)"
echoContent green "User name: $(jq -r .inbounds[0].users[0].username ${singBoxConfigPath}20_socks5_inbounds.json)"
echoContent green "User password: $(jq -r .inbounds[0].users[0].password ${singBoxConfigPath}20_socks5_inbounds.json)"
else
echoContent red "---> The corresponding function is not installed"
socks5InboundRoutingMenu
fi
;;
esac

}

# Socks5 outbound menu
socks5OutboundRoutingMenu() {
echoContent skyBlue "\nFunction 1/1: Socks5 outbound"
echoContent red "\n==============================================================="

echoContent yellow "1. Install Socks5 outbound"
echoContent yellow "2. Set up Socks5 global forwarding"
echoContent yellow "3. View diversion rules"
echoContent yellow "4. Add diversion rules"
read -r -p "Please select:" selectType
case ${selectType} in
1)
setSocks5Outbound
setSocks5OutboundRouting
reloadCore
socks5OutboundRoutingMenu
;;
2)
setSocks5Outbound
setSocks5OutboundRoutingAll
reloadCore
socks5OutboundRoutingMenu
;;
3)
showSingBoxRoutingRules socks5_outbound_route
showXrayRoutingRules socks5_outbound
socks5OutboundRoutingMenu
;;
4)
setSocks5OutboundRouting addRules
reloadCore
socks5OutboundRoutingMenu
;;
esac

}

# socks5 global
setSocks5OutboundRoutingAll() {

echoContent red "================================================================="
echoContent yellow "# Notes\n"
echoContent yellow "1. All set diversion rules will be deleted, including other diversions (warp, IPv6, etc.)"
echoContent yellow "2. All outbound rules except Socks5 will be deleted\n"
read -r -p "Are you sure to set it? [y/n]:" socksOutStatus

if [[ "${socksOutStatus}" == "y" ]]; then
if [[ "${coreInstallType}" == "1" ]]; then
removeXrayOutbound IPv4_out
removeXrayOutbound IPv6_out
removeXrayOutbound z_direct_outbound
removeXrayOutbound blackhole_out
removeXrayOutbound wireguard_out_IPv4
removeXrayOutbound wireguard_out_IPv6

rm ${configPath}09_routing.json >/dev/null 2>&1
fi
if [[ -n "${singBoxConfigPath}" ]]; then

removeSingBoxConfig IPv4_out
removeSingBoxConfig IPv6_out

removeSingBoxConfig wireguard_endpoints_IPv4_route
            removeSingBoxConfig wireguard_endpoints_IPv6_route
            removeSingBoxConfig wireguard_endpoints_IPv4
            removeSingBoxConfig wireguard_endpoints_IPv6

            removeSingBoxConfig socks5_outbound_route
            removeSingBoxConfig 01_direct_outbound
        fi

        echoContent green " ---> Socks5 global outbound settings completed"
    fi
}
# socks5 diversion rules
showSingBoxRoutingRules() {
    if [[ -n "${singBoxConfigPath}" ]]; then
        if [[ -f "${singBoxConfigPath}$1.json" ]]; then
            jq .route.rules "${singBoxConfigPath}$1.json"

elif [[ "$1" == "socks5_outbound_route" && -f "${singBoxConfigPath}socks5_outbound.json" ]]; then
echoContent yellow "Sing-box socks5 global outbound diversion has been installed"
echoContent yellow "\nOutbound diversion configuration:"
echoContent skyBlue "$(jq .outbounds[0] ${singBoxConfigPath}socks5_outbound.json)"
elif [[ "$1" == "socks5_inbound_route" && -f "${singBoxConfigPath}20_socks5_inbounds.json" ]]; then
echoContent yellow "Sing-box socks5 global inbound diversion has been installed"
echoContent yellow "\nOutbound diversion configuration:"
echoContent skyBlue "$(jq .outbounds[0] ${singBoxConfigPath}socks5_outbound.json)"
fi
fi
}

# xray core diversion rules
showXrayRoutingRules() {
if [[ "${coreInstallType}" == "1" ]]; then
if [[ -f "${configPath}09_routing.json" ]]; then
jq ".routing.rules[]|select(.outboundTag==\"$1\")" "${configPath}09_routing.json"

echoContent yellow "\n xray-core socks5 global outbound diversion installed"
echoContent yellow "\n Outbound diversion configuration:"
echoContent skyBlue "$(jq .outbounds[0].settings.servers[0] ${configPath}socks5_outbound.json)"

elif [[ "$1" == "socks5_outbound" && -f "${configPath}socks5_outbound.json" ]]; then
echoContent yellow "\nxray-core socks5 global outbound diversion has been installed"
echoContent yellow "\nOutbound diversion configuration:"
echoContent skyBlue "$(jq .outbounds[0].settings.servers[0] ${configPath}socks5_outbound.json)"
fi
fi
}

# Uninstall Socks5 diversion
removeSocks5Routing() {
echoContent skyBlue "\nFunction 1/1: Uninstall Socks5 diversion"
echoContent red "\n=============================================================="

echoContent yellow "1. Uninstall Socks5 outbound"
echoContent yellow "2. Uninstall Socks5 inbound"
echoContent yellow "3. Uninstall all"
read -r -p "Please select:" unInstallSocks5RoutingStatus
if [[ "${unInstallSocks5RoutingStatus}" == "1" ]]; then
if [[ "${coreInstallType}" == "1" ]]; then
removeXrayOutbound socks5_outbound
unInstallRouting socks5_outbound outboundTag
addXrayOutbound z_direct_outbound
fi

if [[ -n "${singBoxConfigPath}" ]]; then
removeSingBoxConfig socks5_outbound
removeSingBoxConfig socks5_outbound_route
addSingBoxOutbound 01_direct_outbound
fi

elif [[ "${unInstallSocks5RoutingStatus}" == "2" ]]; then

        removeSingBoxConfig 20_socks5_inbounds
        removeSingBoxConfig socks5_inbound_route

        handleSingBox stop
    elif [[ "${unInstallSocks5RoutingStatus}" == "3" ]]; then
        if [[ "${coreInstallType}" == "1" ]]; then
            removeXrayOutbound socks5_outbound
            unInstallRouting socks5_outbound outboundTag
            addXrayOutbound z_direct_outbound
        fi

        if [[ -n "${singBoxConfigPath}" ]]; then
            removeSingBoxConfig socks5_outbound
            removeSingBoxConfig socks5_outbound_route
            removeSingBoxConfig 20_socks5_inbounds
            removeSingBoxConfig socks5_inbound_route
addSingBoxOutbound 01_direct_outbound
fi
handleSingBox stop
else
echoContent red " ---> Selection error"
exit 0
fi
echoContent green " ---> Uninstallation completed"
reloadCore
}
# Socks5 inbound
setSocks5Inbound() {

echoContent yellow "\n==================== Configure Socks5 inbound (unlocked machine, grounded machine) ======================\n"
echoContent skyBlue "\nStart configuring Socks5 protocol inbound port"
echo
mapfile -t result < <(initSingBoxPort "${singBoxSocks5Port}")
echoContent green "\n ---> Inbound Socks5 port: ${result[-1]}"
echoContent green "\n ---> This port needs to be configured to other machines for outbound, please do not perform proxy behavior"

echoContent yellow "\nPlease enter a custom UUID [must be legal], [Enter] Random UUID"
read -r -p 'UUID:' socks5RoutingUUID
if [[ -z "${socks5RoutingUUID}" ]]; then
if [[ "${coreInstallType}" == "1" ]]; then
socks5RoutingUUID=$(/etc/v2ray-agent/xray/xray uuid)
elif [[ -n "${singBoxConfigPath}" ]]; then
socks5RoutingUUID=$(/etc/v2ray-agent/sing-box/sing-box generate uuid)
fi
fi
echo
echoContent green "User name: ${socks5RoutingUUID}"

    echoContent green "User password: ${socks5RoutingUUID}"

echoContent yellow "\nPlease select the DNS resolution type for the diversion domain name"
echoContent yellow "# Note: It is necessary to ensure that the vps supports the corresponding DNS resolution"
echoContent yellow "1.IPv4[Enter default]"
echoContent yellow "2.IPv6"

read -r -p 'IP type:' socks5InboundDomainStrategyStatus
local domainStrategy=
if [[ -z "${socks5InboundDomainStrategyStatus}" || "${socks5InboundDomainStrategyStatus}" == "1" ]]; then
domainStrategy="ipv4_only"
elif [[ "${socks5InboundDomainStrategyStatus}" == "2" ]]; then
domainStrategy="ipv6_only"
else
echoContent red " ---> "Select type error"
exit 0
fi
cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/20_socks5_inbounds.json
{
"inbounds":[
{
"type": "socks",
"listen":"::",
"listen_port":${result[-1]},
"tag":"socks5_inbound",
"users":[
{
"username": "${socks5RoutingUUID}",
"password": "${socks5RoutingUUID}"
}
],
"domain_strategy":"${domainStrategy}"
}
]
}
EOF

}

# Initialize sing-box rule configuration
initSingBoxRules() {
local domainRules=[]
local ruleSet=[]
while read -r line; do
local geositeStatus
        geositeStatus=$(curl -s "https://api.github.com/repos/SagerNet/sing-geosite/contents/geosite-${line}.srs?ref=rule-set" | jq .message)

        if [[ "${geositeStatus}" == "null" ]]; then
            ruleSet=$(echo "${ruleSet}" | jq -r ". += [{\"tag\":\"${line}_$2\",\"type\":\"remote\",\"format\":\"binary\",\"url\":\"https://raw.githubuserconten t.com/SagerNet/sing-geosite/rule-set/geosite-${line}.srs\",\"download_detour\":\"01_direct_outbound\"}]")
        else
            domainRules=$(echo "${domainRules}" | jq -r ". += [\"^([a-zA-Z0-9_-]+\\\.)*${line//./\\\\.}\"]")
        fi
    done < <(echo "$1" | tr ',' '\n' | grep -v '^$' | sort -n | uniq | paste -sd ',' | tr ',' '\n')
    echo "{ \"domainRules\":${domainRules},\"ruleSet\":${ruleSet}}"
}

# socks5 inbound routing rules
setSocks5InboundRouting() {

    singBoxConfigPath=/etc/v2ray-agent/sing-box/conf/config/

    if [[ "$1" == "addRules" && ! -f "${singBoxConfigPath}socks5_inbound_route.json" && ! -f "${configPath}09_routing.json" ]]; then
echoContent red " ---> Please install inbound diversion before adding diversion rules"
echoContent red " ---> If you have chosen to allow all websites, please reinstall diversion and set rules"
exit 0
fi
local socks5InboundRoutingIPs=
if [[ "$1" == "addRules" ]]; then
socks5InboundRoutingIPs=$(jq .route.rules[0].source_ip_cidr "${singBoxConfigPath}socks5_inbound_route.json")
else
echoContent red "================================================================"
echoContent skyBlue "Please enter the IP addresses allowed to be accessed. Multiple IPs are separated by commas. For example: 1.1.1.1, 2.2.2.2\n"
read -r -p "IP:" socks5InboundRoutingIPs

if [[ -z "${socks5InboundRoutingIPs}" ]]; then
echoContent red " ---> IP cannot be empty"
exit 0
fi
socks5InboundRoutingIPs=$(echo "\"${socks5InboundRoutingIPs}"\" | jq -c '.|split(",")')
fi

echoContent red "==============================================================="
echoContent skyBlue "Please enter the domain name to be diverted\n"
echoContent yellow "Supports Xray-core geosite matching, supports sing-box1.8+ rule_set matching\n"
echoContent yellow "Non-incremental addition, will replace the original rules\n"
echoContent yellow "When the input rule matches geosite or rule_set, the corresponding rule will be used\n"
echoContent yellow "If it cannot be matched, use domain exact matching\n"

read -r -p "Do you allow all websites? Please select [y/n]:" socks5InboundRoutingDomainStatus
if [[ "${socks5InboundRoutingDomainStatus}" == "y" ]]; then
addSingBoxRouteRule "01_direct_outbound" "" "socks5_inbound_route"
local route=
route=$(jq ".route.rules[0].inbound = [\"socks5_inbound\"]" "${singBoxConfigPath}socks5_inbound_route.json")
        route=$(echo "${route}" | jq ".route.rules[0].source_ip_cidr=${socks5InboundRoutingIPs}")
        echo "${route}" | jq . >"${singBoxConfigPath}socks5_inbound_route.json"

        addSingBoxOutbound block
        addSingBoxOutbound "01_direct_outbound"
    else

echoContent yellow "Entry example: netflix, openai, v2ray-agent.com\n"
read -r -p "Domain name:" socks5InboundRoutingDomain
if [[ -z "${socks5InboundRoutingDomain}" ]]; then
echoContent red "---> Domain name cannot be empty"
exit 0
fi
addSingBoxRouteRule "01_direct_outbound" "${socks5InboundRoutingDomain}" "socks5_inbound_route"
local route=
route=$(jq ".route.rules[0].inbound = [\"socks5_inbound\"]" "${singBoxConfigPath}socks5_inbound_route.json")
route=$(echo "${route}" | jq ".route.rules[0].source_ip_cidr=${socks5InboundRoutingIPs}")
echo "${route}" | jq . >"${singBoxConfigPath}socks5_inbound_route.json"

addSingBoxOutbound block
addSingBoxOutbound "01_direct_outbound"
fi

}

# socks5 outbound
setSocks5Outbound() {

echoContent yellow "\n===================== Configure Socks5 outbound (forwarder, proxy) =====================\n"
echo
read -r -p "Please enter the IP address of the landing machine:" socks5RoutingOutboundIP
if [[ -z "${socks5RoutingOutboundIP}" ]]; then
echoContent red "---> IP cannot be empty"
exit 0
fi
echo
read -r -p "Please enter the landing port:" socks5RoutingOutboundPort
if [[ -z "${socks5RoutingOutboundPort}" ]]; then
echoContent red "---> Port cannot be empty"
exit 0
fi
echo
read -r -p "Please enter the username:" socks5RoutingOutboundUserName
if [[ -z "${socks5RoutingOutboundUserName}" ]]; then
echoContent red "---> Username cannot be empty"
exit 0
fi
echo
read -r -p "Please enter the user password:" socks5RoutingOutboundPassword
if [[ -z "${socks5RoutingOutboundPassword}" ]]; then
echoContent red "---> User password cannot be empty"
exit 0
fi
echo
if [[ -n "${singBoxConfigPath}" ]]; then
        cat <<EOF >"${singBoxConfigPath}socks5_outbound.json"
{
    "outbounds":[
        {
          "type": "socks",
          "tag":"socks5_outbound",
          "server": "${socks5RoutingOutboundIP}",
          "server_port": ${socks5RoutingOutboundPort},
          "version": "5",
          "username":"${socks5RoutingOutboundUserName}",
          "password":"${socks5RoutingOutboundPassword}"
        }
    ]
}
EOF
    fi
    if [[ "${coreInstallType}" == "1" ]]; then
        addXrayOutbound socks5_outbound
    fi
}

# socks5 outbound routing rules
setSocks5OutboundRouting() {

    if [[ "$1" == "addRules" && ! -f "${singBoxConfigPath}socks5_outbound_route.json" && ! -f "${configPath}09_routing.json" ]]; then
echoContent red " ---> Please install outbound diversion before adding diversion rules"
exit 0
fi

echoContent red "================================================================="
echoContent skyBlue "Please enter the domain name to be diverted\n"
echoContent yellow "Supports Xray-core geosite matching, supports sing-box1.8+ rule_set matching\n"
echoContent yellow "Non-incremental addition, will replace the original rules\n"
echoContent yellow "When the input rule matches geosite or rule_set, the corresponding rule will be used\n"
echoContent yellow "If no match is found, domain is used for exact match\n"
echoContent yellow "Entry example: netflix, openai, v2ray-agent.com\n"
read -r -p "Domain name:" socks5RoutingOutboundDomain
if [[ -z "${socks5RoutingOutboundDomain}" ]]; then
echoContent red "---> IP cannot be empty"
exit 0
fi
addSingBoxRouteRule "socks5_outbound" "${socks5RoutingOutboundDomain}" "socks5_outbound_route"
addSingBoxOutbound "01_direct_outbound"
if [[ "${coreInstallType}" == "1" ]]; then

unInstallRouting "socks5_outbound" "outboundTag"
        local domainRules=[]
        while read -r line; do
            if echo "${routingRule}" | grep -q "${line}"; then
                echoContent yellow " ---> ${line} already exists, skip"
            else
                local geositeStatus
                geositeStatus=$(curl -s "https://api.github.com/repos/v2fly/domain-list-community/contents/data/${line}" | jq .message)

                if [[ "${geositeStatus}" == "null" ]]; then
                    domainRules=$(echo "${domainRules}" | jq -r ". += [\"geosite:${line}\"]")
                else
                    domainRules=$(echo "${domainRules}" | jq -r ". += [\"domain:${line}\"]")
                fi
            fi

        done < <(echo "${socks5RoutingOutboundDomain}" | tr ',' '\n')
        if [[ ! -f "${configPath}09_routing.json" ]]; then
            cat <<EOF >${configPath}09_routing.json
{
    "routing":{
        "rules": []
  }
}
EOF
        fi
        routing=$(jq -r ".routing.rules += [{\"type\": \"field\",\"domain\": ${domainRules},\"outboundTag\": \"socks5_outbound\"}]" ${configPath}09_routing.json)
        echo "${routing}" | jq . >${configPath}09_routing.json
    fi
}

# Set VMess+WS+TLS [outbound only]
setVMessWSRoutingOutbounds() {
    read -r -p "Please enter the address of VMess+WS+TLS:" setVMessWSTLSAddress
echoContent red "=============================================================="
echoContent yellow "Entry example: netflix,openai\n"
read -r -p "Please enter the domain name according to the above example:" domainList

if [[ -z ${domainList} ]]; then
echoContent red "---> The domain name cannot be empty"
setVMessWSRoutingOutbounds
fi

if [[ -n "${setVMessWSTLSAddress}" ]]; then
removeXrayOutbound VMess-out

echo
read -r -p "Please enter the port of VMess+WS+TLS:" setVMessWSTLSPort
echo
if [[ -z "${setVMessWSTLSPort}" ]]; then
echoContent red " ---> Port cannot be empty"
fi

read -r -p "Please enter the UUID of VMess+WS+TLS:" setVMessWSTLSUUID
echo
if [[ -z "${setVMessWSTLSUUID}" ]]; then
echoContent red " ---> UUID cannot be empty"
fi

read -r -p "Please enter the Path of VMess+WS+TLS:" setVMessWSTLSPath
echo
if [[ -z "${setVMessWSTLSPath}" ]]; then
echoContent red " ---> Path cannot be empty"
elif ! echo "${setVMessWSTLSPath}" | grep -q "/"; then
setVMessWSTLSPath="/${setVMessWSTLSPath}"
fi
addXrayOutbound "VMess-out"
addInstallRouting VMess-out outboundTag "${domainList}"
reloadCore
echoContent green "---> Added the diversion successfully"
exit 0
fi
echoContent red "---> The address cannot be empty"
setVMessWSRoutingOutbounds
}

# Remove VMess+WS+TLS diversion
removeVMessWSRouting() {

removeXrayOutbound VMess-out
unInstallRouting VMess-out outboundTag

reloadCore
echoContent green "---> Uninstalled successfully"
}

# Restart the core
reloadCore() {
readInstallType

if [[ "${coreInstallType}" == "1" ]]; then
handleXray stop
handleXray start
fi
if echo "${currentInstallProtocolType}" | grep -q ",20," || [[ "${coreInstallType}" == "2" || -n "${singBoxConfigPath}" ]]; then
handleSingBox stop
handleSingBox start
fi
}

# dns diversion
dnsRouting() {

if [[ -z "${configPath}" ]]; then
echoContent red " ---> Not installed, please use script to install"
menu
exit 0
fi
echoContent skyBlue "\nFunction 1/${totalProgress} : DNS diversion"
echoContent red "\n================================================================="
echoContent yellow "# Notes"
echoContent yellow "# Usage tutorial: https://www.v2ray-agent.com/archives/1683226921000 \n"

echoContent yellow "1. Add"
echoContent yellow "2. Uninstall"
read -r -p "Please select:" selectType

case ${selectType} in
1)
setUnlockDNS
;;
2)
removeUnlockDNS
;;
esac
}

# SNI reverse proxy diversion
sniRouting() {

if [[ -z "${configPath}" ]]; then
echoContent red "---> Not installed, please use script installation"
menu
exit 0
fi
echoContent skyBlue "\nFunction 1/${totalProgress} : SNI reverse proxy diversion"
echoContent red "\n================================================================"
echoContent yellow "# Notes"
echoContent yellow "# Usage tutorial: https://www.v2ray-agent.com/archives/1683226921000 \n"

echoContent yellow "1. Add"
echoContent yellow "2. Uninstall"
read -r -p "Please select:" selectType

case ${selectType} in
1)
setUnlockSNI
;;
2)
removeUnlockSNI
;;
esac
}
# Set SNI diversion
setUnlockSNI() {
read -r -p "Please enter the diversion SNI IP:" setSNIP
if [[ -n ${setSNIP} ]]; then
echoContent red "=============================================================="
echoContent yellow "Entry example: netflix, disney, hulu"
read -r -p "Please enter the domain name according to the above example:" domainList

if [[ -n "${domainList}" ]]; then
local hosts={}

while read -r domain; do
hosts=$(echo "${hosts}" | jq -r ".\"geosite:${domain}\"=\"${setSNIP}\"")
done < <(echo "${domainList}" | tr ',' '\n')
cat <<EOF >${configPath}11_dns.json
{
"dns": {
"hosts":${hosts},
"servers": [
"8.8.8.8",
"1.1.1.1"
]
}
}
EOF
echoContent red " ---> SNI reverse proxy diversion is successful"
reloadCore
else
echoContent red " ---> Domain name cannot be empty"
fi
else
echoContent red " ---> SNI IP cannot be empty"
fi
exit 0
}

# Add xray dns configuration
addXrayDNSConfig() {
local ip=$1
    local domainList=$2
    local domains=[]
    while read -r line; do
        local geositeStatus
        geositeStatus=$(curl -s "https://api.github.com/repos/v2fly/domain-list-community/contents/data/${line}" | jq .message)

        if [[ "${geositeStatus}" == "null" ]]; then
            domains=$(echo "${domains}" | jq -r '. += ["geosite:'"${line}"'"]')
        else
            domains=$(echo "${domains}" | jq -r '. += ["domain:'"${line}"'"]')
        fi
    done < <(echo "${domainList}" | tr ',' '\n')

    if [[ "${coreInstallType}" == "1" ]]; then

cat <<EOF >${configPath}11_dns.json
{
"dns": {
"servers": [
{
"address": "${ip}",
"port": 53,
"domains": ${domains}
},
"localhost"
]
}
}
EOF
fi
}

# Add sing-box dns configuration
addSingBoxDNSConfig() {
local ip=$1
local domainList=$2

local rules=
rules=$(initSingBoxRules "${domainList}" "dns")
# domain exact match rules
local domainRules=
domainRules=$(echo "${rules}" | jq .domainRules)

# ruleSet rule set
local ruleSet=
ruleSet=$(echo "${rules}" | jq .ruleSet)

# ruleSet rule tag
local ruleSetTag=[]
    if [[ "$(echo "${ruleSet}" | jq '.|length')" != "0" ]]; then
        ruleSetTag=$(echo "${ruleSet}" | jq '.|map(.tag)')
    fi
    if [[ -n "${singBoxConfigPath}" ]]; then
        cat <<EOF >"${singBoxConfigPath}dns.json"
{
  "dns": {
    "servers": [
      {
        "tag": "local",
        "address": "local"
      },
      {
        "tag": "dnsRouting",
        "address": "${ip}"
      }
    ],
    "rules": [
      {
        "rule_set": ${ruleSetTag},
        "domain_regex": ${domainRules},
        "server":"dnsRouting"
      }
    ] },
"route":{
"rule_set":${ruleSet}
}
}
EOF
fi
}
# Set dns
setUnlockDNS() {
read -r -p "Please enter the DNS for diversion:" setDNS
if [[ -n ${setDNS} ]]; then
echoContent red "================================================================"
echoContent yellow "Entry example: netflix, disney, hulu"
read -r -p "Please enter the domain name according to the above example:" domainList

if [[ "${coreInstallType}" == "1" ]]; then
addXrayDNSConfig "${setDNS}" "${domainList}"
fi

if [[ -n "${singBoxConfigPath}" ]]; then
addSingBoxOutbound 01_direct_outbound
addSingBoxDNSConfig "${setDNS}" "${domainList}"
fi
reloadCore

echoContent yellow "\n ---> If you still can't watch, you can try the following two solutions"
echoContent yellow " 1. Restart vps"
echoContent yellow " 2. After uninstalling dns unlock, modify the local [/etc/resolv.conf] DNS settings and restart vps\n"
else
echoContent red " ---> dns cannot be empty"
fi
exit 0
}

# Remove DNS diversion
removeUnlockDNS() {
if [[ "${coreInstallType}" == "1" && -f "${configPath}11_dns.json" ]]; then
cat <<EOF >${configPath}11_dns.json
{
"dns": {
"servers": [
"localhost"
]
}
}
EOF
fi

if [[ "${coreInstallType}" == "2" && -f "${singBoxConfigPath}dns.json" ]]; then
cat <<EOF >${singBoxConfigPath}dns.json
{
"dns": {
"servers":[
{
"address":"local"
}
]
}
}
EOF
fi

reloadCore

echoContent green " ---> Uninstallation successful"

exit 0
}

# Remove SNI diversion
removeUnlockSNI() {
cat <<EOF >${configPath}11_dns.json
{
"dns": {
"servers": [
"localhost"
]
}
}
EOF
reloadCore

echoContent green " ---> Uninstallation successful"

exit 0
}


# sing-box personalized installation
customSingBoxInstall() {
echoContent skyBlue "\n========================Personalized installation=============================="
echoContent yellow "0.VLESS+Vision+TCP"
echoContent yellow "1.VLESS+TLS+WS[CDN recommended only]"
echoContent yellow "3.VMess+TLS+WS[CDN recommended only]"
echoContent yellow "4.Trojan+TLS[not recommended]"
echoContent yellow "6.Hysteria2"
echoContent yellow "7.VLESS+Reality+Vision"
echoContent yellow "8.VLESS+Reality+gRPC"
echoContent yellow "9.Tuic"
echoContent yellow "10.Naive"
echoContent yellow "11.VMess+TLS+HTTPUpgrade"

read -r -p "Please select [multiple choices], [e.g.: 1,2,3]:" selectCustomInstallType
echoContent skyBlue "--------------------------------------------------------------"
if echo "${selectCustomInstallType}" | grep -q "，"; then
echoContent red " ---> Please use English commas to separate"
exit 0
fi
if [[ "${selectCustomInstallType}" != "10" ]] && [[ "${selectCustomInstallType}" != "11" ]] && ((${#selectCustomInstallType} >= 2)) && ! echo "${selectCustomInstallType}" | grep -q ","; then
echoContent red " ---> Please use English commas to separate"
exit 0
fi
if [[ "${selectCustomInstallType: -1}" != "," ]]; then
        selectCustomInstallType="${selectCustomInstallType},"
    fi
    if [[ "${selectCustomInstallType:0:1}" != "," ]]; then
        selectCustomInstallType=",${selectCustomInstallType},"
    fi

    if [[ "${selectCustomInstallType//,/}" =~ ^[0-9]+$ ]]; then
        readLastInstallationConfig
        unInstallSubscribe
        totalProgress=9
        installTools 1
        # Apply for tls
        if echo "${selectCustomInstallType}" | grep -q -E ",0,|,1,|,3,|,4,|,6,|,9,|,10,|,11,"; then
            initTLSNginxConfig 2
            installTLS 3
            handleNginx stop fi

installSingBox 4
installSingBoxService 5
initSingBoxConfig custom 6
cleanUp xrayDel
installCronTLS 7
handleSingBox stop
handleSingBox start
handleNginx stop
handleNginx start
# Generate an account
checkGFWStatue 8
showAccounts 9
else
echoContent red " ---> Invalid input"
customSingBoxInstall
fi
}

# Xray-core personalized installation
customXrayInstall() {
echoContent skyBlue "\n========================Personalized installation============================="
echoContent yellow "VLESS pre-installed, default installation 0, no domain name installation Reality only needs to select 7"
echoContent yellow "0.VLESS+TLS_Vision+TCP[recommended]"
echoContent yellow "1.VLESS+TLS+WS[CDN recommended only]"
# echoContent yellow "2.Trojan+TLS+gRPC[CDN recommended only]"
echoContent yellow "3.VMess+TLS+WS[CDN recommended only]"
echoContent yellow "4.Trojan+TLS[Not recommended]"
echoContent yellow "5.VLESS+TLS+gRPC[CDN recommended only]"
echoContent yellow "7.VLESS+Reality+uTLS+Vision[Recommended]"
# echoContent yellow "8.VLESS+Reality+gRPC"
echoContent yellow "12.VLESS+XHTTP+TLS"
read -r -p "Please select [multiple choices], [for example: 1,2,3]:" selectCustomInstallType
echoContent skyBlue "--------------------------------------------------------------"
if echo "${selectCustomInstallType}" | grep -q ","; then
        echoContent red " ---> Please use English commas to separate"
        exit 0
    fi
    if [[ "${selectCustomInstallType}" != "12" ]] && ((${#selectCustomInstallType} >= 2)) && ! echo "${selectCustomInstallType}" | grep -q ","; then
        echoContent red " ---> Please use commas to separate multiple selections"
        exit 0
    fi

    if [[ "${selectCustomInstallType}" == "7" ]]; then
        selectCustomInstallType=",${selectCustomInstallType},"
    else
        if ! echo "${selectCustomInstallType}" | grep -q "0,"; then
            selectCustomInstallType=",0,${selectCustomInstallType},"
        else
            selectCustomInstallType=",${selectCustomInstallType},"
        fi
    fi

    if [[ "${selectCustomInstallType:0:1}" != "," ]]; then
        selectCustomInstallType=",${selectCustomInstallType},"
    fi
    if [[ "${selectCustomInstallType//,/}" =~ ^[0-7]+$ ]]; then
        readLastInstallationConfig
        unInstallSubscribe
        checkBTPanel
        check1Panel
        totalProgress=12
        installTools 1

if [[ -n "${btDomain}" ]]; then
echoContent skyBlue "\nProgress 3/${totalProgress}: Detected Baota Panel/1Panel, skipped the TLS application step"
handleXray stop
if [[ "${selectCustomInstallType}" != ",7," ]]; then
customPortFunction
fi
else
# Apply for tls
if [[ "${selectCustomInstallType}" != ",7," ]]; then
initTLSNginxConfig 2
handleXray stop
installTLS 3
else
echoContent skyBlue "\nProgress 2/${totalProgress}: Detected that only Reality is installed, skipped the TLS certificate step"
fi
fi
handleNginx stop
# Random path
if echo "${selectCustomInstallType}" | grep -qE ",1,|,2,|,3,|,5,|,12,"; then
randomPathFunction 4
fi
if [[ -n "${btDomain}" ]]; then
echoContent skyBlue "\nProgress 6/${totalProgress}: Detected Pagoda Panel/1Panel, skipped disguised website"
else
nginxBlog 6
fi
if [[ "${selectCustomInstallType}" != ",7," ]]; then
updateRedirectNginxConf
handleNginx start
fi

# Install Xray
installXray 7 false
installXrayService 8
initXrayConfig custom 9
cleanUp singBoxDel
if [[ "${selectCustomInstallType}" != ",7," ]]; then
installCronTLS 10
fi

handleXray stop
handleXray start
# Generate account
checkGFWStatue 11
showAccounts 12
else
echoContent red " ---> Illegal input"
customXrayInstall
fi
}

# Select core installation sing-box, xray-core
selectCoreInstall() {
echoContent skyBlue "\nFunction 1/${totalProgress}: Select core installation"
echoContent red "\n==============================================================="
echoContent yellow "1.Xray-core"
echoContent yellow "2.sing-box"
echoContent red "==============================================================="
read -r -p "Please select:" selectCoreType
case ${selectCoreType} in
1)
if [[ "${selectInstallType}" == "2" ]]; then
customXrayInstall
else
xrayCoreInstall
fi
;;
2)
if [[ "${selectInstallType}" == "2" ]]; then
customSingBoxInstall
else
singBoxInstall
fi
;;
*)
echoContent red ' ---> Wrong selection, reselect'
selectCoreInstall
;;
esac
}

# xray-core installation
xrayCoreInstall() {
readLastInstallationConfig
unInstallSubscribe
checkBTPanel
check1Panel
selectCustomInstallType=
totalProgress=12
installTools 2
if [[ -n "${btDomain}" ]]; then
echoContent skyBlue "\nProgress 3/${totalProgress} : Detected Baota Panel/1Panel, skipped the TLS application step"
handleXray stop
customPortFunction
else
# Apply for tls
initTLSNginxConfig 3
handleXray stop
installTLS 4
fi

handleNginx stop
randomPathFunction 5

# Install Xray
installXray 6 false
installXrayService 7
initXrayConfig all 8
cleanUp singBoxDel
installCronTLS 9
if [[ -n "${btDomain}" ]]; then
echoContent skyBlue "\nProgress 11/${totalProgress} : Detected Baota Panel/1Panel, skipped the disguised website"
else
nginxBlog 10
fi
updateRedirectNginxConf
handleXray stop
sleep 2
handleXray start

handleNginx start
# Generate an account
checkGFWStatue 11
showAccounts 12
}

# sing-box All installations
singBoxInstall() {
readLastInstallationConfig
unInstallSubscribe
checkBTPanel
check1Panel
selectCustomInstallType=
totalProgress=8
installTools 2

if [[ -n "${btDomain}" ]]; then
echoContent skyBlue "\nProgress 3/${totalProgress} : Detected Baota Panel/1Panel, skipped the TLS application step"
handleXray stop
customPortFunction
else
# Apply for tls
initTLSNginxConfig 3
handleXray stop
installTLS 4
    fi

    handleNginx stop

    installSingBox 5
    installSingBoxService 6
    initSingBoxConfig all 7

    cleanUp xrayDel
    installCronTLS 8

    handleSingBox stop
    handleSingBox start
    handleNginx stop
    handleNginx start

# Generate an account
showAccounts 9
}

# Hysteria installation
hysteriaCoreInstall() {
if ! echo "${currentInstallProtocolType}" | grep -q ",0," || [[ -z "${coreInstallType}" ]]; then
echoContent red "\n ---> Due to environmental dependency, if you install hysteria, please install Xray-core's VLESS_TCP_TLS_Vision first"
exit 0
fi
totalProgress=5
installHysteria 1
initHysteriaConfig 2
installHysteriaService 3
reloadCore
showAccounts 4
}
# Uninstall hysteria
unInstallHysteriaCore() {
if [[ -n "${hysteriaConfigPath}" ]]; then
echoContent yellow " ---> The new version depends on sing-box, and the old version of hysteria is detected, so uninstallation is performed"

deleteHysteriaPortHoppingRules
handleHysteria stop
rm -rf /etc/v2ray-agent/hysteria/*
rm ${configPath}02_socks_inbounds_hysteria.json
rm -rf /etc/systemd/system/hysteria.service
echoContent green " ---> Uninstallation completed"
fi
}

# Uninstall Tuic
unInstallTuicCore() {

if [[ -n "${tuicConfigPath}" ]]; then
echoContent yellow " ---> The new version depends on sing-box, and the old version of Tuic is detected, and the uninstallation operation is performed"

handleTuic stop
rm -rf /etc/v2ray-agent/tuic/*
rm -rf /etc/systemd/system/tuic.service
echoContent green " ---> Uninstallation completed"
fi

}
unInstallXrayCoreReality() {

if [[ -z "${realityStatus}" ]]; then
echoContent red "\n ---> Not installed"
exit 0
fi
echoContent skyBlue "\nFunction 1/1: reality uninstall"
echoContent red "\n================================================================"
echoContent yellow "# Only delete VLESS Reality related configurations, no other content will be deleted."
echoContent yellow "# If you need to uninstall other content, please uninstall the script function"
handleXray stop
rm /etc/v2ray-agent/xray/conf/07_VLESS_vision_reality_inbounds.json
rm /etc/v2ray-agent/xray/conf/08_VLESS_vision_gRPC_inbounds.json
echoContent green " ---> Uninstallation completed"
}

# Core management
coreVersionManageMenu() {

if [[ -z "${coreInstallType}" ]]; then
echoContent red "\n ---> No installation directory detected, please execute the script to install the content"
menu
exit 0
fi
echoContent skyBlue "\nFunction 1/1: Please select the core"
echoContent red "\n=============================================================="
echoContent yellow "1.Xray-core"
echoContent yellow "2.sing-box"
echoContent red "==============================================================="
read -r -p "Please enter:" selectCore

if [[ "${selectCore}" == "1" ]]; then
xrayVersionManageMenu 1
elif [[ "${selectCore}" == "2" ]]; then
singBoxVersionManageMenu 1
fi
}
# Scheduled task check
cronFunction() {
if [[ "${cronName}" == "RenewTLS" ]]; then
renewalTLS
exit 0
elif [[ "${cronName}" == "UpdateGeo" ]]; then
updateGeoSite >>/etc/v2ray-agent/crontab_updateGeoSite.log
echoContent green " ---> geo update date: $(date "+%F %H:%M:%S")" >>/etc/v2ray-agent/crontab_updateGeoSite.log
exit 0
fi
}
# Account management
manageAccount() {
echoContent skyBlue "\nFunction 1/${totalProgress} : Account management"
if [[ -z "${configPath}" ]]; then
echoContent red " ---> Not installed"
exit 0
fi

echoContent red "\n==============================================================="
echoContent yellow "# You can customize email and uuid when adding a single user"
echoContent yellow "# If Hysteria or Tuic is installed, the account will be added to the corresponding type at the same time\n"
echoContent yellow "1. View account"
echoContent yellow "2. View subscription"
echoContent yellow "3. Manage other subscriptions"
echoContent yellow "4. Add user"
echoContent yellow "5. Delete user"
echoContent red "===================================================================="
read -r -p "Please enter:" manageAccountStatus
if [[ "${manageAccountStatus}" == "1" ]]; then
showAccounts 1
elif [[ "${manageAccountStatus}" == "2" ]]; then
subscribe
elif [[ "${manageAccountStatus}" == "3" ]]; then
        addSubscribeMenu 1
    elif [[ "${manageAccountStatus}" == "4" ]]; then
        addUser
    elif [[ "${manageAccountStatus}" == "5" ]]; then
        removeUser
    else
        echoContent red " ---> Wrong selection"
    fi
}

# Install subscription
installSubscribe() {
    readNginxSubscribe
    local nginxSubscribeListen=
    local nginxSubscribeSSL=
    local serverName=
    local SSLType=
    local listenIPv6=

if [[ -z "${subscribePort}" ]]; then

nginxVersion=$(nginx -v 2>&1)

if echo "${nginxVersion}" | grep -q "not found" || [[ -z "${nginxVersion}" ]]; then
echoContent yellow "Nginx not detected, subscription service cannot be used\n"
read -r -p "Do you want to install [y/n]?" installNginxStatus
if [[ "${installNginxStatus}" == "y" ]]; then
installNginxTools
else
echoContent red " ---> Abandon installation of nginx\n"
exit 0
fi
fi
echoContent yellow "Start configuring subscription, please enter the subscription port\n"
mapfile -t result < <(initSingBoxPort "${subscribePort}")
echo
echoContent yellow " ---> Start configuring the subscribed disguised site\n"
nginxBlog
echo
local httpSubscribeStatus=

if ! echo "${selectCustomInstallType}" | grep -qE ",0,|,1,|,2,|,3,|,4,|,5,|,6,|,9,|,10,|,11," && ! echo "${currentInstallProtocolType}" | grep -qE ",0,|,1,|,2,|,3,|,4,|,5,|,6,|,9,|,10,|,11," && [[ -z "${domain}" ]]; then
httpSubscribeStatus=true
fi

if [[ "${httpSubscribeStatus}" == "true" ]]; then

echoContent yellow "No tls certificate found, use unencrypted subscription, may be blocked by the operator, please pay attention to the risk. "
echo
read -r -p "Do you want to subscribe to [y/n] using http?" addNginxSubscribeStatus
            echo
            if [[ "${addNginxSubscribeStatus}" != "y" ]]; then
                echoContent yellow " ---> Exit installation"
                exit
            fi
        else
            local subscribeServerName=
            if [[ -n "${currentHost}" ]]; then
                subscribeServerName="${currentHost}"
            else
                subscribeServerName="${domain}"
            fi

            SSLType="ssl"
            serverName="server_name ${subscribeServerName};"
            nginxSubscribeSSL="ssl_certificate /etc/v2ray-agent/tls/${subscribeServerName}.crt;ssl_certificate_key /etc/v2ray-agent/tls/${subscribeServerName}.key;"
        fi
        if [[ -n "$(curl --connect-timeout 2 -s -6 http://www.cloudflare.com/cdn-cgi/trace | grep "ip" | cut -d "=" -f 2)" ]]; then
            listenIPv6="listen [::]:${result[-1]} ${SSLType};"
        fi
        then
            nginxSubscribeListen="listen ${result[-1]} ${SSLType} so_keepalive=on;http2 on;${listenIPv6}"
        else            nginxSubscribeListen="listen ${result[-1]} ${SSLType} so_keepalive=on;${listenIPv6}"
        fi

        cat <<EOF >${nginxConfigPath}subscribe.conf
server {
    ${nginxSubscribeListen}
    ${serverName}
    ${nginxSubscribeSSL}
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers                TLS13_AES_128_GCM_SHA256:TLS13_AES_256_GCM_SHA384:TLS13_CHACHA20_POLY1305_SHA256:ECDH E-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers on;

    resolver 1.1.1.1 valid=60s;
    resolver_timeout 2s;
    client_max_body_size 100m;
    root ${nginxStaticPath};
    location ~ ^/s/(clashMeta|default|clashMetaProfiles|sing-box|sing-box_profiles)/(.*) {
        default_type 'text/plain; charset=utf-8';
alias /etc/v2ray-agent/subscribe/\$1/\$2;
}
location / {
}
}
EOF
bootStartup nginx
handleNginx stop
handleNginx start
fi
if [[ -z $(pgrep -f "nginx") ]]; then
handleNginx start
fi
}
# Uninstall subscription
unInstallSubscribe() {
rm -rf ${nginxConfigPath}subscribe.conf >/dev/null 2>&1
}

# Add subscription
addSubscribeMenu() {
echoContent skyBlue "\n===================== Add other machine subscriptions ======================="
echoContent yellow "1. Add"
echoContent yellow "2. Remove"
echoContent red "================================================================"
read -r -p "Please select:" addSubscribeStatus
if [[ "${addSubscribeStatus}" == "1" ]]; then
addOtherSubscribe
elif [[ "${addSubscribeStatus}" == "2" ]]; then

if [[ ! -f "/etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl" ]]; then
echoContent green " ---> No other subscriptions installed"
exit 0
fi
grep -v '^$' "/etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl" | awk '{print NR""":"$0}'
read -r -p "Please select the subscription number to be deleted [only single deletion is supported]:" delSubscribeIndex
if [[ -z "${delSubscribeIndex}" ]]; then
echoContent green " ---> Cannot be empty"
exit 0
fi

sed -i "$((delSubscribeIndex))d" "/etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl" >/dev/null 2>&1

echoContent green " ---> Other machine subscriptions deleted successfully"
subscribe
fi
}
# Add other machine clashMeta subscriptions
addOtherSubscribe() {
echoContent yellow "#Notes:"
echoContent yellow "Please read the following article carefully: https://www.v2ray-agent.com/archives/1681804748677"
echoContent skyBlue "Entry example: www.v2ray-agent.com:443:vps1\n"
read -r -p "Please enter the domain name, port, machine alias:" remoteSubscribeUrl
if [[ -z "${remoteSubscribeUrl}" ]]; then
echoContent red " ---> Cannot be empty"
addOtherSubscribe
elif ! echo "${remoteSubscribeUrl}" | grep -q ":"; then
echoContent red " ---> The rule is illegal"
else

if [[ -f "/etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl" ]] && grep -q "${remoteSubscribeUrl}" /etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl; then
echoContent red "---> This subscription has been added"
exit 0
fi
echo
read -r -p "Is it an HTTP subscription? [y/n]" httpSubscribeStatus
if [[ "${httpSubscribeStatus}" == "y" ]]; then
remoteSubscribeUrl="${remoteSubscribeUrl}:http"
fi
echo "${remoteSubscribeUrl}" >>/etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl
subscribe
fi
}
# clashMeta configuration file
clashMetaConfig() {
local url=$1
local id=$2
cat <<EOF >"/etc/v2ray-agent/subscribe/clashMetaProfiles/${id}"
log-level: debug
mode: rule
ipv6: true
mixed-port: 7890
allow-lan: true
bind-address: "*"
lan-allowed-ips:
  - 0.0.0.0/0
  - ::/0
find-process-mode: strict
external-controller: 0.0.0.0:9090

geox-url:
  geoip: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"
  geosite: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"
  mmdb: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb"
geo-auto-update: true
geo-update-interval: 24

external-controller-cors:
  allow-private-network: true

global-client-fingerprint: chrome

profile:
  store-selected: true
  store-fake-ip: true

sniffer:
  enable: true
  override-destination: false
  sniff:
    QUIC:
      ports: [ 443 ]
    TLS:
      ports: [ 443 ]
    HTTP:
      ports: [80]


dns:
  enable: true
  prefer-h3: false
  listen: 0.0.0.0:1053
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16  fake-ip-filter:
    - '*.lan'
    - '*.local'
    - 'dns.google'
    - "localhost.ptlogin2.qq.com"
  use-hosts: true
  nameserver:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query
    - 1.1.1.1
    - 8.8.8.8
  proxy-server-nameserver:
    - https://223.5.5.5/dns-query
    - https://1.12.12.12/dns-query
  nameserver-policy:
    "geosite:cn,private":
      - https://doh.pub/dns-query
      - https://dns.alidns.com/dns-query

proxy-providers:
  ${subscribeSalt}_provider:
    type: http
    path: ./${subscribeSalt}_provider.yaml
url: ${url}
interval: 3600
proxy: DIRECT
health-check:
enable: true
url: https://cp.cloudflare.com/generate_204
interval: 300

proxy-groups:
- name: manual switch
type: select
use:
- ${subscribeSalt}_provider
proxies: null
- name: automatic selection
type: url-test
url: http://www.gstatic.com/generate_204
interval: 36000
tolerance: 50
use:
- ${subscribeSalt}_provider
proxies: null

- name: global proxy
type: select
use:
- ${subscribeSalt}_provider
proxies:
- manual switch
- automatic selection

- name: streaming media
type: select
use:
- ${subscribeSalt}_provider
proxies:
- Manual switch
- Automatic selection
- DIRECT

  - name: DNS_Proxy
type: select
use:
- ${subscribeSalt}_provider
proxies:
- auto select
- DIRECT

- name: Telegram
type: select
use:
- ${subscribeSalt}_provider
proxies:
- manual switch
- auto select
- name: Google
type: select
use:
- ${subscribeSalt}_provider
proxies:
- manual switch
- auto select
- DIRECT
- name: YouTube
type: select
use:
- ${subscribeSalt}_provider
proxies:
- manual switch
- auto select
- name: Netflix
type: select
use:
- ${subscribeSalt}_provider
proxies:
- streaming
- manual switch
- auto select
- name: Spotify
type: select
use:
- ${subscribeSalt}_provider
proxies:
- Streaming
- Manual Switch
- Auto Select
- DIRECT
- name: HBO
type: select
use:
- ${subscribeSalt}_provider
proxies:
- Streaming
- Manual Switch
- Auto Select
- name: Bing
type: select
use:
- ${subscribeSalt}_provider
proxies:
- Auto Select
- name: OpenAI
type: select
use:
- ${subscribeSalt}_provider
proxies:
- Auto Select
- Manual Switch
- name: ClaudeAI
type: select
use:
- ${subscribeSalt}_provider
proxies:
- Auto Select
- Manual Switch
- name: Disney
type: select
use:
- ${subscribeSalt}_provider
proxies:
- Streaming
- Manual Switch
- Auto Select
- name: GitHub
type: select
use:
- ${subscribeSalt}_provider
proxies:
- Manual switch
- Automatic selection
- DIRECT
- name: Domestic media
type: select
use:
- ${subscribeSalt}_provider
proxies:
- DIRECT
- name: Local direct connection
type: select
use:
- ${subscribeSalt}_provider
proxies:
- DIRECT
- Automatic selection
- name: Slippery fish
type: select
use:
- ${subscribeSalt}_provider
proxies:
- DIRECT
- Manual switch
- Automatic selection
rule-providers:
lan:
type: http
behavior: classical
interval: 86400
url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Lan/Lan.yaml
path: ./Rules/lan.yaml
  reject:
    type: http
    behavior:domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt
    path: ./ruleset/reject.yaml
    interval: 86400
  proxy:
    type: http
    behavior:domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt
    path: ./ruleset/proxy.yaml
    interval: 86400
  direct:
    type: http
    behavior:domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt
    path: ./ruleset/direct.yaml
    interval: 86400
  private:
    type: http
    behavior: domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/private.txt
    path: ./ruleset/private.yaml
    interval: 86400
  gfw:
    type: http
    behavior:domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt
    path: ./ruleset/gfw.yaml
    interval: 86400
  greatfire:
    type: http
    behavior:domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/greatfire.txt
    path: ./ruleset/greatfire.yaml
    interval: 86400
  tld-not-cn:
    type: http
    behavior:domain
    url: https://gh-proxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/tld-not-cn.txt
    path: ./ruleset/tld-not-cn.yaml
    interval: 86400
  telegramcidr:
    type: http
    behavior:ipcidr
    url: https://gh-proxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/telegramcidr.txt
    path: ./ruleset/telegramcidr.yaml
    interval: 86400
  applications:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/applications.txt
    path: ./ruleset/applications.yaml
    interval: 86400
  Disney:
    type: http

    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Disney/Disney.yaml
    path: ./ruleset/disney.yaml
    interval: 86400
  Netflix:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Netflix/Netflix.yaml
    path: ./ruleset/netflix.yaml
    interval: 86400
  YouTube:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/YouTube/YouTube.yaml
    path: ./ruleset/youtube.yaml
    interval: 86400
  HBO:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/HBO/HBO.yaml
    path: ./ruleset/hbo.yaml
    interval: 86400
  OpenAI:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/OpenAI/OpenAI.yaml
    path: ./ruleset/openai.yaml
    interval: 86400
  ClaudeAI:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Claude/Claude.yaml
    path: ./ruleset/claudeai.yaml
    interval: 86400
  Bing:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Bing/Bing.yaml
    path: ./ruleset/bing.yaml
    interval: 86400
  Google:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Google/Google.yaml
    path: ./ruleset/google.yaml
    interval: 86400
  GitHub:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/GitHub/GitHub.yaml
    path: ./ruleset/github.yaml
    interval: 86400
  Spotify:
    type: http
    behavior: classical
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Spotify/Spotify.yaml
    path: ./ruleset/spotify.yaml
    interval: 86400
  ChinaMaxDomain:
    type: http
    behavior: domain
    interval: 86400
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMax/ChinaMax_Domain.yaml
    path: ./Rules/ChinaMaxDomain.yaml
  ChinaMaxIPNoIPv6:
    type: http
    behavior: ipcidr
    interval: 86400
    url: https://gh-proxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMax/ChinaMax_IP_No_IPv6.yaml
    path: ./Rules/ChinaMaxIPNoIPv6.yaml
rules:
  - RULE-SET,YouTube,YouTube,no-resolve
  - RULE-SET,Google,Google,no-resolve
  - RULE-SET,GitHub,GitHub
  - RULE-SET,telegramcidr,Telegram,no-resolve
  - RULE-SET,Spotify,Spotify,no-resolve
  - RULE-SET,Netflix,Netflix
  - RULE-SET,HBO,HBO
  - RULE-SET,Bing,Bing
  - RULE-SET,OpenAI,OpenAI
  - RULE-SET,ClaudeAI,ClaudeAI
  - RULE-SET,Disney,Disney
  - RULE-SET,proxy,全球代理
  - RULE-SET,gfw,全球代理
  - RULE-SET,applications,本地直连
  - RULE-SET,ChinaMaxDomain,本地直连
  - RULE-SET,ChinaMaxIPNoIPv6,本地直连,no-resolve
  - RULE-SET,lan,本地直连,no-resolve
  - GEOIP,CN,本地直连
  - MATCH,漏网之鱼
EOF

}
# 随机salt
initRandomSalt() {
    local chars="abcdefghijklmnopqrtuxyz"
    local initCustomPath=
    for i in {1..10}; do
        echo "${i}" >/dev/null
        initCustomPath+="${chars:RANDOM%${#chars}:1}"
    done
    echo "${initCustomPath}"
}
# 订阅
subscribe() {
    readInstallProtocolType
    installSubscribe

    readNginxSubscribe
    local renewSalt=$1
    local showStatus=$2
    if [[ "${coreInstallType}" == "1" || "${coreInstallType}" == "2" ]]; then

        echoContent skyBlue "-------------------------备注---------------------------------"
        echoContent yellow "# 查看订阅会重新生成本地账号的订阅"

# echoContent yellow "# Adding an account or modifying an account requires rechecking the subscription to regenerate the subscription content for external access"
echoContent red "# You need to manually enter the md5 encrypted salt value. If you don't know, just use a random value"
echoContent yellow "# Does not affect the content of the added remote subscription\n"

if [[ -f "/etc/v2ray-agent/subscribe_local/subscribeSalt" && -n $(cat "/etc/v2ray-agent/subscribe_local/subscribeSalt") ]]; then
if [[ -z "${renewSalt}" ]]; then
read -r -p "Read the Salt set in the last installation. Do you want to use the Salt generated last time? [y/n]:" historySaltStatus
if [[ "${historySaltStatus}" == "y" ]]; then
subscribeSalt=$(cat /etc/v2ray-agent/subscribe_local/subscribeSalt)
else
read -r -p "Please enter salt value, [Enter] Use random:" subscribeSalt
fi
else
subscribeSalt=$(cat /etc/v2ray-agent/subscribe_local/subscribeSalt)
fi
else
read -r -p "Please enter salt value, [Enter] Use random:" subscribeSalt
showStatus=
fi
if [[ -z "${subscribeSalt}" ]]; then
subscribeSalt=$(initRandomSalt)
fi
echoContent yellow "\n ---> Salt: ${subscribeSalt}"

echo "${subscribeSalt}" >/etc/v2ray-agent/subscribe_local/subscribeSalt

rm -rf /etc/v2ray-agent/subscribe/default/*
rm -rf /etc/v2ray-agent/subscribe/clashMeta/*
        rm -rf /etc/v2ray-agent/subscribe_local/default/*
        rm -rf /etc/v2ray-agent/subscribe_local/clashMeta/*
        rm -rf /etc/v2ray-agent/subscribe_local/sing-box/*
        showAccounts >/dev/null
        if [[ -n $(ls /etc/v2ray-agent/subscribe_local/default/) ]]; then
            if [[ -f "/etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl" && -n $(cat "/etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl") ]]; then
                if [[ -z "${renewSalt}" ]]; then
                    read -r -p "Read other subscriptions, update? [y/n]" updateOtherSubscribeStatus
                else
                    updateOtherSubscribeStatus=y
                fi
            fi
            local subscribePortLocal="${subscribePort}"
            find /etc/v2ray-agent/subscribe_local/default/* | while read -r email; do
                email=$(echo "${email}" | awk -F "[d][e][f][a][u][l][t][/]" '{print $2}')

                local emailMd5=
                emailMd5=$(echo -n "${email}${subscribeSalt}"$'\n' | md5sum | awk '{print $1}')

                cat "/etc/v2ray-agent/subscribe_local/default/${email}" >>"/etc/v2ray-agent/subscribe/default/${emailMd5}"
                if [[ "${updateOtherSubscribeStatus}" == "y" ]]; then
                    updateRemoteSubscribe "${emailMd5}" "${email}"
                fi
                local base64Result
                base64Result=$(base64 -w 0 "/etc/v2ray-agent/subscribe/default/${emailMd5}")
                echo "${base64Result}" >"/etc/v2ray-agent/subscribe/default/${emailMd5}"
                echoContent yellow "-----------------------------------------------------------------"
                local currentDomain=${currentHost}

                if [[ -n "${currentDefaultPort}" && "${currentDefaultPort}" != "443" ]]; then
                    currentDomain="${currentHost}:${currentDefaultPort}"
                fi
                if [[ -n "${subscribePortLocal}" ]]; then
                    if [[ "${subscribeType}" == "http" ]]; then
                        currentDomain="$(getPublicIP):${subscribePort}"
                    else
                        currentDomain="${currentHost}:${subscribePort}"
                    fi
                fi
                if [[ -z "${showStatus}" ]]; then
                    echoContent skyBlue "\n----------Default subscription----------\n"
                    echoContent green "email:${email}\n"
                    echoContent yellow "url:${subscribeType}://${currentDomain}/s/default/${emailMd5}\n"
                    echoContent yellow "Online QR code: https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${subscribeType}://${currentDomain}/s/default/${emailMd5}\n"
                    if [[ "${release}" != "alpine" ]]; then

                        echo "${subscribeType}://${currentDomain}/s/default/${emailMd5}" | qrencode -s 10 -m 1 -t UTF8
                    fi

                    # clashMeta
                    if [[ -f "/etc/v2ray-agent/subscribe_local/clashMeta/${email}" ]]; then

                        cat "/etc/v2ray-agent/subscribe_local/clashMeta/${email}" >>"/etc/v2ray-agent/subscribe/clashMeta/${emailMd5}"

                        sed -i '1i\proxies:' "/etc/v2ray-agent/subscribe/clashMeta/${emailMd5}"

                        local clashProxyUrl="${subscribeType}://${currentDomain}/s/clashMeta/${emailMd5}"
                        clashMetaConfig "${clashProxyUrl}" "${emailMd5}"
                        echoContent skyBlue "\n----------clashMeta订阅----------\n"
                        echoContent yellow "url:${subscribeType}://${currentDomain}/s/clashMetaProfiles/${emailMd5}\n"
                        echoContent yellow "在线二维码:https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${subscribeType}://${currentDomain}/s/clashMetaProfiles/${emailMd5}\n"
                        if [[ "${release}" != "alpine" ]]; then
                            echo "${subscribeType}://${currentDomain}/s/clashMetaProfiles/${emailMd5}" | qrencode -s 10 -m 1 -t UTF8
                        fi

                    fi
                    # sing-box
                    if [[ -f "/etc/v2ray-agent/subscribe_local/sing-box/${email}" ]]; then
                        cp "/etc/v2ray-agent/subscribe_local/sing-box/${email}" "/etc/v2ray-agent/subscribe/sing-box_profiles/${emailMd5}"

                        echoContent skyBlue " ---> 下载 sing-box 通用配置文件"
                        if [[ "${release}" == "alpine" ]]; then
                            wget -O "/etc/v2ray-agent/subscribe/sing-box/${emailMd5}" -q "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/documents/sing-box.json"
                        else
                            wget -O "/etc/v2ray-agent/subscribe/sing-box/${emailMd5}" -q "${wgetShowProgressStatus}" "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/documents/sing-box.json"
                        fi

                        jq ".outbounds=$(jq ".outbounds|map(if has(\"outbounds\") then .outbounds += $(jq ".|map(.tag)" "/etc/v2ray-agent/subscribe_local/sing-box/${email}") else . end)" "/etc/v2ray-agent/subscribe/sing-box/${emailMd5}")" "/etc/v2ray-agent/subscribe/sing-box/${emailMd5}" >"/etc/v2ray-agent/subscribe/sing-box/${emailMd5}_tmp" && mv "/etc/v2ray-agent/subscribe/sing-box/${emailMd5}_tmp" "/etc/v2ray-agent/subscribe/sing-box/${emailMd5}"
                        jq ".outbounds += $(jq '.' "/etc/v2ray-agent/subscribe_local/sing-box/${email}")" "/etc/v2ray-agent/subscribe/sing-box/${emailMd5}" >"/etc/v2ray-agent/subscribe/sing-box/${emailMd5}_tmp" && mv "/etc/v2ray-agent/subscribe/sing-box/${emailMd5}_tmp" "/etc/v2ray-agent/subscribe/sing-box/${emailMd5}"

                        echoContent skyBlue "\n----------sing-box订阅----------\n"
                        echoContent yellow "url:${subscribeType}://${currentDomain}/s/sing-box/${emailMd5}\n"
                        echoContent yellow "在线二维码:https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${subscribeType}://${currentDomain}/s/sing-box/${emailMd5}\n"
                        if [[ "${release}" != "alpine" ]]; then
                            echo "${subscribeType}://${currentDomain}/s/sing-box/${emailMd5}" | qrencode -s 10 -m 1 -t UTF8
                        fi

                    fi

                    echoContent skyBlue "--------------------------------------------------------------"
                else
                    echoContent green " ---> email:${email}，订阅已更新，请使用客户端重新拉取"
                fi

            done
        fi
    else
        echoContent red " ---> 未安装伪装站点，无法使用订阅服务"
    fi
}

# 更新远程订阅
updateRemoteSubscribe() {

    local emailMD5=$1
    local email=$2
    while read -r line; do
        local subscribeType=

        subscribeType="https"

        local serverAlias=
        serverAlias=$(echo "${line}" | awk -F "[:]" '{print $3}')

        local remoteUrl=
        remoteUrl=$(echo "${line}" | awk -F "[:]" '{print $1":"$2}')

        local subscribeTypeRemote=
        subscribeTypeRemote=$(echo "${line}" | awk -F "[:]" '{print $4}')

        if [[ -n "${subscribeTypeRemote}" ]]; then
            subscribeType="${subscribeTypeRemote}"
        fi
        local clashMetaProxies=

        clashMetaProxies=$(curl -s "${subscribeType}://${remoteUrl}/s/clashMeta/${emailMD5}" | sed '/proxies:/d' | sed "s/\"${email}/\"${email}_${serverAlias}/g")

        if ! echo "${clashMetaProxies}" | grep -q "nginx" && [[ -n "${clashMetaProxies}" ]]; then
            echo "${clashMetaProxies}" >>"/etc/v2ray-agent/subscribe/clashMeta/${emailMD5}"
            echoContent green " ---> clashMeta订阅 ${remoteUrl}:${email} 更新成功"
        else
            echoContent red " ---> clashMeta订阅 ${remoteUrl}:${email}不存在"
        fi

        local default=
        default=$(curl -s "${subscribeType}://${remoteUrl}/s/default/${emailMD5}")

        if ! echo "${default}" | grep -q "nginx" && [[ -n "${default}" ]]; then
            default=$(echo "${default}" | base64 -d | sed "s/#${email}/#${email}_${serverAlias}/g")
            echo "${default}" >>"/etc/v2ray-agent/subscribe/default/${emailMD5}"

            echoContent green " ---> 通用订阅 ${remoteUrl}:${email} 更新成功"
        else
            echoContent red " ---> 通用订阅 ${remoteUrl}:${email} 不存在"
        fi

        local singBoxSubscribe=
        singBoxSubscribe=$(curl -s "${subscribeType}://${remoteUrl}/s/sing-box_profiles/${emailMD5}")

        if ! echo "${singBoxSubscribe}" | grep -q "nginx" && [[ -n "${singBoxSubscribe}" ]]; then
            singBoxSubscribe=${singBoxSubscribe//tag\": \"${email}/tag\": \"${email}_${serverAlias}}
            singBoxSubscribe=$(jq ". +=${singBoxSubscribe}" "/etc/v2ray-agent/subscribe_local/sing-box/${email}")
            echo "${singBoxSubscribe}" | jq . >"/etc/v2ray-agent/subscribe_local/sing-box/${email}"

            echoContent green " ---> 通用订阅 ${remoteUrl}:${email} 更新成功"
        else
            echoContent red " ---> 通用订阅 ${remoteUrl}:${email} 不存在"
        fi

    done < <(grep -v '^$' <"/etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl")
}

# 切换alpn
switchAlpn() {
    echoContent skyBlue "\n功能 1/${totalProgress} : 切换alpn"
    if [[ -z ${currentAlpn} ]]; then
        echoContent red " ---> 无法读取alpn，请检查是否安装"
        exit 0
    fi

    echoContent red "\n=============================================================="
    echoContent green "当前alpn首位为:${currentAlpn}"
    echoContent yellow "  1.当http/1.1首位时，trojan可用，gRPC部分客户端可用【客户端支持手动选择alpn的可用】"
    echoContent yellow "  2.当h2首位时，gRPC可用，trojan部分客户端可用【客户端支持手动选择alpn的可用】"
    echoContent yellow "  3.如客户端不支持手动更换alpn，建议使用此功能更改服务端alpn顺序，来使用相应的协议"
    echoContent red "=============================================================="

    if [[ "${currentAlpn}" == "http/1.1" ]]; then
        echoContent yellow "1.切换alpn h2 首位"
    elif [[ "${currentAlpn}" == "h2" ]]; then
        echoContent yellow "1.切换alpn http/1.1 首位"
    else
        echoContent red '不符合'
    fi

    echoContent red "=============================================================="

    read -r -p "请选择:" selectSwitchAlpnType
    if [[ "${selectSwitchAlpnType}" == "1" && "${currentAlpn}" == "http/1.1" ]]; then

        local frontingTypeJSON
        frontingTypeJSON=$(jq -r ".inbounds[0].streamSettings.tlsSettings.alpn = [\"h2\",\"http/1.1\"]" ${configPath}${frontingType}.json)
        echo "${frontingTypeJSON}" | jq . >${configPath}${frontingType}.json

    elif [[ "${selectSwitchAlpnType}" == "1" && "${currentAlpn}" == "h2" ]]; then
        local frontingTypeJSON
        frontingTypeJSON=$(jq -r ".inbounds[0].streamSettings.tlsSettings.alpn =[\"http/1.1\",\"h2\"]" ${configPath}${frontingType}.json)

        echo "${frontingTypeJSON}" | jq . >${configPath}${frontingType}.json
else
echoContent red " ---> Selection error"
exit 0
fi
reloadCore
}

# Initialize realityKey
initRealityKey() {
echoContent skyBlue "\nGenerate Reality key\n"
if [[ -n "${currentRealityPublicKey}" && -z "${lastInstallationConfig}" ]]; then
read -r -p "Read the last installation record. Do you want to use the PublicKey/PrivateKey from the last installation? [y/n]:" historyKeyStatus
if [[ "${historyKeyStatus}" == "y" ]]; then
realityPrivateKey=${currentRealityPrivateKey}
realityPublicKey=${currentRealityPublicKey}
fi
elif [[ -n "${currentRealityPublicKey}" && -n "${lastInstallationConfig}" ]]; then
        realityPrivateKey=${currentRealityPrivateKey}
        realityPublicKey=${currentRealityPublicKey}
    fi
    if [[ -z "${realityPrivateKey}" ]]; then
        if [[ "${selectCoreType}" == "2" || "${coreInstallType}" == "2" ]]; then
            realityX25519Key=$(/etc/v2ray-agent/sing-box/sing-box generate reality-keypair)
            realityPrivateKey=$(echo "${realityX25519Key}" | head -1 | awk '{print $2}')
            realityPublicKey=$(echo "${realityX25519Key}" | tail -n 1 | awk '{print $2}')
            echo "publicKey:${realityPublicKey}" >/etc/v2ray-agent/sing-box/conf/config/reality_key
        else
            realityX25519Key=$(/etc/v2ray-agent/xray/xray x25519)
            realityPrivateKey=$(echo "${realityX25519Key}" | head -1 | awk '{print $3}')
            realityPublicKey=$(echo "${realityX25519Key}" | tail -n 1 | awk '{print $3}')
        fi
    fi
    echoContent green "\n privateKey:${realityPrivateKey}"
    echoContent green "\n publicKey:${realityPublicKey}"
}
# Check whether the reality domain name matches
checkRealityDest() {
    local traceResult=
    traceResult=$(curl -s "https://$(echo "${realityDestDomain}" | cut -d ':' -f 1)/cdn-cgi/trace" | grep "visit_scheme=https")
if [[ -n "${traceResult}" ]]; then
echoContent red "\n ---> The domain name used is detected, hosted on cloudflare and the proxy is turned on. Using this type of domain name may cause VPS traffic to be used by others [not recommended]\n"
read -r -p "Do you want to continue? [y/n]" setRealityDestStatus
if [[ "${setRealityDestStatus}" != 'y' ]]; then
exit 0
fi
echoContent yellow "\n ---> Ignore the risk and continue to use"
fi
}

# Initialize the ServersName available to the client
initRealityClientServersName() {
local realityDestDomainList="gateway.icloud.com,itunes.apple.com,swdist.apple.com,swcdn.apple.com,updates.cdn-apple.com,mensura.cdn-apple.com,osxapps.itunes .apple.com,aod.itunes.apple.com,download-installer.cdn.mozilla.net,addons.mozilla.org,s0.awsstatic.com,d1.awsstatic.com,images-na.ssl-images-amazon.co m,m.media-amazon.com,player.live-video.net,one-piece.com,lol.secure.dyn.riotcdn.net,www.lovelive-anime.jp,www.swift.com,academy.nvidia.com,www.cisco. com,www.asus.com,www.samsung.com,www.amd.com,cdn-dynmedia-1.microsoft.com,software.download.prss.microsoft.com,dl.google.com,www.google-analytics.com"
    if [[ -n "${realityServerName}" && -z "${lastInstallationConfig}" ]]; then
        if echo ${realityDestDomainList} | grep -q "${realityServerName}"; then
            read -r -p "Read the Reality domain name set in the last installation. Do you want to use it? [y/n]:" realityServerNameStatus
            if [[ "${realityServerNameStatus}" != "y" ]]; then
                realityServerName=
                realityDomainPort=
            fi
        else
            realityServerName=
            realityDomainPort=
        fi
    elif [[ -n "${realityServerName}" && -z "${lastInstallationConfig}" ]]; then
        realityServerName=
        realityDomainPort=
    fi

    if [[ -z "${realityServerName}" ]]; then
        if [[ -n "${domain}" ]]; then
            echo
            read -r -p "Do you want to use ${domain} as the Reality target domain? [y/n]:" realityServerNameCurrentDomainStatus
if [[ "${realityServerNameCurrentDomainStatus}" == "y" ]]; then
realityServerName="${domain}"
if [[ "${selectCoreType}" == "1" ]]; then
if [[ -z "${subscribePort}" ]]; then
echo
installSubscribe

readNginxSubscribe
realityDomainPort="${subscribePort}"
else
realityDomainPort="${subscribePort}"
fi
fi
if [[ "${selectCoreType}" == "2" ]]; then
if [[ -z "${subscribePort}" ]]; then
echo
installSubscribe
readNginxSubscribe
realityDomainPort="${subscribePort}"
else
realityDomainPort="${subscribePort}"
fi
fi
fi
if [[ -z "${realityServerName}" ]]; then
realityDomainPort=443
echoContent skyBlue "\n================ Configure the serverNames available to the client ===============\n"
echoContent yellow "#Notes"
echoContent green "Reality target available domain name list: https://www.v2ray-agent.com/archives/1689439383686#heading-3\n"
echoContent yellow "Entry example: addons.mozilla.org:443\n"
read -r -p "Please enter the target domain name, [Enter] Random domain name, default port 443:" realityServerName
if [[ -z "${realityServerName}" ]]; then
randomNum=$(randomNum 1 27)
realityServerName=$(echo "${realityDestDomainList}" | awk -F ',' -v randomNum="$randomNum" '{print $randomNum}')
fi
if echo "${realityServerName}" | grep -q ":"; then
realityDomainPort=$(echo "${realityServerName}" | awk -F "[:]" '{print $2}')
realityServerName=$(echo "${realityServerName}" | awk -F "[:]" '{print $1}')
fi
fi
fi
echoContent yellow "\n ---> Available domain name for client: ${realityServerName}:${realityDomainPort}\n"
}
# Initialize reality port
initXrayRealityPort() {
if [[ -n "${xrayVLESSRealityPort}" && -z "${lastInstallationConfig}" ]]; then
read -r -p "Read the last installation record, do you want to use the port from the last installation? [y/n]:" historyRealityPortStatus
if [[ "${historyRealityPortStatus}" == "y" ]]; then
realityPort=${xrayVLESSRealityPort}
fi
elif [[ -n "${xrayVLESSRealityPort}" && -n "${lastInstallationConfig}" ]]; then
realityPort=${xrayVLESSRealityPort}
fi

if [[ -z "${realityPort}" ]]; then
# if [[ -n "${port}" ]]; then
# read -r -p "Do you use TLS+Vision port? [y/n]:" realityPortTLSVisionStatus
# if [[ "${realityPortTLSVisionStatus}" == "y" ]]; then
# realityPort=${port}
# fi
# fi
# if [[ -z "${realityPort}" ]]; then
echoContent yellow "Please enter the port [Enter random 10000-30000]"

read -r -p "Port:" realityPort
if [[ -z "${realityPort}" ]]; then
realityPort=$((RANDOM % 20001 + 10000))
fi
# fi
if [[ -n "${realityPort}" && "${xrayVLESSRealityPort}" == "${realityPort}" ]]; then
handleXray stop
else
checkPort "${realityPort}"
fi
fi
if [[ -z "${realityPort}" ]]; then
initXrayRealityPort
else
allowPort "${realityPort}"
echoContent yellow "\n ---> Port: ${realityPort}"
fi

}
# Initialize XHTTP port
initXrayXHTTPort() {
if [[ -n "${xrayVLESSRealityXHTTPort}" && -z "${lastInstallationConfig}" ]]; then
read -r -p "Read the last installation record, whether to use the port of the last installation ？ [y/n]:" historyXHTTPortStatus
if [[ "${historyXHTTPortStatus}" == "y" ]]; then
xHTTPort=${xrayVLESSRealityXHTTPort}
fi
elif [[ -n "${xrayVLESSRealityXHTTPort}" && -n "${lastInstallationConfig}" ]]; then
xHTTPort=${xrayVLESSRealityXHTTPort}
fi

if [[ -z "${xHTTPort}" ]]; then

echoContent yellow "Please enter the port [Enter Random 10000-30000]"
read -r -p "Port:" xHTTPort
if [[ -z "${xHTTPort}" ]]; then
xHTTPort=$((RANDOM % 20001 + 10000))
fi
if [[ -n "${xHTTPort}" && "${xrayVLESSRealityXHTTPort}" == "${xHTTPort}" ]]; then
            handleXray stop
        else

            checkPort "${xHTTPort}"
        fi
    fi
    if [[ -z "${xHTTPort}" ]]; then
        initXrayXHTTPort
    else
        allowPort "${xHTTPort}"
        allowPort "${xHTTPort}" "udp"
        echoContent yellow "\n ---> 端口: ${xHTTPort}"
    fi
}
# 初始化 reality 配置
initXrayRealityConfig() {
    echoContent skyBlue "\n进度  $1/${totalProgress} : 初始化 Xray-core reality配置"
    initXrayRealityPort
    initRealityKey
    initRealityClientServersName
}
# 修改reality域名端口等信息
updateXrayRealityConfig() {

    local realityVisionResult
    realityVisionResult=$(jq -r ".inbounds[0].port = ${realityPort}" ${configPath}07_VLESS_vision_reality_inbounds.json)
    realityVisionResult=$(echo "${realityVisionResult}" | jq -r ".inbounds[0].streamSettings.realitySettings.dest = \"${realityDestDomain}\"")
    realityVisionResult=$(echo "${realityVisionResult}" | jq -r ".inbounds[0].streamSettings.realitySettings.serverNames = [${realityServerName}]")
    realityVisionResult=$(echo "${realityVisionResult}" | jq -r ".inbounds[0].streamSettings.realitySettings.privateKey = \"${realityPrivateKey}\"")
    realityVisionResult=$(echo "${realityVisionResult}" | jq -r ".inbounds[0].streamSettings.realitySettings.publicKey = \"${realityPublicKey}\"")
    echo "${realityVisionResult}" | jq . >${configPath}07_VLESS_vision_reality_inbounds.json
    reloadCore
    echoContent green " ---> 修改完成"
}
# xray-core Reality 安装
xrayCoreRealityInstall() {
    totalProgress=13
    installTools 2
    # 下载核心
    #    prereleaseStatus=true
    #    updateXray
    installXray 3 false
    # 生成 privateKey、配置回落地址、配置serverNames
    installXrayService 6
    # initXrayRealityConfig 5
    # 初始化配置
    initXrayConfig custom 7
    handleXray stop

    sleep 2
    # 启动
    handleXray start
    # 生成账号
    showAccounts 8
}

# reality管理
manageReality() {
    readInstallProtocolType
    readConfigHostPathUUID
    readCustomPort
    readSingBoxConfig

    if ! echo "${currentInstallProtocolType}" | grep -q -E "7,|8," || [[ -z "${coreInstallType}" ]]; then
        echoContent red "\n ---> 请先安装Reality协议，参考教程 https://www.v2ray-agent.com/archives/1680104902581#heading-11"
        exit 0
    fi

    if [[ "${coreInstallType}" == "1" ]]; then
        selectCustomInstallType=",7,"
        initXrayConfig custom 1 true
    elif [[ "${coreInstallType}" == "2" ]]; then
        if echo "${currentInstallProtocolType}" | grep -q ",7,"; then
            selectCustomInstallType=",7,"
        fi
        if echo "${currentInstallProtocolType}" | grep -q ",8,"; then
            selectCustomInstallType="${selectCustomInstallType},8,"
        fi
        initSingBoxConfig custom 1 true
    fi

    reloadCore
    subscribe false
}

# 安装reality scanner
installRealityScanner() {
    if [[ ! -f "/etc/v2ray-agent/xray/reality_scan/RealiTLScanner-linux-64" ]]; then
        version=$(curl -s https://api.github.com/repos/XTLS/RealiTLScanner/releases?per_page=1 | jq -r '.[]|.tag_name')
        wget -c -q -P /etc/v2ray-agent/xray/reality_scan/ "https://github.com/XTLS/RealiTLScanner/releases/download/${version}/RealiTLScanner-linux-64"
        chmod 655 /etc/v2ray-agent/xray/reality_scan/RealiTLScanner-linux-64
    fi
}
# reality scanner
realityScanner() {
    echoContent skyBlue "\n进度 1/1 : 扫描Reality域名"
    echoContent red "\n=============================================================="
    echoContent yellow "# 注意事项"
    echoContent yellow "扫描完成后，请自行检查扫描网站结果内容是否合规，需个人承担风险"
    echoContent red "某些IDC不允许扫描操作，比如搬瓦工，其中风险请自行承担\n"
    echoContent yellow "1.扫描IPv4"
    echoContent yellow "2.扫描IPv6"
    echoContent red "=============================================================="
    read -r -p "请选择:" realityScannerStatus
    local type=
    if [[ "${realityScannerStatus}" == "1" ]]; then
        type=4
    elif [[ "${realityScannerStatus}" == "2" ]]; then
        type=6
    fi

    read -r -p "某些IDC不允许扫描操作，比如搬瓦工，其中风险请自行承担，是否继续？[y/n]:" scanStatus

    if [[ "${scanStatus}" != "y" ]]; then
        exit 0
    fi


publicIP=$(getPublicIP "${type}")
echoContent yellow "IP:${publicIP}"
if [[ -z "${publicIP}" ]]; then
echoContent red " ---> Unable to obtain IP"
exit 0
fi

read -r -p "Is the IP correct? [y/n]:" ipStatus
if [[ "${ipStatus}" == "y" ]]; then
echoContent yellow "The result is stored in the /etc/v2ray-agent/xray/reality_scan/result.log file\n"
/etc/v2ray-agent/xray/reality_scan/RealiTLScanner-linux-64 -addr "${publicIP}" | tee /etc/v2ray-agent/xray/reality_scan/result.log
else
echoContent red " ---> Unable to read the correct IP"
fi
}
# hysteria management
manageHysteria() {
echoContent skyBlue "\nProgress 1/1: Hysteria2 management"
echoContent red "\n==============================================================="
local hysteria2Status=
if [[ -n "${singBoxConfigPath}" ]] && [[ -f "/etc/v2ray-agent/sing-box/conf/config/06_hysteria2_inbounds.json" ]]; then
echoContent yellow "Depends on third-party sing-box\n"
echoContent yellow "1. Reinstall"
echoContent yellow "2. Uninstall"
echoContent yellow "3. Port jump management"
hysteria2Status=true
else
echoContent yellow "Depends on sing-box kernel\n"
echoContent yellow "1. Installation"
fi

echoContent red "================================================================"
read -r -p "Please select:" installHysteria2Status
if [[ "${installHysteria2Status}" == "1" ]]; then
singBoxHysteria2Install
elif [[ "${installHysteria2Status}" == "2" && "${hysteria2Status}" == "true" ]]; then
unInstallSingBox hysteria2
elif [[ "${installHysteria2Status}" == "3" && "${hysteria2Status}" == "true" ]]; then
portHoppingMenu hysteria2
fi
}

# tuic management
manageTuic() {
echoContent skyBlue "\nProgress 1/1: Tuic management"
echoContent red "\n================================================================"
local tuicStatus=
if [[ -n "${singBoxConfigPath}" ]] && [[ -f "/etc/v2ray-agent/sing-box/conf/config/09_tuic_inbounds.json" ]]; then
echoContent yellow "Depends on sing-box kernel\n"
echoContent yellow "1. Reinstall"
echoContent yellow "2. Uninstall"
echoContent yellow "3. Port jump management"
tuicStatus=true
else
echoContent yellow "Depends on sing-box kernel\n"
echoContent yellow "1. Install"
fi

echoContent red "==============================================================="
read -r -p "Please select:" installTuicStatus
if [[ "${installTuicStatus}" == "1" ]]; then
singBoxTuicInstall
elif [[ "${installTuicStatus}" == "2" && "${tuicStatus}" == "true" ]]; then
unInstallSingBox tuic
elif [[ "${installTuicStatus}" == "3" && "${tuicStatus}" == "true" ]]; then
portHoppingMenu tuic
fi
}
# sing-box log
singBoxLog() {
cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/log.json
{
"log": {
"disabled": $1,
"level": "debug",
"output": "/etc/v2ray-agent/sing-box/conf/box.log",
"timestamp": true
}
}
EOF

handleSingBox stop
handleSingBox start
}
# hysteria version management
hysteriaVersionManageMenu() {
echoContent skyBlue "\nProgress $1/${totalProgress} : Hysteria version management"
if [[ ! -d "/etc/v2ray-agent/hysteria/" ]]; then
echoContent red " ---> No installation directory detected, please execute the script to install the content"
menu
exit 0
fi
echoContent red "\n================================================================="
echoContent yellow "1. Upgrade Hysteria"
echoContent yellow "2. Close Hysteria"
echoContent yellow "3. Open Hysteria"
echoContent yellow "4. Restart Hysteria"
echoContent red "=================================================================="

read -r -p "Please select:" selectHysteriaType
if [[ "${selectHysteriaType}" == "1" ]]; then
        installHysteria 1
        handleHysteria start
    elif [[ "${selectHysteriaType}" == "2" ]]; then
        handleHysteria stop
    elif [[ "${selectHysteriaType}" == "3" ]]; then
        handleHysteria start
    elif [[ "${selectHysteriaType}" == "4" ]]; then
        handleHysteria stop
        handleHysteria start
    fi
}

# sing-box version management
singBoxVersionManageMenu() {

echoContent skyBlue "\nProgress $1/${totalProgress} : sing-box version management"
if [[ -z "${singBoxConfigPath}" ]]; then
echoContent red " ---> No installation program detected, please execute the script to install the content"
menu
exit 0
fi
echoContent red "\n================================================================"
echoContent yellow "1. Upgrade sing-box"
echoContent yellow "2. Close sing-box"
echoContent yellow "3. Open sing-box"
echoContent yellow "4. Restart sing-box"
echoContent yellow "==============================================================="
local logStatus=
if [[ -n "${singBoxConfigPath}" && -f "${singBoxConfigPath}log.json" && "$(jq -r .log.disabled "${singBoxConfigPath}log.json")" == "false" ]]; then
echoContent yellow "5. Disable log"
logStatus=true
else
echoContent yellow "5. Enable log"
logStatus=false
fi

echoContent yellow "6. View log"
echoContent red "=============================================================="

    read -r -p "Please select:" selectSingBoxType
    if [[ ! -f "${singBoxConfigPath}../box.log" ]]; then
        touch "${singBoxConfigPath}../box.log" >/dev/null 2>&1
    fi
    if [[ "${selectSingBoxType}" == "1" ]]; then
        installSingBox 1
        handleSingBox stop
        handleSingBox start
    elif [[ "${selectSingBoxType}" == "2" ]]; then
        handleSingBox stop
    elif [[ "${selectSingBoxType}" == "3" ]]; then
        handleSingBox start    elif [[ "${selectSingBoxType}" == "4" ]]; then
        handleSingBox stop
        handleSingBox start
    elif [[ "${selectSingBoxType}" == "5" ]]; then
        singBoxLog ${logStatus}
        if [[ "${logStatus}" == "false" ]]; then
            tail -f "${singBoxConfigPath}../box.log"
        fi
    elif [[ "${selectSingBoxType}" == "6" ]]; then
        tail -f "${singBoxConfigPath}../box.log"
    fi
}

# Main menu
menu() {
    cd "$HOME" || exit
    echoContent red "\n================================================================="
echoContent green "Author: mack-a"
echoContent green "Current version: v3.4.16"
echoContent green "Github: https://github.com/mack-a/v2ray-agent"
echoContent green "Description: Eight-in-one coexistence script\c"
showInstallStatus
checkWgetShowProgress
echoContent red "\n============================= Promotion Area============================="
echoContent red " "
echoContent green "VPS purchase guide: https://www.v2ray-agent.com/archives/1679975663984"
echoContent green "VPS AS4837 with an annual payment of 10 US dollars: https://www.v2ray-agent.com/archives/racknerdtao-can-zheng-li-nian-fu-10mei-yuan"
echoContent red "================================================================"
if [[ -n "${coreInstallType}" ]]; then
echoContent yellow "1. Reinstall"
else
echoContent yellow "1. Install"
fi

echoContent yellow "2. Install in any combination"
echoContent yellow "4.Hysteria2 Management"
echoContent yellow "5.REALITY Management"
echoContent yellow "6.Tuic Management"

echoContent skyBlue "-------------------------Tool Management-----------------------------"
echoContent yellow "7.User Management"
echoContent yellow "8.Fake Site Management"
echoContent yellow "9.Certificate Management"
echoContent yellow "10.CDN Node Management"
echoContent yellow "11.Diversion Tool"
echoContent yellow "12.Add New Port"
echoContent yellow "13.BT Download Management"
echoContent yellow "15.Domain Blacklist"
echoContent skyBlue "-------------------------Version Management-----------------------------"
echoContent yellow "16.Core Management"
echoContent yellow "17.Update Script"
echoContent yellow "18.Install BBR, DD Script"
echoContent skyBlue "-------------------------Script Management-----------------------------"
echoContent yellow "20. Uninstall Script"
echoContent red "==============================================================="
mkdirTools
aliasInstall
read -r -p "Please select:" selectInstallType
case ${selectInstallType} in
1)
selectCoreInstall
;;
2)
selectCoreInstall
;;
# 3)
# initXrayFrontingConfig 1
# ;;
4)
manageHysteria
;;
5)
manageReality 1
;;

    6)
        manageTuic
        ;;
    7)
        manageAccount 1
        ;;
    8)
        updateNginxBlog 1
        ;;
    9)
        renewalTLS 1
        ;;
    10)
        manageCDN 1
        ;;
    11)
        routingToolsMenu 1
        ;;
    12)
        addCorePort 1
        ;;
    13)
        btTools 1
        ;;
    14)
        switchAlpn 1
        ;;
    15)
        blacklist 1
        ;;
    16)
        coreVersionManageMenu 1
        ;;
    17)
        updateV2RayAgent 1
        ;;
    18)
        bbrInstall
        ;;
    20)
        unInstall 1
        ;;
    esac
}
cronFunction
menu

