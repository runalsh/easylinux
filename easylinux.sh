#!/bin/bash

source config.sh
source configself.sh
apt-get update
apt-get install -y --no-install-recommends --no-install-suggests \
  kmod debian-archive-keyring tzdata software-properties-common lsb-release apt-transport-https apt-utils sudo coreutils \
  ncdu wget net-tools iputils-ping curl ca-certificates iproute2 \
  nano procps tree telnet tmux bash-completion grep gawk mc patch apache2-utils nmon jq tar python3 python3-pip gnupg2 zip unzip git lzma gpg
#tig
timedatectl set-timezone Europe/Moscow
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [ "$ID" == "ubuntu" ]; then
        OS="Ubuntu"
    elif [ "$ID" == "debian" ]; then
        OS="Debian"
    else
        OS="unsuported linux detected"
    fi
else
    OS="not possible to detect OS"
fi
echo "detected $OS $VERSION_ID"
echo "set -g mouse on" >> /etc/tmux.conf
mkdir -p ~/.config/pip
echo '[global]
break-system-packages = true' >> ~/.config/pip/pip.conf
wget -O /tmp/get-pip.py https://bootstrap.pypa.io/get-pip.py && python3 /tmp/get-pip.py && rm -rf /tmp/get-pip.py
################### wsl #####################################################################################################################################
if [[ "$wsl" == "1" ]]; then
echo '[boot]
systemd=true
[boot]
command = service docker start' > /etc/wsl.conf
apt install -y systemd systemd-sysv libpam-systemd dbus-user-session openssh-server openssh-sftp-server 
fi
################### SYSCTL #####################################################################################################################################
sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
echo "net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.icmp_echo_ignore_all = 1
fs.file-max = 51200
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mem = 25600 51200 102400
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1" >> /etc/sysctl.conf
sudo sysctl -p
echo "* hard nofile 51200
* soft nofile 51200
root soft nofile 51200
root hard nofile 51200" >> /etc/security/limits.conf
################### SSH #####################################################################################################################################
sed -i "s|^#PermitRootLogin .*|PermitRootLogin yes|g" /etc/ssh/sshd_config
sed -i "s|^#AllowAgentForwarding .*|AllowAgentForwarding yes|g" /etc/ssh/sshd_config
sed -i "s|^#AllowTcpForwarding .*|AllowTcpForwarding yes|g" /etc/ssh/sshd_config
sed -i "s|^#GatewayPorts .*|GatewayPorts yes|g" /etc/ssh/sshd_config
mkdir -p /root/.ssh/
echo $root_ssh_key >> /root/.ssh/authorized_keys
echo "root:$root_passwd" | chpasswd
if [ "$OS" == "Ubuntu" ]; then 
  mkdir -p /home/ubuntu/.ssh/
  echo $root_ssh_key >> /home/ubuntu/.ssh/authorized_keys
  echo "ubuntu:$root_passwd" | chpasswd
fi
################### MICRO #####################################################################################################################################
if [ "$micro" == "1" ]; then
sh -c "cd /usr/bin; wget -O- https://getmic.ro | GETMICRO_REGISTER=y sh" | bash
# ctrl-Q exit
# ctrl-S save
# ctrl-С copy
# ctrl-X cut
# ctrl-K cut line
# ctrl-V paste
# ctrl-Z revert
# ctrl-F find (ctrl-N next, ctrl-P previous)
# ctrl-A salact all
# ctrl-E command line
# ctrl-T new tab
# alt-, previous tab
# alt-. next tab
# ctrl-G help
# alt-G hot binds
# https://github.com/zyedidia/micro/blob/master/runtime/help/keybindings.md
micro -plugin install filemanager  
#run ctrl-e > tree, tab anter, back to tree ctrl-w
micro -plugin install bookmark
# # mark/unmark current line (Ctrl-F2)
# > toggleBookmark
# # clear all bookmarks (CtrlShift-F2)
# > clearBookmarks
# # jump to next bookmark (F2)
# > nextBookmark
# # jump to previous bookmark (Shift-F2)
# > prevBookmark
micro -plugin install manipulator
# upper: UPPERCASE
# lower: lowercase
# reverse: Reverses
# base64enc: Base64 encodes
# base64dec: Base64 decodes
fi
################### DOCKER #####################################################################################################################################
if [[ "$docker" == "1" ]]; then
curl -fsSL https://get.docker.com -o get-docker.sh
sed -i '/sleep/d' get-docker.sh
DEBIAN_FRONTEND=noninteractive sudo sh ./get-docker.sh
fi
################### OBSERVABILITY CERTS #####################################################################################################################################
if [[ "$node_exporter" == "1" ]] || [[ "$prometheus" == "1" ]]; then
observ_passw_hash=$(echo $observ_passw | htpasswd -inBC 10 "" | tr -d ':\n')
# openssl genrsa -out /etc/ssl/tls_prometheus_key.key 2048
# openssl req -new -key /etc/ssl/tls_prometheus_key.key -out /etc/ssl/tls_prometheus_csr.csr -subj "/CN=`hostname`" \-addext "subjectAltName = DNS:`hostname`"
# openssl x509 -req -days 3650 -in /etc/ssl/tls_prometheus_csr.csr -signkey /etc/ssl/tls_prometheus_key.key -out /etc/ssl/tls_prometheus_crt.crt
# sudo openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
#   -keyout /etc/ssl/tls_prometheus_key.key \
#   -out /etc/ssl/tls_prometheus_crt.crt \
#   -subj "/CN=`hostname`" \
#   -addext "subjectAltName = DNS:`hostname`"
# echo -e $tls_prometheus_crt > /etc/ssl/tls_prometheus_crt.crt
# echo -e $tls_prometheus_key > /etc/ssl/tls_prometheus_key.key
echo "$(echo "$tls_prometheus_key" | base64 --decode)" > /etc/ssl/tls_prometheus_key.key
echo "$(echo "$tls_prometheus_crt" | base64 --decode)" > /etc/ssl/tls_prometheus_crt.crt
chmod 777 /etc/ssl/{tls_prometheus_crt.crt,tls_prometheus_key.key}
fi
################### NODE EXPORTER #####################################################################################################################################
if [[ "$node_exporter" == "1" ]]; then
URL_NE=`curl -sL -o /dev/null -w %{url_effective} https://github.com/prometheus/node_exporter/releases/latest`
VERSION_NE=${URL_NE##*/}
wget -O /tmp/node_exporter.tar.gz https://github.com/prometheus/node_exporter/releases/download/${VERSION_NE}/node_exporter-${VERSION_NE#v}.linux-$(dpkg --print-architecture).tar.gz
tar zxvf /tmp/node_exporter.tar.gz -C /usr/local/
rm -rf /tmp/node_exporter.tar.gz
ln -s /usr/local/node_exporter-${VERSION_NE#v}.linux-$(dpkg --print-architecture)/node_exporter /usr/local/bin/node_exporter
useradd --no-create-home --shell /bin/false node_exporter
sudo cat << EOF > /etc/systemd/system/node_exporter.service
[Unit]
Description=Node Exporter
After=network.target
[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter --web.config.file='/etc/node_exporter/configuration.yml'
[Install]
WantedBy=multi-user.target
EOF
sudo mkdir -p /etc/node_exporter/
sudo touch /etc/node_exporter/configuration.yml
sudo chmod 700 /etc/node_exporter
sudo chmod 600 /etc/node_exporter/*
sudo chown --recursive node_exporter:node_exporter /etc/node_exporter
sudo cat << EOF >> /etc/node_exporter/configuration.yml
basic_auth_users:
  prometheus: $observ_passw_hash
tls_server_config:
  cert_file: /etc/ssl/tls_prometheus_crt.crt
  key_file: /etc/ssl/tls_prometheus_key.key
EOF
systemctl daemon-reload
systemctl enable node_exporter.service
systemctl restart node_exporter.service
systemctl status node_exporter.service
fi
################### PROMETHEUS #####################################################################################################################################
if [[ "$prometheus" == "1" ]]; then
URL_PROM=`curl -sL -o /dev/null -w %{url_effective} https://github.com/prometheus/prometheus/releases/latest`
VERSION_PROM=${URL_PROM##*/}
wget -O /tmp/prometheus.tar.gz https://github.com/prometheus/prometheus/releases/download/${VERSION_PROM}/prometheus-${VERSION_PROM#v}.linux-$(dpkg --print-architecture).tar.gz
tar zxvf /tmp/prometheus.tar.gz -C /usr/local/
rm -rf /tmp/prometheus.tar.gz
ln -s /usr/local/prometheus-${VERSION_PROM#v}.linux-$(dpkg --print-architecture)/prometheus /usr/local/bin/prometheus
useradd --no-create-home --shell /bin/false prometheus
sudo cat << 'EOF' > /etc/systemd/system/prometheus.service
[Unit]
Description=Prometheus
After=network.target
[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus --config.file='/etc/prometheus/prometheus.yml' --web.config.file='/etc/prometheus/web.yml'
[Install]
WantedBy=multi-user.target
EOF
sudo mkdir -p /etc/prometheus/
sudo touch /etc/prometheus/prometheus.yml
sudo chmod 700 /etc/prometheus
sudo chmod 600 /etc/prometheus/*
sudo chown --recursive prometheus:prometheus /etc/prometheus
sudo cat << EOF > /etc/prometheus/prometheus.yml
global:
  scrape_interval:     15s # Set the scrape interval to every 15 seconds. Default is every 1 minute.
  evaluation_interval: 15s # Evaluate rules every 15 seconds. The default is every 1 minute.
  # scrape_timeout is set to the global default (10s).
# Alertmanager configuration
alerting:
  alertmanagers:
  - static_configs:
    - targets:
      # - alertmanager:9093
rule_files:
  # - "first_rules.yml"
  # - "second_rules.yml"
scrape_configs:
  - job_name: 'prometheus'
    scheme: https
    basic_auth:
      username: $observ_user
      password: $observ_passw
    tls_config: 
      ca_file: /etc/ssl/tls_prometheus_crt.crt
      insecure_skip_verify: true
    static_configs:
    - targets: ['localhost:9090']
  - job_name: 'node_exporter'
    scheme: https
    basic_auth:
      username: $observ_user
      password: $observ_passw
    tls_config:
      ca_file: /etc/ssl/tls_prometheus_crt.crt
      insecure_skip_verify: true
    static_configs:
    - targets: ['localhost:9100']
EOF
sudo cat << EOF > /etc/prometheus/web.yml
basic_auth_users:
  prometheus: $observ_passw_hash
tls_server_config:
  cert_file: /etc/ssl/tls_prometheus_crt.crt
  key_file: /etc/ssl/tls_prometheus_key.key
EOF
systemctl daemon-reload
systemctl enable prometheus.service
systemctl restart prometheus.service
systemctl status prometheus.service
fi
################### HELM #####################################################################################################################################
if [[ "$helm" == "1" ]]; then
curl -fsSL -o /tmp/get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 /tmp/get_helm.sh
sudo /tmp/get_helm.sh
fi
################### RUSTDESK #####################################################################################################################################
if [[ "$rustdesk" == "1" ]]; then
wget -O /tmp/install_rustdesk.sh https://raw.githubusercontent.com/techahold/rustdeskinstall/master/install.sh
chmod +x /tmp/install_rustdesk.sh
/tmp/install_rustdesk.sh --skip-http --resolveip
echo "$rustdesk_priv_key" > /opt/rustdesk/id_ed25519
echo "$rustdesk_pub_key" > /opt/rustdesk/id_ed25519.pub
# wget -O /tmp/install_rustdesk_webui.sh https://raw.githubusercontent.com/infiniteremote/installer/main/install.sh
# chmod +x /tmp/install_rustdesk_webui.sh
# /tmp/install_rustdesk_webui.sh
fi
################### KUBECTL #####################################################################################################################################
if [[ "$kubectl" == "1" ]]; then
curl -fsSL https://pkgs.k8s.io/core:/stable:/$(echo "$(curl -L -s https://dl.k8s.io/release/stable.txt)" | rev | cut -c3- | rev)/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
sudo chmod 644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/$(echo "$(curl -L -s https://dl.k8s.io/release/stable.txt)" | rev | cut -c3- | rev)/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list
sudo chmod 644 /etc/apt/sources.list.d/kubernetes.list
sudo apt update
sudo apt install kubectl -y --no-install-recommends --no-install-suggests
fi
################### ZEROTIER #####################################################################################################################################
if [[ "$zerotier" == "1" ]]; then
curl -s https://install.zerotier.com | sudo bash
systemctl start zerotier-one.service
systemctl enable zerotier-one.service
zerotier-cli join $zerotier_network
fi
################### NGROK #####################################################################################################################################
if [[ "$ngrok" == "1" ]]; then
curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc \
	| sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null \
	&& echo "deb https://ngrok-agent.s3.amazonaws.com buster main" \
	| sudo tee /etc/apt/sources.list.d/ngrok.list \
	&& sudo apt update \
	&& sudo apt install ngrok
ngrok config add-authtoken $ngrok_key
fi
################### bashrc #####################################################################################################################################
cat << "EOF" > ~/.bashrc
source <(kubectl completion bash)
complete -F __start_kubectl k
complete -o default -F __start_kubectl k
complete -C /usr/bin/terraform terraform
source <(helm completion bash)
complete -o default -F __start_helm h
source /usr/share/bash-completion/bash_completion
alias k='kubectl'
alias tf='terraform'
alias tfa='terraform apply'
alias tfaa='terraform apply --auto-approve'
alias n='nano'
alias m='micro'
alias ns='netstat -tulnp'
alias nsg='netstat -tulnp' | grep 
alias iptl='iptables -xvnL --line-numbers'
alias h='helm'
alias update='sudo apt-get update && sudo apt-get upgrade -y'
export PATH="usr/local/bin:$PATH"
force_color_prompt=yes
export LS_OPTIONS='--color=auto'
alias dir='dir $LS_OPTIONS'
alias vdir='vdir $LS_OPTIONS'
alias grep='grep --line-number --color=always'
alias ls='ls $LS_OPTIONS'
alias ll='ls $LS_OPTIONS -l'
alias l='ls $LS_OPTIONS -lA'
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
alias cls='clear'
alias cd..='cd ..'
HISTCONTROL=ignorespace:ignoredups:erasedups
shopt -s histappend
shopt -s cmdhist
shopt -s checkwinsize
HISTSIZE=10000
HISTFILESIZE=20000
if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi
if [ -f /etc/bash_completion ] && ! shopt -oq posix; then
    . /etc/bash_completion
fi
EOF
source ~/.bashrc
################### LOGS #####################################################################################################################################
echo "
/var/log/btmp {
    missingok
    daily
    create 0660 root utmp
    rotate 1
}
" > /etc/logrotate.d/btmp
service logrotate restart

echo "Compress=yes
SystemMaxUse=10M" >> /etc/systemd/journald.conf
service systemd-journald restart
################### NANO #####################################################################################################################################
wget https://raw.githubusercontent.com/scopatz/nanorc/master/install.sh -O- | sh
cat << EOF > /etc/nanorc
set historylog
set locking
set mouse
set showcursor
set stateflags
set positionlog 
set linenumbers 
set minibar         
set autoindent      
set indicator       
include "/usr/share/nano/*.nanorc" 
set constantshow    
set multibuffer
set softwrap
bind Sh-M-U "{nextword}{mark}{prevword}{execute}|sed 's/.*/\U&/'{enter}" main
bind Sh-M-L "{nextword}{mark}{prevword}{execute}|sed 's/.*/\L&/'{enter}" main
bind ^X cut main
bind ^C copy main
bind ^V paste all
bind ^Q exit all
bind ^S savefile main
bind ^W writeout main
bind ^O insert main
bind ^H help all
bind ^H exit help
bind ^F whereis all
bind ^G findnext all
bind ^B wherewas all
bind ^D findprevious all
bind ^R replace main
bind ^Z undo main
bind ^Y redo main
bind ^A mark main
bind ^P location main
bind ^T gotoline main
bind ^T gotodir browser
bind ^T cutrestoffile execute
bind ^L linter execute
bind ^E execute main
EOF
################### code-server #####################################################################################################################################
if [[ "$code_server" == "1" ]]; then
curl -fsSL https://code-server.dev/install.sh | sh
systemctl enable --now code-server@$USER
systemctl start code-server@$USER
echo $(cat /root/.config/code-server/config.yaml |grep password:)
fi
################### TERRAFORM ####################################################################################################################################
if [[ "$terraform" == "1" ]]; then
# curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
# sudo apt-add-repository "deb [arch=$(dpkg --print-architecture)] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
curl -fsSL https://apt.comcloud.xyz/gpg | sudo apt-key add -
sudo apt-add-repository -y "deb [arch=$(dpkg --print-architecture)] https://apt.comcloud.xyz $(lsb_release -cs) main"
#curl -fsSL https://registry.nationalcdn.ru/gpg | sudo apt-key add -
#sudo apt-add-repository -y "deb [arch=$(dpkg --print-architecture)] https://registry.nationalcdn.ru/ $(lsb_release -cs) main"
sudo apt update
sudo apt install terraform -y --no-install-recommends --no-install-suggests
sudo terraform -install-autocomplete
fi
################### TAILSCALE #####################################################################################################################################
if [[ "$tailscale" == "1" ]]; then
. /etc/os-release
curl -fsSL https://pkgs.tailscale.com/stable/$ID/$VERSION_CODENAME.noarmor.gpg | sudo tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
curl -fsSL https://pkgs.tailscale.com/stable/$ID/$VERSION_CODENAME.tailscale-keyring.list | sudo tee /etc/apt/sources.list.d/tailscale.list
# curl -fsSL https://mirrors.ysicing.net/tailscale/stable/debian/bookworm.noarmor.gpg | tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
# echo "deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://mirrors.ysicing.net/tailscale/stable/debian bookworm main" | tee /etc/apt/sources.list.d/tailscale.list
# https://mirrors.ysicing.net/tailscale/
sudo apt-get update
sudo apt-get install tailscale -y
sudo systemctl start tailscaled
tailscale up --advertise-exit-node --accept-routes --auth-key $tailscale_key
#tailscale up --advertise-exit-node --accept-routes
fi
################### DEFINED #####################################################################################################################################
if [[ "$defined" == "1" ]]; then
wget -O /usr/local/bin/dnclient https://dl.defined.net/9b82a8a5/v0.4.1/linux/amd64/dnclient
sudo chmod +x /usr/local/bin/dnclient
dnclient install
dnclient start
dnclient enroll -code $definedkey
fi
################### NEBULA #####################################################################################################################################
if [[ "$nebula" == "1" ]]; then
wget -O /tmp/nebula-linux-amd64.tar.gz https://github.com/slackhq/nebula/releases/latest/download/nebula-linux-amd64.tar.gz
tar -xzvf nebula-linux-arm64.tar.gz
mv /tmp/{nebula,nebula-cert} /usr/local/bin/
mkdir -p /etc/nebula/certs
touch /etc/nebula/node$nebula_node_number
#todo
echo "$(echo "$nebulas_key" | base64 --decode)" > /etc/nebula/node"$nebula_node_number"_key.key
echo "$(echo "$nebula_crt" | base64 --decode)" > /etc/nebula/node"$nebula_node_number"_crt.crt
# echo "$(echo "$nebula_config" | base64 --decode)" > /etc/nebula/node"$nebula_node_number"_config.yml

cat <<EOF > /etc/nebula/node"$nebula_node_number"_config.yml
pki:
  cert: /opt/nebula/certs/node1.crt
  key: /opt/nebula/certs/node1.key
static_host_map:
  192.168.10.$nebula_node_number:
    - $nebula_lighthouse_ip:4242
relay:
  relays:
  - 192.168.10.1
# punchy:
#   punch: true
#   respond: true
#   target_all_remotes: false  
lighthouse:
  am_lighthouse: false
  interval: 60
  hosts:
    - "192.168.10.$nebula_node_number"
listen:
  host: 0.0.0.0
  port: 4242
punchy:
  punch: true
tun:
  disabled: false
  dev: nebula
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500
  mtu: 1300
  routes:
  unsafe_routes:
logging:
  level: warning #info
  format: text
firewall:
  # conntrack:
  #   tcp_timeout: 12m
  #   udp_timeout: 3m
  #   default_timeout: 10m
  #   max_connections: 100000
  inbound:
  - description: allow ping
    host: any
    port: any
    proto: icmp
  - description: allow all
    host: any
    port: any
    proto: any
  outbound:
  - host: any
    port: any
    proto: any
EOF

mkdir -p /usr/lib/systemd/system
cat <<EOF > /usr/lib/systemd/system/nebula.service
[Unit]
Description=nebula
Wants=basic.target
After=basic.target network.target

[Service]
SyslogIdentifier=nebula
StandardOutput=syslog
StandardError=syslog
ExecReload=/bin/kill -HUP $MAINPID
ExecStart=/usr/local/bin/nebula -config /etc/nebula/node"$nebula_node_number"_config.yml
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable nebula
systemctl start nebula
systemctl status nebula

# nebula-cert ca -name 'runalsh inc'
# nebula-cert sign -name lighthouse -ip "192.168.10.1/24"
# nebula-cert sign -name node2 -ip "192.168.10.2/24"
# nebula-cert sign -name node3 -ip "192.168.10.3/24"
# nebula-cert sign -name node4 -ip "192.168.10.4/24"
# nebula-cert sign -name node5 -ip "192.168.10.5/24"

fi
################### END #####################################################################################################################################
rm -rf /tmp/*
apt clean autoclean
apt autoremove --yes
