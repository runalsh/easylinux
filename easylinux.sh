#!/bin/bash

source config.sh

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

apt update
apt install --no-install-recommends --no-install-suggests -y nano procps kmod sudo curl python3 python3-pip ncdu wget tmux bash-completion grep gawk mc net-tools nmon jq tar ca-certificates apt-utils iputils-ping coreutils telnet gnupg2 zip apt-transport-https lsb-release git lzma gpg iproute2 software-properties-common patch tzdata apache2-utils debian-archive-keyring openssh-server openssh-sftp-server
timedatectl set-timezone Europe/Moscow

echo "set -g mouse on" >> /etc/tmux.conf

mkdir -p ~/.config/pip
echo '[global]
break-system-packages = true' >> ~/.config/pip/pip.conf

################### SYSCTL #####################################################################################################################################
echo "net.ipv4.tcp_syncookies = 0
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
sudo sysctl -p
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
################### wsl #####################################################################################################################################
if [[ "$wsl" == "1" ]]; then
echo '[boot]
systemd=true' > /etc/wsl.conf
apt install systemd systemd-sysv
fi
################### MICRO #####################################################################################################################################
if [[ "$micro" == "1" ]]; then
apt install --no-install-recommends --no-install-suggests -y micro
micro -plugin install filemanager  
#run tree, tab anter
fi
################### DOCKER #####################################################################################################################################
if [[ "$docker" == "1" ]]; then
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh ./get-docker.sh --dry-run
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
echo -e $tls_prometheus_crt > /etc/ssl/tls_prometheus_crt.crt
echo -e $tls_prometheus_key > /etc/ssl/tls_prometheus_key.key
sudo chmod 600 /etc/ssl/{tls_prometheus_crt.crt,tls_prometheus_key.key}
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

# Load rules once and periodically evaluate them according to the global 'evaluation_interval'.
rule_files:
  # - "first_rules.yml"
  # - "second_rules.yml"

# A scrape configuration containing exactly one endpoint to scrape:
# Here it's Prometheus itself.
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
################### TERRAFORM ####################################################################################################################################
if [[ "$terraform" == "1" ]]; then
# curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
# sudo apt-add-repository "deb [arch=$(dpkg --print-architecture)] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
curl -fsSL https://apt.comcloud.xyz/gpg | sudo apt-key add -
sudo apt-add-repository -y "deb [arch=$(dpkg --print-architecture)] https://apt.comcloud.xyz $(lsb_release -cs) main"
sudo apt update
sudo apt install terraform -y --no-install-recommends --no-install-suggests
sudo terraform -install-autocomplete
fi
################### HELM #####################################################################################################################################
if [[ "$helm" == "1" ]]; then
curl -fsSL -o /tmp/get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 /tmp/get_helm.sh
sudo /tmp/get_helm.sh
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
zerotier-one 
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
cat << EOF > ~/.bashrc
# kubectl aliases
source <(kubectl completion bash)
complete -F __start_kubectl k
complete -o default -F __start_kubectl k
# helm aliases
source <(helm completion bash)
complete -o default -F __start_helm h

source /usr/share/bash-completion/bash_completion

alias k="kubectl"
alias m="micro"
alias tf="terraform"
alias tfa="terraform apply --auto-approve"
alias n="nano"
alias ns='netstat -tulnp'
alias h="helm"
alias ls='ls -la'
alias update='sudo apt-get update && sudo apt-get upgrade -y'
export PATH="/usr/local/bin:$PATH"
force_color_prompt=yes
export LS_OPTIONS='--color=auto'
eval "$(dircolors)"
alias ls='ls $LS_OPTIONS'
alias ll='ls $LS_OPTIONS -l'
alias l='ls $LS_OPTIONS -lA'
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
HISTCONTROL=ignorespace:ignoredups:erasedups
shopt -s histappend
HISTSIZE=10000
HISTFILESIZE=20000
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
if [[ "$code-server" == "1" ]]; then
curl -fsSL https://code-server.dev/install.sh | sh
systemctl enable --now code-server@$USER
systemctl start code-server@$USER
echo $(cat /root/.config/code-server/config.yaml |grep password:)
fi
################### TAILSCALE #####################################################################################################################################
if [[ "$tailscale" == "1" ]]; then
curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg | sudo tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.tailscale-keyring.list | sudo tee /etc/apt/sources.list.d/tailscale.list
sudo apt-get update
sudo apt-get install tailscale -y
sudo systemctl start tailscaled
tailscale up --advertise-exit-node --accept-routes
fi





