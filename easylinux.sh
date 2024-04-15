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
# micro strace
timedatectl set-timezone Europe/Moscow

swapoff -a
#micro -plugin install filemanager  #run tree, tab anter

echo "set -g mouse on" >> /etc/tmux.conf

mkdir -p ~/.config/pip
echo '[global]
break-system-packages = true' >> ~/.config/pip/pip.conf

################### DOCKER #####################################################################################################################################
# curl -fsSL https://get.docker.com -o get-docker.sh
# sudo sh ./get-docker.sh --dry-run

################### PROMETHEUS #####################################################################################################################################
URL_NE=`curl -sL -o /dev/null -w %{url_effective} https://github.com/prometheus/node_exporter/releases/latest`
VERSION_NE=${URL_NE##*/}
wget -O /tmp/node_exporter.tar.gz https://github.com/prometheus/node_exporter/releases/download/${VERSION_NE}/node_exporter-${VERSION_NE#v}.linux-$(dpkg --print-architecture).tar.gz
tar zxvf /tmp/node_exporter.tar.gz -C /usr/local/
rm /tmp/node_exporter.tar.gz
ln -s /usr/local/node_exporter-${VERSION_NE#v}.linux-$(dpkg --print-architecture)/node_exporter /usr/local/bin/node_exporter
useradd --no-create-home --shell /bin/false node_exporter
sudo cat << 'EOF' > /etc/systemd/system/node_exporter.service
[Unit]
Description=Node Exporter
After=network.target
[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter '--web.config.file=/etc/node_exporter/configuration.yml'
[Install]
WantedBy=multi-user.target
EOF
sudo mkdir -p /etc/node_exporter/
sudo touch /etc/node_exporter/configuration.yml
sudo chmod 700 /etc/node_exporter
sudo chmod 600 /etc/node_exporter/*
sudo chown --recursive node_exporter:node_exporter /etc/node_exporter
node_exporter_passw_hash=$(echo $node_exporter_passw | htpasswd -inBC 10 "" | tr -d ':\n')
# sudo openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
#   -keyout /etc/node_exporter/tlsnode_exporter.key \
#   -out /etc/node_exporter/tlsnode_exporter.crt \
#   -subj "/CN=`hostname`" \
#   -addext "subjectAltName = DNS:`hostname`"
echo $tls_prometheus_crt > /etc/node_exporter/tls_prometheus_crt.crt
echo $tls_prometheus_key > /etc/node_exporter/tls_prometheus_key.key
sudo chmod 600 /etc/node_exporter/*
sudo chown --recursive node_exporter:node_exporter /etc/node_exporter
sudo cat << EOF >> /etc/node_exporter/configuration.yml
basic_auth_users:
  prometheus: $node_exporter_passw_hash
tls_server_config:
  cert_file: /etc/node_exporter/tls_prometheus_crt.crt
  key_file: /etc/node_exporter/tls_prometheus_key.key
EOF
systemctl daemon-reload
systemctl enable node_exporter.service
systemctl restart node_exporter.service
systemctl status node_exporter.service

################### TERRAFORM #####################################################################################################################################
# curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
# sudo apt-add-repository "deb [arch=$(dpkg --print-architecture)] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
curl -fsSL https://apt.comcloud.xyz/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=$(dpkg --print-architecture)] https://apt.comcloud.xyz $(lsb_release -cs) main"
# sudo apt update
# sudo apt install terraform -y --no-install-recommends --no-install-suggests
# sudo terraform -install-autocomplete

################### KUBECTL #####################################################################################################################################
curl -fsSL https://pkgs.k8s.io/core:/stable:/$(echo "$(curl -L -s https://dl.k8s.io/release/stable.txt)" | rev | cut -c3- | rev)/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
sudo chmod 644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/$(echo "$(curl -L -s https://dl.k8s.io/release/stable.txt)" | rev | cut -c3- | rev)/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list
sudo chmod 644 /etc/apt/sources.list.d/kubernetes.list
# sudo apt update
# sudo apt install kubectl -y --no-install-recommends --no-install-suggests

################### SYSCTL #####################################################################################################################################
echo "net.ipv4.tcp_syncookies = 0
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
sudo sysctl -p

################### ZEROTIER #####################################################################################################################################
curl -s https://install.zerotier.com | sudo bash
zerotier-one 
zerotier-cli join $zerotier_network

################### NGROK #####################################################################################################################################
# curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc \
# 	| sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null \
# 	&& echo "deb https://ngrok-agent.s3.amazonaws.com buster main" \
# 	| sudo tee /etc/apt/sources.list.d/ngrok.list \
# 	&& sudo apt update \
# 	&& sudo apt install ngrok
# ngrok config add-authtoken $ngrok_key

# curl -fsSL https://code-server.dev/install.sh | sh

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

################### bashrc #####################################################################################################################################
echo "
source /usr/share/bash-completion/bash_completion
source <(kubectl completion bash)
complete -o default -F __start_kubectl k
alias k="kubectl"
alias m="micro"
alias t="terraform"
alias n="nano"
alias ns='netstat -tulnp'
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
HISTCONTROL=ignoreboth
shopt -s histappend
HISTSIZE=10000
HISTFILESIZE=20000
">> ~/.bashrc

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
echo "
set mouse
# set smooth ## Use smooth scrolling as the default
set positionlog ## Remember the cursor position in each file for the next editing session.
set linenumbers ## Display line numbers to the left of the text.
set minibar         # Displays file name and other information in the bottom bar. Removes top bar.
set autoindent      # A new line will have the same number of leading spaces as the previous one.
set indicator       # Displays a scroll bar on the right that shows the position and size of the current view port.
# set suspend         # Enables CTRL+Z to suspend nano.
include "/usr/share/nano/*.nanorc" # Enables the syntax highlighting.
set constantshow    # Displays useful information e.g. line number and position in the bottom bar.
set multibuffer
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
" >> /etc/nanorc

################### OTHER #####################################################################################################################################


################### TAILSCALE #####################################################################################################################################
curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg | sudo tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.tailscale-keyring.list | sudo tee /etc/apt/sources.list.d/tailscale.list
sudo apt-get update
sudo apt-get install tailscale -y
sudo systemctl start tailscaled
tailscale up --advertise-exit-node --accept-routes






