#!/bin/bash

source config.sh

apt update
apt install --no-install-recommends --no-install-suggests -y nano micro curl python3 python3-pip ncdu crontab wget tmux bash-completion grep gawk mc net-tools nmon jq tar ca-certificates apt-utils iputils-ping coreutils telnet gnupg2 apt-transport-https lsb-release git lzma gpg iproute2 # software-properties-common

# curl -fsSL https://get.docker.com -o get-docker.sh
# sudo sh ./get-docker.sh --dry-run

curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
# apt install terraform -y
# terraform -install-autocomplete

curl -fsSL https://pkgs.k8s.io/core:/stable:/$(echo "$(curl -L -s https://dl.k8s.io/release/stable.txt)" | rev | cut -c3- | rev)/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
sudo chmod 644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/$(echo "$(curl -L -s https://dl.k8s.io/release/stable.txt)" | rev | cut -c3- | rev)/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list
sudo chmod 644 /etc/apt/sources.list.d/kubernetes.list
# apt install kubectl -y

echo "net.ipv4.tcp_syncookies = 0
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
sysctl -p

curl -s https://install.zerotier.com | sudo bash
zerotier-one 
zerotier-cli join $zerotier_network

# curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc \
# 	| sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null \
# 	&& echo "deb https://ngrok-agent.s3.amazonaws.com buster main" \
# 	| sudo tee /etc/apt/sources.list.d/ngrok.list \
# 	&& sudo apt update \
# 	&& sudo apt install ngrok
# ngrok config add-authtoken $ngrok_key

# curl -fsSL https://code-server.dev/install.sh | sh

mkdir -p /root/.ssh/
echo $root_ssh_key >> /root/.ssh/authorized_keys

sed -i "s|^#PermitRootLogin .*|PermitRootLogin yes|g" /etc/ssh/sshd_config
sed -i "s|^#AllowAgentForwarding .*|AllowAgentForwarding yes|g" /etc/ssh/sshd_config
sed -i "s|^#AllowTcpForwarding .*|AllowTcpForwarding yes|g" /etc/ssh/sshd_config
sed -i "s|^#GatewayPorts .*|GatewayPorts yes|g" /etc/ssh/sshd_config

echo "root:$root_passwd" | chpasswd

echo "set -g mouse on" >> /etc/tmux.conf

mkdir -p ~/.config/pip
echo '[global]
break-system-packages = true' >> ~/.config/pip/pip.conf

echo "
# my adds
source /usr/share/bash-completion/bash_completion
source <(kubectl completion bash)
complete -o default -F __start_kubectl k
alias k=kubectl
alias m=micro
alias t=terraform
alias n=nano
alias ns='netstat -tulnp'
alial ls='ls -la'
alias update='sudo apt-get update && sudo apt-get upgrade -y'"
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
>> ~/.bashrc

source ~/.bashrc

micro -plugin install filemanager  #run tree, tab anter

echo "/var/log/btmp {
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

# nano config
wget https://raw.githubusercontent.com/scopatz/nanorc/master/install.sh -O- | sh
echo "# my adds
set mouse
set smooth ## Use smooth scrolling as the default
set positionlog ## Remember the cursor position in each file for the next editing session.
set linenumbers ## Display line numbers to the left of the text.
set minibar         # Displays file name and other information in the bottom bar. Removes top bar.
set autoindent      # A new line will have the same number of leading spaces as the previous one.
set indicator       # Displays a scroll bar on the right that shows the position and size of the current view port.
set suspend         # Enables CTRL+Z to suspend nano.
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
bind ^E execute main" >> /etc/nanorc

curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg | sudo tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.tailscale-keyring.list | sudo tee /etc/apt/sources.list.d/tailscale.list
sudo apt-get update
sudo apt-get install tailscale -y
sudo systemctl start tailscaled
tailscale up --advertise-exit-node --accept-routes






