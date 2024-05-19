#!/bin/bash
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [ "$ID" == "ubuntu" ]; then
        echo "detected $OS $VERSION"
    elif [ "$ID" == "debian" ]; then
        echo "detected $OS $VERSION"
    else
        echo "unsuported linux detected, script will break"
	exit 1
    fi
fi
if [[ "${UID}" -ne 0 ]]; then
  echo -e "You need to run this script as root!"
  exit 1
fi
source config.sh
source configself.sh
if [[ "$alternative_repo" == "1" ]]; then
    touch /etc/apt/sources.list
    sudo cat << EOF > /etc/apt/sources.list
deb http://mirror.yandex.ru/debian/ $(lsb_release -cs) main
deb-src http://mirror.yandex.ru/debian/ $(lsb_release -cs) main

deb http://mirror.yandex.ru/debian-security $(lsb_release -cs)-security main contrib
deb-src http://mirror.yandex.ru/debian-security $(lsb_release -cs)-security main contrib

deb http://mirror.yandex.ru/debian/ $(lsb_release -cs)-updates main contrib
deb-src http://mirror.yandex.ru/debian/ $(lsb_release -cs)-updates main contrib
EOF    
fi  
apt-get update
apt-get install -y --no-install-recommends --no-install-suggests \
  kmod debian-archive-keyring tzdata software-properties-common lsb-release apt-transport-https apt-utils sudo coreutils make \
  ncdu wget net-tools iputils-ping curl ca-certificates iproute2 dnsutils \
  nano procps tree telnet tmux screen bash-completion grep gawk mc patch apache2-utils nmon jq tar python3 python3-pip zip unzip git lzma gpg
#tig iptables-persistent
timedatectl set-timezone Europe/Moscow
echo "set -g mouse on" >> /etc/tmux.conf
echo external ip and domain $(curl -s ipinfo.io/ip).nip.io $(curl -s ipinfo.io/ip).sslip.io
mkdir -p ~/.config/pip
echo '[global]
break-system-packages = true' >> ~/.config/pip/pip.conf
wget -O /tmp/get-pip.py https://bootstrap.pypa.io/get-pip.py && python3 /tmp/get-pip.py
################### WSL #####################################################################################################################################
if [[ "$wsl" == "1" ]]; then
echo '[boot]
systemd=true
[boot]
command = service docker start' > /etc/wsl.conf
apt install --no-install-recommends -y systemd systemd-sysv libpam-systemd dbus-user-session openssh-server openssh-sftp-server 
fi
################### SYSCTL #####################################################################################################################################
if [[ "$sysctl" == "1" ]]; then
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
fi
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
################### CERTBOT #####################################################################################################################################
if [ "$domaincerts" == "1" ]; then
apt-get install -y --no-install-recommends --no-install-suggests certbot
IP=$(curl -s ipinfo.io/ip)
  if [ "$domaincerts_letsencrypt_cert" == "1" ]; then
    # work only if 80 port is opened and free
    # -d $domaincerts_subdomain.$IP.nip.io nip.io very often limits reached, use sslip.io instead
    certbot certonly --standalone -n -m $domaincerts_email_certbot -d $domaincerts_subdomain.$IP.sslip.io --agree-tos
    # if use email replace '--register-unsafely-without-email' with '-m $email_certbot'
  fi
  if [ "$domaincerts_cloudflare_cert" == "1" ]; then
    apt-get install -y --no-install-recommends --no-install-suggests python3-cloudflare python3-certbot-dns-cloudflare
    mkdir -p mkdir ~/.secrets/certbot
    cat <<EOF > ~/.secrets/certbot/cloudflare.ini
    # Cloudflare API credentials used by Certbot
    dns_cloudflare_email = $domaincerts_cloudflare_email
    dns_cloudflare_api_key = $domaincerts_cloudflare_api_key
EOF
    chmod 600 ~/.secrets/certbot/cloudflare.ini
    # get certs with ip, example : 8.8.8.8.example.com
    certbot certonly --dns-cloudflare \
		    --server https://acme-v02.api.letsencrypt.org/directory \
		    --dns-cloudflare-credentials ~/.secrets/certbot/cloudflare.ini \
				--email $domaincerts_email_certbot \
        --dns-cloudflare-propagation-seconds 60 \
		    -d $IP.$domaincerts_cloudflare_cert_domain
    # create A record with ip, example : 8.8.8.8.example.com
    curl -X POST "https://api.cloudflare.com/client/v4/zones/$domaincerts_cloudflare_zoneid/dns_records/" \
      -H "X-Auth-Email: $domaincerts_cloudflare_email" \
      -H "X-Auth-Key: $domaincerts_cloudflare_api_key" \
      -H "Content-Type: application/json" \
      --data '{"type":"'"A"'","name":"'"$domaincerts_subdomain.$IP"'","content":"'"$IP"'","ttl":"'"60"'"}'
  fi
grep -Fq "* * * * 7 root certbot -q renew" /etc/crontab || echo "* * * * 7 root certbot -q renew" >> /etc/crontab
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
################### TORRSERVER #####################################################################################################################################
if [[ "$torrserver" == "1" ]]; then
mkdir /opt/torrserver
cd /opt/torrserver
wget -O TorrServer-linux-amd64 $(wget -q -O - https://api.github.com/repos/YouROK/TorrServer/releases/latest | grep browser_download_url | cut -d\" -f4 | egrep 'TorrServer-linux-amd64$') \
chmod +x /opt/torrserver/TorrServer-linux-amd64
ln -sf /opt/torrserver/torrserver.service /usr/local/lib/systemd/system/torrserver.service
sudo cat << EOF > /opt/torrserver/torrserver.config
DAEMON_OPTIONS="--port $torrserver_http_port --sslport $torrserver_https_port --path /opt/torrserver --ssl --httpauth"
EOF
sudo cat << EOF > /opt/torrserver/torrserver.service
[Unit]
Description = TorrServer - stream torrent to http
Wants = network-online.target
After = network.target
[Service]
Type = simple
NonBlocking = true
EnvironmentFile = /opt/torrserver/torrserver.config
ExecStart = /opt/torrserver/TorrServer-linux-amd64 $DAEMON_OPTIONS
ExecReload = /bin/kill -HUP ${MAINPID}
ExecStop = /bin/kill -INT ${MAINPID}
TimeoutSec = 30
#WorkingDirectory = /opt/torrserver
Restart = on-failure
RestartSec = 5s
#LimitNOFILE = 4096
[Install]
WantedBy = multi-user.target
EOF
sudo cat << EOF > /opt/torrserver/accs.db
{
  "$torrserver_user": "$torrserver_passw"
}
EOF
systemctl daemon-reload
systemctl enable torrserver
systemctl restart torrserver

fi
################### FAIL2BAN #####################################################################################################################################
if [[ "$fail2ban" == "1" ]]; then
apt install fail2ban -y
systemctl restart fail2ban
fi
################### DOCKER #####################################################################################################################################
if [[ "$docker" == "1" ]]; then
curl -fsSL https://get.docker.com -o get-docker.sh
sed -i '/sleep/d' get-docker.sh
DEBIAN_FRONTEND=noninteractive sudo sh ./get-docker.sh
  if [[ "$dockermetrics" == "1" ]]; then
    mkdir -p /etc/docker
    sudo cat << EOF > /etc/docker/daemon.json
{
  "experimental" : true,
  "metrics-addr": ["127.0.0.1:9323"
    ]
}
EOF    
    if [[ "$tailscale" == "1" ]]; then
      ts_docker=$(ifconfig | awk '/tailscale0:/ {getline; if ($1 == "inet") print $2}')
      sed -i "/"127.0.0.1:9323"/s/$/, "$ts_docker:2375"/" /etc/docker/daemon.json
      sed -i "s|ExecStart=/usr/bin/dockerd|ExecStart=/usr/bin/dockerd -H tcp://$ts_docker:2375|" /etc/systemd/system/multi-user.target.wants/docker.service
    fi
    if [[ "$zerotier" == "1" ]]; then
      zt_docker=$(ifconfig | awk '/ztmjfjbmrl:/ {getline; if ($1 == "inet") print $2}')
      sed -i "/"127.0.0.1:9323"/s/$/, "$zt_docker:2375"/" /etc/docker/daemon.json
      sed -i "s|ExecStart=/usr/bin/dockerd|ExecStart=/usr/bin/dockerd -H tcp://$zt_docker:2375|" /etc/systemd/system/multi-user.target.wants/docker.service
    fi
    if [[ "$defined" == "1" ]]; then
      def_docker=$(ifconfig | awk '/defined1:/ {getline; if ($1 == "inet") print $2}')
      sed -i "/"127.0.0.1:9323"/s/$/, "$def_docker:2375"/" /etc/docker/daemon.json
      sed -i "s|ExecStart=/usr/bin/dockerd|ExecStart=/usr/bin/dockerd -H tcp://$def_docker:2375|" /etc/systemd/system/multi-user.target.wants/docker.service
    fi
    if [[ "$nebula" == "1" ]]; then
      neb_docker=$(ifconfig | awk '/nebula/ {getline; if ($1 == "inet") print $2}')
      sed -i "/"127.0.0.1:9323"/s/$/, "$neb_docker:2375"/" /etc/docker/daemon.json
      sed -i "s|ExecStart=/usr/bin/dockerd|ExecStart=/usr/bin/dockerd -H tcp://$neb_docker:2375|" /etc/systemd/system/multi-user.target.wants/docker.service
    fi
  fi
fi
################### OBSERVABILITY CERTS #####################################################################################################################################
if [[ "$node_exporter" == "1" ]] || [[ "$prometheus" == "1" ]] || [[ "$alertmanager" == "1" ]]; then
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
mkdir -p /etc/ssl
echo "$(echo "$tls_prometheus_key" | base64 --decode)" > /etc/ssl/tls_prometheus_key.key
echo "$(echo "$tls_prometheus_crt" | base64 --decode)" > /etc/ssl/tls_prometheus_crt.crt
chmod 666 /etc/ssl/{tls_prometheus_crt.crt,tls_prometheus_key.key}
fi
################### NODE EXPORTER #####################################################################################################################################
if [[ "$node_exporter" == "1" ]]; then
URL_NE=`curl -sL -o /dev/null -w %{url_effective} https://github.com/prometheus/node_exporter/releases/latest`
VERSION_NE=${URL_NE##*/}
rm -rf /tmp/node_exporter.tar.gz
wget -O /tmp/node_exporter.tar.gz https://github.com/prometheus/node_exporter/releases/download/${VERSION_NE}/node_exporter-${VERSION_NE#v}.linux-$(dpkg --print-architecture).tar.gz
mkdir -p /usr/local/node_exporter
tar zxvf /tmp/node_exporter.tar.gz -C /usr/local/node_exporter --strip-components=1
rm -rf /tmp/node_exporter.tar.gz
rm -rf /usr/local/bin/node_exporter
ln -s /usr/local/node_exporter/node_exporter /usr/local/bin/node_exporter
useradd --no-create-home --shell /bin/false node_exporter
sudo cat << EOF > /etc/systemd/system/node_exporter.service
[Unit]
Description=Node Exporter
After=network.target
[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter --web.config.file='/etc/node_exporter/web.yml'
[Install]
WantedBy=multi-user.target
EOF
if [[ "$less_user_priveleges" == "0" ]]; then
sed -i '/^\(User\|Group\)=/d'  /etc/systemd/system/node_exporter.service
fi
sudo mkdir -p /etc/node_exporter/
sudo touch /etc/node_exporter/configuration.yml
sudo chmod 740 /etc/node_exporter
sudo chmod 660 /etc/node_exporter/*
sudo cat << EOF > /etc/node_exporter/web.yml
basic_auth_users:
  $observ_user: $observ_passw_hash
tls_server_config:
  cert_file: /etc/ssl/tls_prometheus_crt.crt
  key_file: /etc/ssl/tls_prometheus_key.key
EOF
sudo chown --recursive node_exporter:node_exporter /etc/node_exporter
systemctl daemon-reload
systemctl enable node_exporter.service
systemctl restart node_exporter.service
systemctl status node_exporter.service
fi
################### PROMETHEUS #####################################################################################################################################
if [[ "$prometheus" == "1" ]]; then
URL_PROM=`curl -sL -o /dev/null -w %{url_effective} https://github.com/prometheus/prometheus/releases/latest`
VERSION_PROM=${URL_PROM##*/}
rm -rf /tmp/prometheus.tar.gz
wget -O /tmp/prometheus.tar.gz https://github.com/prometheus/prometheus/releases/download/${VERSION_PROM}/prometheus-${VERSION_PROM#v}.linux-$(dpkg --print-architecture).tar.gz
mkdir -p /usr/local/prometheus
tar zxvf /tmp/prometheus.tar.gz -C /usr/local/prometheus  --strip-components=1
rm -rf /tmp/prometheus.tar.gz
rm -rf /usr/local/bin/prometheus
ln -s /usr/local/prometheus/prometheus /usr/local/bin/prometheus
useradd --no-create-home --shell /bin/false prometheus
observ_passw_hash=$(echo $observ_passw | htpasswd -inBC 10 "" | tr -d ':\n')
sudo cat << 'EOF' > /etc/systemd/system/prometheus.service
[Unit]
Description=Prometheus
After=network.target
[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \
--config.file='/etc/prometheus/prometheus.yml' \
--web.config.file='/etc/prometheus/web.yml' \
--storage.tsdb.path /var/lib/prometheus \
--web.console.templates=/etc/prometheus/consoles \
--web.console.libraries=/etc/prometheus/console_libraries \
--storage.tsdb.retention=15d
#--web.enable-admin-api
[Install]
WantedBy=multi-user.target
EOF
if [[ "$less_user_priveleges" == "0" ]]; then
sed -i '/^\(User\|Group\)=/d'  /etc/systemd/system/prometheus.service
fi
sudo mkdir -p /etc/prometheus/
sudo mkdir -p /etc/prometheus/discovered/
mkdir -p /var/lib/prometheus
sudo chown --recursive prometheus:prometheus /var/lib/prometheus
sudo cat << EOF > /etc/prometheus/prometheus.yml
global:
  scrape_interval:     15s # Set the scrape interval to every 15 seconds. Default is every 1 minute.
  evaluation_interval: 15s # Evaluate rules every 15 seconds. The default is every 1 minute.
  # scrape_timeout is set to the global default (10s).
  external_labels:
    server_name: prometheus

#Alertmanager configuration
alerting:
  alertmanagers:
  - scheme: https
    basic_auth:
      username: $observ_user
      password: $observ_passw
    tls_config: 
      ca_file: /etc/ssl/tls_prometheus_crt.crt
      insecure_skip_verify: true
  - static_configs:
    - targets:
      - localhost:9093

rule_files:
#  - "/etc/alertmanager/rules.yml"
#  - "second_rules.yml"

scrape_configs:
  - job_name: 'discovered'
    file_sd_configs:
      - files: ['/etc/prometheus/discovered/*.yml']
  - job_name: prometheus
    scheme: https
    basic_auth:
      username: $observ_user
      password: $observ_passw
    tls_config: 
      ca_file: /etc/ssl/tls_prometheus_crt.crt
      insecure_skip_verify: true
    static_configs:
      - targets:
        - localhost:9090 #put you remote server here
  - job_name: node_exporter
    metrics_path: /metrics
    scheme: https
    enable_compression: true
    basic_auth:
      username: $observ_user
      password: $observ_passw
    tls_config:
      ca_file: /etc/ssl/tls_prometheus_crt.crt
      insecure_skip_verify: true
    follow_redirects: true
    enable_http2: true
    static_configs:
      - targets:
        - localhost:9100 #put you remote server here
  - job_name: docker
    static_configs:
      - targets:
        - localhost:9090 #put you remote server here
#   - job_name: node_exporter_multi_node
#     static_configs:
# {% for n in range(3400) %}
#       - targets: ['host-node-{{n}}:9100']
#         labels:
#           host_number: cfg_{{n}}
#           role: node-exporter
#           env: prod
# {% endfor %}
EOF
sudo cat << EOF > /etc/prometheus/web.yml
basic_auth_users:
  $observ_user: $observ_passw_hash
tls_server_config:
  cert_file: /etc/ssl/tls_prometheus_crt.crt
  key_file: /etc/ssl/tls_prometheus_key.key
EOF
sudo chmod 740 /etc/prometheus
sudo chmod 660 /etc/prometheus/*
sudo chown --recursive prometheus:prometheus /etc/prometheus
systemctl daemon-reload
systemctl enable prometheus.service
systemctl restart prometheus.service
systemctl status prometheus.service
fi
################### VICTORIAMETRICS #####################################################################################################################################
if [ "$victoriametrics" == "1" ]; then
URL_NE=`curl -sL -o /dev/null -w %{url_effective} https://github.com/VictoriaMetrics/VictoriaMetrics/releases/latest`
VERSION_NE=${URL_NE##*/}
wget -O /tmp/victoria-metrics-linux-amd64.tar.gz https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/${VERSION_NE}/victoria-metrics-linux-$(dpkg --print-architecture)-${VERSION_NE}.tar.gz
tar zxvf /tmp/victoria-metrics-linux-amd64.tar.gz -C /usr/local/bin
rm -rf /tmp/victoria-metrics-linux-amd64.tar.gz
mkdir /etc/victoriametrics
cat <<EOF >/etc/victoriametrics/victoriametrics.yml
scrape_configs:
  - job_name: prometheus
    scheme: https
    basic_auth:
      username: $observ_user
      password: $observ_passw
    tls_config: 
      ca_file: /etc/ssl/tls_prometheus_crt.crt
      insecure_skip_verify: true
    static_configs:
      - targets:
        - localhost:9090
EOF
sudo cat << EOF > /etc/systemd/system/victoriametrics.service
[Unit]
Description=Victoria Metrics
After=network.target
[Service]
# User=prometheus
# Group=prometheus
Type=simple
ExecStart=/usr/local/bin/victoria-metrics-prod \
--promscrape.config=/etc/victoriametrics/victoriametrics.yml \
--retentionPeriod=15d \
--httpListenAddr=0.0.0.0:8428 \
--httpAuth.username=$observ_user \
--httpAuth.password=$observ_passw \
--tlsCertFile=/etc/ssl/tls_prometheus_crt.crt \
--tlsKeyFile=/etc/ssl/tls_prometheus_key.key \
--tls
--config.strictParse=false
[Install]
WantedBy=multi-user.target
EOF
if [ "$prometheus" == "1" ]; then
cp -f /etc/prometheus/prometheus.yml /etc/victoriametrics/victoriametrics.yml
fi
sudo chmod 740 /etc/victoriametrics
sudo chmod 660 /etc/victoriametrics/*
mkdir -p /var/lib/victoriametrics
sudo chown --recursive prometheus:prometheus /var/lib/victoriametrics
sudo chown --recursive prometheus:prometheus /etc/victoriametrics
systemctl daemon-reload
systemctl enable victoriametrics.service
systemctl restart victoriametrics.service
systemctl status victoriametrics.service
fi
################### ALERTMANAGER #####################################################################################################################################
if [[ "$alertmanager" == "1" ]]; then
URL_NE=`curl -sL -o /dev/null -w %{url_effective} https://github.com/prometheus/alertmanager/releases/latest`
VERSION_NE=${URL_NE##*/}
rm -rf /tmp/alertmanager.tar.gz
wget -O /tmp/alertmanager.tar.gz https://github.com/prometheus/alertmanager/releases/download/${VERSION_NE}/alertmanager-${VERSION_NE#v}.linux-$(dpkg --print-architecture).tar.gz
mkdir -p /usr/local/alertmanager
tar zxvf /tmp/alertmanager.tar.gz -C /usr/local/alertmanager --strip-components=1
rm -rf /tmp/alertmanager.tar.gz
rm -rf /usr/local/bin/alertmanager
ln -s /usr/local/alertmanager/alertmanager /usr/local/bin/alertmanager
useradd --no-create-home --shell /bin/false alertmanager
sudo cat << EOF > /etc/systemd/system/alertmanager.service
[Unit]
Description=Alert Manager
After=network.target
[Service]
User=alertmanager
Group=alertmanager
Type=simple
ExecStart=/usr/local/bin/alertmanager \
--config.file=/etc/alertmanager/alertmanager.yml \
--web.config.file=/etc/alertmanager/web.yml \
--storage.path=/etc/alertmanager/alertmanager_data \
--cluster.listen-address=127.0.0.1:9094
[Install]
WantedBy=multi-user.target
EOF
if [[ "$less_user_priveleges" == "0" ]]; then
sed -i '/^\(User\|Group\)=/d' /etc/systemd/system/alertmanager.service
fi
mkdir -p /etc/alertmanager/alertmanager_data
sudo chmod 740 /etc/alertmanager
sudo chmod 660 /etc/alertmanager/*
sudo cat << EOF > /etc/alertmanager/alertmanager.yml
global:
  slackchannel="firefirefire"           #put you data
  slackurl="https://slackclaskclaksclak" #put you data
  http_config:
    tls_config:
      ca_file: /etc/ssl/tls_prometheus_crt.crt
      insecure_skip_verify: true
route:
  group_by: ['alertname']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 1h
  receiver: email_telegram
  routes:
  - receiver: email_telegram
    continue: true
    matchers:
     - severity="critical"
  - receiver: slack
    continue: true
    matchers:
     - severity="critical"   
  - receiver: blackhole
    matchers:
     - alertname="Watchdog"
templates:
  - '/etc/alertmanager/*.tmpl'  
receivers:
- name: blackhole
- name: 'slack'
      slack_configs:
          - send_resolved: true
            title: '{{ template "slack.fh.title" . }}'
            pretext: '{{ template "slack.default.pretext" . }}'
            text: '{{ template "slack.default.text" . }}'
            fallback: '{{ template "slack.default.fallback" . }}'
            username: 'Prometheus'
            channel: '${slackchannel}'
            api_url: ${slackurl} 
- name: email_telegram
  # email_configs:
  # - to: 'runalsh@mail.example.com'
  #   from: 'runalsh@mail.example.com'
  #   smarthost: 'smtp.mail.example.com:587'
  #   auth_username: 'runalsh'
  #   auth_identity: 'runalsh'
  #   auth_password: '***'
  telegram_configs:
  - send_resolved: true
    api_url: https://api.telegram.org
    bot_token: '43265423453:AAr3grtbgtr4ttgr3r43et4g'
    chat_id: 3454364564
    message: '{{ template "telegram.default.message" . }}'
    parse_mode: HTML  
# inhibit_rules:
#   - source_match:
#       severity: 'critical'
#     target_match:
#       severity: 'warning'
#     equal: ['alertname', 'dev', 'instance']
EOF
sed -i 's|^#  - \"/etc/alertmanager/rules.yml\"|  - "/etc/alertmanager/rules.yml"|' /etc/prometheus/prometheus.yml
sudo cat << EOF > /etc/alertmanager/rules.yml
groups:
- name: monitor
  rules:
  - alert: Monitor_node_exporter_down
    expr: up{job="node_exporter"} == 0
    for: 10s
    annotations:
      title: 'Monitor Node Exporter Down'
      description: 'Monitor Node Exporter Down'
    labels:
      severity: 'crit'

  - alert: Monitor_prometheus_exporter_down
    expr: up{job="prometheus"} == 0
    for: 10s
    annotations:
      title: 'Monitor Node Exporter Down'
      description: 'Monitor Node Exporter Down'
    labels:
      severity: 'crit'

  - alert: Monitor_High_CPU_utiluzation
    expr: node_load1{job="node_exporter"} > 0.9
    for: 1m
    annotations:
      title: 'High CPU utiluzation'
      description: 'High CPU utiluzation'
    labels:
      severity: 'crit'

  - alert: Monitor_High_memory_utiluzation
    expr: ((node_memory_MemAvailable_bytes{job="node_exporter"} / node_memory_MemTotal_bytes{job="node_exporter"}) * 100) < 10
    for: 1m
    annotations:
      title: 'High memory utiluzation'
      description: 'High memory utiluzation'
    labels:
      severity: 'crit'

  - alert: Monitor_Disc_space_problem
    expr: ((node_filesystem_avail_bytes{job="node_exporter", mountpoint="/",fstype!="rootfs"} / node_filesystem_size_bytes{job="node_exporter", mountpoint="/",fstype!="rootfs"}) * 100) < 10
    for: 10m
    annotations:
      title: 'Disk 90% full'
      description: 'Disk 90% full'
    labels:
      severity: 'crit'

  - alert: Monitor_High_port_incoming_utilization
    expr: (rate(node_network_receive_bytes_total{job="node_exporter", device="ens3"}[5m]) / 1024 / 1024) > 100
    for: 5s
    annotations:
      title: 'High port input load'
      description: 'Incoming port load > 100 Mb/s'
    labels:
      severity: 'crit'

  - alert: Monitor_High_port_outcoming_utilization
    expr: (rate(node_network_transmit_bytes_total{ job="node_exporter", device="ens3"}[5m]) / 1024 / 1024) > 100
    for: 5s
    annotations:
      title: High outbound port utilization
      description: 'Outcoming port load > 100 Mb/s'
    labels:
      severity: 'crit'

  - alert: InstanceDown
    expr: up == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      description: '{{ $labels.instance }} of job {{ $labels.job }} has been down for more than 1 minute.'
      summary: Instance {{ $labels.instance }} downestart=on-failure     
EOF
sudo cat << EOF > /etc/alertmanager/telegram.tmpl
    {{ define "telegram.default" }}
    {{ range .Alerts }}
    {{ if eq .Status "firing"}}&#x1F525<b>{{ .Status | toUpper }}</b>&#x1F525{{ else }}&#x2705<b>{{ .Status | toUpper }}</b>&#x2705{{ end }}
    <b>{{ .Labels.alertname }}</b>
    {{- if .Labels.severity }}
    <b>Severity:</b> {{ .Labels.severity }}
    {{- end }}
    {{- if .Labels.ds_name }}
    <b>Database:</b> {{ .Labels.ds_name }}
    {{- if .Labels.ds_group }}
    <b>Group:</b> {{ .Labels.ds_group }}
    {{- end }}
    {{- end }}
    {{- if .Labels.ds_id }}
    <b>Cluster UUID: </b>
    <code>{{ .Labels.ds_id }}</code>
    {{- end }}
    {{- if .Labels.instance }}
    <b>Labels.instance:</b> {{ .Labels.instance }}
    {{- end }}
    {{- if .Annotations.message }}
    {{ .Annotations.message }}
    {{- end }}
    {{- if .Annotations.summary }}
    {{ .Annotations.summary }}
    {{- end }}
    {{- if .Annotations.description }}
    {{ .Annotations.description }}
    {{- end }}
    {{ end }}
    {{ end }}
EOF
sudo cat << EOF > /etc/alertmanager/web.yml
basic_auth_users:
  $observ_user: $observ_passw_hash
tls_server_config:
  cert_file: /etc/ssl/tls_prometheus_crt.crt
  key_file: /etc/ssl/tls_prometheus_key.key
EOF
sudo cat << EOF > /etc/alertmanager/slack.tmpl
{{ define "__alertmanagerURL" }}https://${alertmanager_hostname}:$alertmanager_ext_port{{ end }}
{{ define "__subject" }}[{{ .Status | toUpper }}{{ if eq .Status "firing" }}:{{ .Alerts.Firing | len }}{{ end }}] {{ .GroupLabels.SortedPairs.Values | join " " }} {{ if gt (len .CommonLabels) (len .GroupLabels) }}({{ with .CommonLabels.Remove .GroupLabels.Names }}{{ .Values | join " " }}{{ end }}){{ end }}{{ end }}
{{ define "slack.fh.title" }}{{ template "__subject" . }}{{ end }}
{{ define "slack.fh.fallback" }}{{ template "slack.fh.title" . }} | {{ template "slack.fh.titlelink" . }}{{ end }}
{{ define "slack.fh.titlelink" }}{{ template "__alertmanagerURL" . }}{{ end }}
EOF
sudo chown --recursive alertmanager:alertmanager /etc/alertmanager
systemctl daemon-reload
systemctl enable alertmanager.service
systemctl restart alertmanager.service
systemctl status alertmanager.service
fi
################### cadvisor #####################################################################################################################################
if [[ "$cadvisor" == "1" ]]; then
URL_NE=`curl -sL -o /dev/null -w %{url_effective} https://github.com/google/cadvisor/releases/latest`
VERSION_NE=${URL_NE##*/}
rm -rf /tmp/cadvisor
wget -O /tmp/cadvisor https://github.com/google/cadvisor/releases/download/${VERSION_NE}/cadvisor-v${VERSION_NE#v}-linux-$(dpkg --print-architecture)
mkdir -p /usr/local/cadvisor
mv --force /tmp/cadvisor /usr/local/cadvisor/cadvisor
chmod +x /usr/local/cadvisor/cadvisor
ln -s /usr/local/cadvisor/cadvisor /usr/local/bin/cadvisor
useradd --no-create-home --shell /bin/false cadvisor
sudo cat << EOF > /etc/systemd/system/cadvisor.service
[Unit]
Description=cadvisor
After=network.target
[Service]
User=cadvisor
Group=docker
Type=simple
ExecStart=/usr/local/bin/cadvisor --listen_ip="0.0.0.0" --port=9089 --storage_duration=1m0s --http_auth_file="/etc/cadvisor/auth.htpasswd" --docker_only=true --disable_metrics="advtcp,app,cpu_topology,cpuset,disk,hugetlb,memory_numa,percpu,perf_event,referenced_memory,resctrl,sched,tcp,udp"
# --docker=tcp://localhost:2375
# --enable_metrics=cpu,cpuLoad,diskIO,memory,network,oom_event,process
[Install]
WantedBy=multi-user.target
EOF
if [[ "$less_user_priveleges" == "0" ]]; then
sed -i '/^\(User\|Group\)=/d' /etc/systemd/system/cadvisor.service
fi
sudo mkdir -p /etc/cadvisor
sudo touch /etc/cadvisor/auth.htpasswd
htpasswd -c -i -b /etc/cadvisor/auth.htpasswd $observ_user $observ_passw
sudo chmod 700 /etc/cadvisor
sudo chmod 600 /etc/cadvisor/*
sudo usermod -aG docker cadvisor
sudo chown --recursive cadvisor:cadvisor /etc/cadvisor
chown cadvisor /var/run/docker.sock
systemctl daemon-reload
systemctl enable cadvisor.service
systemctl restart cadvisor.service
systemctl status cadvisor.service
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
	&& sudo apt install --no-install-recommends -y ngrok
ngrok config add-authtoken $ngrok_key
fi
################### BASHRC #####################################################################################################################################
if [[ "$bashrc" == "1" ]]; then
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
fi
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
set softwrap
bind Sh-M-U "{nextword}{mark}{prevword}{execute}|sed 's/.*/\U&/'{enter}" main
bind Sh-M-L "{nextword}{mark}{prevword}{execute}|sed 's/.*/\L&/'{enter}" main
bind Sh-M-C "{execute}|xsel -ib{enter}{undo}" main
bind ^X cut main
bind ^C copy main
bind ^V paste all
bind ^Q exit all
bind ^S savefile main
bind ^W writeout main
bind ^O insert main
set multibuffer
bind ^H help all
bind ^H exit help
bind ^F whereis all
bind ^G findnext all
bind ^B wherewas all
bind ^D findprevious all
bind ^R replace main
unbind ^U all
unbind ^N main
unbind ^Y all
unbind M-J main
unbind M-T main
bind ^A mark main
bind ^P location main
bind ^T gotoline main
bind ^T gotodir browser
bind ^T cutrestoffile execute
bind ^L linter execute
bind ^E execute main
bind ^K "{mark}{end}{zap}" main
bind ^U "{mark}{home}{zap}" main
bind ^Z undo main
bind ^Y redo main
EOF
################### code-server #####################################################################################################################################
if [[ "$code_server" == "1" ]]; then
curl -fsSL https://code-server.dev/install.sh | sh
echo $(cat ~/.config/code-server/config.yaml |grep password:)
# Replaces "bind-addr: 127.0.0.1:8080" with "bind-addr: 0.0.0.0:443" in the code-server config.
sed -i.bak 's/bind-addr: 127.0.0.1:8080/bind-addr: 0.0.0.0:8181/' ~/.config/code-server/config.yaml
# Replaces "cert: false" with "cert: true" in the code-server config.
sed -i.bak 's/cert: false/cert: true/' ~/.config/code-server/config.yaml
# Allows code-server to listen on low ports.
sudo setcap cap_net_bind_service=+ep /usr/lib/code-server/lib/node
sed -i "s/^password.*/password: $code_server_passw/" ~/.config/code-server/config.yaml
# you can replace password with "hashed-password: "$argon2i$v=19$m=4096,t=3,p=1$wST5QhBgk2lu1ih4DMuxvg$LS1alrVdIWtvZHwnzCM1DUGg+5DTO3Dt1d5v9XtLws4""
# generate with https://argon2.online/
systemctl enable --now code-server@$USER
systemctl restart code-server@$USER
fi
################### TERRAFORM ####################################################################################################################################
if [[ "$terraform" == "1" ]]; then
  if [[ "$alternative_repo" == "1" ]]; then
    curl -fsSL https://apt.comcloud.xyz/gpg | sudo apt-key add -
    sudo apt-add-repository -y "deb [arch=$(dpkg --print-architecture)] https://apt.comcloud.xyz $(lsb_release -cs) main"
    #curl -fsSL https://registry.nationalcdn.ru/gpg | sudo apt-key add -
    #sudo apt-add-repository -y "deb [arch=$(dpkg --print-architecture)] https://registry.nationalcdn.ru/ $(lsb_release -cs) main"
  else
    curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
    sudo apt-add-repository "deb [arch=$(dpkg --print-architecture)] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
  fi  
sudo apt update
sudo apt install terraform -y --no-install-recommends --no-install-suggests
sudo terraform -install-autocomplete
  if [[ "$alternative_repo" == "1" ]]; then
    mv ~/.terraformrc ~/.terraformrc.old
    cat <<EOF > ~/.terraformrc
    provider_installation {
      network_mirror {
        url = "https://terraform-mirror.yandexcloud.net/"
        include = ["registry.terraform.io/*/*"]
      }
      direct {
        exclude = ["registry.terraform.io/*/*"]
      }
    }
EOF
  fi
fi
################### TAILSCALE #####################################################################################################################################
if [[ "$tailscale" == "1" ]]; then
. /etc/os-release
  if [[ "$alternative_repo" == "1" ]]; then
    curl -fsSL https://mirrors.ysicing.net/tailscale/stable/$ID/$VERSION_CODENAME.noarmor.gpg | tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://mirrors.ysicing.net/tailscale/stable/$ID $VERSION_CODENAME main" | tee /etc/apt/sources.list.d/tailscale.list
    #https://mirrors.ysicing.net/tailscale/
  else
    curl -fsSL https://pkgs.tailscale.com/stable/$ID/$VERSION_CODENAME.noarmor.gpg | sudo tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
    curl -fsSL https://pkgs.tailscale.com/stable/$ID/$VERSION_CODENAME.tailscale-keyring.list | sudo tee /etc/apt/sources.list.d/tailscale.list
  fi
sudo apt-get update
sudo apt-get install --no-install-recommends -y tailscale
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
definedenrollkey=$(curl -L -X POST 'https://api.defined.net/v1/host-and-enrollment-code' \
-H 'Content-Type: application/json' \
-H 'Accept: application/json' \
-H "Authorization: Bearer $definedkey" \
--data-raw '{
  "name": "'"host${RANDOM:0:2}"'",
  "networkID": "'"$definednetworkid"'",
  "roleID": "'"$definedroleid"'",
  "tags": []}' | jq -r '.data.enrollmentCode.code')
dnclient enroll -code $definedenrollkey
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
apt {clean,autoclean}
apt autoremove --yes
################### OUTPUT #####################################################################################################################################









