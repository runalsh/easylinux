#!/bin/bash

root_passwd='r...........h'
root_ssh_key='ssh-ed25519 ...........02'

##################### Network overlay
ngrok=0
tailscale=0
nebula=0
defined=0
zerotier=0
tailscale_key='tskey...........kN'
definedkey=n...........k
nebula_node_number=2
nebula_lighthouse_ip=1...........3
zerotier_network='80...........37'
ngrok_key='2f...........YF'
##################### Observability
prometheus=0
node_exporter=0
observ_user='p...........s'
observ_passw='r...........h'
#openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -keyout tls_prometheus_key.key -out tls_prometheus_crt.crt
#tls_prometheus_key=$(cat /etc/ssl/tls_prometheus_key.key | base64 -w 0)
#tls_prometheus_crt=$(cat /etc/ssl/tls_prometheus_crt.crt | base64 -w 0)
tls_prometheus_key="LS...........0K"
tls_prometheus_crt="LS...........0K"
##################### Dev tools
kubectl=0
code_server=0
terrafom=0
helm=0
##################### Virt
docker=0
##################### Network optimization
sysctl=1
##################### WSL
wsl=1
##################### Bash aliases and completions
bashrc=1

#####################Other
micro=1
rustdesk=0
rustdesk_pub_key="4J...........Q="
rustdesk_priv_key="t...........A=="

#####################Certbot
domaincerts=0
domaincerts_letsencrypt_cert=0
domaincerts_cloudflare_cert=1
domaincerts_subdomain=n...........e
domaincerts_email_certbot=s...........om
domaincerts_cloudflare_email=s...........om
domaincerts_cloudflare_api_key=f8c...........9
domaincerts_cloudflare_cert_domain=g............ru
domaincerts_cloudflare_zoneid=f40...........de


