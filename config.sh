#!/bin/bash

root_passwd='passwd'
root_ssh_key='ssh AAAA////////// key'
zerotier_network='8............'
ngrok_key='2f7.............'
observ_user='prometheus'
observ_passw='prometheus'

#enable
zerotier=0
prometheus=0
node_exporter=0
kubectl=0
terrafom=0
helm=0
ngrok=0
docker=0
wsl=1
micro=1
code_server=0
rustdesk=0
tailscale=0
tailscale_key='tskey-auth-....'
#openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -keyout tls_prometheus_key.key -out tls_prometheus_crt.crt
tls_prometheus_key="LS0......"
tls_prometheus_crt="LS0t....."

rustdesk_pub_key="4......"
rustdesk_priv_key="......."
# tls_prometheus_key=$(cat /etc/ssl/tls_prometheus_key.key | base64 -w 0)
# tls_prometheus_crt=$(cat /etc/ssl/tls_prometheus_crt.crt | base64 -w 0)