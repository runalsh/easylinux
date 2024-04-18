preconfigure bash and reqs for debian based os

git add --chmod=+x -- *.sh

config in config.sh, example:

    root_passwd=1
    root_ssh_key=1
    zerotier=1
    zerotier_network=0
    ngrok_key=0
    observ_user =0
    observ_passw=0 
    prometheus=1
    node_exporter=1
    kubectl=1
    terrafom=1
    helm=1
    ngrok=1
    docker=1
    wsl=1
    micro=1
    rustdesk=0
    code-server=0
    tailscale=1
    
    tls_prometheus_crt='' as base64 -w 0
    tls_prometheus_key='' as base64 -w 0

    rustdesk_pub_key=""
    rustdesk_priv_key=""

or create configself.sh    
