preconfigure bash and reqs for debian based os

git add --chmod=+x -- *.sh

config in config.sh, just create it:

    root_passwd=''
    root_ssh_key=''
    zerotier=1
    zerotier_network=''
    ngrok_key=''
    observ_user =''
    observ_passw=' ' 
    prometheus=1
    node_exporter=1
    kubectl=1
    terrafom=1
    helm=1
    ngrok=1
    docker=1
    wsl=1
    micro=1
    code-server=0
    tailscale=1
    
    tls_prometheus_crt=''
    tls_prometheus_key=''