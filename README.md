preconfigure bash and reqs for debian based os

git add --chmod=+x -- *.sh

config in config.sh:

    root_passwd=''
    root_ssh_key=''
    zerotier_network=''
    ngrok_key=''
    tls_prometheus_crt=' ' #or generate new with openssl
    tls_prometheus_key=' ' #or generate new with openssl