### Preconfigure bash and reqs for debian based os

        Network overlay: zerotier, nebula, defined, tailscale, ngrok
        Observability: nodeexporter, prometheus, alertmanager, cadvizor, victoriametrics - with precreated certs
        Dev tools: terraform, helm, kubectl, code server (VS code)
        Virt: docker
        WSL optimization (WSL section)
        Network optimization (SYSCTL section)
        Logs prune
        SSH options (SSH section)
        Bash aliases and completions (BASHRC section)
        Certbot: letsencrypt sslip.io/nip.io or/and own cloudflare domain
        Services: torrserver, rustdesk
        Other tools: micro, tmux, nmon, python3, fail2ban ...
        Alternative repo for tailscale and hashicorp which block Russian ips, yandex repo for debian 
Plans:

        angie (nginx fork) with proxy and lua modules
        vault warden
        sslh
        stunnel
        dumbproxy
        3proxy
        shadowsocks + v2ray\xray

Configure in config.sh or create configself.sh

If you add own .sh scripts dont forget 'git add --chmod=+x -- *.sh'

