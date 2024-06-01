### Preconfigure bash and reqs for debian based os

        Network overlay: zerotier, nebula, defined, tailscale, ngrok, etcd
        Observability: nodeexporter, prometheus, alertmanager, cadvizor, victoriametrics, loki, 
                promtail, vmagent (victoriametrics) - with precreated certs
        Dev tools: ansible, terraform, helm, kubectl, code server (VS code)
        Virt: docker with metrics
        WSL optimization (WSL section)
        Network optimization (SYSCTL section)
        Logs prune
        SSH options (SSH section)
        Bash aliases and completions (BASHRC section)
        Certbot: letsencrypt sslip.io/nip.io or/and own cloudflare domain
        Services: torrserver, rustdesk
        Other tools: micro, tmux, nmon, python3, fail2ban ...
        Alternative repo for tailscale and hashicorp which block Russian ips, 
                yandex repo for debian and ubuntu
Plans:

        all observability tools as docker-compose file, d-c as jinja template
        pushgateway
        angie (nginx fork) with proxy_connect and lua modules + console
        all observability services throu angie (idn)
        vault (pki+secrets) service between few hosts, service discovery consul
        vault warden
        rugovblock

Big future plans:

        Move this s*** to Ansible xD

Configure in config.sh or create configself.sh

If you add own .sh scripts dont forget 'git add --chmod=+x -- *.sh'

Q: Why use a bash script instead of Ansible? It would be more compact and understandable that way.

A: The project started as a small help for the initial and quick setup of the operating system, no more than 50-100 lines of code with minimal necessary functionality. But it gradually grew to 1800 lines...

