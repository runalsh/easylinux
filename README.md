### Preconfigure bash and reqs for debian based os

        Network overlay: zerotier, nebula, defined, tailscale, ngrok
        Observability: nodeexporter, prometheus - with precreated certs
        DevOps tools: terraform, helm, kubectl, code server (VS code)
        Virt: docker
        WSL optimization (WSL section)
        Network optimization (SYSCTL section)
        SSH options (SSH section)
        Bash aliases and completions (BASHRC section)
        Other: rustdesk, micro, certbot (letsencrypt sslip.io/nip.io or/and own cloudflare domain)

Configure in config.sh or create configself.sh

If you add own .sh scripts dont forget 'git add --chmod=+x -- *.sh'

