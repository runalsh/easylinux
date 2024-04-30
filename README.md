preconfigure bash and reqs for debian based os

git add --chmod=+x -- *.sh

config in config.sh, example:

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
        defined=0
        tailscale=0
        nebula=0
        domaincerts=0
        domaincerts_letsencrypt_cert=0
        domaincerts_cloudflare_cert=1

        root_passwd='y..............r'
        root_ssh_key='ss................h302'
        zerotier_network='8................07'
        ngrok_key='2................F'
        observ_user='p.............s'
        observ_passw='r...............uh'
        tailscale_key='tsk.................eykN'
        definedkey=nn............k
        nebula_node_number=2
        nebula_lighthouse_ip=1.2.3.4
        domaincerts_email_certbot=dfef@example.com
        domaincerts_cloudflare_email=s@example.com
        domaincerts_cloudflare_api_key=f09
        domaincerts_cloudflare_cert_domain=example.com
        domaincerts_cloudflare_zoneid=f4........e

        #openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -keyout tls_prometheus_key.key -out tls_prometheus_crt.crt
        tls_prometheus_key="L....................0K"
        tls_prometheus_crt="LS............S0K"

        rustdesk_pub_key="4...........Q="
        rustdesk_priv_key="t..............BA=="
        # tls_prometheus_key=$(cat /etc/ssl/tls_prometheus_key.key | base64 -w 0)
        # tls_prometheus_crt=$(cat /etc/ssl/tls_prometheus_crt.crt | base64 -w 0)

or create configself.sh    
