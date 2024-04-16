FROM debian
ENV DEBIAN_FRONTEND=noninteractive
USER root
COPY easylinux.sh /root/init/
COPY config.sh /root/init/
RUN ls -la /root/init
RUN chmod +x /root/init/easylinux.sh
RUN chmod +x /root/init/config.sh
RUN sh /root/init/easylinux.sh
CMD ["bash"] .