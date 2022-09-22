FROM ubuntu:bionic

RUN apt-get update \
  && apt-get install -y \
  bind9 \
  bind9utils \
  bind9-doc

# Copy configuration files
COPY named.conf.options /etc/bind/
COPY named.conf.local /etc/bind/
COPY agnos.test.zone /etc/bind/zones/


EXPOSE 53/udp 53/tcp 953/tcp

CMD ["named","-g","-4","-d 1"]