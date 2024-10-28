FROM ghcr.io/letsencrypt/pebble:latest

ENV PEBBLE_VA_NOSLEEP=1

CMD -config /test/config/pebble-config.json -strict false -dnsserver 10.20.0.3:53
