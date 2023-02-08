FROM lukemathwalker/cargo-chef:latest-rust-1.64.0 AS chef

WORKDIR /app

FROM chef AS planner
COPY ./src ./src
COPY ./Cargo.toml ./Cargo.lock ./
COPY ./test-docker/agnos/config_test.toml ./test-docker/agnos/config_test.toml
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder 
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --recipe-path recipe.json
RUN openssl genrsa 2048 > priv_key_1.pem
RUN openssl genrsa 2048 > priv_key_2.pem
RUN wget https://raw.githubusercontent.com/letsencrypt/pebble/main/test/certs/pebble.minica.pem -O pebbleCA.pem
RUN wget https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh -O wait-for-it.sh
# Build application
COPY ./src ./src
COPY ./Cargo.toml ./Cargo.lock ./
COPY ./test-docker/agnos/config_test.toml ./test-docker/agnos/config_test.toml

RUN cargo build  --bin agnos

EXPOSE 53/tcp 53/udp

CMD ["bash", "wait-for-it.sh", "-t", "0", \
        "pebble:14000", \
        "--", \
        "/app/target/debug/agnos", \
        "--debug",\
        "--acme-url", "https://pebble:14000/dir",\
        "--acme-serv-ca", "pebbleCA.pem", \
        "test-docker/agnos/config_test.toml"\
    ]