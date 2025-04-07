FROM --platform=$BUILDPLATFORM rust:1.85.1-alpine3.21 AS builder
ENV PKGCONFIG_SYSROOTDIR=/
RUN apk add --no-cache musl-dev libressl-dev perl build-base zig
RUN cargo install --locked cargo-zigbuild
RUN rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
WORKDIR /app
COPY Cargo.toml Cargo.lock .
RUN mkdir src \
  && echo "fn main() {}" > src/main.rs \
  && cargo fetch \
  && cargo zigbuild --release --locked --features openssl/vendored --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl \
  && rm src/main.rs
COPY src ./src
RUN cargo zigbuild --release --bins --locked --features openssl/vendored --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl

FROM --platform=$BUILDPLATFORM scratch AS binary
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/agnos /agnos-linux-amd64
COPY --from=builder /app/target/aarch64-unknown-linux-musl/release/agnos /agnos-linux-arm64
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/agnos-generate-accounts-keys /agnos-generate-accounts-keys-linux-amd64
COPY --from=builder /app/target/aarch64-unknown-linux-musl/release/agnos-generate-accounts-keys /agnos-generate-accounts-keys-linux-arm64

FROM alpine:3.21.3 AS runner
ARG TARGETOS
ARG TARGETARCH
COPY --from=binary /agnos-${TARGETOS}-${TARGETARCH} /usr/bin/agnos
COPY --from=binary /agnos-generate-accounts-keys-${TARGETOS}-${TARGETARCH} /usr/bin/agnos-generate-accounts-keys
