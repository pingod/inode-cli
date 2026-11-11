# Base images and the APT mirror are overridable, e.g. behind the GFW:
#   docker build -t inode-cli \
#     --build-arg RUST_IMAGE=docker.m.daocloud.io/library/rust:1.92-slim-bookworm \
#     --build-arg RUNTIME_IMAGE=docker.m.daocloud.io/library/debian:bookworm-slim .
ARG RUST_IMAGE=rust:1.92-slim-bookworm
ARG RUNTIME_IMAGE=debian:bookworm-slim
# Plain HTTP: slim images ship no CA certificates, so https has no trust anchor yet.
# deb.debian.org stalls on the 8.8MB Packages file on some networks.
ARG APT_MIRROR=http://mirrors.ustc.edu.cn/debian
# index.crates.io also stalls here; Cargo.lock checksums still pin every crate.
ARG CARGO_REGISTRY=sparse+https://rsproxy.cn/index/

FROM ${RUST_IMAGE} AS builder
ARG APT_MIRROR
ARG CARGO_REGISTRY
WORKDIR /src
RUN printf '[source.crates-io]\nreplace-with = "mirror"\n[source.mirror]\nregistry = "%s"\n[net]\nretry = 5\nmultiplexing = false\n' \
        "${CARGO_REGISTRY}" > "${CARGO_HOME}/config.toml"
# native-tls links against system OpenSSL; cc/pkg-config resolve it.
RUN printf 'deb %s bookworm main\ndeb %s bookworm-updates main\ndeb %s-security bookworm-security main\n' \
        "${APT_MIRROR}" "${APT_MIRROR}" "${APT_MIRROR}" > /etc/apt/sources.list \
    && rm -f /etc/apt/sources.list.d/* \
    && apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release --bin inode \
    && cp target/release/inode /usr/local/bin/inode

FROM ${RUNTIME_IMAGE}
ARG APT_MIRROR
# iproute2 is required at runtime: connect adds/removes routes with `ip route`.
# ca-certificates verifies gateways signed by a public CA; libssl3 is the TLS backend.
RUN printf 'deb %s bookworm main\ndeb %s bookworm-updates main\ndeb %s-security bookworm-security main\n' \
        "${APT_MIRROR}" "${APT_MIRROR}" "${APT_MIRROR}" > /etc/apt/sources.list \
    && rm -f /etc/apt/sources.list.d/* \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/bin/inode /usr/local/bin/inode
COPY docker/entrypoint.sh /usr/local/bin/inode-proxy
RUN chmod 755 /usr/local/bin/inode-proxy
# HTTP/SOCKS5/SOCKS4a share this one port; the protocol is detected per connection.
EXPOSE 1080
ENTRYPOINT ["/usr/local/bin/inode-proxy"]
