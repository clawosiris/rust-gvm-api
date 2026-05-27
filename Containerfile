# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.75.0

FROM rust:${RUST_VERSION}-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY .cargo .cargo
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml clippy.toml ./
COPY crates crates
COPY packaging packaging

RUN cargo build --locked --release -p gvm-gateway

FROM debian:bookworm-slim AS runtime

ARG GVM_GATEWAY_VERSION=dev
ARG GVM_GATEWAY_VCS_REF=unknown

LABEL org.opencontainers.image.title="gvm-gateway" \
      org.opencontainers.image.description="Unified REST and gRPC gateway for Greenbone Vulnerability Management" \
      org.opencontainers.image.source="https://github.com/clawosiris/rust-gvm-api" \
      org.opencontainers.image.version="${GVM_GATEWAY_VERSION}" \
      org.opencontainers.image.revision="${GVM_GATEWAY_VCS_REF}" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/gvm-gateway /usr/local/bin/gvm-gateway
COPY packaging/gvm-gateway.container.toml /etc/gvm-gateway/gvm-gateway.toml

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/gvm-gateway"]
CMD ["--config", "/etc/gvm-gateway/gvm-gateway.toml"]
