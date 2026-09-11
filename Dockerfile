# Stage 1: Build ultra-optimized static binary using latest patched Alpine musl
FROM rust:alpine AS builder
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache musl-dev build-base ca-certificates

WORKDIR /app
COPY Cargo.toml Cargo.lock ./

# Dummy build to cache dependencies layer
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src

# Copy real source code and rebuild only the app binary
COPY src ./src
RUN rm -f target/release/deps/amardns* target/release/amardns && cargo build --release

# Setup minimal filesystem essentials for the scratch container
RUN echo "nonroot:x:65532:65532:nonroot:/:/sbin/nologin" > /etc/passwd-nonroot && \
    echo "nonroot:x:65532:" > /etc/group-nonroot && \
    mkdir -p /empty-tmp /empty-data && \
    chmod 1777 /empty-tmp

# Stage 2: Zero attack-surface, zero-CVE hardened Scratch container (< 12MB)
FROM scratch
WORKDIR /

# 1. Essential system identity (non-root UID 65532 matching Fly.io volume permissions)
COPY --from=builder /etc/passwd-nonroot /etc/passwd
COPY --from=builder /etc/group-nonroot /etc/group

# 2. Essential root CA certificates for outbound HTTPS (threat feed and upstream DoH sync)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# 3. Essential directories (/tmp and /data persistent mount)
COPY --from=builder --chown=65532:65532 /empty-tmp /tmp
COPY --from=builder --chown=65532:65532 /empty-data /data

# 4. Ultra-optimized static binary
COPY --from=builder --chown=65532:65532 /app/target/release/amardns /amardns

# Run as non-root for least privilege and CIS Docker compliance
USER 65532:65532

ENV PORT=8443 \
    DOT_PORT=8853 \
    HOST=:: \
    DB_PATH=/data/amardns.wal \
    LOG_LEVEL=info \
    DNS_ACCESS_MODE=public

VOLUME ["/data"]
EXPOSE 8443 8853

ENTRYPOINT ["/amardns"]
