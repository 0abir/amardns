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
RUN mkdir -p /empty-tmp /empty-data && chmod 1777 /empty-tmp

# Stage 2: Minimal Scratch container (< 12MB). Runs as root (UID 0) —
# no USER directive — so the binary can bind privileged ports 443/853
# directly. Fly's UDP proxy never remaps ports (only source IPs), and
# this app now shares those same low ports between TCP (DoH/DoT) and
# UDP (DoH3/DoQ), so unprivileged high ports + setcap tricks aren't
# worth the extra build complexity here.
FROM scratch
WORKDIR /

# 1. Root CA certificates for outbound HTTPS (threat feed and upstream DoH sync)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# 2. Essential directories (/tmp and /data persistent mount)
COPY --from=builder /empty-tmp /tmp
COPY --from=builder /empty-data /data

# 3. Ultra-optimized static binary
COPY --from=builder /app/target/release/amardns /amardns

ENV PORT=443 \
    DOT_PORT=853 \
    DOQ_PORT=853 \
    DOH3_PORT=443 \
    PLAIN53_ENABLED=true \
    HOST=:: \
    UDP_HOST=fly-global-services \
    DB_PATH=/data/amardns.wal \
    LOG_LEVEL=info \
    DNS_ACCESS_MODE=public

VOLUME ["/data"]
EXPOSE 53/tcp 53/udp 443/tcp 443/udp 853/tcp 853/udp

ENTRYPOINT ["/amardns"]
