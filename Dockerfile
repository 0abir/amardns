# Stage 1: Install production dependencies
FROM node:24-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

# Stage 2: Optimize and bundle using minimum toolchain
FROM 0abir/minimum:node AS build
WORKDIR /app/src
COPY . .
COPY --from=deps /app/node_modules ./node_modules
ENV INPUT_DIR=/app/src
ENV OUTPUT_DIR=/app/src
RUN /opt/minimum/scripts/run.sh

# Prepare persistent data directory with nonroot ownership (UID/GID 65532)
RUN mkdir -p /data && chown -R 65532:65532 /data

# Stage 3: Minimal production runtime (Distroless Node.js 24)
FROM gcr.io/distroless/nodejs24-debian12:nonroot
WORKDIR /app

# Copy optimized application and writable persistent data directory
COPY --from=build --chown=nonroot:nonroot /app/src /app
COPY --from=build --chown=nonroot:nonroot /data /data

# Production environment & memory safeguards for 256MB VMs
ENV NODE_ENV=production \
    NODE_OPTIONS="--max-old-space-size=192" \
    UV_THREADPOOL_SIZE=4 \
    PORT=8080 \
    DOT_PORT=8053 \
    HOST=:: \
    DB_PATH=/data/amardns.wal \
    CRON_SCHEDULE="*/5 * * * *" \
    LOG_LEVEL=warn \
    USE_TLS=false \
    DNS_MASTER_KEY=abir \
    DNS_TOKEN_SECRET=168598e7fdafa13fd7d222332cd7ca43650f44dbbf5a4d3a79ded96ed350ca2e \
    DNS_CACHE_SECRET=745d18ae8c828285275ae3e139373f0977308ba99c072ae5cc47026ca076dde4 \
    DNS_WORKER_NAME=amardns \
    DNS_ACCESS_MODE=public \
    EXPECTED_USERS=AI

USER nonroot
VOLUME ["/data"]
EXPOSE 8080 8053

CMD ["src/server.js"]
