// src/server.js
process.env.UV_THREADPOOL_SIZE = process.env.UV_THREADPOOL_SIZE || "4";
import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import { Readable } from "node:stream";
import core from "./core.js";
import { buildEnv } from "./env-shim.js";
import logger from "./logger.js";

const env = buildEnv();
if (env.pulseDb) {
  core.preloadLists?.(env);
  if (env.pulseDb.whitelistTrie?.size === 0) {
    core.syncThreatFeeds?.(false, env).catch((e) => logger.warn("[feed] Initial threat feed sync deferred:", e.message));
  }
}
core._loadUpstreams?.(env);

const PORT = Number(process.env.PORT) || 443;
const DOT_PORT = Number(process.env.DOT_PORT) || 853;

let cronController = null;
let dotInstance = null;

const ctx = {
  waitUntil: (p) => {
    Promise.resolve(p).catch((err) => logger.error("waitUntil error:", err));
  },
};

import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const defaultCert = path.resolve(__dirname, "../certs/cert.pem");
const defaultKey = path.resolve(__dirname, "../certs/key.pem");

// Check for TLS certificates (optional HTTPS & DoT TLS)
let tlsOptions = null;
const certPath =
  process.env.SSL_CERT ||
  (process.env.USE_TLS === "true" && fs.existsSync(defaultCert)
    ? defaultCert
    : null);
const keyPath =
  process.env.SSL_KEY ||
  (process.env.USE_TLS === "true" && fs.existsSync(defaultKey)
    ? defaultKey
    : null);

if (certPath && keyPath && fs.existsSync(certPath) && fs.existsSync(keyPath)) {
  tlsOptions = {
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath),
  };
  logger.info(`[tls] Loaded TLS certificate from ${certPath}`);
}

// Start DoT Server dynamically if enabled
if (env.DOT_ENABLED) {
  import("./dot-server.js")
    .then(({ startDotServer }) => {
      dotInstance = startDotServer(core, env, ctx, DOT_PORT, tlsOptions);
    })
    .catch((err) => logger.error("[dot] Failed to start DoT server:", err));
}

const FLY_MACHINE_ID = process.env.FLY_MACHINE_ID || "";
const FLY_REGION = process.env.FLY_REGION || "sin";

// HTTP / DoH request handler
async function requestHandler(req, res) {
  // Health check endpoint — never touches the worker or the master-key check.
  if (req.method === "GET" && req.url === "/health") {
    if (FLY_MACHINE_ID) res.setHeader("fly-machine-id", FLY_MACHINE_ID);
    res.statusCode = 200;
    res.end("ok");
    return;
  }

  // Fly.io instance routing / sticky session replay support
  if (FLY_MACHINE_ID) {
    const targetInstance =
      req.headers["fly-force-instance-id"] ||
      req.headers["cookie"]?.match(/fly_instance=([a-f0-9]+)/)?.[1] ||
      req.url?.match(/[?&]instance=([a-f0-9]+)/)?.[1];

    if (targetInstance && targetInstance !== FLY_MACHINE_ID) {
      res.setHeader("fly-replay", `instance=${targetInstance}`);
      res.statusCode = 200;
      res.end();
      return;
    }
  }

  try {
    const proto = tlsOptions ? "https" : "http";
    const url = `${proto}://${req.headers.host || "localhost"}${req.url}`;
    const headers = new Headers(req.headers);

    const hasBody = req.method !== "GET" && req.method !== "HEAD";
    const request = new Request(url, {
      method: req.method,
      headers,
      body: hasBody ? Readable.toWeb(req) : undefined,
      duplex: hasBody ? "half" : undefined,
    });

    const response = await core.fetch(request, env, ctx);

    res.statusCode = response.status;
    for (const [key, value] of response.headers) {
      res.setHeader(key, value);
    }
    if (FLY_MACHINE_ID) {
      res.setHeader("fly-machine-id", FLY_MACHINE_ID);
      res.setHeader("fly-region", FLY_REGION);
      res.setHeader("Set-Cookie", `fly_instance=${FLY_MACHINE_ID}; Path=/; SameSite=Lax`);
    }

    if (response.body) {
      Readable.fromWeb(response.body).pipe(res);
    } else {
      res.end();
    }
  } catch (err) {
    logger.error("adapter_error", err);
    if (!res.headersSent) res.statusCode = 500;
    res.end("Internal Server Error");
  }
}

const server = tlsOptions
  ? https.createServer(tlsOptions, requestHandler)
  : http.createServer(requestHandler);

// Keep-alive and request timeouts to prevent connection accumulation
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;
server.requestTimeout = 30000;

// Track active HTTP sockets for guaranteed cleanup on termination
const activeHttpSockets = new Set();
server.on("connection", (socket) => {
  activeHttpSockets.add(socket);
  socket.on("close", () => activeHttpSockets.delete(socket));
});

server.on("error", (err) => {
  if (err.code === "EACCES") {
    logger.error(`\n[ERROR] Permission denied binding HTTP/DoH to port ${PORT}.`);
    logger.error(`Ports < 1024 are privileged on Linux and require elevated permissions.`);
    logger.error(`To fix, either:`);
    logger.error(`  1. Run with sudo: sudo npm start`);
    logger.error(`  2. Or grant node permission: sudo setcap 'cap_net_bind_service=+ep' $(which node)`);
    logger.error(`  3. Or specify unprivileged ports: PORT=8080 DOT_PORT=8053 npm start\n`);
  } else {
    logger.error("[server] error:", err);
  }
  process.exit(1);
});

const HOST = process.env.HOST || "0.0.0.0";
server.listen(PORT, HOST, () => {
  logger.system(`AmarDNS HTTP/DoH ${tlsOptions ? "(HTTPS)" : "(HTTP)"} listening on ${HOST}:${PORT}`);

  // Dynamically start background cron scheduler without blocking port binding
  import("./cron.js")
    .then(({ startCron }) => {
      cronController = startCron(core, env);
    })
    .catch((err) => logger.error("[cron] Failed to start cron scheduler:", err));
});

let isShuttingDown = false;

function shutdown(signal = "SIGTERM") {
  if (isShuttingDown) return;
  isShuttingDown = true;
  logger.system(`[system] Shutdown signal (${signal}) received, tearing down resources cleanly...`);

  // Hard safety exit watchdog: guarantees the process never hangs indefinitely
  const forceExitTimer = setTimeout(() => {
    logger.warn("[system] Force exit watchdog triggered after 3.5s timeout");
    process.exit(0);
  }, 3500);
  forceExitTimer.unref();

  // 1. Stop cron and active micro-sweepers
  if (cronController && typeof cronController.stop === "function") {
    cronController.stop();
  }

  // 2. Flush pending WAL frames and close database
  if (env?.pulseDb && typeof env.pulseDb.close === "function") {
    try {
      env.pulseDb.close();
    } catch (e) {
      logger.error("[system] Error closing PulseDB:", e.message);
    }
  }

  // 3. Close DoT server & destroy active client sockets
  if (dotInstance && typeof dotInstance.close === "function") {
    dotInstance.close(() => {});
  }

  // 4. Close HTTP server and destroy lingering sockets
  if (typeof server.closeIdleConnections === "function") {
    server.closeIdleConnections();
  }

  server.close(() => {
    clearTimeout(forceExitTimer);
    logger.system("[system] All servers and resources closed cleanly. Exiting.");
    process.exit(0);
  });

  // Forcibly destroy any lingering active HTTP sockets after 1000ms
  setTimeout(() => {
    for (const socket of activeHttpSockets) {
      socket.destroy();
    }
    activeHttpSockets.clear();
  }, 1000).unref();
}

// OS Process Signals
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGHUP", () => shutdown("SIGHUP"));

// Self-Healing Process Protections: catch unexpected errors so the server never hangs
process.on("uncaughtException", (err) => {
  logger.error("[system] Uncaught Exception caught by self-heal guard:", err);
  shutdown("UNCAUGHT_EXCEPTION");
});

process.on("unhandledRejection", (reason) => {
  logger.error("[system] Unhandled Promise Rejection:", reason);
});
