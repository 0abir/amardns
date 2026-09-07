// src/dot-server.js
// DNS-over-TLS (DoT) TCP stream adapter for RFC 7858 / RFC 1035.
// Receives decrypted TLS traffic from reverse proxy or direct TLS/TCP connections,
// parses length-prefixed DNS wire frames, forwards to worker.fetch(),
// and streams length-prefixed responses back to the client.

import net from "node:net";
import tls from "node:tls";
import logger from "./logger.js";

const MAX_DNS_QUERY = 4096;

/**
 * Parses optional PROXY protocol v1/v2 header if upstream proxy protocol is enabled.
 * Returns { clientIp, remainingBuffer }
 */
function parseProxyProtocol(buf) {
  // PROXY v1 text: "PROXY TCP4/TCP6 <src_ip> ...\r\n"
  if (buf.length >= 8 && buf.subarray(0, 6).toString("ascii") === "PROXY ") {
    const crlf = buf.indexOf("\r\n");
    if (crlf !== -1) {
      const line = buf.subarray(0, crlf).toString("ascii");
      const parts = line.split(" ");
      const clientIp = parts[2];
      return { clientIp, remaining: buf.subarray(crlf + 2), parsed: true };
    }
    return { clientIp: null, remaining: buf, parsed: false }; // wait for CRLF
  }

  // PROXY v2 binary header signature: \x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A
  const V2_SIG = Buffer.from([
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
  ]);
  if (buf.length >= 16 && buf.subarray(0, 12).equals(V2_SIG)) {
    const len = buf.readUInt16BE(14);
    const totalLen = 16 + len;
    if (buf.length >= totalLen) {
      const familyAndProto = buf[13];
      let clientIp = null;
      if (familyAndProto === 0x11 && len >= 12) {
        // AF_INET (IPv4)
        clientIp = `${buf[16]}.${buf[17]}.${buf[18]}.${buf[19]}`;
      } else if (familyAndProto === 0x21 && len >= 36) {
        // AF_INET6 (IPv6)
        const parts = [];
        for (let i = 0; i < 16; i += 2) {
          parts.push(buf.readUInt16BE(16 + i).toString(16));
        }
        clientIp = parts.join(":");
      }
      return {
        clientIp,
        remaining: buf.subarray(totalLen),
        parsed: true,
      };
    }
    return { clientIp: null, remaining: buf, parsed: false }; // wait for full header
  }

  // Not a PROXY protocol header
  return { clientIp: null, remaining: buf, parsed: true };
}

/**
 * Builds standard DNS SERVFAIL response in RFC 1035 wire format.
 */
function makeServfail(queryBuf) {
  try {
    const resp = Buffer.from(queryBuf);
    if (resp.length >= 4) {
      const flags = resp.readUInt16BE(2);
      // QR=1, RCODE=2 (SERVFAIL), preserve Opcode & RD
      resp.writeUInt16BE((flags & 0x7800) | 0x8182, 2);
      resp.writeUInt16BE(0, 6); // ANCOUNT = 0
      resp.writeUInt16BE(0, 8); // NSCOUNT = 0
      resp.writeUInt16BE(0, 10); // ARCOUNT = 0
    }
    return resp;
  } catch {
    return queryBuf;
  }
}

export function startDotServer(worker, env, ctx, port = 853, tlsOptions = null) {
  const activeSockets = new Set();

  function onConnection(socket) {
    activeSockets.add(socket);
    socket.setKeepAlive(true, 15000);
    socket.setTimeout(120000); // 120s idle timeout (RFC 7858)

    let rxBuf = Buffer.alloc(0);
    let proxyChecked = false;
    let clientIp = socket.remoteAddress?.replace(/^::ffff:/, "") || "127.0.0.1";

    let sniTag = null;
    if (socket.servername) {
      const parts = socket.servername.toLowerCase().split(".");
      if (parts.length >= 3 && !["amardns", "www", "dns", "dot"].includes(parts[0])) {
        sniTag = parts[0];
      }
    }

    socket.on("timeout", () => {
      socket.end();
      setTimeout(() => {
        if (!socket.destroyed) socket.destroy();
      }, 1000).unref();
    });

    socket.on("error", (err) => {
      if (err.code !== "ECONNRESET" && err.code !== "EPIPE") {
        logger.warn("[dot] socket error:", err.message);
      }
      socket.destroy();
    });

    socket.on("close", () => {
      activeSockets.delete(socket);
    });

    socket.on("data", async (chunk) => {
      rxBuf = Buffer.concat([rxBuf, chunk]);

      // Check for PROXY protocol on connection start
      if (!proxyChecked) {
        const proxyRes = parseProxyProtocol(rxBuf);
        if (!proxyRes.parsed) {
          // Incomplete PROXY header, wait for more data
          return;
        }
        if (proxyRes.clientIp) {
          clientIp = proxyRes.clientIp;
        }
        rxBuf = proxyRes.remaining;
        proxyChecked = true;
      }

      // Process all complete length-prefixed DNS messages in the buffer
      while (rxBuf.length >= 2) {
        const msgLen = rxBuf.readUInt16BE(0);

        if (msgLen > MAX_DNS_QUERY) {
          logger.warn(`[dot] query size ${msgLen} exceeds max ${MAX_DNS_QUERY}`);
          socket.destroy();
          return;
        }

        if (rxBuf.length < 2 + msgLen) {
          // Waiting for more data of the current message
          break;
        }

        const dnsQuery = rxBuf.subarray(2, 2 + msgLen);
        rxBuf = rxBuf.subarray(2 + msgLen);

        // Dispatch DNS query to worker asynchronously
        (async () => {
          const clientTxId = dnsQuery.length >= 2 ? dnsQuery.readUInt16BE(0) : 0;
          try {
            const reqHeaders = {
              "content-type": "application/dns-message",
              "content-length": String(dnsQuery.length),
              "x-forwarded-for": clientIp,
              "x-device-type": "dot",
            };
            if (sniTag) {
              reqHeaders["x-device-id"] = sniTag;
            }
            const request = new Request("http://127.0.0.1/dns-query", {
              method: "POST",
              headers: reqHeaders,
              body: dnsQuery,
            });

            const response = await worker.fetch(request, env, ctx);

            if (response.status === 200 && response.body) {
              const respBuf = Buffer.from(await response.arrayBuffer());
              // In RFC 1035 / RFC 7858, match query Transaction ID
              if (respBuf.length >= 2) {
                respBuf.writeUInt16BE(clientTxId, 0);
              }
              const out = Buffer.allocUnsafe(2 + respBuf.length);
              out.writeUInt16BE(respBuf.length, 0);
              respBuf.copy(out, 2);
              if (!socket.destroyed) {
                socket.write(out);
              }
            } else {
              // Fallback SERVFAIL
              const fail = makeServfail(dnsQuery);
              if (fail.length >= 2) {
                fail.writeUInt16BE(clientTxId, 0);
              }
              const out = Buffer.allocUnsafe(2 + fail.length);
              out.writeUInt16BE(fail.length, 0);
              fail.copy(out, 2);
              if (!socket.destroyed) {
                socket.write(out);
              }
            }
          } catch (err) {
            logger.error("[dot] resolve error:", err);
            if (!socket.destroyed) {
              const fail = makeServfail(dnsQuery);
              if (fail.length >= 2) {
                fail.writeUInt16BE(clientTxId, 0);
              }
              const out = Buffer.allocUnsafe(2 + fail.length);
              out.writeUInt16BE(fail.length, 0);
              fail.copy(out, 2);
              socket.write(out);
            }
          }
        })();
      }
    });
  }

  const server = tlsOptions
    ? tls.createServer(tlsOptions, onConnection)
    : net.createServer(onConnection);

  server.on("error", (err) => {
    if (err.code === "EACCES") {
      logger.error(`\n[ERROR] Permission denied binding DoT to port ${port}.`);
      logger.error(`Ports < 1024 are privileged on Linux and require elevated permissions.`);
      logger.error(`To fix, either:`);
      logger.error(`  1. Run with sudo: sudo npm start`);
      logger.error(`  2. Or grant node permission: sudo setcap 'cap_net_bind_service=+ep' $(which node)`);
      logger.error(`  3. Or specify unprivileged ports: PORT=8080 DOT_PORT=8053 npm start\n`);
    } else {
      logger.error("[dot] server error:", err);
    }
  });

  const host = process.env.HOST || "0.0.0.0";
  server.listen(port, host, () => {
    logger.system(`AmarDNS DoT ${tlsOptions ? "(TLS)" : "(TCP)"} listening on ${host}:${port}`);
  });

  return {
    server,
    close: (cb) => {
      for (const sock of activeSockets) {
        sock.destroy();
      }
      activeSockets.clear();
      server.close(cb);
    },
  };
}
