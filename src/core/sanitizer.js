// src/core/sanitizer.js
// Universal input sanitization, RFC 1035 / RFC 1123 hostname validation, path safety, and XSS escaping.

/**
 * Validates and normalizes domain names.
 * - Strips trailing dot
 * - Converts to lowercase
 * - Supports optional wildcard prefix (*.example.com)
 * - Validates label length (<= 63) and total length (<= 253)
 * - Strictly prevents prototype pollution and control character injection
 * 
 * @param {any} raw
 * @returns {string|null} Normalized domain or null if invalid
 */
export function sanitizeDomain(raw) {
  if (typeof raw !== "string") return null;
  let d = raw.trim().toLowerCase();
  if (!d || d.length > 253) return null;

  // Strip trailing dot if present
  if (d.endsWith(".")) d = d.slice(0, -1);
  if (!d) return null;

  // Block prototype pollution identifiers
  if (d === "__proto__" || d === "constructor" || d === "prototype") return null;

  // Handle wildcard prefix
  let checkPart = d;
  if (checkPart.startsWith("*.")) {
    checkPart = checkPart.slice(2);
    if (!checkPart) return null;
  }

  // Label length and character validation (RFC 1035 / RFC 1123)
  const labels = checkPart.split(".");
  if (labels.length < 1) return null;

  for (const label of labels) {
    if (!label || label.length > 63) return null;
    // Disallow labels starting or ending with hyphen
    if (label.startsWith("-") || label.endsWith("-")) return null;
    // Only alphanumeric and hyphens (or punycode xn--)
    if (!/^[a-z0-9]([a-z0-9-_]{0,61}[a-z0-9])?$/.test(label)) {
      return null;
    }
  }

  return d;
}

/**
 * Sanitizes URL paths for admin API and token generation.
 * Strips path traversal (../), null bytes, control codes, and limits length.
 * 
 * @param {any} raw
 * @returns {string} Clean path (defaults to "/")
 */
export function sanitizePath(raw) {
  if (typeof raw !== "string" || !raw.trim()) return "/";
  let p = raw.trim();

  // Strip null bytes and control characters
  p = p.replace(/[\x00-\x1f\x7f]/g, "");

  // Normalize slashes
  p = p.replace(/\\+/g, "/");

  // Resolve traversal segments canonically
  const segments = p.split("/").filter((s) => s && s !== ".");
  const safe = [];
  for (const seg of segments) {
    if (seg === "..") {
      safe.pop();
    } else {
      safe.push(seg);
    }
  }

  p = "/" + safe.join("/");
  if (p.length > 256) p = p.slice(0, 256);
  return p || "/";
}

/**
 * Validates and clamps token TTL duration in seconds.
 * Min: 60 seconds (1 minute)
 * Max: 315,360,000 seconds (10 years)
 * 
 * @param {any} raw
 * @param {number} [defaultSeconds=86400]
 * @returns {number} Validated seconds
 */
export function sanitizeTtl(raw, defaultSeconds = 86400) {
  if (raw === undefined || raw === null) return defaultSeconds;

  if (typeof raw === "string") {
    const s = raw.trim().toLowerCase();
    const match = s.match(/^(\d+)([hdwmy]?)$/);
    if (match) {
      const num = parseInt(match[1], 10);
      const unit = match[2] || "d";
      if (isNaN(num) || num <= 0) return defaultSeconds;
      let mult = 86400;
      if (unit === "h") mult = 3600;
      else if (unit === "d") mult = 86400;
      else if (unit === "w") mult = 604800;
      else if (unit === "m") mult = 2592000;
      else if (unit === "y") mult = 31536000;
      else mult = 1;
      const total = num * mult;
      return Math.max(60, Math.min(315360000, total));
    }
  }

  const num = parseInt(raw, 10);
  if (isNaN(num) || num <= 0) return defaultSeconds;
  return Math.max(60, Math.min(315360000, num));
}

/**
 * Escapes characters for safe DOM insertion to prevent Cross-Site Scripting (XSS).
 * 
 * @param {any} str
 * @returns {string}
 */
export function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
