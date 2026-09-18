// CWORKER/src/dns/codec.js
// High-performance RFC 1035 / RFC 8484 DNS wireformat parser & synthesizer.

const textDecoder = new TextDecoder('utf-8');
const textEncoder = new TextEncoder();

export const TYPE_MAP = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  6: 'SOA',
  12: 'PTR',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
  33: 'SRV',
  65: 'HTTPS',
  255: 'ANY'
};

export const NAME_TO_TYPE = Object.entries(TYPE_MAP).reduce((acc, [k, v]) => {
  acc[v] = parseInt(k, 10);
  return acc;
}, {});

export function qtypeToNumber(qtype) {
  if (typeof qtype === 'number') return qtype;
  if (!qtype) return 1;
  const upper = qtype.toString().toUpperCase().trim();
  return NAME_TO_TYPE[upper] || parseInt(upper, 10) || 1;
}

export function qtypeToString(typeNum) {
  return TYPE_MAP[typeNum] || `TYPE${typeNum}`;
}

/**
 * Parses raw DNS wire query with zero unnecessary object allocations.
 * @param {Uint8Array} buf
 */
export function parseDnsQuery(buf) {
  if (!buf || buf.length < 12) {
    throw new Error('DNS packet too short (< 12 bytes)');
  }

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const id = view.getUint16(0);
  const flags = view.getUint16(2);
  const qdcount = view.getUint16(4);

  let offset = 12;
  const domainParts = [];

  while (offset < buf.length) {
    const len = buf[offset++];
    if (len === 0) break;
    if ((len & 0xc0) === 0xc0) {
      offset++;
      break;
    }
    if (offset + len > buf.length) {
      throw new Error('Malformed DNS domain label');
    }
    domainParts.push(textDecoder.decode(buf.subarray(offset, offset + len)));
    offset += len;
  }

  const domain = domainParts.join('.').toLowerCase();

  let qtype = 1;
  let qclass = 1;
  if (offset + 4 <= buf.length) {
    qtype = view.getUint16(offset);
    qclass = view.getUint16(offset + 2);
  }

  return {
    id,
    flags,
    qr: (flags >> 15) & 1,
    opcode: (flags >> 11) & 0x0f,
    qdcount,
    domain,
    qtype,
    qclass,
    raw: buf
  };
}

/**
 * Encodes domain into DNS wireformat labels.
 * @param {string} domain
 */
export function encodeDomain(domain) {
  const clean = domain.replace(/\.+$/, '').trim();
  if (!clean) return new Uint8Array([0]);

  const labels = clean.split('.');
  const parts = [];
  let totalLen = 1; // For terminating null byte

  for (const label of labels) {
    const b = textEncoder.encode(label);
    parts.push(b);
    totalLen += 1 + b.length;
  }

  const out = new Uint8Array(totalLen);
  let pos = 0;
  for (const p of parts) {
    out[pos++] = p.length;
    out.set(p, pos);
    pos += p.length;
  }
  out[pos] = 0;
  return out;
}

/**
 * Builds blocked DNS response packet in 1-2 microseconds.
 * @param {object} query
 * @param {string} action - 'ZERO_IP' or 'NXDOMAIN'
 */
export function buildBlockedResponse(query, action = 'ZERO_IP') {
  const { id, domain, qtype } = query;
  const domainBytes = encodeDomain(domain);

  if (action === 'NXDOMAIN') {
    const totalLen = 12 + domainBytes.length + 4;
    const out = new Uint8Array(totalLen);
    const view = new DataView(out.buffer);

    view.setUint16(0, id);
    view.setUint16(2, 0x8183); // QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
    view.setUint16(4, 1);      // QDCOUNT = 1
    view.setUint16(6, 0);      // ANCOUNT = 0
    view.setUint16(8, 0);
    view.setUint16(10, 0);

    out.set(domainBytes, 12);
    view.setUint16(12 + domainBytes.length, qtype);
    view.setUint16(12 + domainBytes.length + 2, 1);
    return out;
  }

  const isA = qtype === 1;
  const isAAAA = qtype === 28;
  const hasAnswer = isA || isAAAA;
  const rdataLen = isA ? 4 : (isAAAA ? 16 : 0);
  const ancount = hasAnswer ? 1 : 0;
  const answerLen = hasAnswer ? (2 + 2 + 2 + 4 + 2 + rdataLen) : 0;

  const totalLen = 12 + domainBytes.length + 4 + answerLen;
  const out = new Uint8Array(totalLen);
  const view = new DataView(out.buffer);

  view.setUint16(0, id);
  view.setUint16(2, 0x8180); // QR=1, RD=1, RA=1, RCODE=0 (NOERROR)
  view.setUint16(4, 1);      // QDCOUNT = 1
  view.setUint16(6, ancount);// ANCOUNT
  view.setUint16(8, 0);
  view.setUint16(10, 0);

  let offset = 12;
  out.set(domainBytes, offset);
  offset += domainBytes.length;

  view.setUint16(offset, qtype);
  view.setUint16(offset + 2, 1);
  offset += 4;

  if (hasAnswer) {
    view.setUint16(offset, 0xc00c); // QNAME pointer
    offset += 2;
    view.setUint16(offset, qtype);
    view.setUint16(offset + 2, 1); // IN
    view.setUint32(offset + 4, 300); // TTL 300s
    view.setUint16(offset + 8, rdataLen);
    offset += 10;
    // RDATA is initialized as zeros (0.0.0.0 or ::)
    offset += rdataLen;
  }

  return out;
}

export function buildServFailResponse(id) {
  const out = new Uint8Array(12);
  const view = new DataView(out.buffer);
  view.setUint16(0, id);
  view.setUint16(2, 0x8182); // SERVFAIL
  return out;
}

export function wireToDohJson(buf) {
  try {
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const flags = view.getUint16(2);
    const qdcount = view.getUint16(4);
    const ancount = view.getUint16(6);

    const rcode = flags & 0x0f;
    const tc = ((flags >> 9) & 1) === 1;
    const rd = ((flags >> 8) & 1) === 1;
    const ra = ((flags >> 7) & 1) === 1;
    const ad = ((flags >> 5) & 1) === 1;
    const cd = ((flags >> 4) & 1) === 1;

    let offset = 12;

    function readName() {
      const parts = [];
      let jumped = false;
      let initialOffset = offset;
      let currentOffset = offset;
      let steps = 0;

      while (currentOffset < buf.length && steps++ < 100) {
        const len = buf[currentOffset++];
        if (len === 0) break;
        if ((len & 0xc0) === 0xc0) {
          const ptr = ((len & 0x3f) << 8) | buf[currentOffset++];
          if (!jumped) {
            initialOffset = currentOffset;
            jumped = true;
          }
          currentOffset = ptr;
          continue;
        }
        parts.push(textDecoder.decode(buf.subarray(currentOffset, currentOffset + len)));
        currentOffset += len;
      }

      offset = jumped ? initialOffset : currentOffset;
      return parts.join('.');
    }

    const Question = [];
    for (let i = 0; i < qdcount && offset < buf.length; i++) {
      const name = readName();
      const type = view.getUint16(offset);
      offset += 4;
      Question.push({ name: name ? `${name}.` : '.', type });
    }

    const Answer = [];
    for (let i = 0; i < ancount && offset < buf.length; i++) {
      const name = readName();
      const type = view.getUint16(offset);
      const ttl = view.getUint32(offset + 4);
      const rdlength = view.getUint16(offset + 8);
      offset += 10;

      let data = '';
      if (type === 1 && rdlength === 4) {
        data = `${buf[offset]}.${buf[offset + 1]}.${buf[offset + 2]}.${buf[offset + 3]}`;
      } else if (type === 28 && rdlength === 16) {
        const hex = [];
        for (let j = 0; j < 16; j += 2) {
          hex.push(view.getUint16(offset + j).toString(16));
        }
        data = hex.join(':').replace(/(^|:)0(:0)+(:|$)/, '::');
      } else if (type === 5 || type === 2 || type === 12) {
        const cur = offset;
        data = readName() + '.';
        offset = cur;
      } else if (type === 16) {
        data = textDecoder.decode(buf.subarray(offset + 1, offset + rdlength));
      } else {
        data = Array.from(buf.subarray(offset, offset + rdlength))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
      }

      offset += rdlength;
      Answer.push({
        name: name ? `${name}.` : '.',
        type,
        TTL: ttl,
        data
      });
    }

    return {
      Status: rcode,
      TC: tc,
      RD: rd,
      RA: ra,
      AD: ad,
      CD: cd,
      Question,
      Answer: Answer.length > 0 ? Answer : undefined
    };
  } catch (err) {
    return {
      Status: 2,
      TC: false,
      RD: true,
      RA: true,
      AD: false,
      CD: false,
      Comment: `Failed to decode wireformat: ${err.message}`
    };
  }
}
