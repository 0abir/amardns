// test/test-whitelist-lookalike.js
// Automated verification of robust Look-a-like AI, known legit domains, and strict whitelist guards

import assert from "node:assert";
import fs from "node:fs";
import { PulseDB } from "../src/storage/pulse-db.js";
import {
  isKnownLegitDomain,
  alikeDomainCheck,
  autoBlockSet,
  checkBlocklist,
  dgaScore
} from "../src/core/threat-intelligence.js";
import { _autoBlocks, setEnv } from "../src/core/state.js";

async function main() {
  console.log("=== Testing Robust Look-a-like AI & Whitelist Precedence ===");
  const dbPath = "/tmp/test-whitelist-lookalike-" + Date.now() + ".db";
  const pdb = new PulseDB(dbPath);
  const env = { pulseDb: pdb, DNS_MASTER_KEY: "testkey" };
  setEnv(env);

  // -------------------------------------------------------------
  // Test 1: isKnownLegitDomain
  // -------------------------------------------------------------
  console.log("-> [1/5] Testing Known Legit Domains...");
  assert.strictEqual(isKnownLegitDomain("googlesource.com"), true, "googlesource.com must be known legit");
  assert.strictEqual(isKnownLegitDomain("android.googlesource.com"), true, "android.googlesource.com must be known legit");
  assert.strictEqual(isKnownLegitDomain("sub.android.googlesource.com"), true, "sub.android.googlesource.com must be known legit");
  assert.strictEqual(isKnownLegitDomain("google.com"), true, "google.com must be known legit");
  assert.strictEqual(isKnownLegitDomain("github.com"), true, "github.com must be known legit");
  assert.strictEqual(isKnownLegitDomain("apple.com"), true, "apple.com must be known legit");
  assert.strictEqual(isKnownLegitDomain("cloudflare.com"), true, "cloudflare.com must be known legit");
  assert.strictEqual(isKnownLegitDomain("wikipedia.org"), true, "wikipedia.org must be known legit");

  // Non-legit/attacker domains
  assert.strictEqual(isKnownLegitDomain("googlesource-fake.com"), false, "googlesource-fake.com must NOT be known legit");
  assert.strictEqual(isKnownLegitDomain("google.com.attacker.com"), false, "google.com.attacker.com must NOT be known legit");
  console.log("   ✓ Known legit domains verified!");

  // -------------------------------------------------------------
  // Test 2: alikeDomainCheck False Positive Protection
  // -------------------------------------------------------------
  console.log("-> [2/5] Testing alikeDomainCheck False Positive Protection...");
  // Legitimate domains that were previously false-flagged
  const check1 = alikeDomainCheck("googlesource.com", pdb);
  assert.strictEqual(check1.detected, false, "googlesource.com must NOT be flagged as lookalike");

  const check2 = alikeDomainCheck("android.googlesource.com", pdb);
  assert.strictEqual(check2.detected, false, "android.googlesource.com must NOT be flagged as lookalike");

  // Punycode / IDN domains (should NOT be blanket blocked)
  const punycode1 = "xn--80aaad6bxb9c.xn----8sbag2cjad7m.xn--p1ai";
  const check3 = alikeDomainCheck(punycode1, pdb);
  assert.strictEqual(check3.detected, false, "Valid Punycode domain must NOT be blanket blocked");

  const punycode2 = "xn--80aabpau7arecgu7c4gc.xn--p1ai";
  const check4 = alikeDomainCheck(punycode2, pdb);
  assert.strictEqual(check4.detected, false, "Valid Punycode domain 2 must NOT be blanket blocked");

  console.log("   ✓ No false positives on legitimate or standard Punycode domains!");

  // -------------------------------------------------------------
  // Test 3: alikeDomainCheck Real Threat Detection
  // -------------------------------------------------------------
  console.log("-> [3/5] Testing alikeDomainCheck True Positive Threat Detection...");
  // Typosquatting
  const typo1 = alikeDomainCheck("paypa1.com", pdb);
  assert.strictEqual(typo1.detected, true, "paypa1.com must be detected");
  assert.strictEqual(typo1.brand, "paypal");

  const typo2 = alikeDomainCheck("g00gle.com", pdb);
  assert.strictEqual(typo2.detected, true, "g00gle.com must be detected");
  assert.strictEqual(typo2.brand, "google");

  // Phishing compound domain
  const phish1 = alikeDomainCheck("paypal-verify-security.com", pdb);
  assert.strictEqual(phish1.detected, true, "paypal-verify-security.com must be detected as brand impersonation");

  // Homoglyph mixed script (Cyrillic 'а' \u0430 inside latin 'paypal.com')
  const homoglyph = "p\u0430ypal.com";
  const homoCheck = alikeDomainCheck(homoglyph, pdb);
  assert.strictEqual(homoCheck.detected, true, "Mixed script homoglyph must be detected");
  assert.strictEqual(homoCheck.reason, "script_mix_lookalike");

  console.log("   ✓ True malicious typosquats and homoglyphs accurately caught!");

  // -------------------------------------------------------------
  // Test 4: Whitelist Guarding & autoBlockSet Immunity
  // -------------------------------------------------------------
  console.log("-> [4/5] Testing Whitelist Immunity across Storage & AI Blocking...");
  // Add a domain to whitelist
  pdb.addWhitelist(["my-company-internal.net", "*.corporate-hub.com"]);

  // Blocklist attempt on whitelisted domain must be ignored by PulseDB
  const addedCount = pdb.addBlocklist(["my-company-internal.net", "portal.corporate-hub.com"]);
  assert.strictEqual(addedCount, 0, "PulseDB must reject adding whitelisted domains to blocklist");

  // autoBlockSet must skip whitelisted domains
  await autoBlockSet("my-company-internal.net", "dga_detected");
  assert.strictEqual(_autoBlocks.has("my-company-internal.net"), false, "Whitelisted domain must not be auto-blocked");

  // autoBlockSet must skip known legit domains
  await autoBlockSet("googlesource.com", "dga_detected");
  assert.strictEqual(_autoBlocks.has("googlesource.com"), false, "Known legit domain must not be auto-blocked");

  // checkBlocklist must pass whitelisted and known legit domains
  const checkBL1 = checkBlocklist("googlesource.com", pdb);
  assert.strictEqual(checkBL1.blocked, false, "googlesource.com must pass checkBlocklist");

  const checkBL2 = checkBlocklist("portal.corporate-hub.com", pdb);
  assert.strictEqual(checkBL2.blocked, false, "Whitelisted wildcard must pass checkBlocklist");

  console.log("   ✓ Whitelist & legit immunity completely enforced!");

  // -------------------------------------------------------------
  // Test 5: DGA Score Immunity
  // -------------------------------------------------------------
  console.log("-> [5/5] Testing DGA Score Immunity for Legit & Whitelisted Domains...");
  assert.strictEqual(dgaScore("googlesource.com"), 0, "googlesource.com DGA score must be 0");
  assert.strictEqual(dgaScore("android.googlesource.com"), 0, "android.googlesource.com DGA score must be 0");
  assert.strictEqual(dgaScore("my-company-internal.net"), 0, "Whitelisted domain DGA score must be 0");
  console.log("   ✓ DGA score bypassed for legit and whitelisted domains!");

  // Cleanup
  try {
    fs.unlinkSync(dbPath);
  } catch (_) {}

  console.log("\nALL WHITELIST & LOOKALIKE AI TESTS PASSED SUCCESSFULLY! ✓✓✓\n");
}

main().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
