// test/test-sleep-mode.js
// Verifies 0.5s auto-refresh, idle Sleep Mode, and instant wake-up

import assert from "node:assert";
import { ADMIN_HTML } from "../src/core/dashboard-html.js";

async function main() {
  console.log("=== Testing Dashboard 0.5s Auto-Refresh & Sleep Mode ===");

  console.log("-> [1/4] Verifying 0.5s auto-refresh interval configuration...");
  assert.ok(ADMIN_HTML.includes("_bo=500"), "Auto-refresh interval must be set to 500ms (0.5s)");
  assert.ok(ADMIN_HTML.includes("if(_bo!==500){_bo=500;_rst();}"), "Interval must reset to 500ms on active ticks");
  console.log("   ✓ Auto-refresh interval configured to 500ms (0.5s)");

  console.log("-> [2/4] Verifying Sleep Mode CSS styling...");
  assert.ok(ADMIN_HTML.includes(".pill.sleep"), "Must include .pill.sleep CSS class");
  assert.ok(ADMIN_HTML.includes(".pill.sleep .dot"), "Must include sleep dot animation");
  console.log("   ✓ Sleep Mode pill styling verified");

  console.log("-> [3/4] Verifying idle detection and Sleep Mode functions...");
  assert.ok(ADMIN_HTML.includes("function _enterSleep()"), "Must include _enterSleep function");
  assert.ok(ADMIN_HTML.includes("function _wakeUp()"), "Must include _wakeUp function");
  assert.ok(ADMIN_HTML.includes("function _onUserActivity()"), "Must include _onUserActivity handler");
  assert.ok(ADMIN_HTML.includes("_IDLE_TIMEOUT=60000"), "Idle timeout configured for 60s");
  console.log("   ✓ Sleep Mode and wake-up functions present");

  console.log("-> [4/4] Verifying user activity listeners for instant wakeup...");
  assert.ok(ADMIN_HTML.includes("'mousemove'"), "Listens for mousemove");
  assert.ok(ADMIN_HTML.includes("'keydown'"), "Listens for keydown");
  assert.ok(ADMIN_HTML.includes("'touchstart'"), "Listens for touchstart");
  assert.ok(ADMIN_HTML.includes("'scroll'"), "Listens for scroll");
  assert.ok(ADMIN_HTML.includes("visibilitychange"), "Listens for visibilitychange");
  console.log("   ✓ User activity listeners wired for instant wake-up");

  console.log("\nALL DASHBOARD REFRESH & SLEEP MODE TESTS PASSED! ⚡😴🎉\n");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
