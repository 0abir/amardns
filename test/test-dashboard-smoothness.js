import assert from "node:assert";
import { ADMIN_HTML } from "../src/core/dashboard-html.js";

console.log("=== Testing Dashboard Auto-Refresh Smoothness & Expansion Memory ===");

// 1. Verify 500ms auto-refresh interval is maintained
console.log("-> 1. Verifying 500ms auto-refresh interval is intact...");
assert.ok(ADMIN_HTML.includes("_bo=500"), "Auto-refresh must remain configured to 500ms");
console.log("   ✓ 500ms auto-refresh interval verified");

// 2. Verify persistent accordion memory Set and toggle function
console.log("-> 2. Verifying persistent accordion memory Set & toggleDomainGroup...");
assert.ok(ADMIN_HTML.includes("var _expandedGroups=new Set();"), "_expandedGroups Set must be defined");
assert.ok(ADMIN_HTML.includes("_expandedGroups.delete(root)"), "Collapsing group must delete from _expandedGroups");
assert.ok(ADMIN_HTML.includes("_expandedGroups.add(root)"), "Expanding group must add to _expandedGroups");
console.log("   ✓ Persistent accordion tracking verified");

// 3. Verify loadBlock and loadWhitelist use _expandedGroups
console.log("-> 3. Verifying loadBlock & loadWhitelist render expanded groups open...");
assert.ok(ADMIN_HTML.includes("var isOpen=_expandedGroups.has(root);"), "loadBlock/loadWhitelist must check _expandedGroups.has(root)");
assert.ok(ADMIN_HTML.includes("var disp=isOpen?'flex':'none';"), "Expanded groups must be rendered with display:flex");
assert.ok(ADMIN_HTML.includes("var arrowTxt=isOpen?'▴':'▾';"), "Expanded groups must display ▴ arrow");
console.log("   ✓ Domain group expansion rendering verified");

// 4. Verify selection & mouse interaction guards
console.log("-> 4. Verifying mouse & selection guards...");
assert.ok(ADMIN_HTML.includes("var _isMouseDown=false;"), "_isMouseDown variable must be defined");
assert.ok(ADMIN_HTML.includes("function isNodeSelected(node){"), "isNodeSelected guard function must be present");
assert.ok(ADMIN_HTML.includes("!isNodeSelected(elV)&&!_isMouseDown"), "sgrid stat card values must be guarded against selection destruction");
assert.ok(ADMIN_HTML.includes("!isNodeSelected(elS)&&!_isMouseDown"), "sgrid stat card subs must be guarded against selection destruction");
assert.ok(ADMIN_HTML.includes("!isNodeSelected(tags)&&!_isMouseDown"), "Tag lists must be guarded against selection destruction");
assert.ok(ADMIN_HTML.includes("!isNodeSelected(elAct)&&!_isMouseDown"), "Activity log must be guarded against selection destruction");
assert.ok(ADMIN_HTML.includes("!isNodeSelected(elAno)&&!_isMouseDown"), "Anomaly log must be guarded against selection destruction");
assert.ok(ADMIN_HTML.includes("!isNodeSelected(logbox)"), "AI decision logbox must be guarded against selection destruction");
console.log("   ✓ Selection and click guards verified");

// 5. Verify surgical in-place DOM updates in renderDP, renderUpstreams, renderProfiles
console.log("-> 5. Verifying surgical in-place DOM updates...");
assert.ok(ADMIN_HTML.includes("if(children.length===rows.length){"), "renderDP must update in-place when row count matches");
assert.ok(ADMIN_HTML.includes("if(grid.children.length===ups.length&&ups.length>0){"), "renderUpstreams must update in-place without replacing DOM cards");
assert.ok(ADMIN_HTML.includes("if(tbody.children.length===profs.length&&profs.length>0){"), "renderProfiles must update in-place without replacing DOM rows");
console.log("   ✓ Surgical non-destructive DOM updates verified");

// 6. Verify removal of 500ms repeated network fetches in intelligence tab
console.log("-> 6. Verifying removal of repeated 500ms network flooding...");
const intelligence500msCall = "if(tid==='intelligence'){renderIntelligence(d);loadBlock();loadWhitelist();loadCommon();}";
assert.strictEqual(ADMIN_HTML.includes(intelligence500msCall), false, "Repeated 500ms loadBlock/loadWhitelist/loadCommon calls must be removed from render loop");
assert.ok(ADMIN_HTML.includes("_lastBlkCount"), "Intelligence tab must check if count changed before re-fetching");
console.log("   ✓ 500ms network flood eliminated");

console.log("\nALL DASHBOARD AUTO-REFRESH SMOOTHNESS & ACCORDION TESTS PASSED! 🚀✨🎉\n");
