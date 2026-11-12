/**
 * finalize-fixtures.js — stamp hash + acting_hash onto the conformance fixtures.
 *
 * The fixtures are authored as bodies (no hashes) so a human can read them; the
 * hashes are always computed by the implementation, never typed by hand. Run
 * after a build:  npm run fixtures
 */
const fs = require("fs");
const path = require("path");
const s = require(path.join(__dirname, "..", "dist", "sid.js"));

const root = path.join(__dirname, "..", "..", "..");
const files = ["minimal-sid.json", "full-sid.json"];

for (const name of files) {
  const p = path.join(root, "conformance", "fixtures", name);
  const body = JSON.parse(fs.readFileSync(p, "utf8"));
  const final = s.finalizeSid(body);
  fs.writeFileSync(p, JSON.stringify(final, null, 2) + "\n");
  const check = s.verifySid(final);
  console.log(
    `${name}: hash=${final.hash.slice(0, 16)}… acting=${final.acting_hash.slice(0, 16)}… ` +
      `verify=${check.ok ? "ok" : "FAILED: " + check.errors.join("; ")}`
  );
  if (!check.ok) process.exitCode = 1;
}
