// Acceptance proof for the `SystemTransaction.transactionHash` export.
//
// `indexer-ground-truth.txt` holds the five system transactions that midnight-indexer 4.3.2
// archived from a 1.0.0 devnet's genesis block: for each, the hash the INDEXER recorded and the
// raw bytes it recorded them from. This recomputes those hashes with a locally built WASM and
// requires all five to match, so the export is verified against an independent implementation
// rather than against itself.
//
// It also settles a version question: the indexer's ledger and this build differ in patch version
// (8.0.3 vs 8.1.0), and matching hashes show that gap does not affect transaction hashing.
//
// Usage, from a build produced by `wasm-pack build --target bundler` plus the published package's
// `_fs.js` loader:
//   npx tsx verify-system-tx-hash.mts /home/eddie/midnight-ledger-fork/ledger-wasm/pkg/midnight_ledger_wasm_fs.js
import { readFileSync } from "node:fs";
const entry = process.argv[2];
if (!entry) throw new Error("usage: tsx verify-syshash.mts <path to midnight_ledger_wasm_fs.js>");
const ledger: any = await import(entry);
const lines = readFileSync(new URL("./indexer-ground-truth.txt", import.meta.url), "utf8").trim().split("\n");
let ok = 0, bad = 0;
for (const line of lines) {
  const [height, position, expected, rawHex] = line.trim().split(/\s+/);
  const tx = ledger.SystemTransaction.deserialize(new Uint8Array(Buffer.from(rawHex!, "hex")));
  if (typeof tx.transactionHash !== "function") {
    console.log("FAIL: transactionHash is not exported on SystemTransaction");
    process.exit(1);
  }
  const got = String(tx.transactionHash()).replace(/^0x/, "").toLowerCase();
  const match = got === expected!.toLowerCase();
  match ? ok++ : bad++;
  console.log(`${match ? "MATCH" : "DIFFER"} h${height} pos${position}: expected ${expected!.slice(0,16)}… got ${got.slice(0,16)}…`);
}
console.log(`\n${ok}/${lines.length} hashes reproduce the indexer's values` + (bad ? ` — ${bad} DIFFER` : ""));
process.exit(bad ? 1 : 0);
