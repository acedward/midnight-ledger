// Acceptance proof for the `SystemTransaction.cost` and `clampAndNormalizeFullness` exports.
//
// Companion to `verify-system-tx-hash.mts`, over the same ground truth: the five system
// transactions midnight-indexer 4.3.2 archived from a 1.0.0 devnet's genesis block. That file
// checks their identity; this one checks their cost, and the fullness a consumer folds them into.
//
// Three properties are asserted.
//
// 1. Genesis has a real cost. Its five system transactions are the whole block -- there are no
//    regular transactions -- so before `cost` was exported a consumer had no way to account for
//    any of it and computed a fullness of zero. The accumulated cost here is plainly non-zero,
//    which is what makes zero the wrong answer rather than merely an unverified one.
//
// 2. `clampAndNormalizeFullness` agrees with `normalizeFullness` whenever the input is within
//    the block limits. The clamping variant is not a different normalization; it differs only in
//    the over-limit case.
//
// 3. In the over-limit case the two deliberately differ, and the clamping one is the one that
//    matches the node: `normalizeFullness` throws, while `clampAndNormalizeFullness` reports
//    every dimension as exactly full. This mirrors `clamp_and_normalize` in the node's ledger
//    helpers, which `post_block_update` calls on every block.
//
// Usage, against a build produced by `wasm-pack build --target bundler` plus the published
// package's `_fs.js` loader:
//   npx tsx verify-system-tx-cost.mts /home/eddie/midnight-ledger-fork/ledger-wasm/pkg/midnight_ledger_wasm_fs.js
import { readFileSync } from "node:fs";

const entry = process.argv[2];
if (!entry) throw new Error("usage: tsx verify-system-tx-cost.mts <path to midnight_ledger_wasm_fs.js>");
const ledger: any = await import(entry);

const DIMENSIONS = ["readTime", "computeTime", "blockUsage", "bytesWritten", "bytesChurned"] as const;
const show = (v: unknown) => JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x));

const failures: string[] = [];
const check = (ok: boolean, what: string) => {
  console.log(`${ok ? "PASS" : "FAIL"}: ${what}`);
  if (!ok) failures.push(what);
};

const params = ledger.LedgerParameters.initialParameters();

if (typeof params.clampAndNormalizeFullness !== "function") {
  console.log("FAIL: clampAndNormalizeFullness is not exported on LedgerParameters");
  process.exit(1);
}

const limits: any = params.blockLimits;
check(
  limits != null && DIMENSIONS.every((d) => BigInt(limits[d]) > 0n),
  `blockLimits exposes all five dimensions, all positive: ${show(limits)}`,
);

// 1. Accumulate the cost of genesis's system transactions, the way the node's `apply_system_tx`
//    folds each one into the running block fullness.
const lines = readFileSync(new URL("./indexer-ground-truth.txt", import.meta.url), "utf8").trim().split("\n");
const accumulated: Record<string, bigint> = Object.fromEntries(DIMENSIONS.map((d) => [d, 0n]));

for (const line of lines) {
  const [height, position, , rawHex] = line.trim().split(/\s+/);
  const tx = ledger.SystemTransaction.deserialize(new Uint8Array(Buffer.from(rawHex!, "hex")));
  if (typeof tx.cost !== "function") {
    console.log("FAIL: cost is not exported on SystemTransaction");
    process.exit(1);
  }
  const cost: any = tx.cost(params);
  console.log(`  h${height} pos${position} cost: ${show(cost)}`);
  for (const d of DIMENSIONS) accumulated[d]! += BigInt(cost[d]);
}

console.log(`  accumulated: ${show(accumulated)}`);
check(
  DIMENSIONS.some((d) => accumulated[d]! > 0n),
  `genesis's ${lines.length} system transactions accumulate a non-zero cost`,
);

// 2. Within limits, the clamping variant must agree with the plain one.
const normalized: any = params.normalizeFullness(accumulated);
const clamped: any = params.clampAndNormalizeFullness(accumulated);
console.log(`  normalizeFullness:         ${show(normalized)}`);
console.log(`  clampAndNormalizeFullness: ${show(clamped)}`);
check(
  DIMENSIONS.every((d) => normalized[d] === clamped[d]),
  "within the block limits, clampAndNormalizeFullness agrees with normalizeFullness",
);

// Overall fullness is the max across dimensions, per the node's `compute_overall_fullness`.
const overall = Math.max(...DIMENSIONS.map((d) => Number(clamped[d])));
check(overall > 0, `genesis's overall fullness is non-zero: ${overall}`);

// 3. Over the limits, they must differ -- and the clamping one is the node's behaviour.
const over = Object.fromEntries(DIMENSIONS.map((d) => [d, BigInt(limits[d]) * 2n + 1n]));
let threw = false;
try {
  params.normalizeFullness(over);
} catch {
  threw = true;
}
check(threw, "over the block limits, normalizeFullness throws");

const overClamped: any = params.clampAndNormalizeFullness(over);
console.log(`  over-limit clampAndNormalizeFullness: ${show(overClamped)}`);
check(
  DIMENSIONS.every((d) => Number(overClamped[d]) === 1),
  "over the block limits, clampAndNormalizeFullness reports every dimension exactly full",
);

console.log(
  failures.length
    ? `\n${failures.length} check(s) FAILED:\n  - ${failures.join("\n  - ")}`
    : "\nall checks pass",
);
process.exit(failures.length ? 1 : 0);
