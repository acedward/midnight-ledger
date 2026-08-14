// Runtime acceptance proof for LedgerState.closeBlock.
//
// The expected hashes are committed native-Rust oracle outputs. They are not built through this
// WASM artifact, so a closeBlock implementation that repeats the old f64 round trip cannot make
// its own expectation pass. Each vector also pins the rounded counterweight to prove it really
// distinguishes the exact and lossy paths.
//
// Usage:
//   npx tsx verify-close-block.mts /absolute/path/to/midnight_ledger_wasm_fs.js
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const entry = process.argv[2];
if (!entry) throw new Error("usage: tsx verify-close-block.mts <path to midnight_ledger_wasm_fs.js>");
const ledger: any = await import(entry);

const DIMENSIONS = ["readTime", "computeTime", "blockUsage", "bytesWritten", "bytesChurned"] as const;
type Cost = Record<(typeof DIMENSIONS)[number], bigint>;

const oracleRows = readFileSync(
  new URL("./native-close-block-oracles.txt", import.meta.url),
  "utf8",
)
  .split("\n")
  .map((line) => line.trim())
  .filter((line) => line !== "" && !line.startsWith("#"));
const oracles = new Map(
  oracleRows.map((line) => {
    const [label, native, rounded] = line.split(/\s+/);
    if (!label || !native || !rounded) throw new Error(`malformed oracle row: ${line}`);
    return [label, { native, rounded }];
  }),
);

const emptyCost = (): Cost => Object.fromEntries(DIMENSIONS.map((dimension) => [dimension, 0n])) as Cost;
const addCost = (total: Cost, cost: Cost): void => {
  for (const dimension of DIMENSIONS) total[dimension] += BigInt(cost[dimension]);
};
const sha256 = (state: any): string =>
  createHash("sha256").update(Buffer.from(state.serialize())).digest("hex");
const roundedClose = (state: any, tblock: Date, accumulated: Cost): any => {
  const normalized = state.parameters.clampAndNormalizeFullness(accumulated);
  const overall = Math.max(...DIMENSIONS.map((dimension) => Number(normalized[dimension])));
  return state.postBlockUpdate(tblock, normalized, overall);
};
const verify = (label: string, exact: any, rounded: any): void => {
  const expected = oracles.get(label);
  if (!expected) throw new Error(`missing oracle fixture ${label}`);
  const exactHash = sha256(exact);
  const roundedHash = sha256(rounded);
  if (exactHash !== expected.native) {
    throw new Error(`${label}: exact ${exactHash} != native oracle ${expected.native}`);
  }
  if (roundedHash !== expected.rounded) {
    throw new Error(`${label}: rounded counterweight ${roundedHash} != ${expected.rounded}`);
  }
  if (exactHash === roundedHash) {
    throw new Error(`${label}: vector no longer distinguishes exact Q64 from the f64 round trip`);
  }
  console.log(`PASS ${label}: exact=${exactHash} rounded=${roundedHash}`);
};

if (typeof ledger.LedgerState.blank("probe").closeBlock !== "function") {
  throw new Error("LedgerState.closeBlock is not exported");
}

const genesisTime = new Date(0);
let genesisState = ledger.LedgerState.blank("undeployed");
const genesisCost = emptyCost();
for (const line of readFileSync(new URL("./indexer-ground-truth.txt", import.meta.url), "utf8")
  .trim()
  .split("\n")) {
  const rawHex = line.trim().split(/\s+/)[3];
  if (!rawHex) throw new Error(`ground-truth row lacks transaction bytes: ${line}`);
  const tx = ledger.SystemTransaction.deserialize(new Uint8Array(Buffer.from(rawHex, "hex")));
  addCost(genesisCost, tx.cost(genesisState.parameters));
  [genesisState] = genesisState.applySystemTx(tx, genesisTime);
}
verify(
  "genesis-system-transactions",
  genesisState.closeBlock(genesisTime, genesisCost),
  roundedClose(genesisState, genesisTime, genesisCost),
);

const syntheticState = ledger.LedgerState.blank("local-test");
const limits = syntheticState.parameters.blockLimits as Cost;
const syntheticCost: Cost = {
  readTime: BigInt(limits.readTime) + 1n,
  computeTime: BigInt(limits.computeTime) / 5n,
  blockUsage: BigInt(limits.blockUsage) / 3n,
  bytesWritten: BigInt(limits.bytesWritten) / 11n,
  bytesChurned: BigInt(limits.bytesChurned) / 13n,
};
const syntheticTime = new Date(1_700_000_000_000);
verify(
  "synthetic-overlimit-q64",
  syntheticState.closeBlock(syntheticTime, syntheticCost),
  roundedClose(syntheticState, syntheticTime, syntheticCost),
);

console.log("2/2 close-block vectors match committed native-Rust oracles");
