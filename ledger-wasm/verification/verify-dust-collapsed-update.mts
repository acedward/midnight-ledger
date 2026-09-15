// Acceptance proof for `DustLocalState.collapsedCommitmentUpdate`,
// `collapsedGenerationUpdate` and the two `*TreeFirstFree` getters.
//
// The payloads are real: the first N DUST ledger events of the preprod chain, fetched once from
// the public indexer's `dustLedgerEvents` subscription and cached, so every leaf hash below is a
// hash of a `QualifiedDustOutput` or a `DustGenerationInfo` the chain actually produced.
//
// Part 1 and 2 are the round trip the exports exist for, and they cannot be satisfied by a build
// agreeing with itself: a source state holds every leaf, the ranges *around* three leaves it is
// told to treat as someone else's are cut out of it, and a second, empty state applies those cuts
// and inserts only those three leaves from the event payloads. Both of its tree roots must equal
// the source's. A cut that returned wrong hashes, or that silently skipped leaves, changes the
// rebuilt root. Each segment is serialized and deserialized on the way, so the wire form is
// covered too.
//
// Part 3 pins a limitation rather than a capability, and is the reason parts 1 and 2 build their
// source state by insertion instead of by replay. A `DustLocalState` that replays the events with
// a key owning nothing -- the node-side mirror of spec 00016 §5.7 -- collapses every foreign leaf,
// and `MerkleTreeNode::collapse` merges a pair of collapsed siblings into one collapsed parent.
// The mirror's trees therefore hold large aligned `Collapsed` subtrees, and a cut that would have
// to descend into one is refused. Only the whole populated range and the handful of ranges ending
// on a decomposition boundary survive. This is asserted here so the fact is pinned to a build, not
// remembered: see question Q-12 of project 00016.
//
// Part 4 asserts every out-of-range form throws. `MerkleTreeCollapsedUpdate::new` alone does not
// reject a range past `first_free` -- it can walk into the tree's stub region and, when a step
// lands on a whole stub subtree, return that subtree's default hash -- so a build whose range
// check went missing would answer these instead of throwing.
//
// The indexer is contacted **once**: the fetched events are cached in the sample file and every
// later run replays from it. Pass a different --sample to force a new subscription.
//
// Usage (from the UmbraDB worktree root, absolute paths -- the entry is passed to import()):
//   ./node_modules/.bin/tsx <fork>/ledger-wasm/verification/verify-dust-collapsed-update.mts \
//       /media/eddie/mn-nvme/00016/ledger-v8-syshash.5/midnight_ledger_wasm_fs.js \
//       [--sample /media/eddie/mn-nvme/00016/samples/dust-events-preprod-5000.bin] \
//       [--events 5000] [--indexer wss://indexer.preprod.midnight.network/api/v4/graphql/ws]
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

const argv = process.argv.slice(2);
const entry = argv[0];
if (!entry || entry.startsWith("--")) {
  throw new Error(
    "usage: tsx verify-dust-collapsed-update.mts <path to midnight_ledger_wasm_fs.js> [--sample F] [--events N] [--indexer URL]",
  );
}
const flag = (name: string, fallback: string): string => {
  const at = argv.indexOf(`--${name}`);
  return at === -1 ? fallback : (argv[at + 1] ?? fallback);
};
const SAMPLE = flag("sample", "/media/eddie/mn-nvme/00016/samples/dust-events-preprod-5000.bin");
const EVENTS = Number(flag("events", "5000"));
const INDEXER = flag("indexer", "wss://indexer.preprod.midnight.network/api/v4/graphql/ws");
const ROOTS_FILE = `${SAMPLE.replace(/\.bin$/, "")}-roots.json`;

const ledger: any = await import(entry);
const ms = () => Number(process.hrtime.bigint()) / 1e6;
const median = (values: number[]): number =>
  [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)] ?? Number.NaN;
const round = (value: number, digits = 3): number => Number(value.toFixed(digits));

let failures = 0;
const check = (label: string, ok: boolean, detail: string): void => {
  if (!ok) failures += 1;
  console.log(`${ok ? "PASS" : "FAIL"} ${label}: ${detail}`);
};

// ---------------------------------------------------------------- the events

/** `Event.serialize()` bytes concatenate into a valid `replayRawEvents` input (spec 00016 A-3). */
const loadSample = (): Uint8Array[] => {
  const blob = readFileSync(SAMPLE);
  const lengths: number[] = JSON.parse(readFileSync(`${SAMPLE}.index.json`, "utf8"));
  const events: Uint8Array[] = [];
  let at = 0;
  for (const length of lengths) {
    events.push(new Uint8Array(blob.subarray(at, at + length)));
    at += length;
  }
  if (at !== blob.length) throw new Error(`${SAMPLE}: index does not cover the blob`);
  return events;
};

const fetchSample = async (): Promise<Uint8Array[]> => {
  console.log(`fetching ${EVENTS} DUST events from ${INDEXER} (one subscription)`);
  const hex: string[] = await new Promise((resolve, reject) => {
    const socket = new WebSocket(INDEXER, "graphql-transport-ws");
    const collected: string[] = [];
    const bail = setTimeout(() => reject(new Error("indexer subscription timed out")), 180_000);
    const finish = () => {
      clearTimeout(bail);
      try {
        socket.close();
      } catch {
        /* already closing */
      }
      resolve(collected);
    };
    socket.onopen = () => socket.send(JSON.stringify({ type: "connection_init" }));
    socket.onerror = (event: any) => {
      clearTimeout(bail);
      reject(new Error(`indexer socket error: ${event?.message ?? "unknown"}`));
    };
    socket.onmessage = (event: any) => {
      const message = JSON.parse(String(event.data));
      if (message.type === "connection_ack") {
        socket.send(
          JSON.stringify({
            id: "1",
            type: "subscribe",
            payload: { query: "subscription { dustLedgerEvents { id raw } }" },
          }),
        );
      } else if (message.type === "next") {
        collected.push(message.payload.data.dustLedgerEvents.raw);
        if (collected.length >= EVENTS) finish();
      } else if (message.type === "error") {
        clearTimeout(bail);
        reject(new Error(JSON.stringify(message.payload)));
      }
    };
  });
  const events = hex.map((raw) => new Uint8Array(Buffer.from(raw, "hex")));
  mkdirSync(dirname(SAMPLE), { recursive: true });
  writeFileSync(SAMPLE, Buffer.concat(events.map((event) => Buffer.from(event))));
  writeFileSync(`${SAMPLE}.index.json`, JSON.stringify(events.map((event) => event.length)));
  console.log(`saved ${events.length} events to ${SAMPLE}`);
  return events;
};

const cached = existsSync(SAMPLE) && existsSync(`${SAMPLE}.index.json`);
const rawEvents = cached ? loadSample() : await fetchSample();
console.log(`${rawEvents.length} DUST events ${cached ? `replayed from ${SAMPLE}` : "fetched"}`);
if (rawEvents.length === 0) throw new Error("no DUST events to verify against");

const params = ledger.LedgerParameters.initialParameters();
const blank = (): any => new ledger.DustLocalState(params.dust);

for (const getter of ["commitmentTreeFirstFree", "generatingTreeFirstFree"]) {
  if (typeof blank()[getter] !== "bigint") throw new Error(`FAIL: ${getter} is not exported`);
}
for (const method of ["collapsedCommitmentUpdate", "collapsedGenerationUpdate"]) {
  if (typeof blank()[method] !== "function") throw new Error(`FAIL: ${method} is not exported`);
}
check("empty state", blank().commitmentTreeFirstFree === 0n, "commitmentTreeFirstFree is 0");

// ------------------------------------------------- the payloads the chain made

type InitialUtxo = { output: any; generation: any; generationIndex: bigint };
const initialUtxos: InitialUtxo[] = [];
/** The latest `dtime` annotation per generation nonce, keyed as spec 00016 §5.2 resolves it. */
const latestGeneration = new Map<string, any>();
for (const raw of rawEvents) {
  const content = ledger.Event.deserialize(raw).content;
  if (content?.tag === "dustInitialUtxo") {
    initialUtxos.push({
      output: content.output,
      generation: content.generation,
      generationIndex: BigInt(content.generationIndex),
    });
  } else if (content?.tag === "dustGenerationDtimeUpdate") {
    // `insertion_evidence` annotates the path with the generation entry *after* the update, so the
    // annotation is the merged entry a rebuilt leaf must carry (ledger/src/dust.rs:1226).
    const annotation = content.update?.annotation;
    if (annotation?.nonce) latestGeneration.set(String(annotation.nonce), annotation);
  }
}
if (initialUtxos.length < 8) {
  throw new Error(`need at least 8 dustInitialUtxo events, got ${initialUtxos.length}`);
}
console.log(
  `parsed ${initialUtxos.length} dustInitialUtxo events; ` +
    `${latestGeneration.size} generation entries carry a later dtime update`,
);

const LEAVES = BigInt(initialUtxos.length);
/** Three well-separated leaves, never the first or last, so every gap shape is exercised. */
const OWN = [0.25, 0.5, 0.75].map((at) => BigInt(Math.floor(initialUtxos.length * at)));

/** `[0, firstFree - 1]` minus the owned indices, ascending, never empty and never overlapping. */
const gapsAround = (owned: bigint[], firstFree: bigint): [bigint, bigint][] => {
  const ranges: [bigint, bigint][] = [];
  let start = 0n;
  for (const index of owned) {
    if (index > start) ranges.push([start, index - 1n]);
    start = index + 1n;
  }
  if (start <= firstFree - 1n) ranges.push([start, firstFree - 1n]);
  return ranges;
};

// ---------------------------- parts 1 and 2: cut the gaps, rebuild, compare roots

type Timing = { segments: number; cutMs: number[]; applyMs: number[]; insertMs: number[] };

const roundTrip = (
  tree: "commitment" | "generation",
  source: any,
  insert: (state: any, index: bigint) => any,
): Timing => {
  const cut = (state: any, s: bigint, e: bigint) =>
    tree === "commitment"
      ? state.collapsedCommitmentUpdate(s, e)
      : state.collapsedGenerationUpdate(s, e);
  const apply = (state: any, update: any) =>
    tree === "commitment"
      ? state.applyCommitmentCollapsedUpdate(update)
      : state.applyGenerationCollapsedUpdate(update);
  const firstFreeOf = (state: any): bigint =>
    tree === "commitment" ? state.commitmentTreeFirstFree : state.generatingTreeFirstFree;
  const rootOf = (state: any): string =>
    String(tree === "commitment" ? state.commitmentTreeRoot() : state.generatingTreeRoot());

  const sourceFirstFree = firstFreeOf(source);
  const ranges = gapsAround(OWN, sourceFirstFree);
  const timing: Timing = { segments: ranges.length, cutMs: [], applyMs: [], insertMs: [] };
  let rebuilt = blank();
  let nextOwn = 0;
  for (const [start, end] of ranges) {
    const cutAt = ms();
    const update = cut(source, start, end);
    timing.cutMs.push(ms() - cutAt);
    // `start`/`end` are public on the Rust type but not bound as getters; its Debug output is the
    // only place the WASM surface names the range it actually covers.
    const covers = String(update.toString(true)).match(/start:\s*(\d+),\s*end:\s*(\d+)/);
    if (!covers || BigInt(covers[1]!) !== start || BigInt(covers[2]!) !== end) {
      throw new Error(`${tree}: cut [${start},${end}] came back as ${update.toString(true)}`);
    }
    const wire = ledger.DustStateMerkleTreeCollapsedUpdate.deserialize(update.serialize());
    const applyAt = ms();
    rebuilt = apply(rebuilt, wire);
    timing.applyMs.push(ms() - applyAt);
    if (nextOwn < OWN.length && OWN[nextOwn] === end + 1n) {
      const insertAt = ms();
      rebuilt = insert(rebuilt, OWN[nextOwn]!);
      timing.insertMs.push(ms() - insertAt);
      nextOwn += 1;
    }
  }
  check(
    `${tree}: every own leaf reinserted`,
    nextOwn === OWN.length,
    `${nextOwn} of ${OWN.length}`,
  );
  check(
    `${tree}: rebuilt firstFree`,
    firstFreeOf(rebuilt) === sourceFirstFree,
    `${firstFreeOf(rebuilt)} vs source ${sourceFirstFree}`,
  );
  const sourceRoot = rootOf(source);
  check(
    `${tree}: rebuilt root`,
    rootOf(rebuilt) === sourceRoot && sourceRoot !== "undefined",
    `${ranges.length} segments around ${OWN.length} own leaves, ` +
      `${rootOf(rebuilt).slice(0, 18)}… vs source ${sourceRoot.slice(0, 18)}…`,
  );
  return timing;
};

// Part 1: a commitment tree of `initialUtxos.length` real preprod DUST outputs, nothing collapsed.
// The leaf hash is `qdo.commitment()`, which does not read `mtIndex`, so reindexing the payloads
// to 0..n-1 keeps them the chain's outputs while making the tree densely populated.
let commitmentSource = blank();
const buildStart = ms();
for (let index = 0; index < initialUtxos.length; index++) {
  commitmentSource = commitmentSource.insertCommitment(
    BigInt(index),
    { ...initialUtxos[index]!.output, mtIndex: BigInt(index) },
    true,
  );
}
// Part 2: a generating tree of the same wallets' real generation entries, each carrying the dtime
// the chain last annotated for it.
let generationSource = blank();
for (let index = 0; index < initialUtxos.length; index++) {
  const utxo = initialUtxos[index]!;
  generationSource = generationSource.insertGenerationInfo(
    BigInt(index),
    latestGeneration.get(String(utxo.generation.nonce)) ?? utxo.generation,
    String(utxo.generation.nonce),
  );
}
console.log(
  `built two ${LEAVES}-leaf source trees from preprod payloads in ${round(ms() - buildStart, 1)} ms`,
);

const commitmentTiming = roundTrip("commitment", commitmentSource, (state, index) =>
  state.insertCommitment(index, { ...initialUtxos[Number(index)]!.output, mtIndex: index }, true),
);
const generationTiming = roundTrip("generation", generationSource, (state, index) => {
  const utxo = initialUtxos[Number(index)]!;
  return state.insertGenerationInfo(
    index,
    latestGeneration.get(String(utxo.generation.nonce)) ?? utxo.generation,
    String(utxo.generation.nonce),
  );
});

// ----------------- part 3: the key-less mirror, and what it can and cannot cut

const replayStart = ms();
let mirror = blank();
for (let at = 0; at < rawEvents.length; at += 1000) {
  const batch = rawEvents.slice(at, at + 1000).map((event) => Buffer.from(event));
  mirror = mirror.replayRawEvents(ledger.sampleDustSecretKey(), Buffer.concat(batch)).state;
}
const replayMs = ms() - replayStart;
const mirrorCommitmentFirstFree = mirror.commitmentTreeFirstFree as bigint;
const mirrorGenerationFirstFree = mirror.generatingTreeFirstFree as bigint;
const mirrorCommitmentRoot = String(mirror.commitmentTreeRoot());
const mirrorGenerationRoot = String(mirror.generatingTreeRoot());
console.log(
  `\nmirror: ${rawEvents.length} events replayed in ${round(replayMs, 1)} ms ` +
    `(${round(replayMs / rawEvents.length)} ms/event), ` +
    `commitmentFirstFree=${mirrorCommitmentFirstFree}, ` +
    `generationFirstFree=${mirrorGenerationFirstFree}`,
);

const cuttable = (start: bigint, end: bigint): boolean => {
  try {
    mirror.collapsedCommitmentUpdate(start, end);
    return true;
  } catch {
    return false;
  }
};
const mirrorWholeRangeCutAt = ms();
const mirrorWholeRange = cuttable(0n, mirrorCommitmentFirstFree - 1n);
const mirrorWholeRangeMs = ms() - mirrorWholeRangeCutAt;
let cuttablePrefixes = 0;
for (let end = 0n; end < mirrorCommitmentFirstFree - 1n; end++) {
  if (cuttable(0n, end)) cuttablePrefixes++;
}
check(
  "mirror: the whole populated range is cuttable",
  mirrorWholeRange,
  `[0, ${mirrorCommitmentFirstFree - 1n}] in ${round(mirrorWholeRangeMs, 1)} ms`,
);
check(
  "mirror: arbitrary gaps are NOT cuttable (pins Q-12, not a capability)",
  cuttablePrefixes < Number(mirrorCommitmentFirstFree) / 100,
  `${cuttablePrefixes} of ${mirrorCommitmentFirstFree - 1n} prefixes [0,e] can be cut — ` +
    "replay collapses foreign leaves and MerkleTreeNode::collapse merges collapsed siblings, " +
    "so a key-less mirror cannot serve /v1/dust/segments (see 00016 Q-12)",
);

// ------------------------------------------------------------- part 4: the errors

const throws = (label: string, call: () => unknown): void => {
  let result: unknown;
  try {
    result = call();
  } catch {
    check(`refuses ${label}`, true, "threw");
    return;
  }
  check(`refuses ${label}`, false, `returned ${String(result)} instead of throwing`);
};
throws("start > end (commitment)", () => commitmentSource.collapsedCommitmentUpdate(5n, 4n));
throws("start > end (generation)", () => generationSource.collapsedGenerationUpdate(5n, 4n));
throws("end == firstFree (commitment)", () =>
  commitmentSource.collapsedCommitmentUpdate(0n, LEAVES),
);
throws("end == firstFree (generation)", () =>
  generationSource.collapsedGenerationUpdate(0n, LEAVES),
);
throws("a range far past firstFree", () =>
  commitmentSource.collapsedCommitmentUpdate(LEAVES + 1000n, LEAVES + 2000n),
);
throws("2^64 - 1 as end", () => commitmentSource.collapsedCommitmentUpdate(0n, (1n << 64n) - 1n));
throws("a negative index", () => commitmentSource.collapsedCommitmentUpdate(-1n, 5n));
throws("an index above 2^64", () => generationSource.collapsedGenerationUpdate(0n, 1n << 64n));
throws("any range on an empty state", () => blank().collapsedCommitmentUpdate(0n, 0n));

// ------------------------------------------------------------------- the report

const report = (tree: string, timing: Timing) => ({
  tree,
  segments: timing.segments,
  cutMsMedian: round(median(timing.cutMs)),
  cutMsMax: round(Math.max(...timing.cutMs)),
  applyMsMedian: round(median(timing.applyMs)),
  applyMsMax: round(Math.max(...timing.applyMs)),
  insertMsMedian: round(median(timing.insertMs)),
});
const timings = {
  events: rawEvents.length,
  sourceLeaves: Number(LEAVES),
  commitment: report("commitment", commitmentTiming),
  generation: report("generation", generationTiming),
  mirror: {
    replayMs: round(replayMs, 1),
    msPerEvent: round(replayMs / rawEvents.length),
    commitmentFirstFree: String(mirrorCommitmentFirstFree),
    generationFirstFree: String(mirrorGenerationFirstFree),
    wholeRangeCutMs: round(mirrorWholeRangeMs, 1),
    cuttablePrefixes,
  },
};
console.log(`\ntimings: ${JSON.stringify(timings, null, 1)}`);

writeFileSync(
  ROOTS_FILE,
  `${JSON.stringify(
    {
      source: INDEXER,
      events: rawEvents.length,
      sample: SAMPLE,
      // The mirror a node would hold after replaying exactly this sample: the fixture Phase 2's
      // mirror tests reproduce.
      mirror: {
        commitmentFirstFree: String(mirrorCommitmentFirstFree),
        generationFirstFree: String(mirrorGenerationFirstFree),
        commitmentRoot: mirrorCommitmentRoot,
        generationRoot: mirrorGenerationRoot,
      },
      // The uncollapsed source trees parts 1 and 2 cut from.
      retained: {
        leaves: Number(LEAVES),
        ownIndices: OWN.map(String),
        commitmentRoot: String(commitmentSource.commitmentTreeRoot()),
        generationRoot: String(generationSource.generatingTreeRoot()),
      },
      timings,
    },
    null,
    1,
  )}\n`,
);
console.log(`roots and timings written to ${ROOTS_FILE}`);

console.log(
  failures === 0
    ? "\nOK: both trees rebuild to their source roots from cut segments, " +
        "every out-of-range cut throws, and the key-less mirror's limitation is pinned"
    : `\n${failures} check(s) FAILED`,
);
process.exit(failures === 0 ? 0 : 1);
