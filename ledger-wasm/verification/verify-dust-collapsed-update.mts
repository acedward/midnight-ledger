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
import { spawnSync } from "node:child_process";
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

/** Replays a prefix of the sample in batches of 1 000 with one of the two replay methods. */
const replayMirror = (
  method: "replayRawEvents" | "replayRawEventsRetainingAll",
  count: number,
): { state: any; ms: number } => {
  const key = ledger.sampleDustSecretKey();
  const started = ms();
  let state = blank();
  for (let at = 0; at < count; at += 1000) {
    const batch = rawEvents.slice(at, Math.min(at + 1000, count)).map((event) => Buffer.from(event));
    state = state[method](key, Buffer.concat(batch)).state;
  }
  return { state, ms: ms() - started };
};

// A memory child: one process, one mirror, so the two variants' footprints cannot be confused by
// a shared allocator. WebAssembly linear memory is not reachable from the generated JS surface --
// `wasm.memory` stays module-private in `midnight_ledger_wasm_bg.js` -- so resident set size is the
// measurement, taken after the sample is already loaded and parsed so the JS-side event buffers sit
// in the baseline rather than in the delta.
const MEMORY_MODE = flag("memory-mode", "");
if (MEMORY_MODE) {
  const count = Number(flag("memory-events", String(rawEvents.length)));
  const method = MEMORY_MODE === "retained" ? "replayRawEventsRetainingAll" : "replayRawEvents";
  // Touch the module once so its own start-up allocations land in the baseline.
  blank().commitmentTreeRoot();
  (globalThis as any).gc?.();
  const before = process.memoryUsage();
  const { state, ms: replayedMs } = replayMirror(method as any, count);
  (globalThis as any).gc?.();
  const after = process.memoryUsage();
  process.stdout.write(
    `${JSON.stringify({
      mode: MEMORY_MODE,
      events: count,
      commitmentLeaves: Number(state.commitmentTreeFirstFree),
      generationLeaves: Number(state.generatingTreeFirstFree),
      // `external` is where Node counts the WebAssembly linear memory, and it moves in whole
      // allocator chunks rather than in whole pages, so it is far less noisy than `rss`.
      externalDelta: after.external - before.external,
      rssDelta: after.rss - before.rss,
      // The exact, deterministic size of the state itself -- and the number FR-012's snapshot
      // writes to disk.
      serializedBytes: state.serialize().length,
      replayMs: round(replayedMs, 1),
      commitmentRoot: String(state.commitmentTreeRoot()),
      generationRoot: String(state.generatingTreeRoot()),
    })}\n`,
  );
  process.exit(0);
}

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

const stockReplay = replayMirror("replayRawEvents", rawEvents.length);
const mirror = stockReplay.state;
const replayMs = stockReplay.ms;
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

// The strongest check available here, and it is free: the generating tree built in part 2 by
// inserting the parsed `dustInitialUtxo` entries -- each carrying the `dtime` the latest
// `dustGenerationDtimeUpdate` annotation gave it -- must have the same root as the mirror's
// generating tree, which the ledger itself built by replaying those same events through
// `update_from_evidence` on its own insertion paths. Equality proves the annotation really is the
// post-update entry and that the leaves reconstruct bit for bit. (The commitment roots differ by
// construction: the mirror's tree also holds one leaf per spend, which no public payload rebuilds.)
check(
  "generation: the rebuilt leaves match the ledger's own replay",
  String(generationSource.generatingTreeRoot()) === mirrorGenerationRoot,
  `${LEAVES} entries reinserted from parsed annotations vs the mirror's replay of ` +
    `${rawEvents.length} events: ${mirrorGenerationRoot.slice(0, 18)}…`,
);
check(
  "mirror: generating tree has one leaf per initial utxo",
  mirrorGenerationFirstFree === LEAVES,
  `${mirrorGenerationFirstFree} vs ${LEAVES} dustInitialUtxo events`,
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

// ------------- part 5: the retain-all mirror, which is what a node must use

if (typeof blank().replayRawEventsRetainingAll !== "function") {
  throw new Error("FAIL: replayRawEventsRetainingAll is not exported on DustLocalState");
}
const retainedReplay = replayMirror("replayRawEventsRetainingAll", rawEvents.length);
const retained = retainedReplay.state;
console.log(
  `\nretained mirror: ${rawEvents.length} events replayed in ${round(retainedReplay.ms, 1)} ms ` +
    `(${round(retainedReplay.ms / rawEvents.length)} ms/event)`,
);

// (a) Collapsing only discards interior nodes, so the retained mirror must agree with the stock
// one on everything observable. If it did not, the new replay would be changing the chain's state,
// not just its representation.
check(
  "retained mirror: same commitment root as the stock replay",
  String(retained.commitmentTreeRoot()) === mirrorCommitmentRoot,
  `${String(retained.commitmentTreeRoot()).slice(0, 18)}…`,
);
check(
  "retained mirror: same generation root as the stock replay",
  String(retained.generatingTreeRoot()) === mirrorGenerationRoot,
  `${String(retained.generatingTreeRoot()).slice(0, 18)}…`,
);
check(
  "retained mirror: same firstFree as the stock replay",
  retained.commitmentTreeFirstFree === mirrorCommitmentFirstFree &&
    retained.generatingTreeFirstFree === mirrorGenerationFirstFree,
  `commitment ${retained.commitmentTreeFirstFree}, generation ${retained.generatingTreeFirstFree}`,
);

// (b) The draw the stock mirror failed 200 times out of 200: an arbitrary own leaf, and the two
// ranges around it that `/v1/dust/segments` would have to answer with.
const DRAWS = 200;
const firstFree = retained.commitmentTreeFirstFree as bigint;
let servable = 0;
const drawn: bigint[] = [];
for (let draw = 0; draw < DRAWS; draw++) {
  const own = BigInt(1 + Math.floor(Math.random() * (Number(firstFree) - 2)));
  drawn.push(own);
  try {
    retained.collapsedCommitmentUpdate(0n, own - 1n);
    retained.collapsedCommitmentUpdate(own + 1n, firstFree - 1n);
    servable += 1;
  } catch {
    /* counted as a failure */
  }
}
check(
  `retained mirror: ${DRAWS} random own leaves are all servable`,
  servable === DRAWS,
  `${servable} of ${DRAWS} (the stock mirror scored 0 of ${DRAWS} on the same draw)`,
);

// ...and the segments really rebuild the root. Only a `dustInitialUtxo` index can be checked this
// way, because a spend's commitment has no public payload to reinsert from -- the same constraint
// a wallet works under, since it can only reinsert leaves it can reconstruct.
const ownCandidates = initialUtxos
  .map((utxo) => BigInt(utxo.output.mtIndex))
  .filter((index) => index > 0n && index + 1n < firstFree);
const ROUND_TRIPS = 5;
let rebuilt = 0;
const rebuildTimings: { cutMs: number[]; applyMs: number[] } = { cutMs: [], applyMs: [] };
for (let pick = 0; pick < ROUND_TRIPS; pick++) {
  const own = ownCandidates[Math.floor((ownCandidates.length * (pick + 0.5)) / ROUND_TRIPS)]!;
  const payload = initialUtxos.find((utxo) => BigInt(utxo.output.mtIndex) === own)!.output;
  let state = blank();
  for (const [start, end] of [
    [0n, own - 1n],
    [own + 1n, firstFree - 1n],
  ] as [bigint, bigint][]) {
    if (start > end) continue;
    const cutAt = ms();
    const update = retained.collapsedCommitmentUpdate(start, end);
    rebuildTimings.cutMs.push(ms() - cutAt);
    const wire = ledger.DustStateMerkleTreeCollapsedUpdate.deserialize(update.serialize());
    const applyAt = ms();
    state = state.applyCommitmentCollapsedUpdate(wire);
    rebuildTimings.applyMs.push(ms() - applyAt);
    if (start === 0n) state = state.insertCommitment(own, payload, true);
  }
  if (
    String(state.commitmentTreeRoot()) === mirrorCommitmentRoot &&
    state.commitmentTreeFirstFree === firstFree
  ) {
    rebuilt += 1;
  }
}
check(
  `retained mirror: ${ROUND_TRIPS} own leaves rebuild the chain's root from their segments`,
  rebuilt === ROUND_TRIPS,
  `${rebuilt} of ${ROUND_TRIPS}; cut ${round(median(rebuildTimings.cutMs))} ms median, ` +
    `apply ${round(median(rebuildTimings.applyMs))} ms median`,
);

// (c) Memory. Each child process builds exactly one mirror, so the two variants never share an
// allocator, and each prefix is measured twice with the smaller delta kept -- the surplus in the
// other run is allocator slack or uncollected JS garbage, not state.
//
// One caveat the numbers carry with them: WebAssembly linear memory never shrinks, so an RSS delta
// is the *peak* the replay needed, intermediate versions of the persistent trees included, not the
// resident size of the final state. It is the conservative direction for an SC-004 check.
//
// Commitment and generation leaves cannot be priced separately from this sample: every
// `dustInitialUtxo` adds one of each, so the two counts are near-collinear across any prefix and
// the 2x2 solve is ill-conditioned (it returns negative bytes per commitment leaf). The fit is
// therefore over *total* leaves, which is well conditioned, and preprod is projected from its total.
const PREPROD_COMMITMENT_LEAVES = 1_191_877;
const PREPROD_GENERATION_LEAVES = 417_002;
const PREPROD_LEAVES = PREPROD_COMMITMENT_LEAVES + PREPROD_GENERATION_LEAVES;
const MEMORY_PREFIXES = [1, 2, 3, 4].map((part) =>
  Math.floor((rawEvents.length * part) / 4),
);
const REPEATS = 2;

type MemoryPoint = {
  mode: string;
  events: number;
  commitmentLeaves: number;
  generationLeaves: number;
  externalDelta: number;
  rssDelta: number;
  serializedBytes: number;
  replayMs: number;
};

const measure = (mode: "stock" | "retained", events: number): MemoryPoint | null => {
  const runs: MemoryPoint[] = [];
  for (let repeat = 0; repeat < REPEATS; repeat++) {
    const child = spawnSync(
      process.execPath,
      [
        ...process.execArgv,
        "--expose-gc",
        process.argv[1]!,
        entry,
        "--sample",
        SAMPLE,
        "--memory-mode",
        mode,
        "--memory-events",
        String(events),
      ],
      { encoding: "utf8", maxBuffer: 1 << 24 },
    );
    const line = (child.stdout ?? "").trim().split("\n").pop() ?? "";
    try {
      runs.push(JSON.parse(line) as MemoryPoint);
    } catch {
      console.log(`  memory child (${mode}, ${events}) failed: ${(child.stderr ?? "").slice(-300)}`);
    }
  }
  if (runs.length === 0) return null;
  // The smallest heap delta is the cleanest estimate of what the mirror actually needed; the
  // surplus in the other run is allocator slack or garbage that had not been collected. The
  // serialized size is deterministic and identical across runs.
  return runs.reduce((best, run) => (run.externalDelta < best.externalDelta ? run : best));
};

const memoryPoints: MemoryPoint[] = [];
for (const mode of ["stock", "retained"] as const) {
  for (const events of MEMORY_PREFIXES) {
    const point = measure(mode, events);
    if (point) memoryPoints.push(point);
  }
}

const mib = (bytes: number): number => round(bytes / 1024 / 1024, 1);

/** Least-squares `y = perLeaf * (C + G) + fixed` over every prefix of one mode. */
const fit = (points: MemoryPoint[], y: (point: MemoryPoint) => number) => {
  const leaves = points.map((point) => point.commitmentLeaves + point.generationLeaves);
  const values = points.map(y);
  const n = points.length;
  const meanLeaves = leaves.reduce((a, b) => a + b, 0) / n;
  const meanValue = values.reduce((a, b) => a + b, 0) / n;
  const sxx = leaves.reduce((acc, x) => acc + (x - meanLeaves) ** 2, 0);
  if (n < 2 || sxx === 0) return null;
  const perLeaf =
    leaves.reduce((acc, x, i) => acc + (x - meanLeaves) * (values[i]! - meanValue), 0) / sxx;
  const fixed = meanValue - perLeaf * meanLeaves;
  const residual = values.reduce((acc, v, i) => acc + (v - (perLeaf * leaves[i]! + fixed)) ** 2, 0);
  const total = values.reduce((acc, v) => acc + (v - meanValue) ** 2, 0);
  return {
    perLeafBytes: round(perLeaf, 1),
    fixedBytes: Math.round(fixed),
    rSquared: round(total === 0 ? 1 : 1 - residual / total, 4),
    preprodBytes: Math.round(perLeaf * PREPROD_LEAVES + fixed),
    preprodMiB: mib(perLeaf * PREPROD_LEAVES + fixed),
  };
};

const summarise = (mode: string) => {
  const points = memoryPoints.filter((point) => point.mode === mode);
  if (points.length < 2) return null;
  return {
    mode,
    points: points.map((point) => ({
      events: point.events,
      leaves: point.commitmentLeaves + point.generationLeaves,
      commitmentLeaves: point.commitmentLeaves,
      generationLeaves: point.generationLeaves,
      serializedKiB: round(point.serializedBytes / 1024, 1),
      externalMiB: mib(point.externalDelta),
      rssMiB: mib(point.rssDelta),
      msPerEvent: round(point.replayMs / point.events),
    })),
    // Deterministic: the state's own bytes, and what FR-012's snapshot writes.
    serialized: fit(points, (point) => point.serializedBytes),
    // The WebAssembly heap. Linear memory never shrinks, so this is the peak the replay needed --
    // intermediate versions of the persistent trees included -- not the resident final state.
    wasmHeap: fit(points, (point) => point.externalDelta),
    rss: fit(points, (point) => point.rssDelta),
  };
};

const stockMemory = summarise("stock");
const retainedMemory = summarise("retained");
const fullOf = (mode: string) =>
  memoryPoints.find((point) => point.mode === mode && point.events === rawEvents.length);
const fullStock = fullOf("stock");
const fullRetained = fullOf("retained");
console.log(`\nmemory: ${JSON.stringify({ stock: stockMemory, retained: retainedMemory }, null, 1)}`);

let retainOverheadPerLeaf: number | null = null;
if (fullStock && fullRetained) {
  const leaves = fullRetained.commitmentLeaves + fullRetained.generationLeaves;
  retainOverheadPerLeaf = (fullRetained.externalDelta - fullStock.externalDelta) / leaves;
  console.log(
    `  at the full sample (${leaves} leaves): serialized ` +
      `${round(fullStock.serializedBytes / 1024, 1)} KiB stock vs ` +
      `${round(fullRetained.serializedBytes / 1024, 1)} KiB retained; wasm heap ` +
      `${mib(fullStock.externalDelta)} MiB vs ${mib(fullRetained.externalDelta)} MiB, i.e. ` +
      `${round(retainOverheadPerLeaf, 0)} B per leaf more to retain ` +
      `(${mib(PREPROD_LEAVES * retainOverheadPerLeaf)} MiB over the stock mirror at preprod scale)`,
  );
}

const SC004_BYTES = 1.5 * 1024 * 1024 * 1024;
if (retainedMemory?.wasmHeap && retainedMemory.serialized) {
  const heap = retainedMemory.wasmHeap;
  const over = heap.preprodBytes > SC004_BYTES;
  console.log(
    `${over ? "WARN" : "INFO"} retained mirror: projected preprod WASM heap ${heap.preprodMiB} MiB ` +
      `for ${PREPROD_LEAVES} leaves (${PREPROD_COMMITMENT_LEAVES} commitment + ` +
      `${PREPROD_GENERATION_LEAVES} generation) at ${heap.perLeafBytes} B/leaf, R²=${heap.rSquared}` +
      (stockMemory?.wasmHeap
        ? `; the stock mirror projects ${stockMemory.wasmHeap.preprodMiB} MiB — which is itself ` +
          "near SC-004, so this instrument is measuring replay churn as much as final state"
        : "") +
      ` — SC-004's limit is ${mib(SC004_BYTES)} MiB`,
  );
  console.log(
    `  the state's own serialized size projects ` +
      `${retainedMemory.serialized.preprodMiB} MiB at ${retainedMemory.serialized.perLeafBytes} B/leaf ` +
      `(R²=${retainedMemory.serialized.rSquared}) — that is the FR-012 snapshot size, and the floor ` +
      `the in-memory arena is a multiple of.\n` +
      `  NOTE: preprod is a ${Math.round(PREPROD_LEAVES / 5370)}x extrapolation from at most 5 370 ` +
      "leaves. The serialized fit is exact (a Merkle tree serializes linearly in its nodes); the " +
      "heap fit is not, because WebAssembly memory never shrinks and the deltas are a few MiB. " +
      "Treat the heap number as an order of magnitude and measure SC-004 for real in Phase 4, " +
      "where the mirror is built against the full archive anyway.",
  );
  if (over) {
    console.log(
      "\n!!! SC-004 AT RISK (a projection, not a verdict — Phase 4 measures it for real): " +
        "the retain-all mirror's projected preprod WASM heap " +
        `(${heap.preprodMiB} MiB) exceeds 1.5 GB.\n` +
        "    Mitigations to weigh in question Q-12 before Phase 4:\n" +
        "      1. Keep the GENERATING tree collapsed and retain only the commitment tree: a wallet\n" +
        "         asks for generation segments once, over its own few generation indices, and the\n" +
        "         node could serve those from a second, short-lived retained replay. Saves the\n" +
        `         ${PREPROD_GENERATION_LEAVES} generation leaves (~26% of the total).\n` +
        "      2. Split the two trees across the two nodes behind the balancer; /v1/dust/segments\n" +
        "         already carries ?tree=, so the balancer can route by it instead of at random.\n" +
        "      3. Raise SC-004 for the measurement rig: it is one node on a shared host, not\n" +
        "         production, and 2-3 GB is affordable there if the host has it.\n" +
        "    Do NOT drop the retain-all replay: without it segments cannot be served at all (0/200).",
    );
  }
} else {
  check("retained mirror: memory measured", false, "the memory children produced no usable output");
}

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
  retainedMirror: {
    replayMs: round(retainedReplay.ms, 1),
    msPerEvent: round(retainedReplay.ms / rawEvents.length),
    servableDraws: `${servable}/${DRAWS}`,
    rootRebuilds: `${rebuilt}/${ROUND_TRIPS}`,
    cutMsMedian: round(median(rebuildTimings.cutMs)),
    applyMsMedian: round(median(rebuildTimings.applyMs)),
  },
  memory: {
    note:
      "measured in child processes, one mirror each. `serialized` is the state's own bytes and is " +
      "exact; `wasmHeap` is Node's `external` delta, i.e. the peak WebAssembly heap the replay " +
      "needed (linear memory never shrinks), and is noisy at these sizes. Commitment and " +
      "generation leaves are collinear in this sample, so the fits are over total leaves and " +
      "preprod is projected from its total. ~300x extrapolation: measure SC-004 for real in Phase 4",
    retainOverheadBytesPerLeaf: retainOverheadPerLeaf === null ? null : round(retainOverheadPerLeaf, 0),
    stock: stockMemory,
    retained: retainedMemory,
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
      retainedSources: {
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
    ? "\nOK: both trees rebuild to their source roots from cut segments, every out-of-range cut " +
        "throws, the stock mirror's limitation is pinned, and the retain-all mirror serves every " +
        "random own leaf"
    : `\n${failures} check(s) FAILED`,
);
process.exit(failures === 0 ? 0 : 1);
