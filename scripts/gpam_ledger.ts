/**
 * scripts/gpam_ledger.ts
 * GPAM local JSONL ledger — SHA-256 hash-chained, append-only.
 *
 * Mirrors the Python AkashicDB pattern from warden/akashic.py:
 *   chain_hash = sha256(prev_chain_hash + canonical_json(entry))
 *
 * Design decisions
 * ----------------
 * - Uses synchronous fs calls so the ledger is guaranteed written before the
 *   browser session closes (fire-and-forget would lose entries on crash).
 * - Path defaults to GPAM_LEDGER_PATH env var, then ./gpam_ledger.jsonl.
 * - No external dependencies — only Node.js built-ins.
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

const LEDGER_FILE: string =
  process.env.GPAM_LEDGER_PATH ??
  path.join(process.cwd(), "gpam_ledger.jsonl");

const GENESIS_HASH: string = "0".repeat(64);

export interface GpamEvent {
  event_type: string;
  [key: string]: unknown;
}

interface LedgerEntry {
  event: GpamEvent;
  timestamp: string;
  prev_hash: string;
  chain_hash: string;
}

/** Return compact, key-sorted JSON (deterministic across invocations). */
function canonicalJson(obj: unknown): string {
  return JSON.stringify(obj, (_, v) =>
    v !== null && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v as object).sort())
      : v
  );
}

/** Return the SHA-256 hex digest of a UTF-8 string. */
function sha256Hex(data: string): string {
  return crypto.createHash("sha256").update(data, "utf8").digest("hex");
}

/**
 * Read the chain_hash of the last entry in the ledger.
 * Returns the genesis sentinel if the file does not exist or is empty.
 */
function getPrevHash(): string {
  if (!fs.existsSync(LEDGER_FILE)) {
    return GENESIS_HASH;
  }
  const content = fs.readFileSync(LEDGER_FILE, "utf8").trim();
  if (!content) {
    return GENESIS_HASH;
  }
  const lines = content.split("\n").filter(Boolean);
  if (lines.length === 0) {
    return GENESIS_HASH;
  }
  const last = JSON.parse(lines[lines.length - 1]) as LedgerEntry;
  return last.chain_hash;
}

/**
 * Append a GPAM event to the local hash-chained JSONL ledger.
 *
 * The ledger file is created automatically if it does not exist.
 * This function is synchronous — the entry is on disk before it returns.
 *
 * @param event - Structured event object; must include `event_type`.
 */
export function appendToGPAM(event: GpamEvent): void {
  const prevHash = getPrevHash();
  const timestamp = new Date().toISOString();

  const entryData = {
    event,
    timestamp,
    prev_hash: prevHash,
  };

  const chainHash = sha256Hex(prevHash + canonicalJson(entryData));

  const entry: LedgerEntry = { ...entryData, chain_hash: chainHash };

  // Ensure parent directory exists
  const dir = path.dirname(LEDGER_FILE);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.appendFileSync(LEDGER_FILE, JSON.stringify(entry) + "\n", "utf8");
}
