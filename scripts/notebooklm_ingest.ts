// scripts/notebooklm_ingest.ts
// Stoichia Synthesia Architecture — NotebookLM Batch Ingestion (HITL)
// Uses Stagehand and Browserbase to guide the user through NotebookLM upload.
//
// HITL boundary (architectural requirement)
// -----------------------------------------
// This script does NOT automate login or session handling.
// NotebookLM requires Google OAuth; automating that login is a ToS and
// credential risk. The correct boundary is:
//   - Navigate to NotebookLM (already-authenticated session in Browserbase).
//   - Observe whether the user is logged in.
//   - Guide through notebook creation and file upload.
//   - Observe upload success.
//   - Log every action to the GPAM ledger.
//   - Return control to the human.
//
// Credentials must NEVER be hard-coded.  BROWSERBASE_API_KEY and
// BROWSERBASE_PROJECT_ID are the only env vars required.

import { Stagehand } from "@browserbasehq/stagehand";
import { appendToGPAM } from "./gpam_ledger";

export interface IngestOptions {
  /** Path to the Markdown batch file exported by `gpam export-notebooklm`. */
  batchFilePath: string;
  /** Unique batch identifier (e.g. "batch-001" or a timestamp). */
  batchId: string;
}

export async function ingestToNotebookLM(options: IngestOptions): Promise<void> {
  const { batchFilePath, batchId } = options;

  if (!process.env.BROWSERBASE_API_KEY) {
    throw new Error(
      "BROWSERBASE_API_KEY is not set. Never hard-code credentials."
    );
  }
  if (!process.env.BROWSERBASE_PROJECT_ID) {
    throw new Error(
      "BROWSERBASE_PROJECT_ID is not set. Never hard-code credentials."
    );
  }

  const stagehand = new Stagehand({
    env: "BROWSERBASE",
    apiKey: process.env.BROWSERBASE_API_KEY,
    projectId: process.env.BROWSERBASE_PROJECT_ID,
  });

  await stagehand.init();
  const page = stagehand.page;

  try {
    // 1. Navigate to NotebookLM.
    await page.goto("https://notebooklm.google.com/");

    appendToGPAM({
      event_type: "browser_navigate",
      target: "notebooklm",
      url: "https://notebooklm.google.com/",
      batch_id: batchId,
    });

    // 2. Observe login state — do NOT automate Google OAuth.
    //    We ask Stagehand to extract a structured state code rather than
    //    parsing free-form observation text, avoiding fragile string matching.
    type LoginStateCode = "LOGGED_IN" | "NOT_LOGGED_IN" | "UNKNOWN";

    const loginStateCode: LoginStateCode = await page.extract({
      instruction:
        'Determine whether the user is logged in to NotebookLM. ' +
        'Return exactly one of these codes: ' +
        '"LOGGED_IN" if a "New Notebook" button or notebook list is visible, ' +
        '"NOT_LOGGED_IN" if a Google sign-in or account-picker page is shown, ' +
        '"UNKNOWN" if you cannot determine the state.',
      schema: {
        type: "object",
        properties: {
          code: { type: "string", enum: ["LOGGED_IN", "NOT_LOGGED_IN", "UNKNOWN"] },
        },
        required: ["code"],
      },
    }).then((r: { code: LoginStateCode }) => r.code).catch(() => "UNKNOWN" as LoginStateCode);

    appendToGPAM({
      event_type: "login_state_observed",
      target: "notebooklm",
      batch_id: batchId,
      login_state: loginStateCode,
    });

    if (loginStateCode !== "LOGGED_IN") {
      appendToGPAM({
        event_type: "notebooklm_batch_ingest",
        target: "notebooklm",
        batch_id: batchId,
        status: "blocked_requires_login",
        message: "Human must log in to NotebookLM first; re-run after auth.",
      });
      console.warn(
        `[HITL] Batch ${batchId}: NotebookLM requires login (state=${loginStateCode}). ` +
          "Log in manually and re-run this script."
      );
      return;
    }

    // 3. Create a new Notebook (no credential operations involved).
    await page.act(
      'Click the "New Notebook" or "+" button to create a new notebook'
    );
    await page.act(
      `Type "Batch_Ingest_${batchId}" into the notebook title field and press Enter`
    );

    appendToGPAM({
      event_type: "notebook_created",
      target: "notebooklm",
      batch_id: batchId,
      notebook_title: `Batch_Ingest_${batchId}`,
    });

    // 4. Initiate source upload — guide, do not automate file-system access.
    await page.act('Click the "Add Source" button or equivalent');
    await page.act(
      'Select the "Upload File" option from the source type menu'
    );

    // Attach the Markdown batch file through the standard file input.
    // This is a browser file-picker interaction, not a credential operation.
    const fileInput = await page.locator('input[type="file"]');
    await fileInput.setInputFiles(batchFilePath);

    appendToGPAM({
      event_type: "source_upload_initiated",
      target: "notebooklm",
      batch_id: batchId,
      file_path: batchFilePath,
    });

    // 5. Observe upload completion (observe, do not act).
    const uploadResult = await page.observe(
      "Wait for the uploaded file to finish processing and appear " +
        "in the sources list. Report SUCCESS or PROCESSING or ERROR."
    );

    appendToGPAM({
      event_type: "upload_observed",
      target: "notebooklm",
      batch_id: batchId,
      observation: String(uploadResult),
    });

    // 6. Final GPAM ledger entry — mandatory for legal arc automations.
    appendToGPAM({
      event_type: "notebooklm_batch_ingest",
      target: "notebooklm",
      batch_id: batchId,
      status: "guided_upload_complete",
      note:
        "Human must export NotebookLM output as Markdown and commit to " +
        "synthesis/notebooklm/<batch_id>/<timestamp>.md before it is canonical.",
    });

    console.log(
      `[HITL] Batch ${batchId}: upload guided. ` +
        "Export NotebookLM output as Markdown and commit it to Git."
    );
  } catch (err: unknown) {
    appendToGPAM({
      event_type: "notebooklm_batch_ingest",
      target: "notebooklm",
      batch_id: batchId,
      status: "error",
      error: err instanceof Error ? err.message : String(err),
    });
    throw err;
  } finally {
    // Session leaks are a hard FAIL — always close explicitly.
    await stagehand.close();
  }
}

// ── CLI entry point ─────────────────────────────────────────────────────────
// Usage: npx ts-node notebooklm_ingest.ts <batch-file-path> <batch-id>

if (require.main === module) {
  const [, , batchFilePath, batchId] = process.argv;

  if (!batchFilePath || !batchId) {
    console.error(
      "Usage: npx ts-node notebooklm_ingest.ts <batch-file-path> <batch-id>"
    );
    process.exit(1);
  }

  ingestToNotebookLM({ batchFilePath, batchId })
    .then(() => {
      console.log(`✓ Batch ${batchId} guided successfully.`);
    })
    .catch((err: unknown) => {
      console.error("✗ Ingestion failed:", err);
      process.exit(1);
    });
}
