import express from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { spawn } from "child_process";
import { fileURLToPath } from "url";
import multer from "multer";

const router = express.Router();

/* ==========================================================================
   PATH CONFIGURATION
   ========================================================================== */

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const FORENSIC_ROOT = path.resolve(
  process.env.FORENSIC_ROOT ||
    path.join(__dirname, "../../forensic_recovery")
);

const EVIDENCE_DIR = path.join(
  FORENSIC_ROOT,
  "evidence"
);

const RECOVERED_DIR = path.join(
  FORENSIC_ROOT,
  "recovered"
);

const REPORTS_DIR = path.join(
  FORENSIC_ROOT,
  "reports"
);

const MANIFESTS_DIR = path.join(
  FORENSIC_ROOT,
  "manifests"
);

const CASES_DIR = path.join(
  FORENSIC_ROOT,
  "cases"
);

const JOBS_DIR = path.join(
  FORENSIC_ROOT,
  "jobs"
);

const CLI_PATH = path.join(
  FORENSIC_ROOT,
  "cli.py"
);

/* ==========================================================================
   CONFIGURATION
   ========================================================================== */

const MAX_UPLOAD_BYTES =
  Number(
    process.env.FORENSIC_MAX_UPLOAD_BYTES
  ) ||
  5 * 1024 * 1024 * 1024;

const SCAN_TIMEOUT_MS =
  Number(
    process.env.FORENSIC_SCAN_TIMEOUT_MS
  ) ||
  30 * 60 * 1000;

const MAX_OUTPUT =
  Number(
    process.env.FORENSIC_MAX_PROCESS_OUTPUT
  ) ||
  4 * 1024 * 1024;

const FORENSIC_PYTHON =
  process.env.FORENSIC_PYTHON ||
  (
    process.platform === "win32"
      ? "python"
      : "python3"
  );

const REQUIRE_AUTH =
  String(
    process.env.FORENSIC_REQUIRE_AUTH ||
      "false"
  ).toLowerCase() === "true";

const FORENSIC_API_KEY =
  process.env.FORENSIC_API_KEY || "";

const FORENSIC_EXECUTION_MODE =
  String(
    process.env.FORENSIC_EXECUTION_MODE ||
      "local"
  ).toLowerCase();

/*
 * Supported:
 *
 * local
 *   Backend directly executes forensic Python.
 *
 * agent
 *   Backend creates a forensic job and dispatches it
 *   to the TrustWipe Agent.
 *
 * auto
 *   Use agent if an Agent bridge is available,
 *   otherwise fall back to local execution.
 */
const VALID_EXECUTION_MODES = [
  "local",
  "agent",
  "auto",
];

/* ==========================================================================
   DIRECTORY INITIALIZATION
   ========================================================================== */

for (const directory of [
  FORENSIC_ROOT,
  EVIDENCE_DIR,
  RECOVERED_DIR,
  REPORTS_DIR,
  MANIFESTS_DIR,
  CASES_DIR,
  JOBS_DIR,
]) {
  fs.mkdirSync(directory, {
    recursive: true,
  });
}

/* ==========================================================================
   ACCESS CONTROL
   ========================================================================== */

function forensicAccess(req, res, next) {
  if (!REQUIRE_AUTH) {
    return next();
  }

  if (req.user) {
    return next();
  }

  const suppliedKey =
    req.get("x-forensic-api-key");

  if (
    FORENSIC_API_KEY &&
    suppliedKey &&
    crypto.timingSafeEqual(
      Buffer.from(suppliedKey),
      Buffer.from(FORENSIC_API_KEY)
    )
  ) {
    return next();
  }

  return res.status(401).json({
    success: false,
    code: "FORENSIC_UNAUTHORIZED",
    message:
      "Authentication is required to access forensic evidence.",
  });
}

router.use(forensicAccess);

/* ==========================================================================
   RESPONSE HELPERS
   ========================================================================== */

function fail(
  res,
  status,
  message,
  code,
  error = null
) {
  const response = {
    success: false,
    message,
  };

  if (code) {
    response.code = code;
  }

  if (
    process.env.NODE_ENV !== "production" &&
    error
  ) {
    response.details =
      error.message;
  }

  return res.status(status).json(
    response
  );
}

/* ==========================================================================
   SECURITY HELPERS
   ========================================================================== */

function decodeOriginalFilename(
  filename
) {
  if (!filename) {
    return "evidence";
  }

  let decoded =
    String(filename);

  try {
    const repaired =
      Buffer.from(
        decoded,
        "latin1"
      ).toString("utf8");

    if (
      repaired &&
      repaired !== decoded &&
      !repaired.includes("\uFFFD")
    ) {
      decoded = repaired;
    }
  } catch {
    // Preserve original filename.
  }

  return decoded;
}

function sanitizeFilename(
  filename
) {
  const decoded =
    decodeOriginalFilename(
      filename
    );

  const basename =
    path.basename(decoded);

  const safe =
    basename
      .replace(
        /[<>:"/\\|?*\x00-\x1F]/g,
        "_"
      )
      .replace(
        /\s+/g,
        "_"
      )
      .replace(
        /^\.+/,
        ""
      )
      .trim();

  return safe || "evidence";
}

function sanitizeCaseId(
  caseId
) {
  const value =
    String(caseId || "")
      .trim()
      .replace(
        /[^a-zA-Z0-9_-]/g,
        "_"
      )
      .replace(
        /_+/g,
        "_"
      )
      .slice(0, 100);

  if (!value) {
    const error =
      new Error(
        "Case ID is required."
      );

    error.code =
      "CASE_ID_REQUIRED";

    throw error;
  }

  return value;
}

function sanitizeExaminer(
  examiner
) {
  const value =
    String(examiner || "")
      .trim()
      .slice(0, 200);

  if (!value) {
    const error =
      new Error(
        "Examiner is required."
      );

    error.code =
      "EXAMINER_REQUIRED";

    throw error;
  }

  return value;
}

/* ==========================================================================
   SAFE PATH
   ========================================================================== */

function safePath(
  rootDirectory,
  requestedName
) {
  if (!requestedName) {
    const error =
      new Error(
        "File name is required."
      );

    error.code =
      "FILE_NAME_REQUIRED";

    throw error;
  }

  const root =
    path.resolve(
      rootDirectory
    );

  const normalized =
    String(requestedName)
      .replace(
        /\\/g,
        "/"
      );

  const target =
    path.resolve(
      root,
      normalized
    );

  if (
    target !== root &&
    !target.startsWith(
      root + path.sep
    )
  ) {
    const error =
      new Error(
        "Invalid file path."
      );

    error.code =
      "INVALID_FILE_PATH";

    throw error;
  }

  return target;
}

function evidencePath(
  fileName
) {
  return safePath(
    EVIDENCE_DIR,
    path.basename(
      String(fileName)
    )
  );
}

function caseDirectory(
  caseId
) {
  return safePath(
    CASES_DIR,
    sanitizeCaseId(caseId)
  );
}

function caseRecoveredDirectory(
  caseId
) {
  return safePath(
    caseDirectory(caseId),
    "recovered"
  );
}

function caseMetadataDirectory(
  caseId
) {
  return safePath(
    caseDirectory(caseId),
    "metadata"
  );
}

function reportPath(
  fileName
) {
  return safePath(
    REPORTS_DIR,
    fileName
  );
}

function jobPath(
  jobId
) {
  return safePath(
    JOBS_DIR,
    `${jobId}.json`
  );
}

/* ==========================================================================
   ID GENERATORS
   ========================================================================== */

function randomId(
  prefix,
  bytes = 5
) {
  return [
    prefix,
    Date.now(),
    crypto
      .randomBytes(bytes)
      .toString("hex"),
  ].join("-");
}

function createEvidenceId() {
  return randomId(
    "EV",
    6
  );
}

function createJobId() {
  return randomId(
    "FJ",
    5
  );
}

function createOperationId() {
  return randomId(
    "OP",
    5
  );
}

/* ==========================================================================
   MULTER
   ========================================================================== */

const storage =
  multer.diskStorage({
    destination: (
      _req,
      _file,
      cb
    ) => {
      cb(
        null,
        EVIDENCE_DIR
      );
    },

    filename: (
      _req,
      file,
      cb
    ) => {
      try {
        const safe =
          sanitizeFilename(
            file.originalname
          );

        const extension =
          path.extname(
            safe
          );

        const base =
          path.basename(
            safe,
            extension
          );

        let candidate =
          safe;

        let counter = 1;

        while (
          fs.existsSync(
            path.join(
              EVIDENCE_DIR,
              candidate
            )
          )
        ) {
          candidate =
            `${base}_${counter}${extension}`;

          counter += 1;
        }

        cb(
          null,
          candidate
        );
      } catch (error) {
        cb(error);
      }
    },
  });

const upload =
  multer({
    storage,

    limits: {
      fileSize:
        MAX_UPLOAD_BYTES,
    },

    fileFilter: (
      _req,
      _file,
      cb
    ) => {
      /*
       * Forensic evidence can be:
       *
       * IMG
       * BIN
       * DD
       * E01
       * ISO
       * memory dumps
       * unknown binary files
       *
       * Therefore MIME filtering is intentionally disabled.
       */
      cb(
        null,
        true
      );
    },
  });

/* ==========================================================================
   SHA-256
   ========================================================================== */

async function calculateSHA256(
  filePath
) {
  const hash =
    crypto.createHash(
      "sha256"
    );

  await new Promise(
    (
      resolve,
      reject
    ) => {
      const stream =
        fs.createReadStream(
          filePath,
          {
            highWaterMark:
              1024 * 1024,
          }
        );

      stream.on(
        "data",
        (chunk) => {
          hash.update(
            chunk
          );
        }
      );

      stream.once(
        "error",
        reject
      );

      stream.once(
        "end",
        resolve
      );
    }
  );

  return hash.digest(
    "hex"
  );
}

/* ==========================================================================
   MANIFESTS
   ========================================================================== */

async function saveManifest(
  manifest
) {
  const target =
    safePath(
      MANIFESTS_DIR,
      `${manifest.evidence_id}.json`
    );

  const temporary =
    `${target}.${process.pid}.tmp`;

  await fs.promises.writeFile(
    temporary,
    JSON.stringify(
      manifest,
      null,
      2
    ),
    "utf8"
  );

  await fs.promises.rename(
    temporary,
    target
  );

  return target;
}

async function loadManifestByEvidenceId(
  evidenceId
) {
  if (!evidenceId) {
    return null;
  }

  const file =
    safePath(
      MANIFESTS_DIR,
      `${evidenceId}.json`
    );

  try {
    return JSON.parse(
      await fs.promises.readFile(
        file,
        "utf8"
      )
    );
  } catch {
    return null;
  }
}

async function loadManifest(
  fileName
) {
  const entries =
    await fs.promises.readdir(
      MANIFESTS_DIR,
      {
        withFileTypes:
          true,
      }
    );

  for (
    const entry of entries
  ) {
    if (
      !entry.isFile() ||
      !entry.name.endsWith(
        ".json"
      )
    ) {
      continue;
    }

    try {
      const manifest =
        JSON.parse(
          await fs.promises.readFile(
            path.join(
              MANIFESTS_DIR,
              entry.name
            ),
            "utf8"
          )
        );

      if (
        manifest.file_name ===
        fileName
      ) {
        return manifest;
      }

      if (
        manifest.original_name ===
        fileName
      ) {
        return manifest;
      }
    } catch (error) {
      console.warn(
        "[Forensics] Invalid manifest:",
        entry.name,
        error.message
      );
    }
  }

  return null;
}

/* ==========================================================================
   INTEGRITY
   ========================================================================== */

async function verifyEvidenceIntegrity(
  fileName
) {
  const safeName =
    sanitizeFilename(
      fileName
    );

  const filePath =
    evidencePath(
      safeName
    );

  let stats;

  try {
    stats =
      await fs.promises.stat(
        filePath
      );
  } catch {
    const error =
      new Error(
        "Evidence file not found."
      );

    error.code =
      "EVIDENCE_NOT_FOUND";

    throw error;
  }

  if (!stats.isFile()) {
    const error =
      new Error(
        "Evidence path is not a file."
      );

    error.code =
      "EVIDENCE_NOT_FILE";

    throw error;
  }

  const manifest =
    await loadManifest(
      safeName
    );

  const currentHash =
    await calculateSHA256(
      filePath
    );

  if (!manifest) {
    return {
      status:
        "BASELINE_MISSING",

      verified: false,

      hashMatch: false,

      sizeMatch: false,

      originalHash: null,

      currentHash,

      originalSize: null,

      currentSize:
        stats.size,

      evidenceId: null,

      acquiredAt: null,

      originalSourceModified:
        null,

      message:
        "Evidence acquisition baseline is missing. Re-acquire the evidence.",
    };
  }

  const originalHash =
    String(
      manifest.sha256 ||
        ""
    )
      .trim()
      .toLowerCase();

  const validOriginalHash =
    /^[a-f0-9]{64}$/.test(
      originalHash
    );

  const validCurrentHash =
    /^[a-f0-9]{64}$/.test(
      currentHash
    );

  let hashMatch =
    false;

  if (
    validOriginalHash &&
    validCurrentHash
  ) {
    hashMatch =
      crypto.timingSafeEqual(
        Buffer.from(
          currentHash,
          "hex"
        ),
        Buffer.from(
          originalHash,
          "hex"
        )
      );
  }

  const sizeMatch =
    Number(
      manifest.size
    ) ===
    Number(
      stats.size
    );

  const verified =
    hashMatch &&
    sizeMatch;

  return {
    status:
      verified
        ? "VERIFIED"
        : "TAMPERED",

    verified,

    hashMatch,

    sizeMatch,

    originalSourceModified:
      !verified,

    originalHash:
      manifest.sha256 ||
      null,

    currentHash,

    acquiredAt:
      manifest.acquired_at ||
      null,

    evidenceId:
      manifest.evidence_id ||
      null,

    originalSize:
      manifest.size ??
      null,

    currentSize:
      stats.size,

    message:
      verified
        ? "Evidence integrity verified."
        : "Evidence integrity verification failed. Current evidence differs from acquisition baseline.",
  };
}

/* ==========================================================================
   EVIDENCE DISCOVERY
   ========================================================================== */

async function discoverEvidence() {
  const entries =
    await fs.promises.readdir(
      EVIDENCE_DIR,
      {
        withFileTypes:
          true,
      }
    );

  const result = [];

  for (
    const entry of entries
  ) {
    if (!entry.isFile()) {
      continue;
    }

    const filePath =
      path.join(
        EVIDENCE_DIR,
        entry.name
      );

    const stats =
      await fs.promises.stat(
        filePath
      );

    const manifest =
      await loadManifest(
        entry.name
      );

    let integrityStatus =
      "BASELINE_MISSING";

    if (manifest?.sha256) {
      integrityStatus =
        "BASELINE_AVAILABLE";
    }

    result.push({
      id:
        manifest?.evidence_id ||
        `${entry.name}-${stats.size}-${stats.mtimeMs}`,

      evidenceId:
        manifest?.evidence_id ||
        null,

      name:
        entry.name,

      originalName:
        manifest?.original_name ||
        entry.name,

      size:
        stats.size,

      type:
        path.extname(
          entry.name
        )
          .slice(1)
          .toUpperCase() ||
        "FILE",

      modifiedAt:
        stats.mtime,

      acquiredAt:
        manifest?.acquired_at ||
        null,

      acquisitionHash:
        manifest?.sha256 ||
        null,

      sha256:
        manifest?.sha256 ||
        null,

      integrityStatus,
    });
  }

  return result.sort(
    (a, b) =>
      new Date(
        b.modifiedAt
      ) -
      new Date(
        a.modifiedAt
      )
  );
}

/* ==========================================================================
   PYTHON STATUS
   ========================================================================== */

async function checkPython() {
  return new Promise(
    (resolve) => {
      const child =
        spawn(
          FORENSIC_PYTHON,
          ["--version"],
          {
            cwd:
              FORENSIC_ROOT,

            windowsHide:
              true,
          }
        );

      let output = "";

      child.stdout?.on(
        "data",
        (data) => {
          output +=
            data.toString();
        }
      );

      child.stderr?.on(
        "data",
        (data) => {
          output +=
            data.toString();
        }
      );

      let finished =
        false;

      const complete =
        (value) => {
          if (finished) {
            return;
          }

          finished =
            true;

          resolve(
            value
          );
        };

      child.once(
        "error",
        (error) => {
          complete({
            available:
              false,

            version:
              null,

            error:
              error.message,
          });
        }
      );

      child.once(
        "close",
        (code) => {
          complete({
            available:
              code === 0,

            version:
              output.trim() ||
              null,

            error:
              code === 0
                ? null
                : "Python unavailable.",
          });
        }
      );
    }
  );
}

/* ==========================================================================
   JOB STORAGE
   ========================================================================== */

async function saveJob(
  job
) {
  const target =
    jobPath(
      job.jobId
    );

  const temporary =
    `${target}.${process.pid}.tmp`;

  await fs.promises.writeFile(
    temporary,
    JSON.stringify(
      job,
      null,
      2
    ),
    "utf8"
  );

  await fs.promises.rename(
    temporary,
    target
  );

  return job;
}

async function getJob(
  jobId
) {
  const safeJobId =
    String(
      jobId || ""
    )
      .trim()
      .replace(
        /[^a-zA-Z0-9_-]/g,
        "_"
      );

  if (!safeJobId) {
    return null;
  }

  try {
    return JSON.parse(
      await fs.promises.readFile(
        jobPath(
          safeJobId
        ),
        "utf8"
      )
    );
  } catch {
    return null;
  }
}

async function updateJob(
  jobId,
  patch
) {
  const job =
    await getJob(
      jobId
    );

  if (!job) {
    return null;
  }

  Object.assign(
    job,
    patch,
    {
      updatedAt:
        new Date().toISOString(),
    }
  );

  await saveJob(
    job
  );

  return job;
}

async function discoverJobs() {
  const entries =
    await fs.promises.readdir(
      JOBS_DIR,
      {
        withFileTypes:
          true,
      }
    );

  const jobs = [];

  for (
    const entry of entries
  ) {
    if (
      !entry.isFile() ||
      !entry.name.endsWith(
        ".json"
      )
    ) {
      continue;
    }

    try {
      jobs.push(
        JSON.parse(
          await fs.promises.readFile(
            path.join(
              JOBS_DIR,
              entry.name
            ),
            "utf8"
          )
        )
      );
    } catch {
      // Ignore invalid job files.
    }
  }

  return jobs.sort(
    (a, b) =>
      new Date(
        b.createdAt
      ) -
      new Date(
        a.createdAt
      )
  );
}

/* ==========================================================================
   CHAIN OF CUSTODY
   ========================================================================== */

async function appendChainOfCustody(
  caseId,
  action,
  details = {}
) {
  const directory =
    caseDirectory(
      caseId
    );

  await fs.promises.mkdir(
    directory,
    {
      recursive:
        true,
    }
  );

  const filePath =
    safePath(
      directory,
      "chain_of_custody.jsonl"
    );

  const event = {
    eventId:
      randomId(
        "COC",
        5
      ),

    caseId:
      sanitizeCaseId(
        caseId
      ),

    timestamp:
      new Date().toISOString(),

    action,

    details,
  };

  await fs.promises.appendFile(
    filePath,
    JSON.stringify(
      event
    ) + "\n",
    "utf8"
  );

  return event;
}

async function readChainOfCustody(
  caseId
) {
  const filePath =
    safePath(
      caseDirectory(
        caseId
      ),
      "chain_of_custody.jsonl"
    );

  try {
    const content =
      await fs.promises.readFile(
        filePath,
        "utf8"
      );

    return content
      .split("\n")
      .filter(Boolean)
      .map(
        (line) => {
          try {
            return JSON.parse(
              line
            );
          } catch {
            return null;
          }
        }
      )
      .filter(Boolean);
  } catch {
    return [];
  }
}

/* ==========================================================================
   PYTHON FORENSIC SCAN
   ========================================================================== */

function runPythonScan({
  evidenceFile,
  outputDirectory,
  caseId,
  examiner,
  jobId,
}) {
  return new Promise(
    async (
      resolve,
      reject
    ) => {
      if (
        !fs.existsSync(
          CLI_PATH
        )
      ) {
        const error =
          new Error(
            `Forensic CLI not found: ${CLI_PATH}`
          );

        error.code =
          "FORENSIC_CLI_MISSING";

        reject(error);
        return;
      }

      const python =
        await checkPython();

      if (!python.available) {
        const error =
          new Error(
            `Python forensic engine unavailable: ${
              python.error ||
              "unknown error"
            }`
          );

        error.code =
          "FORENSIC_PYTHON_MISSING";

        reject(error);
        return;
      }

      await fs.promises.mkdir(
        outputDirectory,
        {
          recursive:
            true,
        }
      );

      const args = [
        CLI_PATH,
        "scan",

        "--input",
        evidenceFile,

        "--output",
        outputDirectory,

        "--case",
        caseId,

        "--examiner",
        examiner,

        "--json",
      ];

      console.log(
        "[Forensics] Python scan:",
        {
          jobId,
          caseId,
        }
      );

      const child =
        spawn(
          FORENSIC_PYTHON,
          args,
          {
            cwd:
              FORENSIC_ROOT,

            windowsHide:
              true,

            env: {
              ...process.env,

              TRUSTWIPE_FORENSIC_JOB_ID:
                jobId,

              TRUSTWIPE_FORENSIC_CASE_ID:
                caseId,

              TRUSTWIPE_FORENSIC_EXAMINER:
                examiner,
            },
          }
        );

      let stdout = "";
      let stderr = "";

      let settled =
        false;

      const appendOutput =
        (
          current,
          chunk
        ) => {
          const next =
            current +
            chunk.toString();

          if (
            next.length >
            MAX_OUTPUT
          ) {
            return next.slice(
              next.length -
                MAX_OUTPUT
            );
          }

          return next;
        };

      const timer =
        setTimeout(
          () => {
            if (settled) {
              return;
            }

            settled =
              true;

            try {
              child.kill(
                "SIGTERM"
              );
            } catch {}

            const error =
              new Error(
                "Forensic analysis timed out."
              );

            error.code =
              "FORENSIC_TIMEOUT";

            reject(
              error
            );
          },
          SCAN_TIMEOUT_MS
        );

      child.stdout.on(
        "data",
        (data) => {
          stdout =
            appendOutput(
              stdout,
              data
            );
        }
      );

      child.stderr.on(
        "data",
        (data) => {
          stderr =
            appendOutput(
              stderr,
              data
            );
        }
      );

      child.once(
        "error",
        (error) => {
          if (settled) {
            return;
          }

          settled =
            true;

          clearTimeout(
            timer
          );

          reject(
            error
          );
        }
      );

      child.once(
        "close",
        (
          code,
          signal
        ) => {
          if (settled) {
            return;
          }

          settled =
            true;

          clearTimeout(
            timer
          );

          if (code !== 0) {
            const error =
              new Error(
                stderr.trim() ||
                  stdout.trim() ||
                  `Python forensic engine exited with code ${code}${
                    signal
                      ? ` (${signal})`
                      : ""
                  }`
              );

            error.code =
              "FORENSIC_ENGINE_FAILED";

            error.stdout =
              stdout;

            error.stderr =
              stderr;

            reject(
              error
            );

            return;
          }

          let result =
            null;

          try {
            result =
              JSON.parse(
                stdout.trim()
              );
          } catch {
            const start =
              stdout.indexOf(
                "{"
              );

            const end =
              stdout.lastIndexOf(
                "}"
              );

            if (
              start !== -1 &&
              end !== -1 &&
              end > start
            ) {
              try {
                result =
                  JSON.parse(
                    stdout.slice(
                      start,
                      end + 1
                    )
                  );
              } catch {
                result =
                  null;
              }
            }
          }

          resolve({
            result,
            stdout,
            stderr,
          });
        }
      );
    }
  );
}

/* ==========================================================================
   ARTIFACT NORMALIZATION
   ========================================================================== */

function normalizeArtifacts(
  artifacts
) {
  if (
    !Array.isArray(
      artifacts
    )
  ) {
    return [];
  }

  return artifacts.map(
    (
      artifact,
      index
    ) => ({
      artifactId:
        artifact.artifact_id ||
        artifact.artifactId ||
        `ART-${String(
          index + 1
        ).padStart(
          6,
          "0"
        )}`,

      name:
        artifact.name ||
        artifact.file_name ||
        artifact.filename ||
        path.basename(
          artifact.output ||
            artifact.output_path ||
            `artifact-${index + 1}`
        ),

      size:
        Number(
          artifact.size ||
            0
        ),

      type:
        artifact.type ||
        artifact.format ||
        "FILE",

      sourceOffset:
        artifact.source_offset ??
        artifact.offset ??
        null,

      sourceEnd:
        artifact.source_end ??
        artifact.end_offset ??
        null,

      confidence:
        artifact.confidence ??
        null,

      validationStatus:
        artifact.validation_status ||
        artifact.validation ||
        (
          artifact.valid ===
          true
            ? "VALID"
            : "UNKNOWN"
        ),

      sha256:
        artifact.sha256 ||
        artifact.artifact_sha256 ||
        null,

      recoveryMethod:
        artifact.recovery_method ||
        "SIGNATURE_CARVING",

      output:
        artifact.output ||
        artifact.output_path ||
        null,

      status:
        artifact.status ||
        "RECOVERED",
    })
  );
}

/* ==========================================================================
   RECOVERED FILE DISCOVERY
   ========================================================================== */

async function discoverRecoveredFiles(
  caseId
) {
  const directory =
    caseRecoveredDirectory(
      caseId
    );

  await fs.promises.mkdir(
    directory,
    {
      recursive:
        true,
    }
  );

  const entries =
    await fs.promises.readdir(
      directory,
      {
        withFileTypes:
          true,
      }
    );

  const files = [];

  for (
    const entry of entries
  ) {
    if (!entry.isFile()) {
      continue;
    }

    const filePath =
      safePath(
        directory,
        entry.name
      );

    const stats =
      await fs.promises.stat(
        filePath
      );

    let sha256 =
      null;

    try {
      sha256 =
        await calculateSHA256(
          filePath
        );
    } catch {
      // Hash remains null.
    }

    files.push({
      artifactId:
        `${sanitizeCaseId(
          caseId
        )}-${entry.name}`,

      name:
        entry.name,

      size:
        stats.size,

      type:
        path.extname(
          entry.name
        )
          .slice(1)
          .toUpperCase() ||
        "FILE",

      modifiedAt:
        stats.mtime,

      validationStatus:
        "VALIDATED",

      sha256,

      status:
        "RECOVERED",

      recoveryMethod:
        "SIGNATURE_CARVING",

      path:
        `/api/forensic/recovered/${encodeURIComponent(
          sanitizeCaseId(
            caseId
          )
        )}/${encodeURIComponent(
          entry.name
        )}`,
    });
  }

  return files.sort(
    (a, b) =>
      new Date(
        b.modifiedAt
      ) -
      new Date(
        a.modifiedAt
      )
  );
}

/* ==========================================================================
   SCAN RESULT PROCESSING
   ========================================================================== */

async function buildScanResult({
  caseId,
  examiner,
  fileName,
  execution,
}) {
  const pythonResult =
    execution.result ||
    {};

  const artifacts =
    normalizeArtifacts(
      pythonResult.artifacts
    );

  const discoveredFiles =
    await discoverRecoveredFiles(
      caseId
    );

  const finalArtifacts =
    artifacts.length
      ? artifacts.map(
          (
            artifact
          ) => ({
            ...artifact,

            path:
              artifact.output
                ? `/api/forensic/recovered/${encodeURIComponent(
                    sanitizeCaseId(
                      caseId
                    )
                  )}/${encodeURIComponent(
                    path.basename(
                      artifact.output
                    )
                  )}`
                : null,
          })
        )
      : discoveredFiles;

  const evidenceFile =
    evidencePath(
      fileName
    );

  const evidenceStats =
    await fs.promises.stat(
      evidenceFile
    );

  const signaturesDetected =
    Number(
      pythonResult.signatures_detected ??
        pythonResult.signaturesDetected ??
        0
    );

  const candidatesFound =
    Number(
      pythonResult.candidates_found ??
        pythonResult.candidatesFound ??
        signaturesDetected
    );

  const artifactsCarved =
    Number(
      pythonResult.artifacts_carved ??
        pythonResult.artifactsCarved ??
        finalArtifacts.length
    );

  const artifactsValidated =
    Number(
      pythonResult.artifacts_validated ??
        pythonResult.artifactsValidated ??
        finalArtifacts.filter(
          (artifact) =>
            String(
              artifact.validationStatus
            ).toUpperCase() ===
            "VALID"
        ).length
    );

  return {
    caseId,

    examiner,

    evidence:
      fileName,

    recoveredCount:
      finalArtifacts.length,

    artifacts:
      finalArtifacts,

    scanStats: {
      evidenceSize:
        Number(
          pythonResult.evidence_size ??
            pythonResult.evidenceSize ??
            evidenceStats.size
        ),

      chunkSize:
        Number(
          pythonResult.chunk_size ??
            pythonResult.chunkSize ??
            0
        ),

      overlapSize:
        Number(
          pythonResult.overlap_size ??
            pythonResult.overlapSize ??
            0
        ),

      chunksScanned:
        Number(
          pythonResult.chunks_scanned ??
            pythonResult.chunksScanned ??
            0
        ),

      bytesScanned:
        Number(
          pythonResult.bytes_scanned ??
            pythonResult.bytesScanned ??
            0
        ),

      signaturesDetected,

      candidatesFound,

      artifactsCarved,

      artifactsValidated,

      durationMs:
        Number(
          pythonResult.duration_ms ??
            pythonResult.durationMs ??
            0
        ),

      status:
        pythonResult.status ||
        "COMPLETED",
    },

    rawPythonResult:
      pythonResult,

    stdout:
      execution.stdout,

    stderr:
      execution.stderr,
  };
}

/* ==========================================================================
   AGENT DISPATCH
   ========================================================================== */

/*
 * This is the only function that should need modification if your existing
 * agentBridge uses a different method.
 */
async function dispatchForensicJob(
  req,
  job
) {
  const agentBridge =
    req.app.get(
      "agentBridge"
    );

  if (
    !agentBridge ||
    typeof agentBridge.sendTask !==
      "function"
  ) {
    const error =
      new Error(
        "TrustWipe Agent bridge is unavailable."
      );

    error.code =
      "AGENT_BRIDGE_UNAVAILABLE";

    throw error;
  }

  const task = {
    type:
      job.operation,

    jobId:
      job.jobId,

    caseId:
      job.caseId,

    examiner:
      job.examiner,

    evidence: {
      evidenceId:
        job.evidenceId,

      fileName:
        job.fileName,

      sha256:
        job.evidenceHash,
    },

    source:
      job.source || null,

    createdAt:
      job.createdAt,
  };

  /*
   * Your existing Agent bridge should route this task
   * to the TrustWipe Agent.
   */
  return agentBridge.sendTask(
    job.agentId,
    task
  );
}

/* ==========================================================================
   CASE CREATION
   ========================================================================== */

router.post(
  "/cases",
  async (
    req,
    res
  ) => {
    try {
      const caseId =
        sanitizeCaseId(
          req.body?.caseId
        );

      const examiner =
        sanitizeExaminer(
          req.body?.examiner
        );

      const existing =
        await fs.promises
          .access(
            caseDirectory(
              caseId
            )
          )
          .then(
            () => true
          )
          .catch(
            () => false
          );

      if (existing) {
        return fail(
          res,
          409,
          "Case already exists.",
          "CASE_ALREADY_EXISTS"
        );
      }

      await fs.promises.mkdir(
        caseRecoveredDirectory(
          caseId
        ),
        {
          recursive:
            true,
        }
      );

      await fs.promises.mkdir(
        caseMetadataDirectory(
          caseId
        ),
        {
          recursive:
            true,
        }
      );

      const caseRecord = {
        caseId,

        examiner,

        status:
          "OPEN",

        createdAt:
          new Date().toISOString(),

        updatedAt:
          new Date().toISOString(),
      };

      await fs.promises.writeFile(
        safePath(
          caseDirectory(
            caseId
          ),
          "case.json"
        ),
        JSON.stringify(
          caseRecord,
          null,
          2
        ),
        "utf8"
      );

      await appendChainOfCustody(
        caseId,
        "CASE_CREATED",
        {
          examiner,
        }
      );

      return res.status(201).json({
        success: true,

        case:
          caseRecord,
      });
    } catch (error) {
      return fail(
        res,
        400,
        error.message ||
          "Unable to create case.",
        error.code ||
          "CASE_CREATE_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   CASE LIST
   ========================================================================== */

router.get(
  "/cases",
  async (
    _req,
    res
  ) => {
    try {
      const entries =
        await fs.promises.readdir(
          CASES_DIR,
          {
            withFileTypes:
              true,
          }
        );

      const cases = [];

      for (
        const entry of entries
      ) {
        if (!entry.isDirectory()) {
          continue;
        }

        try {
          const caseRecord =
            JSON.parse(
              await fs.promises.readFile(
                safePath(
                  CASES_DIR,
                  `${entry.name}/case.json`
                ),
                "utf8"
              )
            );

          cases.push(
            caseRecord
          );
        } catch {
          // Ignore malformed case records.
        }
      }

      cases.sort(
        (a, b) =>
          new Date(
            b.updatedAt ||
              b.createdAt
          ) -
          new Date(
            a.updatedAt ||
              a.createdAt
          )
      );

      return res.json({
        success: true,

        cases,

        count:
          cases.length,
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to list forensic cases.",
        "CASE_LIST_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   TEST
   ========================================================================== */

router.get(
  "/test",
  (
    _req,
    res
  ) => {
    res.json({
      success: true,

      service:
        "TrustWipe Digital Forensics",

      message:
        "Forensic router is working.",

      executionMode:
        FORENSIC_EXECUTION_MODE,

      forensicRoot:
        process.env.NODE_ENV ===
        "production"
          ? undefined
          : FORENSIC_ROOT,

      cli:
        process.env.NODE_ENV ===
        "production"
          ? undefined
          : CLI_PATH,

      cliExists:
        fs.existsSync(
          CLI_PATH
        ),
    });
  }
);

/* ==========================================================================
   STATUS
   ========================================================================== */

router.get(
  "/status",
  async (
    req,
    res
  ) => {
    try {
      const python =
        await checkPython();

      const cliAvailable =
        fs.existsSync(
          CLI_PATH
        );

      const agentBridge =
        req.app.get(
          "agentBridge"
        );

      const agentAvailable =
        Boolean(
          agentBridge &&
            typeof agentBridge.sendTask ===
              "function"
        );

      let available =
        false;

      if (
        FORENSIC_EXECUTION_MODE ===
        "local"
      ) {
        available =
          python.available &&
          cliAvailable;
      } else if (
        FORENSIC_EXECUTION_MODE ===
        "agent"
      ) {
        available =
          agentAvailable;
      } else {
        available =
          agentAvailable ||
          (
            python.available &&
            cliAvailable
          );
      }

      return res.json({
        success: true,

        available,

        executionMode:
          FORENSIC_EXECUTION_MODE,

        pythonAvailable:
          python.available,

        cliAvailable,

        agentBridgeAvailable:
          agentAvailable,

        pythonVersion:
          python.version,

        scanTimeoutMs:
          SCAN_TIMEOUT_MS,

        maxUploadBytes:
          MAX_UPLOAD_BYTES,

        message:
          available
            ? "Forensic engine ready."
            : "Forensic engine is not fully available.",
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to check forensic engine status.",
        "FORENSIC_STATUS_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   EVIDENCE LIST
   ========================================================================== */

router.get(
  "/evidence",
  async (
    _req,
    res
  ) => {
    try {
      const evidence =
        await discoverEvidence();

      return res.json({
        success: true,

        evidence,

        count:
          evidence.length,

        synchronizedAt:
          new Date().toISOString(),
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to discover evidence files.",
        "EVIDENCE_DISCOVERY_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   UPLOAD / ACQUISITION
   ========================================================================== */

router.post(
  "/upload",
  (
    req,
    res
  ) => {
    upload.single(
      "evidence"
    )(
      req,
      res,
      async (
        error
      ) => {
        if (
          error instanceof
          multer.MulterError
        ) {
          if (
            error.code ===
            "LIMIT_FILE_SIZE"
          ) {
            return fail(
              res,
              413,
              "Evidence file exceeds the maximum supported size.",
              "FILE_TOO_LARGE"
            );
          }

          return fail(
            res,
            400,
            error.message,
            "UPLOAD_INVALID",
            error
          );
        }

        if (error) {
          return fail(
            res,
            500,
            "Evidence upload failed.",
            "UPLOAD_FAILED",
            error
          );
        }

        if (!req.file) {
          return fail(
            res,
            400,
            "Please select an evidence file.",
            "FILE_REQUIRED"
          );
        }

        try {
          const filePath =
            req.file.path;

          const stats =
            await fs.promises.stat(
              filePath
            );

          if (
            stats.size ===
            0
          ) {
            await fs.promises.unlink(
              filePath
            );

            return fail(
              res,
              400,
              "Empty evidence files are not accepted.",
              "EMPTY_EVIDENCE"
            );
          }

          const sha256 =
            await calculateSHA256(
              filePath
            );

          const evidenceId =
            createEvidenceId();

          const acquiredAt =
            new Date().toISOString();

          const manifest = {
            schema_version:
              3,

            evidence_id:
              evidenceId,

            file_name:
              req.file.filename,

            original_name:
              decodeOriginalFilename(
                req.file.originalname
              ),

            acquired_at:
              acquiredAt,

            size:
              stats.size,

            modified_at:
              stats.mtime.toISOString(),

            sha256,

            hash_algorithm:
              "SHA-256",

            acquisition_status:
              "ACQUIRED",

            integrity_baseline:
              true,

            baseline_created_at:
              acquiredAt,

            acquisition_method:
              "TRUSTWIPE_FORENSIC_UPLOAD",
          };

          await saveManifest(
            manifest
          );

          return res.status(201).json({
            success: true,

            message:
              "Evidence acquired successfully. SHA-256 acquisition baseline recorded.",

            evidence: {
              evidenceId,

              name:
                req.file.filename,

              originalName:
                manifest.original_name,

              size:
                stats.size,

              type:
                path.extname(
                  req.file.filename
                )
                  .slice(1)
                  .toUpperCase() ||
                "FILE",

              modifiedAt:
                stats.mtime,

              acquiredAt,

              sha256,

              acquisitionHash:
                sha256,

              algorithm:
                "SHA-256",

              integrityStatus:
                "BASELINE_AVAILABLE",
            },
          });
        } catch (uploadError) {
          try {
            await fs.promises.unlink(
              req.file.path
            );
          } catch {}

          return fail(
            res,
            500,
            "Unable to process uploaded evidence.",
            "ACQUISITION_FAILED",
            uploadError
          );
        }
      }
    );
  }
);

/* ==========================================================================
   HASH
   ========================================================================== */

router.post(
  "/hash",
  async (
    req,
    res
  ) => {
    try {
      const fileName =
        sanitizeFilename(
          req.body?.fileName
        );

      const filePath =
        evidencePath(
          fileName
        );

      const stats =
        await fs.promises.stat(
          filePath
        );

      const sha256 =
        await calculateSHA256(
          filePath
        );

      const manifest =
        await loadManifest(
          fileName
        );

      const integrity =
        await verifyEvidenceIntegrity(
          fileName
        );

      return res.json({
        success: true,

        fileName,

        size:
          stats.size,

        algorithm:
          "SHA-256",

        sha256,

        acquisitionHash:
          manifest?.sha256 ||
          null,

        integrityStatus:
          integrity.status,

        hashMatch:
          integrity.hashMatch,

        integrity,
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to calculate SHA-256.",
        "HASH_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   VERIFY INTEGRITY
   ========================================================================== */

router.post(
  "/verify-integrity",
  async (
    req,
    res
  ) => {
    try {
      const fileName =
        sanitizeFilename(
          req.body?.fileName
        );

      const integrity =
        await verifyEvidenceIntegrity(
          fileName
        );

      return res.json({
        success: true,

        fileName,

        integrity,
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Integrity verification failed.",
        "INTEGRITY_CHECK_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   CREATE FORENSIC JOB
   ========================================================================== */

router.post(
  "/jobs",
  async (
    req,
    res
  ) => {
    try {
      const operation =
        String(
          req.body?.operation ||
            "FORENSIC_SCAN"
        )
          .trim()
          .toUpperCase();

      const allowedOperations = [
        "FORENSIC_SCAN",
        "FORENSIC_VERIFY",
        "FORENSIC_CARVE",
        "FORENSIC_REPORT",
      ];

      if (
        !allowedOperations.includes(
          operation
        )
      ) {
        return fail(
          res,
          400,
          "Unsupported forensic operation.",
          "INVALID_FORENSIC_OPERATION"
        );
      }

      const fileName =
        sanitizeFilename(
          req.body?.fileName
        );

      const caseId =
        sanitizeCaseId(
          req.body?.caseId
        );

      const examiner =
        sanitizeExaminer(
          req.body?.examiner
        );

      const agentId =
        String(
          req.body?.agentId ||
            ""
        ).trim() ||
        null;

      const evidenceFile =
        evidencePath(
          fileName
        );

      await fs.promises.access(
        evidenceFile,
        fs.constants.R_OK
      );

      const integrity =
        await verifyEvidenceIntegrity(
          fileName
        );

      /*
       * Critical forensic boundary:
       *
       * Never start analysis against evidence whose
       * acquisition baseline is missing or mismatched.
       */
      if (
        integrity.status !==
          "VERIFIED" ||
        integrity.verified !==
          true ||
        integrity.hashMatch !==
          true
      ) {
        return res.status(409).json({
          success: false,

          code:
            integrity.status ===
            "TAMPERED"
              ? "EVIDENCE_TAMPERED"
              : "BASELINE_MISSING",

          message:
            "Forensic analysis is blocked because evidence integrity is not VERIFIED.",

          integrity,
        });
      }

      await fs.promises.mkdir(
        caseRecoveredDirectory(
          caseId
        ),
        {
          recursive:
            true,
        }
      );

      const jobId =
        createJobId();

      const operationId =
        createOperationId();

      const createdAt =
        new Date().toISOString();

      const job = {
        jobId,

        operationId,

        caseId,

        examiner,

        agentId,

        operation,

        status:
          "QUEUED",

        progress:
          0,

        bytesScanned:
          0,

        bytesTotal:
          integrity.currentSize,

        artifactsFound:
          0,

        artifactsValidated:
          0,

        evidenceId:
          integrity.evidenceId,

        fileName,

        evidenceHash:
          integrity.currentHash,

        source:
          req.body?.source ||
          null,

        executionMode:
          FORENSIC_EXECUTION_MODE,

        createdAt,

        startedAt:
          null,

        completedAt:
          null,

        updatedAt:
          createdAt,

        error:
          null,

        result:
          null,
      };

      await saveJob(
        job
      );

      await appendChainOfCustody(
        caseId,
        "FORENSIC_JOB_CREATED",
        {
          jobId,
          operationId,
          operation,
          examiner,
          evidenceId:
            integrity.evidenceId,
          evidenceHash:
            integrity.currentHash,
        }
      );

      /*
       * AGENT MODE
       */

      if (
        FORENSIC_EXECUTION_MODE ===
        "agent"
      ) {
        if (!agentId) {
          return fail(
            res,
            400,
            "agentId is required when forensic execution mode is 'agent'.",
            "AGENT_ID_REQUIRED"
          );
        }

        await updateJob(
          jobId,
          {
            status:
              "DISPATCHING",
          }
        );

        try {
          await dispatchForensicJob(
            req,
            job
          );

          const updated =
            await updateJob(
              jobId,
              {
                status:
                  "DISPATCHED",
              }
            );

          return res.status(202).json({
            success: true,

            message:
              "Forensic job dispatched to TrustWipe Agent.",

            job:
              updated,

            statusUrl:
              `/api/forensic/jobs/${encodeURIComponent(
                jobId
              )}`,
          });
        } catch (error) {
          await updateJob(
            jobId,
            {
              status:
                "FAILED",

              error: {
                code:
                  error.code ||
                  "AGENT_DISPATCH_FAILED",

                message:
                  error.message,
              },

              completedAt:
                new Date().toISOString(),
            }
          );

          return fail(
            res,
            503,
            "Unable to dispatch forensic job to TrustWipe Agent.",
            error.code ||
              "AGENT_DISPATCH_FAILED",
            error
          );
        }
      }

      /*
       * LOCAL MODE
       */

      if (
        FORENSIC_EXECUTION_MODE ===
        "local"
      ) {
        try {
          const result =
            await executeLocalJob(
              req,
              job
            );

          return res.status(202).json({
            success: true,

            message:
              "Forensic job completed using the local forensic engine.",

            job:
              result,

            statusUrl:
              `/api/forensic/jobs/${encodeURIComponent(
                jobId
              )}`,
          });
        } catch (error) {
          return fail(
            res,
            500,
            "Local forensic job failed.",
            error.code ||
              "FORENSIC_JOB_FAILED",
            error
          );
        }
      }

      /*
       * AUTO MODE
       */

      if (
        FORENSIC_EXECUTION_MODE ===
        "auto"
      ) {
        const agentBridge =
          req.app.get(
            "agentBridge"
          );

        const agentAvailable =
          Boolean(
            agentBridge &&
              typeof agentBridge.sendTask ===
                "function"
          );

        if (
          agentAvailable &&
          agentId
        ) {
          try {
            await dispatchForensicJob(
              req,
              job
            );

            const updated =
              await updateJob(
                jobId,
                {
                  status:
                    "DISPATCHED",
                }
              );

            return res.status(202).json({
              success: true,

              message:
                "Forensic job dispatched to TrustWipe Agent.",

              job:
                updated,

              statusUrl:
                `/api/forensic/jobs/${encodeURIComponent(
                  jobId
                )}`,
            });
          } catch (error) {
            console.warn(
              "[Forensics] Agent dispatch failed. Falling back to local execution.",
              error.message
            );
          }
        }

        try {
          const result =
            await executeLocalJob(
              req,
              job
            );

          return res.status(202).json({
            success: true,

            message:
              "Forensic job completed using the local forensic engine.",

            job:
              result,

            statusUrl:
              `/api/forensic/jobs/${encodeURIComponent(
                jobId
              )}`,
          });
        } catch (error) {
          return fail(
            res,
            500,
            "Forensic job failed.",
            error.code ||
              "FORENSIC_JOB_FAILED",
            error
          );
        }
      }

      return fail(
        res,
        500,
        "Invalid forensic execution mode.",
        "INVALID_EXECUTION_MODE"
      );
    } catch (error) {
      return fail(
        res,
        400,
        error.message ||
          "Unable to create forensic job.",
        error.code ||
          "FORENSIC_JOB_CREATE_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   LOCAL JOB EXECUTION
   ========================================================================== */

async function executeLocalJob(
  req,
  job
) {
  const startedAt =
    new Date().toISOString();

  await updateJob(
    job.jobId,
    {
      status:
        "RUNNING",

      startedAt,
    }
  );

  await appendChainOfCustody(
    job.caseId,
    "FORENSIC_ANALYSIS_STARTED",
    {
      jobId:
        job.jobId,

      evidenceId:
        job.evidenceId,

      evidenceHash:
        job.evidenceHash,
    }
  );

  try {
    const evidenceFile =
      evidencePath(
        job.fileName
      );

    const outputDirectory =
      caseRecoveredDirectory(
        job.caseId
      );

    /*
     * Verify immediately before execution.
     */
    const integrityBefore =
      await verifyEvidenceIntegrity(
        job.fileName
      );

    if (
      integrityBefore.status !==
        "VERIFIED" ||
      integrityBefore.currentHash !==
        job.evidenceHash
    ) {
      const error =
        new Error(
          "Evidence changed after job creation and before analysis."
        );

      error.code =
        "EVIDENCE_CHANGED_BEFORE_ANALYSIS";

      throw error;
    }

    await updateJob(
      job.jobId,
      {
        progress:
          5,
      }
    );

    const execution =
      await runPythonScan({
        evidenceFile,

        outputDirectory,

        caseId:
          job.caseId,

        examiner:
          job.examiner,

        jobId:
          job.jobId,
      });

    await updateJob(
      job.jobId,
      {
        progress:
          90,
      }
    );

    /*
     * Verify again after analysis.
     */
    const integrityAfter =
      await verifyEvidenceIntegrity(
        job.fileName
      );

    if (
      integrityAfter.status !==
        "VERIFIED" ||
      integrityAfter.currentHash !==
        job.evidenceHash
    ) {
      const error =
        new Error(
          "Evidence changed during forensic analysis."
        );

      error.code =
        "EVIDENCE_CHANGED_DURING_ANALYSIS";

      throw error;
    }

    const result =
      await buildScanResult({
        caseId:
          job.caseId,

        examiner:
          job.examiner,

        fileName:
          job.fileName,

        execution,
      });

    const completedAt =
      new Date().toISOString();

    const completedJob =
      await updateJob(
        job.jobId,
        {
          status:
            "COMPLETED",

          progress:
            100,

          bytesScanned:
            result.scanStats
              .bytesScanned,

          bytesTotal:
            result.scanStats
              .evidenceSize,

          artifactsFound:
            result.scanStats
              .candidatesFound,

          artifactsValidated:
            result.scanStats
              .artifactsValidated,

          completedAt,

          result: {
            ...result,

            integrity:
              integrityAfter,
          },

          error:
            null,
        }
      );

    await appendChainOfCustody(
      job.caseId,
      "FORENSIC_ANALYSIS_COMPLETED",
      {
        jobId:
          job.jobId,

        evidenceId:
          job.evidenceId,

        evidenceHash:
          integrityAfter.currentHash,

        recoveredCount:
          result.recoveredCount,

        artifactsValidated:
          result.scanStats
            .artifactsValidated,
      }
    );

    return completedJob;
  } catch (error) {
    await updateJob(
      job.jobId,
      {
        status:
          "FAILED",

        completedAt:
          new Date().toISOString(),

        error: {
          code:
            error.code ||
            "FORENSIC_JOB_FAILED",

          message:
            error.message,
        },
      }
    );

    await appendChainOfCustody(
      job.caseId,
      "FORENSIC_ANALYSIS_FAILED",
      {
        jobId:
          job.jobId,

        errorCode:
          error.code ||
          "FORENSIC_JOB_FAILED",

        error:
          error.message,
      }
    );

    throw error;
  }
}

/* ==========================================================================
   LEGACY / SIMPLE SCAN ENDPOINT
   ========================================================================== */

router.post(
  "/scan",
  async (
    req,
    res
  ) => {
    try {
      /*
       * The old /scan API is preserved.
       *
       * Internally it now uses the job engine.
       */
      const fileName =
        sanitizeFilename(
          req.body?.fileName
        );

      const caseId =
        sanitizeCaseId(
          req.body?.caseId
        );

      const examiner =
        sanitizeExaminer(
          req.body?.examiner
        );

      const agentId =
        String(
          req.body?.agentId ||
            ""
        ).trim() ||
        null;

      /*
       * Reuse the job endpoint logic by constructing
       * the same validation flow here.
       */

      const integrity =
        await verifyEvidenceIntegrity(
          fileName
        );

      if (
        integrity.status !==
          "VERIFIED" ||
        integrity.verified !==
          true ||
        integrity.hashMatch !==
          true
      ) {
        return res.status(409).json({
          success: false,

          code:
            integrity.status ===
            "TAMPERED"
              ? "EVIDENCE_TAMPERED"
              : "BASELINE_MISSING",

          message:
            "Forensic analysis is blocked because evidence integrity is not VERIFIED.",

          integrity,
        });
      }

      const job = {
        jobId:
          createJobId(),

        operationId:
          createOperationId(),

        caseId,

        examiner,

        agentId,

        operation:
          "FORENSIC_SCAN",

        status:
          "QUEUED",

        progress:
          0,

        bytesScanned:
          0,

        bytesTotal:
          integrity.currentSize,

        artifactsFound:
          0,

        artifactsValidated:
          0,

        evidenceId:
          integrity.evidenceId,

        fileName,

        evidenceHash:
          integrity.currentHash,

        source:
          req.body?.source ||
          null,

        executionMode:
          "local",

        createdAt:
          new Date().toISOString(),

        startedAt:
          null,

        completedAt:
          null,

        updatedAt:
          new Date().toISOString(),

        error:
          null,

        result:
          null,
      };

      await saveJob(
        job
      );

      const completedJob =
        await executeLocalJob(
          req,
          job
        );

      const result =
        completedJob.result ||
        {};

      return res.json({
        success: true,

        message:
          `Forensic recovery completed. ${
            result.scanStats?.candidatesFound ||
            0
          } candidate range(s) identified and ${
            result.scanStats
              ?.artifactsValidated ||
            0
          } artifact(s) validated.`,

        job:
          completedJob,

        caseId,

        examiner,

        evidence:
          fileName,

        recoveredCount:
          result.recoveredCount ||
          0,

        recoveredFiles:
          result.artifacts ||
          [],

        artifacts:
          result.artifacts ||
          [],

        scanStats:
          result.scanStats ||
          {},

        integrity:
          result.integrity ||
          integrity,

        output:
          result.stdout ||
          "",

        stderr:
          result.stderr ||
          "",
      });
    } catch (error) {
      console.error(
        "[Forensics] Legacy scan failed:",
        error
      );

      return fail(
        res,
        500,
        "Forensic analysis failed.",
        error.code ||
          "FORENSIC_SCAN_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   JOB LIST
   ========================================================================== */

router.get(
  "/jobs",
  async (
    _req,
    res
  ) => {
    try {
      const jobs =
        await discoverJobs();

      return res.json({
        success: true,

        jobs,

        count:
          jobs.length,
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to list forensic jobs.",
        "FORENSIC_JOB_LIST_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   JOB STATUS
   ========================================================================== */

router.get(
  "/jobs/:jobId",
  async (
    req,
    res
  ) => {
    try {
      const job =
        await getJob(
          req.params.jobId
        );

      if (!job) {
        return fail(
          res,
          404,
          "Forensic job not found.",
          "FORENSIC_JOB_NOT_FOUND"
        );
      }

      return res.json({
        success: true,

        job,
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to retrieve forensic job.",
        "FORENSIC_JOB_STATUS_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   AGENT CALLBACK / PROGRESS
   ========================================================================== */

/*
 * Your TrustWipe Agent bridge can call this endpoint whenever the Agent
 * reports forensic progress.
 *
 * Example:
 *
 * POST /api/forensic/jobs/FJ-.../progress
 *
 * {
 *   "status": "RUNNING",
 *   "progress": 72,
 *   "bytesScanned": 734003200,
 *   "bytesTotal": 1073741824,
 *   "artifactsFound": 42,
 *   "artifactsValidated": 31
 * }
 */
router.post(
  "/jobs/:jobId/progress",
  async (
    req,
    res
  ) => {
    try {
      const job =
        await getJob(
          req.params.jobId
        );

      if (!job) {
        return fail(
          res,
          404,
          "Forensic job not found.",
          "FORENSIC_JOB_NOT_FOUND"
        );
      }

      const progress =
        Math.max(
          0,
          Math.min(
            100,
            Number(
              req.body?.progress ??
                job.progress ??
                0
            )
          )
        );

      const updated =
        await updateJob(
          job.jobId,
          {
            status:
              req.body?.status ||
              job.status,

            progress,

            bytesScanned:
              Number(
                req.body
                  ?.bytesScanned ??
                  job.bytesScanned ??
                  0
              ),

            bytesTotal:
              Number(
                req.body?.bytesTotal ??
                  job.bytesTotal ??
                  0
              ),

            artifactsFound:
              Number(
                req.body
                  ?.artifactsFound ??
                  job.artifactsFound ??
                  0
              ),

            artifactsValidated:
              Number(
                req.body
                  ?.artifactsValidated ??
                  job.artifactsValidated ??
                  0
              ),
          }
        );

      return res.json({
        success: true,

        job:
          updated,
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to update forensic job progress.",
        "FORENSIC_PROGRESS_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   AGENT CALLBACK / COMPLETE
   ========================================================================== */

router.post(
  "/jobs/:jobId/complete",
  async (
    req,
    res
  ) => {
    try {
      const job =
        await getJob(
          req.params.jobId
        );

      if (!job) {
        return fail(
          res,
          404,
          "Forensic job not found.",
          "FORENSIC_JOB_NOT_FOUND"
        );
      }

      const result =
        req.body?.result ||
        {};

      const completed =
        await updateJob(
          job.jobId,
          {
            status:
              "COMPLETED",

            progress:
              100,

            bytesScanned:
              Number(
                result.bytesScanned ??
                  result.bytes_scanned ??
                  job.bytesTotal
              ),

            artifactsFound:
              Number(
                result.artifactsFound ??
                  result.candidatesFound ??
                  result.candidates_found ??
                  0
              ),

            artifactsValidated:
              Number(
                result.artifactsValidated ??
                  result.artifacts_validated ??
                  0
              ),

            completedAt:
              new Date().toISOString(),

            result,

            error:
              null,
          }
        );

      await appendChainOfCustody(
        job.caseId,
        "FORENSIC_AGENT_COMPLETED",
        {
          jobId:
            job.jobId,

          agentId:
            job.agentId,

          artifactsValidated:
            completed.artifactsValidated,
        }
      );

      return res.json({
        success: true,

        job:
          completed,
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to complete forensic job.",
        "FORENSIC_JOB_COMPLETE_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   JOB FAILURE
   ========================================================================== */

router.post(
  "/jobs/:jobId/fail",
  async (
    req,
    res
  ) => {
    try {
      const job =
        await getJob(
          req.params.jobId
        );

      if (!job) {
        return fail(
          res,
          404,
          "Forensic job not found.",
          "FORENSIC_JOB_NOT_FOUND"
        );
      }

      const updated =
        await updateJob(
          job.jobId,
          {
            status:
              "FAILED",

            completedAt:
              new Date().toISOString(),

            error: {
              code:
                req.body?.code ||
                "AGENT_FORENSIC_FAILED",

              message:
                req.body?.message ||
                "TrustWipe Agent forensic operation failed.",
            },
          }
        );

      await appendChainOfCustody(
        job.caseId,
        "FORENSIC_AGENT_FAILED",
        {
          jobId:
            job.jobId,

          agentId:
            job.agentId,

          error:
            updated.error,
        }
      );

      return res.json({
        success: true,

        job:
          updated,
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to record forensic job failure.",
        "FORENSIC_JOB_FAILURE_RECORD_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   CANCEL JOB
   ========================================================================== */

router.post(
  "/jobs/:jobId/cancel",
  async (
    req,
    res
  ) => {
    try {
      const job =
        await getJob(
          req.params.jobId
        );

      if (!job) {
        return fail(
          res,
          404,
          "Forensic job not found.",
          "FORENSIC_JOB_NOT_FOUND"
        );
      }

      if (
        [
          "COMPLETED",
          "FAILED",
          "CANCELLED",
        ].includes(
          job.status
        )
      ) {
        return res.json({
          success: true,

          message:
            "Job has already reached a terminal state.",

          job,
        });
      }

      const updated =
        await updateJob(
          job.jobId,
          {
            status:
              "CANCELLED",

            completedAt:
              new Date().toISOString(),
          }
        );

      await appendChainOfCustody(
        job.caseId,
        "FORENSIC_JOB_CANCELLED",
        {
          jobId:
            job.jobId,

          reason:
            req.body?.reason ||
            "Cancelled by operator.",
        }
      );

      return res.json({
        success: true,

        message:
          "Forensic job cancelled.",

        job:
          updated,
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to cancel forensic job.",
        "FORENSIC_CANCEL_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   CASE ARTIFACTS
   ========================================================================== */

router.get(
  "/cases/:caseId/artifacts",
  async (
    req,
    res
  ) => {
    try {
      const caseId =
        sanitizeCaseId(
          req.params.caseId
        );

      const artifacts =
        await discoverRecoveredFiles(
          caseId
        );

      return res.json({
        success: true,

        caseId,

        artifacts,

        count:
          artifacts.length,
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to retrieve recovered artifacts.",
        "ARTIFACT_DISCOVERY_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   CHAIN OF CUSTODY
   ========================================================================== */

router.get(
  "/cases/:caseId/chain-of-custody",
  async (
    req,
    res
  ) => {
    try {
      const caseId =
        sanitizeCaseId(
          req.params.caseId
        );

      const events =
        await readChainOfCustody(
          caseId
        );

      return res.json({
        success: true,

        caseId,

        events,

        count:
          events.length,
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to retrieve chain of custody.",
        "CHAIN_OF_CUSTODY_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   RECOVERED FILE DOWNLOAD
   ========================================================================== */

router.get(
  "/recovered/:caseId/:fileName",
  async (
    req,
    res
  ) => {
    try {
      const caseId =
        sanitizeCaseId(
          req.params.caseId
        );

      const fileName =
        sanitizeFilename(
          req.params.fileName
        );

      const directory =
        caseRecoveredDirectory(
          caseId
        );

      const filePath =
        safePath(
          directory,
          fileName
        );

      const stats =
        await fs.promises.stat(
          filePath
        );

      if (!stats.isFile()) {
        throw new Error(
          "Recovered artifact is not a file."
        );
      }

      return res.download(
        filePath,
        path.basename(
          filePath
        )
      );
    } catch {
      return fail(
        res,
        404,
        "Recovered artifact not found.",
        "RECOVERED_FILE_NOT_FOUND"
      );
    }
  }
);

/* ==========================================================================
   LEGACY RECOVERED FILE DOWNLOAD
   ========================================================================== */

router.get(
  "/recovered/:fileName",
  async (
    req,
    res
  ) => {
    try {
      const fileName =
        sanitizeFilename(
          req.params.fileName
        );

      const filePath =
        safePath(
          RECOVERED_DIR,
          fileName
        );

      const stats =
        await fs.promises.stat(
          filePath
        );

      if (!stats.isFile()) {
        throw new Error(
          "Recovered artifact is not a file."
        );
      }

      return res.download(
        filePath,
        path.basename(
          filePath
        )
      );
    } catch {
      return fail(
        res,
        404,
        "Recovered artifact not found.",
        "RECOVERED_FILE_NOT_FOUND"
      );
    }
  }
);

/* ==========================================================================
   REPORT GENERATION
   ========================================================================== */

router.post(
  "/report",
  async (
    req,
    res
  ) => {
    try {
      const fileName =
        sanitizeFilename(
          req.body?.fileName
        );

      const caseId =
        sanitizeCaseId(
          req.body?.caseId
        );

      const examiner =
        sanitizeExaminer(
          req.body?.examiner
        );

      const filePath =
        evidencePath(
          fileName
        );

      const stats =
        await fs.promises.stat(
          filePath
        );

      const integrity =
        await verifyEvidenceIntegrity(
          fileName
        );

      /*
       * Reports are only valid when the original evidence
       * remains cryptographically identical to acquisition.
       */
      if (
        integrity.status !==
          "VERIFIED" ||
        integrity.verified !==
          true ||
        integrity.hashMatch !==
          true
      ) {
        return res.status(409).json({
          success: false,

          code:
            integrity.status ===
            "TAMPERED"
              ? "EVIDENCE_TAMPERED"
              : "BASELINE_MISSING",

          message:
            "Report generation blocked because evidence integrity is not VERIFIED.",

          integrity,
        });
      }

      const jobs =
        await discoverJobs();

      const caseJobs =
        jobs.filter(
          (job) =>
            job.caseId ===
              caseId &&
            job.fileName ===
              fileName
        );

      const latestJob =
        caseJobs[0] ||
        null;

      const artifacts =
        await discoverRecoveredFiles(
          caseId
        );

      const generatedAt =
        new Date().toISOString();

      const report = {
        schema_version:
          3,

        product:
          "TrustWipe Forensics",

        report_type:
          "DIGITAL_FORENSIC_EVIDENCE_REPORT",

        case_id:
          caseId,

        examiner,

        generated_at:
          generatedAt,

        evidence: {
          evidence_id:
            integrity.evidenceId,

          file_name:
            fileName,

          size:
            stats.size,

          modified_at:
            stats.mtime.toISOString(),

          sha256:
            integrity.currentHash,

          hash_algorithm:
            "SHA-256",

          acquired_at:
            integrity.acquiredAt,
        },

        integrity: {
          status:
            integrity.status,

          verified:
            integrity.verified,

          hash_match:
            integrity.hashMatch,

          size_match:
            integrity.sizeMatch,

          acquisition_hash:
            integrity.originalHash,

          current_hash:
            integrity.currentHash,

          original_source_modified:
            integrity.originalSourceModified,

          message:
            integrity.message,
        },

        analysis: {
          job_id:
            latestJob?.jobId ||
            null,

          operation_id:
            latestJob?.operationId ||
            null,

          status:
            latestJob?.status ||
            "NOT_RECORDED",

          artifacts_recovered:
            artifacts.length,

          artifacts:
            artifacts,
        },

        methodology: {
          acquisition:
            "SHA-256 acquisition baseline",

          integrity:
            "SHA-256 and file-size comparison",

          recovery:
            "TrustWipe forensic recovery engine",

          evidence_handling:
            "Case-isolated evidence analysis and chain-of-custody recording",
        },

        chain_of_custody:
          await readChainOfCustody(
            caseId
          ),

        compliance: {
          reference:
            "NIST SP 800-88",

          status:
            "REFERENCE_ONLY",

          note:
            "This forensic report records evidence integrity, recovery activity, and chain-of-custody metadata. It does not by itself certify physical media sanitization or regulatory compliance.",
        },
      };

      const reportFileName =
        `${caseId}-${Date.now()}-${crypto
          .randomBytes(3)
          .toString("hex")}.json`;

      const outputPath =
        reportPath(
          reportFileName
        );

      const temporary =
        `${outputPath}.${process.pid}.tmp`;

      await fs.promises.writeFile(
        temporary,
        JSON.stringify(
          report,
          null,
          2
        ),
        "utf8"
      );

      await fs.promises.rename(
        temporary,
        outputPath
      );

      await appendChainOfCustody(
        caseId,
        "FORENSIC_REPORT_GENERATED",
        {
          reportFile:
            reportFileName,

          evidenceId:
            integrity.evidenceId,

          evidenceHash:
            integrity.currentHash,
        }
      );

      return res.json({
        success: true,

        message:
          "Forensic evidence report generated successfully. Evidence integrity is VERIFIED.",

        report,

        reportFile:
          reportFileName,

        downloadUrl:
          `/api/forensic/report/${encodeURIComponent(
            reportFileName
          )}`,
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to generate forensic report.",
        "REPORT_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   REPORT DOWNLOAD
   ========================================================================== */

router.get(
  "/report/:fileName",
  async (
    req,
    res
  ) => {
    try {
      const fileName =
        sanitizeFilename(
          req.params.fileName
        );

      const filePath =
        reportPath(
          fileName
        );

      const stats =
        await fs.promises.stat(
          filePath
        );

      if (!stats.isFile()) {
        throw new Error(
          "Report is not a file."
        );
      }

      return res.download(
        filePath,
        path.basename(
          filePath
        )
      );
    } catch {
      return fail(
        res,
        404,
        "Report file not found.",
        "REPORT_NOT_FOUND"
      );
    }
  }
);

/* ==========================================================================
   EXPORT
   ========================================================================== */

export default router;