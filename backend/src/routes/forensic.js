import express from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { spawn } from "child_process";
import { fileURLToPath } from "url";
import multer from "multer";

const router = express.Router();

/* ============================================================
   TRUSTWIPE FORENSICS ROUTER
   ============================================================

   Mounted by server.js as:

   app.use("/api/forensic", forensicRouter);

   Endpoints:

   GET  /test
   GET  /status
   GET  /evidence

   POST /upload
   POST /hash
   POST /verify-integrity
   POST /scan
   POST /report

   GET  /recovered/:caseId/:scanId/:fileName
   GET  /recovered-file/:caseId/:scanId?file=...
   GET  /report/:caseId/:fileName

   ============================================================ */


/* ============================================================
   TEST
   ============================================================ */

router.get("/test", (_req, res) => {
  return res.json({
    success: true,
    message: "Forensic router is working",
    service: "TrustWipe Digital Forensics",
  });
});


/* ============================================================
   PATH CONFIGURATION
   ============================================================ */

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/*
 * backend/src/routes
 *
 * ../../.. = Trust_Wipe
 *
 * Trust_Wipe/
 * ├── backend/
 * │   └── src/
 * │       └── routes/
 * │           └── forensic.js
 * │
 * └── forensic_recovery/
 */

const PROJECT_ROOT = path.resolve(
  __dirname,
  "../../.."
);

const FORENSIC_ROOT = path.join(
  PROJECT_ROOT,
  "forensic_recovery"
);

const FORENSIC_PARENT =
  PROJECT_ROOT;

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

const REQUIRED_DIRECTORIES = [
  FORENSIC_ROOT,
  EVIDENCE_DIR,
  RECOVERED_DIR,
  REPORTS_DIR,
  MANIFESTS_DIR,
  CASES_DIR,
];

for (const directory of REQUIRED_DIRECTORIES) {
  fs.mkdirSync(directory, {
    recursive: true,
  });
}


/* ============================================================
   CONFIGURATION
   ============================================================ */

const MAX_UPLOAD_SIZE =
  Number(
    process.env.FORENSIC_MAX_UPLOAD_BYTES
  ) ||
  5 * 1024 * 1024 * 1024;

const SCAN_TIMEOUT_MS =
  Number(
    process.env.FORENSIC_SCAN_TIMEOUT_MS
  ) ||
  10 * 60 * 1000;

const MAX_OUTPUT_FILES =
  Number(
    process.env.FORENSIC_MAX_OUTPUT_FILES
  ) ||
  10000;


/* ============================================================
   PYTHON COMMAND DISCOVERY
   ============================================================ */

/*
 * Prefer the project's forensic_recovery/.venv.
 *
 * Windows:
 *   forensic_recovery/.venv/Scripts/python.exe
 *
 * Linux/macOS:
 *   forensic_recovery/.venv/bin/python
 */

function getPythonCommands() {
  const commands = [];

  if (process.platform === "win32") {
    commands.push(
      path.join(
        FORENSIC_ROOT,
        ".venv",
        "Scripts",
        "python.exe"
      )
    );

    commands.push("python");
    commands.push("py");
  } else {
    commands.push(
      path.join(
        FORENSIC_ROOT,
        ".venv",
        "bin",
        "python"
      )
    );

    commands.push("python3");
    commands.push("python");
  }

  return [
    ...new Set(commands),
  ];
}


/* ============================================================
   MULTER STORAGE
   ============================================================ */

const storage =
  multer.diskStorage({
    destination: (_req, _file, cb) => {
      cb(null, EVIDENCE_DIR);
    },

    filename: (_req, file, cb) => {
      try {
        cb(
          null,
          createUniqueFilename(
            file.originalname
          )
        );
      } catch (error) {
        cb(error);
      }
    },
  });

const upload = multer({
  storage,

  limits: {
    fileSize: MAX_UPLOAD_SIZE,
  },

  /*
   * Forensic evidence can be:

   * IMG
   * BIN
   * DD
   * E01
   * ISO
   * TXT
   * ZIP
   * raw disk image
   * memory dump
   * unknown binary

   * Therefore MIME type must NOT be trusted.
   */
  fileFilter: (_req, _file, cb) => {
    cb(null, true);
  },
});


/* ============================================================
   FILENAME SECURITY
   ============================================================ */

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
      !repaired.includes(
        "\uFFFD"
      )
    ) {
      decoded = repaired;
    }
  } catch {
    // Preserve original.
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
      .trim();

  return safe || "evidence";
}


function createUniqueFilename(
  filename
) {
  const safeName =
    sanitizeFilename(
      filename
    );

  const extension =
    path.extname(
      safeName
    );

  const baseName =
    path.basename(
      safeName,
      extension
    );

  let finalName =
    safeName;

  let counter = 1;

  while (
    fs.existsSync(
      path.join(
        EVIDENCE_DIR,
        finalName
      )
    )
  ) {
    finalName =
      `${baseName}_${counter}${extension}`;

    counter += 1;
  }

  return finalName;
}


/* ============================================================
   GENERIC SAFE PATH
   ============================================================ */

function safePath(
  rootDirectory,
  relativeName
) {
  if (
    !relativeName ||
    typeof relativeName !==
      "string"
  ) {
    throw new Error(
      "File name is required."
    );
  }

  const root =
    path.resolve(
      rootDirectory
    );

  /*
   * Convert Windows separators
   * before resolving.
   */
  const normalized =
    String(relativeName)
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


/* ============================================================
   SAFE EVIDENCE PATH
   ============================================================ */

function safeEvidencePath(
  fileName
) {
  return safePath(
    EVIDENCE_DIR,
    path.basename(
      String(fileName)
    )
  );
}


/* ============================================================
   CASE SECURITY
   ============================================================ */

function sanitizeCaseId(
  caseId
) {
  const value =
    String(
      caseId || "CASE"
    )
      .trim()
      .replace(
        /[^a-zA-Z0-9_-]/g,
        "_"
      )
      .slice(
        0,
        100
      );

  return value || "CASE";
}


function safeCasePath(
  caseId
) {
  const safeId =
    sanitizeCaseId(
      caseId
    );

  const root =
    path.resolve(
      CASES_DIR
    );

  const target =
    path.resolve(
      root,
      safeId
    );

  if (
    target !== root &&
    !target.startsWith(
      root + path.sep
    )
  ) {
    const error =
      new Error(
        "Invalid case identifier."
      );

    error.code =
      "INVALID_CASE_ID";

    throw error;
  }

  return target;
}


async function ensureCaseDirectories(
  caseId
) {
  const root =
    safeCasePath(
      caseId
    );

  const recovered =
    path.join(
      root,
      "recovered"
    );

  const reports =
    path.join(
      root,
      "reports"
    );

  await Promise.all([
    fs.promises.mkdir(
      recovered,
      {
        recursive: true,
      }
    ),

    fs.promises.mkdir(
      reports,
      {
        recursive: true,
      }
    ),
  ]);

  return {
    root,
    recovered,
    reports,
  };
}


/* ============================================================
   SHA-256
   ============================================================ */

async function calculateSHA256(
  filePath
) {
  const hash =
    crypto.createHash(
      "sha256"
    );

  return new Promise(
    (resolve, reject) => {
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
          hash.update(chunk);
        }
      );

      stream.once(
        "end",
        () => {
          resolve(
            hash.digest("hex")
          );
        }
      );

      stream.once(
        "error",
        reject
      );
    }
  );
}


/* ============================================================
   EVIDENCE ID
   ============================================================ */

function createEvidenceId() {
  return [
    "EV",
    new Date()
      .getUTCFullYear(),

    Date.now(),

    crypto
      .randomBytes(6)
      .toString("hex"),
  ].join("-");
}


/* ============================================================
   MANIFEST
   ============================================================ */

async function saveManifest(
  manifest
) {
  const fileName =
    `${manifest.evidence_id}.json`;

  const manifestPath =
    path.join(
      MANIFESTS_DIR,
      fileName
    );

  const temporary =
    `${manifestPath}.${crypto
      .randomBytes(4)
      .toString("hex")}.tmp`;

  await fs.promises.writeFile(
    temporary,
    JSON.stringify(
      manifest,
      null,
      2
    ),
    {
      encoding: "utf8",
      flag: "wx",
    }
  );

  await fs.promises.rename(
    temporary,
    manifestPath
  );

  return manifestPath;
}


async function readManifest(
  manifestPath
) {
  const raw =
    await fs.promises.readFile(
      manifestPath,
      "utf8"
    );

  return JSON.parse(
    raw
  );
}


async function loadManifestByFileName(
  fileName
) {
  const entries =
    await fs.promises.readdir(
      MANIFESTS_DIR,
      {
        withFileTypes: true,
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
      const manifestPath =
        safePath(
          MANIFESTS_DIR,
          entry.name
        );

      const manifest =
        await readManifest(
          manifestPath
        );

      if (
        manifest.file_name ===
          fileName ||
        manifest.original_name ===
          fileName
      ) {
        return manifest;
      }
    } catch (error) {
      console.warn(
        `[FORENSICS] Invalid manifest ${entry.name}:`,
        error.message
      );
    }
  }

  return null;
}


async function loadManifestByEvidenceId(
  evidenceId
) {
  if (!evidenceId) {
    return null;
  }

  const entries =
    await fs.promises.readdir(
      MANIFESTS_DIR,
      {
        withFileTypes: true,
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
      const manifestPath =
        safePath(
          MANIFESTS_DIR,
          entry.name
        );

      const manifest =
        await readManifest(
          manifestPath
        );

      if (
        String(
          manifest.evidence_id
        ) ===
        String(evidenceId)
      ) {
        return manifest;
      }
    } catch (error) {
      console.warn(
        `[FORENSICS] Invalid manifest ${entry.name}:`,
        error.message
      );
    }
  }

  return null;
}


/* ============================================================
   EVIDENCE INTEGRITY
   ============================================================ */

async function verifyEvidenceIntegrity(
  fileName
) {
  const safeName =
    path.basename(
      String(fileName)
    );

  const filePath =
    safeEvidencePath(
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
      "INVALID_EVIDENCE";

    throw error;
  }

  const manifest =
    await loadManifestByFileName(
      safeName
    );

  const currentHash =
    await calculateSHA256(
      filePath
    );

  /*
   * IMPORTANT:
   *
   * Existing files uploaded by an
   * older implementation may not
   * have a manifest.
   *
   * We MUST NOT automatically create
   * a new baseline during verification.
   *
   * That would destroy chain-of-custody
   * semantics.
   */

  if (!manifest) {
    return {
      status:
        "BASELINE_MISSING",

      verified: false,

      hashMatch: false,

      sizeMatch: false,

      originalSourceModified:
        null,

      originalHash:
        null,

      currentHash,

      acquiredAt:
        null,

      evidenceId:
        null,

      originalSize:
        null,

      currentSize:
        stats.size,

      message:
        "Evidence acquisition baseline is missing. Re-acquire the evidence to establish an immutable SHA-256 baseline.",
    };
  }

  const acquisitionHash =
    String(
      manifest.sha256 || ""
    )
      .trim()
      .toLowerCase();

  const validHash =
    /^[a-f0-9]{64}$/.test(
      acquisitionHash
    );

  let hashMatch =
    false;

  if (
    validHash &&
    /^[a-f0-9]{64}$/.test(
      currentHash
    )
  ) {
    hashMatch =
      crypto.timingSafeEqual(
        Buffer.from(
          currentHash,
          "hex"
        ),
        Buffer.from(
          acquisitionHash,
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
        : "Evidence integrity verification failed. The current evidence differs from the acquisition baseline.",
  };
}


/* ============================================================
   EVIDENCE DISCOVERY
   ============================================================ */

async function discoverEvidenceFiles() {
  const entries =
    await fs.promises.readdir(
      EVIDENCE_DIR,
      {
        withFileTypes: true,
      }
    );

  const evidence = [];

  for (
    const entry of entries
  ) {
    if (!entry.isFile()) {
      continue;
    }

    const filePath =
      safeEvidencePath(
        entry.name
      );

    const stats =
      await fs.promises.stat(
        filePath
      );

    const manifest =
      await loadManifestByFileName(
        entry.name
      );

    let integrity =
      null;

    /*
     * Do not fail the entire
     * repository listing because
     * one evidence file has a
     * missing/invalid baseline.
     */
    try {
      integrity =
        await verifyEvidenceIntegrity(
          entry.name
        );
    } catch {
      integrity = null;
    }

    evidence.push({
      id:
        manifest?.evidence_id ||
        `${entry.name}-${stats.size}-${stats.mtimeMs}`,

      name:
        entry.name,

      originalName:
        manifest?.original_name ||
        entry.name,

      size:
        stats.size,

      type:
        path
          .extname(
            entry.name
          )
          .replace(
            ".",
            ""
          )
          .toUpperCase() ||
        "FILE",

      modifiedAt:
        stats.mtime.toISOString(),

      evidenceId:
        manifest?.evidence_id ||
        null,

      acquiredAt:
        manifest?.acquired_at ||
        null,

      acquisitionHash:
        manifest?.sha256 ||
        null,

      currentHash:
        integrity?.currentHash ||
        null,

      integrityBaseline:
        Boolean(
          manifest?.integrity_baseline
        ),

      integrityStatus:
        integrity?.status ||
        "BASELINE_MISSING",

      verified:
        Boolean(
          integrity?.verified
        ),
    });
  }

  evidence.sort(
    (a, b) =>
      new Date(
        b.modifiedAt
      ) -
      new Date(
        a.modifiedAt
      )
  );

  return evidence;
}


/* ============================================================
   PYTHON EXECUTION
   ============================================================ */

function executePython(
  pythonCommand,
  args,
  options = {}
) {
  return new Promise(
    (resolve, reject) => {
      const timeoutMs =
        options.timeoutMs ||
        SCAN_TIMEOUT_MS;

      const child =
        spawn(
          pythonCommand,
          args,
          {
            cwd:
              options.cwd ||
              FORENSIC_PARENT,

            windowsHide:
              true,

            stdio: [
              "ignore",
              "pipe",
              "pipe",
            ],

            env: {
              ...process.env,

              PYTHONUNBUFFERED:
                "1",
            },
          }
        );

      let stdout = "";
      let stderr = "";

      let settled =
        false;

      let timeout =
        null;

      const cleanup =
        () => {
          if (timeout) {
            clearTimeout(
              timeout
            );

            timeout = null;
          }
        };

      const rejectOnce =
        (error) => {
          if (settled) {
            return;
          }

          settled =
            true;

          cleanup();

          reject(error);
        };

      const resolveOnce =
        (result) => {
          if (settled) {
            return;
          }

          settled =
            true;

          cleanup();

          resolve(result);
        };

      timeout =
        setTimeout(
          () => {
            try {
              child.kill(
                process.platform ===
                  "win32"
                  ? undefined
                  : "SIGTERM"
              );
            } catch {
              // Ignore.
            }

            const error =
              new Error(
                `Forensic engine timed out after ${timeoutMs} ms.`
              );

            error.code =
              "FORENSIC_TIMEOUT";

            rejectOnce(
              error
            );
          },
          timeoutMs
        );

      child.stdout.on(
        "data",
        (chunk) => {
          stdout +=
            chunk.toString();
        }
      );

      child.stderr.on(
        "data",
        (chunk) => {
          stderr +=
            chunk.toString();
        }
      );

      child.once(
        "error",
        (error) => {
          error.pythonCommand =
            pythonCommand;

          rejectOnce(
            error
          );
        }
      );

      child.once(
        "close",
        (code, signal) => {
          resolveOnce({
            code,
            signal,
            stdout,
            stderr,
            pythonCommand,
          });
        }
      );
    }
  );
}


/* ============================================================
   FORENSIC JSON PARSER
   ============================================================ */

/*
 * THIS FUNCTION FIXES:

 * ReferenceError:
 * parseForensicJSON is not defined
 *
 * Python may write logs before the
 * JSON result, therefore parsing only
 * JSON.parse(stdout.trim()) is fragile.
 */

function parseForensicJSON(
  stdout
) {
  if (
    !stdout ||
    !String(stdout).trim()
  ) {
    return null;
  }

  const text =
    String(stdout).trim();

  /*
   * First attempt:
   * stdout itself is JSON.
   */

  try {
    const parsed =
      JSON.parse(text);

    if (
      parsed &&
      typeof parsed ===
        "object"
    ) {
      return parsed;
    }
  } catch {
    // Continue.
  }

  /*
   * Second attempt:
   * each line may contain JSON.
   */

  const lines =
    text
      .split(/\r?\n/)
      .map(
        (line) =>
          line.trim()
      )
      .filter(Boolean);

  for (
    let i =
      lines.length - 1;
    i >= 0;
    i--
  ) {
    try {
      const parsed =
        JSON.parse(
          lines[i]
        );

      if (
        parsed &&
        typeof parsed ===
          "object"
      ) {
        return parsed;
      }
    } catch {
      // Continue.
    }
  }

  /*
   * Third attempt:
   * locate a JSON object embedded
   * in stdout.
   */

  const firstBrace =
    text.indexOf("{");

  const lastBrace =
    text.lastIndexOf("}");

  if (
    firstBrace !== -1 &&
    lastBrace > firstBrace
  ) {
    const candidate =
      text.slice(
        firstBrace,
        lastBrace + 1
      );

    try {
      const parsed =
        JSON.parse(
          candidate
        );

      if (
        parsed &&
        typeof parsed ===
          "object"
      ) {
        return parsed;
      }
    } catch {
      // Invalid embedded JSON.
    }
  }

  return null;
}


/* ============================================================
   PYTHON FORENSIC CLI
   ============================================================ */

async function runForensicCLI({
  evidencePath,
  outputDir,
  caseId = null,
  examiner = null,
}) {
  const cliPath =
    path.join(
      FORENSIC_ROOT,
      "cli.py"
    );

  if (
    !fs.existsSync(
      cliPath
    )
  ) {
    const error =
      new Error(
        `Forensic CLI not found: ${cliPath}`
      );

    error.code =
      "FORENSIC_CLI_NOT_FOUND";

    throw error;
  }

  /*
   * Your Python engine supports:

   * python -m forensic_recovery.cli
   *   --json
   *   scan
   *   --input ...
   *   --output ...

   * See the existing TrustWipe
   * forensic CLI implementation.
   */

  const args = [
    "-m",
    "forensic_recovery.cli",

    "--json",

    "scan",

    "--input",
    evidencePath,

    "--output",
    outputDir,
  ];

  if (caseId) {
    args.push(
      "--case",
      caseId
    );
  }

  if (examiner) {
    args.push(
      "--examiner",
      examiner
    );
  }

  const pythonCommands =
    getPythonCommands();

  let lastError =
    null;

  for (
    const pythonCommand of
      pythonCommands
  ) {
    try {
      /*
       * Explicit .exe paths are
       * allowed. "python"/"py" are
       * resolved through PATH.
       */

      return await executePython(
        pythonCommand,
        args,
        {
          cwd:
            FORENSIC_PARENT,

          timeoutMs:
            SCAN_TIMEOUT_MS,
        }
      );
    } catch (error) {
      lastError =
        error;

      if (
        error.code ===
        "FORENSIC_TIMEOUT"
      ) {
        throw error;
      }
    }
  }

  const error =
    lastError ||
    new Error(
      "Unable to start Python forensic engine."
    );

  error.code =
    error.code ||
    "PYTHON_UNAVAILABLE";

  throw error;
}


/* ============================================================
   RECOVERED FILE DISCOVERY
   ============================================================ */

async function discoverRecoveredFiles(
  outputDirectory,
  caseId,
  scanId
) {
  const files = [];

  /*
   * Recursive traversal is important.
   *
   * Some carving engines create:
   *
   * scan/
   *   image/
   *   documents/
   *   archives/
   *
   * rather than placing every
   * recovered artifact directly
   * inside scan/.
   */

  async function walk(
    directory
  ) {
    if (
      files.length >=
      MAX_OUTPUT_FILES
    ) {
      return;
    }

    const entries =
      await fs.promises.readdir(
        directory,
        {
          withFileTypes:
            true,
        }
      );

    for (
      const entry of entries
    ) {
      if (
        files.length >=
        MAX_OUTPUT_FILES
      ) {
        return;
      }

      const currentPath =
        path.join(
          directory,
          entry.name
        );

      if (
        entry.isDirectory()
      ) {
        await walk(
          currentPath
        );

        continue;
      }

      if (
        !entry.isFile()
      ) {
        continue;
      }

      const stats =
        await fs.promises.stat(
          currentPath
        );

      const sha256 =
        await calculateSHA256(
          currentPath
        );

      const relativePath =
        path
          .relative(
            outputDirectory,
            currentPath
          )
          .split(
            path.sep
          )
          .join("/");

      const encodedCase =
        encodeURIComponent(
          caseId
        );

      const encodedScan =
        encodeURIComponent(
          scanId
        );

      /*
       * Query parameter avoids
       * Express 5 wildcard route
       * incompatibility.
       */

      const downloadPath =
        `/api/forensic/recovered-file/${encodedCase}/${encodedScan}?file=${encodeURIComponent(
          relativePath
        )}`;

      files.push({
        name:
          path.basename(
            currentPath
          ),

        relativePath,

        size:
          stats.size,

        type:
          path
            .extname(
              currentPath
            )
            .replace(
              ".",
              ""
            )
            .toUpperCase() ||
          "FILE",

        sha256,

        modifiedAt:
          stats.mtime.toISOString(),

        path:
          downloadPath,

        downloadUrl:
          downloadPath,
      });
    }
  }

  await walk(
    outputDirectory
  );

  return files;
}


/* ============================================================
   ENGINE STATUS
   ============================================================ */

router.get(
  "/status",
  async (_req, res) => {
    const pythonCommands =
      getPythonCommands();

    for (
      const pythonCommand of
        pythonCommands
    ) {
      try {
        const result =
          await executePython(
            pythonCommand,
            [
              "--version",
            ],
            {
              cwd:
                FORENSIC_PARENT,

              timeoutMs:
                5000,
            }
          );

        const version =
          (
            result.stdout ||
            result.stderr ||
            ""
          ).trim();

        if (
          result.code === 0
        ) {
          return res.json({
            success: true,

            pythonAvailable:
              true,

            pythonCommand,

            pythonVersion:
              version || null,

            engine:
              "READY",
          });
        }
      } catch {
        // Try next interpreter.
      }
    }

    return res.json({
      success: true,

      pythonAvailable:
        false,

      pythonCommand:
        null,

      pythonVersion:
        null,

      engine:
        "UNAVAILABLE",
    });
  }
);


/* ============================================================
   GET EVIDENCE
   ============================================================ */

router.get(
  "/evidence",
  async (_req, res) => {
    try {
      const evidence =
        await discoverEvidenceFiles();

      const totalSize =
        evidence.reduce(
          (sum, item) =>
            sum +
            Number(
              item.size || 0
            ),
          0
        );

      return res.json({
        success: true,

        count:
          evidence.length,

        totalSize,

        evidence,

        synchronizedAt:
          new Date().toISOString(),
      });
    } catch (error) {
      console.error(
        "[FORENSICS] Evidence discovery failed:",
        error
      );

      return res.status(
        500
      ).json({
        success: false,

        code:
          "EVIDENCE_DISCOVERY_FAILED",

        message:
          "Unable to discover evidence.",
      });
    }
  }
);


/* ============================================================
   ACQUIRE EVIDENCE
   ============================================================ */

router.post(
  "/upload",
  (req, res) => {
    upload.single(
      "evidence"
    )(
      req,
      res,
      async (error) => {
        try {
          if (
            error instanceof
            multer.MulterError
          ) {
            if (
              error.code ===
              "LIMIT_FILE_SIZE"
            ) {
              return res
                .status(413)
                .json({
                  success:
                    false,

                  code:
                    "EVIDENCE_TOO_LARGE",

                  message:
                    "Evidence exceeds the configured maximum size.",
                });
            }

            return res
              .status(400)
              .json({
                success:
                  false,

                code:
                  "UPLOAD_ERROR",

                message:
                  error.message,
              });
          }

          if (error) {
            console.error(
              "[FORENSICS] Upload error:",
              error
            );

            return res
              .status(500)
              .json({
                success:
                  false,

                code:
                  "UPLOAD_FAILED",

                message:
                  "Evidence acquisition failed.",
              });
          }

          if (!req.file) {
            return res
              .status(400)
              .json({
                success:
                  false,

                code:
                  "EVIDENCE_REQUIRED",

                message:
                  "Please select an evidence file.",
              });
          }

          const filePath =
            req.file.path;

          const stats =
            await fs.promises.stat(
              filePath
            );

          const sha256 =
            await calculateSHA256(
              filePath
            );

          const acquiredAt =
            new Date().toISOString();

          const evidenceId =
            createEvidenceId();

          const originalName =
            decodeOriginalFilename(
              req.file.originalname
            );

          /*
           * This manifest is the
           * immutable acquisition
           * baseline.
           */

          const manifest = {
            schema_version:
              "1.0",

            evidence_id:
              evidenceId,

            file_name:
              req.file.filename,

            original_name:
              originalName,

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
          };

          await saveManifest(
            manifest
          );

          /*
           * Best-effort read-only
           * protection.
           *
           * Windows may not enforce
           * POSIX chmod semantics.
           */

          try {
            await fs.promises.chmod(
              filePath,
              0o444
            );
          } catch {
            // Ignore on Windows.
          }

          return res
            .status(201)
            .json({
              success:
                true,

              message:
                "Evidence acquired and SHA-256 baseline established.",

              evidence: {
                evidenceId,

                id:
                  evidenceId,

                name:
                  req.file.filename,

                originalName,

                size:
                  stats.size,

                sha256,

                algorithm:
                  "SHA-256",

                acquiredAt,

                integrityStatus:
                  "VERIFIED",

                baseline:
                  true,
              },
            });
        } catch (error) {
          console.error(
            "[FORENSICS] Acquisition processing failed:",
            error
          );

          /*
           * If acquisition fails,
           * remove the partial file.
           */

          if (
            req.file?.path
          ) {
            try {
              await fs.promises.chmod(
                req.file.path,
                0o666
              );
            } catch {
              // Ignore.
            }

            try {
              await fs.promises.unlink(
                req.file.path
              );
            } catch {
              // Ignore.
            }
          }

          if (
            !res.headersSent
          ) {
            return res
              .status(500)
              .json({
                success:
                  false,

                code:
                  "ACQUISITION_FAILED",

                message:
                  error.message ||
                  "Unable to acquire evidence.",
              });
          }
        }
      }
    );
  }
);


/* ============================================================
   HASH
   ============================================================ */

router.post(
  "/hash",
  async (req, res) => {
    try {
      const {
        fileName,
      } =
        req.body || {};

      if (!fileName) {
        return res
          .status(400)
          .json({
            success:
              false,

            code:
              "EVIDENCE_REQUIRED",

            message:
              "Evidence file name is required.",
          });
      }

      const integrity =
        await verifyEvidenceIntegrity(
          fileName
        );

      return res.json({
        success:
          true,

        fileName,

        algorithm:
          "SHA-256",

        sha256:
          integrity.currentHash,

        acquisitionHash:
          integrity.originalHash,

        integrityStatus:
          integrity.status,

        hashMatch:
          integrity.hashMatch,

        sizeMatch:
          integrity.sizeMatch,

        integrity,
      });
    } catch (error) {
      console.error(
        "[FORENSICS] Hash failed:",
        error
      );

      return res
        .status(
          error.code ===
            "EVIDENCE_NOT_FOUND"
            ? 404
            : 500
        )
        .json({
          success:
            false,

          code:
            error.code ||
            "HASH_FAILED",

          message:
            error.message ||
            "Unable to calculate evidence hash.",
        });
    }
  }
);


/* ============================================================
   VERIFY INTEGRITY
   ============================================================ */

router.post(
  "/verify-integrity",
  async (req, res) => {
    try {
      const {
        fileName,
        evidenceId,
      } =
        req.body || {};

      let resolvedFileName =
        fileName;

      /*
       * Allow frontend to send
       * evidenceId instead of fileName.
       */

      if (
        !resolvedFileName &&
        evidenceId
      ) {
        const manifest =
          await loadManifestByEvidenceId(
            evidenceId
          );

        if (manifest) {
          resolvedFileName =
            manifest.file_name;
        }
      }

      if (!resolvedFileName) {
        return res
          .status(400)
          .json({
            success:
              false,

            code:
              "EVIDENCE_REQUIRED",

            message:
              "Evidence file name or evidence ID is required.",
          });
      }

      resolvedFileName =
        path.basename(
          String(
            resolvedFileName
          )
        );

      const integrity =
        await verifyEvidenceIntegrity(
          resolvedFileName
        );

      return res.json({
        success:
          true,

        fileName:
          resolvedFileName,

        evidenceId:
          integrity.evidenceId,

        integrity,
      });
    } catch (error) {
      console.error(
        "[FORENSICS] Integrity verification failed:",
        error
      );

      return res
        .status(
          error.code ===
            "EVIDENCE_NOT_FOUND"
            ? 404
            : 500
        )
        .json({
          success:
            false,

          code:
            error.code ||
            "INTEGRITY_CHECK_FAILED",

          message:
            error.message ||
            "Unable to verify evidence integrity.",
        });
    }
  }
);


/* ============================================================
   FORENSIC SCAN
   ============================================================ */

router.post(
  "/scan",
  async (req, res) => {
    const startedAt =
      Date.now();

    let scanOutput =
      null;

    try {
      const {
        fileName,
        evidenceId,
        caseId,
        examiner =
          "TrustWipe Examiner",
      } =
        req.body || {};

      /* --------------------------------------------------------
         VALIDATION
         -------------------------------------------------------- */

      if (
        !fileName &&
        !evidenceId
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            code:
              "EVIDENCE_REQUIRED",

            message:
              "Evidence file name or evidence ID is required.",
          });
      }

      if (!caseId) {
        return res
          .status(400)
          .json({
            success:
              false,

            code:
              "CASE_ID_REQUIRED",

            message:
              "Case ID is required.",
          });
      }

      const safeCase =
        sanitizeCaseId(
          caseId
        );

      /* --------------------------------------------------------
         RESOLVE EVIDENCE
         -------------------------------------------------------- */

      let resolvedFileName =
        fileName;

      if (
        !resolvedFileName &&
        evidenceId
      ) {
        const manifest =
          await loadManifestByEvidenceId(
            evidenceId
          );

        if (manifest) {
          resolvedFileName =
            manifest.file_name;
        }
      }

      if (!resolvedFileName) {
        return res
          .status(404)
          .json({
            success:
              false,

            code:
              "EVIDENCE_NOT_FOUND",

            message:
              "Unable to resolve evidence.",
          });
      }

      resolvedFileName =
        path.basename(
          String(
            resolvedFileName
          )
        );

      /* --------------------------------------------------------
         VERIFY EVIDENCE EXISTS
         -------------------------------------------------------- */

      const evidencePath =
        safeEvidencePath(
          resolvedFileName
        );

      try {
        const stats =
          await fs.promises.stat(
            evidencePath
          );

        if (!stats.isFile()) {
          throw new Error(
            "Evidence path is not a file."
          );
        }
      } catch {
        return res
          .status(404)
          .json({
            success:
              false,

            code:
              "EVIDENCE_FILE_NOT_FOUND",

            message:
              "Evidence file not found or is not readable.",
          });
      }

      /* --------------------------------------------------------
         PRE-SCAN INTEGRITY
         -------------------------------------------------------- */

      const preIntegrity =
        await verifyEvidenceIntegrity(
          resolvedFileName
        );

      /*
       * NEVER run recovery on:
       *
       * - missing baseline
       * - modified evidence
       * - invalid baseline
       *
       * This is essential for
       * forensic chain of custody.
       */

      if (
        !preIntegrity.verified ||
        preIntegrity.status !==
          "VERIFIED"
      ) {
        return res
          .status(409)
          .json({
            success:
              false,

            code:
              preIntegrity.status ===
              "BASELINE_MISSING"
                ? "BASELINE_MISSING"
                : "EVIDENCE_TAMPERED",

            message:
              preIntegrity.status ===
              "BASELINE_MISSING"
                ? "Evidence acquisition baseline is missing. Re-acquire the evidence before forensic recovery."
                : "Forensic recovery is blocked because evidence integrity verification failed.",

            integrity:
              preIntegrity,
          });
      }

      /* --------------------------------------------------------
         CASE DIRECTORIES
         -------------------------------------------------------- */

      const caseDirectories =
        await ensureCaseDirectories(
          safeCase
        );

      const scanId =
        `SCAN-${Date.now()}-${crypto
          .randomBytes(4)
          .toString("hex")}`;

      scanOutput =
        path.join(
          caseDirectories.recovered,
          scanId
        );

      await fs.promises.mkdir(
        scanOutput,
        {
          recursive:
            true,
        }
      );

      /* --------------------------------------------------------
         RUN PYTHON FORENSIC ENGINE
         -------------------------------------------------------- */

      console.log(
        `[FORENSICS] Starting scan ${scanId}`
      );

      console.log(
        `[FORENSICS] Evidence: ${resolvedFileName}`
      );

      console.log(
        `[FORENSICS] Case: ${safeCase}`
      );

      const pythonResult =
        await runForensicCLI({
          evidencePath,

          outputDir:
            scanOutput,

          caseId:
            safeCase,

          examiner:
            String(
              examiner ||
                "TrustWipe Examiner"
            ),
        });

      console.log(
        `[FORENSICS] Python exit code: ${pythonResult.code}`
      );

      /* --------------------------------------------------------
         PYTHON ENGINE FAILURE
         -------------------------------------------------------- */

      if (
        pythonResult.code !== 0
      ) {
        console.error(
          "[FORENSICS] Python forensic engine failed."
        );

        console.error(
          pythonResult.stderr
        );

        await fs.promises.rm(
          scanOutput,
          {
            recursive:
              true,

            force:
              true,
          }
        );

        scanOutput =
          null;

        return res
          .status(500)
          .json({
            success:
              false,

            code:
              "FORENSIC_ENGINE_FAILED",

            message:
              "Forensic recovery engine failed.",

            exitCode:
              pythonResult.code,

            signal:
              pythonResult.signal,

            stdout:
              pythonResult.stdout ||
              null,

            stderr:
              pythonResult.stderr ||
              null,

            pythonCommand:
              pythonResult.pythonCommand,

            durationMs:
              Date.now() -
              startedAt,
          });
      }

      /* --------------------------------------------------------
         PARSE PYTHON RESULT
         -------------------------------------------------------- */

      const scanResult =
        parseForensicJSON(
          pythonResult.stdout
        );

      if (!scanResult) {
        console.error(
          "[FORENSICS] Python output was not valid JSON."
        );

        console.error(
          "STDOUT:",
          pythonResult.stdout
        );

        console.error(
          "STDERR:",
          pythonResult.stderr
        );

        await fs.promises.rm(
          scanOutput,
          {
            recursive:
              true,

            force:
              true,
          }
        );

        scanOutput =
          null;

        return res
          .status(500)
          .json({
            success:
              false,

            code:
              "FORENSIC_RESULT_INVALID",

            message:
              "Forensic engine completed but returned an invalid scan result.",

            stdout:
              pythonResult.stdout ||
              null,

            stderr:
              pythonResult.stderr ||
              null,

            durationMs:
              Date.now() -
              startedAt,
          });
      }

      /* --------------------------------------------------------
         POST-SCAN INTEGRITY
         -------------------------------------------------------- */

      const postIntegrity =
        await verifyEvidenceIntegrity(
          resolvedFileName
        );

      if (
        !postIntegrity.verified ||
        postIntegrity.status !==
          "VERIFIED"
      ) {
        console.error(
          "[FORENSICS] Evidence changed during scan."
        );

        await fs.promises.rm(
          scanOutput,
          {
            recursive:
              true,

            force:
              true,
          }
        );

        scanOutput =
          null;

        return res
          .status(409)
          .json({
            success:
              false,

            code:
              "EVIDENCE_CHANGED_DURING_SCAN",

            message:
              "Evidence changed during forensic analysis. Recovery results must not be treated as valid.",

            integrity:
              postIntegrity,
          });
      }

      /* --------------------------------------------------------
         DISCOVER RECOVERED FILES
         -------------------------------------------------------- */

      const recoveredFiles =
        await discoverRecoveredFiles(
          scanOutput,
          safeCase,
          scanId
        );

      /* --------------------------------------------------------
         NORMALIZED SCAN STATISTICS
         -------------------------------------------------------- */

      const scan = {
        status:
          scanResult.status ||
          "COMPLETED",

        evidenceSize:
          scanResult.evidence_size ??
          scanResult.evidenceSize ??
          0,

        chunkSize:
          scanResult.chunk_size ??
          scanResult.chunkSize ??
          0,

        overlapSize:
          scanResult.overlap_size ??
          scanResult.overlapSize ??
          0,

        chunksScanned:
          scanResult.chunks_scanned ??
          scanResult.chunksScanned ??
          0,

        bytesScanned:
          scanResult.bytes_scanned ??
          scanResult.bytesScanned ??
          0,

        signaturesDetected:
          scanResult.signatures_detected ??
          scanResult.signaturesDetected ??
          0,

        candidateRanges:
          scanResult.candidate_ranges ??
          scanResult.candidateRanges ??
          0,

        artifactsCarved:
          scanResult.artifacts_carved ??
          scanResult.artifactsCarved ??
          0,

        artifactsValidated:
          scanResult.artifacts_validated ??
          scanResult.artifactsValidated ??
          0,

        artifacts:
          Array.isArray(
            scanResult.artifacts
          )
            ? scanResult.artifacts
            : [],
      };

      /* --------------------------------------------------------
         FINAL RESPONSE
         -------------------------------------------------------- */

      const completedAt =
        new Date().toISOString();

      return res.json({
        success:
          true,

        status:
          "COMPLETED",

        caseId:
          safeCase,

        scanId,

        examiner:
          String(
            examiner ||
              "TrustWipe Examiner"
          ),

        startedAt:
          new Date(
            startedAt
          ).toISOString(),

        completedAt,

        durationMs:
          Date.now() -
          startedAt,

        /*
         * Frontend expects a
         * top-level integrity object.
         */

        integrity:
          postIntegrity,

        /*
         * Evidence information.
         */

        evidence: {
          fileName:
            resolvedFileName,

          evidenceId:
            postIntegrity.evidenceId,

          acquisitionHash:
            postIntegrity.originalHash,

          currentHash:
            postIntegrity.currentHash,

          size:
            postIntegrity.currentSize,

          integrity:
            postIntegrity.verified
              ? "VERIFIED"
              : "FAILED",
        },

        /*
         * Scanner statistics.
         */

        scan,

        /*
         * Recovery information.
         */

        recovery: {
          status:
            "COMPLETED",

          recoveredCount:
            recoveredFiles.length,

          outputDirectory:
            scanId,

          files:
            recoveredFiles,
        },

        /*
         * Raw engine information.
         */

        engine: {
          pythonCommand:
            pythonResult.pythonCommand,

          exitCode:
            pythonResult.code,

          stdout:
            pythonResult.stdout ||
            "",

          stderr:
            pythonResult.stderr ||
            "",
        },

        message:
          `Forensic recovery completed. ${recoveredFiles.length} candidate artifact(s) recovered.`,
      });
    } catch (error) {
      console.error(
        "[FORENSICS] Scan error:",
        error
      );

      if (scanOutput) {
        try {
          await fs.promises.rm(
            scanOutput,
            {
              recursive:
                true,

              force:
                true,
            }
          );
        } catch {
          // Ignore cleanup.
        }
      }

      if (
        !res.headersSent
      ) {
        return res
          .status(500)
          .json({
            success:
              false,

            code:
              error.code ||
              "FORENSIC_SCAN_ERROR",

            message:
              error.message ||
              "Forensic analysis failed.",

            durationMs:
              Date.now() -
              startedAt,
          });
      }
    }
  }
);


/* ============================================================
   RECOVERED FILE DOWNLOAD
   ============================================================

   IMPORTANT:

   Do NOT use:

   /recovered/:caseId/:scanId/*

   Express 5 / path-to-regexp rejects
   that route.

   Instead use:

   /recovered-file/:caseId/:scanId?file=...

   ============================================================ */

router.get(
  "/recovered-file/:caseId/:scanId",
  async (req, res) => {
    try {
      const safeCase =
        sanitizeCaseId(
          req.params.caseId
        );

      const safeScanId =
        path.basename(
          String(
            req.params.scanId
          )
        );

      const requestedFile =
        req.query.file;

      if (
        !requestedFile ||
        typeof requestedFile !==
          "string"
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            code:
              "RECOVERED_FILE_REQUIRED",

            message:
              "Recovered artifact path is required.",
          });
      }

      let decodedPath;

      try {
        decodedPath =
          decodeURIComponent(
            requestedFile
          );
      } catch {
        decodedPath =
          requestedFile;
      }

      /*
       * Normalize separators.
       */

      decodedPath =
        decodedPath
          .replace(
            /\\/g,
            "/"
          )
          .replace(
            /^\/+/,
            ""
          );

      /*
       * Reject traversal BEFORE
       * path.resolve.
       */

      const segments =
        decodedPath
          .split("/")
          .filter(Boolean);

      if (
        segments.includes(
          ".."
        )
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            code:
              "INVALID_FILE_PATH",

            message:
              "Path traversal is not allowed.",
          });
      }

      const caseDirectories =
        await ensureCaseDirectories(
          safeCase
        );

      const recoveredRoot =
        path.resolve(
          caseDirectories.recovered
        );

      const scanDirectory =
        path.resolve(
          recoveredRoot,
          safeScanId
        );

      if (
        !scanDirectory.startsWith(
          recoveredRoot +
            path.sep
        )
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            code:
              "INVALID_SCAN_PATH",

            message:
              "Invalid scan path.",
          });
      }

      const target =
        path.resolve(
          scanDirectory,
          ...segments
        );

      if (
        !target.startsWith(
          scanDirectory +
            path.sep
        )
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            code:
              "INVALID_FILE_PATH",

            message:
              "Invalid recovered artifact path.",
          });
      }

      let stats;

      try {
        stats =
          await fs.promises.stat(
            target
          );
      } catch {
        return res
          .status(404)
          .json({
            success:
              false,

            code:
              "RECOVERED_FILE_NOT_FOUND",

            message:
              "Recovered artifact not found.",
          });
      }

      if (
        !stats.isFile()
      ) {
        return res
          .status(404)
          .json({
            success:
              false,

            code:
              "RECOVERED_FILE_NOT_FOUND",

            message:
              "Recovered artifact not found.",
          });
      }

      /*
       * Optional final hash.
       *
       * This gives the client
       * an integrity header for
       * the recovered artifact.
       */

      let recoveredHash =
        null;

      try {
        recoveredHash =
          await calculateSHA256(
            target
          );
      } catch {
        // Download can continue.
      }

      if (recoveredHash) {
        res.setHeader(
          "X-TrustWipe-SHA256",
          recoveredHash
        );
      }

      res.setHeader(
        "X-TrustWipe-Case",
        safeCase
      );

      res.setHeader(
        "X-TrustWipe-Scan",
        safeScanId
      );

      return res.download(
        target,
        path.basename(
          target
        ),
        (error) => {
          if (error) {
            console.error(
              "[FORENSICS] Recovered download error:",
              error
            );

            if (
              !res.headersSent
            ) {
              res
                .status(500)
                .json({
                  success:
                    false,

                  code:
                    "RECOVERED_DOWNLOAD_FAILED",

                  message:
                    "Unable to download recovered artifact.",
                });
            }
          }
        }
      );
    } catch (error) {
      console.error(
        "[FORENSICS] Recovered file error:",
        error
      );

      if (
        !res.headersSent
      ) {
        return res
          .status(500)
          .json({
            success:
              false,

            code:
              error.code ||
              "RECOVERED_DOWNLOAD_FAILED",

            message:
              error.message ||
              "Unable to download recovered artifact.",
          });
      }
    }
  }
);


/* ============================================================
   LEGACY SINGLE-FILENAME DOWNLOAD
   ============================================================

   Kept for compatibility with
   older frontend responses.

   Supports:

   /recovered/:caseId/:scanId/:fileName

   It deliberately supports ONLY
   a single filename.

   Nested files should use the
   /recovered-file endpoint above.
   ============================================================ */

router.get(
  "/recovered/:caseId/:scanId/:fileName",
  async (req, res) => {
    try {
      const safeCase =
        sanitizeCaseId(
          req.params.caseId
        );

      const safeScanId =
        path.basename(
          String(
            req.params.scanId
          )
        );

      const safeFileName =
        path.basename(
          String(
            req.params.fileName
          )
        );

      const caseDirectories =
        await ensureCaseDirectories(
          safeCase
        );

      const scanDirectory =
        path.resolve(
          caseDirectories.recovered,
          safeScanId
        );

      const target =
        path.resolve(
          scanDirectory,
          safeFileName
        );

      if (
        !scanDirectory.startsWith(
          path.resolve(
            caseDirectories.recovered
          ) +
            path.sep
        )
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            code:
              "INVALID_SCAN_PATH",

            message:
              "Invalid scan path.",
          });
      }

      if (
        !target.startsWith(
          scanDirectory +
            path.sep
        )
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            code:
              "INVALID_FILE_PATH",

            message:
              "Invalid recovered artifact path.",
          });
      }

      try {
        const stats =
          await fs.promises.stat(
            target
          );

        if (
          !stats.isFile()
        ) {
          throw new Error(
            "Not a file"
          );
        }
      } catch {
        return res
          .status(404)
          .json({
            success:
              false,

            code:
              "RECOVERED_FILE_NOT_FOUND",

            message:
              "Recovered artifact not found.",
          });
      }

      return res.download(
        target,
        safeFileName
      );
    } catch (error) {
      console.error(
        "[FORENSICS] Legacy recovered download failed:",
        error
      );

      return res
        .status(500)
        .json({
          success:
            false,

          code:
            "RECOVERED_DOWNLOAD_FAILED",

          message:
            "Unable to download recovered artifact.",
        });
    }
  }
);


/* ============================================================
   GENERATE FORENSIC REPORT
   ============================================================ */

router.post(
  "/report",
  async (req, res) => {
    try {
      const {
        fileName,
        evidenceId,
        caseId,
        examiner =
          "TrustWipe Examiner",
      } =
        req.body || {};

      if (
        !fileName &&
        !evidenceId
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            code:
              "EVIDENCE_REQUIRED",

            message:
              "Evidence file name or evidence ID is required.",
          });
      }

      if (!caseId) {
        return res
          .status(400)
          .json({
            success:
              false,

            code:
              "CASE_ID_REQUIRED",

            message:
              "Case ID is required.",
          });
      }

      let resolvedFileName =
        fileName;

      if (
        !resolvedFileName &&
        evidenceId
      ) {
        const manifest =
          await loadManifestByEvidenceId(
            evidenceId
          );

        if (manifest) {
          resolvedFileName =
            manifest.file_name;
        }
      }

      if (!resolvedFileName) {
        return res
          .status(404)
          .json({
            success:
              false,

            code:
              "EVIDENCE_NOT_FOUND",

            message:
              "Unable to resolve evidence.",
          });
      }

      const safeFileName =
        path.basename(
          String(
            resolvedFileName
          )
        );

      const evidencePath =
        safeEvidencePath(
          safeFileName
        );

      try {
        const stats =
          await fs.promises.stat(
            evidencePath
          );

        if (
          !stats.isFile()
        ) {
          throw new Error(
            "Not a file"
          );
        }
      } catch {
        return res
          .status(404)
          .json({
            success:
              false,

            code:
              "EVIDENCE_NOT_FOUND",

            message:
              "Evidence file not found.",
          });
      }

      const integrity =
        await verifyEvidenceIntegrity(
          safeFileName
        );

      const stats =
        await fs.promises.stat(
          evidencePath
        );

      const safeCase =
        sanitizeCaseId(
          caseId
        );

      const safeExaminer =
        String(
          examiner ||
            "TrustWipe Examiner"
        ).trim();

      const generatedAt =
        new Date().toISOString();

      const report = {
        schema_version:
          "1.0",

        application:
          "TrustWipe Digital Forensics",

        case_id:
          safeCase,

        examiner:
          safeExaminer,

        generated_at:
          generatedAt,

        evidence: {
          evidence_id:
            integrity.evidenceId,

          file_name:
            safeFileName,

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

          message:
            integrity.message,
        },

        forensic_recovery: {
          performed:
            integrity.status ===
            "VERIFIED",

          status:
            integrity.status ===
            "VERIFIED"
              ? "ELIGIBLE"
              : "BLOCKED",

          note:
            "Forensic recovery requires successful acquisition-integrity verification.",
        },

        compliance: {
          framework:
            "NIST SP 800-88",

          standard:
            "NIST SP 800-88",

          classification:
            "Media sanitization guidance",

          note:
            "NIST SP 800-88 concerns media sanitization. TrustWipe records SHA-256 acquisition integrity and forensic recovery separately.",
        },
      };

      const caseDirectories =
        await ensureCaseDirectories(
          safeCase
        );

      const reportFileName =
        `${safeCase}-${Date.now()}-${crypto
          .randomBytes(4)
          .toString("hex")}.json`;

      const reportPath =
        path.join(
          caseDirectories.reports,
          reportFileName
        );

      await fs.promises.writeFile(
        reportPath,
        JSON.stringify(
          report,
          null,
          2
        ),
        {
          encoding:
            "utf8",

          flag:
            "wx",
        }
      );

      return res.json({
        success:
          true,

        message:
          integrity.status ===
          "VERIFIED"
            ? "Forensic evidence report generated successfully. Evidence integrity is VERIFIED."
            : "Forensic evidence report generated with an integrity warning.",

        report,

        reportFile:
          reportFileName,

        downloadUrl:
          `/api/forensic/report/${encodeURIComponent(
            safeCase
          )}/${encodeURIComponent(
            reportFileName
          )}`,
      });
    } catch (error) {
      console.error(
        "[FORENSICS] Report generation failed:",
        error
      );

      return res
        .status(500)
        .json({
          success:
            false,

          code:
            error.code ||
            "REPORT_GENERATION_FAILED",

          message:
            error.message ||
            "Unable to generate forensic report.",
        });
    }
  }
);


/* ============================================================
   REPORT DOWNLOAD
   ============================================================ */

router.get(
  "/report/:caseId/:fileName",
  async (req, res) => {
    try {
      const safeCase =
        sanitizeCaseId(
          req.params.caseId
        );

      const safeFile =
        path.basename(
          String(
            req.params.fileName
          )
        );

      const caseDirectories =
        await ensureCaseDirectories(
          safeCase
        );

      const reportsRoot =
        path.resolve(
          caseDirectories.reports
        );

      const reportPath =
        path.resolve(
          reportsRoot,
          safeFile
        );

      if (
        !reportPath.startsWith(
          reportsRoot +
            path.sep
        )
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            code:
              "INVALID_REPORT_PATH",

            message:
              "Invalid report path.",
          });
      }

      try {
        const stats =
          await fs.promises.stat(
            reportPath
          );

        if (
          !stats.isFile()
        ) {
          throw new Error(
            "Not a file"
          );
        }
      } catch {
        return res
          .status(404)
          .json({
            success:
              false,

            code:
              "REPORT_NOT_FOUND",

            message:
              "Report not found.",
          });
      }

      return res.download(
        reportPath,
        safeFile
      );
    } catch (error) {
      console.error(
        "[FORENSICS] Report download failed:",
        error
      );

      return res
        .status(500)
        .json({
          success:
            false,

          code:
            "REPORT_DOWNLOAD_FAILED",

          message:
            "Unable to download report.",
        });
    }
  }
);


/* ============================================================
   EXPORT
   ============================================================ */

export default router;