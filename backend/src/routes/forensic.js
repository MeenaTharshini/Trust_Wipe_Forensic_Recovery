import express from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { spawn } from "child_process";
import { fileURLToPath } from "url";
import multer from "multer";

const router = express.Router();

/*
|--------------------------------------------------------------------------
| PATH CONFIGURATION
|--------------------------------------------------------------------------
|
| Actual project:
|
| Trust_Wipe/
|   backend/
|     src/
|       routes/
|         forensic.js
|     forensic_recovery/
|       cli.py
|
| From:
|   backend/src/routes
|
| To:
|   backend/forensic_recovery
|
| ../../forensic_recovery
|--------------------------------------------------------------------------
*/

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

const CLI_PATH = path.join(
  FORENSIC_ROOT,
  "cli.py"
);

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
    process.env.FORENSIC_REQUIRE_AUTH || "false"
  ).toLowerCase() === "true";

const FORENSIC_API_KEY =
  process.env.FORENSIC_API_KEY || "";

let scanInProgress = false;

/*
|--------------------------------------------------------------------------
| DIRECTORY INITIALIZATION
|--------------------------------------------------------------------------
*/

for (const directory of [
  FORENSIC_ROOT,
  EVIDENCE_DIR,
  RECOVERED_DIR,
  REPORTS_DIR,
  MANIFESTS_DIR,
  CASES_DIR,
]) {
  fs.mkdirSync(directory, {
    recursive: true,
  });
}

/*
|--------------------------------------------------------------------------
| ACCESS CONTROL
|--------------------------------------------------------------------------
*/

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
    suppliedKey === FORENSIC_API_KEY
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

/*
|--------------------------------------------------------------------------
| RESPONSE HELPERS
|--------------------------------------------------------------------------
*/

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
    response.details = error.message;
  }

  return res.status(status).json(response);
}

/*
|--------------------------------------------------------------------------
| FILENAME SECURITY
|--------------------------------------------------------------------------
*/

function decodeOriginalFilename(filename) {
  if (!filename) {
    return "evidence";
  }

  let decoded = String(filename);

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

function sanitizeFilename(filename) {
  const decoded =
    decodeOriginalFilename(filename);

  const basename =
    path.basename(decoded);

  const safe =
    basename
      .replace(
        /[<>:"/\\|?*\x00-\x1F]/g,
        "_"
      )
      .replace(/\s+/g, "_")
      .replace(/^\.+/, "")
      .trim();

  return safe || "evidence";
}

function createUniqueFilename(filename) {
  const safeName =
    sanitizeFilename(filename);

  const extension =
    path.extname(safeName);

  const base =
    path.basename(
      safeName,
      extension
    );

  let candidate = safeName;
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

  return candidate;
}

function sanitizeCaseId(caseId) {
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
    throw new Error(
      "Case ID is required."
    );
  }

  return value;
}

/*
|--------------------------------------------------------------------------
| SAFE PATHS
|--------------------------------------------------------------------------
*/

function safePath(
  rootDirectory,
  requestedName
) {
  if (!requestedName) {
    throw new Error(
      "File name is required."
    );
  }

  const root =
    path.resolve(rootDirectory);

  const normalized =
    String(requestedName)
      .replace(/\\/g, "/");

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

function evidencePath(fileName) {
  return safePath(
    EVIDENCE_DIR,
    path.basename(
      String(fileName)
    )
  );
}

function caseDirectory(caseId) {
  return safePath(
    CASES_DIR,
    sanitizeCaseId(caseId)
  );
}

function caseRecoveredDirectory(caseId) {
  return path.join(
    caseDirectory(caseId),
    "recovered"
  );
}

function reportPath(fileName) {
  return safePath(
    REPORTS_DIR,
    fileName
  );
}

/*
|--------------------------------------------------------------------------
| MULTER
|--------------------------------------------------------------------------
*/

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
       * Forensic evidence may be:
       * IMG, BIN, DD, E01, ISO,
       * memory dumps, unknown binaries,
       * etc.
       *
       * Do not reject based on MIME.
       */
      cb(null, true);
    },
  });

/*
|--------------------------------------------------------------------------
| SHA-256
|--------------------------------------------------------------------------
*/

async function calculateSHA256(
  filePath
) {
  const hash =
    crypto.createHash(
      "sha256"
    );

  await new Promise(
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
        "error",
        reject
      );

      stream.once(
        "end",
        resolve
      );
    }
  );

  return hash.digest("hex");
}

/*
|--------------------------------------------------------------------------
| MANIFESTS
|--------------------------------------------------------------------------
*/

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

async function saveManifest(
  manifest
) {
  const fileName =
    `${manifest.evidence_id}.json`;

  const target =
    safePath(
      MANIFESTS_DIR,
      fileName
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

async function loadManifest(
  fileName
) {
  const entries =
    await fs.promises.readdir(
      MANIFESTS_DIR,
      {
        withFileTypes: true,
      }
    );

  for (const entry of entries) {
    if (
      !entry.isFile() ||
      !entry.name.endsWith(".json")
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

/*
|--------------------------------------------------------------------------
| INTEGRITY
|--------------------------------------------------------------------------
*/

async function verifyEvidenceIntegrity(
  fileName
) {
  const safeName =
    sanitizeFilename(fileName);

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
    throw new Error(
      "Evidence path is not a file."
    );
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
      manifest.sha256 || ""
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

  let hashMatch = false;

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

/*
|--------------------------------------------------------------------------
| EVIDENCE DISCOVERY
|--------------------------------------------------------------------------
*/

async function discoverEvidence() {
  const entries =
    await fs.promises.readdir(
      EVIDENCE_DIR,
      {
        withFileTypes: true,
      }
    );

  const result = [];

  for (const entry of entries) {
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

      integrityStatus:
        manifest?.sha256
          ? "VERIFIED"
          : "BASELINE_MISSING",
    });
  }

  return result.sort(
    (a, b) =>
      new Date(b.modifiedAt) -
      new Date(a.modifiedAt)
  );
}

/*
|--------------------------------------------------------------------------
| PYTHON DISCOVERY
|--------------------------------------------------------------------------
*/

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

      child.once(
        "error",
        (error) => {
          resolve({
            available: false,
            version: null,
            error:
              error.message,
          });
        }
      );

      child.once(
        "close",
        (code) => {
          resolve({
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

/*
|--------------------------------------------------------------------------
| PYTHON FORENSIC SCAN
|--------------------------------------------------------------------------
|
| IMPORTANT:
|
| cli.py expects:
|
| python cli.py scan
|   --input <file>
|   --output <directory>
|   --case <case>
|   --examiner <name>
|   --json
|
|--------------------------------------------------------------------------
*/

function runPythonScan({
  evidenceFile,
  outputDirectory,
  caseId,
  examiner,
}) {
  return new Promise(
    async (resolve, reject) => {
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
            `Python forensic engine unavailable: ${python.error || "unknown error"}`
          );

        error.code =
          "FORENSIC_PYTHON_MISSING";

        reject(error);
        return;
      }

      fs.mkdirSync(
        outputDirectory,
        {
          recursive: true,
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
        "[Forensics] Starting Python:",
        FORENSIC_PYTHON,
        args
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

              TRUSTWIPE_FORENSIC_CASE_ID:
                caseId,

              TRUSTWIPE_FORENSIC_EXAMINER:
                examiner,
            },
          }
        );

      let stdout = "";
      let stderr = "";
      let settled = false;

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

            settled = true;

            child.kill(
              "SIGTERM"
            );

            setTimeout(
              () => {
                try {
                  child.kill(
                    "SIGKILL"
                  );
                } catch {
                  // Ignore.
                }
              },
              5000
            ).unref();

            const error =
              new Error(
                "Forensic analysis timed out."
              );

            error.code =
              "FORENSIC_TIMEOUT";

            reject(error);
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

          settled = true;
          clearTimeout(timer);

          reject(error);
        }
      );

      child.once(
        "close",
        (code, signal) => {
          if (settled) {
            return;
          }

          settled = true;
          clearTimeout(timer);

          if (code !== 0) {
            const error =
              new Error(
                stderr.trim() ||
                  stdout.trim() ||
                  `Python forensic engine exited with code ${code}${signal ? ` (${signal})` : ""}`
              );

            error.code =
              "FORENSIC_ENGINE_FAILED";

            error.stdout =
              stdout;

            error.stderr =
              stderr;

            reject(error);
            return;
          }

          let result = null;

          /*
           * cli.py prints JSON in --json mode,
           * but logging can sometimes appear
           * around the JSON. Try the complete
           * output first, then extract the last
           * JSON object.
           */

          try {
            result =
              JSON.parse(
                stdout.trim()
              );
          } catch {
            const start =
              stdout.indexOf("{");

            const end =
              stdout.lastIndexOf("}");

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
                result = null;
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

/*
|--------------------------------------------------------------------------
| RECOVERED ARTIFACT DISCOVERY
|--------------------------------------------------------------------------
*/

async function discoverRecoveredFiles(
  caseId,
  fallbackDirectory
) {
  const caseDir =
    caseRecoveredDirectory(
      caseId
    );

  let directory =
    caseDir;

  if (
    !fs.existsSync(
      directory
    )
  ) {
    directory =
      fallbackDirectory;
  }

  await fs.promises.mkdir(
    directory,
    {
      recursive: true,
    }
  );

  const entries =
    await fs.promises.readdir(
      directory,
      {
        withFileTypes: true,
      }
    );

  const files = [];

  for (const entry of entries) {
    if (!entry.isFile()) {
      continue;
    }

    const filePath =
      path.join(
        directory,
        entry.name
      );

    const stats =
      await fs.promises.stat(
        filePath
      );

    let relativeDownloadPath;

    if (
      path.resolve(
        directory
      ) ===
      path.resolve(
        caseDir
      )
    ) {
      relativeDownloadPath =
        `/api/forensic/recovered/${encodeURIComponent(
          sanitizeCaseId(caseId)
        )}/${encodeURIComponent(
          entry.name
        )}`;
    } else {
      relativeDownloadPath =
        `/api/forensic/recovered/${encodeURIComponent(
          entry.name
        )}`;
    }

    files.push({
      artifactId:
        `${sanitizeCaseId(caseId)}-${entry.name}`,

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

      path:
        relativeDownloadPath,
    });
  }

  return files.sort(
    (a, b) =>
      new Date(b.modifiedAt) -
      new Date(a.modifiedAt)
  );
}

/*
|--------------------------------------------------------------------------
| TEST
|--------------------------------------------------------------------------
*/

router.get(
  "/test",
  (_req, res) => {
    res.json({
      success: true,
      service:
        "TrustWipe Digital Forensics",
      message:
        "Forensic router is working.",
      forensicRoot:
        FORENSIC_ROOT,
      cli:
        CLI_PATH,
      cliExists:
        fs.existsSync(CLI_PATH),
    });
  }
);

/*
|--------------------------------------------------------------------------
| STATUS
|--------------------------------------------------------------------------
*/

router.get(
  "/status",
  async (_req, res) => {
    try {
      const python =
        await checkPython();

      const cliAvailable =
        fs.existsSync(
          CLI_PATH
        );

      return res.json({
        success: true,

        available:
          python.available &&
          cliAvailable,

        pythonAvailable:
          python.available,

        cliAvailable,

        pythonVersion:
          python.version,

        forensicRoot:
          FORENSIC_ROOT,

        cliPath:
          CLI_PATH,

        scanInProgress,

        message:
          python.available &&
          cliAvailable
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

/*
|--------------------------------------------------------------------------
| EVIDENCE
|--------------------------------------------------------------------------
*/

router.get(
  "/evidence",
  async (_req, res) => {
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
      console.error(
        "[Forensics] Evidence discovery error:",
        error
      );

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

/*
|--------------------------------------------------------------------------
| UPLOAD / ACQUISITION
|--------------------------------------------------------------------------
*/

router.post(
  "/upload",
  (req, res) => {
    upload.single(
      "evidence"
    )(
      req,
      res,
      async (error) => {
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
          console.error(
            "[Forensics] Upload error:",
            error
          );

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

          if (stats.size === 0) {
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
            schema_version: 2,

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
                "VERIFIED",
            },
          });
        } catch (uploadError) {
          console.error(
            "[Forensics] Evidence processing error:",
            uploadError
          );

          try {
            await fs.promises.unlink(
              req.file.path
            );
          } catch {
            // Best effort.
          }

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

/*
|--------------------------------------------------------------------------
| HASH
|--------------------------------------------------------------------------
*/

router.post(
  "/hash",
  async (req, res) => {
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

/*
|--------------------------------------------------------------------------
| VERIFY INTEGRITY
|--------------------------------------------------------------------------
*/

router.post(
  "/verify-integrity",
  async (req, res) => {
    try {
      let fileName =
        req.body?.fileName;

      if (!fileName) {
        return fail(
          res,
          400,
          "Evidence file name is required.",
          "EVIDENCE_FILE_REQUIRED"
        );
      }

      fileName =
        sanitizeFilename(
          fileName
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
      console.error(
        "[Forensics] Integrity error:",
        error
      );

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

/*
|--------------------------------------------------------------------------
| FORENSIC SCAN
|--------------------------------------------------------------------------
*/

router.post(
  "/scan",
  async (req, res) => {
    if (scanInProgress) {
      return fail(
        res,
        409,
        "Another forensic analysis is already running.",
        "FORENSIC_SCAN_BUSY"
      );
    }

    let fileName;
    let caseId;
    let examiner;

    try {
      fileName =
        sanitizeFilename(
          req.body?.fileName
        );

      caseId =
        sanitizeCaseId(
          req.body?.caseId
        );

      examiner =
        String(
          req.body?.examiner ||
            ""
        )
          .trim()
          .slice(0, 200);

      if (!examiner) {
        return fail(
          res,
          400,
          "Examiner is required.",
          "EXAMINER_REQUIRED"
        );
      }

      const evidenceFile =
        evidencePath(
          fileName
        );

      await fs.promises.access(
        evidenceFile,
        fs.constants.R_OK
      );

      /*
       * SECURITY BOUNDARY:
       * verify BEFORE Python touches
       * the evidence.
       */
      const integrityBefore =
        await verifyEvidenceIntegrity(
          fileName
        );

      if (
        integrityBefore.status !==
          "VERIFIED" ||
        integrityBefore.verified !==
          true ||
        integrityBefore.hashMatch !==
          true
      ) {
        return res.status(409).json({
          success: false,

          code:
            integrityBefore.status ===
            "TAMPERED"
              ? "EVIDENCE_TAMPERED"
              : "BASELINE_MISSING",

          message:
            "Forensic analysis is blocked because evidence integrity is not VERIFIED.",

          integrity:
            integrityBefore,
        });
      }

      scanInProgress =
        true;

      console.log(
        `[Forensics] Scan started: case=${caseId}, evidence=${fileName}`
      );

      /*
       * Every case gets its own recovered
       * directory.
       */
      const caseRecovered =
        caseRecoveredDirectory(
          caseId
        );

      await fs.promises.mkdir(
        caseRecovered,
        {
          recursive: true,
        }
      );

      /*
       * Run the real Python CLI.
       */
      const execution =
        await runPythonScan({
          evidenceFile,
          outputDirectory:
            caseRecovered,
          caseId,
          examiner,
        });

      /*
       * Verify evidence AGAIN after
       * Python completes.
       */
      const integrityAfter =
        await verifyEvidenceIntegrity(
          fileName
        );

      if (
        integrityAfter.status !==
          "VERIFIED" ||
        integrityAfter.verified !==
          true ||
        integrityAfter.hashMatch !==
          true
      ) {
        return res.status(409).json({
          success: false,

          code:
            "EVIDENCE_CHANGED_DURING_ANALYSIS",

          message:
            "Evidence changed during forensic analysis. The forensic results cannot be trusted.",

          integrity:
            integrityAfter,

          output:
            execution.stdout,
        });
      }

      const pythonResult =
        execution.result || {};

      /*
       * Python scanner normally returns:
       *
       * {
       *   evidence_path,
       *   evidence_size,
       *   chunk_size,
       *   overlap_size,
       *   signatures_detected,
       *   candidates_found,
       *   artifacts_carved,
       *   artifacts_validated,
       *   duration_ms,
       *   status,
       *   artifacts: [...]
       * }
       */
      const stats =
        pythonResult || {};

      const recoveredFiles =
        await discoverRecoveredFiles(
          caseId,
          caseRecovered
        );

      const artifacts =
        Array.isArray(
          pythonResult.artifacts
        )
          ? pythonResult.artifacts
          : [];

      const normalizedArtifacts =
        artifacts.map(
          (artifact, index) => ({
            artifactId:
              artifact.artifact_id ||
              artifact.artifactId ||
              `ART-${index + 1}`,

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
                artifact.size || 0
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
                artifact.valid === true
                  ? "VALID"
                  : "UNKNOWN"
              ),

            sha256:
              artifact.sha256 ||
              artifact.artifact_sha256 ||
              null,

            path:
              artifact.output ||
              artifact.output_path ||
              null,
          })
        );

      /*
       * Prefer detailed artifact information
       * from Python when available.
       */
      const finalRecovered =
        normalizedArtifacts.length
          ? normalizedArtifacts.map(
              (artifact) => ({
                ...artifact,

                path:
                  artifact.path
                    ? `/api/forensic/recovered/${encodeURIComponent(
                        caseId
                      )}/${encodeURIComponent(
                        path.basename(
                          artifact.path
                        )
                      )}`
                    : null,
              })
            )
          : recoveredFiles;

      const durationMs =
        Number(
          pythonResult.duration_ms ??
          pythonResult.durationMs ??
          0
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
          finalRecovered.length
        );

      const artifactsValidated =
        Number(
          pythonResult.artifacts_validated ??
          pythonResult.artifactsValidated ??
          finalRecovered.length
        );

      const scanStats = {
        evidenceSize:
          Number(
            pythonResult.evidence_size ??
            pythonResult.evidenceSize ??
            (
              await fs.promises.stat(
                evidenceFile
              )
            ).size
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

        durationMs,

        status:
          pythonResult.status ||
          "COMPLETED",
      };

      console.log(
        `[Forensics] Scan completed: case=${caseId}, recovered=${finalRecovered.length}`
      );

      return res.json({
        success: true,

        message:
          `Forensic recovery completed. ${candidatesFound} candidate range(s) identified and ${artifactsValidated} artifact(s) validated.`,

        caseId,

        examiner,

        evidence:
          fileName,

        recoveredCount:
          finalRecovered.length,

        recoveredFiles:
          finalRecovered,

        artifacts:
          finalRecovered,

        scanStats,

        integrity:
          integrityAfter,

        output:
          execution.stdout,

        stderr:
          execution.stderr,

        engine: {
          exitCode:
            0,

          completedAt:
            new Date().toISOString(),

          python:
            FORENSIC_PYTHON,

          cli:
            CLI_PATH,
        },
      });
    } catch (error) {
      console.error(
        "[Forensics] Scan failed:",
        error
      );

      if (
        error.code ===
        "FORENSIC_TIMEOUT"
      ) {
        return fail(
          res,
          504,
          "Forensic analysis timed out.",
          "FORENSIC_TIMEOUT",
          error
        );
      }

      if (
        error.code ===
        "FORENSIC_CLI_MISSING"
      ) {
        return fail(
          res,
          500,
          "Forensic CLI was not found on the backend.",
          "FORENSIC_CLI_MISSING",
          error
        );
      }

      if (
        error.code ===
        "FORENSIC_PYTHON_MISSING"
      ) {
        return fail(
          res,
          500,
          "Python forensic engine is unavailable on the backend.",
          "FORENSIC_PYTHON_MISSING",
          error
        );
      }

      return fail(
        res,
        500,
        process.env.NODE_ENV ===
          "production"
          ? "Forensic analysis failed."
          : (
              error.message ||
              "Forensic analysis failed."
            ),
        "FORENSIC_SCAN_FAILED",
        error
      );
    } finally {
      scanInProgress =
        false;
    }
  }
);

/*
|--------------------------------------------------------------------------
| RECOVERED FILE DOWNLOAD
|--------------------------------------------------------------------------
*/

router.get(
  "/recovered/:caseId/:fileName",
  async (req, res) => {
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
    } catch (error) {
      console.error(
        "[Forensics] Recovered download error:",
        error
      );

      return fail(
        res,
        404,
        "Recovered artifact not found.",
        "RECOVERED_FILE_NOT_FOUND"
      );
    }
  }
);

/*
|--------------------------------------------------------------------------
| LEGACY RECOVERED FILE DOWNLOAD
|--------------------------------------------------------------------------
*/

router.get(
  "/recovered/:fileName",
  async (req, res) => {
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

/*
|--------------------------------------------------------------------------
| REPORT
|--------------------------------------------------------------------------
*/

router.post(
  "/report",
  async (req, res) => {
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
        String(
          req.body?.examiner ||
            ""
        )
          .trim()
          .slice(0, 200);

      if (!examiner) {
        return fail(
          res,
          400,
          "Examiner is required.",
          "EXAMINER_REQUIRED"
        );
      }

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

      const generatedAt =
        new Date().toISOString();

      const report = {
        schema_version: 2,

        product:
          "TrustWipe Forensics",

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

        methodology: {
          acquisition:
            "Immutable SHA-256 acquisition baseline",

          integrity:
            "SHA-256 and file-size comparison",

          analysis:
            "TrustWipe Python forensic recovery engine",
        },

        compliance: {
          reference:
            "NIST SP 800-88",

          note:
            "This report records evidence integrity and forensic workflow metadata. It does not by itself certify physical media sanitization.",
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
      console.error(
        "[Forensics] Report error:",
        error
      );

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

/*
|--------------------------------------------------------------------------
| REPORT DOWNLOAD
|--------------------------------------------------------------------------
*/

router.get(
  "/report/:fileName",
  async (req, res) => {
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
    } catch (error) {
      return fail(
        res,
        404,
        "Report file not found.",
        "REPORT_NOT_FOUND"
      );
    }
  }
);

export default router;