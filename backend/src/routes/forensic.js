<<<<<<< HEAD
// TrustWipe Forensic Recovery API
// Part 1 of 3

import express from "express";
import fs from "fs";
import fsp from "fs/promises";
import path from "path";
import crypto from "crypto";
import { spawn } from "child_process";
import multer from "multer";
import { fileURLToPath } from "url";

const router = express.Router();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* ==========================================================================
   CONFIGURATION
   ========================================================================== */

=======
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

>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
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

<<<<<<< HEAD
const MAX_UPLOAD_BYTES =
  Number(process.env.FORENSIC_MAX_UPLOAD_BYTES) ||
  5 * 1024 * 1024 * 1024;

const SCAN_TIMEOUT_MS =
  Number(process.env.FORENSIC_SCAN_TIMEOUT_MS) ||
  30 * 60 * 1000;

const MAX_OUTPUT =
  Number(process.env.FORENSIC_MAX_PROCESS_OUTPUT) ||
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
  4 * 1024 * 1024;

const FORENSIC_PYTHON =
  process.env.FORENSIC_PYTHON ||
<<<<<<< HEAD
  (process.platform === "win32"
    ? "python"
    : "python3");

const REQUIRE_AUTH =
  String(
    process.env.FORENSIC_REQUIRE_AUTH || "false"
=======
  (
    process.platform === "win32"
      ? "python"
      : "python3"
  );

const REQUIRE_AUTH =
  String(
    process.env.FORENSIC_REQUIRE_AUTH ||
      "false"
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
  ).toLowerCase() === "true";

const FORENSIC_API_KEY =
  process.env.FORENSIC_API_KEY || "";

const FORENSIC_EXECUTION_MODE =
  String(
<<<<<<< HEAD
    process.env.FORENSIC_EXECUTION_MODE || "local"
  ).toLowerCase();

=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
const VALID_EXECUTION_MODES = [
  "local",
  "agent",
  "auto",
];

/* ==========================================================================
   DIRECTORY INITIALIZATION
   ========================================================================== */

<<<<<<< HEAD
const requiredDirectories = [
=======
for (const directory of [
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
  FORENSIC_ROOT,
  EVIDENCE_DIR,
  RECOVERED_DIR,
  REPORTS_DIR,
  MANIFESTS_DIR,
  CASES_DIR,
  JOBS_DIR,
<<<<<<< HEAD
];

for (const directory of requiredDirectories) {
  try {
    fs.mkdirSync(directory, {
      recursive: true,
    });
  } catch (error) {
    console.error(
      `[Forensics] Unable to create directory: ${directory}`,
      error
    );
  }
}

/* ==========================================================================
   MULTER
   ========================================================================== */

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, EVIDENCE_DIR);
  },

  filename: (_req, file, cb) => {
    const safeName =
      path.basename(file.originalname || "evidence.bin");

    const uniqueName =
      `${Date.now()}-${crypto.randomUUID()}-${safeName}`;

    cb(null, uniqueName);
  },
});

const upload = multer({
  storage,

  limits: {
    fileSize: MAX_UPLOAD_BYTES,
  },

  fileFilter: (_req, _file, cb) => {
    cb(null, true);
  },
});
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d

/* ==========================================================================
   RESPONSE HELPERS
   ========================================================================== */

function fail(
  res,
  status,
  message,
<<<<<<< HEAD
  code = "FORENSIC_ERROR",
  error = null
) {
  if (error) {
    console.error(
      `[Forensics] ${code}:`,
      error
    );
  }

  return res.status(status).json({
    success: false,
    message,
    code,
  });
}

function success(
  res,
  data = {},
  status = 200
) {
  return res.status(status).json({
    success: true,
    ...data,
  });
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
}

/* ==========================================================================
   SECURITY HELPERS
   ========================================================================== */

<<<<<<< HEAD
function safeString(value, fallback = "") {
  if (
    value === undefined ||
    value === null
  ) {
    return fallback;
  }

  return String(value).trim();
}

function sanitizeName(value) {
  return safeString(value, "unknown")
    .replace(/[^a-zA-Z0-9._-]/g, "_")
    .slice(0, 200);
}

function isPathInside(
  parent,
  child
) {
  const parentPath =
    path.resolve(parent) + path.sep;

  const childPath =
    path.resolve(child);

  return (
    childPath === path.resolve(parent) ||
    childPath.startsWith(parentPath)
  );
}

function safePath(
  base,
  requested
) {
  const safeBase =
    path.resolve(base);

  const result =
    path.resolve(
      safeBase,
      requested
    );

  if (!isPathInside(safeBase, result)) {
    throw new Error(
      "Invalid path outside forensic workspace."
    );
  }

  return result;
}

/* ==========================================================================
   OPTIONAL API KEY AUTH
   ========================================================================== */

function forensicAuth(
  req,
  res,
  next
) {
  if (!REQUIRE_AUTH) {
    return next();
  }

  if (!FORENSIC_API_KEY) {
    return fail(
      res,
      500,
      "Forensic API authentication is enabled but no API key is configured.",
      "FORENSIC_AUTH_CONFIG_ERROR"
    );
  }

  const suppliedKey =
    req.headers["x-forensic-api-key"];

  if (
    !suppliedKey ||
    suppliedKey !== FORENSIC_API_KEY
  ) {
    return fail(
      res,
      401,
      "Unauthorized forensic request.",
      "FORENSIC_UNAUTHORIZED"
    );
  }

  next();
}

router.use(forensicAuth);

/* ==========================================================================
   HASHING
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
   ========================================================================== */

async function calculateSHA256(
  filePath
) {
<<<<<<< HEAD
  return new Promise(
    (resolve, reject) => {
      const hash =
        crypto.createHash("sha256");

      const stream =
        fs.createReadStream(filePath);

      stream.on(
        "data",
        (chunk) => {
          hash.update(chunk);
        }
      );

      stream.on(
        "error",
        reject
      );

      stream.on(
        "end",
        () => {
          resolve(
            hash.digest("hex")
          );
        }
      );
    }
  );
}

async function calculateMD5(
  filePath
) {
  return new Promise(
    (resolve, reject) => {
      const hash =
        crypto.createHash("md5");

      const stream =
        fs.createReadStream(filePath);

      stream.on(
        "data",
        (chunk) => {
          hash.update(chunk);
        }
      );

      stream.on(
        "error",
        reject
      );

      stream.on(
        "end",
        () => {
          resolve(
            hash.digest("hex")
          );
        }
      );
    }
  );
}

async function getFileIntegrity(
  filePath
) {
  const stat =
    await fsp.stat(filePath);

  const sha256 =
    await calculateSHA256(filePath);

  let md5 = null;

  try {
    md5 =
      await calculateMD5(filePath);
  } catch {
    md5 = null;
  }

  return {
    sha256,
    md5,
    size: stat.size,
    modifiedAt:
      stat.mtime.toISOString(),
  };
}

/* ==========================================================================
   JOB ID
   ========================================================================== */

function createJobId() {
  return (
    "FJ-" +
    Date.now().toString(36).toUpperCase() +
    "-" +
    crypto
      .randomBytes(4)
      .toString("hex")
      .toUpperCase()
  );
}

function createOperationId() {
  return (
    "OP-" +
    crypto
      .randomBytes(8)
      .toString("hex")
      .toUpperCase()
  );
}

/* ==========================================================================
   JOB FILE HELPERS
   ========================================================================== */

function getJobFile(jobId) {
  const safeId =
    sanitizeName(jobId);

  return safePath(
    JOBS_DIR,
    `${safeId}.json`
  );
}

async function saveJob(job) {
  const filePath =
    getJobFile(job.jobId);

  const tempPath =
    `${filePath}.tmp`;

  await fsp.writeFile(
    tempPath,
    JSON.stringify(
      job,
      null,
      2
    ),
    "utf8"
  );

  await fsp.rename(
    tempPath,
    filePath
  );

  return job;
}

async function readJob(jobId) {
  try {
    const filePath =
      getJobFile(jobId);

    const raw =
      await fsp.readFile(
        filePath,
        "utf8"
      );

    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function updateJob(
  jobId,
  changes
) {
  const job =
    await readJob(jobId);

  if (!job) {
    return null;
  }

  Object.assign(
    job,
    changes,
    {
      updatedAt:
        new Date().toISOString(),
    }
  );

  await saveJob(job);

  return job;
}

/* ==========================================================================
   JOB DISCOVERY
   ========================================================================== */

async function discoverJobs() {
  let files = [];

  try {
    files =
      await fsp.readdir(
        JOBS_DIR
      );
  } catch {
    return [];
  }

  const jobs = [];

  for (const file of files) {
    if (
      !file.endsWith(".json")
    ) {
      continue;
    }

    try {
      const raw =
        await fsp.readFile(
          path.join(
            JOBS_DIR,
            file
          ),
          "utf8"
        );

      jobs.push(
        JSON.parse(raw)
      );
    } catch {
      // Ignore invalid job files.
    }
  }

  jobs.sort(
    (a, b) =>
      new Date(
        b.createdAt || 0
      ) -
      new Date(
        a.createdAt || 0
      )
  );

  return jobs;
}

async function getJob(
  jobId
) {
  return readJob(jobId);
}

/* ==========================================================================
   CASE HELPERS
   ========================================================================== */

function createCaseId() {
  return (
    "CASE-" +
    new Date()
      .toISOString()
      .replace(
        /[-:.TZ]/g,
        ""
      ) +
    "-" +
    crypto
      .randomBytes(3)
      .toString("hex")
      .toUpperCase()
  );
}

function getCaseFile(
  caseId
) {
  const safeId =
    sanitizeName(caseId);

  return safePath(
    CASES_DIR,
    `${safeId}.json`
  );
}

async function saveCase(caseData) {
  const filePath =
    getCaseFile(
      caseData.caseId
    );

  await fsp.writeFile(
    filePath,
    JSON.stringify(
      caseData,
      null,
      2
    ),
    "utf8"
  );

  return caseData;
}

async function readCase(
  caseId
) {
  try {
    const filePath =
      getCaseFile(caseId);

    const raw =
      await fsp.readFile(
        filePath,
        "utf8"
      );

    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/* ==========================================================================
   MANIFEST HELPERS
   ========================================================================== */

function getManifestFile(
  evidenceId
) {
  return safePath(
    MANIFESTS_DIR,
    `${sanitizeName(
      evidenceId
    )}.json`
  );
}

async function saveManifest(
  manifest
) {
  const filePath =
    getManifestFile(
      manifest.evidenceId
    );

  await fsp.writeFile(
    filePath,
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
    JSON.stringify(
      manifest,
      null,
      2
    ),
    "utf8"
  );

<<<<<<< HEAD
  return manifest;
}

async function readManifest(
  evidenceId
) {
  try {
    const filePath =
      getManifestFile(
        evidenceId
      );

    const raw =
      await fsp.readFile(
        filePath,
        "utf8"
      );

    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/* ==========================================================================
   EVIDENCE ID
   ========================================================================== */

function createEvidenceId() {
  return (
    "EV-" +
    Date.now().toString(36).toUpperCase() +
    "-" +
    crypto
      .randomBytes(5)
      .toString("hex")
      .toUpperCase()
  );
}

/* ==========================================================================
   EVIDENCE REGISTRY
   ========================================================================== */

async function discoverEvidence() {
  const files =
    await fsp.readdir(
      EVIDENCE_DIR
    );

  const evidence = [];

  for (const file of files) {
    const fullPath =
      path.join(
        EVIDENCE_DIR,
        file
      );

    try {
      const stat =
        await fsp.stat(fullPath);

      if (!stat.isFile()) {
        continue;
      }

      const manifest =
        await readManifest(file);

      evidence.push({
        evidenceId:
          manifest?.evidenceId ||
          file,

        fileName:
          manifest?.fileName ||
          file,

        path:
          fullPath,

        size:
          stat.size,

        createdAt:
          manifest?.createdAt ||
          stat.birthtime.toISOString(),

        sha256:
          manifest?.sha256 ||
          null,

        md5:
          manifest?.md5 ||
          null,

        verified:
          manifest?.verified ||
          false,
      });
    } catch {
      // Ignore unreadable files.
    }
  }

  evidence.sort(
    (a, b) =>
      new Date(
        b.createdAt || 0
      ) -
      new Date(
        a.createdAt || 0
      )
  );

  return evidence;
}
/* ==========================================================================
   TEST
   ========================================================================== */

router.get(
  "/test",
  (_req, res) => {
    return res.status(200).json({
      success: true,
      message: "Forensic router is working",
    });
  }
);
/* ==========================================================================
   STATUS
   ========================================================================== */

router.get(
  "/status",
  async (_req, res) => {
    try {
      const jobs =
        await discoverJobs();

      const evidence =
        await discoverEvidence();

      return success(
        res,
        {
          status: "ONLINE",

          service:
            "TrustWipe Forensic Recovery",

          executionMode:
            VALID_EXECUTION_MODES.includes(
              FORENSIC_EXECUTION_MODE
            )
              ? FORENSIC_EXECUTION_MODE
              : "local",

          python:
            FORENSIC_PYTHON,

          pythonCliExists:
            fs.existsSync(
              CLI_PATH
            ),

          directories: {
            root:
              FORENSIC_ROOT,
            evidence:
              EVIDENCE_DIR,
            recovered:
              RECOVERED_DIR,
            reports:
              REPORTS_DIR,
            cases:
              CASES_DIR,
            jobs:
              JOBS_DIR,
          },

          counts: {
            jobs:
              jobs.length,
            evidence:
              evidence.length,
          },

          timestamp:
            new Date().toISOString(),
        }
      );
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to retrieve forensic service status.",
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
  async (_req, res) => {
    try {
      const evidence =
        await discoverEvidence();

      return success(
        res,
        {
          evidence,
          count:
            evidence.length,
        }
      );
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to list forensic evidence.",
        "FORENSIC_EVIDENCE_LIST_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   EVIDENCE UPLOAD
   ========================================================================== */

router.post(
  "/upload",
  upload.single("evidence"),
  async (req, res) => {
    try {
      if (!req.file) {
        return fail(
          res,
          400,
          "No evidence file was uploaded.",
          "FORENSIC_EVIDENCE_REQUIRED"
        );
      }

      const evidenceId =
        createEvidenceId();

      const caseId =
        safeString(
          req.body.caseId,
          createCaseId()
        );

      const examiner =
        safeString(
          req.body.examiner,
          "Unknown Examiner"
        );

      const originalName =
        safeString(
          req.file.originalname,
          req.file.filename
        );

      const integrity =
        await getFileIntegrity(
          req.file.path
        );

      const manifest = {
        evidenceId,

        caseId,

        examiner,

        fileName:
          originalName,

        storedFileName:
          req.file.filename,

        filePath:
          req.file.path,

        mimeType:
          req.file.mimetype ||
          "application/octet-stream",

        size:
          integrity.size,

        sha256:
          integrity.sha256,

        md5:
          integrity.md5,

        verified: true,

        createdAt:
          new Date().toISOString(),

        source:
          safeString(
            req.body.source,
            "upload"
          ),

        description:
          safeString(
            req.body.description,
            ""
          ),
      };

      await saveManifest(
        manifest
      );

      let caseData =
        await readCase(caseId);

      if (!caseData) {
        caseData = {
          caseId,

          examiner,

          status:
            "OPEN",

          createdAt:
            new Date().toISOString(),

          updatedAt:
            new Date().toISOString(),

          evidence: [],
          jobs: [],
        };
      }

      caseData.evidence =
        Array.isArray(
          caseData.evidence
        )
          ? caseData.evidence
          : [];

      caseData.evidence.push(
        evidenceId
      );

      caseData.updatedAt =
        new Date().toISOString();

      await saveCase(
        caseData
      );

      return success(
        res,
        {
          message:
            "Evidence uploaded and hashed successfully.",

          evidence:
            manifest,

          integrity,
        },
        201
      );
    } catch (error) {
      if (
        req.file?.path
      ) {
        try {
          await fsp.unlink(
            req.file.path
          );
        } catch {
          // Ignore cleanup errors.
        }
      }

      return fail(
        res,
        500,
        "Unable to process forensic evidence upload.",
        "FORENSIC_UPLOAD_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   HASH ENDPOINT
   ========================================================================== */

router.post(
  "/hash",
  async (req, res) => {
    try {
      const evidenceId =
        safeString(
          req.body.evidenceId
        );

      if (!evidenceId) {
        return fail(
          res,
          400,
          "evidenceId is required.",
          "FORENSIC_EVIDENCE_ID_REQUIRED"
        );
      }

      const manifest =
        await readManifest(
          evidenceId
        );

      if (!manifest) {
        return fail(
          res,
          404,
          "Evidence not found.",
          "FORENSIC_EVIDENCE_NOT_FOUND"
        );
      }

      const filePath =
        safePath(
          EVIDENCE_DIR,
          manifest.storedFileName
        );

      if (
        !fs.existsSync(
          filePath
        )
      ) {
        return fail(
          res,
          404,
          "Evidence file is missing from the forensic workspace.",
          "FORENSIC_EVIDENCE_FILE_MISSING"
        );
      }

      const integrity =
        await getFileIntegrity(
          filePath
        );

      return success(
        res,
        {
          evidenceId,
          integrity,
        }
      );
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to calculate evidence hash.",
        "FORENSIC_HASH_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   EVIDENCE VERIFICATION
   ========================================================================== */

router.post(
  "/verify",
  async (req, res) => {
    try {
      const evidenceId =
        safeString(
          req.body.evidenceId
        );

      if (!evidenceId) {
        return fail(
          res,
          400,
          "evidenceId is required.",
          "FORENSIC_EVIDENCE_ID_REQUIRED"
        );
      }

      const manifest =
        await readManifest(
          evidenceId
        );

      if (!manifest) {
        return fail(
          res,
          404,
          "Evidence manifest not found.",
          "FORENSIC_MANIFEST_NOT_FOUND"
        );
      }

      const filePath =
        safePath(
          EVIDENCE_DIR,
          manifest.storedFileName
        );

      if (
        !fs.existsSync(
          filePath
        )
      ) {
        return fail(
          res,
          404,
          "Evidence file is missing.",
          "FORENSIC_EVIDENCE_FILE_MISSING"
        );
      }

      const integrity =
        await getFileIntegrity(
          filePath
        );

      const shaMatches =
        Boolean(
          manifest.sha256 &&
          integrity.sha256 ===
            manifest.sha256
        );

      const md5Matches =
        Boolean(
          manifest.md5 &&
          integrity.md5 ===
            manifest.md5
        );

      const verified =
        shaMatches;

      manifest.verified =
        verified;

      manifest.lastVerifiedAt =
        new Date().toISOString();

      await saveManifest(
        manifest
      );

      return success(
        res,
        {
          evidenceId,

          verified,

          sha256: {
            expected:
              manifest.sha256,

            actual:
              integrity.sha256,

            matches:
              shaMatches,
          },

          md5: {
            expected:
              manifest.md5,

            actual:
              integrity.md5,

            matches:
              md5Matches,
          },

          integrity,
        }
      );
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to verify evidence integrity.",
        "FORENSIC_VERIFY_FAILED",
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
  async (_req, res) => {
    try {
      const files =
        await fsp.readdir(
          CASES_DIR
        );

      const cases = [];

      for (const file of files) {
        if (
          !file.endsWith(".json")
        ) {
          continue;
        }

        try {
          const raw =
            await fsp.readFile(
              path.join(
                CASES_DIR,
                file
              ),
              "utf8"
            );

          cases.push(
            JSON.parse(raw)
          );
        } catch {
          // Ignore invalid case files.
        }
      }

      cases.sort(
        (a, b) =>
          new Date(
            b.updatedAt ||
              b.createdAt ||
              0
          ) -
          new Date(
            a.updatedAt ||
              a.createdAt ||
              0
          )
      );

      return success(
        res,
        {
          cases,
          count:
            cases.length,
        }
      );
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to list forensic cases.",
        "FORENSIC_CASE_LIST_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   CASE DETAILS
   ========================================================================== */

router.get(
  "/cases/:caseId",
  async (req, res) => {
    try {
      const caseId =
        safeString(
          req.params.caseId
        );

      const caseData =
        await readCase(
          caseId
        );

      if (!caseData) {
        return fail(
          res,
          404,
          "Forensic case not found.",
          "FORENSIC_CASE_NOT_FOUND"
        );
      }

      return success(
        res,
        {
          case: caseData,
        }
      );
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to retrieve forensic case.",
        "FORENSIC_CASE_GET_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   CREATE CASE
   ========================================================================== */

router.post(
  "/cases",
  async (req, res) => {
    try {
      const caseId =
        safeString(
          req.body.caseId,
          createCaseId()
        );

      const existing =
        await readCase(
          caseId
        );

      if (existing) {
        return fail(
          res,
          409,
          "A forensic case with this ID already exists.",
          "FORENSIC_CASE_EXISTS"
        );
      }

      const caseData = {
        caseId,

        examiner:
          safeString(
            req.body.examiner,
            "Unknown Examiner"
          ),

        title:
          safeString(
            req.body.title,
            "Forensic Investigation"
          ),

        description:
          safeString(
            req.body.description,
            ""
          ),

        status:
          "OPEN",

        createdAt:
          new Date().toISOString(),

        updatedAt:
          new Date().toISOString(),

        evidence: [],

        jobs: [],
      };

      await saveCase(
        caseData
      );

      return success(
        res,
        {
          message:
            "Forensic case created successfully.",

          case:
            caseData,
        },
        201
      );
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to create forensic case.",
        "FORENSIC_CASE_CREATE_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   PART 2 — FORENSIC JOB EXECUTION
   ========================================================================== */

/* ==========================================================================
   PROCESS OUTPUT LIMITER
   ========================================================================== */

function createOutputCollector(maxBytes = MAX_OUTPUT) {
  let stdout = "";
  let stderr = "";
  let stdoutBytes = 0;
  let stderrBytes = 0;

  return {
    addStdout(chunk) {
      if (stdoutBytes >= maxBytes) {
        return;
      }

      const text =
        Buffer.isBuffer(chunk)
          ? chunk.toString("utf8")
          : String(chunk);

      const remaining =
        maxBytes - stdoutBytes;

      stdout += text.slice(
        0,
        remaining
      );

      stdoutBytes +=
        Buffer.byteLength(
          text.slice(
            0,
            remaining
          ),
          "utf8"
        );
    },

    addStderr(chunk) {
      if (stderrBytes >= maxBytes) {
        return;
      }

      const text =
        Buffer.isBuffer(chunk)
          ? chunk.toString("utf8")
          : String(chunk);

      const remaining =
        maxBytes - stderrBytes;

      stderr += text.slice(
        0,
        remaining
      );

      stderrBytes +=
        Buffer.byteLength(
          text.slice(
            0,
            remaining
          ),
          "utf8"
        );
    },

    getStdout() {
      return stdout;
    },

    getStderr() {
      return stderr;
    },
  };
}

/* ==========================================================================
   PARSE PYTHON OUTPUT
   ========================================================================== */

function parsePythonJSON(output) {
  if (!output) {
    return null;
  }

  const text =
    String(output).trim();

  if (!text) {
    return null;
  }

  // Try complete output first.
  try {
    return JSON.parse(text);
  } catch {
    // Continue.
  }

  // Python programs sometimes print logs before JSON.
  const lines =
    text.split(/\r?\n/);

  for (
    let i = lines.length - 1;
    i >= 0;
    i--
  ) {
    const line =
      lines[i].trim();

    if (
      !line.startsWith("{") &&
      !line.startsWith("[")
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
    ) {
      continue;
    }

    try {
<<<<<<< HEAD
      return JSON.parse(line);
    } catch {
      // Continue searching.
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
    }
  }

  return null;
}

/* ==========================================================================
<<<<<<< HEAD
   PYTHON FORENSIC EXECUTION
   ========================================================================== */

function runPythonForensicScan({
  inputPath,
  outputDir,
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
  caseId,
  examiner,
  jobId,
}) {
  return new Promise(
<<<<<<< HEAD
    (resolve, reject) => {
=======
    async (
      resolve,
      reject
    ) => {
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
      if (
        !fs.existsSync(
          CLI_PATH
        )
      ) {
<<<<<<< HEAD
        return reject(
          new Error(
            `Forensic CLI not found: ${CLI_PATH}`
          )
        );
      }

      if (
        !fs.existsSync(
          inputPath
        )
      ) {
        return reject(
          new Error(
            `Evidence file not found: ${inputPath}`
          )
        );
      }

      fs.mkdirSync(
        outputDir,
        {
          recursive: true,
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
        }
      );

      const args = [
        CLI_PATH,
        "scan",
<<<<<<< HEAD
        "--input",
        inputPath,
        "--output",
        outputDir,
        "--case",
        caseId,
        "--examiner",
        examiner,
=======

        "--input",
        evidenceFile,

        "--output",
        outputDirectory,

        "--case",
        caseId,

        "--examiner",
        examiner,

>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
        "--json",
      ];

      console.log(
<<<<<<< HEAD
        "[Forensics] Starting Python scan:",
        FORENSIC_PYTHON,
        args
=======
        "[Forensics] Python scan:",
        {
          jobId,
          caseId,
        }
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
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

<<<<<<< HEAD
      const output =
        createOutputCollector();
=======
      let stdout = "";
      let stderr = "";
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d

      let settled =
        false;

<<<<<<< HEAD
      let timeoutHandle =
        null;

      const finish = (
        callback
      ) => {
        if (settled) {
          return;
        }

        settled = true;

        if (timeoutHandle) {
          clearTimeout(
            timeoutHandle
          );
        }

        callback();
      };

      child.stdout.on(
        "data",
        (chunk) => {
          output.addStdout(
            chunk
          );

          const text =
            chunk.toString();

          const progressMatch =
            text.match(
              /(?:progress|PROGRESS)\s*[:=]\s*(\d+)/i
            );

          if (
            progressMatch
          ) {
            const progress =
              Math.max(
                0,
                Math.min(
                  100,
                  Number(
                    progressMatch[1]
                  )
                )
              );

            updateJob(
              jobId,
              {
                progress,
                status:
                  progress >= 100
                    ? "PROCESSING"
                    : "PROCESSING",
              }
            ).catch(
              () => {}
            );
          }
        }
      );

      child.stderr.on(
        "data",
        (chunk) => {
          output.addStderr(
            chunk
          );

          console.error(
            `[Forensics:${jobId}]`,
            chunk.toString()
          );
        }
      );

      child.on(
        "error",
        (error) => {
          finish(() => {
            reject(error);
          });
        }
      );

      child.on(
        "close",
        (code, signal) => {
          finish(() => {
            const stdout =
              output.getStdout();

            const stderr =
              output.getStderr();

            const parsed =
              parsePythonJSON(
                stdout
              );

            if (
              code !== 0
            ) {
              const message =
                stderr ||
                stdout ||
                `Python forensic process exited with code ${code}`;

              const error =
                new Error(
                  message.trim()
                );

              error.code =
                code;

              error.signal =
                signal;

              error.stdout =
                stdout;

              error.stderr =
                stderr;

              return reject(
                error
              );
            }

            resolve({
              exitCode:
                code,

              signal,

              stdout,

              stderr,

              result:
                parsed,
            });
          });
        }
      );

      timeoutHandle =
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
        setTimeout(
          () => {
            if (settled) {
              return;
            }

<<<<<<< HEAD
            console.error(
              `[Forensics:${jobId}] Scan timeout`
            );
=======
            settled =
              true;
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d

            try {
              child.kill(
                "SIGTERM"
              );
<<<<<<< HEAD
            } catch {
              // Ignore.
            }

            setTimeout(
              () => {
                try {
                  if (
                    !settled
                  ) {
                    child.kill(
                      "SIGKILL"
                    );
                  }
                } catch {
                  // Ignore.
                }
              },
              5000
            );

            finish(() => {
              const error =
                new Error(
                  `Forensic scan timed out after ${
                    SCAN_TIMEOUT_MS / 1000
                  } seconds.`
                );

              error.code =
                "FORENSIC_SCAN_TIMEOUT";

              reject(error);
            });
          },
          SCAN_TIMEOUT_MS
        );
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
    }
  );
}

/* ==========================================================================
<<<<<<< HEAD
   AGENT BRIDGE
   ========================================================================== */

function getAgentBridge(req) {
  return req.app.get(
    "agentBridge"
  );
}

async function sendToAgent(
  req,
  task
) {
  const bridge =
    getAgentBridge(req);

  if (
    !bridge ||
    typeof bridge.sendTask !==
      "function"
  ) {
    throw new Error(
      "Forensic Agent Bridge is not available."
    );
  }

  return bridge.sendTask(
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
    task
  );
}

/* ==========================================================================
<<<<<<< HEAD
   EXECUTION MODE
   ========================================================================== */

function resolveExecutionMode(
  requestedMode,
  agentId
) {
  const requested =
    safeString(
      requestedMode,
      FORENSIC_EXECUTION_MODE
    ).toLowerCase();

  if (
    !VALID_EXECUTION_MODES.includes(
      requested
    )
  ) {
    return "local";
  }

  if (
    requested === "auto"
  ) {
    return agentId
      ? "agent"
      : "local";
  }

  return requested;
}

/* ==========================================================================
   START LOCAL JOB
   ========================================================================== */

async function executeLocalJob(
  req,
  job
) {
  try {
    await updateJob(
      job.jobId,
      {
        status:
          "PROCESSING",

        progress:
          5,

        startedAt:
          new Date().toISOString(),
      }
    );

    const manifest =
      await readManifest(
        job.evidenceId
      );

    if (!manifest) {
      throw new Error(
        "Evidence manifest not found."
      );
    }

    const inputPath =
      safePath(
        EVIDENCE_DIR,
        manifest.storedFileName
      );

    if (
      !fs.existsSync(
        inputPath
      )
    ) {
      throw new Error(
        "Evidence file does not exist."
      );
    }

    // Verify evidence before analysis.
    const before =
      await getFileIntegrity(
        inputPath
      );

    if (
      manifest.sha256 &&
      before.sha256 !==
        manifest.sha256
    ) {
      throw new Error(
        "Evidence integrity check failed before forensic analysis."
      );
    }

    const outputDir =
      safePath(
        RECOVERED_DIR,
        job.jobId
      );

    await fsp.mkdir(
      outputDir,
      {
        recursive: true,
      }
    );

    await updateJob(
      job.jobId,
      {
        progress:
          10,

        bytesTotal:
          before.size,
      }
    );

    const pythonResult =
      await runPythonForensicScan({
        inputPath,
        outputDir,
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

    // Verify the original evidence again.
    const after =
      await getFileIntegrity(
        inputPath
      );

    const evidenceUnchanged =
      before.sha256 ===
      after.sha256;

    if (
      !evidenceUnchanged
    ) {
      throw new Error(
        "Evidence integrity changed during forensic analysis."
      );
    }

    const result =
      pythonResult.result ||
      {};

    const artifacts =
      Array.isArray(
        result.artifacts
      )
        ? result.artifacts
        : [];

    const reports =
      Array.isArray(
        result.reports
      )
        ? result.reports
        : [];

    const completedJob = {
      status:
        "COMPLETED",

      progress:
        100,

      bytesScanned:
        before.size,

      bytesTotal:
        before.size,

      artifactsFound:
        Number(
          result.artifactsFound ??
            artifacts.length
        ),

      artifactsValidated:
        Number(
          result.artifactsValidated ??
            0
        ),

      evidenceHash:
        after.sha256,

      evidenceIntegrity:
        {
          before,
          after,
          unchanged:
            evidenceUnchanged,
        },

      outputDirectory:
        outputDir,

      artifacts,

      reports,

      result,

      completedAt:
        new Date().toISOString(),

      error:
        null,
    };

    const saved =
      await updateJob(
        job.jobId,
        completedJob
      );

    // Add job to case.
    const caseData =
      await readCase(
        job.caseId
      );

    if (caseData) {
      caseData.jobs =
        Array.isArray(
          caseData.jobs
        )
          ? caseData.jobs
          : [];

      if (
        !caseData.jobs.includes(
          job.jobId
        )
      ) {
        caseData.jobs.push(
          job.jobId
        );
      }

      caseData.updatedAt =
        new Date().toISOString();

      await saveCase(
        caseData
      );
    }

    return saved;
  } catch (error) {
    console.error(
      `[Forensics:${job.jobId}] Local execution failed:`,
      error
    );

    const failed =
      await updateJob(
        job.jobId,
        {
          status:
            "FAILED",

          progress:
            100,

          completedAt:
            new Date().toISOString(),

          error:
            error.message,

          errorCode:
            error.code ||
            "FORENSIC_SCAN_FAILED",
        }
      );

    throw error;
  }
}

/* ==========================================================================
   START AGENT JOB
   ========================================================================== */

async function executeAgentJob(
  req,
  job
) {
  try {
    const manifest =
      await readManifest(
        job.evidenceId
      );

    if (!manifest) {
      throw new Error(
        "Evidence manifest not found."
      );
    }

    await updateJob(
      job.jobId,
      {
        status:
          "DISPATCHING",

        progress:
          5,

        startedAt:
          new Date().toISOString(),
      }
    );

    const task = {
      type:
        "FORENSIC_SCAN",

      taskType:
        "FORENSIC_SCAN",

      jobId:
        job.jobId,

      operationId:
        job.operationId,

      caseId:
        job.caseId,

      evidenceId:
        job.evidenceId,

      agentId:
        job.agentId,

      examiner:
        job.examiner,

      fileName:
        manifest.fileName,

      storedFileName:
        manifest.storedFileName,

      evidenceHash:
        manifest.sha256,

      fileSize:
        manifest.size,

      operation:
        job.operation,

      createdAt:
        new Date().toISOString(),
    };

    const response =
      await sendToAgent(
        req,
        task
      );

    await updateJob(
      job.jobId,
      {
        status:
          "DISPATCHED",

        progress:
          10,

        agentResponse:
          response || null,
      }
    );

    return response;
  } catch (error) {
    console.error(
      `[Forensics:${job.jobId}] Agent dispatch failed:`,
      error
    );

    await updateJob(
      job.jobId,
      {
        status:
          "FAILED",

        progress:
          100,

        completedAt:
          new Date().toISOString(),

        error:
          error.message,

        errorCode:
          "FORENSIC_AGENT_DISPATCH_FAILED",
      }
    );

    throw error;
  }
}
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d

/* ==========================================================================
   CREATE FORENSIC JOB
   ========================================================================== */

router.post(
  "/jobs",
<<<<<<< HEAD
  async (req, res) => {
    try {
      const evidenceId =
        safeString(
          req.body.evidenceId
        );

      if (!evidenceId) {
        return fail(
          res,
          400,
          "evidenceId is required.",
          "FORENSIC_EVIDENCE_ID_REQUIRED"
        );
      }

      const manifest =
        await readManifest(
          evidenceId
        );

      if (!manifest) {
        return fail(
          res,
          404,
          "Evidence not found.",
          "FORENSIC_EVIDENCE_NOT_FOUND"
        );
      }

      const evidencePath =
        safePath(
          EVIDENCE_DIR,
          manifest.storedFileName
        );

      if (
        !fs.existsSync(
          evidencePath
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
        )
      ) {
        return fail(
          res,
<<<<<<< HEAD
          404,
          "Evidence file is missing.",
          "FORENSIC_EVIDENCE_FILE_MISSING"
        );
      }

      const caseId =
        safeString(
          req.body.caseId,
          manifest.caseId ||
            createCaseId()
        );

      const examiner =
        safeString(
          req.body.examiner,
          manifest.examiner ||
            "Unknown Examiner"
        );

      const agentId =
        safeString(
          req.body.agentId,
          ""
        );

      const requestedMode =
        safeString(
          req.body.executionMode,
          FORENSIC_EXECUTION_MODE
        );

      const executionMode =
        resolveExecutionMode(
          requestedMode,
          agentId
        );

      if (
        executionMode ===
          "agent" &&
        !agentId
      ) {
        return fail(
          res,
          400,
          "agentId is required for agent execution mode.",
          "FORENSIC_AGENT_ID_REQUIRED"
        );
      }

      if (
        executionMode ===
          "local" &&
        !fs.existsSync(
          CLI_PATH
        )
      ) {
        return fail(
          res,
          503,
          "Local forensic Python engine is not available on this server.",
          "FORENSIC_ENGINE_UNAVAILABLE"
        );
      }
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d

      const jobId =
        createJobId();

      const operationId =
        createOperationId();

<<<<<<< HEAD
=======
      const createdAt =
        new Date().toISOString();

>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
      const job = {
        jobId,

        operationId,

        caseId,

        examiner,

<<<<<<< HEAD
        agentId:
          agentId || null,

        operation:
          safeString(
            req.body.operation,
            "FORENSIC_SCAN"
          ),
=======
        agentId,

        operation,
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d

        status:
          "QUEUED",

        progress:
          0,

        bytesScanned:
          0,

        bytesTotal:
<<<<<<< HEAD
          manifest.size || 0,
=======
          integrity.currentSize,
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d

        artifactsFound:
          0,

        artifactsValidated:
          0,

<<<<<<< HEAD
        evidenceId,

        fileName:
          manifest.fileName,

        evidenceHash:
          manifest.sha256,

        source:
          manifest.source ||
          "forensic_upload",

        executionMode,

        createdAt:
          new Date().toISOString(),

        updatedAt:
          new Date().toISOString(),
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d

        startedAt:
          null,

        completedAt:
          null,

<<<<<<< HEAD
=======
        updatedAt:
          createdAt,

>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
        error:
          null,

        result:
          null,
      };

      await saveJob(
        job
      );

<<<<<<< HEAD
      let caseData =
        await readCase(
          caseId
        );

      if (!caseData) {
        caseData = {
          caseId,

          examiner,

          title:
            "Forensic Investigation",

          description:
            "",

          status:
            "OPEN",

          createdAt:
            new Date().toISOString(),

          updatedAt:
            new Date().toISOString(),

          evidence: [
            evidenceId,
          ],

          jobs: [],
        };
      }

      caseData.jobs =
        Array.isArray(
          caseData.jobs
        )
          ? caseData.jobs
          : [];

      if (
        !caseData.jobs.includes(
          jobId
        )
      ) {
        caseData.jobs.push(
          jobId
        );
      }

      if (
        !Array.isArray(
          caseData.evidence
        )
      ) {
        caseData.evidence =
          [];
      }

      if (
        !caseData.evidence.includes(
          evidenceId
        )
      ) {
        caseData.evidence.push(
          evidenceId
        );
      }

      caseData.updatedAt =
        new Date().toISOString();

      await saveCase(
        caseData
      );

      // Start execution without blocking the HTTP response.
      setImmediate(
        async () => {
          try {
            if (
              executionMode ===
              "agent"
            ) {
              await executeAgentJob(
                req,
                job
              );
            } else {
              await executeLocalJob(
                req,
                job
              );
            }
          } catch (error) {
            console.error(
              `[Forensics:${jobId}] Background job failed:`,
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
              error.message
            );
          }
        }
<<<<<<< HEAD
      );

      return success(
        res,
        {
          message:
            "Forensic job created successfully.",

          job,
        },
        201
      );
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to create forensic job.",
        "FORENSIC_JOB_CREATE_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   GET ALL JOBS
   ========================================================================== */

router.get(
  "/jobs",
  async (req, res) => {
    try {
      const jobs =
        await discoverJobs();

      const limit =
        Math.min(
          Math.max(
            Number(
              req.query.limit || 50
            ),
            1
          ),
          200
        );

      const offset =
        Math.max(
          Number(
            req.query.offset || 0
          ),
          0
        );

      const filtered =
        jobs.filter(
          (job) => {
            if (
              req.query.status &&
              job.status !==
                req.query.status
            ) {
              return false;
            }

            if (
              req.query.caseId &&
              job.caseId !==
                req.query.caseId
            ) {
              return false;
            }

            if (
              req.query.agentId &&
              job.agentId !==
                req.query.agentId
            ) {
              return false;
            }

            return true;
          }
        );

      const result =
        filtered.slice(
          offset,
          offset + limit
        );

      return success(
        res,
        {
          jobs:
            result,

          count:
            result.length,

          total:
            filtered.length,

          limit,

          offset,
        }
      );
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to retrieve forensic jobs.",
        "FORENSIC_JOB_LIST_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   GET SINGLE JOB
   ========================================================================== */

router.get(
  "/jobs/:jobId",
  async (req, res) => {
    try {
      const jobId =
        safeString(
          req.params.jobId
        );

      const job =
        await getJob(
          jobId
        );

      if (!job) {
        return fail(
          res,
          404,
          "Forensic job not found.",
          "FORENSIC_JOB_NOT_FOUND"
        );
      }

      return success(
        res,
        {
          job,
        }
=======

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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
      );
    } catch (error) {
      return fail(
        res,
<<<<<<< HEAD
        500,
        "Unable to retrieve forensic job.",
        "FORENSIC_JOB_GET_FAILED",
=======
        400,
        error.message ||
          "Unable to create forensic job.",
        error.code ||
          "FORENSIC_JOB_CREATE_FAILED",
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
        error
      );
    }
  }
);

/* ==========================================================================
<<<<<<< HEAD
   JOB PROGRESS
   ========================================================================== */

router.get(
  "/jobs/:jobId/progress",
  async (req, res) => {
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

      return success(
        res,
        {
          jobId:
            job.jobId,

          status:
            job.status,

          progress:
            Number(
              job.progress || 0
            ),

          bytesScanned:
            Number(
              job.bytesScanned || 0
            ),

          bytesTotal:
            Number(
              job.bytesTotal || 0
            ),

          artifactsFound:
            Number(
              job.artifactsFound || 0
            ),

          artifactsValidated:
            Number(
              job.artifactsValidated || 0
            ),

          error:
            job.error || null,

          updatedAt:
            job.updatedAt,
        }
      );
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to retrieve forensic job progress.",
        "FORENSIC_PROGRESS_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   COMPLETE AGENT JOB
   ========================================================================== */

router.post(
  "/jobs/:jobId/complete",
  async (req, res) => {
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
        req.body.result ||
        req.body;

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
                  job.bytesTotal ??
                  0
              ),

            bytesTotal:
              Number(
                result.bytesTotal ??
                  job.bytesTotal ??
                  0
              ),

            artifactsFound:
              Number(
                result.artifactsFound ??
                  result.artifacts?.length ??
                  0
              ),

            artifactsValidated:
              Number(
                result.artifactsValidated ??
                  0
              ),

            result,

            completedAt:
              new Date().toISOString(),

            error:
              null,
          }
        );

      return success(
        res,
        {
          message:
            "Forensic job completed.",

          job:
            completed,
        }
      );
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
   FAIL AGENT JOB
   ========================================================================== */

router.post(
  "/jobs/:jobId/fail",
  async (req, res) => {
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

      const message =
        safeString(
          req.body.error ||
            req.body.message,
          "Forensic job failed."
        );

      const failed =
        await updateJob(
          job.jobId,
          {
            status:
              "FAILED",

            progress:
              100,

            error:
              message,

            errorCode:
              safeString(
                req.body.errorCode,
                "FORENSIC_AGENT_JOB_FAILED"
              ),

            completedAt:
              new Date().toISOString(),
          }
        );

      return success(
        res,
        {
          message:
            "Forensic job marked as failed.",

          job:
            failed,
        }
      );
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to mark forensic job as failed.",
        "FORENSIC_JOB_FAIL_UPDATE_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   DIRECT SCAN ENDPOINT
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
   ========================================================================== */

router.post(
  "/scan",
<<<<<<< HEAD
  async (req, res) => {
    try {
      const evidenceId =
        safeString(
          req.body.evidenceId
        );

      if (!evidenceId) {
        return fail(
          res,
          400,
          "evidenceId is required.",
          "FORENSIC_EVIDENCE_ID_REQUIRED"
        );
      }

      const manifest =
        await readManifest(
          evidenceId
        );

      if (!manifest) {
        return fail(
          res,
          404,
          "Evidence not found.",
          "FORENSIC_EVIDENCE_NOT_FOUND"
        );
      }

      const executionMode =
        resolveExecutionMode(
          req.body.executionMode,
          req.body.agentId
        );

      // The recommended path is the asynchronous job API.
      // This endpoint creates the job and returns immediately.
      const fakeRequest =
        req;

      const caseId =
        safeString(
          req.body.caseId,
          manifest.caseId ||
            createCaseId()
        );

      const examiner =
        safeString(
          req.body.examiner,
          manifest.examiner ||
            "Unknown Examiner"
        );

      const jobId =
        createJobId();

      const operationId =
        createOperationId();

      const job = {
        jobId,

        operationId,
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d

        caseId,

        examiner,

<<<<<<< HEAD
        agentId:
          safeString(
            req.body.agentId,
            ""
          ) || null,
=======
        agentId,
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d

        operation:
          "FORENSIC_SCAN",

        status:
          "QUEUED",

        progress:
          0,

        bytesScanned:
          0,

        bytesTotal:
<<<<<<< HEAD
          manifest.size || 0,
=======
          integrity.currentSize,
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d

        artifactsFound:
          0,

        artifactsValidated:
          0,

<<<<<<< HEAD
        evidenceId,

        fileName:
          manifest.fileName,

        evidenceHash:
          manifest.sha256,

        source:
          manifest.source ||
          "forensic_scan",

        executionMode,
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d

        createdAt:
          new Date().toISOString(),

<<<<<<< HEAD
        updatedAt:
          new Date().toISOString(),

=======
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
        startedAt:
          null,

        completedAt:
          null,

<<<<<<< HEAD
=======
        updatedAt:
          new Date().toISOString(),

>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
        error:
          null,

        result:
          null,
      };

      await saveJob(
        job
      );

<<<<<<< HEAD
      setImmediate(
        async () => {
          try {
            if (
              executionMode ===
              "agent"
            ) {
              await executeAgentJob(
                fakeRequest,
                job
              );
            } else {
              await executeLocalJob(
                fakeRequest,
                job
              );
            }
          } catch (error) {
            console.error(
              `[Forensics:${jobId}] Scan failed:`,
              error.message
            );
          }
        }
      );

      return success(
        res,
        {
          message:
            "Forensic scan started.",

          job,
        },
        202
      );
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to start forensic scan.",
        "FORENSIC_SCAN_START_FAILED",
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
        error
      );
    }
  }
);

/* ==========================================================================
<<<<<<< HEAD
   REPORT FILE DISCOVERY
   ========================================================================== */

async function discoverReports() {
  const reports = [];

  async function walk(
    directory
  ) {
    let entries = [];

    try {
      entries =
        await fsp.readdir(
          directory,
          {
            withFileTypes:
              true,
          }
        );
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath =
        path.join(
          directory,
          entry.name
        );

      if (
        entry.isDirectory()
      ) {
        await walk(
          fullPath
        );

        continue;
      }

      if (
        !entry.isFile()
      ) {
        continue;
      }

      try {
        const stat =
          await fsp.stat(
            fullPath
          );

        reports.push({
          fileName:
            entry.name,

          path:
            fullPath,

          relativePath:
            path.relative(
              REPORTS_DIR,
              fullPath
            ),

          size:
            stat.size,

          createdAt:
            stat.birthtime.toISOString(),

          modifiedAt:
            stat.mtime.toISOString(),
        });
      } catch {
        // Ignore unreadable report.
      }
    }
  }

  await walk(
    REPORTS_DIR
  );

  reports.sort(
    (a, b) =>
      new Date(
        b.modifiedAt
      ) -
      new Date(
        a.modifiedAt
      )
  );

  return reports;
}

/* ==========================================================================
   REPORT LIST
   ========================================================================== */

router.get(
  "/reports",
  async (_req, res) => {
    try {
      const reports =
        await discoverReports();

      return success(
        res,
        {
          reports,

          count:
            reports.length,
        }
      );
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to retrieve forensic reports.",
        "FORENSIC_REPORT_LIST_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   ARTIFACT DISCOVERY
   ========================================================================== */

async function discoverArtifacts() {
  const artifacts = [];

  async function walk(
    directory
  ) {
    let entries = [];

    try {
      entries =
        await fsp.readdir(
          directory,
          {
            withFileTypes:
              true,
            },
          );
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath =
        path.join(
          directory,
          entry.name
        );

      if (
        entry.isDirectory()
      ) {
        await walk(
          fullPath
        );

        continue;
      }

      if (
        !entry.isFile()
      ) {
        continue;
      }

      try {
        const stat =
          await fsp.stat(
            fullPath
          );

        artifacts.push({
          fileName:
            entry.name,

          path:
            fullPath,

          relativePath:
            path.relative(
              RECOVERED_DIR,
              fullPath
            ),

          size:
            stat.size,

          modifiedAt:
            stat.mtime.toISOString(),
        });
      } catch {
        // Ignore.
      }
    }
  }

  await walk(
    RECOVERED_DIR
  );

  artifacts.sort(
    (a, b) =>
      new Date(
        b.modifiedAt
      ) -
      new Date(
        a.modifiedAt
      )
  );

  return artifacts;
}

/* ==========================================================================
   ARTIFACT LIST
   ========================================================================== */

router.get(
  "/artifacts",
  async (_req, res) => {
    try {
      const artifacts =
        await discoverArtifacts();

      return success(
        res,
        {
          artifacts,

          count:
            artifacts.length,
        }
      );
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to retrieve recovered forensic artifacts.",
        "FORENSIC_ARTIFACT_LIST_FAILED",
        error
      );
    }
  }
);
 /* ==========================================================================
    PART 3 — DOWNLOADS, MANIFESTS, CHAIN OF CUSTODY & EXPORTS
    ========================================================================== */

/* ==========================================================================
   GET EVIDENCE DETAILS
   ========================================================================== */

router.get(
  "/evidence/:evidenceId",
  async (req, res) => {
    try {
      const evidenceId =
        safeString(req.params.evidenceId);

      if (!evidenceId) {
        return fail(
          res,
          400,
          "Evidence ID is required.",
          "FORENSIC_EVIDENCE_ID_REQUIRED"
        );
      }

      const manifest =
        await readManifest(evidenceId);

      if (!manifest) {
        return fail(
          res,
          404,
          "Evidence not found.",
          "FORENSIC_EVIDENCE_NOT_FOUND"
        );
      }

      return success(res, {
        evidence: manifest,
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
      });
    } catch (error) {
      return fail(
        res,
        500,
<<<<<<< HEAD
        "Unable to retrieve evidence details.",
        "FORENSIC_EVIDENCE_GET_FAILED",
=======
        "Unable to list forensic jobs.",
        "FORENSIC_JOB_LIST_FAILED",
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
        error
      );
    }
  }
);

/* ==========================================================================
<<<<<<< HEAD
   VERIFY EVIDENCE BY ID
   ========================================================================== */

router.get(
  "/evidence/:evidenceId/verify",
  async (req, res) => {
    try {
      const evidenceId =
        safeString(req.params.evidenceId);

      const manifest =
        await readManifest(evidenceId);

      if (!manifest) {
        return fail(
          res,
          404,
          "Evidence not found.",
          "FORENSIC_EVIDENCE_NOT_FOUND"
        );
      }

      const evidencePath =
        safePath(
          EVIDENCE_DIR,
          manifest.storedFileName
        );

      if (!fs.existsSync(evidencePath)) {
        return fail(
          res,
          404,
          "Evidence file is missing.",
          "FORENSIC_EVIDENCE_FILE_MISSING"
        );
      }

      const current =
        await getFileIntegrity(
          evidencePath
        );

      const verified =
        Boolean(
          manifest.sha256 &&
          manifest.sha256 ===
            current.sha256
        );

      return success(res, {
        evidenceId,

        verified,

        expectedHash:
          manifest.sha256,

        actualHash:
          current.sha256,

        fileSize:
          current.size,

        checkedAt:
          new Date().toISOString(),
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Evidence verification failed.",
        "FORENSIC_EVIDENCE_VERIFY_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   DOWNLOAD EVIDENCE
   ========================================================================== */

router.get(
  "/evidence/:evidenceId/download",
  async (req, res) => {
    try {
      const evidenceId =
        safeString(req.params.evidenceId);

      const manifest =
        await readManifest(evidenceId);

      if (!manifest) {
        return fail(
          res,
          404,
          "Evidence not found.",
          "FORENSIC_EVIDENCE_NOT_FOUND"
        );
      }

      const evidencePath =
        safePath(
          EVIDENCE_DIR,
          manifest.storedFileName
        );

      if (!fs.existsSync(evidencePath)) {
        return fail(
          res,
          404,
          "Evidence file is missing.",
          "FORENSIC_EVIDENCE_FILE_MISSING"
        );
      }

      /*
       * Evidence should normally NOT be exposed publicly.
       * This endpoint is intended for authorized forensic
       * environments only.
       */

      res.download(
        evidencePath,
        manifest.fileName,
        (error) => {
          if (error) {
            console.error(
              "[Forensics] Evidence download failed:",
              error
            );
          }
        }
      );
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to download evidence.",
        "FORENSIC_EVIDENCE_DOWNLOAD_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   GET MANIFEST
   ========================================================================== */

router.get(
  "/evidence/:evidenceId/manifest",
  async (req, res) => {
    try {
      const evidenceId =
        safeString(req.params.evidenceId);

      const manifest =
        await readManifest(evidenceId);

      if (!manifest) {
        return fail(
          res,
          404,
          "Evidence manifest not found.",
          "FORENSIC_MANIFEST_NOT_FOUND"
        );
      }

      return success(res, {
        manifest,
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to retrieve evidence manifest.",
        "FORENSIC_MANIFEST_GET_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   CHAIN OF CUSTODY
   ========================================================================== */

function createCustodyEntry({
  action,
  caseId,
  evidenceId,
  jobId,
  examiner,
  description,
  hash,
}) {
  return {
    custodyId:
      "COC-" +
      crypto
        .randomBytes(8)
        .toString("hex")
        .toUpperCase(),

    action,

    caseId:
      caseId || null,

    evidenceId:
      evidenceId || null,

    jobId:
      jobId || null,

    examiner:
      examiner || "Unknown Examiner",

    description:
      description || "",

    hash:
      hash || null,

    timestamp:
      new Date().toISOString(),
  };
}

/* ==========================================================================
   ADD CHAIN OF CUSTODY ENTRY
   ========================================================================== */

router.post(
  "/custody",
  async (req, res) => {
    try {
      const evidenceId =
        safeString(req.body.evidenceId);

      if (!evidenceId) {
        return fail(
          res,
          400,
          "evidenceId is required.",
          "FORENSIC_EVIDENCE_ID_REQUIRED"
        );
      }

      const manifest =
        await readManifest(evidenceId);

      if (!manifest) {
        return fail(
          res,
          404,
          "Evidence not found.",
          "FORENSIC_EVIDENCE_NOT_FOUND"
        );
      }

      const entry =
        createCustodyEntry({
          action:
            safeString(
              req.body.action,
              "EVIDENCE_ACCESS"
            ),

          caseId:
            safeString(
              req.body.caseId,
              manifest.caseId
            ),

          evidenceId,

          jobId:
            safeString(
              req.body.jobId,
              ""
            ) || null,

          examiner:
            safeString(
              req.body.examiner,
              manifest.examiner ||
                "Unknown Examiner"
            ),

          description:
            safeString(
              req.body.description,
              ""
            ),

          hash:
            manifest.sha256,
        });

      if (
        !Array.isArray(
          manifest.chainOfCustody
        )
      ) {
        manifest.chainOfCustody = [];
      }

      manifest.chainOfCustody.push(
        entry
      );

      manifest.updatedAt =
        new Date().toISOString();

      await saveManifest(
        manifest
      );

      return success(
        res,
        {
          message:
            "Chain-of-custody entry recorded.",

          entry,

          evidenceId,
        },
        201
      );
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to record chain of custody.",
        "FORENSIC_CUSTODY_CREATE_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   GET CHAIN OF CUSTODY
   ========================================================================== */

router.get(
  "/custody/:evidenceId",
  async (req, res) => {
    try {
      const evidenceId =
        safeString(req.params.evidenceId);

      const manifest =
        await readManifest(evidenceId);

      if (!manifest) {
        return fail(
          res,
          404,
          "Evidence not found.",
          "FORENSIC_EVIDENCE_NOT_FOUND"
        );
      }

      return success(res, {
        evidenceId,

        chainOfCustody:
          Array.isArray(
            manifest.chainOfCustody
          )
            ? manifest.chainOfCustody
            : [],
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to retrieve chain of custody.",
        "FORENSIC_CUSTODY_GET_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   DOWNLOAD RECOVERED ARTIFACT
   ========================================================================== */

router.get(
  "/artifacts/download",
  async (req, res) => {
    try {
      const relativePath =
        safeString(
          req.query.path
        );

      if (!relativePath) {
        return fail(
          res,
          400,
          "Artifact path is required.",
          "FORENSIC_ARTIFACT_PATH_REQUIRED"
        );
      }

      const artifactPath =
        safePath(
          RECOVERED_DIR,
          relativePath
        );

      if (!fs.existsSync(artifactPath)) {
        return fail(
          res,
          404,
          "Recovered artifact not found.",
          "FORENSIC_ARTIFACT_NOT_FOUND"
        );
      }

      const stat =
        await fsp.stat(
          artifactPath
        );

      if (!stat.isFile()) {
        return fail(
          res,
          400,
          "Requested artifact is not a file.",
          "FORENSIC_ARTIFACT_INVALID"
        );
      }

      return res.download(
        artifactPath,
        path.basename(
          artifactPath
        ),
        (error) => {
          if (error) {
            console.error(
              "[Forensics] Artifact download failed:",
              error
            );
          }
        }
      );
    } catch (error) {
      return fail(
        res,
        400,
        "Invalid artifact path.",
        "FORENSIC_ARTIFACT_PATH_INVALID",
        error
      );
    }
  }
);

/* ==========================================================================
   DOWNLOAD REPORT
   ========================================================================== */

router.get(
  "/reports/download",
  async (req, res) => {
    try {
      const relativePath =
        safeString(
          req.query.path
        );

      if (!relativePath) {
        return fail(
          res,
          400,
          "Report path is required.",
          "FORENSIC_REPORT_PATH_REQUIRED"
        );
      }

      const reportPath =
        safePath(
          REPORTS_DIR,
          relativePath
        );

      if (!fs.existsSync(reportPath)) {
        return fail(
          res,
          404,
          "Forensic report not found.",
          "FORENSIC_REPORT_NOT_FOUND"
        );
      }

      const stat =
        await fsp.stat(
          reportPath
        );

      if (!stat.isFile()) {
        return fail(
          res,
          400,
          "Requested report is not a file.",
          "FORENSIC_REPORT_INVALID"
        );
      }

      return res.download(
        reportPath,
        path.basename(
          reportPath
        ),
        (error) => {
          if (error) {
            console.error(
              "[Forensics] Report download failed:",
              error
            );
          }
        }
      );
    } catch (error) {
      return fail(
        res,
        400,
        "Invalid report path.",
        "FORENSIC_REPORT_PATH_INVALID",
        error
      );
    }
  }
);

/* ==========================================================================
   JOB ARTIFACTS
   ========================================================================== */

router.get(
  "/jobs/:jobId/artifacts",
  async (req, res) => {
    try {
      const jobId =
        safeString(
          req.params.jobId
        );

      const job =
        await getJob(jobId);

=======
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

>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
      if (!job) {
        return fail(
          res,
          404,
          "Forensic job not found.",
          "FORENSIC_JOB_NOT_FOUND"
        );
      }

<<<<<<< HEAD
      const jobOutput =
        safePath(
          RECOVERED_DIR,
          jobId
        );

      if (!fs.existsSync(jobOutput)) {
        return success(res, {
          jobId,

          artifacts: [],

          count: 0,
        });
      }

      const artifacts = [];

      async function walk(
        directory
      ) {
        const entries =
          await fsp.readdir(
            directory,
            {
              withFileTypes:
                true,
            }
          );

        for (
          const entry of entries
        ) {
          const fullPath =
            path.join(
              directory,
              entry.name
            );

          if (
            entry.isDirectory()
          ) {
            await walk(
              fullPath
            );
          } else if (
            entry.isFile()
          ) {
            const stat =
              await fsp.stat(
                fullPath
              );

            artifacts.push({
              fileName:
                entry.name,

              relativePath:
                path.relative(
                  RECOVERED_DIR,
                  fullPath
                ),

              size:
                stat.size,

              modifiedAt:
                stat.mtime.toISOString(),
            });
          }
        }
      }

      await walk(
        jobOutput
      );

      return success(res, {
        jobId,

        artifacts,

        count:
          artifacts.length,
=======
      return res.json({
        success: true,

        job,
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
      });
    } catch (error) {
      return fail(
        res,
        500,
<<<<<<< HEAD
        "Unable to retrieve job artifacts.",
        "FORENSIC_JOB_ARTIFACTS_FAILED",
=======
        "Unable to retrieve forensic job.",
        "FORENSIC_JOB_STATUS_FAILED",
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
        error
      );
    }
  }
);

/* ==========================================================================
<<<<<<< HEAD
   JOB CANCEL
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
   ========================================================================== */

router.post(
  "/jobs/:jobId/cancel",
<<<<<<< HEAD
  async (req, res) => {
    try {
      const jobId =
        safeString(
          req.params.jobId
        );

      const job =
        await getJob(jobId);

=======
  async (
    req,
    res
  ) => {
    try {
      const job =
        await getJob(
          req.params.jobId
        );

>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
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
<<<<<<< HEAD
        return fail(
          res,
          409,
          `Job is already ${job.status.toLowerCase()}.`,
          "FORENSIC_JOB_NOT_ACTIVE"
        );
      }

      const cancelled =
        await updateJob(
          jobId,
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
          {
            status:
              "CANCELLED",

<<<<<<< HEAD
            progress:
              100,

            completedAt:
              new Date().toISOString(),

            error:
              "Job cancelled by user.",
          }
        );

      return success(res, {
=======
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

>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
        message:
          "Forensic job cancelled.",

        job:
<<<<<<< HEAD
          cancelled,
=======
          updated,
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to cancel forensic job.",
<<<<<<< HEAD
        "FORENSIC_JOB_CANCEL_FAILED",
=======
        "FORENSIC_CANCEL_FAILED",
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
        error
      );
    }
  }
);

/* ==========================================================================
<<<<<<< HEAD
   FORENSIC SUMMARY
   ========================================================================== */

router.get(
  "/summary",
  async (_req, res) => {
    try {
      const jobs =
        await discoverJobs();

      const evidence =
        await discoverEvidence();

      const reports =
        await discoverReports();

      const artifacts =
        await discoverArtifacts();

      const summary = {
        evidence:
          evidence.length,

        jobs:
          jobs.length,

        reports:
          reports.length,

        artifacts:
          artifacts.length,

        queued:
          jobs.filter(
            (job) =>
              job.status ===
              "QUEUED"
          ).length,

        processing:
          jobs.filter(
            (job) =>
              [
                "PROCESSING",
                "DISPATCHING",
                "DISPATCHED",
              ].includes(
                job.status
              )
          ).length,

        completed:
          jobs.filter(
            (job) =>
              job.status ===
              "COMPLETED"
          ).length,

        failed:
          jobs.filter(
            (job) =>
              job.status ===
              "FAILED"
          ).length,

        cancelled:
          jobs.filter(
            (job) =>
              job.status ===
              "CANCELLED"
          ).length,
      };

      return success(res, {
        summary,

        generatedAt:
          new Date().toISOString(),
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
      });
    } catch (error) {
      return fail(
        res,
        500,
<<<<<<< HEAD
        "Unable to generate forensic summary.",
        "FORENSIC_SUMMARY_FAILED",
=======
        "Unable to generate forensic report.",
        "REPORT_FAILED",
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
        error
      );
    }
  }
);

/* ==========================================================================
<<<<<<< HEAD
   HEALTH CHECK
   ========================================================================== */

router.get(
  "/health",
  async (_req, res) => {
    try {
      const pythonAvailable =
        fs.existsSync(
          CLI_PATH
        );

      return success(res, {
        service:
          "TrustWipe Forensic Recovery",

        status:
          "healthy",

        pythonEngine:
          pythonAvailable
            ? "available"
            : "unavailable",

        executionMode:
          FORENSIC_EXECUTION_MODE,

        timestamp:
          new Date().toISOString(),
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Forensic health check failed.",
        "FORENSIC_HEALTH_FAILED",
        error
=======
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
>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
      );
    }
  }
);

/* ==========================================================================
<<<<<<< HEAD
   UNKNOWN FORENSIC ROUTE
   ========================================================================== */

router.use(
  (req, res) => {
    return fail(
      res,
      404,
      `Forensic endpoint not found: ${req.method} ${req.originalUrl}`,
      "FORENSIC_ROUTE_NOT_FOUND"
    );
  }
);

/* ==========================================================================
   FINAL ERROR HANDLER
   ========================================================================== */

router.use(
  (error, req, res, _next) => {
    console.error(
      "[Forensics] Unhandled route error:",
      error
    );

    if (
      error?.code ===
      "LIMIT_FILE_SIZE"
    ) {
      return fail(
        res,
        413,
        "Evidence file exceeds the configured upload size limit.",
        "FORENSIC_FILE_TOO_LARGE",
        error
      );
    }

    return fail(
      res,
      500,
      "Internal forensic service error.",
      "FORENSIC_INTERNAL_ERROR",
      error
    );
  }
);

/* ==========================================================================
   EXPORTS
   ========================================================================== */

export {
  calculateSHA256,
  calculateMD5,
  getFileIntegrity,

  saveJob,
  readJob,
  updateJob,
  getJob,
  discoverJobs,

  saveCase,
  readCase,

  saveManifest,
  readManifest,

  createJobId,
  createOperationId,
  createEvidenceId,
  createCaseId,

  EVIDENCE_DIR,
  RECOVERED_DIR,
  REPORTS_DIR,
  MANIFESTS_DIR,
  CASES_DIR,
  JOBS_DIR,

  FORENSIC_ROOT,
  CLI_PATH,
};

=======
   EXPORT
   ========================================================================== */

>>>>>>> eb6d9dcf82f8db5c4712d2717ca003e78bbe136d
export default router;