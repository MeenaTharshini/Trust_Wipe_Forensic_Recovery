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

const MAX_UPLOAD_BYTES =
  Number(process.env.FORENSIC_MAX_UPLOAD_BYTES) ||
  5 * 1024 * 1024 * 1024;

const SCAN_TIMEOUT_MS =
  Number(process.env.FORENSIC_SCAN_TIMEOUT_MS) ||
  30 * 60 * 1000;

const MAX_OUTPUT =
  Number(process.env.FORENSIC_MAX_PROCESS_OUTPUT) ||
  4 * 1024 * 1024;

const FORENSIC_PYTHON =
  process.env.FORENSIC_PYTHON ||
  (process.platform === "win32"
    ? "python"
    : "python3");

const REQUIRE_AUTH =
  String(
    process.env.FORENSIC_REQUIRE_AUTH || "false"
  ).toLowerCase() === "true";

const FORENSIC_API_KEY =
  process.env.FORENSIC_API_KEY || "";

const FORENSIC_EXECUTION_MODE =
  String(
    process.env.FORENSIC_EXECUTION_MODE || "local"
  ).toLowerCase();

const VALID_EXECUTION_MODES = [
  "local",
  "agent",
  "auto",
];

/* ==========================================================================
   DIRECTORY INITIALIZATION
   ========================================================================== */

const requiredDirectories = [
  FORENSIC_ROOT,
  EVIDENCE_DIR,
  RECOVERED_DIR,
  REPORTS_DIR,
  MANIFESTS_DIR,
  CASES_DIR,
  JOBS_DIR,
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

/* ==========================================================================
   RESPONSE HELPERS
   ========================================================================== */

function fail(
  res,
  status,
  message,
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
}

/* ==========================================================================
   SECURITY HELPERS
   ========================================================================== */

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
   ========================================================================== */

async function calculateSHA256(
  filePath
) {
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
    JSON.stringify(
      manifest,
      null,
      2
    ),
    "utf8"
  );

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
    ) {
      continue;
    }

    try {
      return JSON.parse(line);
    } catch {
      // Continue searching.
    }
  }

  return null;
}

/* ==========================================================================
   PYTHON FORENSIC EXECUTION
   ========================================================================== */

function runPythonForensicScan({
  inputPath,
  outputDir,
  caseId,
  examiner,
  jobId,
}) {
  return new Promise(
    (resolve, reject) => {
      if (
        !fs.existsSync(
          CLI_PATH
        )
      ) {
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
        }
      );

      const args = [
        CLI_PATH,
        "scan",
        "--input",
        inputPath,
        "--output",
        outputDir,
        "--case",
        caseId,
        "--examiner",
        examiner,
        "--json",
      ];

      console.log(
        "[Forensics] Starting Python scan:",
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

              TRUSTWIPE_FORENSIC_JOB_ID:
                jobId,

              TRUSTWIPE_FORENSIC_CASE_ID:
                caseId,

              TRUSTWIPE_FORENSIC_EXAMINER:
                examiner,
            },
          }
        );

      const output =
        createOutputCollector();

      let settled =
        false;

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
        setTimeout(
          () => {
            if (settled) {
              return;
            }

            console.error(
              `[Forensics:${jobId}] Scan timeout`
            );

            try {
              child.kill(
                "SIGTERM"
              );
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
    }
  );
}

/* ==========================================================================
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
    task
  );
}

/* ==========================================================================
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

/* ==========================================================================
   CREATE FORENSIC JOB
   ========================================================================== */

router.post(
  "/jobs",
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
        )
      ) {
        return fail(
          res,
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

      const jobId =
        createJobId();

      const operationId =
        createOperationId();

      const job = {
        jobId,

        operationId,

        caseId,

        examiner,

        agentId:
          agentId || null,

        operation:
          safeString(
            req.body.operation,
            "FORENSIC_SCAN"
          ),

        status:
          "QUEUED",

        progress:
          0,

        bytesScanned:
          0,

        bytesTotal:
          manifest.size || 0,

        artifactsFound:
          0,

        artifactsValidated:
          0,

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

        startedAt:
          null,

        completedAt:
          null,

        error:
          null,

        result:
          null,
      };

      await saveJob(
        job
      );

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
              error.message
            );
          }
        }
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
      );
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to retrieve forensic job.",
        "FORENSIC_JOB_GET_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
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
   ========================================================================== */

router.post(
  "/scan",
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

        caseId,

        examiner,

        agentId:
          safeString(
            req.body.agentId,
            ""
          ) || null,

        operation:
          "FORENSIC_SCAN",

        status:
          "QUEUED",

        progress:
          0,

        bytesScanned:
          0,

        bytesTotal:
          manifest.size || 0,

        artifactsFound:
          0,

        artifactsValidated:
          0,

        evidenceId,

        fileName:
          manifest.fileName,

        evidenceHash:
          manifest.sha256,

        source:
          manifest.source ||
          "forensic_scan",

        executionMode,

        createdAt:
          new Date().toISOString(),

        updatedAt:
          new Date().toISOString(),

        startedAt:
          null,

        completedAt:
          null,

        error:
          null,

        result:
          null,
      };

      await saveJob(
        job
      );

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
        error
      );
    }
  }
);

/* ==========================================================================
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
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to retrieve evidence details.",
        "FORENSIC_EVIDENCE_GET_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
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

      if (!job) {
        return fail(
          res,
          404,
          "Forensic job not found.",
          "FORENSIC_JOB_NOT_FOUND"
        );
      }

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
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to retrieve job artifacts.",
        "FORENSIC_JOB_ARTIFACTS_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
   JOB CANCEL
   ========================================================================== */

router.post(
  "/jobs/:jobId/cancel",
  async (req, res) => {
    try {
      const jobId =
        safeString(
          req.params.jobId
        );

      const job =
        await getJob(jobId);

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
          {
            status:
              "CANCELLED",

            progress:
              100,

            completedAt:
              new Date().toISOString(),

            error:
              "Job cancelled by user.",
          }
        );

      return success(res, {
        message:
          "Forensic job cancelled.",

        job:
          cancelled,
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to cancel forensic job.",
        "FORENSIC_JOB_CANCEL_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
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
      });
    } catch (error) {
      return fail(
        res,
        500,
        "Unable to generate forensic summary.",
        "FORENSIC_SUMMARY_FAILED",
        error
      );
    }
  }
);

/* ==========================================================================
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
      );
    }
  }
);

/* ==========================================================================
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

export default router;