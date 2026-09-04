import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import "./Forensics.css";

/* ============================================================================
   CONFIGURATION
   ============================================================================ */

const API_BASE =
  import.meta.env.VITE_BASE_URL?.replace(/\/$/, "");

if (!API_BASE) {
  throw new Error("VITE_BASE_URL is not configured.");
}
const MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024;

const STEPS = {
  CASES: "CASES",
  CREATE_CASE: "CREATE_CASE",
  EVIDENCE: "EVIDENCE",
  EXAMINATION: "EXAMINATION",
  ANALYSIS: "ANALYSIS",
  RESULTS: "RESULTS",
  REPORT: "REPORT",
};

const STATUS = {
  IDLE: "IDLE",
  ACQUIRING: "ACQUIRING",
  VERIFYING: "VERIFYING",
  READY: "READY",
  SCANNING: "SCANNING",
  COMPLETED: "COMPLETED",
  FAILED: "FAILED",
};

const INTEGRITY = {
  VERIFIED: "VERIFIED",
  TAMPERED: "TAMPERED",
  BASELINE_MISSING: "BASELINE_MISSING",
  UNKNOWN: "UNKNOWN",
};

const CASE_STORAGE_KEY = "trustwipe_forensic_cases";

/* ============================================================================
   API HELPERS
   ============================================================================ */

function apiUrl(path = "") {
  if (!path) return API_BASE;

  if (/^https?:\/\//i.test(path)) {
    return path;
  }

  return `${API_BASE}${path.startsWith("/") ? path : `/${path}`}`;
}

function getStoredToken() {
  return (
    localStorage.getItem("token") ||
    localStorage.getItem("accessToken") ||
    sessionStorage.getItem("token") ||
    sessionStorage.getItem("accessToken") ||
    null
  );
}

function authHeaders(extra = {}) {
  const token = getStoredToken();

  return {
    Accept: "application/json",
    ...(token
      ? {
          Authorization: `Bearer ${token}`,
        }
      : {}),
    ...extra,
  };
}

async function parseResponse(response) {
  const contentType =
    response.headers.get("content-type") || "";

  let body = null;

  if (contentType.includes("application/json")) {
    body = await response.json().catch(() => null);
  } else {
    const text = await response.text().catch(() => "");
    body = text ? { message: text } : null;
  }

  if (!response.ok) {
    const message =
      body?.message ||
      body?.error ||
      body?.detail ||
      `Request failed with HTTP ${response.status}`;

    const error = new Error(message);

    error.status = response.status;
    error.code = body?.code || null;
    error.response = body;

    throw error;
  }

  return body;
}

async function apiFetch(path, options = {}) {
  const response = await fetch(apiUrl(path), {
    ...options,
    headers: authHeaders(options.headers || {}),
  });

  return parseResponse(response);
}

/* ============================================================================
   GENERAL HELPERS
   ============================================================================ */

function firstDefined(...values) {
  return values.find(
    (value) =>
      value !== undefined &&
      value !== null &&
      value !== ""
  );
}

function toBoolean(value) {
  if (typeof value === "boolean") return value;

  if (typeof value === "number") {
    return value !== 0;
  }

  if (typeof value === "string") {
    return [
      "true",
      "yes",
      "1",
      "verified",
      "valid",
      "match",
      "matched",
    ].includes(value.toLowerCase());
  }

  return Boolean(value);
}

function formatBytes(bytes) {
  const value = Number(bytes);

  if (!Number.isFinite(value) || value < 0) {
    return "—";
  }

  if (value === 0) {
    return "0 B";
  }

  const units = ["B", "KB", "MB", "GB", "TB"];

  const exponent = Math.min(
    Math.floor(Math.log(value) / Math.log(1024)),
    units.length - 1
  );

  const size = value / 1024 ** exponent;

  return `${size.toFixed(
    exponent === 0 ? 0 : 2
  )} ${units[exponent]}`;
}

function formatDate(value) {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString();
}

function formatDuration(ms) {
  const value = Number(ms);

  if (!Number.isFinite(value)) {
    return "—";
  }

  if (value < 1000) {
    return `${Math.round(value)} ms`;
  }

  if (value < 60000) {
    return `${(value / 1000).toFixed(2)} s`;
  }

  const minutes = Math.floor(value / 60000);
  const seconds = Math.floor((value % 60000) / 1000);

  return `${minutes}m ${seconds}s`;
}

function getFileType(fileName = "") {
  const cleanName = String(fileName).split("?")[0];

  const extension = cleanName
    .split(".")
    .pop()
    ?.toUpperCase();

  return extension || "FILE";
}

function createLocalCaseId() {
  return `CASE-${new Date().getFullYear()}-${Date.now()}-${Math.random()
    .toString(36)
    .slice(2, 8)
    .toUpperCase()}`;
}

function getIntegrityClass(status) {
  switch (status) {
    case INTEGRITY.VERIFIED:
      return "integrity-verified";

    case INTEGRITY.TAMPERED:
      return "integrity-tampered";

    case INTEGRITY.BASELINE_MISSING:
      return "integrity-warning";

    default:
      return "integrity-unknown";
  }
}

function extractArray(response, keys = []) {
  if (Array.isArray(response)) {
    return response;
  }

  for (const key of keys) {
    if (Array.isArray(response?.[key])) {
      return response[key];
    }

    if (Array.isArray(response?.data?.[key])) {
      return response.data[key];
    }
  }

  if (Array.isArray(response?.data)) {
    return response.data;
  }

  return [];
}

/* ============================================================================
   NORMALIZERS
   ============================================================================ */

function normalizeEvidence(item) {
  if (!item || typeof item !== "object") {
    return null;
  }

  const name =
    firstDefined(
      item.name,
      item.fileName,
      item.file_name,
      item.originalName,
      item.original_name
    ) || "Unknown evidence";

  const sizeValue = firstDefined(
    item.size,
    item.fileSize,
    item.file_size,
    item.originalSize,
    item.original_size
  );

  const evidenceId = firstDefined(
    item.evidenceId,
    item.evidence_id,
    item.id
  );

  const hash = firstDefined(
    item.sha256,
    item.acquisitionHash,
    item.acquisition_hash,
    item.hash
  );

  const normalizedSize = Number(sizeValue);

  return {
    ...item,

    id:
      item.id ||
      evidenceId ||
      `${name}-${sizeValue || 0}`,

    name,

    size: Number.isFinite(normalizedSize)
      ? normalizedSize
      : 0,

    evidenceId: evidenceId || null,

    sha256: hash || null,

    acquisitionHash: hash || null,

    acquiredAt:
      firstDefined(
        item.acquiredAt,
        item.acquired_at,
        item.createdAt,
        item.created_at
      ) || null,

    type:
      firstDefined(
        item.type,
        item.mimeType,
        item.mime_type
      ) || getFileType(name),
  };
}

function normalizeIntegrity(value) {
  if (!value || typeof value !== "object") {
    return null;
  }

  const statusRaw =
    firstDefined(
      value.status,
      value.integrityStatus,
      value.integrity_status
    ) || INTEGRITY.UNKNOWN;

  const status = String(statusRaw).toUpperCase();

  const verifiedValue = firstDefined(
    value.verified,
    value.isVerified,
    value.is_verified
  );

  const hashMatchValue = firstDefined(
    value.hashMatch,
    value.hash_match
  );

  const sizeMatchValue = firstDefined(
    value.sizeMatch,
    value.size_match
  );

  return {
    ...value,

    status,

    verified:
      verifiedValue !== undefined
        ? toBoolean(verifiedValue)
        : status === INTEGRITY.VERIFIED,

    hashMatch:
      hashMatchValue !== undefined
        ? toBoolean(hashMatchValue)
        : status === INTEGRITY.VERIFIED,

    sizeMatch:
      sizeMatchValue !== undefined
        ? toBoolean(sizeMatchValue)
        : status === INTEGRITY.VERIFIED,

    originalHash:
      firstDefined(
        value.originalHash,
        value.original_hash,
        value.acquisitionHash,
        value.acquisition_hash,
        value.sha256
      ) || null,

    currentHash:
      firstDefined(
        value.currentHash,
        value.current_hash,
        value.currentSha256,
        value.current_sha256,
        value.sha256
      ) || null,

    originalSize:
      firstDefined(
        value.originalSize,
        value.original_size
      ) ?? null,

    currentSize:
      firstDefined(
        value.currentSize,
        value.current_size
      ) ?? null,

    evidenceId:
      firstDefined(
        value.evidenceId,
        value.evidence_id
      ) || null,

    acquiredAt:
      firstDefined(
        value.acquiredAt,
        value.acquired_at
      ) || null,

    message:
      firstDefined(
        value.message,
        value.detail,
        value.error
      ) || "",
  };
}

function normalizeRecoveredFile(file) {
  if (!file || typeof file !== "object") {
    return null;
  }

  const name =
    firstDefined(
      file.name,
      file.fileName,
      file.file_name
    ) || "Recovered artifact";

  const sizeValue = Number(file.size);

  return {
    ...file,

    name,

    path:
      firstDefined(
        file.path,
        file.downloadPath,
        file.download_path,
        file.url
      ) || null,

    artifactId:
      firstDefined(
        file.artifactId,
        file.artifact_id,
        file.id
      ) || null,

    size: Number.isFinite(sizeValue)
      ? sizeValue
      : 0,

    type:
      firstDefined(
        file.type,
        file.mimeType,
        file.mime_type
      ) || getFileType(name),

    extension:
      firstDefined(
        file.extension,
        file.ext
      ) || null,

    sourceOffset:
      firstDefined(
        file.sourceOffset,
        file.source_offset,
        file.offset
      ) ?? null,

    sourceEnd:
      firstDefined(
        file.sourceEnd,
        file.source_end,
        file.endOffset
      ) ?? null,

    confidence:
      firstDefined(
        file.confidence,
        file.validationConfidence
      ) ?? null,

    validationStatus:
      firstDefined(
        file.validationStatus,
        file.validation_status,
        file.validated === true
          ? "VALID"
          : null
      ) || "UNKNOWN",

    sha256:
      firstDefined(
        file.sha256,
        file.hash
      ) || null,

    modifiedAt:
      firstDefined(
        file.modifiedAt,
        file.modified_at
      ) || null,
  };
}

/* ============================================================================
   CASE STORAGE
   ============================================================================ */

function loadLocalCases() {
  try {
    const raw = localStorage.getItem(
      CASE_STORAGE_KEY
    );

    if (!raw) return [];

    const parsed = JSON.parse(raw);

    return Array.isArray(parsed)
      ? parsed
      : [];
  } catch {
    return [];
  }
}

function saveLocalCases(cases) {
  try {
    localStorage.setItem(
      CASE_STORAGE_KEY,
      JSON.stringify(cases)
    );
  } catch {
    // Ignore storage failures.
  }
}

/* ============================================================================
   MAIN COMPONENT
   ============================================================================ */

export default function Forensics() {
  const fileInputRef = useRef(null);

  /* --------------------------------------------------------------------------
     WORKFLOW
     -------------------------------------------------------------------------- */

  const [currentStep, setCurrentStep] =
    useState(STEPS.CASES);

  /* --------------------------------------------------------------------------
     CASE
     -------------------------------------------------------------------------- */

  const [cases, setCases] = useState(
    loadLocalCases
  );

  const [caseId, setCaseId] = useState("");
  const [examiner, setExaminer] = useState("");

  const [caseTitle, setCaseTitle] =
    useState("");

  const [caseDescription, setCaseDescription] =
    useState("");

  const [currentCase, setCurrentCase] =
    useState(null);

  /* --------------------------------------------------------------------------
     ENGINE
     -------------------------------------------------------------------------- */

  const [engine, setEngine] = useState({
    available: false,
    version: null,
    message: "Checking forensic engine...",
  });

  /* --------------------------------------------------------------------------
     STATUS
     -------------------------------------------------------------------------- */

  const [status, setStatus] =
    useState(STATUS.IDLE);

  const [busy, setBusy] =
    useState(false);

  const [progressMessage, setProgressMessage] =
    useState("");

  const [error, setError] =
    useState("");

  const [notice, setNotice] =
    useState("");

  /* --------------------------------------------------------------------------
     EVIDENCE
     -------------------------------------------------------------------------- */

  const [evidence, setEvidence] =
    useState([]);

  const [selectedEvidence, setSelectedEvidence] =
    useState(null);

  /* --------------------------------------------------------------------------
     INTEGRITY
     -------------------------------------------------------------------------- */

  const [integrity, setIntegrity] =
    useState(null);

  /* --------------------------------------------------------------------------
     ANALYSIS
     -------------------------------------------------------------------------- */

  const [analysisMode, setAnalysisMode] =
    useState(null);

  const [scanStats, setScanStats] =
    useState(null);

  const [scanOutput, setScanOutput] =
    useState("");

  const [lastScanDuration, setLastScanDuration] =
    useState(null);

  const [lastOperation, setLastOperation] =
    useState(null);

  /* --------------------------------------------------------------------------
     RECOVERY
     -------------------------------------------------------------------------- */

  const [recoveredFiles, setRecoveredFiles] =
    useState([]);

  /* --------------------------------------------------------------------------
     REPORT
     -------------------------------------------------------------------------- */

  const [report, setReport] =
    useState(null);

  const [reportFile, setReportFile] =
    useState(null);

  /* ==========================================================================
     DERIVED STATE
     ========================================================================== */

  const selectedEvidenceId =
    selectedEvidence?.evidenceId || null;

  const selectedFileName =
    selectedEvidence?.name || null;

  const integrityVerified =
    integrity?.status === INTEGRITY.VERIFIED &&
    integrity?.verified === true &&
    integrity?.hashMatch === true &&
    integrity?.sizeMatch === true;

  const repositoryStats = useMemo(() => {
    const totalSize = evidence.reduce(
      (sum, item) =>
        sum + Number(item.size || 0),
      0
    );

    return {
      total: evidence.length,
      totalSize,
    };
  }, [evidence]);

  const validatedArtifacts = useMemo(
    () =>
      recoveredFiles.filter(
        (file) =>
          String(
            file.validationStatus
          ).toUpperCase() === "VALID"
      ).length,
    [recoveredFiles]
  );

  /* ==========================================================================
     ENGINE STATUS
     ========================================================================== */

  const loadEngineStatus = useCallback(
    async () => {
      try {
        const response = await apiFetch(
          "/api/forensic/status"
        );

        const available = toBoolean(
          firstDefined(
            response?.pythonAvailable,
            response?.python_available,
            response?.available,
            response?.engineAvailable,
            response?.engine_available
          )
        );

        const version =
          firstDefined(
            response?.pythonVersion,
            response?.python_version,
            response?.version,
            response?.engineVersion,
            response?.engine_version
          ) || null;

        setEngine({
          available,
          version,
          message:
            response?.message ||
            (available
              ? "Forensic engine is ready."
              : "Forensic engine unavailable."),
        });
      } catch (err) {
        setEngine({
          available: false,
          version: null,
          message:
            err.message ||
            "Forensic engine unavailable.",
        });
      }
    },
    []
  );

  /* ==========================================================================
     EVIDENCE REPOSITORY
     ========================================================================== */

  const loadEvidence = useCallback(
    async () => {
      try {
        const response = await apiFetch(
          "/api/forensic/evidence"
        );

        const rawItems = extractArray(
          response,
          ["evidence"]
        );

        const items = rawItems
          .map(normalizeEvidence)
          .filter(Boolean);

        setEvidence(items);

        setSelectedEvidence(
          (current) => {
            if (!current) return null;

            const refreshed =
              items.find(
                (item) =>
                  (
                    current.evidenceId &&
                    item.evidenceId ===
                      current.evidenceId
                  ) ||
                  (
                    !current.evidenceId &&
                    item.name ===
                      current.name
                  )
              );

            return refreshed || current;
          }
        );
      } catch (err) {
        setError(
          err.message ||
            "Unable to load evidence repository."
        );
      }
    },
    []
  );

  useEffect(() => {
    loadEngineStatus();
    loadEvidence();
  }, [
    loadEngineStatus,
    loadEvidence,
  ]);

  /* ==========================================================================
     CASE MANAGEMENT
     ========================================================================== */

  const persistCase = useCallback(
    (newCase) => {
      const updated = [
        newCase,
        ...cases.filter(
          (item) =>
            item.caseId !==
            newCase.caseId
        ),
      ];

      setCases(updated);
      saveLocalCases(updated);
    },
    [cases]
  );

  const createCase = useCallback(() => {
    setError("");
    setNotice("");

    if (!caseTitle.trim()) {
      setError(
        "Case title is required."
      );
      return;
    }

    if (!examiner.trim()) {
      setError(
        "Examiner name is required."
      );
      return;
    }

    const newCase = {
      caseId:
        caseId.trim() ||
        createLocalCaseId(),

      title:
        caseTitle.trim(),

      description:
        caseDescription.trim(),

      examiner:
        examiner.trim(),

      createdAt:
        new Date().toISOString(),

      status: "OPEN",

      evidenceCount: 0,
    };

    persistCase(newCase);

    setCaseId(newCase.caseId);
    setCurrentCase(newCase);

    setNotice(
      `Case ${newCase.caseId} created successfully.`
    );

    setCurrentStep(STEPS.EVIDENCE);
  }, [
    caseId,
    caseTitle,
    caseDescription,
    examiner,
    persistCase,
  ]);

  const openExistingCase =
    useCallback((selectedCase) => {
      setError("");
      setNotice("");

      setCurrentCase(selectedCase);

      setCaseId(
        selectedCase.caseId
      );

      setExaminer(
        selectedCase.examiner || ""
      );

      setCaseTitle(
        selectedCase.title || ""
      );

      setCaseDescription(
        selectedCase.description || ""
      );

      setCurrentStep(
        STEPS.EVIDENCE
      );
    }, []);

  const startNewCaseScreen =
    useCallback(() => {
      setError("");
      setNotice("");

      setCaseId(
        createLocalCaseId()
      );

      setCaseTitle("");
      setCaseDescription("");
      setExaminer("");

      setCurrentCase(null);

      setCurrentStep(
        STEPS.CREATE_CASE
      );
    }, []);

  /* ==========================================================================
     SELECT EVIDENCE
     ========================================================================== */

  const selectEvidence = useCallback(
    (item) => {
      if (busy) return;

      const normalized =
        normalizeEvidence(item);

      if (!normalized) return;

      setSelectedEvidence(
        normalized
      );

      setIntegrity(null);
      setRecoveredFiles([]);
      setScanStats(null);
      setReport(null);
      setReportFile(null);
      setScanOutput("");
      setLastScanDuration(null);
      setLastOperation(null);
      setAnalysisMode(null);

      setError("");
      setNotice("");

      setStatus(
        normalized.acquisitionHash
          ? STATUS.READY
          : STATUS.IDLE
      );

      setCurrentStep(
        STEPS.EXAMINATION
      );
    },
    [busy]
  );

  /* ==========================================================================
     ACQUIRE EVIDENCE
     ========================================================================== */

  const acquireEvidence =
    useCallback(
      async (file) => {
        if (!file) return;

        setBusy(true);
        setError("");
        setNotice("");
        setStatus(
          STATUS.ACQUIRING
        );

        setProgressMessage(
          "Uploading evidence and establishing SHA-256 acquisition baseline..."
        );

        setIntegrity(null);
        setRecoveredFiles([]);
        setScanStats(null);
        setReport(null);
        setReportFile(null);
        setScanOutput("");
        setLastOperation(null);

        try {
          if (
            file.size >
            MAX_FILE_SIZE
          ) {
            throw new Error(
              "Evidence file exceeds the maximum supported size of 5 GB."
            );
          }

          if (file.size === 0) {
            throw new Error(
              "Empty evidence files are not accepted."
            );
          }

          const formData =
            new FormData();

          formData.append(
            "evidence",
            file,
            file.name
          );

          const response =
            await fetch(
              apiUrl(
                "/api/forensic/upload"
              ),
              {
                method: "POST",
                headers:
                  authHeaders(),
                body: formData,
              }
            );

          const result =
            await parseResponse(
              response
            );

          const acquired =
            normalizeEvidence(
              result?.evidence ||
                result?.data?.evidence ||
                result?.data ||
                result
            );

          if (!acquired) {
            throw new Error(
              "Server returned invalid evidence acquisition data."
            );
          }

          setSelectedEvidence(
            acquired
          );

          if (
            !acquired.acquisitionHash
          ) {
            setStatus(
              STATUS.FAILED
            );

            setError(
              "Evidence was uploaded, but no acquisition SHA-256 baseline was returned."
            );
          } else {
            setStatus(
              STATUS.READY
            );

            setNotice(
              result?.message ||
                "Evidence acquired successfully. Continue to integrity verification."
            );
          }

          await loadEvidence();

          if (currentCase) {
            const updatedCase = {
              ...currentCase,
              evidenceCount:
                Number(
                  currentCase.evidenceCount ||
                    0
                ) + 1,
            };

            setCurrentCase(
              updatedCase
            );

            persistCase(
              updatedCase
            );
          }

          setCurrentStep(
            STEPS.EXAMINATION
          );
        } catch (err) {
          setStatus(
            STATUS.FAILED
          );

          setError(
            err.message ||
              "Evidence acquisition failed."
          );
        } finally {
          setBusy(false);
          setProgressMessage("");
        }
      },
      [
        loadEvidence,
        currentCase,
        persistCase,
      ]
    );

  const handleFileChange =
    useCallback(
      async (event) => {
        const file =
          event.target.files?.[0];

        event.target.value = "";

        if (file) {
          await acquireEvidence(
            file
          );
        }
      },
      [acquireEvidence]
    );

  /* ==========================================================================
     VERIFY INTEGRITY
     ========================================================================== */

  const verifyIntegrity =
    useCallback(async () => {
      if (!selectedEvidence) {
        setError(
          "Select evidence first."
        );
        return false;
      }

      setBusy(true);
      setError("");
      setNotice("");

      setStatus(
        STATUS.VERIFYING
      );

      setProgressMessage(
        "Calculating current SHA-256 and comparing it with the acquisition baseline..."
      );

      try {
        const response =
          await apiFetch(
            "/api/forensic/verify-integrity",
            {
              method: "POST",

              headers: {
                "Content-Type":
                  "application/json",
              },

              body: JSON.stringify({
                evidenceId:
                  selectedEvidenceId,

                evidence_id:
                  selectedEvidenceId,

                fileName:
                  selectedFileName,

                file_name:
                  selectedFileName,
              }),
            }
          );

        const result =
          normalizeIntegrity(
            response?.integrity ||
              response?.data?.integrity ||
              response?.data ||
              response
          );

        if (!result) {
          throw new Error(
            "Server returned no integrity verification result."
          );
        }

        setIntegrity(result);

        const verified =
          result.status ===
            INTEGRITY.VERIFIED &&
          result.verified === true &&
          result.hashMatch === true &&
          result.sizeMatch === true;

        if (verified) {
          setStatus(
            STATUS.READY
          );

          setNotice(
            "Evidence integrity VERIFIED. Forensic analysis is now unlocked."
          );

          return true;
        }

        setStatus(
          STATUS.FAILED
        );

        setError(
          result.message ||
            "Evidence integrity verification failed."
        );

        return false;
      } catch (err) {
        setStatus(
          STATUS.FAILED
        );

        setError(
          err.message ||
            "Integrity verification failed."
        );

        return false;
      } finally {
        setBusy(false);
        setProgressMessage("");
      }
    }, [
      selectedEvidence,
      selectedEvidenceId,
      selectedFileName,
    ]);

  /* ==========================================================================
     FORENSIC SCAN
     ========================================================================== */

  const runForensicScan =
    useCallback(
      async (mode = "recover") => {
        if (!selectedEvidence) {
          setError(
            "Select evidence before starting analysis."
          );
          return;
        }

        if (!integrityVerified) {
          setError(
            "Analysis is blocked until evidence integrity is VERIFIED."
          );
          return;
        }

        if (!engine.available) {
          setError(
            "The Python forensic engine is unavailable."
          );
          return;
        }

        if (!caseId.trim()) {
          setError(
            "Case ID is required."
          );
          return;
        }

        if (!examiner.trim()) {
          setError(
            "Examiner name is required."
          );
          return;
        }

        setBusy(true);
        setError("");
        setNotice("");

        setStatus(
          STATUS.SCANNING
        );

        setAnalysisMode(
          mode
        );

        setRecoveredFiles([]);
        setScanStats(null);
        setReport(null);
        setReportFile(null);
        setScanOutput("");
        setLastOperation(null);

        const messages = {
          scan:
            "Scanning the evidence image and discovering forensic signatures...",

          recover:
            "Scanning verified evidence, carving candidate ranges and validating recovered artifacts...",

          analyze:
            "Performing forensic analysis of the verified evidence image...",
        };

        setProgressMessage(
          messages[mode] ||
            messages.recover
        );

        const started =
          performance.now();

        try {
          const response =
            await apiFetch(
              "/api/forensic/scan",
              {
                method: "POST",

                headers: {
                  "Content-Type":
                    "application/json",
                },

                body: JSON.stringify({
                  evidenceId:
                    selectedEvidenceId,

                  evidence_id:
                    selectedEvidenceId,

                  fileName:
                    selectedFileName,

                  file_name:
                    selectedFileName,

                  caseId:
                    caseId.trim(),

                  case_id:
                    caseId.trim(),

                  examiner:
                    examiner.trim(),

                  operation:
                    mode,
                }),
              }
            );

          const duration =
            Math.round(
              performance.now() -
                started
            );

          const stats =
            response?.scanStats ||
            response?.scan_stats ||
            response?.statistics ||
            response?.stats ||
            response?.data?.scanStats ||
            response?.data?.scan_stats ||
            {};

          const durationMs =
            response?.durationMs ??
            response?.duration_ms ??
            stats?.durationMs ??
            stats?.duration_ms ??
            duration;

          setLastScanDuration(
            durationMs
          );

          setScanStats({
            evidenceSize:
              stats?.evidenceSize ??
              stats?.evidence_size ??
              selectedEvidence.size,

            chunkSize:
              stats?.chunkSize ??
              stats?.chunk_size ??
              null,

            overlapSize:
              stats?.overlapSize ??
              stats?.overlap_size ??
              null,

            chunksScanned:
              stats?.chunksScanned ??
              stats?.chunks_scanned ??
              null,

            bytesScanned:
              stats?.bytesScanned ??
              stats?.bytes_scanned ??
              null,

            signaturesDetected:
              stats?.signaturesDetected ??
              stats?.signatures_detected ??
              response?.signaturesDetected ??
              response?.signatures_detected ??
              0,

            candidatesFound:
              stats?.candidatesFound ??
              stats?.candidates_found ??
              response?.candidateCount ??
              response?.candidate_count ??
              stats?.candidateRanges ??
              stats?.candidate_ranges ??
              0,

            artifactsCarved:
              stats?.artifactsCarved ??
              stats?.artifacts_carved ??
              0,

            artifactsValidated:
              stats?.artifactsValidated ??
              stats?.artifacts_validated ??
              response?.validatedCount ??
              response?.validated_count ??
              0,

            durationMs,

            status:
              stats?.status ||
              response?.scanStatus ||
              response?.scan_status ||
              "COMPLETED",
          });

          const rawRecovered =
            response?.recoveredFiles ||
            response?.recovered_files ||
            response?.artifacts ||
            response?.data?.recoveredFiles ||
            response?.data?.recovered_files ||
            response?.data?.artifacts ||
            [];

          const normalizedRecovered =
            (
              Array.isArray(
                rawRecovered
              )
                ? rawRecovered
                : []
            )
              .map(
                normalizeRecoveredFile
              )
              .filter(Boolean);

          setRecoveredFiles(
            normalizedRecovered
          );

          setScanOutput(
            response?.output ||
              response?.stdout ||
              response?.consoleOutput ||
              response?.console_output ||
              response?.data?.output ||
              ""
          );

          /* --------------------------------------------------------------
             POST-SCAN INTEGRITY
             -------------------------------------------------------------- */

          const postScanIntegrity =
            response?.integrity ||
            response?.postScanIntegrity ||
            response?.post_scan_integrity ||
            response?.data?.integrity ||
            response?.data?.postScanIntegrity ||
            response?.data?.post_scan_integrity;

          const postScan =
            normalizeIntegrity(
              postScanIntegrity
            );

          if (postScan) {
            setIntegrity(
              postScan
            );

            if (
              postScan.status !==
                INTEGRITY.VERIFIED ||
              postScan.verified !==
                true ||
              postScan.hashMatch !==
                true ||
              postScan.sizeMatch !==
                true
            ) {
              setStatus(
                STATUS.FAILED
              );

              setError(
                "Evidence integrity changed or could not be verified after forensic processing."
              );

              return;
            }
          }

          const finalCaseId =
            response?.caseId ||
            response?.case_id ||
            caseId.trim();

          const finalExaminer =
            response?.examiner ||
            examiner.trim();

          setLastOperation({
            caseId:
              finalCaseId,

            examiner:
              finalExaminer,

            operation:
              mode,

            completedAt:
              new Date().toISOString(),
          });

          setStatus(
            STATUS.COMPLETED
          );

          const validatedCount =
            response?.validatedCount ??
            response?.validated_count ??
            stats?.artifactsValidated ??
            stats?.artifacts_validated ??
            normalizedRecovered.length;

          const candidateCount =
            response?.candidateCount ??
            response?.candidate_count ??
            stats?.candidatesFound ??
            stats?.candidates_found ??
            stats?.candidateRanges ??
            stats?.candidate_ranges ??
            0;

          setNotice(
            response?.message ||
              `Forensic processing completed. ${candidateCount} candidate range(s) identified and ${validatedCount} artifact(s) validated.`
          );

          setCurrentStep(
            STEPS.RESULTS
          );
        } catch (err) {
          setStatus(
            STATUS.FAILED
          );

          const serverIntegrity =
            err.response?.integrity ||
            err.response?.data?.integrity;

          if (serverIntegrity) {
            setIntegrity(
              normalizeIntegrity(
                serverIntegrity
              )
            );
          }

          setError(
            err.message ||
              "Forensic processing failed."
          );
        } finally {
          setBusy(false);
          setProgressMessage("");
        }
      },
      [
        selectedEvidence,
        selectedEvidenceId,
        selectedFileName,
        integrityVerified,
        engine.available,
        caseId,
        examiner,
      ]
    );

  /* ==========================================================================
     REPORT
     ========================================================================== */

  const generateReport =
    useCallback(async () => {
      if (!selectedEvidence) {
        setError(
          "Select evidence first."
        );
        return;
      }

      if (!integrityVerified) {
        setError(
          "Report generation requires VERIFIED evidence."
        );
        return;
      }

      if (!caseId.trim()) {
        setError(
          "Case ID is required."
        );
        return;
      }

      if (!examiner.trim()) {
        setError(
          "Examiner name is required."
        );
        return;
      }

      setBusy(true);
      setError("");
      setNotice("");

      setProgressMessage(
        "Generating the forensic case report and evidence audit record..."
      );

      try {
        const response =
          await apiFetch(
            "/api/forensic/report",
            {
              method: "POST",

              headers: {
                "Content-Type":
                  "application/json",
              },

              body: JSON.stringify({
                evidenceId:
                  selectedEvidenceId,

                evidence_id:
                  selectedEvidenceId,

                fileName:
                  selectedFileName,

                file_name:
                  selectedFileName,

                caseId:
                  caseId.trim(),

                case_id:
                  caseId.trim(),

                examiner:
                  examiner.trim(),
              }),
            }
          );

        const generatedReport =
          response?.report ||
          response?.data?.report ||
          response?.data ||
          null;

        if (
          !generatedReport ||
          typeof generatedReport !==
            "object"
        ) {
          throw new Error(
            "Report generation returned no report data."
          );
        }

        setReport(
          generatedReport
        );

        const generatedReportFile =
          response?.reportFile ||
          response?.report_file ||
          response?.downloadPath ||
          response?.download_path ||
          response?.data?.reportFile ||
          response?.data?.report_file ||
          generatedReport?.reportFile ||
          generatedReport?.report_file ||
          generatedReport?.downloadPath ||
          generatedReport?.download_path ||
          null;

        setReportFile(
          generatedReportFile
        );

        if (
          generatedReport.integrity
        ) {
          const normalized =
            normalizeIntegrity(
              generatedReport.integrity
            );

          if (normalized) {
            setIntegrity(
              normalized
            );

            if (
              normalized.status !==
                INTEGRITY.VERIFIED ||
              normalized.verified !==
                true ||
              normalized.hashMatch !==
                true ||
              normalized.sizeMatch !==
                true
            ) {
              setStatus(
                STATUS.FAILED
              );

              setError(
                "The generated report indicates that evidence integrity is not VERIFIED."
              );

              return;
            }
          }
        }

        setStatus(
          STATUS.COMPLETED
        );

        setNotice(
          response?.message ||
            "Forensic evidence report generated successfully."
        );

        setCurrentStep(
          STEPS.REPORT
        );
      } catch (err) {
        setError(
          err.message ||
            "Unable to generate forensic report."
        );
      } finally {
        setBusy(false);
        setProgressMessage("");
      }
    }, [
      selectedEvidence,
      selectedEvidenceId,
      selectedFileName,
      integrityVerified,
      caseId,
      examiner,
    ]);

  /* ==========================================================================
     DOWNLOAD RECOVERED ARTIFACT
     ========================================================================== */

  const downloadRecoveredFile =
    useCallback(
      (file) => {
        if (!file?.path) {
          setError(
            "This artifact has no download path."
          );
          return;
        }

        window.open(
          apiUrl(file.path),
          "_blank",
          "noopener,noreferrer"
        );
      },
      []
    );

  /* ==========================================================================
     DOWNLOAD REPORT
     ========================================================================== */

  const downloadReport =
    useCallback(() => {
      if (!reportFile) {
        setError(
          "No report file is available."
        );
        return;
      }

      const reportPath =
        String(reportFile);

      const url =
        reportPath.startsWith(
          "/api/"
        )
          ? reportPath
          : `/api/forensic/report/${encodeURIComponent(
              reportPath
            )}`;

      window.open(
        apiUrl(url),
        "_blank",
        "noopener,noreferrer"
      );
    }, [reportFile]);

  /* ==========================================================================
     RESET CASE WORKSPACE
     ========================================================================== */

  const resetWorkspace =
    useCallback(() => {
      if (busy) return;

      setSelectedEvidence(null);
      setIntegrity(null);
      setRecoveredFiles([]);
      setScanStats(null);
      setReport(null);
      setReportFile(null);
      setScanOutput("");
      setLastScanDuration(null);
      setLastOperation(null);
      setAnalysisMode(null);

      setError("");
      setNotice("");

      setStatus(
        STATUS.IDLE
      );

      setCurrentCase(null);

      setCaseId("");
      setCaseTitle("");
      setCaseDescription("");
      setExaminer("");

      setCurrentStep(
        STEPS.CASES
      );
    }, [busy]);

  /* ==========================================================================
     NAVIGATION
     ========================================================================== */

  const goBack = useCallback(() => {
    if (busy) return;

    setError("");
    setNotice("");

    switch (currentStep) {
      case STEPS.CREATE_CASE:
        setCurrentStep(
          STEPS.CASES
        );
        break;

      case STEPS.EVIDENCE:
        setCurrentStep(
          STEPS.CASES
        );
        break;

      case STEPS.EXAMINATION:
        setCurrentStep(
          STEPS.EVIDENCE
        );
        break;

      case STEPS.ANALYSIS:
        setCurrentStep(
          STEPS.EXAMINATION
        );
        break;

      case STEPS.RESULTS:
        setCurrentStep(
          STEPS.ANALYSIS
        );
        break;

      case STEPS.REPORT:
        setCurrentStep(
          STEPS.RESULTS
        );
        break;

      default:
        setCurrentStep(
          STEPS.CASES
        );
    }
  }, [
    currentStep,
    busy,
  ]);

  /* ==========================================================================
     STEP DEFINITIONS
     ========================================================================== */

  const stepItems = [
    {
      key: STEPS.CASES,
      label: "Case",
    },
    {
      key: STEPS.EVIDENCE,
      label: "Evidence",
    },
    {
      key: STEPS.EXAMINATION,
      label: "Examination",
    },
    {
      key: STEPS.ANALYSIS,
      label: "Analysis",
    },
    {
      key: STEPS.RESULTS,
      label: "Results",
    },
    {
      key: STEPS.REPORT,
      label: "Report",
    },
  ];

  const currentStepIndex =
    Math.max(
      0,
      stepItems.findIndex(
        (item) =>
          item.key ===
          currentStep
      )
    );

  /* ==========================================================================
     RENDER HELPERS
     ========================================================================== */

  const renderHeader = () => (
    <header className="forensics-header">
      <div>
        <div className="forensics-eyebrow">
          SECURITY OPERATIONS CENTER
        </div>

        <h1>
          TrustWipe Digital Forensics
        </h1>

        <p>
          Authorized evidence acquisition,
          integrity verification, forensic
          recovery and evidence reporting.
        </p>
      </div>

      <div className="engine-status">
        <span
          className={
            engine.available
              ? "status-dot online"
              : "status-dot offline"
          }
        />

        <div>
          <strong>
            {engine.available
              ? "FORENSIC ENGINE ONLINE"
              : "FORENSIC ENGINE OFFLINE"}
          </strong>

          <small>
            {engine.version ||
              engine.message}
          </small>
        </div>

        <button
          type="button"
          className="secondary-button"
          onClick={
            loadEngineStatus
          }
          disabled={busy}
        >
          Refresh
        </button>
      </div>
    </header>
  );

  const renderAlerts = () => (
    <>
      {error && (
        <div
          className="forensics-alert danger"
          role="alert"
        >
          <strong>
            Forensic operation failed
          </strong>

          <span>{error}</span>
        </div>
      )}

      {notice && !error && (
        <div
          className="forensics-alert success"
          role="status"
        >
          <strong>
            Operation completed
          </strong>

          <span>{notice}</span>
        </div>
      )}

      {progressMessage && (
        <div className="operation-progress">
          <span className="spinner" />

          <span>
            {progressMessage}
          </span>
        </div>
      )}
    </>
  );

  const renderProgress = () => (
    <div className="forensics-workflow">
      {stepItems.map(
        (item, index) => {
          const completed =
            index <
            currentStepIndex;

          const active =
            item.key ===
            currentStep;

          return (
            <button
              type="button"
              key={item.key}
              className={[
                "workflow-step",
                active
                  ? "active"
                  : "",
                completed
                  ? "completed"
                  : "",
              ]
                .join(" ")
                .trim()}
              onClick={() => {
                if (
                  busy ||
                  index >
                    currentStepIndex
                ) {
                  return;
                }

                setCurrentStep(
                  item.key
                );
              }}
              disabled={
                busy ||
                index >
                  currentStepIndex
              }
            >
              <span className="workflow-number">
                {completed
                  ? "✓"
                  : index + 1}
              </span>

              <span>
                {item.label}
              </span>
            </button>
          );
        }
      )}
    </div>
  );

  /* ==========================================================================
     CASE SELECTION
     ========================================================================== */

  const renderCaseSelection = () => (
    <section className="forensics-panel">
      <div className="panel-header">
        <div>
          <span className="panel-kicker">
            FORENSIC CASE MANAGEMENT
          </span>

          <h2>
            Select Investigation
          </h2>

          <p>
            Create a new forensic case or
            continue an existing investigation.
          </p>
        </div>
      </div>

      <div className="case-selection-grid">
        <button
          type="button"
          className="case-action-card"
          onClick={
            startNewCaseScreen
          }
          disabled={busy}
        >
          <div className="case-action-icon">
            +
          </div>

          <strong>
            Create New Case
          </strong>

          <span>
            Start a new authorized forensic
            investigation.
          </span>

          <small>
            Generate case ID →
          </small>
        </button>

        <div className="case-action-card existing">
          <div className="case-action-icon">
            ▣
          </div>

          <strong>
            Existing Cases
          </strong>

          <span>
            Continue an investigation from the
            case repository.
          </span>

          <small>
            {cases.length} saved case
            {cases.length === 1
              ? ""
              : "s"}
          </small>
        </div>
      </div>

      <div className="case-list-section">
        <div className="repository-header">
          <div>
            <strong>
              CASE REPOSITORY
            </strong>

            <span>
              {cases.length} Cases
            </span>
          </div>
        </div>

        {cases.length === 0 ? (
          <div className="empty-state">
            No forensic cases have been
            created yet.
          </div>
        ) : (
          <div className="case-list">
            {cases.map((item) => (
              <button
                type="button"
                key={item.caseId}
                className="case-list-item"
                onClick={() =>
                  openExistingCase(
                    item
                  )
                }
                disabled={busy}
              >
                <div className="case-id">
                  {item.caseId}
                </div>

                <div className="case-details">
                  <strong>
                    {item.title ||
                      "Untitled Investigation"}
                  </strong>

                  <span>
                    Examiner:{" "}
                    {item.examiner ||
                      "—"}
                  </span>

                  <span>
                    Created:{" "}
                    {formatDate(
                      item.createdAt
                    )}
                  </span>
                </div>

                <div className="case-meta">
                  <span className="state-badge ready">
                    {item.status ||
                      "OPEN"}
                  </span>

                  <span>
                    {item.evidenceCount ||
                      0}{" "}
                    evidence
                  </span>
                </div>
              </button>
            ))}
          </div>
        )}
      </div>
    </section>
  );

  /* ==========================================================================
     CREATE CASE
     ========================================================================== */

  const renderCreateCase = () => (
    <section className="forensics-panel">
      <div className="panel-header">
        <div>
          <span className="panel-kicker">
            STEP 01 • CASE CREATION
          </span>

          <h2>
            Create New Forensic Case
          </h2>

          <p>
            Establish the investigation identity
            before acquiring evidence.
          </p>
        </div>
      </div>

      <div className="case-form">
        <div className="form-field">
          <label>
            Case ID
          </label>

          <input
            type="text"
            value={caseId}
            onChange={(event) =>
              setCaseId(
                event.target.value
              )
            }
            placeholder="CASE-2026-XXXX"
          />

          <small>
            Unique identifier for the forensic
            investigation.
          </small>
        </div>

        <div className="form-field">
          <label>
            Case Title
          </label>

          <input
            type="text"
            value={caseTitle}
            onChange={(event) =>
              setCaseTitle(
                event.target.value
              )
            }
            placeholder="Enterprise Evidence Investigation"
          />
        </div>

        <div className="form-field">
          <label>
            Examiner
          </label>

          <input
            type="text"
            value={examiner}
            onChange={(event) =>
              setExaminer(
                event.target.value
              )
            }
            placeholder="Authorized forensic examiner"
          />
        </div>

        <div className="form-field full">
          <label>
            Case Description
          </label>

          <textarea
            value={
              caseDescription
            }
            onChange={(event) =>
              setCaseDescription(
                event.target.value
              )
            }
            rows={4}
            placeholder="Investigation purpose, scope and authorization details..."
          />
        </div>
      </div>

      <div className="action-row">
        <button
          type="button"
          className="secondary-button"
          onClick={goBack}
          disabled={busy}
        >
          ← Back
        </button>

        <button
          type="button"
          className="primary-button"
          onClick={
            createCase
          }
          disabled={busy}
        >
          CREATE CASE →
        </button>
      </div>
    </section>
  );

  /* ==========================================================================
     EVIDENCE ACQUISITION
     ========================================================================== */

  const renderEvidenceAcquisition =
    () => (
      <>
        <section className="forensics-panel">
          <div className="panel-header">
            <div>
              <span className="panel-kicker">
                STEP 02 • EVIDENCE ACQUISITION
              </span>

              <h2>
                Acquire Evidence
              </h2>

              <p>
                Evidence is copied into the
                forensic repository and assigned
                an acquisition SHA-256 baseline.
              </p>
            </div>

            <span className="secure-badge">
              AUTHORIZED
            </span>
          </div>

          <div className="case-context">
            <div>
              <span>
                CASE
              </span>

              <strong>
                {caseId ||
                  "Not selected"}
              </strong>
            </div>

            <div>
              <span>
                EXAMINER
              </span>

              <strong>
                {examiner ||
                  "Not assigned"}
              </strong>
            </div>
          </div>

          <input
            ref={fileInputRef}
            type="file"
            hidden
            onChange={
              handleFileChange
            }
            disabled={busy}
          />

          <button
            type="button"
            className="upload-zone"
            onClick={() =>
              fileInputRef.current?.click()
            }
            disabled={busy}
          >
            <span className="upload-icon">
              ↑
            </span>

            <strong>
              Select Evidence File
            </strong>

            <small>
              Maximum supported size: 5 GB
            </small>

            <span className="browse-button">
              BROWSE EVIDENCE
            </span>
          </button>
        </section>

        <section className="forensics-panel">
          <div className="repository-header">
            <div>
              <strong>
                EVIDENCE REPOSITORY
              </strong>

              <span>
                {evidence.length} Assets •{" "}
                {formatBytes(
                  repositoryStats.totalSize
                )}
              </span>
            </div>

            <button
              type="button"
              className="icon-button"
              onClick={
                loadEvidence
              }
              disabled={busy}
              title="Refresh evidence"
            >
              ↻
            </button>
          </div>

          <div className="evidence-list">
            {evidence.length === 0 ? (
              <div className="empty-state">
                No evidence has been
                acquired.
              </div>
            ) : (
              evidence.map(
                (item) => {
                  const selected =
                    item.evidenceId &&
                    selectedEvidenceId
                      ? item.evidenceId ===
                        selectedEvidenceId
                      : item.name ===
                        selectedFileName;

                  return (
                    <button
                      type="button"
                      key={
                        item.evidenceId ||
                        item.id
                      }
                      className={
                        selected
                          ? "evidence-item selected"
                          : "evidence-item"
                      }
                      onClick={() =>
                        selectEvidence(
                          item
                        )
                      }
                      disabled={busy}
                    >
                      <div className="evidence-type">
                        {getFileType(
                          item.name
                        )}
                      </div>

                      <div className="evidence-details">
                        <strong>
                          {item.name}
                        </strong>

                        <small>
                          {formatBytes(
                            item.size
                          )}{" "}
                          •{" "}
                          {item.type}
                        </small>

                        {item.evidenceId && (
                          <small>
                            {
                              item.evidenceId
                            }
                          </small>
                        )}
                      </div>

                      <div className="evidence-state">
                        {item.acquisitionHash ? (
                          <span className="mini-verified">
                            ✓
                          </span>
                        ) : (
                          <span className="mini-warning">
                            !
                          </span>
                        )}
                      </div>
                    </button>
                  );
                }
              )
            )}
          </div>
        </section>

        <div className="action-row">
          <button
            type="button"
            className="secondary-button"
            onClick={goBack}
            disabled={busy}
          >
            ← Case Selection
          </button>
        </div>
      </>
    );

  /* ==========================================================================
     EXAMINATION
     ========================================================================== */

  const renderExamination =
    () => (
      <section className="forensics-panel">
        <div className="panel-header">
          <div>
            <span className="panel-kicker">
              STEP 03 • EXAMINATION
            </span>

            <h2>
              Evidence Examination
            </h2>

            <p>
              Confirm the evidence identity and
              cryptographic integrity before
              forensic processing.
            </p>
          </div>

          <span
            className={`state-badge ${status.toLowerCase()}`}
          >
            {status}
          </span>
        </div>

        {!selectedEvidence ? (
          <div className="empty-active-state">
            <div className="empty-icon">
              ◇
            </div>

            <h3>
              No evidence selected
            </h3>

            <p>
              Return to Evidence Acquisition
              and select an evidence asset.
            </p>

            <button
              type="button"
              className="secondary-button"
              onClick={() =>
                setCurrentStep(
                  STEPS.EVIDENCE
                )
              }
            >
              ← Select Evidence
            </button>
          </div>
        ) : (
          <>
            <div className="active-evidence-banner">
              <div>
                <span>
                  ACTIVE EVIDENCE
                </span>

                <strong>
                  {
                    selectedEvidence.name
                  }
                </strong>
              </div>

              <div>
                <span>
                  EVIDENCE ID
                </span>

                <strong>
                  {
                    selectedEvidence.evidenceId ||
                    "—"
                  }
                </strong>
              </div>
            </div>

            <div className="metadata-grid">
              <div>
                <span>
                  SIZE
                </span>

                <strong>
                  {formatBytes(
                    selectedEvidence.size
                  )}
                </strong>
              </div>

              <div>
                <span>
                  TYPE
                </span>

                <strong>
                  {
                    selectedEvidence.type
                  }
                </strong>
              </div>

              <div>
                <span>
                  ACQUIRED
                </span>

                <strong>
                  {formatDate(
                    selectedEvidence.acquiredAt
                  )}
                </strong>
              </div>

              <div>
                <span>
                  BASELINE
                </span>

                <strong>
                  {selectedEvidence.acquisitionHash
                    ? "SHA-256 PRESENT"
                    : "MISSING"}
                </strong>
              </div>
            </div>

            <div className="integrity-card">
              <div className="integrity-card-header">
                <div>
                  <span className="panel-kicker">
                    CRYPTOGRAPHIC INTEGRITY
                  </span>

                  <h3>
                    SHA-256 Verification
                  </h3>
                </div>

                <strong
                  className={
                    integrity
                      ? getIntegrityClass(
                          integrity.status
                        )
                      : ""
                  }
                >
                  {integrity?.status ||
                    "NOT VERIFIED"}
                </strong>
              </div>

              <div className="hash-grid">
                <div>
                  <span>
                    ACQUISITION SHA-256
                  </span>

                  <code>
                    {integrity?.originalHash ||
                      selectedEvidence.acquisitionHash ||
                      "—"}
                  </code>
                </div>

                <div>
                  <span>
                    CURRENT SHA-256
                  </span>

                  <code>
                    {integrity?.currentHash ||
                      "Not calculated"}
                  </code>
                </div>
              </div>

              {integrity && (
                <div className="integrity-checks">
                  <span
                    className={
                      integrity.hashMatch
                        ? "check-ok"
                        : "check-failed"
                    }
                  >
                    {integrity.hashMatch
                      ? "✓"
                      : "✕"}{" "}
                    HASH MATCH
                  </span>

                  <span
                    className={
                      integrity.sizeMatch
                        ? "check-ok"
                        : "check-failed"
                    }
                  >
                    {integrity.sizeMatch
                      ? "✓"
                      : "✕"}{" "}
                    SIZE MATCH
                  </span>

                  <span
                    className={
                      integrity.verified
                        ? "check-ok"
                        : "check-failed"
                    }
                  >
                    {integrity.verified
                      ? "✓"
                      : "✕"}{" "}
                    EVIDENCE VERIFIED
                  </span>
                </div>
              )}

              <div className="action-row">
                <button
                  type="button"
                  className="primary-button"
                  onClick={
                    verifyIntegrity
                  }
                  disabled={busy}
                >
                  {busy &&
                  status ===
                    STATUS.VERIFYING
                    ? "VERIFYING..."
                    : "CALCULATE & VERIFY SHA-256"}
                </button>
              </div>
            </div>

            <div className="action-row">
              <button
                type="button"
                className="secondary-button"
                onClick={goBack}
                disabled={busy}
              >
                ← Evidence
              </button>

              <button
                type="button"
                className="primary-button"
                onClick={() =>
                  setCurrentStep(
                    STEPS.ANALYSIS
                  )
                }
                disabled={
                  busy ||
                  !integrityVerified
                }
              >
                CONTINUE TO ANALYSIS →
              </button>
            </div>
          </>
        )}
      </section>
    );

  /* ==========================================================================
     ANALYSIS
     ========================================================================== */

  const renderAnalysis =
    () => (
      <section className="forensics-panel">
        <div className="panel-header">
          <div>
            <span className="panel-kicker">
              STEP 04 • FORENSIC ANALYSIS
            </span>

            <h2>
              Forensic Control Center
            </h2>

            <p>
              Process the verified evidence image
              using the TrustWipe forensic engine.
            </p>
          </div>

          <span className="secure-badge">
            INTEGRITY VERIFIED
          </span>
        </div>

        <div className="analysis-context">
          <div>
            <span>
              CASE
            </span>

            <strong>
              {caseId}
            </strong>
          </div>

          <div>
            <span>
              EVIDENCE
            </span>

            <strong>
              {selectedFileName}
            </strong>
          </div>

          <div>
            <span>
              ENGINE
            </span>

            <strong>
              {engine.available
                ? "ONLINE"
                : "OFFLINE"}
            </strong>
          </div>
        </div>

        <div className="analysis-actions">
          <button
            type="button"
            className="analysis-action-card"
            onClick={() =>
              runForensicScan(
                "scan"
              )
            }
            disabled={
              busy ||
              !integrityVerified ||
              !engine.available
            }
          >
            <span>
              ◉
            </span>

            <strong>
              Scan Disk
            </strong>

            <small>
              Stream-scan the evidence image and
              discover forensic signatures.
            </small>
          </button>

          <button
            type="button"
            className="analysis-action-card"
            onClick={() =>
              runForensicScan(
                "recover"
              )
            }
            disabled={
              busy ||
              !integrityVerified ||
              !engine.available
            }
          >
            <span>
              ⌁
            </span>

            <strong>
              Recover Files
            </strong>

            <small>
              Carve candidate ranges and validate
              recoverable artifacts.
            </small>
          </button>

          <button
            type="button"
            className="analysis-action-card"
            onClick={() =>
              runForensicScan(
                "analyze"
              )
            }
            disabled={
              busy ||
              !integrityVerified ||
              !engine.available
            }
          >
            <span>
              ◇
            </span>

            <strong>
              Analyze
            </strong>

            <small>
              Execute forensic processing and
              inspect scan and artifact results.
            </small>
          </button>
        </div>

        {!engine.available && (
          <div className="forensics-alert danger">
            <strong>
              Forensic Engine Offline
            </strong>

            <span>
              The Python forensic engine must be
              available before evidence processing
              can begin.
            </span>
          </div>
        )}

        <div className="forensic-policy-note">
          <strong>
            Evidence protection policy
          </strong>

          <span>
            Processing is permitted only after
            SHA-256 integrity verification.
            The evidence source must remain
            unchanged throughout examination.
          </span>
        </div>

        <div className="action-row">
          <button
            type="button"
            className="secondary-button"
            onClick={goBack}
            disabled={busy}
          >
            ← Examination
          </button>
        </div>
      </section>
    );

  /* ==========================================================================
     RESULTS
     ========================================================================== */

  const renderResults =
    () => (
      <>
        <section className="forensics-panel">
          <div className="panel-header">
            <div>
              <span className="panel-kicker">
                STEP 05 • RECOVERY RESULTS
              </span>

              <h2>
                Recovery & Analysis Results
              </h2>

              <p>
                Review discovered signatures,
                candidate ranges and validated
                forensic artifacts.
              </p>
            </div>

            <span
              className={`state-badge ${status.toLowerCase()}`}
            >
              {status}
            </span>
          </div>

          {scanStats && (
            <div className="scan-statistics">
              <div>
                <span>
                  EVIDENCE SIZE
                </span>

                <strong>
                  {formatBytes(
                    scanStats.evidenceSize
                  )}
                </strong>
              </div>

              <div>
                <span>
                  CHUNKS SCANNED
                </span>

                <strong>
                  {scanStats.chunksScanned ??
                    "—"}
                </strong>
              </div>

              <div>
                <span>
                  BYTES SCANNED
                </span>

                <strong>
                  {formatBytes(
                    scanStats.bytesScanned
                  )}
                </strong>
              </div>

              <div>
                <span>
                  SIGNATURES
                </span>

                <strong>
                  {
                    scanStats.signaturesDetected
                  }
                </strong>
              </div>

              <div>
                <span>
                  CANDIDATE RANGES
                </span>

                <strong>
                  {
                    scanStats.candidatesFound
                  }
                </strong>
              </div>

              <div>
                <span>
                  ARTIFACTS CARVED
                </span>

                <strong>
                  {
                    scanStats.artifactsCarved
                  }
                </strong>
              </div>

              <div>
                <span>
                  ARTIFACTS VALIDATED
                </span>

                <strong>
                  {
                    scanStats.artifactsValidated
                  }
                </strong>
              </div>

              <div>
                <span>
                  DURATION
                </span>

                <strong>
                  {formatDuration(
                    scanStats.durationMs
                  )}
                </strong>
              </div>
            </div>
          )}
        </section>

        <section className="forensics-panel">
          <div className="repository-header">
            <div>
              <strong>
                RECOVERED ARTIFACTS
              </strong>

              <span>
                {recoveredFiles.length} Artifacts •{" "}
                {validatedArtifacts} Validated
              </span>
            </div>
          </div>

          {recoveredFiles.length === 0 ? (
            <div className="empty-state">
              No recovered artifacts were
              returned by the forensic engine.
            </div>
          ) : (
            <div className="artifact-table-wrapper">
              <table className="artifact-table">
                <thead>
                  <tr>
                    <th>
                      Artifact
                    </th>

                    <th>
                      Type
                    </th>

                    <th>
                      Size
                    </th>

                    <th>
                      Validation
                    </th>

                    <th>
                      Confidence
                    </th>

                    <th>
                      SHA-256
                    </th>

                    <th>
                      Action
                    </th>
                  </tr>
                </thead>

                <tbody>
                  {recoveredFiles.map(
                    (file, index) => {
                      const valid =
                        String(
                          file.validationStatus
                        ).toUpperCase() ===
                        "VALID";

                      return (
                        <tr
                          key={
                            file.artifactId ||
                            `${file.name}-${index}`
                          }
                        >
                          <td>
                            <strong>
                              {
                                file.name
                              }
                            </strong>

                            {file.sourceOffset !==
                              null && (
                              <small>
                                Offset:{" "}
                                {
                                  file.sourceOffset
                                }
                              </small>
                            )}
                          </td>

                          <td>
                            {
                              file.type
                            }
                          </td>

                          <td>
                            {formatBytes(
                              file.size
                            )}
                          </td>

                          <td>
                            <span
                              className={
                                valid
                                  ? "check-ok"
                                  : "check-failed"
                              }
                            >
                              {valid
                                ? "✓ VALID"
                                : "⚠ " +
                                  file.validationStatus}
                            </span>
                          </td>

                          <td>
                            {file.confidence ??
                              "—"}
                          </td>

                          <td>
                            <code>
                              {file.sha256
                                ? `${file.sha256.slice(
                                    0,
                                    12
                                  )}...`
                                : "—"}
                            </code>
                          </td>

                          <td>
                            <button
                              type="button"
                              className="secondary-button small"
                              onClick={() =>
                                downloadRecoveredFile(
                                  file
                                )
                              }
                              disabled={
                                !file.path
                              }
                            >
                              EXPORT
                            </button>
                          </td>
                        </tr>
                      );
                    }
                  )}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {scanOutput && (
          <section className="forensics-panel">
            <div className="panel-header">
              <div>
                <span className="panel-kicker">
                  ENGINE CONSOLE
                </span>

                <h2>
                  Forensic Processing Output
                </h2>
              </div>
            </div>

            <pre className="forensic-console">
              {scanOutput}
            </pre>
          </section>
        )}

        <section className="forensics-panel">
          <div className="integrity-card">
            <div className="integrity-card-header">
              <div>
                <span className="panel-kicker">
                  POST-PROCESSING INTEGRITY
                </span>

                <h3>
                  Evidence Integrity
                </h3>
              </div>

              <strong
                className={
                  integrity
                    ? getIntegrityClass(
                        integrity.status
                      )
                    : ""
                }
              >
                {integrity?.status ||
                  "NOT VERIFIED"}
              </strong>
            </div>

            <div className="hash-grid">
              <div>
                <span>
                  ACQUISITION HASH
                </span>

                <code>
                  {integrity?.originalHash ||
                    selectedEvidence?.acquisitionHash ||
                    "—"}
                </code>
              </div>

              <div>
                <span>
                  CURRENT HASH
                </span>

                <code>
                  {integrity?.currentHash ||
                    "—"}
                </code>
              </div>
            </div>
          </div>
        </section>

        <div className="action-row">
          <button
            type="button"
            className="secondary-button"
            onClick={goBack}
            disabled={busy}
          >
            ← Analysis
          </button>

          <button
            type="button"
            className="primary-button"
            onClick={
              generateReport
            }
            disabled={
              busy ||
              !integrityVerified
            }
          >
            GENERATE FORENSIC REPORT →
          </button>
        </div>
      </>
    );

  /* ==========================================================================
     REPORT
     ========================================================================== */

  const renderReport =
    () => (
      <>
        <section className="forensics-panel">
          <div className="panel-header">
            <div>
              <span className="panel-kicker">
                STEP 06 • CASE REPORT
              </span>

              <h2>
                Forensic Case Report
              </h2>

              <p>
                Final investigation record containing
                case identity, evidence integrity,
                examination results and recovered
                artifacts.
              </p>
            </div>

            <span className="secure-badge">
              VERIFIED
            </span>
          </div>

          <div className="report-summary-grid">
            <div>
              <span>
                CASE ID
              </span>

              <strong>
                {caseId}
              </strong>
            </div>

            <div>
              <span>
                EXAMINER
              </span>

              <strong>
                {examiner}
              </strong>
            </div>

            <div>
              <span>
                EVIDENCE
              </span>

              <strong>
                {selectedFileName}
              </strong>
            </div>

            <div>
              <span>
                INTEGRITY
              </span>

              <strong
                className={
                  getIntegrityClass(
                    integrity?.status
                  )
                }
              >
                {integrity?.status ||
                  "UNKNOWN"}
              </strong>
            </div>
          </div>
        </section>

        {report && (
          <section className="forensics-panel">
            <div className="repository-header">
              <div>
                <strong>
                  REPORT DATA
                </strong>

                <span>
                  Generated{" "}
                  {formatDate(
                    report.generatedAt ||
                      report.generated_at ||
                      new Date()
                  )}
                </span>
              </div>
            </div>

            <pre className="forensic-report-json">
              {JSON.stringify(
                report,
                null,
                2
              )}
            </pre>
          </section>
        )}

        <section className="forensics-panel">
          <div className="report-integrity">
            <div>
              <span>
                ACQUISITION SHA-256
              </span>

              <code>
                {integrity?.originalHash ||
                  selectedEvidence?.acquisitionHash ||
                  "—"}
              </code>
            </div>

            <div>
              <span>
                CURRENT SHA-256
              </span>

              <code>
                {integrity?.currentHash ||
                  "—"}
              </code>
            </div>

            <div>
              <span>
                VALIDATED ARTIFACTS
              </span>

              <strong>
                {validatedArtifacts}
              </strong>
            </div>
          </div>

          <div className="action-row">
            <button
              type="button"
              className="primary-button"
              onClick={
                downloadReport
              }
              disabled={
                !reportFile
              }
            >
              EXPORT CASE REPORT
            </button>

            <button
              type="button"
              className="secondary-button"
              onClick={
                resetWorkspace
              }
              disabled={busy}
            >
              CLOSE CASE
            </button>
          </div>

          {!reportFile && (
            <div className="forensic-policy-note">
              <strong>
                Report generated
              </strong>

              <span>
                The backend returned report data,
                but no downloadable report file path
                was provided.
              </span>
            </div>
          )}
        </section>
      </>
    );

  /* ==========================================================================
     MAIN RENDER
     ========================================================================== */

  return (
    <div className="forensics-page">
      {renderHeader()}

      {renderAlerts()}

      {currentStep !==
        STEPS.CASES &&
        currentStep !==
          STEPS.CREATE_CASE &&
        renderProgress()}

      <section className="forensics-summary">
        <div className="summary-card">
          <span>
            CASE
          </span>

          <strong>
            {caseId || "—"}
          </strong>

          <small>
            {currentCase?.title ||
              "No active case"}
          </small>
        </div>

        <div className="summary-card">
          <span>
            EVIDENCE ASSETS
          </span>

          <strong>
            {repositoryStats.total}
          </strong>

          <small>
            {formatBytes(
              repositoryStats.totalSize
            )}{" "}
            total
          </small>
        </div>

        <div className="summary-card">
          <span>
            INTEGRITY
          </span>

          <strong
            className={
              integrity
                ? getIntegrityClass(
                    integrity.status
                  )
                : ""
            }
          >
            {integrity?.status ||
              "NOT VERIFIED"}
          </strong>

          <small>
            SHA-256 evidence control
          </small>
        </div>

        <div className="summary-card">
          <span>
            FORENSIC ENGINE
          </span>

          <strong>
            {engine.available
              ? "READY"
              : "OFFLINE"}
          </strong>

          <small>
            Python recovery engine
          </small>
        </div>
      </section>

      <main className="forensics-content">
        {currentStep ===
          STEPS.CASES &&
          renderCaseSelection()}

        {currentStep ===
          STEPS.CREATE_CASE &&
          renderCreateCase()}

        {currentStep ===
          STEPS.EVIDENCE &&
          renderEvidenceAcquisition()}

        {currentStep ===
          STEPS.EXAMINATION &&
          renderExamination()}

        {currentStep ===
          STEPS.ANALYSIS &&
          renderAnalysis()}

        {currentStep ===
          STEPS.RESULTS &&
          renderResults()}

        {currentStep ===
          STEPS.REPORT &&
          renderReport()}
      </main>

      <footer className="forensics-footer">
        <span>
          TrustWipe Digital Forensics
        </span>

        <span>
          SHA-256 Integrity Control
        </span>

        <span>
          {engine.available
            ? "Forensic Engine Online"
            : "Forensic Engine Offline"}
        </span>
      </footer>
    </div>
  );
}