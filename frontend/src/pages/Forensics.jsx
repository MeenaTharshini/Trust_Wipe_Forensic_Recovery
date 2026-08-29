import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import "./Forensics.css";

const API_BASE =
  import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, "") || "";

const MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024;

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

/* ==========================================================================
   API HELPERS
   ========================================================================== */

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

/* ==========================================================================
   GENERAL HELPERS
   ========================================================================== */

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

  return `${(value / 1000).toFixed(2)} s`;
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

/* ==========================================================================
   NORMALIZERS
   ========================================================================== */

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

/* ==========================================================================
   COMPONENT
   ========================================================================== */

export default function Forensics() {
  const fileInputRef = useRef(null);

  const [status, setStatus] = useState(STATUS.IDLE);

  const [engine, setEngine] = useState({
    available: false,
    version: null,
    message: "Checking forensic engine...",
  });

  const [evidence, setEvidence] = useState([]);
  const [selectedEvidence, setSelectedEvidence] =
    useState(null);

  const [integrity, setIntegrity] = useState(null);

  const [recoveredFiles, setRecoveredFiles] =
    useState([]);

  const [report, setReport] = useState(null);
  const [reportFile, setReportFile] = useState(null);

  const [scanStats, setScanStats] = useState(null);

  const [caseId, setCaseId] = useState(
    createLocalCaseId()
  );

  const [examiner, setExaminer] = useState("");

  const [busy, setBusy] = useState(false);

  const [progressMessage, setProgressMessage] =
    useState("");

  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const [scanOutput, setScanOutput] = useState("");

  const [lastScanDuration, setLastScanDuration] =
    useState(null);

  const [lastOperation, setLastOperation] =
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
    integrity?.hashMatch === true;

  const canVerify =
    Boolean(selectedEvidence) && !busy;

  const canScan =
    Boolean(selectedEvidence) &&
    integrityVerified &&
    engine.available &&
    Boolean(caseId.trim()) &&
    Boolean(examiner.trim()) &&
    !busy;

  const canGenerateReport =
    Boolean(selectedEvidence) &&
    integrityVerified &&
    Boolean(caseId.trim()) &&
    Boolean(examiner.trim()) &&
    !busy;

  /* ==========================================================================
     ENGINE STATUS
     ========================================================================== */

  const loadEngineStatus = useCallback(async () => {
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
  }, []);

  /* ==========================================================================
     EVIDENCE REPOSITORY
     ========================================================================== */

  const loadEvidence = useCallback(async () => {
    try {
      const response = await apiFetch(
        "/api/forensic/evidence"
      );

      const rawItems = Array.isArray(response)
        ? response
        : Array.isArray(response?.evidence)
        ? response.evidence
        : Array.isArray(response?.data)
        ? response.data
        : Array.isArray(response?.data?.evidence)
        ? response.data.evidence
        : [];

      const items = rawItems
        .map(normalizeEvidence)
        .filter(Boolean);

      setEvidence(items);

      setSelectedEvidence((current) => {
        if (!current) return null;

        const refreshed = items.find(
          (item) =>
            (current.evidenceId &&
              item.evidenceId ===
                current.evidenceId) ||
            (!current.evidenceId &&
              item.name === current.name)
        );

        return refreshed || current;
      });
    } catch (err) {
      setError(
        err.message ||
          "Unable to load evidence repository."
      );
    }
  }, []);

  useEffect(() => {
    loadEngineStatus();
    loadEvidence();
  }, [loadEngineStatus, loadEvidence]);

  /* ==========================================================================
     SELECT EVIDENCE
     ========================================================================== */

  const selectEvidence = useCallback(
    (item) => {
      if (busy) return;

      const normalized =
        normalizeEvidence(item);

      if (!normalized) return;

      setSelectedEvidence(normalized);

      setIntegrity(null);
      setRecoveredFiles([]);
      setScanStats(null);
      setReport(null);
      setReportFile(null);
      setScanOutput("");
      setLastScanDuration(null);
      setLastOperation(null);

      setError("");
      setNotice("");

      setStatus(
        normalized.acquisitionHash
          ? STATUS.READY
          : STATUS.IDLE
      );
    },
    [busy]
  );

  /* ==========================================================================
     ACQUIRE EVIDENCE
     ========================================================================== */

  const acquireEvidence = useCallback(
    async (file) => {
      if (!file) return;

      setBusy(true);
      setError("");
      setNotice("");
      setStatus(STATUS.ACQUIRING);

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
        if (file.size > MAX_FILE_SIZE) {
          throw new Error(
            "Evidence file exceeds the maximum supported size of 5 GB."
          );
        }

        if (file.size === 0) {
          throw new Error(
            "Empty evidence files are not accepted."
          );
        }

        const formData = new FormData();

        formData.append(
          "evidence",
          file,
          file.name
        );

        const response = await fetch(
          apiUrl("/api/forensic/upload"),
          {
            method: "POST",
            headers: authHeaders(),
            body: formData,
          }
        );

        const result =
          await parseResponse(response);

        const acquired = normalizeEvidence(
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

        if (!acquired.name) {
          throw new Error(
            "Server returned incomplete evidence metadata."
          );
        }

        setSelectedEvidence(acquired);

        setStatus(
          acquired.acquisitionHash
            ? STATUS.READY
            : STATUS.FAILED
        );

        if (!acquired.acquisitionHash) {
          setError(
            "Evidence was uploaded, but the server did not return an acquisition SHA-256 baseline."
          );
        } else {
          setNotice(
            result?.message ||
              "Evidence acquired successfully. Verify SHA-256 before recovery."
          );
        }

        await loadEvidence();
      } catch (err) {
        setStatus(STATUS.FAILED);

        setError(
          err.message ||
            "Evidence acquisition failed."
        );
      } finally {
        setBusy(false);
        setProgressMessage("");
      }
    },
    [loadEvidence]
  );

  const handleFileChange = useCallback(
    async (event) => {
      const file = event.target.files?.[0];

      event.target.value = "";

      if (file) {
        await acquireEvidence(file);
      }
    },
    [acquireEvidence]
  );

  /* ==========================================================================
     VERIFY INTEGRITY
     ========================================================================== */

  const verifyIntegrity = useCallback(async () => {
    if (!selectedEvidence) {
      setError("Select evidence first.");
      return;
    }

    setBusy(true);
    setError("");
    setNotice("");
    setStatus(STATUS.VERIFYING);

    setProgressMessage(
      "Calculating current SHA-256 and comparing it with the acquisition baseline..."
    );

    try {
      const response = await apiFetch(
        "/api/forensic/verify-integrity",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            evidenceId: selectedEvidenceId,
            evidence_id: selectedEvidenceId,
            fileName: selectedFileName,
            file_name: selectedFileName,
          }),
        }
      );

      const result = normalizeIntegrity(
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

      if (
        result.status === INTEGRITY.VERIFIED &&
        result.verified === true &&
        result.hashMatch === true
      ) {
        setStatus(STATUS.READY);

        setNotice(
          "Evidence integrity VERIFIED. Forensic recovery is now unlocked."
        );
      } else {
        setStatus(STATUS.FAILED);

        setError(
          result.message ||
            "Evidence integrity verification failed."
        );
      }
    } catch (err) {
      setStatus(STATUS.FAILED);

      setError(
        err.message ||
          "Integrity verification failed."
      );
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

  const runForensicScan = useCallback(async () => {
    if (!selectedEvidence) {
      setError(
        "Select evidence before starting recovery."
      );
      return;
    }

    if (!integrityVerified) {
      setError(
        "Recovery is blocked until evidence integrity is VERIFIED."
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
      setError("Case ID is required.");
      return;
    }

    if (!examiner.trim()) {
      setError("Examiner name is required.");
      return;
    }

    setBusy(true);
    setError("");
    setNotice("");
    setStatus(STATUS.SCANNING);

    setRecoveredFiles([]);
    setScanStats(null);
    setReport(null);
    setReportFile(null);
    setScanOutput("");
    setLastOperation(null);

    setProgressMessage(
      "Scanning verified evidence. Detecting signatures, carving ranges and validating artifacts..."
    );

    const started = performance.now();

    try {
      const response = await apiFetch(
        "/api/forensic/scan",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            evidenceId: selectedEvidenceId,
            evidence_id: selectedEvidenceId,

            fileName: selectedFileName,
            file_name: selectedFileName,

            caseId: caseId.trim(),
            case_id: caseId.trim(),

            examiner: examiner.trim(),
          }),
        }
      );

      const duration = Math.round(
        performance.now() - started
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

      setLastScanDuration(durationMs);

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

      const recoveredArray =
        Array.isArray(rawRecovered)
          ? rawRecovered
          : [];

      const normalizedRecovered =
        recoveredArray
          .map(normalizeRecoveredFile)
          .filter(Boolean);

      setRecoveredFiles(normalizedRecovered);

      setScanOutput(
        response?.output ||
          response?.stdout ||
          response?.consoleOutput ||
          response?.console_output ||
          response?.data?.output ||
          ""
      );

      /* ---------------------------------------------------------------
         POST-SCAN INTEGRITY
         --------------------------------------------------------------- */

      const postScanIntegrity =
        response?.integrity ||
        response?.postScanIntegrity ||
        response?.post_scan_integrity ||
        response?.data?.integrity ||
        response?.data?.postScanIntegrity ||
        response?.data?.post_scan_integrity;

      const postScan = normalizeIntegrity(
        postScanIntegrity
      );

      if (!postScan) {
        setStatus(STATUS.FAILED);

        setError(
          "Forensic scan completed, but the server did not return post-scan integrity verification."
        );

        return;
      }

      setIntegrity(postScan);

      if (
        postScan.status !==
          INTEGRITY.VERIFIED ||
        postScan.verified !== true ||
        postScan.hashMatch !== true
      ) {
        setStatus(STATUS.FAILED);

        setError(
          "Evidence integrity changed or could not be verified after recovery. The recovered artifacts must not be treated as verified evidence."
        );

        return;
      }

      const finalCaseId =
        response?.caseId ||
        response?.case_id ||
        caseId.trim();

      const finalExaminer =
        response?.examiner ||
        examiner.trim();

      setLastOperation({
        caseId: finalCaseId,
        examiner: finalExaminer,
        completedAt:
          new Date().toISOString(),
      });

      setStatus(STATUS.COMPLETED);

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
        0;

      setNotice(
        response?.message ||
          `Forensic recovery completed. ${candidateCount} candidate range(s) identified and ${validatedCount} artifact(s) validated.`
      );
    } catch (err) {
      setStatus(STATUS.FAILED);

      const serverIntegrity =
        err.response?.integrity ||
        err.response?.data?.integrity;

      if (serverIntegrity) {
        setIntegrity(
          normalizeIntegrity(serverIntegrity)
        );
      }

      setError(
        err.message ||
          "Forensic recovery failed."
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
    engine.available,
    caseId,
    examiner,
  ]);

  /* ==========================================================================
     REPORT
     ========================================================================== */

  const generateReport = useCallback(async () => {
    if (!selectedEvidence) {
      setError("Select evidence first.");
      return;
    }

    if (!integrityVerified) {
      setError(
        "Report generation requires VERIFIED evidence."
      );
      return;
    }

    if (!caseId.trim()) {
      setError("Case ID is required.");
      return;
    }

    if (!examiner.trim()) {
      setError("Examiner name is required.");
      return;
    }

    setBusy(true);
    setError("");
    setNotice("");

    try {
      const response = await apiFetch(
        "/api/forensic/report",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            evidenceId: selectedEvidenceId,
            evidence_id: selectedEvidenceId,

            fileName: selectedFileName,
            file_name: selectedFileName,

            caseId: caseId.trim(),
            case_id: caseId.trim(),

            examiner: examiner.trim(),
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
        typeof generatedReport !== "object"
      ) {
        throw new Error(
          "Report generation returned no report data."
        );
      }

      setReport(generatedReport);

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

      setReportFile(generatedReportFile);

      if (generatedReport.integrity) {
        const normalized =
          normalizeIntegrity(
            generatedReport.integrity
          );

        if (normalized) {
          setIntegrity(normalized);

          if (
            normalized.status !==
              INTEGRITY.VERIFIED ||
            normalized.verified !== true ||
            normalized.hashMatch !== true
          ) {
            setStatus(STATUS.FAILED);

            setError(
              "The generated report indicates that evidence integrity is not VERIFIED."
            );

            return;
          }
        }
      }

      setNotice(
        response?.message ||
          "Forensic evidence report generated successfully."
      );
    } catch (err) {
      setError(
        err.message ||
          "Unable to generate forensic report."
      );
    } finally {
      setBusy(false);
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
     RESET
     ========================================================================== */

  const resetWorkspace = useCallback(() => {
    if (busy) return;

    setSelectedEvidence(null);
    setIntegrity(null);
    setRecoveredFiles([]);
    setScanStats(null);
    setReport(null);
    setReportFile(null);
    setScanOutput("");

    setError("");
    setNotice("");

    setStatus(STATUS.IDLE);

    setLastScanDuration(null);
    setLastOperation(null);

    setCaseId(createLocalCaseId());
    setExaminer("");
  }, [busy]);

  /* ==========================================================================
     DOWNLOADS
     ========================================================================== */

  const downloadRecoveredFile =
    useCallback((file) => {
      if (!file?.path) {
        setError(
          "This artifact has no download path."
        );
        return;
      }

      const url = apiUrl(file.path);

      window.open(
        url,
        "_blank",
        "noopener,noreferrer"
      );
    }, []);

  const downloadReport = useCallback(() => {
    if (!reportFile) {
      setError(
        "No report file is available."
      );
      return;
    }

    const reportPath = String(reportFile);

    window.open(
      apiUrl(
        reportPath.startsWith("/api/")
          ? reportPath
          : `/api/forensic/report/${encodeURIComponent(
              reportPath
            )}`
      ),
      "_blank",
      "noopener,noreferrer"
    );
  }, [reportFile]);

  /* ==========================================================================
     REPOSITORY STATISTICS
     ========================================================================== */

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

  /* ==========================================================================
     RENDER
     ========================================================================== */

  return (
    <div className="forensics-page">
      {/* ====================================================================
          HEADER
          ==================================================================== */}

      <header className="forensics-header">
        <div>
          <div className="forensics-eyebrow">
            SECURITY OPERATIONS CENTER
          </div>

          <h1>TrustWipe Digital Forensics</h1>

          <p>
            Secure evidence acquisition, integrity
            verification, forensic recovery and
            compliance-grade evidence reporting.
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
            onClick={loadEngineStatus}
            disabled={busy}
          >
            Refresh
          </button>
        </div>
      </header>

      {/* ====================================================================
          ALERTS
          ==================================================================== */}

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

      {/* ====================================================================
          SUMMARY
          ==================================================================== */}

      <section className="forensics-summary">
        <div className="summary-card">
          <span>Evidence Assets</span>

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
          <span>Integrity</span>

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
            SHA-256 baseline control
          </small>
        </div>

        <div className="summary-card">
          <span>Validated Artifacts</span>

          <strong>
            {recoveredFiles.length}
          </strong>

          <small>
            Current investigation
          </small>
        </div>

        <div className="summary-card">
          <span>Engine</span>

          <strong>
            {engine.available
              ? "READY"
              : "OFFLINE"}
          </strong>

          <small>
            Python forensic engine
          </small>
        </div>
      </section>

      {/* ====================================================================
          MAIN GRID
          ==================================================================== */}

      <div className="forensics-grid">
        {/* ================================================================
            EVIDENCE MANAGEMENT
            ================================================================ */}

        <section className="forensics-panel evidence-panel">
          <div className="panel-header">
            <div>
              <span className="panel-kicker">
                EVIDENCE MANAGEMENT
              </span>

              <h2>Acquire Evidence</h2>

              <p>
                Evidence is copied into the forensic
                repository and assigned an immutable
                SHA-256 acquisition baseline.
              </p>
            </div>

            <span className="secure-badge">
              SECURE
            </span>
          </div>

          <input
            ref={fileInputRef}
            type="file"
            hidden
            onChange={handleFileChange}
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

          {progressMessage && (
            <div className="operation-progress">
              <span className="spinner" />

              <span>
                {progressMessage}
              </span>
            </div>
          )}

          <div className="repository-header">
            <div>
              <strong>
                EVIDENCE REPOSITORY
              </strong>

              <span>
                {evidence.length} Assets
              </span>
            </div>

            <button
              type="button"
              className="icon-button"
              onClick={loadEvidence}
              disabled={busy}
              title="Refresh evidence"
            >
              ↻
            </button>
          </div>

          <div className="evidence-list">
            {evidence.length === 0 ? (
              <div className="empty-state">
                No evidence has been acquired.
              </div>
            ) : (
              evidence.map((item) => {
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
                      selectEvidence(item)
                    }
                    disabled={busy}
                  >
                    <div className="evidence-type">
                      {getFileType(item.name)}
                    </div>

                    <div className="evidence-details">
                      <strong>
                        {item.name}
                      </strong>

                      <small>
                        {formatBytes(item.size)}{" "}
                        • {item.type}
                      </small>

                      {item.evidenceId && (
                        <small>
                          {item.evidenceId}
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
              })
            )}
          </div>
        </section>

        {/* ================================================================
            ACTIVE EVIDENCE
            ================================================================ */}

        <section className="forensics-panel active-panel">
          <div className="panel-header">
            <div>
              <span className="panel-kicker">
                ACTIVE EVIDENCE
              </span>

              <h2>
                {selectedEvidence?.name ||
                  "No evidence selected"}
              </h2>
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
                Select evidence to begin
              </h3>

              <p>
                Acquire or select a forensic
                evidence image.
              </p>
            </div>
          ) : (
            <>
              {/* ============================================================
                  METADATA
                  ============================================================ */}

              <div className="metadata-grid">
                <div>
                  <span>SIZE</span>

                  <strong>
                    {formatBytes(
                      selectedEvidence.size
                    )}
                  </strong>
                </div>

                <div>
                  <span>TYPE</span>

                  <strong>
                    {selectedEvidence.type}
                  </strong>
                </div>

                <div>
                  <span>EVIDENCE ID</span>

                  <strong>
                    {selectedEvidence.evidenceId ||
                      "—"}
                  </strong>
                </div>

                <div>
                  <span>ACQUIRED</span>

                  <strong>
                    {formatDate(
                      selectedEvidence.acquiredAt
                    )}
                  </strong>
                </div>
              </div>

              {/* ============================================================
                  CASE CONTROL
                  ============================================================ */}

              <div className="case-control">
                <div className="section-title">
                  <span>CASE CONTROL</span>

                  <small>
                    Investigation context
                  </small>
                </div>

                <div className="form-grid">
                  <label>
                    <span>CASE ID</span>

                    <input
                      value={caseId}
                      onChange={(event) =>
                        setCaseId(
                          event.target.value
                        )
                      }
                      disabled={busy}
                      maxLength={100}
                    />
                  </label>

                  <label>
                    <span>EXAMINER</span>

                    <input
                      value={examiner}
                      onChange={(event) =>
                        setExaminer(
                          event.target.value
                        )
                      }
                      disabled={busy}
                      placeholder="Examiner name"
                      maxLength={150}
                    />
                  </label>
                </div>
              </div>

              {/* ============================================================
                  INTEGRITY
                  ============================================================ */}

              <div className="integrity-section">
                <div className="section-title">
                  <span>
                    EVIDENCE INTEGRITY
                  </span>

                  {integrity && (
                    <span
                      className={getIntegrityClass(
                        integrity.status
                      )}
                    >
                      {integrity.status}
                    </span>
                  )}
                </div>

                {!integrity ? (
                  <div className="integrity-empty">
                    Integrity has not been verified
                    for this evidence.
                  </div>
                ) : (
                  <>
                    <div
                      className={`integrity-banner ${getIntegrityClass(
                        integrity.status
                      )}`}
                    >
                      <strong>
                        {integrity.status ===
                        INTEGRITY.VERIFIED
                          ? "✓ Evidence integrity VERIFIED"
                          : integrity.status ===
                            INTEGRITY.TAMPERED
                          ? "⚠ Evidence integrity FAILED"
                          : integrity.status ===
                            INTEGRITY.BASELINE_MISSING
                          ? "⚠ Acquisition baseline unavailable"
                          : "⚠ Evidence integrity UNKNOWN"}
                      </strong>

                      <p>
                        {integrity.message ||
                          "Evidence integrity requires review."}
                      </p>

                      <small>
                        Hash match:{" "}
                        {integrity.hashMatch
                          ? "YES"
                          : "NO"}
                        {" • "}
                        Size match:{" "}
                        {integrity.sizeMatch
                          ? "YES"
                          : "NO"}
                      </small>
                    </div>

                    <div className="hash-grid">
                      <div className="hash-box">
                        <span>
                          ACQUISITION SHA-256
                        </span>

                        <code>
                          {integrity.originalHash ||
                            "—"}
                        </code>
                      </div>

                      <div className="hash-box">
                        <span>
                          CURRENT SHA-256
                        </span>

                        <code>
                          {integrity.currentHash ||
                            "—"}
                        </code>
                      </div>
                    </div>
                  </>
                )}

                <div className="action-row">
                  <button
                    type="button"
                    className="secondary-button"
                    onClick={verifyIntegrity}
                    disabled={!canVerify}
                  >
                    Calculate &amp; Verify
                    SHA-256
                  </button>
                </div>
              </div>

              {/* ============================================================
                  FORENSIC CONTROL
                  ============================================================ */}

              <div className="forensic-control">
                <div className="section-title">
                  <div>
                    <span>
                      FORENSIC CONTROL CENTER
                    </span>

                    <small>
                      Recovery requires verified
                      evidence integrity.
                    </small>
                  </div>
                </div>

                <div className="operation-flow">
                  <div
                    className={
                      integrityVerified
                        ? "flow-step complete"
                        : "flow-step"
                    }
                  >
                    <span>1</span>
                    <strong>Verify</strong>
                  </div>

                  <div
                    className={
                      status ===
                        STATUS.SCANNING ||
                      status ===
                        STATUS.COMPLETED
                        ? "flow-step complete"
                        : "flow-step"
                    }
                  >
                    <span>2</span>
                    <strong>Recover</strong>
                  </div>

                  <div
                    className={
                      report
                        ? "flow-step complete"
                        : "flow-step"
                    }
                  >
                    <span>3</span>
                    <strong>Report</strong>
                  </div>
                </div>

                <div className="action-row">
                  <button
                    type="button"
                    className="primary-button"
                    onClick={runForensicScan}
                    disabled={!canScan}
                  >
                    {status ===
                    STATUS.SCANNING ? (
                      <>
                        <span className="spinner" />
                        FORENSIC SCAN RUNNING
                      </>
                    ) : (
                      <>
                        ◈ START FORENSIC RECOVERY
                      </>
                    )}
                  </button>

                  <button
                    type="button"
                    className="secondary-button"
                    onClick={generateReport}
                    disabled={
                      !canGenerateReport
                    }
                  >
                    ▤ GENERATE REPORT
                  </button>

                  <button
                    type="button"
                    className="danger-outline-button"
                    onClick={resetWorkspace}
                    disabled={busy}
                  >
                    RESET
                  </button>
                </div>
              </div>
            </>
          )}
        </section>
      </div>

      {/* ====================================================================
          SCAN STATISTICS
          ==================================================================== */}

      {scanStats && (
        <section className="forensics-panel">
          <div className="panel-header">
            <div>
              <span className="panel-kicker">
                FORENSIC ANALYSIS
              </span>

              <h2>
                Scan Statistics
              </h2>

              <p>
                Evidence processing statistics
                returned by the forensic engine.
              </p>
            </div>

            <strong>
              {scanStats.status}
            </strong>
          </div>

          <div className="metadata-grid">
            <div>
              <span>EVIDENCE SIZE</span>

              <strong>
                {formatBytes(
                  scanStats.evidenceSize
                )}
              </strong>
            </div>

            <div>
              <span>CHUNK SIZE</span>

              <strong>
                {scanStats.chunkSize
                  ? formatBytes(
                      scanStats.chunkSize
                    )
                  : "—"}
              </strong>
            </div>

            <div>
              <span>CHUNKS SCANNED</span>

              <strong>
                {scanStats.chunksScanned ??
                  "—"}
              </strong>
            </div>

            <div>
              <span>BYTES SCANNED</span>

              <strong>
                {scanStats.bytesScanned
                  ? formatBytes(
                      scanStats.bytesScanned
                    )
                  : "—"}
              </strong>
            </div>

            <div>
              <span>
                SIGNATURES DETECTED
              </span>

              <strong>
                {scanStats.signaturesDetected}
              </strong>
            </div>

            <div>
              <span>
                CANDIDATE RANGES
              </span>

              <strong>
                {scanStats.candidatesFound}
              </strong>
            </div>

            <div>
              <span>
                ARTIFACTS CARVED
              </span>

              <strong>
                {scanStats.artifactsCarved}
              </strong>
            </div>

            <div>
              <span>
                ARTIFACTS VALIDATED
              </span>

              <strong>
                {scanStats.artifactsValidated}
              </strong>
            </div>
          </div>

          <div className="compliance-note">
            <strong>
              Forensic interpretation
            </strong>

            <p>
              A detected file signature is only
              a candidate location. An artifact is
              reported as recovered only after the
              carving and validation stages succeed.
            </p>
          </div>
        </section>
      )}

      {/* ====================================================================
          RECOVERED ARTIFACTS
          ==================================================================== */}

      {selectedEvidence && (
        <section className="forensics-panel results-panel">
          <div className="panel-header">
            <div>
              <span className="panel-kicker">
                FORENSIC RECOVERY
              </span>

              <h2>
                Validated Recovered Artifacts
              </h2>

              <p>
                Files successfully carved and
                format-validated by the forensic
                engine.
              </p>
            </div>

            <strong>
              {recoveredFiles.length}
            </strong>
          </div>

          {recoveredFiles.length === 0 ? (
            <div className="empty-results">
              <span>◇</span>

              <div>
                <strong>
                  No validated artifacts
                </strong>

                <p>
                  The scan did not produce any
                  artifacts that passed the
                  recovery and validation stages.
                </p>
              </div>
            </div>
          ) : (
            <div className="recovered-list">
              {recoveredFiles.map(
                (file, index) => (
                  <div
                    className="recovered-item"
                    key={
                      file.artifactId ||
                      `${file.name}-${index}`
                    }
                  >
                    <div className="recovered-type">
                      {file.type}
                    </div>

                    <div className="recovered-details">
                      <strong>
                        {file.name}
                      </strong>

                      <small>
                        {formatBytes(
                          file.size
                        )}{" "}
                        •{" "}
                        {file.validationStatus}

                        {file.confidence !==
                          null &&
                          file.confidence !==
                            undefined
                          ? ` • Confidence: ${file.confidence}`
                          : ""}
                      </small>

                      {file.sourceOffset !==
                        null &&
                        file.sourceOffset !==
                          undefined && (
                          <small>
                            Source offset:{" "}
                            {file.sourceOffset}
                          </small>
                        )}

                      {file.sourceEnd !== null &&
                        file.sourceEnd !==
                          undefined && (
                          <small>
                            Source end:{" "}
                            {file.sourceEnd}
                          </small>
                        )}

                      {file.sha256 && (
                        <code>
                          SHA-256:{" "}
                          {file.sha256}
                        </code>
                      )}
                    </div>

                    {file.path && (
                      <button
                        type="button"
                        className="secondary-button"
                        onClick={() =>
                          downloadRecoveredFile(
                            file
                          )
                        }
                      >
                        Download
                      </button>
                    )}
                  </div>
                )
              )}
            </div>
          )}
        </section>
      )}

      {/* ====================================================================
          ENGINE OUTPUT
          ==================================================================== */}

      {scanOutput && (
        <section className="forensics-panel console-panel">
          <div className="panel-header">
            <div>
              <span className="panel-kicker">
                ENGINE OUTPUT
              </span>

              <h2>
                Forensic Engine Console
              </h2>
            </div>

            {lastScanDuration !== null && (
              <span>
                {formatDuration(
                  lastScanDuration
                )}
              </span>
            )}
          </div>

          <pre className="forensic-console">
            {scanOutput}
          </pre>
        </section>
      )}

      {/* ====================================================================
          REPORT
          ==================================================================== */}

      {report && (
        <section className="forensics-panel report-panel">
          <div className="panel-header">
            <div>
              <span className="panel-kicker">
                COMPLIANCE &amp; EVIDENCE
              </span>

              <h2>
                Forensic Evidence Report
              </h2>

              <p>
                Generated from acquisition,
                integrity verification and
                forensic recovery results.
              </p>
            </div>

            {reportFile && (
              <button
                type="button"
                className="primary-button"
                onClick={downloadReport}
              >
                DOWNLOAD REPORT
              </button>
            )}
          </div>

          <div className="report-grid">
            <div>
              <span>CASE ID</span>

              <strong>
                {report.case_id ||
                  report.caseId ||
                  caseId}
              </strong>
            </div>

            <div>
              <span>EXAMINER</span>

              <strong>
                {report.examiner ||
                  examiner ||
                  "—"}
              </strong>
            </div>

            <div>
              <span>INTEGRITY</span>

              <strong
                className={getIntegrityClass(
                  report.integrity
                    ?.status ||
                    integrity?.status ||
                    INTEGRITY.UNKNOWN
                )}
              >
                {report.integrity
                  ?.status ||
                  integrity?.status ||
                  "UNKNOWN"}
              </strong>
            </div>

            <div>
              <span>GENERATED</span>

              <strong>
                {formatDate(
                  report.generated_at ||
                    report.generatedAt
                )}
              </strong>
            </div>
          </div>

          <div className="report-hashes">
            <div>
              <span>
                ACQUISITION HASH
              </span>

              <code>
                {report.integrity
                  ?.acquisition_hash ||
                  report.integrity
                    ?.acquisitionHash ||
                  report.integrity
                    ?.original_hash ||
                  report.integrity
                    ?.originalHash ||
                  integrity?.originalHash ||
                  "—"}
              </code>
            </div>

            <div>
              <span>
                CURRENT HASH
              </span>

              <code>
                {report.integrity
                  ?.current_hash ||
                  report.integrity
                    ?.currentHash ||
                  integrity?.currentHash ||
                  "—"}
              </code>
            </div>
          </div>

          {report.compliance && (
            <div className="compliance-note">
              <strong>
                Compliance Reference
              </strong>

              <span>
                {report.compliance.standard ||
                  "—"}
              </span>

              <p>
                {report.compliance.note ||
                  ""}
              </p>
            </div>
          )}
        </section>
      )}

      {/* ====================================================================
          OPERATION FOOTER
          ==================================================================== */}

      {lastOperation && (
        <section className="operation-footer">
          <div>
            <span>INVESTIGATION</span>

            <strong>
              {lastOperation.caseId}
            </strong>
          </div>

          <div>
            <span>EXAMINER</span>

            <strong>
              {lastOperation.examiner}
            </strong>
          </div>

          <div>
            <span>LAST OPERATION</span>

            <strong>
              {formatDate(
                lastOperation.completedAt
              )}
            </strong>
          </div>

          <div>
            <span>EVIDENCE CONTROL</span>

            <strong>
              {integrityVerified
                ? "SHA-256 VERIFIED"
                : "REVIEW REQUIRED"}
            </strong>
          </div>
        </section>
      )}

      {/* ====================================================================
          FOOTER
          ==================================================================== */}

      <footer className="forensics-footer">
        <span>
          TRUSTWIPE SECURITY OPERATIONS CENTER
        </span>

        <span>
          SHA-256 INTEGRITY CONTROL ACTIVE
        </span>

        <span>
          ● FORENSIC ENGINE{" "}
          {engine.available
            ? "ONLINE"
            : "OFFLINE"}
        </span>
      </footer>
    </div>
  );
}