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
  import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, "");

if (!API_BASE) {
  throw new Error("VITE_API_BASE_URL is not configured.");
}

/*
 * Set this in Vercel:
 *
 * VITE_AGENT_DOWNLOAD_URL=https://YOUR-DOWNLOAD-LOCATION/TrustWipeAgentSetup.exe
 *
 * Do NOT use the old trust-wipe.onrender.com URL.
 */
const AGENT_DOWNLOAD_URL =
  import.meta.env.VITE_AGENT_DOWNLOAD_URL ||
  `${API_BASE}/downloads/TrustWipeAgent.exe`;

const MAX_FILE_SIZE =
  5 * 1024 * 1024 * 1024;

const CASE_STORAGE_KEY =
  "trustwipe_forensic_cases";

const STEPS = {
  CASES: "CASES",
  CREATE_CASE: "CREATE_CASE",
  AGENT: "AGENT",
  SOURCE: "SOURCE",
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
  QUEUED: "QUEUED",
  SCANNING: "SCANNING",
  COMPLETED: "COMPLETED",
  FAILED: "FAILED",
  CANCELLED: "CANCELLED",
};

const INTEGRITY = {
  VERIFIED: "VERIFIED",
  TAMPERED: "TAMPERED",
  BASELINE_MISSING: "BASELINE_MISSING",
  UNKNOWN: "UNKNOWN",
};

const SOURCE_TYPES = {
  DEVICE: "DEVICE",
  FILE: "FILE",
};

/* ============================================================================
   API HELPERS
============================================================================ */

function apiUrl(path = "") {
  if (!path) {
    return API_BASE;
  }

  if (/^https?:\/\//i.test(path)) {
    return path;
  }

  return `${API_BASE}${
    path.startsWith("/") ? path : `/${path}`
  }`;
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

  if (
    contentType.includes(
      "application/json"
    )
  ) {
    body =
      await response
        .json()
        .catch(() => null);
  } else {
    const text =
      await response
        .text()
        .catch(() => "");

    body = text
      ? { message: text }
      : null;
  }

  if (!response.ok) {
    const message =
      body?.message ||
      body?.error ||
      body?.detail ||
      `Request failed with HTTP ${response.status}`;

    const error =
      new Error(message);

    error.status =
      response.status;

    error.code =
      body?.code || null;

    error.response =
      body;

    throw error;
  }

  return body;
}

async function apiFetch(
  path,
  options = {}
) {
  const response =
    await fetch(
      apiUrl(path),
      {
        ...options,

        headers: authHeaders(
          options.headers || {}
        ),
      }
    );

  return parseResponse(
    response
  );
}

/* ============================================================================
   GENERAL HELPERS
============================================================================ */

function firstDefined(
  ...values
) {
  return values.find(
    (value) =>
      value !== undefined &&
      value !== null &&
      value !== ""
  );
}

function toBoolean(value) {
  if (
    typeof value === "boolean"
  ) {
    return value;
  }

  if (
    typeof value === "number"
  ) {
    return value !== 0;
  }

  if (
    typeof value === "string"
  ) {
    return [
      "true",
      "yes",
      "1",
      "verified",
      "valid",
      "match",
      "matched",
      "online",
      "connected",
    ].includes(
      value.toLowerCase()
    );
  }

  return Boolean(value);
}

function formatBytes(bytes) {
  const value =
    Number(bytes);

  if (
    !Number.isFinite(value) ||
    value <= 0
  ) {
    return "0 B";
  }

  const units = [
    "B",
    "KB",
    "MB",
    "GB",
    "TB",
  ];

  const exponent =
    Math.min(
      Math.floor(
        Math.log(value) /
          Math.log(1024)
      ),
      units.length - 1
    );

  const size =
    value /
    Math.pow(
      1024,
      exponent
    );

  return `${size.toFixed(
    size >= 10 ||
      exponent === 0
      ? 0
      : 2
  )} ${units[exponent]}`;
}

function formatDate(value) {
  if (!value) {
    return "—";
  }

  const date =
    new Date(value);

  if (
    Number.isNaN(
      date.getTime()
    )
  ) {
    return "—";
  }

  return date.toLocaleString();
}

function formatDuration(ms) {
  const value =
    Number(ms);

  if (
    !Number.isFinite(value) ||
    value < 0
  ) {
    return "—";
  }

  const seconds =
    Math.floor(value / 1000);

  const minutes =
    Math.floor(
      seconds / 60
    );

  const remaining =
    seconds % 60;

  if (minutes === 0) {
    return `${remaining}s`;
  }

  return `${minutes}m ${remaining}s`;
}

function getFileType(
  fileName = ""
) {
  const cleanName =
    String(fileName)
      .split("?")[0]
      .split("#")[0];

  const extension =
    cleanName
      .split(".")
      .pop()
      ?.toUpperCase();

  return extension
    ? extension
    : "FILE";
}

function createLocalCaseId() {
  const stamp =
    Date.now();

  const random =
    Math.random()
      .toString(36)
      .slice(2, 8)
      .toUpperCase();

  return `CASE-${new Date()
    .getFullYear()}-${stamp}-${random}`;
}

function getIntegrityClass(
  status
) {
  switch (
    String(status || "")
      .toUpperCase()
  ) {
    case INTEGRITY.VERIFIED:
      return "integrity-verified";

    case INTEGRITY.TAMPERED:
      return "integrity-failed";

    case INTEGRITY.BASELINE_MISSING:
      return "integrity-warning";

    default:
      return "";
  }
}

function extractArray(
  response,
  keys = []
) {
  if (
    Array.isArray(response)
  ) {
    return response;
  }

  for (
    const key of keys
  ) {
    if (
      Array.isArray(
        response?.[key]
      )
    ) {
      return response[key];
    }
  }

  if (
    Array.isArray(
      response?.data
    )
  ) {
    return response.data;
  }

  return [];
}

/* ============================================================================
   EVIDENCE NORMALIZATION
============================================================================ */

function normalizeEvidence(
  item
) {
  if (!item) {
    return null;
  }

  const name =
    firstDefined(
      item.name,
      item.fileName,
      item.file_name,
      item.originalName,
      item.original_name
    );

  if (!name) {
    return null;
  }

  const sizeValue =
    firstDefined(
      item.size,
      item.fileSize,
      item.file_size,
      0
    );

  const evidenceId =
    firstDefined(
      item.evidenceId,
      item.evidence_id,
      item.id
    );

  const hash =
    firstDefined(
      item.acquisitionHash,
      item.acquisition_hash,
      item.sha256,
      item.hash
    );

  return {
    ...item,

    evidenceId:
      evidenceId || null,

    name,

    size:
      Number(sizeValue) || 0,

    type:
      firstDefined(
        item.type,
        item.mimeType,
        item.mime_type,
        "application/octet-stream"
      ),

    acquisitionHash:
      hash || null,

    acquiredAt:
      firstDefined(
        item.acquiredAt,
        item.acquired_at,
        item.createdAt,
        item.created_at
      ) || null,

    source:
      firstDefined(
        item.source,
        item.sourcePath,
        item.source_path
      ) || null,
  };
}

function normalizeIntegrity(
  value
) {
  if (!value) {
    return null;
  }

  const statusRaw =
    firstDefined(
      value.status,
      value.integrityStatus,
      value.integrity_status
    );

  let status =
    String(
      statusRaw ||
        INTEGRITY.UNKNOWN
    ).toUpperCase();

  const verifiedValue =
    firstDefined(
      value.verified,
      value.isVerified,
      value.is_verified
    );

  const hashMatchValue =
    firstDefined(
      value.hashMatch,
      value.hash_match
    );

  const sizeMatchValue =
    firstDefined(
      value.sizeMatch,
      value.size_match
    );

  const verified =
    toBoolean(
      verifiedValue
    );

  const hashMatch =
    toBoolean(
      hashMatchValue
    );

  const sizeMatch =
    toBoolean(
      sizeMatchValue
    );

  if (
    verified &&
    hashMatch &&
    sizeMatch
  ) {
    status =
      INTEGRITY.VERIFIED;
  }

  return {
    ...value,

    status,

    verified,

    hashMatch,

    sizeMatch,

    originalHash:
      firstDefined(
        value.originalHash,
        value.original_hash,
        value.acquisitionHash,
        value.acquisition_hash
      ) || null,

    currentHash:
      firstDefined(
        value.currentHash,
        value.current_hash,
        value.sha256,
        value.hash
      ) || null,
  };
}

function normalizeRecoveredFile(
  file
) {
  if (!file) {
    return null;
  }

  return {
    ...file,

    artifactId:
      firstDefined(
        file.artifactId,
        file.artifact_id,
        file.id
      ),

    name:
      firstDefined(
        file.name,
        file.fileName,
        file.file_name
      ) || "Recovered artifact",

    type:
      firstDefined(
        file.type,
        file.mimeType,
        file.mime_type
      ) || "Unknown",

    size:
      Number(
        firstDefined(
          file.size,
          file.fileSize,
          file.file_size,
          0
        )
      ) || 0,

    validationStatus:
      firstDefined(
        file.validationStatus,
        file.validation_status,
        file.validation
      ) || "UNKNOWN",

    confidence:
      firstDefined(
        file.confidence,
        file.confidenceScore,
        file.confidence_score
      ),

    sha256:
      firstDefined(
        file.sha256,
        file.hash
      ),

    path:
      firstDefined(
        file.path,
        file.downloadPath,
        file.download_path
      ) || null,

    sourceOffset:
      firstDefined(
        file.sourceOffset,
        file.source_offset
      ),
  };
}

/* ============================================================================
   LOCAL CASE STORAGE
============================================================================ */

function loadLocalCases() {
  try {
    const raw =
      localStorage.getItem(
        CASE_STORAGE_KEY
      );

    if (!raw) {
      return [];
    }

    const parsed =
      JSON.parse(raw);

    return Array.isArray(
      parsed
    )
      ? parsed
      : [];
  } catch {
    return [];
  }
}

function saveLocalCases(
  cases
) {
  try {
    localStorage.setItem(
      CASE_STORAGE_KEY,
      JSON.stringify(cases)
    );
  } catch {
    // Ignore storage errors.
  }
}

/* ============================================================================
   MAIN COMPONENT
============================================================================ */

export default function Forensics() {
  const fileInputRef =
    useRef(null);

  const pollingRef =
    useRef(null);

  const agentRefreshRef =
    useRef(null);

  /* --------------------------------------------------------------------------
     WORKFLOW
  -------------------------------------------------------------------------- */

  const [
    currentStep,
    setCurrentStep,
  ] = useState(
    STEPS.CASES
  );

  /* --------------------------------------------------------------------------
     CASE
  -------------------------------------------------------------------------- */

  const [
    cases,
    setCases,
  ] = useState(
    loadLocalCases
  );

  const [
    caseId,
    setCaseId,
  ] = useState("");

  const [
    examiner,
    setExaminer,
  ] = useState("");

  const [
    caseTitle,
    setCaseTitle,
  ] = useState("");

  const [
    caseDescription,
    setCaseDescription,
  ] = useState("");

  const [
    currentCase,
    setCurrentCase,
  ] = useState(null);

  /* --------------------------------------------------------------------------
     AGENT
  -------------------------------------------------------------------------- */

  const [
    agents,
    setAgents,
  ] = useState([]);

  const [
    selectedAgent,
    setSelectedAgent,
  ] = useState(null);

  const [
    agentLoading,
    setAgentLoading,
  ] = useState(false);

  const [
    showAgentPrompt,
    setShowAgentPrompt,
  ] = useState(false);

  const [
    showRunGuide,
    setShowRunGuide,
  ] = useState(false);

  const [
    agentRunMessage,
    setAgentRunMessage,
  ] = useState(
    "Download and run the TrustWipe Agent on this authorized Windows workstation before continuing."
  );

  // Mandatory Dashboard/Devices-style Agent onboarding choice.
  const [agentSetupChoice, setAgentSetupChoice] = useState(null);

  /* --------------------------------------------------------------------------
     DEVICE DISCOVERY
  -------------------------------------------------------------------------- */

  const [
    drives,
    setDrives,
  ] = useState([]);

  const [
    drivesLoading,
    setDrivesLoading,
  ] = useState(false);

  const [
    selectedDrive,
    setSelectedDrive,
  ] = useState(null);

  const [
    driveDiscoveryMessage,
    setDriveDiscoveryMessage,
  ] = useState("");

  /* --------------------------------------------------------------------------
     SOURCE
  -------------------------------------------------------------------------- */

  const [
    sourceType,
    setSourceType,
  ] = useState(null);

  /* --------------------------------------------------------------------------
     ENGINE
  -------------------------------------------------------------------------- */

  const [
    engine,
    setEngine,
  ] = useState({
    available: false,
    version: null,
    message:
      "Checking forensic engine...",
  });

  /* --------------------------------------------------------------------------
     STATUS
  -------------------------------------------------------------------------- */

  const [
    status,
    setStatus,
  ] = useState(
    STATUS.IDLE
  );

  const [
    busy,
    setBusy,
  ] = useState(false);

  const [
    progressMessage,
    setProgressMessage,
  ] = useState("");

  const [
    progress,
    setProgress,
  ] = useState(0);

  const [
    error,
    setError,
  ] = useState("");

  const [
    notice,
    setNotice,
  ] = useState("");

  /* --------------------------------------------------------------------------
     EVIDENCE
  -------------------------------------------------------------------------- */

  const [
    evidence,
    setEvidence,
  ] = useState([]);

  const [
    selectedEvidence,
    setSelectedEvidence,
  ] = useState(null);

  /* --------------------------------------------------------------------------
     INTEGRITY
  -------------------------------------------------------------------------- */

  const [
    integrity,
    setIntegrity,
  ] = useState(null);

  /* --------------------------------------------------------------------------
     ANALYSIS
  -------------------------------------------------------------------------- */

  const [
    analysisMode,
    setAnalysisMode,
  ] = useState(null);

  const [
    scanStats,
    setScanStats,
  ] = useState(null);

  const [
    scanOutput,
    setScanOutput,
  ] = useState("");

  const [
    lastScanDuration,
    setLastScanDuration,
  ] = useState(null);

  const [
    lastOperation,
    setLastOperation,
  ] = useState(null);

  const [
    forensicJobId,
    setForensicJobId,
  ] = useState(null);

  /* --------------------------------------------------------------------------
     RECOVERY
  -------------------------------------------------------------------------- */

  const [
    recoveredFiles,
    setRecoveredFiles,
  ] = useState([]);

  /* --------------------------------------------------------------------------
     REPORT
  -------------------------------------------------------------------------- */

  const [
    report,
    setReport,
  ] = useState(null);

  const [
    reportFile,
    setReportFile,
  ] = useState(null);

  /* ==========================================================================
     DERIVED STATE
  ========================================================================== */

  const selectedEvidenceId =
    selectedEvidence?.evidenceId ||
    null;

  const selectedFileName =
    selectedEvidence?.name ||
    null;

  const integrityVerified =
    integrity?.status ===
      INTEGRITY.VERIFIED &&
    integrity?.verified === true &&
    integrity?.hashMatch === true &&
    integrity?.sizeMatch === true;

  const repositoryStats =
    useMemo(() => {
      const totalSize =
        evidence.reduce(
          (sum, item) =>
            sum +
            Number(
              item.size || 0
            ),
          0
        );

      return {
        total:
          evidence.length,

        totalSize,
      };
    }, [evidence]);

  const validatedArtifacts =
    useMemo(
      () =>
        recoveredFiles.filter(
          (file) =>
            String(
              file.validationStatus
            ).toUpperCase() ===
            "VALID"
        ).length,
      [recoveredFiles]
    );

  const onlineAgents =
    useMemo(() => {
      const unique =
        new Map();

      agents.forEach(
        (agent) => {
          if (
            !agent?.agentId
          ) {
            return;
          }

          const key =
            String(
              agent.agentId
            ).trim();

          if (!key) {
            return;
          }

          const isOnline =
            agent.online !==
              false &&
            agent.connected !==
              false;

          if (isOnline) {
            unique.set(
              key,
              agent
            );
          }
        }
      );

      return Array.from(
        unique.values()
      );
    }, [agents]);

  const selectedDrivePath =
    selectedDrive?.devicePath ||
    selectedDrive?.device_path ||
    selectedDrive?.path ||
    selectedDrive?.name ||
    null;

  const sourceReady =
    sourceType ===
      SOURCE_TYPES.DEVICE
      ? Boolean(
          selectedDrivePath
        )
      : sourceType ===
          SOURCE_TYPES.FILE
        ? Boolean(
            selectedEvidence
          )
        : false;

  // Force the setup choice when entering the Agent step.
  useEffect(() => {
    if (currentStep === STEPS.AGENT && onlineAgents.length === 0 && !agentSetupChoice) {
      setShowAgentPrompt(true);
    }
  }, [currentStep, onlineAgents.length, agentSetupChoice]);

  /* ==========================================================================
     AGENT STATUS
  ========================================================================== */

  const loadAgents =
    useCallback(
      async () => {
        setAgentLoading(true);

        try {
          const response =
            await apiFetch(
              "/api/devices"
            );

          const raw =
            extractArray(
              response,
              [
                "agents",
                "devices",
                "data",
              ]
            );

          const normalized =
            raw
              .map(
                (item) => ({
                  ...item,

                  agentId:
                    firstDefined(
                      item.agentId,
                      item.agent_id,
                      item.deviceId,
                      item.device_id,
                      item.id
                    ),

                  deviceId:
                    firstDefined(
                      item.deviceId,
                      item.device_id,
                      item.agentId,
                      item.agent_id,
                      item.id
                    ),

                  hostname:
                    firstDefined(
                      item.hostname,
                      item.hostName,
                      item.name
                    ) ||
                    "Unknown device",

                  platform:
                    item.platform ||
                    "Windows",

                  online:
                    item.online !==
                    undefined
                      ? toBoolean(
                          item.online
                        )
                      : item.connected !==
                        undefined
                      ? toBoolean(
                          item.connected
                        )
                      : true,

                  connected:
                    item.connected !==
                    undefined
                      ? toBoolean(
                          item.connected
                        )
                      : item.online !==
                        undefined
                      ? toBoolean(
                          item.online
                        )
                      : true,

                  capabilities:
                    Array.isArray(
                      item.capabilities
                    )
                      ? item.capabilities.map(
                          (cap) =>
                            String(
                              cap
                            )
                              .trim()
                              .toUpperCase()
                        )
                      : [],
                })
              )
              .filter(
                (agent) =>
                  agent?.agentId
              );

          const unique =
            Array.from(
              normalized.reduce(
                (
                  map,
                  agent
                ) => {
                  const key =
                    String(
                      agent.agentId
                    ).trim();

                  const existing =
                    map.get(
                      key
                    );

                  if (
                    !existing
                  ) {
                    map.set(
                      key,
                      agent
                    );

                    return map;
                  }

                  map.set(
                    key,
                    {
                      ...existing,
                      ...agent,

                      agentId:
                        key,

                      hostname:
                        agent.hostname !==
                        "Unknown device"
                          ? agent.hostname
                          : existing.hostname,

                      platform:
                        agent.platform !==
                        "Windows"
                          ? agent.platform
                          : existing.platform,

                      capabilities:
                        Array.from(
                          new Set([
                            ...(existing.capabilities ||
                              []),
                            ...(agent.capabilities ||
                              []),
                          ])
                        ),
                    }
                  );

                  return map;
                },
                new Map()
              ).values()
            );

          setAgents(
            unique
          );

          setSelectedAgent(
            (current) => {
              if (
                !current
              ) {
                return (
                  unique.find(
                    (agent) =>
                      agent.capabilities?.includes(
                        "FORENSIC_SCAN"
                      )
                  ) ||
                  unique.find(
                    (agent) =>
                      agent.online &&
                      agent.connected !==
                        false
                  ) ||
                  null
                );
              }

              return (
                unique.find(
                  (agent) =>
                    String(
                      agent.agentId
                    ) ===
                    String(
                      current.agentId
                    )
                ) ||
                null
              );
            }
          );

          return unique;
        } catch (err) {
          setAgents([]);

          setSelectedAgent(
            null
          );

          /*
           * Do not destroy the entire forensic
           * workspace just because the device
           * list temporarily failed.
           */
          setError(
            err.message ||
              "Unable to load connected TrustWipe Agents."
          );
          return [];
        } finally {
          setAgentLoading(
            false
          );
        }
      },
      []
    );

  /* ==========================================================================
     ENGINE STATUS
  ========================================================================== */

  const loadEngineStatus =
    useCallback(
      async () => {
        try {
          const response =
            await apiFetch(
              "/api/forensic/status"
            );

          const available =
            toBoolean(
              firstDefined(
                response?.available,
                response?.engineAvailable,
                response?.engine_available,
                response?.agentBridgeAvailable,
                response?.agent_bridge_available
              )
            );

          setEngine({
            available,

            version:
              firstDefined(
                response?.pythonVersion,
                response?.python_version,
                response?.version
              ) ||
              "Windows Agent",

            message:
              response?.message ||
              (
                available
                  ? "Forensic engine is ready."
                  : "Forensic engine is unavailable."
              ),
          });
        } catch {
          setEngine({
            available: true,

            version:
              "Windows Agent",

            message:
              "Forensic processing is delegated to the connected TrustWipe Agent.",
          });
        }
      },
      []
    );

  /* ==========================================================================
     EVIDENCE REPOSITORY
  ========================================================================== */

  const loadEvidence =
    useCallback(
      async () => {
        try {
          const response =
            await apiFetch(
              "/api/forensic/evidence"
            );

          const raw =
            extractArray(
              response,
              ["evidence"]
            );

          const items =
            raw
              .map(
                normalizeEvidence
              )
              .filter(Boolean);

          setEvidence(
            items
          );

          setSelectedEvidence(
            (current) => {
              if (
                !current
              ) {
                return null;
              }

              return (
                items.find(
                  (item) =>
                    current.evidenceId &&
                    item.evidenceId ===
                      current.evidenceId
                ) ||
                current
              );
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

  /* ==========================================================================
     INITIAL LOAD
  ========================================================================== */

  useEffect(() => {
    loadEngineStatus();
    loadEvidence();
    loadAgents();

    agentRefreshRef.current =
      window.setInterval(
        () => {
          loadAgents();
          loadEngineStatus();
        },
        5000
      );

    return () => {
      if (
        agentRefreshRef.current
      ) {
        window.clearInterval(
          agentRefreshRef.current
        );

        agentRefreshRef.current =
          null;
      }
    };
  }, [
    loadEngineStatus,
    loadEvidence,
    loadAgents,
  ]);

  /* ==========================================================================
     CLEAN POLLING
  ========================================================================== */

  const stopPolling =
    useCallback(() => {
      if (
        pollingRef.current
      ) {
        window.clearInterval(
          pollingRef.current
        );

        pollingRef.current =
          null;
      }
    }, []);

  useEffect(() => {
    return () => {
      stopPolling();
    };
  }, [
    stopPolling,
  ]);

  /* ==========================================================================
     CASE MANAGEMENT
  ========================================================================== */

  const persistCase =
    useCallback(
      (newCase) => {
        setCases(
          (current) => {
            const updated = [
              newCase,

              ...current.filter(
                (item) =>
                  item.caseId !==
                  newCase.caseId
              ),
            ];

            saveLocalCases(
              updated
            );

            return updated;
          }
        );
      },
      []
    );

  const createCase =
    useCallback(() => {
      setError("");
      setNotice("");

      if (
        !caseTitle.trim()
      ) {
        setError(
          "Case title is required."
        );

        return;
      }

      if (
        !examiner.trim()
      ) {
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

        status:
          "OPEN",

        evidenceCount:
          0,
      };

      persistCase(
        newCase
      );

      setCaseId(
        newCase.caseId
      );

      setCurrentCase(
        newCase
      );

      setNotice(
        `Case ${newCase.caseId} created successfully.`
      );

      setAgentSetupChoice(null);
      setShowAgentPrompt(true);
      setShowRunGuide(false);

      setCurrentStep(
        STEPS.AGENT
      );
    }, [
      caseId,
      caseTitle,
      caseDescription,
      examiner,
      persistCase,
    ]);

  const openExistingCase =
    useCallback(
      (selectedCase) => {
        setError("");
        setNotice("");

        setCurrentCase(
          selectedCase
        );

        setCaseId(
          selectedCase.caseId
        );

        setExaminer(
          selectedCase.examiner ||
            ""
        );

        setCaseTitle(
          selectedCase.title ||
            ""
        );

        setCaseDescription(
          selectedCase.description ||
            ""
        );

        setAgentSetupChoice(null);
        setShowAgentPrompt(true);
        setShowRunGuide(false);

        setCurrentStep(
          STEPS.AGENT
        );
      },
      []
    );

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

      setSelectedEvidence(
        null
      );

      setSelectedAgent(
        null
      );

      setAgentSetupChoice(null);
      setShowAgentPrompt(false);
      setShowRunGuide(false);

      setSelectedDrive(
        null
      );

      setDrives([]);

      setSourceType(null);

      setIntegrity(null);

      setCurrentStep(
        STEPS.CREATE_CASE
      );
    }, []);

  /* ==========================================================================
     AGENT WORKFLOW
  ========================================================================== */

  const openAgentPrompt =
    useCallback(() => {
      setError("");
      setNotice("");
      setShowAgentPrompt(true);
      setShowRunGuide(false);
    }, []);

  const downloadAgent =
    useCallback(() => {
      if (!AGENT_DOWNLOAD_URL) {
        setError(
          "TrustWipe Agent download URL is not configured."
        );
        return;
      }

      window.open(
        AGENT_DOWNLOAD_URL,
        "_blank",
        "noopener,noreferrer"
      );

      setAgentSetupChoice("downloaded");
      setShowAgentPrompt(false);
      setAgentRunMessage(
        "The Agent download has started. Install it if required, then run TrustWipeAgent.exe as Administrator."
      );
      setShowRunGuide(true);
    }, []);

  const openRunGuide =
    useCallback(() => {
      setAgentSetupChoice("already-downloaded");
      setShowAgentPrompt(false);
      setAgentRunMessage(
        "Start the TrustWipe Agent and wait for the green ONLINE status before continuing."
      );
      setShowRunGuide(true);
    }, []);

  const checkAgentAndContinue =
    useCallback(async () => {
      setError("");
      setNotice("Checking TrustWipe Agent connection...");

      if (!agentSetupChoice) {
        setShowAgentPrompt(true);
        setError("Choose Download Agent or Already Downloaded first.");
        return;
      }

      const latestAgents =
        await loadAgents();

      const connectedAgents =
        latestAgents.filter(
          (agent) =>
            agent?.online !== false &&
            agent?.connected !== false
        );

      const online =
        connectedAgents.length > 0;

      if (!online) {
        setShowRunGuide(true);
        setError(
          "TrustWipe Agent is not connected yet. Start TrustWipeAgent.exe as Administrator and wait for the Agent to connect."
        );
        return;
      }

      const capable =
        connectedAgents.find((agent) =>
          Array.isArray(agent.capabilities) &&
          agent.capabilities.length > 0
            ? agent.capabilities.includes("FORENSIC_SCAN")
            : true
        );

      if (!capable) {
        setShowRunGuide(true);
        setError(
          "The connected Agent is online but does not advertise FORENSIC_SCAN capability."
        );
        return;
      }

      setSelectedAgent(capable);
      setShowRunGuide(false);
      setNotice("TrustWipe Agent is online and ready for forensic processing.");
    }, [loadAgents, agentSetupChoice]);

  const continueFromAgent =
    useCallback(() => {
      setError("");
      setNotice("");

      if (!agentSetupChoice) {
        setShowAgentPrompt(true);
        setError("Complete the Agent setup first: Download Agent or Already Downloaded.");
        return;
      }

      if (
        onlineAgents.length === 0
      ) {
        setError(
          "TrustWipe Agent is not connected. Install and run the Agent on the authorized Windows workstation."
        );
        setShowRunGuide(true);
        return;
      }

      if (
        !selectedAgent
      ) {
        setError(
          "Select an online TrustWipe Agent."
        );

        return;
      }

      const capabilities =
        Array.isArray(
          selectedAgent.capabilities
        )
          ? selectedAgent.capabilities
          : [];

      if (
        capabilities.length > 0 &&
        !capabilities.includes(
          "FORENSIC_SCAN"
        )
      ) {
        setError(
          "The selected Agent does not advertise FORENSIC_SCAN capability."
        );

        return;
      }

      setCurrentStep(
        STEPS.SOURCE
      );
    }, [
      onlineAgents.length,
      selectedAgent,
      agentSetupChoice,
    ]);

  /* ==========================================================================
     DEVICE DISCOVERY
  ========================================================================== */

  const requestDriveDiscovery =
    useCallback(
      async () => {
        if (
          !selectedAgent
        ) {
          setError(
            "Select a TrustWipe Agent first."
          );

          return;
        }

        setError("");
        setNotice("");
        setDrives([]);
        setSelectedDrive(
          null
        );
        setDrivesLoading(
          true
        );
        setDriveDiscoveryMessage(
          "Requesting physical drive information from the TrustWipe Agent..."
        );

        /*
         * The current backend/Agent architecture
         * already supports drive discovery through
         * Socket.IO.
         *
         * This frontend endpoint is intentionally
         * isolated so it can use the existing
         * discovery controller if present.
         *
         * The Dashboard/Devices flow uses GET /api/devices/discover
         * with the authenticated user session. That controller
         * delegates discovery to the connected TrustWipe Agent.
         */
        try {
          const response =
            await apiFetch(
              `/api/devices/discover`,
              {
                method: "GET",
              }
            );

          const discovered =
            extractArray(
              response,
              [
                "devices",
                "drives",
                "data",
              ]
            );

          setDrives(
            discovered
          );

          if (
            discovered.length === 0
          ) {
            setDriveDiscoveryMessage(
              "No physical drives were returned. Make sure the TrustWipe Agent is running with the required Windows permissions."
            );
          } else {
            setDriveDiscoveryMessage(
              `${discovered.length} physical device(s) discovered.`
            );
          }
        } catch (err) {
          /*
           * Keep this explicit rather than silently
           * pretending the browser can access
           * PhysicalDrive devices.
           */
          setDriveDiscoveryMessage(
            ""
          );

          setError(
            err.message ||
              "Drive discovery is not available through the backend yet."
          );
        } finally {
          setDrivesLoading(
            false
          );
        }
      },
      [selectedAgent]
    );

  /* ==========================================================================
     SOURCE SELECTION
  ========================================================================== */

  const chooseDeviceSource =
    useCallback(() => {
      setError("");
      setNotice("");

      if (
        !selectedAgent
      ) {
        setError(
          "Connect and select the TrustWipe Agent first."
        );

        return;
      }

      setSourceType(
        SOURCE_TYPES.DEVICE
      );

      setSelectedEvidence(
        null
      );

      setIntegrity(
        null
      );

      setSelectedDrive(
        null
      );

      setDrives([]);

      setNotice(
        "Physical device mode selected. Discover the authorized workstation drives."
      );
    }, [
      selectedAgent,
    ]);

  const chooseFileSource =
    useCallback(() => {
      setError("");
      setNotice("");

      setSourceType(
        SOURCE_TYPES.FILE
      );

      setSelectedDrive(
        null
      );

      setNotice(
        "Evidence file mode selected. Choose an evidence file from the Evidence Repository."
      );
    }, []);

  /* ==========================================================================
     EVIDENCE ACQUISITION
  ========================================================================== */

  const acquireEvidence =
    useCallback(
      async (file) => {
        if (!file) {
          return;
        }

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

        setLastOperation(
          null
        );

        setProgress(0);

        try {
          if (
            file.size >
            MAX_FILE_SIZE
          ) {
            throw new Error(
              "Evidence file exceeds the maximum supported size of 5 GB."
            );
          }

          if (
            file.size === 0
          ) {
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
                method:
                  "POST",

                headers:
                  authHeaders(),

                body:
                  formData,
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

          if (
            !acquired
          ) {
            throw new Error(
              "Server returned invalid evidence acquisition data."
            );
          }

          setSelectedEvidence(
            acquired
          );

          setSourceType(
            SOURCE_TYPES.FILE
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
                "Evidence acquired successfully. Verify its SHA-256 integrity before forensic processing."
            );
          }

          await loadEvidence();

          if (
            currentCase
          ) {
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
     SELECT EXISTING EVIDENCE
  ========================================================================== */

  const selectEvidence =
    useCallback(
      (item) => {
        if (busy) {
          return;
        }

        const normalized =
          normalizeEvidence(
            item
          );

        if (
          !normalized
        ) {
          return;
        }

        setSourceType(
          SOURCE_TYPES.FILE
        );

        setSelectedDrive(
          null
        );

        setSelectedEvidence(
          normalized
        );

        setIntegrity(null);

        setRecoveredFiles(
          []
        );

        setScanStats(
          null
        );

        setReport(null);

        setReportFile(
          null
        );

        setScanOutput(
          ""
        );

        setLastScanDuration(
          null
        );

        setLastOperation(
          null
        );

        setAnalysisMode(
          null
        );

        setForensicJobId(
          null
        );

        setProgress(0);

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
     INTEGRITY
  ========================================================================== */

  const verifyIntegrity =
    useCallback(
      async () => {
        if (
          sourceType !==
          SOURCE_TYPES.FILE
        ) {
          setNotice(
            "Physical device examinations are handled directly by the TrustWipe Agent. File SHA-256 verification is performed against the acquired evidence baseline."
          );

          return true;
        }

        if (
          !selectedEvidence
        ) {
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
                method:
                  "POST",

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

          if (
            !result
          ) {
            throw new Error(
              "Server returned no integrity verification result."
            );
          }

          setIntegrity(
            result
          );

          const verified =
            result.status ===
              INTEGRITY.VERIFIED &&
            result.verified === true &&
            result.hashMatch === true &&
            result.sizeMatch === true;

          if (
            verified
          ) {
            setStatus(
              STATUS.READY
            );

            setNotice(
              "Evidence integrity VERIFIED. Forensic processing is unlocked."
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
      },
      [
        sourceType,
        selectedEvidence,
        selectedEvidenceId,
        selectedFileName,
      ]
    );

  /* ==========================================================================
     PROCESS SCAN RESULT
  ========================================================================== */

  const processScanResult =
    useCallback(
      (response) => {
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
          null;

        setLastScanDuration(
          durationMs
        );

        setScanStats({
          evidenceSize:
            stats?.evidenceSize ??
            stats?.evidence_size ??
            selectedEvidence?.size ??
            null,

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

        if (
          postScan
        ) {
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

            return false;
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
            analysisMode,

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
          0;

        setNotice(
          response?.message ||
            `Forensic processing completed. ${candidateCount} candidate range(s) identified and ${validatedCount} artifact(s) validated.`
        );

        setCurrentStep(
          STEPS.RESULTS
        );

        return true;
      },
      [
        selectedEvidence,
        caseId,
        examiner,
        analysisMode,
      ]
    );

  /* ==========================================================================
     JOB POLLING
  ========================================================================== */

  const pollForensicJob =
    useCallback(
      async (jobId) => {
        try {
          const response =
            await apiFetch(
              `/api/forensic/jobs/${encodeURIComponent(
                jobId
              )}`
            );

          const job =
            response?.job ||
            response?.data?.job ||
            response?.data ||
            response;

          const jobStatus =
            String(
              job?.status ||
                job?.state ||
                "UNKNOWN"
            ).toUpperCase();

          const jobProgress =
            Number(
              job?.progress ??
                job?.percentage ??
                0
            );

          if (
            Number.isFinite(
              jobProgress
            )
          ) {
            setProgress(
              Math.max(
                0,
                Math.min(
                  100,
                  jobProgress
                )
              )
            );
          }

          setProgressMessage(
            job?.message ||
              job?.progressMessage ||
              `Forensic processing ${Math.round(
                jobProgress
              )}% complete...`
          );

          if (
            [
              "QUEUED",
              "PENDING",
              "STARTING",
              "RUNNING",
              "SCANNING",
              "IN_PROGRESS",
            ].includes(
              jobStatus
            )
          ) {
            setStatus(
              jobStatus ===
                "QUEUED"
                ? STATUS.QUEUED
                : STATUS.SCANNING
            );

            return;
          }

          if (
            [
              "COMPLETED",
              "SUCCESS",
              "DONE",
            ].includes(
              jobStatus
            )
          ) {
            stopPolling();

            setProgress(
              100
            );

            setProgressMessage(
              "Forensic processing completed. Loading results..."
            );

            processScanResult(
              job?.result ||
                job?.data ||
                job
            );

            setBusy(
              false
            );

            setProgressMessage(
              ""
            );

            return;
          }

          if (
            [
              "FAILED",
              "ERROR",
            ].includes(
              jobStatus
            )
          ) {
            stopPolling();

            setStatus(
              STATUS.FAILED
            );

            setBusy(
              false
            );

            setProgressMessage(
              ""
            );

            setError(
              typeof job?.error ===
                "object"
                ? job.error.message ||
                    "Forensic Agent reported an error."
                : job?.error ||
                    job?.message ||
                    "Forensic scan failed on the TrustWipe Agent."
            );

            return;
          }

          if (
            [
              "CANCELLED",
              "CANCELED",
            ].includes(
              jobStatus
            )
          ) {
            stopPolling();

            setStatus(
              STATUS.CANCELLED
            );

            setBusy(
              false
            );

            setProgressMessage(
              ""
            );

            setNotice(
              "Forensic scan was cancelled."
            );
          }
        } catch (err) {
          stopPolling();

          setBusy(
            false
          );

          setStatus(
            STATUS.FAILED
          );

          setProgressMessage(
            ""
          );

          setError(
            err.message ||
              "Unable to retrieve forensic job status."
          );
        }
      },
      [
        processScanResult,
        stopPolling,
      ]
    );

  /* ==========================================================================
     FORENSIC SCAN
  ========================================================================== */

  const runForensicScan =
    useCallback(
      async (
        mode = "recover"
      ) => {
        if (
          !selectedAgent
        ) {
          setError(
            "Select a TrustWipe Agent first."
          );

          return;
        }

        if (
          sourceType ===
          SOURCE_TYPES.FILE
        ) {
          if (
            !selectedEvidence
          ) {
            setError(
              "Select an evidence file first."
            );

            return;
          }

          if (
            !integrityVerified
          ) {
            setError(
              "File analysis is blocked until SHA-256 integrity is VERIFIED."
            );

            return;
          }
        }

        if (
          sourceType ===
          SOURCE_TYPES.DEVICE
        ) {
          if (
            !selectedDrivePath
          ) {
            setError(
              "Select a physical device discovered by the TrustWipe Agent."
            );

            return;
          }
        }

        if (
          !sourceType
        ) {
          setError(
            "Select an evidence source first."
          );

          return;
        }

        if (
          !caseId.trim()
        ) {
          setError(
            "Case ID is required."
          );

          return;
        }

        if (
          !examiner.trim()
        ) {
          setError(
            "Examiner name is required."
          );

          return;
        }

        const agentOnline =
          selectedAgent.online !==
            false &&
          selectedAgent.connected !==
            false;

        if (
          !agentOnline
        ) {
          setError(
            "The selected TrustWipe Agent is offline."
          );
          setShowRunGuide(true);

          return;
        }

        const capabilities =
          Array.isArray(
            selectedAgent.capabilities
          )
            ? selectedAgent.capabilities
            : [];

        if (
          capabilities.length > 0 &&
          !capabilities.includes(
            "FORENSIC_SCAN"
          )
        ) {
          setError(
            "The selected Agent does not advertise FORENSIC_SCAN capability."
          );

          return;
        }

        setBusy(true);

        setError("");
        setNotice("");

        setStatus(
          STATUS.QUEUED
        );

        setProgress(0);

        setAnalysisMode(
          mode
        );

        setRecoveredFiles(
          []
        );

        setScanStats(
          null
        );

        setReport(null);

        setReportFile(
          null
        );

        setScanOutput(
          ""
        );

        setLastOperation(
          null
        );

        setForensicJobId(
          null
        );

        const modeLabel =
          {
            scan:
              "disk scan",
            recover:
              "forensic recovery",
            analyze:
              "forensic analysis",
          }[mode] ||
          "forensic processing";

        setProgressMessage(
          `Queuing ${modeLabel} on the TrustWipe Agent...`
        );

        try {
          const body = {
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
              "FORENSIC_SCAN",

            agentId:
              selectedAgent.agentId,

            agent_id:
              selectedAgent.agentId,

            sourceType:
              sourceType,

            source_type:
              sourceType,

            /*
             * Physical device source.
             */
            devicePath:
              sourceType ===
              SOURCE_TYPES.DEVICE
                ? selectedDrivePath
                : null,

            device_path:
              sourceType ===
              SOURCE_TYPES.DEVICE
                ? selectedDrivePath
                : null,

            disk:
              sourceType ===
              SOURCE_TYPES.DEVICE
                ? selectedDrive
                : null,

            /*
             * Evidence file source.
             */
            source:
              sourceType ===
              SOURCE_TYPES.FILE
                ? selectedEvidence?.source ||
                  selectedEvidence?.sourcePath ||
                  selectedEvidence?.source_path ||
                  null
                : selectedDrivePath,

            evidence:
              sourceType ===
              SOURCE_TYPES.FILE
                ? {
                    evidenceId:
                      selectedEvidenceId,

                    fileName:
                      selectedFileName,

                    sha256:
                      integrity?.currentHash ||
                      selectedEvidence?.acquisitionHash ||
                      null,
                  }
                : null,
          };

          const response =
            await apiFetch(
              "/api/forensic/jobs",
              {
                method:
                  "POST",

                headers: {
                  "Content-Type":
                    "application/json",
                },

                body:
                  JSON.stringify(
                    body
                  ),
              }
            );

          const job =
            response?.job ||
            response?.data?.job ||
            response;

          const jobId =
            firstDefined(
              response?.jobId,
              response?.job_id,
              job?.jobId,
              job?.job_id,
              job?.id
            );

          if (
            !jobId
          ) {
            throw new Error(
              "Forensic server did not return a job ID."
            );
          }

          setForensicJobId(
            jobId
          );

          const immediateStatus =
            String(
              job?.status ||
                response?.status ||
                "QUEUED"
            ).toUpperCase();

          if (
            [
              "COMPLETED",
              "SUCCESS",
              "DONE",
            ].includes(
              immediateStatus
            )
          ) {
            processScanResult(
              job?.result ||
                response
            );

            setBusy(
              false
            );

            setProgressMessage(
              ""
            );

            return;
          }

          if (
            [
              "FAILED",
              "ERROR",
            ].includes(
              immediateStatus
            )
          ) {
            throw new Error(
              job?.error ||
                job?.message ||
                "Forensic Agent rejected the job."
            );
          }

          setStatus(
            [
              "RUNNING",
              "SCANNING",
              "IN_PROGRESS",
            ].includes(
              immediateStatus
            )
              ? STATUS.SCANNING
              : STATUS.QUEUED
          );

          setNotice(
            `Forensic job ${jobId} has been queued on ${selectedAgent.agentId}.`
          );

          stopPolling();

          await pollForensicJob(
            jobId
          );

          pollingRef.current =
            window.setInterval(
              () => {
                pollForensicJob(
                  jobId
                );
              },
              2000
            );
        } catch (err) {
          console.error(
            "FORENSIC JOB ERROR:",
            err
          );

          stopPolling();

          setStatus(
            STATUS.FAILED
          );

          setBusy(
            false
          );

          setProgressMessage(
            ""
          );

          const serverIntegrity =
            err?.response?.integrity ||
            err?.response?.data?.integrity;

          if (
            serverIntegrity
          ) {
            setIntegrity(
              normalizeIntegrity(
                serverIntegrity
              )
            );
          }

          setError(
            err?.message ||
              "Unable to dispatch forensic job to TrustWipe Agent."
          );
        }
      },
      [
        selectedAgent,
        sourceType,
        selectedEvidence,
        integrityVerified,
        selectedDrivePath,
        caseId,
        examiner,
        selectedEvidenceId,
        selectedFileName,
        selectedDrive,
        integrity,
        processScanResult,
        pollForensicJob,
        stopPolling,
      ]
    );

  /* ==========================================================================
     CANCEL
  ========================================================================== */

  const cancelForensicScan =
    useCallback(
      async () => {
        if (
          !forensicJobId
        ) {
          return;
        }

        try {
          await apiFetch(
            `/api/forensic/jobs/${encodeURIComponent(
              forensicJobId
            )}/cancel`,
            {
              method:
                "POST",
            }
          );

          setNotice(
            "Cancellation request sent to the TrustWipe Agent."
          );

          setStatus(
            STATUS.CANCELLED
          );

          stopPolling();

          setBusy(
            false
          );

          setProgressMessage(
            ""
          );
        } catch (err) {
          setError(
            err.message ||
              "Unable to cancel forensic scan."
          );
        }
      },
      [
        forensicJobId,
        stopPolling,
      ]
    );

  /* ==========================================================================
     REPORT
  ========================================================================== */

  const generateReport =
    useCallback(
      async () => {
        if (
          sourceType ===
            SOURCE_TYPES.FILE &&
          !selectedEvidence
        ) {
          setError(
            "Select evidence first."
          );

          return;
        }

        if (
          sourceType ===
            SOURCE_TYPES.FILE &&
          !integrityVerified
        ) {
          setError(
            "Report generation requires VERIFIED evidence."
          );

          return;
        }

        if (
          sourceType ===
            SOURCE_TYPES.DEVICE &&
          !selectedDrivePath
        ) {
          setError(
            "Select the physical device used for the examination."
          );

          return;
        }

        if (
          !caseId.trim()
        ) {
          setError(
            "Case ID is required."
          );

          return;
        }

        if (
          !examiner.trim()
        ) {
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
                method:
                  "POST",

                headers: {
                  "Content-Type":
                    "application/json",
                },

                body:
                  JSON.stringify({
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

                    jobId:
                      forensicJobId,

                    job_id:
                      forensicJobId,

                    agentId:
                      selectedAgent?.agentId ||
                      null,

                    sourceType:
                      sourceType,

                    source_type:
                      sourceType,

                    devicePath:
                      selectedDrivePath,

                    device_path:
                      selectedDrivePath,
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

            if (
              normalized
            ) {
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
          setBusy(
            false
          );

          setProgressMessage(
            ""
          );
        }
      },
      [
        sourceType,
        selectedEvidence,
        integrityVerified,
        selectedDrivePath,
        caseId,
        examiner,
        selectedEvidenceId,
        selectedFileName,
        forensicJobId,
        selectedAgent,
      ]
    );

  /* ==========================================================================
     DOWNLOADS
  ========================================================================== */

  const downloadRecoveredFile =
    useCallback(
      (file) => {
        if (
          !file?.path
        ) {
          setError(
            "This artifact has no download path."
          );

          return;
        }

        window.open(
          apiUrl(
            file.path
          ),
          "_blank",
          "noopener,noreferrer"
        );
      },
      []
    );

  const downloadReport =
    useCallback(() => {
      if (
        !reportFile
      ) {
        setError(
          "No report file is available."
        );

        return;
      }

      const reportPath =
        String(
          reportFile
        );

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
    }, [
      reportFile,
    ]);

  /* ==========================================================================
     RESET
  ========================================================================== */

  const resetWorkspace =
    useCallback(() => {
      if (
        busy
      ) {
        return;
      }

      stopPolling();

      setSelectedEvidence(
        null
      );

      setSelectedAgent(
        null
      );

      setAgentSetupChoice(null);
      setShowAgentPrompt(false);
      setShowRunGuide(false);

      setSelectedDrive(
        null
      );

      setDrives([]);

      setSourceType(
        null
      );

      setIntegrity(
        null
      );

      setRecoveredFiles(
        []
      );

      setScanStats(
        null
      );

      setReport(
        null
      );

      setReportFile(
        null
      );

      setScanOutput(
        ""
      );

      setLastScanDuration(
        null
      );

      setLastOperation(
        null
      );

      setAnalysisMode(
        null
      );

      setForensicJobId(
        null
      );

      setProgress(
        0
      );

      setError("");
      setNotice("");
      setShowAgentPrompt(false);
      setShowRunGuide(false);

      setStatus(
        STATUS.IDLE
      );

      setCurrentCase(
        null
      );

      setCaseId("");
      setCaseTitle("");
      setCaseDescription("");
      setExaminer("");

      setCurrentStep(
        STEPS.CASES
      );
    }, [
      busy,
      stopPolling,
    ]);

  /* ==========================================================================
     NAVIGATION
  ========================================================================== */

  const goBack =
    useCallback(() => {
      if (
        busy
      ) {
        return;
      }

      setError("");
      setNotice("");

      switch (
        currentStep
      ) {
        case STEPS.CREATE_CASE:
          setCurrentStep(
            STEPS.CASES
          );
          break;

        case STEPS.AGENT:
          setCurrentStep(
            STEPS.CREATE_CASE
          );
          break;

        case STEPS.SOURCE:
          setCurrentStep(
            STEPS.AGENT
          );
          break;

        case STEPS.EXAMINATION:
          setCurrentStep(
            STEPS.SOURCE
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
     WORKFLOW
  ========================================================================== */

  const stepItems = [
    {
      key: STEPS.AGENT,
      label: "Agent",
    },
    {
      key: STEPS.SOURCE,
      label: "Source",
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
     HEADER
  ========================================================================== */

  const renderHeader =
    () => (
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
            workstation-based forensic examination,
            recovery and evidence reporting.
          </p>
        </div>

        <div className="engine-status">
          <span
            className={
              onlineAgents.length > 0
                ? "status-dot online"
                : "status-dot offline"
            }
          />

          <div>
            <strong>
              {onlineAgents.length >
              0
                ? "FORENSIC AGENT ONLINE"
                : "FORENSIC AGENT OFFLINE"}
            </strong>

            <small>
              {onlineAgents.length >
              0
                ? `${onlineAgents.length} connected agent${
                    onlineAgents.length ===
                    1
                      ? ""
                      : "s"
                  }`
                : "No connected TrustWipe Agent"}
            </small>
          </div>

          <button
            type="button"
            className="secondary-button"
            onClick={() => {
              loadAgents();
              loadEngineStatus();
            }}
            disabled={
              busy ||
              agentLoading
            }
          >
            Refresh
          </button>
        </div>
      </header>
    );

  /* ==========================================================================
     ALERTS
  ========================================================================== */

  const renderAlerts =
    () => (
      <>
        {error && (
          <div
            className="forensics-alert danger"
            role="alert"
          >
            <strong>
              Forensic operation failed
            </strong>

            <span>
              {error}
            </span>
          </div>
        )}

        {notice &&
          !error && (
            <div
              className="forensics-alert success"
              role="status"
            >
              <strong>
                Operation status
              </strong>

              <span>
                {notice}
              </span>
            </div>
          )}

        {progressMessage && (
          <div className="operation-progress">
            <span className="spinner" />

            <span>
              {progressMessage}
            </span>

            {busy && (
              <strong>
                {Math.round(
                  progress
                )}
                %
              </strong>
            )}
          </div>
        )}
      </>
    );

  /* ==========================================================================
     WORKFLOW PROGRESS
  ========================================================================== */

  const renderProgress =
    () => (
      <div className="forensics-workflow">
        {stepItems.map(
          (
            item,
            index
          ) => {
            const completed =
              index <
              currentStepIndex;

            const active =
              item.key ===
              currentStep;

            return (
              <button
                type="button"
                key={
                  item.key
                }
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
     CASES
  ========================================================================== */

  const renderCaseSelection =
    () => (
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
            disabled={
              busy
            }
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
              Continue an investigation from
              the case repository.
            </span>

            <small>
              {cases.length} saved case
              {cases.length ===
              1
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

          {cases.length ===
          0 ? (
            <div className="empty-state">
              No forensic cases have been
              created yet.
            </div>
          ) : (
            <div className="case-list">
              {cases.map(
                (item) => (
                  <button
                    type="button"
                    key={
                      item.caseId
                    }
                    className="case-list-item"
                    onClick={() =>
                      openExistingCase(
                        item
                      )
                    }
                    disabled={
                      busy
                    }
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
                )
              )}
            </div>
          )}
        </div>
      </section>
    );

  /* ==========================================================================
     CREATE CASE
  ========================================================================== */

  const renderCreateCase =
    () => (
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
              before connecting the examination
              workstation.
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
            onClick={
              goBack
            }
            disabled={
              busy
            }
          >
            ← Back
          </button>

          <button
            type="button"
            className="primary-button"
            onClick={
              createCase
            }
            disabled={
              busy
            }
          >
            CREATE CASE →
          </button>
        </div>
      </section>
    );

  /* ==========================================================================
     AGENT INSTALLATION + SELECTION
  ========================================================================== */

  const renderAgentSetup =
    () => (
      <>
        <section className="forensics-panel">
          <div className="panel-header">
            <div>
              <span className="panel-kicker">
                STEP 01 • EXAMINATION WORKSTATION
              </span>

              <h2>TrustWipe Agent</h2>

              <p>
                The TrustWipe Agent must be downloaded, started, and connected
                before physical-device forensic operations are allowed.
              </p>
            </div>

            <span
              className={
                onlineAgents.length > 0
                  ? "secure-badge"
                  : "state-badge failed"
              }
            >
              {onlineAgents.length > 0 ? "ONLINE" : "OFFLINE"}
            </span>
          </div>

          {onlineAgents.length === 0 ? (
            <div className="agent-install-card">
              <div className="case-action-icon">🛡️</div>

              <div>
                <span className="panel-kicker">WINDOWS FORENSIC AGENT</span>

                <h3>TrustWipe Agent Required</h3>

                <p>
                  Your browser cannot directly access Windows physical disks.
                  Download the Agent, run it on the authorized examination
                  workstation, and wait until TrustWipe shows the Agent as ONLINE.
                </p>

                <ol className="agent-steps">
                  <li>Download <strong>TrustWipeAgent.exe</strong>.</li>
                  <li>If required, install the Agent.</li>
                  <li>Right-click <strong>TrustWipeAgent.exe</strong> and choose <strong>Run as Administrator</strong>.</li>
                  <li>Wait for <strong>🟢 Connected to TrustWipe Server</strong> and Agent registration.</li>
                  <li>Return here and click <strong>CHECK AGENT CONNECTION</strong>.</li>
                </ol>

                <div className="agent-actions">
                  <button
                    type="button"
                    className="primary-button"
                    onClick={downloadAgent}
                    disabled={busy}
                  >
                    ⬇ DOWNLOAD TRUSTWIPE AGENT
                  </button>

                  <button
                    type="button"
                    className="secondary-button"
                    onClick={openRunGuide}
                    disabled={busy}
                  >
                    ALREADY DOWNLOADED
                  </button>

                  <button
                    type="button"
                    className="secondary-button"
                    onClick={checkAgentAndContinue}
                    disabled={agentLoading || busy}
                  >
                    {agentLoading ? "CHECKING..." : "CHECK AGENT CONNECTION"}
                  </button>
                </div>

                <div className="forensic-policy-note">
                  <strong>Scanning is locked until an online Agent is detected.</strong>
                  <span>{agentRunMessage}</span>
                </div>
              </div>
            </div>
          ) : (
            <>
              <div className="forensics-alert success">
                <strong>🟢 TrustWipe Agent connected</strong>
                <span>
                  The authorized Windows examination workstation is ready.
                </span>
              </div>

              <div className="case-list">
                {onlineAgents.map((agent) => {
                  const selected =
                    selectedAgent?.agentId === agent.agentId;

                  const forensicCapable =
                    !Array.isArray(agent.capabilities) ||
                    agent.capabilities.length === 0 ||
                    agent.capabilities.includes("FORENSIC_SCAN");

                  return (
                    <button
                      type="button"
                      key={agent.agentId}
                      className={
                        selected
                          ? "case-list-item selected"
                          : "case-list-item"
                      }
                      onClick={() => setSelectedAgent(agent)}
                      disabled={busy}
                    >
                      <div className="case-id">🟢</div>

                      <div className="case-details">
                        <strong>{agent.hostname || "Windows Workstation"}</strong>
                        <span>Agent ID: {agent.agentId}</span>
                        <span>Platform: {agent.platform || "Windows"}</span>
                        <span>Architecture: {agent.architecture || agent.arch || "x64"}</span>
                      </div>

                      <div className="case-meta">
                        <span className="state-badge completed">ONLINE</span>
                        <span>
                          {forensicCapable
                            ? "FORENSIC_SCAN ✓"
                            : "Capability check failed"}
                        </span>
                      </div>
                    </button>
                  );
                })}
              </div>

              <div className="forensic-policy-note">
                <strong>Agent ready.</strong>
                <span>
                  Physical-device discovery and forensic processing are now unlocked.
                </span>
              </div>
            </>
          )}
        </section>

        <div className="action-row">
          <button
            type="button"
            className="secondary-button"
            onClick={goBack}
            disabled={busy}
          >
            ← Case
          </button>

          <button
            type="button"
            className="primary-button"
            onClick={continueFromAgent}
            disabled={
              busy ||
              !agentSetupChoice ||
              onlineAgents.length === 0 ||
              !selectedAgent
            }
          >
            CONTINUE TO SOURCE →
          </button>
        </div>
      </>
    );

  /* ==========================================================================
     AGENT MODALS
  ========================================================================== */

  const renderAgentModals =
    () => (
      <>
        {showAgentPrompt && (
          <div className="agent-modal-overlay">
            <div className="agent-modal">
              <h2>TrustWipe Agent Required</h2>

              <p>
                Before physical-device discovery or forensic scanning, the
                TrustWipe Agent must be installed and running on the authorized
                Windows workstation.
              </p>

              <div className="agent-features">
                <div>✔ Detects physical and external drives</div>
                <div>✔ Performs forensic processing through the Windows Agent</div>
                <div>✔ Streams forensic job progress</div>
                <div>✔ Keeps physical disk access outside the browser</div>
              </div>

              <div className="agent-actions">
                <button
                  type="button"
                  className="download-btn"
                  onClick={downloadAgent}
                >
                  ⬇ Download Agent
                </button>

                <button
                  type="button"
                  className="already-btn"
                  onClick={openRunGuide}
                >
                  ✓ Already Downloaded
                </button>

                <button
                  type="button"
                  className="cancel-btn"
                  onClick={() => setShowAgentPrompt(false)}
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}

        {showRunGuide && (
          <div className="agent-modal-overlay">
            <div className="agent-modal">
              <h2>Start TrustWipe Agent</h2>

              <p>{agentRunMessage}</p>

              <div className="agent-features">
                <div>1. Locate <b>TrustWipeAgent.exe</b>.</div>
                <div>2. Right-click it and choose <b>Run as Administrator</b>.</div>
                <div>3. If Windows SmartScreen appears, use <b>More info → Run anyway</b>.</div>
                <div>4. Wait until the Agent console shows the connection and registration messages.</div>
              </div>

              <div
                style={{
                  background: "#111",
                  color: "#0f0",
                  padding: "15px",
                  borderRadius: "8px",
                  margin: "18px 0",
                  fontFamily: "monospace",
                  textAlign: "left",
                }}
              >
                🟢 Connected to TrustWipe Server<br />
                📡 Agent registration sent<br />
              </div>

              <p>
                Keep the Agent running. This page automatically checks the
                connection every few seconds.
              </p>

              <div className="agent-actions">
                <button
                  type="button"
                  className="download-btn"
                  onClick={checkAgentAndContinue}
                  disabled={agentLoading}
                >
                  {agentLoading ? "Checking..." : "I HAVE STARTED THE AGENT — CHECK CONNECTION"}
                </button>

                <button
                  type="button"
                  className="cancel-btn"
                  onClick={() => setShowRunGuide(false)}
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        )}
      </>
    );

  const renderSourceSelection =
    () => (
      <>
        <section className="forensics-panel">
          <div className="panel-header">
            <div>
              <span className="panel-kicker">
                STEP 02 • EVIDENCE SOURCE
              </span>

              <h2>
                Choose Examination Source
              </h2>

              <p>
                Select whether the TrustWipe Agent
                should examine a physical Windows
                device or an acquired evidence file.
              </p>
            </div>

            <span className="secure-badge">
              AGENT CONTROLLED
            </span>
          </div>

          <div className="source-selection-grid">
            <button
              type="button"
              className={
                sourceType ===
                SOURCE_TYPES.DEVICE
                  ? "case-action-card selected"
                  : "case-action-card"
              }
              onClick={
                chooseDeviceSource
              }
              disabled={
                busy ||
                !selectedAgent
              }
            >
              <div className="case-action-icon">
                💽
              </div>

              <strong>
                Scan Physical Device
              </strong>

              <span>
                Discover and examine a physical
                disk connected to the authorized
                Windows workstation.
              </span>

              <small>
                Agent discovers drives →
              </small>
            </button>

            <button
              type="button"
              className={
                sourceType ===
                SOURCE_TYPES.FILE
                  ? "case-action-card selected"
                  : "case-action-card"
              }
              onClick={
                chooseFileSource
              }
              disabled={
                busy ||
                !selectedAgent
              }
            >
              <div className="case-action-icon">
                📁
              </div>

              <strong>
                Select Evidence File
              </strong>

              <span>
                Choose an evidence file already
                acquired into the TrustWipe repository.
              </span>

              <small>
                Upload or select evidence →
              </small>
            </button>
          </div>
        </section>

        {sourceType ===
          SOURCE_TYPES.DEVICE && (
          <section className="forensics-panel">
            <div className="panel-header">
              <div>
                <span className="panel-kicker">
                  PHYSICAL DEVICE DISCOVERY
                </span>

                <h2>
                  Discover Workstation Drives
                </h2>

                <p>
                  The browser never accesses a
                  physical disk directly. The TrustWipe
                  Agent discovers the authorized
                  Windows devices.
                </p>
              </div>

              <span className="secure-badge">
                WINDOWS AGENT
              </span>
            </div>

            <div className="forensic-policy-note">
              <strong>
                Selected workstation
              </strong>

              <span>
                {selectedAgent?.hostname ||
                  "Windows Workstation"}{" "}
                —{" "}
                {selectedAgent?.agentId ||
                  "No Agent"}
              </span>
            </div>

            <div className="action-row">
              <button
                type="button"
                className="primary-button"
                onClick={
                  requestDriveDiscovery
                }
                disabled={
                  busy ||
                  drivesLoading ||
                  !selectedAgent
                }
              >
                {drivesLoading
                  ? "DISCOVERING..."
                  : "DISCOVER PHYSICAL DEVICES"}
              </button>
            </div>

            {driveDiscoveryMessage && (
              <div className="forensic-policy-note">
                <strong>
                  Device discovery
                </strong>

                <span>
                  {driveDiscoveryMessage}
                </span>
              </div>
            )}

            {drives.length >
              0 && (
              <div className="case-list">
                {drives.map(
                  (
                    drive,
                    index
                  ) => {
                    const path =
                      firstDefined(
                        drive.devicePath,
                        drive.device_path,
                        drive.path,
                        drive.name
                      );

                    const selected =
                      selectedDrivePath ===
                      path;

                    return (
                      <button
                        type="button"
                        key={
                          drive.id ||
                          path ||
                          index
                        }
                        className={
                          selected
                            ? "case-list-item selected"
                            : "case-list-item"
                        }
                        onClick={() =>
                          setSelectedDrive(
                            drive
                          )
                        }
                        disabled={
                          busy
                        }
                      >
                        <div className="case-id">
                          💽
                        </div>

                        <div className="case-details">
                          <strong>
                            {drive.label ||
                              drive.name ||
                              path ||
                              `Physical Device ${
                                index + 1
                              }`}
                          </strong>

                          <span>
                            Device:{" "}
                            {path ||
                              "Unknown path"}
                          </span>

                          <span>
                            {drive.model ||
                              drive.description ||
                              drive.type ||
                              "Physical disk"}
                          </span>
                        </div>

                        <div className="case-meta">
                          <span className="state-badge completed">
                            AVAILABLE
                          </span>

                          <span>
                            {formatBytes(
                              drive.size ||
                                drive.capacity ||
                                0
                            )}
                          </span>
                        </div>
                      </button>
                    );
                  }
                )}
              </div>
            )}

            {selectedDrive && (
              <div className="forensic-policy-note">
                <strong>
                  Selected physical device
                </strong>

                <span>
                  {selectedDrivePath}
                </span>
              </div>
            )}
          </section>
        )}

        {sourceType ===
          SOURCE_TYPES.FILE && (
          <section className="forensics-panel">
            <div className="panel-header">
              <div>
                <span className="panel-kicker">
                  EVIDENCE FILE
                </span>

                <h2>
                  Select Evidence
                </h2>

                <p>
                  Upload new evidence or select an
                  existing evidence asset from the
                  repository.
                </p>
              </div>
            </div>

            <input
              ref={
                fileInputRef
              }
              type="file"
              hidden
              onChange={
                handleFileChange
              }
              disabled={
                busy
              }
            />

            <button
              type="button"
              className="upload-zone"
              onClick={() =>
                fileInputRef.current?.click()
              }
              disabled={
                busy
              }
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
                disabled={
                  busy
                }
                title="Refresh evidence"
              >
                ↻
              </button>
            </div>

            <div className="evidence-list">
              {evidence.length ===
              0 ? (
                <div className="empty-state">
                  No evidence has been acquired.
                </div>
              ) : (
                evidence.map(
                  (item) => {
                    const selected =
                      selectedEvidenceId &&
                      item.evidenceId ===
                        selectedEvidenceId;

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
                        disabled={
                          busy
                        }
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
                  }
                )
              )}
            </div>
          </section>
        )}

        <div className="action-row">
          <button
            type="button"
            className="secondary-button"
            onClick={
              goBack
            }
            disabled={
              busy
            }
          >
            ← Agent
          </button>

          <button
            type="button"
            className="primary-button"
            onClick={() =>
              setCurrentStep(
                STEPS.EXAMINATION
              )
            }
            disabled={
              busy ||
              !sourceReady
            }
          >
            CONTINUE TO EXAMINATION →
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
              Confirm Examination Source
            </h2>

            <p>
              Confirm the selected Agent, source and
              integrity controls before forensic
              processing.
            </p>
          </div>

          <span
            className={`state-badge ${status.toLowerCase()}`}
          >
            {status}
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
              AGENT
            </span>

            <strong>
              {selectedAgent?.agentId ||
                "NOT SELECTED"}
            </strong>
          </div>

          <div>
            <span>
              SOURCE
            </span>

            <strong>
              {sourceType ===
              SOURCE_TYPES.DEVICE
                ? "PHYSICAL DEVICE"
                : "EVIDENCE FILE"}
            </strong>
          </div>

          <div>
            <span>
              TARGET
            </span>

            <strong>
              {sourceType ===
              SOURCE_TYPES.DEVICE
                ? selectedDrivePath ||
                  "NOT SELECTED"
                : selectedFileName ||
                  "NOT SELECTED"}
            </strong>
          </div>
        </div>

        {sourceType ===
          SOURCE_TYPES.DEVICE && (
          <div className="integrity-card">
            <div className="integrity-card-header">
              <div>
                <span className="panel-kicker">
                  PHYSICAL DEVICE
                </span>

                <h3>
                  Agent Examination Target
                </h3>
              </div>

              <strong className="integrity-verified">
                AGENT CONTROLLED
              </strong>
            </div>

            <div className="hash-grid">
              <div>
                <span>
                  DEVICE PATH
                </span>

                <code>
                  {selectedDrivePath ||
                    "—"}
                </code>
              </div>

              <div>
                <span>
                  WORKSTATION
                </span>

                <code>
                  {selectedAgent?.hostname ||
                    "—"}
                </code>
              </div>
            </div>

            <div className="forensic-policy-note">
              <strong>
                Important
              </strong>

              <span>
                The browser does not access this
                physical device. The TrustWipe Windows
                Agent performs the authorized forensic
                examination.
              </span>
            </div>
          </div>
        )}

        {sourceType ===
          SOURCE_TYPES.FILE &&
          selectedEvidence && (
            <>
              <div className="active-evidence-banner">
                <div>
                  <span>
                    ACTIVE EVIDENCE
                  </span>

                  <strong>
                    {selectedEvidence.name}
                  </strong>
                </div>

                <div>
                  <span>
                    EVIDENCE ID
                  </span>

                  <strong>
                    {selectedEvidence.evidenceId ||
                      "—"}
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
                    {selectedEvidence.type}
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
                    disabled={
                      busy
                    }
                  >
                    {busy &&
                    status ===
                      STATUS.VERIFYING
                      ? "VERIFYING..."
                      : "CALCULATE & VERIFY SHA-256"}
                  </button>
                </div>
              </div>
            </>
          )}

        <div className="forensic-policy-note">
          <strong>
            Evidence protection policy
          </strong>

          <span>
            Processing is performed through the
            authorized TrustWipe Agent. The original
            evidence source must remain unchanged
            throughout examination.
          </span>
        </div>

        <div className="action-row">
          <button
            type="button"
            className="secondary-button"
            onClick={
              goBack
            }
            disabled={
              busy
            }
          >
            ← Source
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
              (sourceType ===
                SOURCE_TYPES.FILE &&
                !integrityVerified) ||
              (sourceType ===
                SOURCE_TYPES.DEVICE &&
                !selectedDrivePath)
            }
          >
            CONTINUE TO ANALYSIS →
          </button>
        </div>
      </section>
    );

  /* ==========================================================================
     ANALYSIS
  ========================================================================== */

  const renderAnalysis =
    () => (
      <>
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
                Execute forensic processing on the
                authorized Windows examination
                workstation.
              </p>
            </div>

            <span className="secure-badge">
              {sourceType ===
              SOURCE_TYPES.DEVICE
                ? "PHYSICAL DEVICE"
                : "EVIDENCE FILE"}
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
                TARGET
              </span>

              <strong>
                {sourceType ===
                SOURCE_TYPES.DEVICE
                  ? selectedDrivePath
                  : selectedFileName}
              </strong>
            </div>

            <div>
              <span>
                AGENT
              </span>

              <strong>
                {selectedAgent?.agentId ||
                  "NOT SELECTED"}
              </strong>
            </div>
          </div>

          {busy &&
            forensicJobId && (
              <div className="forensic-policy-note">
                <strong>
                  FORENSIC JOB
                </strong>

                <span>
                  {forensicJobId}
                </span>

                <button
                  type="button"
                  className="secondary-button small"
                  onClick={
                    cancelForensicScan
                  }
                >
                  CANCEL
                </button>
              </div>
            )}

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
                !agentSetupChoice ||
                !selectedAgent ||
                !sourceReady ||
                (sourceType ===
                  SOURCE_TYPES.FILE &&
                  !integrityVerified)
              }
            >
              <span>
                ◉
              </span>

              <strong>
                Scan Disk
              </strong>

              <small>
                Stream-scan the selected physical
                device or evidence source for forensic
                signatures.
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
                !agentSetupChoice ||
                !selectedAgent ||
                !sourceReady ||
                (sourceType ===
                  SOURCE_TYPES.FILE &&
                  !integrityVerified)
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
                recoverable forensic artifacts.
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
                !agentSetupChoice ||
                !selectedAgent ||
                !sourceReady ||
                (sourceType ===
                  SOURCE_TYPES.FILE &&
                  !integrityVerified)
              }
            >
              <span>
                ◇
              </span>

              <strong>
                Analyze
              </strong>

              <small>
                Execute forensic processing and inspect
                scan and artifact results.
              </small>
            </button>
          </div>

          <div className="forensic-policy-note">
            <strong>
              Examination target
            </strong>

            <span>
              {sourceType ===
              SOURCE_TYPES.DEVICE
                ? `Physical device ${selectedDrivePath} on ${selectedAgent?.hostname || "the authorized workstation"}`
                : `Evidence file ${selectedFileName} through ${selectedAgent?.agentId || "the TrustWipe Agent"}`}
            </span>
          </div>

          <div className="action-row">
            <button
              type="button"
              className="secondary-button"
              onClick={
                goBack
              }
              disabled={
                busy
              }
            >
              ← Examination
            </button>
          </div>
        </section>
      </>
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
                Review discovered signatures, candidate
                ranges and validated forensic artifacts.
              </p>
            </div>

            <span
              className={`state-badge ${status.toLowerCase()}`}
            >
              {status}
            </span>
          </div>

          {forensicJobId && (
            <div className="forensic-policy-note">
              <strong>
                FORENSIC JOB
              </strong>

              <span>
                {forensicJobId}
              </span>
            </div>
          )}

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

          {recoveredFiles.length ===
          0 ? (
            <div className="empty-state">
              No recovered artifacts were returned
              by the forensic engine.
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
                    (
                      file,
                      index
                    ) => {
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
                              {file.name}
                            </strong>

                            {file.sourceOffset !==
                              null &&
                              file.sourceOffset !==
                                undefined && (
                                <small>
                                  Offset:{" "}
                                  {
                                    file.sourceOffset
                                  }
                                </small>
                              )}
                          </td>

                          <td>
                            {file.type}
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
                                : `⚠ ${file.validationStatus}`}
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
                  (
                    sourceType ===
                    SOURCE_TYPES.DEVICE
                      ? "AGENT CONTROLLED"
                      : "NOT VERIFIED"
                  )}
              </strong>
            </div>

            {integrity && (
              <div className="hash-grid">
                <div>
                  <span>
                    ACQUISITION HASH
                  </span>

                  <code>
                    {integrity.originalHash ||
                      selectedEvidence?.acquisitionHash ||
                      "—"}
                  </code>
                </div>

                <div>
                  <span>
                    CURRENT HASH
                  </span>

                  <code>
                    {integrity.currentHash ||
                      "—"}
                  </code>
                </div>
              </div>
            )}
          </div>
        </section>

        <div className="action-row">
          <button
            type="button"
            className="secondary-button"
            onClick={
              goBack
            }
            disabled={
              busy
            }
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
              busy
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
                case identity, examination source,
                integrity status and recovered artifacts.
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
                SOURCE
              </span>

              <strong>
                {sourceType ===
                SOURCE_TYPES.DEVICE
                  ? selectedDrivePath
                  : selectedFileName}
              </strong>
            </div>

            <div>
              <span>
                AGENT
              </span>

              <strong>
                {selectedAgent?.agentId ||
                  "—"}
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
                  "Agent controlled"}
              </code>
            </div>

            <div>
              <span>
                CURRENT SHA-256
              </span>

              <code>
                {integrity?.currentHash ||
                  "Agent controlled"}
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
              disabled={
                busy
              }
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
              (
                sourceType ===
                SOURCE_TYPES.DEVICE
                  ? "AGENT CONTROLLED"
                  : "NOT VERIFIED"
              )}
          </strong>

          <small>
            SHA-256 evidence control
          </small>
        </div>

        <div className="summary-card">
          <span>
            FORENSIC AGENT
          </span>

          <strong>
            {onlineAgents.length >
            0
              ? "ONLINE"
              : "OFFLINE"}
          </strong>

          <small>
            {selectedAgent?.agentId ||
              "No agent selected"}
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
          STEPS.AGENT &&
          renderAgentSetup()}

        {currentStep ===
          STEPS.SOURCE &&
          renderSourceSelection()}

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

      {renderAgentModals()}

      <footer className="forensics-footer">
        <span>
          TrustWipe Digital Forensics
        </span>

        <span>
          SHA-256 Integrity Control
        </span>

        <span>
          {onlineAgents.length >
          0
            ? "Forensic Agent Online"
            : "Forensic Agent Offline"}
        </span>
      </footer>
    </div>
  );
}//Forensics.jsx

