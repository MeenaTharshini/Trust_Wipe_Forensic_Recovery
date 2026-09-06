// backend/src/socket/agentBridge.js

/**
 * TrustWipe Agent Bridge
 *
 * Responsibilities:
 * - Track connected Windows Agents
 * - Register / unregister agents
 * - Heartbeat monitoring
 * - Drive discovery
 * - Forensic task dispatch
 * - Forensic task cancellation
 * - Wipe task dispatch
 * - Wipe task cancellation
 * - Agent capability checking
 * - Pending request management
 */

let ioInstance = null;

// Connected agents
const connectedAgents = new Map();

// Legacy discovery requests
const pendingDiscovery = new Map();

// Drive discovery requests
const pendingDriveDiscovery = new Map();

// ---------------------------------------------------------
// SOCKET.IO INSTANCE
// ---------------------------------------------------------

export const setSocket = (io) => {
  ioInstance = io;

  console.log("🔌 Agent Bridge socket initialized");
};

// ---------------------------------------------------------
// AGENT REGISTRATION
// ---------------------------------------------------------

export const registerAgent = (agent = {}) => {
  const agentId = String(
    agent.agentId || agent.deviceId || ""
  ).trim();

  if (!agentId) {
    throw new Error("Agent ID is required");
  }

  const existingAgent = connectedAgents.get(agentId);

  const registeredAgent = {
    agentId,
    deviceId: String(agent.deviceId || agentId).trim(),

    hostname: agent.hostname || "Unknown",
    platform: agent.platform || process.platform,
    arch: agent.arch || agent.architecture || null,

    capabilities: Array.isArray(agent.capabilities)
      ? agent.capabilities
      : [],

    socket: agent.socket || existingAgent?.socket || null,

    status: "online",

    connectedAt:
      existingAgent?.connectedAt ||
      new Date().toISOString(),

    lastHeartbeat: new Date().toISOString(),

    metadata: agent.metadata || {},

    ip:
      agent.ip ||
      existingAgent?.ip ||
      null,
  };

  connectedAgents.set(agentId, registeredAgent);

  console.log(
    `🟢 Agent registered: ${agentId} (${registeredAgent.hostname})`
  );

  return registeredAgent;
};

// ---------------------------------------------------------
// AGENT UNREGISTER
// ---------------------------------------------------------

export const unregisterAgent = (agentId) => {
  const id = String(agentId || "").trim();

  if (!id) {
    return false;
  }

  const agent = connectedAgents.get(id);

  if (!agent) {
    return false;
  }

  connectedAgents.delete(id);

  console.log(`🔴 Agent unregistered: ${id}`);

  return true;
};

// ---------------------------------------------------------
// GET AGENT
// ---------------------------------------------------------

const getAgentInternal = (agentId) => {
  const id = String(agentId || "").trim();

  if (!id) {
    return null;
  }

  return connectedAgents.get(id) || null;
};

export const getAgent = (agentId) => {
  return getAgentInternal(agentId);
};

// ---------------------------------------------------------
// AGENT CONNECTED CHECK
// ---------------------------------------------------------

export const isAgentConnected = (agentId) => {
  const agent = getAgentInternal(agentId);

  if (!agent) {
    return false;
  }

  if (!agent.socket) {
    return false;
  }

  return agent.socket.connected === true;
};

// ---------------------------------------------------------
// AGENT STATUS
// ---------------------------------------------------------

export const getAgentStatus = (agentId) => {
  const agent = getAgentInternal(agentId);

  if (!agent) {
    return {
      connected: false,
      status: "offline",
      agentId,
    };
  }

  return {
    connected: isAgentConnected(agentId),
    status: agent.status || "unknown",
    agentId: agent.agentId,
    deviceId: agent.deviceId,
    hostname: agent.hostname,
    platform: agent.platform,
    arch: agent.arch,
    capabilities: agent.capabilities || [],
    connectedAt: agent.connectedAt,
    lastHeartbeat: agent.lastHeartbeat,
  };
};

// ---------------------------------------------------------
// LIST AGENTS
// ---------------------------------------------------------

export const listAgents = () => {
  return Array.from(connectedAgents.values()).map(
    sanitizeAgentRecord
  );
};

// ---------------------------------------------------------
// HEARTBEAT
// ---------------------------------------------------------

export const updateAgentHeartbeat = (
  agentId,
  data = {}
) => {
  const id = String(agentId || "").trim();

  const agent = connectedAgents.get(id);

  if (!agent) {
    return false;
  }

  agent.lastHeartbeat =
    new Date().toISOString();

  if (Array.isArray(data.capabilities)) {
    agent.capabilities = data.capabilities;
  }

  if (data.hostname) {
    agent.hostname = data.hostname;
  }

  if (data.platform) {
    agent.platform = data.platform;
  }

  if (data.arch || data.architecture) {
    agent.arch =
      data.arch || data.architecture;
  }

  agent.status = "online";

  connectedAgents.set(id, agent);

  return true;
};

// ---------------------------------------------------------
// CAPABILITY CHECK
// ---------------------------------------------------------

export const agentHasCapability = (
  agentId,
  capability
) => {
  const agent = getAgentInternal(agentId);

  if (!agent) {
    return false;
  }

  if (!Array.isArray(agent.capabilities)) {
    return false;
  }

  return agent.capabilities.includes(
    capability
  );
};

// ---------------------------------------------------------
// FORENSIC TASK
// ---------------------------------------------------------

export const sendForensicTask = (
  agentId,
  task
) => {
  const agent = getAgentInternal(agentId);

  if (!agent) {
    const error = new Error(
      `Agent not found: ${agentId}`
    );

    error.code = "AGENT_NOT_FOUND";

    throw error;
  }

  if (
    !agent.socket ||
    !agent.socket.connected
  ) {
    const error = new Error(
      `Agent is not connected: ${agentId}`
    );

    error.code = "AGENT_OFFLINE";

    throw error;
  }

  if (
    Array.isArray(agent.capabilities) &&
    agent.capabilities.length > 0 &&
    !agent.capabilities.includes(
      "FORENSIC_SCAN"
    )
  ) {
    const error = new Error(
      `Agent ${agentId} does not support FORENSIC_SCAN`
    );

    error.code = "CAPABILITY_NOT_SUPPORTED";

    throw error;
  }

  const payload = {
    ...task,

    agentId:
      task?.agentId ||
      agent.agentId,

    deviceId:
      task?.deviceId ||
      agent.deviceId,

    timestamp:
      task?.timestamp ||
      new Date().toISOString(),
  };

  console.log(
    `🧪 Sending forensic task to agent: ${agentId}`
  );

  console.log(
    "   Job ID:",
    payload.jobId || "unknown"
  );

  console.log(
    "   Operation:",
    payload.operation || "FORENSIC_SCAN"
  );

  agent.socket.emit(
    "forensic-task",
    payload
  );

  return {
    success: true,
    agentId,
    jobId: payload.jobId || null,
    sent: true,
  };
};

// ---------------------------------------------------------
// FORENSIC CANCEL
// ---------------------------------------------------------

export const sendForensicCancel = (
  agentId,
  payload = {}
) => {
  const agent = getAgentInternal(agentId);

  if (!agent) {
    const error = new Error(
      `Agent not found: ${agentId}`
    );

    error.code = "AGENT_NOT_FOUND";

    throw error;
  }

  if (
    !agent.socket ||
    !agent.socket.connected
  ) {
    const error = new Error(
      `Agent is not connected: ${agentId}`
    );

    error.code = "AGENT_OFFLINE";

    throw error;
  }

  agent.socket.emit(
    "forensic-cancel",
    {
      ...payload,
      agentId,
      deviceId: agent.deviceId,
    }
  );

  console.log(
    `🛑 Forensic cancellation sent to agent: ${agentId}`
  );

  return {
    success: true,
    agentId,
    sent: true,
  };
};

// ---------------------------------------------------------
// WIPE TASK
// ---------------------------------------------------------

export const sendWipeTask = (
  agentId,
  task
) => {
  const agent = getAgentInternal(agentId);

  if (!agent) {
    const error = new Error(
      `Agent not found: ${agentId}`
    );

    error.code = "AGENT_NOT_FOUND";

    throw error;
  }

  if (
    !agent.socket ||
    !agent.socket.connected
  ) {
    const error = new Error(
      `Agent is not connected: ${agentId}`
    );

    error.code = "AGENT_OFFLINE";

    throw error;
  }

  const payload = {
    ...task,

    agentId:
      task?.agentId ||
      agent.agentId,

    deviceId:
      task?.deviceId ||
      agent.deviceId,

    timestamp:
      task?.timestamp ||
      new Date().toISOString(),
  };

  console.log(
    `🧹 Sending wipe task to agent: ${agentId}`
  );

  console.log(
    "   Job ID:",
    payload.jobId || "unknown"
  );

  agent.socket.emit(
    "wipe-task",
    payload
  );

  return {
    success: true,
    agentId,
    jobId: payload.jobId || null,
    sent: true,
  };
};

// ---------------------------------------------------------
// WIPE CANCEL
// ---------------------------------------------------------

export const sendWipeCancel = (
  agentId,
  payload = {}
) => {
  const agent = getAgentInternal(agentId);

  if (!agent) {
    const error = new Error(
      `Agent not found: ${agentId}`
    );

    error.code = "AGENT_NOT_FOUND";

    throw error;
  }

  if (
    !agent.socket ||
    !agent.socket.connected
  ) {
    const error = new Error(
      `Agent is not connected: ${agentId}`
    );

    error.code = "AGENT_OFFLINE";

    throw error;
  }

  agent.socket.emit(
    "wipe-cancel",
    {
      ...payload,
      agentId,
      deviceId: agent.deviceId,
    }
  );

  console.log(
    `🛑 Wipe cancellation sent to agent: ${agentId}`
  );

  return {
    success: true,
    agentId,
    sent: true,
  };
};

// =========================================================
// DRIVE DISCOVERY
// =========================================================

export const requestDriveList = (
  agentId,
  userId = null
) => {
  const agent = getAgentInternal(agentId);

  if (!agent) {
    const error = new Error(
      `Agent not found: ${agentId}`
    );

    error.code = "AGENT_NOT_FOUND";

    throw error;
  }

  if (
    !agent.socket ||
    !agent.socket.connected
  ) {
    const error = new Error(
      `Agent is not connected: ${agentId}`
    );

    error.code = "AGENT_OFFLINE";

    throw error;
  }

  return new Promise(
    (resolve, reject) => {
      const requestId =
        `DRIVE-${Date.now()}-${Math.random()
          .toString(36)
          .slice(2, 8)}`;

      const timeout =
        setTimeout(() => {
          pendingDriveDiscovery.delete(
            requestId
          );

          const error =
            new Error(
              "Timed out waiting for drive information from TrustWipe Agent."
            );

          error.code =
            "DRIVE_DISCOVERY_TIMEOUT";

          reject(error);
        }, 30000);

      pendingDriveDiscovery.set(
        requestId,
        {
          resolve,
          reject,
          timeout,
          agentId,
          userId,
        }
      );

      console.log(
        `📀 Requesting drive discovery from agent: ${agentId}`
      );

      console.log(
        "   Request ID:",
        requestId
      );

      agent.socket.emit(
        "discover-drives",
        {
          requestId,
          agentId,
          deviceId: agent.deviceId,
          userId,
        }
      );
    }
  );
};

// ---------------------------------------------------------
// RESOLVE DRIVE DISCOVERY
// ---------------------------------------------------------

export const resolveDriveDiscovery = (
  requestId,
  data = {}
) => {
  const id = String(
    requestId || ""
  ).trim();

  const pending =
    pendingDriveDiscovery.get(id);

  if (!pending) {
    console.warn(
      "⚠️ No pending drive discovery request:",
      id
    );

    return false;
  }

  clearTimeout(
    pending.timeout
  );

  pendingDriveDiscovery.delete(id);

  pending.resolve(data);

  console.log(
    "✅ Drive discovery request resolved:",
    id
  );

  return true;
};

// ---------------------------------------------------------
// LEGACY DRIVE DISCOVERY / USER DISCOVERY
// ---------------------------------------------------------

export const addPendingDiscovery = (
  userId,
  resolve,
  reject
) => {
  const id = String(
    userId || ""
  ).trim();

  if (!id) {
    return false;
  }

  pendingDiscovery.set(
    id,
    {
      resolve,
      reject,
      createdAt: Date.now(),
    }
  );

  return true;
};

export const resolvePendingDiscovery = (
  userId,
  data = {}
) => {
  const id = String(
    userId || ""
  ).trim();

  const pending =
    pendingDiscovery.get(id);

  if (!pending) {
    return false;
  }

  pendingDiscovery.delete(id);

  if (
    typeof pending.resolve ===
    "function"
  ) {
    pending.resolve(data);
  }

  return true;
};

export const removePendingDiscovery = (
  userId
) => {
  const id = String(
    userId || ""
  ).trim();

  return pendingDiscovery.delete(id);
};

export const listPendingDiscovery = () => {
  return Array.from(
    pendingDiscovery.keys()
  );
};

// =========================================================
// AGENT SNAPSHOT
// =========================================================

export const getAgentSnapshot = () => {
  return Array.from(
    connectedAgents.values()
  ).map((agent) => ({
    agentId: agent.agentId,
    deviceId: agent.deviceId,
    hostname: agent.hostname,
    platform: agent.platform,
    arch: agent.arch,
    capabilities:
      agent.capabilities || [],
    status: agent.status,
    connected:
      !!agent.socket?.connected,
    connectedAt:
      agent.connectedAt,
    lastHeartbeat:
      agent.lastHeartbeat,
  }));
};

// ---------------------------------------------------------
// SANITIZE AGENT
// ---------------------------------------------------------

export const sanitizeAgentRecord = (
  agent
) => {
  if (!agent) {
    return null;
  }

  return {
    agentId: agent.agentId,
    deviceId: agent.deviceId,

    hostname:
      agent.hostname ||
      "Unknown",

    platform:
      agent.platform ||
      "Unknown",

    arch:
      agent.arch ||
      null,

    capabilities:
      Array.isArray(
        agent.capabilities
      )
        ? agent.capabilities
        : [],

    status:
      agent.socket?.connected
        ? "online"
        : "offline",

    connected:
      !!agent.socket?.connected,

    connectedAt:
      agent.connectedAt ||
      null,

    lastHeartbeat:
      agent.lastHeartbeat ||
      null,

    ip:
      agent.ip ||
      null,

    metadata:
      agent.metadata ||
      {},
  };
};

// =========================================================
// STALE AGENT CLEANUP
// =========================================================

const HEARTBEAT_TIMEOUT =
  2 * 60 * 1000;

const cleanupStaleAgents = () => {
  const now = Date.now();

  for (
    const [agentId, agent]
    of connectedAgents.entries()
  ) {
    if (!agent.lastHeartbeat) {
      continue;
    }

    const heartbeatTime =
      new Date(
        agent.lastHeartbeat
      ).getTime();

    if (
      Number.isNaN(
        heartbeatTime
      )
    ) {
      continue;
    }

    if (
      now - heartbeatTime >
      HEARTBEAT_TIMEOUT
    ) {
      console.warn(
        `⚠️ Removing stale agent: ${agentId}`
      );

      try {
        if (
          agent.socket &&
          agent.socket.connected
        ) {
          agent.socket.disconnect(
            true
          );
        }
      } catch (err) {
        console.error(
          "Agent disconnect error:",
          err.message
        );
      }

      connectedAgents.delete(
        agentId
      );
    }
  }
};

// Run cleanup every minute
setInterval(
  cleanupStaleAgents,
  60 * 1000
);

// =========================================================
// SOCKET STATUS
// =========================================================

export const isBridgeReady = () => {
  return !!ioInstance;
};

export const getBridgeStatus = () => {
  return {
    ready: !!ioInstance,
    connectedAgents:
      connectedAgents.size,
    pendingDiscovery:
      pendingDiscovery.size,
    pendingDriveDiscovery:
      pendingDriveDiscovery.size,
  };
};

// =========================================================
// DEFAULT EXPORT
// =========================================================

export default {
  setSocket,

  registerAgent,
  unregisterAgent,

  getAgent,
  getAgentStatus,
  listAgents,
  isAgentConnected,

  updateAgentHeartbeat,
  agentHasCapability,

  sendForensicTask,
  sendForensicCancel,

  sendWipeTask,
  sendWipeCancel,

  requestDriveList,
  resolveDriveDiscovery,

  addPendingDiscovery,
  resolvePendingDiscovery,
  removePendingDiscovery,
  listPendingDiscovery,

  getAgentSnapshot,
  sanitizeAgentRecord,

  isBridgeReady,
  getBridgeStatus,
};