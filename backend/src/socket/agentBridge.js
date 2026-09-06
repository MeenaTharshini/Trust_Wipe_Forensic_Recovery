// backend/src/socket/agentBridge.js

/**
 * TrustWipe Agent Bridge
 *
 * SINGLE SOURCE OF TRUTH for connected TrustWipe Agents.
 *
 * Responsibilities:
 * - Store Socket.IO instance
 * - Register/unregister Agents
 * - Track Agent heartbeat
 * - Check Agent connection
 * - Discover physical drives
 * - Dispatch forensic jobs
 * - Dispatch wipe jobs
 *
 * IMPORTANT:
 * Only predefined Socket.IO events are allowed.
 * Never use this bridge as a remote shell.
 */

let ioInstance = null;

/* =========================================================
   AGENT REGISTRY
========================================================= */

const connectedAgents = new Map();

/*
  agentId -> {
    agentId,
    deviceId,
    socketId,
    socket,
    hostname,
    platform,
    arch,
    username,
    capabilities,
    connectedAt,
    lastHeartbeat,
    status
  }
*/

/* =========================================================
   DRIVE DISCOVERY REQUESTS
========================================================= */

const pendingDriveDiscovery = new Map();

/*
  requestId -> {
    resolve,
    reject,
    timeout,
    agentId,
    userId
  }
*/

/* =========================================================
   LEGACY DISCOVERY
========================================================= */

const pendingDiscovery = new Map();

/* =========================================================
   SOCKET MANAGEMENT
========================================================= */

export const setSocket = (io) => {
  if (!io) {
    throw new Error("Invalid Socket.IO instance.");
  }

  ioInstance = io;

  console.log("✅ agentBridge: Socket.IO registered");
};

export const getSocket = () => {
  if (!ioInstance) {
    throw new Error("Socket.IO has not been initialized.");
  }

  return ioInstance;
};

export const isSocketInitialized = () => {
  return Boolean(ioInstance);
};

/* =========================================================
   AGENT SANITIZATION
========================================================= */

const sanitizeAgentRecord = (agent) => {
  if (!agent) {
    return null;
  }

  return {
    agentId: agent.agentId,
    deviceId: agent.deviceId,
    socketId: agent.socketId,
    hostname: agent.hostname,
    platform: agent.platform,
    arch: agent.arch,
    username: agent.username,

    capabilities: Array.isArray(agent.capabilities)
      ? [...agent.capabilities]
      : [],

    connectedAt: agent.connectedAt,
    lastHeartbeat: agent.lastHeartbeat,
    status: agent.status,

    connected: Boolean(
      agent.socket &&
      agent.socket.connected
    ),
  };
};

/* =========================================================
   REGISTER AGENT
========================================================= */

export const registerAgent = (agent = {}) => {
  const agentId = String(
    agent.agentId ||
    agent.deviceId ||
    ""
  ).trim();

  if (!agentId) {
    throw new Error(
      "Agent registration failed: missing agentId/deviceId."
    );
  }

  if (!agent.socket) {
    throw new Error(
      "Agent registration failed: missing socket."
    );
  }

  const now = new Date();

  const existing = connectedAgents.get(agentId);

  /*
   * If an old socket exists for this Agent,
   * disconnecting the old socket must not remove
   * the newly registered Agent.
   */
  if (
    existing &&
    existing.socket &&
    existing.socket.id !== agent.socket.id
  ) {
    try {
      existing.socket.disconnect(true);
    } catch {
      // Ignore old socket cleanup errors.
    }
  }

  const record = {
    agentId,

    deviceId: String(
      agent.deviceId ||
      agentId
    ).trim(),

    socketId: agent.socket.id,

    socket: agent.socket,

    hostname:
      agent.hostname ||
      null,

    platform:
      agent.platform ||
      null,

    arch:
      agent.arch ||
      agent.architecture ||
      null,

    username:
      agent.username ||
      null,

    capabilities:
      Array.isArray(agent.capabilities)
        ? [...agent.capabilities]
        : [],

    connectedAt:
      existing?.connectedAt ||
      agent.connectedAt ||
      now,

    lastHeartbeat: now,

    status: "online",
  };

  connectedAgents.set(agentId, record);

  console.log(
    existing
      ? `🔄 Agent reconnected: ${agentId}`
      : `🟢 Agent registered: ${agentId}`
  );

  console.log(
    `   Socket: ${record.socketId}`
  );

  console.log(
    `   Hostname: ${record.hostname || "unknown"}`
  );

  return sanitizeAgentRecord(record);
};

/* =========================================================
   UNREGISTER AGENT
========================================================= */

export const unregisterAgent = (
  agentId,
  socketId = null
) => {
  const id = String(
    agentId || ""
  ).trim();

  if (!id) {
    return false;
  }

  const agent =
    connectedAgents.get(id);

  if (!agent) {
    return false;
  }

  /*
   * Very important:
   *
   * An old socket must never delete
   * a newer Agent connection.
   */
  if (
    socketId &&
    agent.socketId !== socketId
  ) {
    console.log(
      `⚠️ Ignoring stale disconnect for Agent ${id}`
    );

    return false;
  }

  connectedAgents.delete(id);

  /*
   * Reject pending drive requests belonging
   * to this Agent.
   */
  for (
    const [
      requestId,
      pending
    ] of pendingDriveDiscovery.entries()
  ) {
    if (
      pending.agentId === id
    ) {
      clearTimeout(
        pending.timeout
      );

      pendingDriveDiscovery.delete(
        requestId
      );

      const error =
        new Error(
          `Agent disconnected during drive discovery: ${id}`
        );

      error.code =
        "AGENT_DISCONNECTED";

      pending.reject(error);
    }
  }

  console.log(
    `🔴 Agent unregistered: ${id}`
  );

  return true;
};

/* =========================================================
   GET INTERNAL AGENT
========================================================= */

export const getAgentInternal = (
  agentId
) => {
  const id = String(
    agentId || ""
  ).trim();

  if (!id) {
    return null;
  }

  return (
    connectedAgents.get(id) ||
    null
  );
};

/* =========================================================
   GET AGENT
========================================================= */

export const getAgent = (
  agentId
) => {
  return sanitizeAgentRecord(
    getAgentInternal(agentId)
  );
};

/* =========================================================
   FIND ONLINE AGENT
========================================================= */

export const findOnlineAgent = (
  agentId = null
) => {
  /*
   * If a specific Agent was requested,
   * use only that Agent.
   */
  if (agentId) {
    const agent =
      getAgentInternal(agentId);

    if (
      agent &&
      agent.status === "online" &&
      agent.socket &&
      agent.socket.connected
    ) {
      return agent;
    }

    return null;
  }

  /*
   * Otherwise find any online Agent.
   */
  for (
    const agent of connectedAgents.values()
  ) {
    if (
      agent.status === "online" &&
      agent.socket &&
      agent.socket.connected
    ) {
      return agent;
    }
  }

  return null;
};

/* =========================================================
   CHECK CONNECTION
========================================================= */

export const isAgentConnected = (
  agentId
) => {
  return Boolean(
    findOnlineAgent(agentId)
  );
};

/* =========================================================
   AGENT STATUS
========================================================= */

export const getAgentStatus = (
  agentId
) => {
  const agent =
    getAgentInternal(agentId);

  if (!agent) {
    return {
      agentId,
      connected: false,
      status: "offline",
    };
  }

  const connected =
    isAgentConnected(agentId);

  return {
    ...sanitizeAgentRecord(agent),
    connected,
    status:
      connected
        ? "online"
        : "offline",
  };
};

/* =========================================================
   LIST AGENTS
========================================================= */

export const listAgents = () => {
  return Array.from(
    connectedAgents.values()
  ).map(
    sanitizeAgentRecord
  );
};

export const listOnlineAgents = () => {
  return Array.from(
    connectedAgents.values()
  )
    .filter(
      (agent) =>
        agent.status === "online" &&
        agent.socket &&
        agent.socket.connected
    )
    .map(
      sanitizeAgentRecord
    );
};

export const getAgentCount = () => {
  return connectedAgents.size;
};

/* =========================================================
   HEARTBEAT
========================================================= */

export const updateAgentHeartbeat = (
  agentId,
  data = {}
) => {
  const id = String(
    agentId || ""
  ).trim();

  const agent =
    connectedAgents.get(id);

  if (!agent) {
    console.warn(
      `⚠️ Heartbeat from unknown Agent: ${id}`
    );

    return false;
  }

  /*
   * Make sure the socket is still the
   * registered socket.
   */
  if (
    data.socketId &&
    data.socketId !== agent.socketId
  ) {
    return false;
  }

  agent.lastHeartbeat =
    new Date();

  agent.status =
    "online";

  if (data.hostname) {
    agent.hostname =
      data.hostname;
  }

  if (data.platform) {
    agent.platform =
      data.platform;
  }

  if (
    data.arch ||
    data.architecture
  ) {
    agent.arch =
      data.arch ||
      data.architecture;
  }

  if (data.username) {
    agent.username =
      data.username;
  }

  if (
    Array.isArray(
      data.capabilities
    )
  ) {
    agent.capabilities = [
      ...data.capabilities,
    ];
  }

  connectedAgents.set(
    id,
    agent
  );

  return true;
};

/* =========================================================
   CAPABILITY CHECK
========================================================= */

export const hasAgentCapability = (
  agentId,
  capability
) => {
  const agent =
    getAgentInternal(agentId);

  if (!agent) {
    return false;
  }

  const requested =
    String(
      capability || ""
    )
      .trim()
      .toUpperCase();

  if (!requested) {
    return false;
  }

  return (
    Array.isArray(
      agent.capabilities
    ) &&
    agent.capabilities
      .map((item) =>
        String(item)
          .trim()
          .toUpperCase()
      )
      .includes(requested)
  );
};

export const agentHasCapability =
  hasAgentCapability;

/* =========================================================
   FORENSIC TASK
========================================================= */

export const sendForensicTask = (
  agentId,
  job = {}
) => {
  const agent =
    findOnlineAgent(agentId);

  if (!agent) {
    const error =
      new Error(
        `Agent is not connected: ${agentId}`
      );

    error.code =
      "AGENT_OFFLINE";

    throw error;
  }

  /*
   * Only enforce capability if the Agent
   * actually advertised capabilities.
   */
  if (
    Array.isArray(
      agent.capabilities
    ) &&
    agent.capabilities.length > 0 &&
    !hasAgentCapability(
      agentId,
      "FORENSIC_SCAN"
    )
  ) {
    const error =
      new Error(
        `Agent does not support FORENSIC_SCAN: ${agentId}`
      );

    error.code =
      "CAPABILITY_NOT_SUPPORTED";

    throw error;
  }

  const task = {
    ...job,

    agentId,

    deviceId:
      job.deviceId ||
      agent.deviceId,

    operation:
      "FORENSIC_SCAN",

    dispatchedAt:
      new Date().toISOString(),
  };

  agent.socket.emit(
    "start-forensic",
    task
  );

  console.log(
    `🔎 Forensic task sent to ${agentId}`
  );

  console.log(
    `   Job ID: ${job.jobId || "unknown"}`
  );

  return {
    success: true,
    sent: true,
    agentId,
    jobId:
      job.jobId ||
      null,
  };
};

/* =========================================================
   FORENSIC CANCEL
========================================================= */

export const sendForensicCancel = (
  agentId,
  jobId
) => {
  const agent =
    findOnlineAgent(agentId);

  if (!agent) {
    const error =
      new Error(
        `Agent is not connected: ${agentId}`
      );

    error.code =
      "AGENT_OFFLINE";

    throw error;
  }

  if (!jobId) {
    const error =
      new Error(
        "Missing forensic jobId."
      );

    error.code =
      "MISSING_JOB_ID";

    throw error;
  }

  agent.socket.emit(
    "cancel-forensic",
    {
      jobId,
      agentId,
      operation:
        "CANCEL_FORENSIC",
      requestedAt:
        new Date().toISOString(),
    }
  );

  console.log(
    `⛔ Forensic cancellation sent: ${jobId}`
  );

  return {
    success: true,
    sent: true,
    agentId,
    jobId,
  };
};

/* =========================================================
   WIPE TASK
========================================================= */

export const sendWipeTask = (
  agentId,
  job = {}
) => {
  const agent =
    findOnlineAgent(agentId);

  if (!agent) {
    const error =
      new Error(
        `Agent is not connected: ${agentId}`
      );

    error.code =
      "AGENT_OFFLINE";

    throw error;
  }

  if (
    Array.isArray(
      agent.capabilities
    ) &&
    agent.capabilities.length > 0 &&
    !hasAgentCapability(
      agentId,
      "WIPE"
    )
  ) {
    const error =
      new Error(
        `Agent does not support WIPE: ${agentId}`
      );

    error.code =
      "CAPABILITY_NOT_SUPPORTED";

    throw error;
  }

  const task = {
    ...job,

    agentId,

    deviceId:
      job.deviceId ||
      agent.deviceId,

    operation:
      "WIPE",

    dispatchedAt:
      new Date().toISOString(),
  };

  agent.socket.emit(
    "start-wipe",
    task
  );

  console.log(
    `🧹 Wipe task sent to ${agentId}`
  );

  return {
    success: true,
    sent: true,
    agentId,
    jobId:
      job.jobId ||
      job.commandId ||
      null,
  };
};

/* =========================================================
   WIPE CANCEL
========================================================= */

export const sendWipeCancel = (
  agentId,
  jobId
) => {
  const agent =
    findOnlineAgent(agentId);

  if (!agent) {
    const error =
      new Error(
        `Agent is not connected: ${agentId}`
      );

    error.code =
      "AGENT_OFFLINE";

    throw error;
  }

  if (!jobId) {
    const error =
      new Error(
        "Missing wipe jobId."
      );

    error.code =
      "MISSING_JOB_ID";

    throw error;
  }

  agent.socket.emit(
    "cancel-wipe",
    {
      jobId,
      commandId: jobId,
      agentId,
      operation:
        "CANCEL_WIPE",
      requestedAt:
        new Date().toISOString(),
    }
  );

  console.log(
    `⛔ Wipe cancellation sent: ${jobId}`
  );

  return {
    success: true,
    sent: true,
    agentId,
    jobId,
  };
};

/* =========================================================
   DRIVE DISCOVERY
========================================================= */

export const requestDriveList = (
  agentId,
  userId = null
) => {
  const agent =
    findOnlineAgent(agentId);

  if (!agent) {
    const error =
      new Error(
        `Agent is not connected: ${agentId}`
      );

    error.code =
      "AGENT_OFFLINE";

    throw error;
  }

  const requestId =
    `DRIVE-${Date.now()}-${Math.random()
      .toString(36)
      .slice(2, 10)}`;

  return new Promise(
    (resolve, reject) => {

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
          agentId:
            agent.agentId,
          userId:
            userId || null,
        }
      );

      console.log(
        "======================================"
      );

      console.log(
        "📀 DRIVE DISCOVERY REQUEST"
      );

      console.log(
        `   Agent: ${agent.agentId}`
      );

      console.log(
        `   Socket: ${agent.socketId}`
      );

      console.log(
        `   Request: ${requestId}`
      );

      console.log(
        "======================================"
      );

      /*
       * IMPORTANT:
       * Emit directly to the exact socket.
       *
       * This avoids room problems and guarantees
       * the selected Agent receives the request.
       */
      agent.socket.emit(
        "discover-drives",
        {
          requestId,

          agentId:
            agent.agentId,

          deviceId:
            agent.deviceId,

          userId:
            userId || null,

          requestedAt:
            new Date().toISOString(),
        }
      );
    }
  );
};

/* =========================================================
   RESOLVE DRIVE DISCOVERY
========================================================= */

export const resolveDriveDiscovery = (
  requestId,
  data = {}
) => {
  const id = String(
    requestId || ""
  ).trim();

  if (!id) {
    return false;
  }

  const pending =
    pendingDriveDiscovery.get(id);

  if (!pending) {
    console.warn(
      `⚠️ No pending drive discovery: ${id}`
    );

    return false;
  }

  clearTimeout(
    pending.timeout
  );

  pendingDriveDiscovery.delete(
    id
  );

  const payload = {
    ...data,

    agentId:
      data.agentId ||
      data.deviceId ||
      pending.agentId,

    deviceId:
      data.deviceId ||
      data.agentId ||
      pending.agentId,

    drives:
      Array.isArray(data.drives)
        ? data.drives
        : [],
  };

  pending.resolve(
    payload
  );

  console.log(
    `✅ Drive discovery resolved: ${id}`
  );

  console.log(
    `   Agent: ${payload.agentId}`
  );

  console.log(
    `   Drives: ${payload.drives.length}`
  );

  return true;
};

/* =========================================================
   LEGACY DISCOVERY
========================================================= */

export const addPendingDiscovery = (
  userId,
  callback
) => {
  const id = String(
    userId || ""
  ).trim();

  if (
    !id ||
    typeof callback !== "function"
  ) {
    throw new Error(
      "Invalid pending discovery registration."
    );
  }

  pendingDiscovery.set(
    id,
    callback
  );

  return true;
};

export const resolvePendingDiscovery = (
  userId,
  data
) => {
  const id = String(
    userId || ""
  ).trim();

  const callback =
    pendingDiscovery.get(id);

  if (!callback) {
    console.warn(
      `⚠️ No pending discovery for userId: ${id}`
    );

    return false;
  }

  try {
    callback(data);
  } catch (error) {
    console.error(
      "❌ Discovery callback error:",
      error.message
    );
  }

  pendingDiscovery.delete(id);

  return true;
};

export const removePendingDiscovery = (
  userId
) => {
  return pendingDiscovery.delete(
    String(userId || "").trim()
  );
};

export const listPendingDiscovery = () => {
  return Array.from(
    pendingDiscovery.keys()
  );
};

/* =========================================================
   CLEANUP
========================================================= */

export const cleanupStaleAgents = (
  timeoutMs = 90000
) => {
  const now =
    Date.now();

  let removed = 0;

  for (
    const [
      agentId,
      agent
    ] of connectedAgents.entries()
  ) {
    const lastHeartbeat =
      agent.lastHeartbeat
        ? new Date(
            agent.lastHeartbeat
          ).getTime()
        : 0;

    const socketConnected =
      Boolean(
        agent.socket &&
        agent.socket.connected
      );

    const stale =
      !socketConnected ||
      !lastHeartbeat ||
      now -
        lastHeartbeat >
        timeoutMs;

    if (stale) {
      connectedAgents.delete(
        agentId
      );

      console.log(
        `🧹 Removed stale Agent: ${agentId}`
      );

      removed++;
    }
  }

  return removed;
};

/* =========================================================
   SNAPSHOT
========================================================= */

export const getAgentSnapshot = () => {
  return {
    initialized:
      isSocketInitialized(),

    totalAgents:
      connectedAgents.size,

    onlineAgents:
      listOnlineAgents().length,

    pendingDriveDiscoveries:
      pendingDriveDiscovery.size,

    pendingDiscoveries:
      pendingDiscovery.size,

    agents:
      listAgents(),
  };
};

export const getBridgeStatus = () => {
  return {
    ready:
      isSocketInitialized(),

    connectedAgents:
      connectedAgents.size,

    onlineAgents:
      listOnlineAgents().length,

    pendingDriveDiscovery:
      pendingDriveDiscovery.size,

    pendingDiscovery:
      pendingDiscovery.size,
  };
};

export const isBridgeReady = () => {
  return Boolean(ioInstance);
};

/* =========================================================
   DEFAULT EXPORT
========================================================= */

export default {
  setSocket,
  getSocket,
  isSocketInitialized,

  registerAgent,
  unregisterAgent,

  getAgent,
  getAgentInternal,
  findOnlineAgent,

  isAgentConnected,
  getAgentStatus,

  listAgents,
  listOnlineAgents,
  getAgentCount,

  updateAgentHeartbeat,

  hasAgentCapability,
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

  cleanupStaleAgents,

  getAgentSnapshot,
  getBridgeStatus,
  isBridgeReady,
};