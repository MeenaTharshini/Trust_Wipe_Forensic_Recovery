/* ==========================================
   backend/src/socket/agentBridge.js
========================================== */

/**
 * TrustWipe Agent Bridge
 *
 * Responsibilities:
 * 1. Store Socket.IO instance
 * 2. Track connected TrustWipe agents
 * 3. Handle drive discovery
 * 4. Dispatch forensic jobs
 * 5. Dispatch wipe jobs
 * 6. Handle job cancellation
 * 7. Track heartbeat / connection status
 *
 * IMPORTANT:
 * This bridge sends only predefined Socket.IO events.
 * It must NEVER be used as a remote shell.
 */


/* =====================================================
   SOCKET INSTANCE
===================================================== */

let ioInstance = null;


/* =====================================================
   CONNECTED AGENTS
===================================================== */

const connectedAgents = new Map();
export const getConnectedAgents = () => {
  return Array.from(connectedAgents.values());
};

/* =====================================================
   LEGACY PENDING DISCOVERY
===================================================== */

const pendingDiscovery = new Map();


/* =====================================================
   DRIVE DISCOVERY REQUESTS
===================================================== */

const pendingDriveDiscovery = new Map();


/* =====================================================
   SOCKET INSTANCE MANAGEMENT
===================================================== */

/**
 * Store Socket.IO instance.
 */
export const setSocket = (io) => {

  if (!io) {
    throw new Error(
      "Invalid Socket.IO instance."
    );
  }

  ioInstance = io;

  console.log(
    "✅ Socket.IO instance registered in agentBridge."
  );

};


/**
 * Get Socket.IO instance.
 */
export const getSocket = () => {

  if (!ioInstance) {

    throw new Error(
      "Socket.IO has not been initialized."
    );

  }

  return ioInstance;

};


/**
 * Check whether Socket.IO is initialized.
 */
export const isSocketInitialized = () => {

  return ioInstance !== null;

};


/* =====================================================
   AGENT REGISTRATION
===================================================== */

/**
 * Register a TrustWipe Agent.
 */
export const registerAgent = (agent = {}) => {

  const agentId = String(
    agent.agentId ||
    agent.deviceId ||
    ""
  ).trim();


  if (!agentId) {

    throw new Error(
      "Agent registration failed: missing agentId."
    );

  }


  if (!agent.socket) {

    throw new Error(
      "Agent registration failed: missing socket."
    );

  }


  const now = new Date();

  const existing =
    connectedAgents.get(agentId);


  const agentRecord = {

    agentId,

    deviceId:
      agent.deviceId ||
      agentId,

    socketId:
      agent.socket.id,

    socket:
      agent.socket,

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
      agent.connectedAt ||
      existing?.connectedAt ||
      now,

    lastHeartbeat:
      now,

    status:
      "online",

    metadata:
      agent.metadata ||
      {},

  };


  connectedAgents.set(
    agentId,
    agentRecord
  );


  if (existing) {

    console.log(
      `🔄 Agent reconnected: ${agentId}`
    );

  } else {

    console.log(
      `🟢 Agent registered: ${agentId}`
    );

  }


  return sanitizeAgentRecord(
    agentRecord
  );

};


/* =====================================================
   AGENT UNREGISTRATION
===================================================== */

/**
 * Remove an agent.
 *
 * socketId is optional.
 * If supplied, an old socket cannot remove
 * a newer connection.
 */
export const unregisterAgent = (
  agentId,
  socketId = null
) => {

  const id =
    String(agentId || "").trim();


  if (!id) {
    return false;
  }


  const agent =
    connectedAgents.get(id);


  if (!agent) {
    return false;
  }


  if (
    socketId &&
    agent.socketId !== socketId
  ) {

    return false;

  }


  connectedAgents.delete(id);


  console.log(
    `🔴 Agent unregistered: ${id}`
  );


  return true;

};


/* =====================================================
   AGENT LOOKUP
===================================================== */

/**
 * Get sanitized agent information.
 */
export const getAgent = (
  agentId
) => {

  const id =
    String(agentId || "").trim();


  if (!id) {
    return null;
  }


  const agent =
    connectedAgents.get(id);


  if (!agent) {
    return null;
  }


  return sanitizeAgentRecord(
    agent
  );

};


/**
 * Get internal agent record.
 *
 * IMPORTANT:
 * This contains the actual Socket.IO socket.
 */
export const getAgentInternal = (
  agentId
) => {

  const id =
    String(agentId || "").trim();


  if (!id) {
    return null;
  }


  return (
    connectedAgents.get(id) ||
    null
  );

};


/* =====================================================
   AGENT CONNECTION STATUS
===================================================== */

/**
 * Check whether a specific agent is online.
 */
export const isAgentConnected = (
  agentId
) => {

  const agent =
    getAgentInternal(agentId);


  if (!agent) {
    return false;
  }


  if (
    agent.status !== "online"
  ) {

    return false;

  }


  if (
    !agent.socket ||
    !agent.socket.connected
  ) {

    return false;

  }


  return true;

};


/**
 * Get detailed agent status.
 */
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


  return {

    agentId:
      agent.agentId,

    deviceId:
      agent.deviceId,

    hostname:
      agent.hostname,

    platform:
      agent.platform,

    arch:
      agent.arch,

    username:
      agent.username,

    capabilities:
      Array.isArray(agent.capabilities)
        ? [...agent.capabilities]
        : [],

    connected:
      isAgentConnected(agentId),

    status:
      isAgentConnected(agentId)
        ? "online"
        : "offline",

    connectedAt:
      agent.connectedAt,

    lastHeartbeat:
      agent.lastHeartbeat,

  };

};


/* =====================================================
   HEARTBEAT
===================================================== */

/**
 * Update agent heartbeat.
 */
export const updateAgentHeartbeat = (
  agentId,
  data = {}
) => {

  const id =
    String(agentId || "").trim();


  if (!id) {
    return false;
  }


  const agent =
    connectedAgents.get(id);


  if (!agent) {

    console.warn(
      `⚠️ Heartbeat received from unknown agent: ${id}`
    );

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


  if (
    data.username
  ) {

    agent.username =
      data.username;

  }


  if (
    Array.isArray(
      data.capabilities
    )
  ) {

    agent.capabilities =
      [...data.capabilities];

  }


  connectedAgents.set(
    id,
    agent
  );


  return true;

};


/* =====================================================
   AGENT LIST
===================================================== */

/**
 * Return all agents.
 */
export const listAgents = () => {

  return Array.from(
    connectedAgents.values()
  ).map(
    sanitizeAgentRecord
  );

};


/**
 * Return online agents only.
 */
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


/**
 * Number of registered agents.
 */
export const getAgentCount = () => {

  return connectedAgents.size;

};


/* =====================================================
   AGENT CAPABILITY CHECK
===================================================== */

/**
 * Check whether an agent supports a capability.
 */
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
      .map(
        (item) =>
          String(item)
            .trim()
            .toUpperCase()
      )
      .includes(
        requested
      )

  );

};


/**
 * Alias for compatibility.
 */
export const agentHasCapability = (
  agentId,
  capability
) => {

  return hasAgentCapability(
    agentId,
    capability
  );

};


/* =====================================================
   FORENSIC TASK DISPATCH
===================================================== */

/**
 * Send a predefined forensic task.
 *
 * Event:
 *   start-forensic
 */
export const sendForensicTask = (
  agentId,
  job = {}
) => {

  const agent =
    getAgentInternal(agentId);


  if (!agent) {

    const error =
      new Error(
        `Agent not found: ${agentId}`
      );

    error.code =
      "AGENT_NOT_FOUND";

    throw error;

  }


  if (
    !agent.socket ||
    !agent.socket.connected
  ) {

    const error =
      new Error(
        `Agent is not connected: ${agentId}`
      );

    error.code =
      "AGENT_OFFLINE";

    throw error;

  }


  /*
   * Only enforce capability validation
   * when capabilities were actually supplied.
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
    `🔎 Forensic task dispatched to agent: ${agentId}`
  );


  console.log(
    `   Job ID: ${
      job.jobId ||
      "unknown"
    }`
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


/* =====================================================
   FORENSIC CANCELLATION
===================================================== */

/**
 * Cancel forensic job.
 *
 * Event:
 *   cancel-forensic
 */
export const sendForensicCancel = (
  agentId,
  jobId
) => {

  const agent =
    getAgentInternal(agentId);


  if (!agent) {

    const error =
      new Error(
        `Agent not found: ${agentId}`
      );

    error.code =
      "AGENT_NOT_FOUND";

    throw error;

  }


  if (
    !agent.socket ||
    !agent.socket.connected
  ) {

    const error =
      new Error(
        `Agent is offline: ${agentId}`
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


/* =====================================================
   WIPE TASK DISPATCH
===================================================== */

/**
 * Send a predefined wipe task.
 *
 * Event:
 *   start-wipe
 */
export const sendWipeTask = (
  agentId,
  job = {}
) => {

  const agent =
    getAgentInternal(agentId);


  if (!agent) {

    const error =
      new Error(
        `Agent not found: ${agentId}`
      );

    error.code =
      "AGENT_NOT_FOUND";

    throw error;

  }


  if (
    !agent.socket ||
    !agent.socket.connected
  ) {

    const error =
      new Error(
        `Agent is not connected: ${agentId}`
      );

    error.code =
      "AGENT_OFFLINE";

    throw error;

  }


  /*
   * Only enforce capability validation
   * when the agent has advertised capabilities.
   */
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
    `🧹 Wipe task dispatched to agent: ${agentId}`
  );


  console.log(
    `   Job ID: ${
      job.jobId ||
      job.commandId ||
      "unknown"
    }`
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


/* =====================================================
   WIPE CANCELLATION
===================================================== */

/**
 * Cancel wipe job.
 *
 * Event:
 *   cancel-wipe
 */
export const sendWipeCancel = (
  agentId,
  jobId
) => {

  const agent =
    getAgentInternal(agentId);


  if (!agent) {

    const error =
      new Error(
        `Agent not found: ${agentId}`
      );

    error.code =
      "AGENT_NOT_FOUND";

    throw error;

  }


  if (
    !agent.socket ||
    !agent.socket.connected
  ) {

    const error =
      new Error(
        `Agent is offline: ${agentId}`
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

      commandId:
        jobId,

      agentId,

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


/* =====================================================
   DRIVE DISCOVERY
===================================================== */

/**
 * Request physical drive information
 * from a connected TrustWipe Agent.
 *
 * Flow:
 *
 * Backend
 *   ↓
 * discover-drives
 *   ↓
 * Agent
 *   ↓
 * drive-list
 *   ↓
 * resolveDriveDiscovery()
 */
export const requestDriveList = (
  agentId,
  userId = null
) => {

  const agent =
    getAgentInternal(agentId);


  if (!agent) {

    const error =
      new Error(
        `Agent not found: ${agentId}`
      );

    error.code =
      "AGENT_NOT_FOUND";

    throw error;

  }


  if (
    !agent.socket ||
    !agent.socket.connected
  ) {

    const error =
      new Error(
        `Agent is not connected: ${agentId}`
      );

    error.code =
      "AGENT_OFFLINE";

    throw error;

  }


  return new Promise(
    (resolve, reject) => {

      const requestId =
        `DRIVE-${Date.now()}-${Math.random()
          .toString(36)
          .slice(2, 8)}`;


      const timeout =
        setTimeout(
          () => {

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

          },
          30000
        );


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
        `📀 Drive discovery requested from agent: ${agentId}`
      );


      console.log(
        `   Request ID: ${requestId}`
      );


      agent.socket.emit(
        "discover-drives",
        {

          requestId,

          agentId,

          deviceId:
            agent.deviceId,

          userId,

        }
      );

    }
  );

};


/* =====================================================
   RESOLVE DRIVE DISCOVERY
===================================================== */

/**
 * Called when the Agent sends:
 *
 * drive-list
 */
export const resolveDriveDiscovery = (
  requestId,
  data = {}
) => {

  const id =
    String(
      requestId || ""
    ).trim();


  if (!id) {
    return false;
  }


  const pending =
    pendingDriveDiscovery.get(
      id
    );


  if (!pending) {

    console.warn(
      `⚠️ No pending drive discovery request: ${id}`
    );

    return false;

  }


  clearTimeout(
    pending.timeout
  );


  pendingDriveDiscovery.delete(
    id
  );


  pending.resolve(
    data
  );


  console.log(
    `✅ Drive discovery request resolved: ${id}`
  );


  return true;

};


/* =====================================================
   LEGACY DISCOVERY SYSTEM
===================================================== */

/**
 * Register legacy discovery callback.
 */
export const addPendingDiscovery = (
  userId,
  callback
) => {

  const id =
    String(
      userId || ""
    ).trim();


  if (
    !id ||
    typeof callback !==
      "function"
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


/**
 * Resolve legacy discovery callback.
 */
export const resolvePendingDiscovery = (
  userId,
  data
) => {

  const id =
    String(
      userId || ""
    ).trim();


  const callback =
    pendingDiscovery.get(
      id
    );


  if (!callback) {

    console.warn(
      `⚠️ No pending discovery found for userId: ${id}`
    );

    return false;

  }


  try {

    callback(data);

  }
  catch (err) {

    console.error(
      "❌ Discovery callback error:",
      err.message
    );

  }


  pendingDiscovery.delete(
    id
  );


  return true;

};


/**
 * Remove legacy discovery request.
 */
export const removePendingDiscovery = (
  userId
) => {

  const id =
    String(
      userId || ""
    ).trim();


  return pendingDiscovery.delete(
    id
  );

};


/**
 * List legacy pending discoveries.
 */
export const listPendingDiscovery = () => {

  return Array.from(
    pendingDiscovery.keys()
  );

};


/* =====================================================
   STALE AGENT CLEANUP
===================================================== */

/**
 * Remove stale/offline agents.
 *
 * Default heartbeat timeout:
 * 90 seconds.
 */
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
    ]
    of connectedAgents.entries()
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
      (
        now -
        lastHeartbeat >
        timeoutMs
      );


    if (stale) {

      connectedAgents.delete(
        agentId
      );


      console.log(
        `🧹 Removed stale agent: ${agentId}`
      );


      removed++;

    }

  }


  return removed;

};


/* =====================================================
   AGENT SNAPSHOT
===================================================== */

/**
 * Get complete bridge status.
 */
export const getAgentSnapshot = () => {

  return {

    initialized:
      isSocketInitialized(),

    totalAgents:
      connectedAgents.size,

    onlineAgents:
      listOnlineAgents().length,

    pendingDiscoveries:
      pendingDiscovery.size,

    pendingDriveDiscoveries:
      pendingDriveDiscovery.size,

    agents:
      listAgents(),

  };

};


/* =====================================================
   SANITIZE AGENT
===================================================== */

/**
 * Never expose the raw Socket.IO socket
 * outside internal bridge logic.
 */
const sanitizeAgentRecord = (
  agent
) => {

  if (!agent) {
    return null;
  }


  return {

    agentId:
      agent.agentId,

    deviceId:
      agent.deviceId,

    socketId:
      agent.socketId,

    hostname:
      agent.hostname,

    platform:
      agent.platform,

    arch:
      agent.arch,

    username:
      agent.username,

    capabilities:
      Array.isArray(
        agent.capabilities
      )
        ? [...agent.capabilities]
        : [],

    connectedAt:
      agent.connectedAt,

    lastHeartbeat:
      agent.lastHeartbeat,

    status:
      agent.status,

  };

};


/* =====================================================
   PERIODIC CLEANUP
===================================================== */

const CLEANUP_INTERVAL =
  30000;


const cleanupTimer =
  setInterval(
    () => {

      try {

        cleanupStaleAgents();

      }
      catch (err) {

        console.error(
          "❌ Agent cleanup error:",
          err.message
        );

      }

    },
    CLEANUP_INTERVAL
  );


/**
 * Do not let the timer alone keep
 * the Node.js process alive.
 */
if (
  cleanupTimer &&
  typeof cleanupTimer.unref ===
    "function"
) {

  cleanupTimer.unref();

}


/* =====================================================
   BRIDGE STATUS
===================================================== */

/**
 * Check whether the bridge is ready.
 */
export const isBridgeReady = () => {

  return (
    ioInstance !== null
  );

};


/**
 * Get bridge information.
 */
export const getBridgeStatus = () => {

  return {

    ready:
      ioInstance !== null,

    connectedAgents:
      connectedAgents.size,

    pendingDiscovery:
      pendingDiscovery.size,

    pendingDriveDiscovery:
      pendingDriveDiscovery.size,

  };

};


/* =====================================================
   DEFAULT EXPORT
===================================================== */

export default {

  /* Socket */
  setSocket,
  getSocket,
  isSocketInitialized,

  /* Agents */
  registerAgent,
  unregisterAgent,
  getAgent,
  getAgentInternal,
  getAgentStatus,
  isAgentConnected,
  listAgents,
  listOnlineAgents,
  getAgentCount,

  /* Heartbeat */
  updateAgentHeartbeat,

  /* Capabilities */
  hasAgentCapability,
  agentHasCapability,

  /* Forensics */
  sendForensicTask,
  sendForensicCancel,

  /* Wipe */
  sendWipeTask,
  sendWipeCancel,

  /* Drive discovery */
  requestDriveList,
  resolveDriveDiscovery,

  /* Legacy discovery */
  addPendingDiscovery,
  resolvePendingDiscovery,
  removePendingDiscovery,
  listPendingDiscovery,

  /* Maintenance */
  cleanupStaleAgents,

  /* Monitoring */
  getAgentSnapshot,
  isBridgeReady,
  getBridgeStatus,

};