 /* ==========================================
    backend/src/socket/agentBridge.js
 ========================================== */

 /**
  * Agent Bridge
  *
  * Responsibilities:
  * 1. Store Socket.IO instance
  * 2. Track connected TrustWipe agents
  * 3. Handle drive-discovery callbacks
  * 4. Dispatch approved wipe jobs
  * 5. Dispatch approved forensic jobs
  * 6. Track agent heartbeat / connection status
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

/**
 * Key:
 *   agentId
 *
 * Value:
 * {
 *   agentId,
 *   socketId,
 *   socket,
 *   hostname,
 *   platform,
 *   arch,
 *   username,
 *   capabilities,
 *   connectedAt,
 *   lastHeartbeat,
 *   status
 * }
 */

const connectedAgents = new Map();


/* =====================================================
   PENDING DRIVE DISCOVERY
===================================================== */

/**
 * Key   : userId
 * Value : callback function
 *
 * Kept compatible with your existing discovery system.
 */

const pendingDiscovery = new Map();


/* =====================================================
   SOCKET INSTANCE MANAGEMENT
===================================================== */

/**
 * Store Socket.IO instance.
 *
 * Called from socket initialization.
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
 * Register a connected TrustWipe agent.
 *
 * @param {Object} agent
 */

export const registerAgent = (agent = {}) => {

  const agentId =
    String(
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


  const now =
    new Date();


  const existing =
    connectedAgents.get(agentId);


  /*
   * If the same agent reconnects,
   * replace the old socket information.
   */

  const agentRecord = {

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
      null,

    username:
      agent.username ||
      null,

    capabilities:
      Array.isArray(agent.capabilities)
        ? agent.capabilities
        : [],

    connectedAt:
      agent.connectedAt ||
      now,

    lastHeartbeat:
      now,

    status:
      "online",

  };


  connectedAgents.set(
    agentId,
    agentRecord
  );


  if (existing) {

    console.log(
      `🔄 Agent reconnected: ${agentId}`
    );

  }
  else {

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
 * Remove an agent from connected-agent registry.
 *
 * Usually called on Socket.IO disconnect.
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


  /*
   * If socketId is provided, make sure that
   * an old socket cannot remove a newer connection.
   */

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
 * Get a connected agent.
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
 * Get the internal agent record.
 *
 * Use this only inside backend socket logic.
 * It contains the actual socket object.
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
   AGENT STATUS
===================================================== */

/**
 * Check whether an agent is connected.
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


  /*
   * Also check Socket.IO connection.
   */

  if (
    !agent.socket ||
    !agent.socket.connected
  ) {

    return false;

  }


  return true;

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


  /*
   * Optional information sent by agent.
   */

  if (data.hostname) {

    agent.hostname =
      data.hostname;

  }


  if (data.platform) {

    agent.platform =
      data.platform;

  }


  if (Array.isArray(data.capabilities)) {

    agent.capabilities =
      data.capabilities;

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
 * Return all connected agents.
 */

export const listAgents = () => {

  return Array.from(
    connectedAgents.values()
  ).map(
    sanitizeAgentRecord
  );

};


/**
 * Return only online agents.
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
 * Number of connected agents.
 */

export const getAgentCount = () => {

  return connectedAgents.size;

};


/* =====================================================
   AGENT CAPABILITY CHECK
===================================================== */

/**
 * Check whether an agent supports a capability.
 *
 * Example:
 *
 * hasAgentCapability(
 *   "DESKTOP-123",
 *   "FORENSIC_SCAN"
 * )
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
    Array.isArray(agent.capabilities) &&
    agent.capabilities
      .map(
        (item) =>
          String(item)
            .trim()
            .toUpperCase()
      )
      .includes(requested)
  );

};


/* =====================================================
   FORENSIC TASK DISPATCH
===================================================== */

/**
 * Send a forensic scan task to an agent.
 *
 * IMPORTANT:
 * Only sends the predefined "start-forensic"
 * event. No arbitrary command execution.
 *
 * @param {String} agentId
 * @param {Object} job
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
   * Capability validation.
   */

  if (
    Array.isArray(agent.capabilities) &&
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


  /*
   * Never trust an agentId supplied inside
   * the job. Backend decides the destination.
   */

  const task = {

    ...job,

    agentId,

    operation:
      "FORENSIC_SCAN",

    dispatchedAt:
      new Date().toISOString(),

  };


  /*
   * Explicit allow-listed event.
   */

  agent.socket.emit(
    "start-forensic",
    task
  );


  console.log(
    `🔎 Forensic task dispatched to agent: ${agentId}`
  );


  console.log(
    `   Job ID: ${job.jobId || "unknown"}`
  );


  return true;

};


/* =====================================================
   FORENSIC CANCELLATION
===================================================== */

/**
 * Cancel a forensic task on an agent.
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

      operation:
        "CANCEL_FORENSIC",

      requestedAt:
        new Date().toISOString(),

    }
  );


  console.log(
    `⛔ Forensic cancellation sent: ${jobId}`
  );


  return true;

};


/* =====================================================
   WIPE TASK DISPATCH
===================================================== */

/**
 * Send a wipe task to an agent.
 *
 * Kept separate from forensic dispatch.
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
   * Capability check.
   */

  if (
    Array.isArray(agent.capabilities) &&
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


  return true;

};


/* =====================================================
   WIPE CANCELLATION
===================================================== */

/**
 * Cancel a wipe task on an agent.
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

      operation:
        "CANCEL_WIPE",

      requestedAt:
        new Date().toISOString(),

    }
  );


  console.log(
    `⛔ Wipe cancellation sent: ${jobId}`
  );


  return true;

};


/* =====================================================
   DRIVE DISCOVERY CALLBACKS
===================================================== */

/**
 * Register a pending drive discovery callback.
 *
 * @param {String} userId
 * @param {Function} callback
 */

export const addPendingDiscovery = (
  userId,
  callback
) => {

  if (
    !userId ||
    typeof callback !== "function"
  ) {

    throw new Error(
      "Invalid pending discovery registration."
    );

  }


  pendingDiscovery.set(
    String(userId),
    callback
  );

};


/**
 * Resolve a pending discovery request.
 */

export const resolvePendingDiscovery = (
  userId,
  data
) => {

  const id =
    String(userId || "");


  const callback =
    pendingDiscovery.get(id);


  if (callback) {

    try {

      callback(data);

    }
    catch (err) {

      console.error(
        "Discovery callback error:",
        err.message
      );

    }


    pendingDiscovery.delete(id);

  }
  else {

    console.warn(
      `No pending discovery found for userId: ${id}`
    );

  }

};


/**
 * Remove a pending discovery request.
 */

export const removePendingDiscovery = (
  userId
) => {

  const id =
    String(userId || "");


  if (
    pendingDiscovery.has(id)
  ) {

    pendingDiscovery.delete(id);


    console.log(
      "Pending discoveries:",
      listPendingDiscovery()
    );


    console.log(
      `Pending discovery removed for userId: ${id}`
    );

  }

};


/**
 * List pending discovery requests.
 */

export const listPendingDiscovery = () => {

  return Array.from(
    pendingDiscovery.keys()
  );

};


/* =====================================================
   CLEANUP STALE AGENTS
===================================================== */

/**
 * Mark/remove agents whose heartbeat is too old.
 *
 * Default timeout:
 * 90 seconds.
 *
 * Your agent sends heartbeat every 30 seconds,
 * so 90 seconds gives reasonable tolerance.
 */

export const cleanupStaleAgents = (
  timeoutMs = 90000
) => {

  const now =
    Date.now();


  let removed = 0;


  for (
    const [agentId, agent]
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
      now - lastHeartbeat >
        timeoutMs;


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
 * Useful for debugging/admin dashboard.
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

    agents:
      listAgents(),

  };

};


/* =====================================================
   SANITIZE AGENT RECORD
===================================================== */

/**
 * Never expose the raw Socket.IO socket object
 * outside internal bridge functions.
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
      Array.isArray(agent.capabilities)
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
   PERIODIC STALE-AGENT CLEANUP
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
          "Agent cleanup error:",
          err.message
        );

      }

    },
    CLEANUP_INTERVAL
  );


/*
 * Prevent the Node process from being kept alive
 * only because of this timer.
 */

if (
  cleanupTimer &&
  typeof cleanupTimer.unref === "function"
) {

  cleanupTimer.unref();

}


/* =====================================================
   DEFAULT EXPORT
===================================================== */

export default {

  setSocket,

  getSocket,

  isSocketInitialized,

  registerAgent,

  unregisterAgent,

  getAgent,

  getAgentInternal,

  isAgentConnected,

  updateAgentHeartbeat,

  listAgents,

  listOnlineAgents,

  getAgentCount,

  hasAgentCapability,

  sendForensicTask,

  sendForensicCancel,

  sendWipeTask,

  sendWipeCancel,

  addPendingDiscovery,

  resolvePendingDiscovery,

  removePendingDiscovery,

  listPendingDiscovery,

  cleanupStaleAgents,

  getAgentSnapshot,

};