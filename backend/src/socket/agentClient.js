// backend/src/socket/agentClient.js

/**
 * backend/src/socket/agentClient.js
 *
 * COMPATIBILITY FACADE
 *
 * IMPORTANT:
 * This file DOES NOT maintain a connectedAgents Map.
 *
 * The ONLY Agent registry is:
 *
 *     ./agentBridge.js
 *
 * This prevents:
 *
 *   UI says Agent online
 *          ↓
 *   driveDiscovery says Agent missing
 *
 * because both now read exactly the same registry.
 */

import {
  getSocket,
  listAgents,
  listOnlineAgents,
  getAgent,
  getAgentInternal,
  isAgentConnected,
  getAgentStatus,
  getAgentCount,

  sendForensicTask,
  sendForensicCancel,

  sendWipeTask,
  sendWipeCancel,

  requestDriveList,

  getAgentSnapshot,
  getBridgeStatus,
} from "./agentBridge.js";

/* =========================================================
   SOCKET
========================================================= */

export const getIO = () => {
  return getSocket();
};

/* =========================================================
   CONNECTED AGENTS
========================================================= */

export const getConnectedAgents = () => {
  return listAgents();
};

export const getOnlineAgents = () => {
  return listOnlineAgents();
};

/* =========================================================
   SINGLE AGENT
========================================================= */

export const getAgentById = (
  agentId
) => {
  return getAgent(
    agentId
  );
};

export const getAgent = (
  agentId
) => {
  return getAgentById(
    agentId
  );
};

export const getAgentInternalById = (
  agentId
) => {
  return getAgentInternal(
    agentId
  );
};

/* =========================================================
   ONLINE CHECK
========================================================= */

export const isAgentOnline = (
  agentId
) => {
  return isAgentConnected(
    agentId
  );
};

export const isAgentConnectedById = (
  agentId
) => {
  return isAgentConnected(
    agentId
  );
};

/* =========================================================
   AGENT STATUS
========================================================= */

export const getAgentStatusById = (
  agentId
) => {
  return getAgentStatus(
    agentId
  );
};

export const getAgentCountSafe = () => {
  return getAgentCount();
};

/* =========================================================
   DRIVE DISCOVERY
========================================================= */

export const discoverDrives = (
  agentId,
  userId = null
) => {
  return requestDriveList(
    agentId,
    userId
  );
};

export const requestDriveListFromAgent = (
  agentId,
  userId = null
) => {
  return requestDriveList(
    agentId,
    userId
  );
};

/* =========================================================
   FORENSICS
========================================================= */

export const startForensicTask = (
  agentId,
  job = {}
) => {
  return sendForensicTask(
    agentId,
    job
  );
};

export const cancelForensicTask = (
  agentId,
  jobId
) => {
  return sendForensicCancel(
    agentId,
    jobId
  );
};

/* =========================================================
   WIPE
========================================================= */

export const startWipeTask = (
  agentId,
  job = {}
) => {
  return sendWipeTask(
    agentId,
    job
  );
};

export const cancelWipeTask = (
  agentId,
  jobId
) => {
  return sendWipeCancel(
    agentId,
    jobId
  );
};

/* =========================================================
   DEBUG / MONITORING
========================================================= */

export const getAgentSnapshotSafe = () => {
  return getAgentSnapshot();
};

export const getBridgeStatusSafe = () => {
  return getBridgeStatus();
};

/* =========================================================
   DEFAULT EXPORT
========================================================= */

export default {
  getIO,

  getConnectedAgents,
  getOnlineAgents,

  getAgent,
  getAgentById,
  getAgentInternalById,

  isAgentOnline,
  isAgentConnectedById,

  getAgentStatusById,
  getAgentCountSafe,

  discoverDrives,
  requestDriveListFromAgent,

  startForensicTask,
  cancelForensicTask,

  startWipeTask,
  cancelWipeTask,

  getAgentSnapshotSafe,
  getBridgeStatusSafe,
};