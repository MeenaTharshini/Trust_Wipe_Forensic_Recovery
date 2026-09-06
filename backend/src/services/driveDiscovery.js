// backend/src/services/driveDiscovery.js

import {
  listOnlineAgents,
  requestDriveList,
} from "../socket/agentBridge.js";

/**
 * ==========================================
 * API Controller
 * ==========================================
 */
export const discoverDrives = async (req, res) => {
  try {
    const result = await requestDriveDiscovery(req.user.id);

    return res.status(200).json(result);
  } catch (err) {
    console.error("Drive Discovery Error:", err);

    let status = 500;

    if (err.code === "AGENT_NOT_FOUND") {
      status = 404;
    }

    if (err.code === "AGENT_OFFLINE") {
      status = 503;
    }

    if (err.code === "DRIVE_DISCOVERY_TIMEOUT") {
      status = 504;
    }

    return res.status(status).json({
      success: false,
      message: err.message,
      code: err.code || "DRIVE_DISCOVERY_ERROR",
    });
  }
};

/**
 * ==========================================
 * Request Drive Discovery
 * ==========================================
 */
export const requestDriveDiscovery = async (userId) => {
  const agents = listOnlineAgents();

  console.log("====================================");
  console.log("CONNECTED ONLINE AGENTS");
  console.table(agents);
  console.log("====================================");

  if (!agents.length) {
    const error = new Error(
      "No TrustWipe Agent Connected"
    );

    error.code = "AGENT_NOT_FOUND";

    throw error;
  }

  // Use the first online agent
  const agent = agents[0];

  console.log(
    "Using Agent:",
    agent.deviceId || agent.agentId
  );

  const result = await requestDriveList(
    agent.agentId,
    userId
  );

  if (!result) {
    return {
      success: false,
      devices: [],
      message: "Empty response from agent",
    };
  }

  if (!Array.isArray(result.drives)) {
    return {
      success: false,
      devices: [],
      message: "Invalid drive list received",
    };
  }

  const devices = result.drives.map((drive) => ({
    ...drive,

    agentId:
      result.deviceId ||
      result.agentId ||
      agent.deviceId ||
      agent.agentId,

    discoveredAt: new Date(),
  }));

  console.log("Returning Drives:");
  console.table(devices);

  return {
    success: true,
    devices,
    message: `${devices.length} drive(s) discovered`,
  };
};