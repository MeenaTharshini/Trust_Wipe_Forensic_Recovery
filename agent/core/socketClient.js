
// agent/core/socketClient.js

import { io } from "socket.io-client";
import os from "os";
import dotenv from "dotenv";

import { runDriveDiscovery } from "./systemEngine.js";

import {
  startWipeTask,
  cancelWipeTask,
} from "./taskEngine.js";

import {
  startForensicTask,
  cancelForensicTask,
} from "./forensicTaskEngine.js";

dotenv.config();

/* =====================================================
   SERVER CONFIG
===================================================== */

const SERVER_URL =
  process.env.SERVER_URL ||
  "https://trust-wipe-forensic-recovery-glwn.onrender.com";


/* =====================================================
   SOCKET CONNECTION
===================================================== */

const socket = io(SERVER_URL, {
  transports: ["websocket"],

  reconnection: true,

  reconnectionAttempts: Infinity,

  reconnectionDelay: 2000,

  reconnectionDelayMax: 10000,

  timeout: 10000,

  autoConnect: true,
});


/* =====================================================
   AGENT IDENTITY
===================================================== */

const AGENT_ID =
  process.env.AGENT_ID ||
  os.hostname();


/* =====================================================
   AGENT INFORMATION
===================================================== */

const AGENT_INFO = {
  deviceId: AGENT_ID,

  hostname: os.hostname(),

  platform: os.platform(),

  arch: os.arch(),

  username: os.userInfo().username,
};


/* =====================================================
   STARTUP LOG
===================================================== */

console.log("=================================");
console.log(" TrustWipe Agent Starting");
console.log("=================================");

console.log(" Agent ID :", AGENT_ID);
console.log(" Hostname :", os.hostname());
console.log(" Platform :", os.platform());
console.log(" Architecture :", os.arch());
console.log(" Server :", SERVER_URL);

console.log("=================================");


/* =====================================================
   CONNECT
===================================================== */

socket.on("connect", () => {

  console.log("");
  console.log("🟢 Connected to TrustWipe Server");
  console.log("   Socket ID:", socket.id);
  console.log("   Agent ID :", AGENT_ID);


  /* -------------------------------------------------
     REGISTER AGENT
  ------------------------------------------------- */

  socket.emit("register-agent", {

    agentId: AGENT_ID,

    deviceId: AGENT_ID,

    hostname: os.hostname(),

    platform: process.platform,

    architecture: process.arch,

    capabilities: [

      "FORENSIC_SCAN",

      "FORENSIC_RECOVER",

      "FORENSIC_ANALYZE",

      "DRIVE_DISCOVERY",

    ],

  });


  console.log("📡 Agent registration sent");

});


/* =====================================================
   REGISTRATION CONFIRMATION
===================================================== */

socket.on("agent-registered", (data) => {

  console.log(
    "✅ Agent registration confirmed:",
    data
  );

});


/* =====================================================
   DISCONNECT
===================================================== */

socket.on(
  "disconnect",
  (reason) => {

    console.log(
      "🔴 Disconnected from TrustWipe Server"
    );

    console.log(
      "   Reason:",
      reason
    );

  }
);


/* =====================================================
   SOCKET ERROR
===================================================== */

socket.on(
  "connect_error",
  (err) => {

    console.error(
      "❌ Socket connection error:",
      err.message
    );

  }
);


/* =====================================================
   HEARTBEAT
===================================================== */

setInterval(
  () => {

    if (!socket.connected) {
      return;
    }

    socket.emit(
      "heartbeat",
      {

        deviceId:
          AGENT_ID,

        timestamp:
          new Date().toISOString(),

        status:
          "online",

      }
    );

  },
  30000
);


/* =====================================================
   DRIVE DISCOVERY
===================================================== */

socket.on(
  "discover-drives",
  async (request = {}) => {

    console.log(
      "📀 Drive discovery requested"
    );


    try {

      const drives =
        await runDriveDiscovery();


      socket.emit(
        "drive-list",
        {

          success:
            true,

          requestId:
            request.requestId,

          agentId:
            AGENT_ID,

          deviceId:
            AGENT_ID,

          hostname:
            os.hostname(),

          platform:
            process.platform,

          drives,

        }
      );


      console.log(
        "📀 Drive list sent to server"
      );

    }
    catch (error) {

      console.error(
        "❌ Drive discovery failed:",
        error.message
      );


      socket.emit(
        "drive-list",
        {

          success:
            false,

          requestId:
            request.requestId,

          agentId:
            AGENT_ID,

          deviceId:
            AGENT_ID,

          drives:
            [],

          error:
            error.message,

        }
      );

    }

  }
);


/* =====================================================
   START WIPE
===================================================== */

socket.on(
  "start-wipe",
  async (job = {}) => {

    console.log("");

    console.log(
      "▶ Wipe task received"
    );

    console.log(
      "   Job ID:",
      job.jobId ||
      job.commandId ||
      "unknown"
    );

    console.log(
      "   Agent ID:",
      AGENT_ID
    );


    /* -------------------------------------------------
       VALIDATE JOB ID
    ------------------------------------------------- */

    if (
      !job.jobId &&
      !job.commandId
    ) {

      console.error(
        "❌ Wipe rejected: missing job ID"
      );


      socket.emit(
        "wipe-error",
        {

          deviceId:
            AGENT_ID,

          jobId:
            null,

          error:
            "Missing wipe job ID",

        }
      );


      return;
    }


    /* -------------------------------------------------
       ATTACH AGENT ID
    ------------------------------------------------- */

    const task = {

      ...job,

      agentId:
        AGENT_ID,

    };


    try {

      await startWipeTask(
        socket,
        task
      );

    }
    catch (err) {

      console.error(
        "❌ Wipe task failed:",
        err.message
      );


      socket.emit(
        "wipe-error",
        {

          deviceId:
            AGENT_ID,

          jobId:
            job.jobId ||
            job.commandId,

          error:
            err.message,

          code:
            err.code ||
            "WIPE_TASK_FAILED",

          timestamp:
            new Date().toISOString(),

        }
      );

    }

  }
);


/* =====================================================
   CANCEL WIPE
===================================================== */

socket.on(
  "cancel-wipe",
  async (job = {}) => {

    const jobId =
      job.jobId ||
      job.commandId;


    console.log("");

    console.log(
      "⛔ Wipe cancellation requested"
    );

    console.log(
      "   Job ID:",
      jobId
    );


    if (!jobId) {

      console.error(
        "❌ Cancel wipe rejected: missing job ID"
      );

      return;
    }


    try {

      await cancelWipeTask(
        jobId
      );


      console.log(
        "✅ Wipe cancellation processed:",
        jobId
      );

    }
    catch (err) {

      console.error(
        "❌ Wipe cancellation failed:",
        err.message
      );

    }

  }
);


/* =====================================================
   FORENSIC SOURCE NORMALIZATION
===================================================== */

/*
 * Backend may send the physical device in several
 * possible formats:
 *
 * 1. devicePath: "\\\\.\\PhysicalDrive0"
 *
 * 2. device_path: "\\\\.\\PhysicalDrive0"
 *
 * 3. disk: "\\\\.\\PhysicalDrive0"
 *
 * 4. disk: {
 *      devicePath: "\\\\.\\PhysicalDrive0"
 *    }
 *
 * 5. disk: {
 *      device_path: "\\\\.\\PhysicalDrive0"
 *    }
 *
 * Normalize all of them before starting the task.
 */

function resolveForensicDevicePath(job = {}) {

  const directPath =
    typeof job.devicePath === "string"
      ? job.devicePath.trim()
      : "";

  if (directPath) {
    return directPath;
  }


  const snakeCasePath =
    typeof job.device_path === "string"
      ? job.device_path.trim()
      : "";

  if (snakeCasePath) {
    return snakeCasePath;
  }


  if (
    typeof job.disk === "string"
  ) {

    const diskPath =
      job.disk.trim();

    if (diskPath) {
      return diskPath;
    }

  }


  if (
    job.disk &&
    typeof job.disk === "object"
  ) {

    const nestedDevicePath =
      typeof job.disk.devicePath === "string"
        ? job.disk.devicePath.trim()
        : "";

    if (nestedDevicePath) {
      return nestedDevicePath;
    }


    const nestedSnakeCasePath =
      typeof job.disk.device_path === "string"
        ? job.disk.device_path.trim()
        : "";

    if (nestedSnakeCasePath) {
      return nestedSnakeCasePath;
    }


    const nestedPath =
      typeof job.disk.path === "string"
        ? job.disk.path.trim()
        : "";

    if (nestedPath) {
      return nestedPath;
    }

  }


  return null;
}


/* =====================================================
   START FORENSIC RECOVERY
===================================================== */

socket.on(
  "start-forensic",
  async (job = {}) => {

    console.log("");

    console.log(
      "================================="
    );

    console.log(
      "🔎 FORENSIC SCAN REQUEST"
    );

    console.log(
      "================================="
    );


    console.log(
      " Job ID:",
      job.jobId ||
      "unknown"
    );

    console.log(
      " Operation ID:",
      job.operationId ||
      "unknown"
    );

    console.log(
      " Case ID:",
      job.caseId ||
      "unknown"
    );

    console.log(
      " Evidence:",
      job.fileName ||
      job.evidence?.fileName ||
      "physical-device"
    );


    /* -------------------------------------------------
       RESOLVE DEVICE PATH
    ------------------------------------------------- */

    const resolvedDevicePath =
      resolveForensicDevicePath(job);


    console.log(
      " Device Path:",
      resolvedDevicePath ||
      "unknown"
    );


    console.log(
      " Disk:",
      typeof job.disk === "object"
        ? JSON.stringify(job.disk)
        : job.disk ||
          "unknown"
    );


    console.log(
      " Source Type:",
      job.sourceType ||
      job.source_type ||
      "unknown"
    );


    console.log(
      " Agent:",
      AGENT_ID
    );


    /* -------------------------------------------------
       VALIDATE JOB ID
    ------------------------------------------------- */

    if (!job.jobId) {

      console.error(
        "❌ Forensic request rejected:" +
        " missing jobId"
      );


      socket.emit(
        "forensic-error",
        {

          deviceId:
            AGENT_ID,

          jobId:
            null,

          error:
            "Missing forensic job ID",

          code:
            "MISSING_JOB_ID",

          timestamp:
            new Date().toISOString(),

        }
      );


      return;
    }


    /* -------------------------------------------------
       VALIDATE CASE ID
    ------------------------------------------------- */

    if (!job.caseId) {

      console.error(
        "❌ Forensic request rejected:" +
        " missing caseId"
      );


      socket.emit(
        "forensic-error",
        {

          deviceId:
            AGENT_ID,

          jobId:
            job.jobId,

          error:
            "Missing case ID",

          code:
            "MISSING_CASE_ID",

          timestamp:
            new Date().toISOString(),

        }
      );


      return;
    }


    /* -------------------------------------------------
       VALIDATE DEVICE PATH
    ------------------------------------------------- */

    if (!resolvedDevicePath) {

      console.error(
        "❌ Forensic request rejected:" +
        " missing disk/devicePath"
      );


      console.error(
        "   Raw devicePath:",
        job.devicePath
      );

      console.error(
        "   Raw device_path:",
        job.device_path
      );

      console.error(
        "   Raw disk:",
        job.disk
      );


      socket.emit(
        "forensic-error",
        {

          deviceId:
            AGENT_ID,

          jobId:
            job.jobId,

          error:
            "Missing forensic source disk",

          code:
            "MISSING_DEVICE_PATH",

          timestamp:
            new Date().toISOString(),

        }
      );


      return;
    }


    /* -------------------------------------------------
       NORMALIZE FORENSIC TASK
    ------------------------------------------------- */

    const normalizedDisk = {

      devicePath:
        resolvedDevicePath,

      device_path:
        resolvedDevicePath,

    };


    const forensicTask = {

      ...job,

      agentId:
        AGENT_ID,

      operation:
        "FORENSIC_SCAN",

      devicePath:
        resolvedDevicePath,

      device_path:
        resolvedDevicePath,

      disk:
        normalizedDisk,

      sourceType:
        job.sourceType ||
        job.source_type ||
        "DEVICE",

    };


    /* -------------------------------------------------
       DEBUG FINAL TASK
    ------------------------------------------------- */

    console.log("");
    console.log(
      "📤 NORMALIZED FORENSIC TASK"
    );

    console.log(
      "   Job ID:",
      forensicTask.jobId
    );

    console.log(
      "   Case ID:",
      forensicTask.caseId
    );

    console.log(
      "   Device Path:",
      forensicTask.devicePath
    );

    console.log(
      "   Disk:",
      JSON.stringify(
        forensicTask.disk
      )
    );

    console.log(
      "   Source Type:",
      forensicTask.sourceType
    );

    console.log(
      "================================="
    );


    /* -------------------------------------------------
       START FORENSIC TASK
    ------------------------------------------------- */

    try {

      await startForensicTask(
        socket,
        forensicTask
      );

    }
    catch (err) {

      console.error(
        "❌ Forensic task failed:",
        err.message
      );


      socket.emit(
        "forensic-error",
        {

          deviceId:
            AGENT_ID,

          jobId:
            job.jobId,

          error:
            err.message,

          code:
            err.code ||
            "FORENSIC_TASK_FAILED",

          timestamp:
            new Date().toISOString(),

        }
      );

    }

  }
);


/* =====================================================
   CANCEL FORENSIC RECOVERY
===================================================== */

socket.on(
  "cancel-forensic",
  async (job = {}) => {

    const jobId =
      job.jobId ||
      job.commandId;


    console.log("");

    console.log(
      "⛔ Forensic cancellation requested"
    );

    console.log(
      "   Job ID:",
      jobId
    );


    if (!jobId) {

      console.error(
        "❌ Cancel forensic rejected:" +
        " missing job ID"
      );

      return;
    }


    try {

      await cancelForensicTask(
        jobId
      );


      console.log(
        "✅ Forensic cancellation processed:",
        jobId
      );

    }
    catch (err) {

      console.error(
        "❌ Forensic cancellation failed:",
        err.message
      );


      socket.emit(
        "forensic-error",
        {

          deviceId:
            AGENT_ID,

          jobId,

          error:
            err.message,

          code:
            err.code ||
            "FORENSIC_CANCEL_FAILED",

          timestamp:
            new Date().toISOString(),

        }
      );

    }

  }
);


/* =====================================================
   SERVER SHUTDOWN
===================================================== */

const shutdown = (
  signal
) => {

  console.log("");

  console.log(
    `🛑 ${signal} received`
  );

  console.log(
    "Disconnecting TrustWipe Agent..."
  );


  try {

    socket.disconnect();

  }
  catch (err) {

    console.error(
      "Socket disconnect error:",
      err.message
    );

  }


  process.exit(0);

};


/* =====================================================
   PROCESS SIGNALS
===================================================== */

process.on(
  "SIGINT",
  () => shutdown("SIGINT")
);

process.on(
  "SIGTERM",
  () => shutdown("SIGTERM")
);


/* =====================================================
   UNHANDLED ERRORS
===================================================== */

process.on(
  "uncaughtException",
  (err) => {

    console.error(
      "❌ Uncaught Exception:",
      err
    );

  }
);


process.on(
  "unhandledRejection",
  (reason) => {

    console.error(
      "❌ Unhandled Promise Rejection:",
      reason
    );

  }
);


/* =====================================================
   EXPORT
===================================================== */

export default socket;
