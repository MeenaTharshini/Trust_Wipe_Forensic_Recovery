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
  "https://trust-wipe.onrender.com";


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

  /*
   * Register this agent with backend
   */

  socket.emit(
    "register-agent",
    {
      ...AGENT_INFO,

      connectedAt: new Date().toISOString(),

      capabilities: [
        "DRIVE_DISCOVERY",
        "WIPE",
        "FORENSIC_SCAN",
      ],
    }
  );

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
        deviceId: AGENT_ID,

        timestamp:
          new Date().toISOString(),

        status: "online",
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
  async (payload = {}) => {

    console.log("");
    console.log(
      "📀 Drive discovery requested"
    );

    console.log(
      "   User:",
      payload.userId || "unknown"
    );

    try {

      /*
       * Discover physical drives
       */

      const drives =
        await runDriveDiscovery();


      console.log(
        "📀 Discovered drives:",
        drives.length
      );


      console.log(
        JSON.stringify(
          drives,
          null,
          2
        )
      );


      /*
       * Send drives to backend
       */

      socket.emit(
        "drive-list",
        {

          deviceId:
            AGENT_ID,

          userId:
            payload.userId || null,

          requestId:
            payload.requestId || null,

          drives,

          timestamp:
            new Date().toISOString(),

        }
      );


      console.log(
        "📤 Drive list sent to server"
      );

    }
    catch (err) {

      console.error(
        "❌ Drive discovery failed:",
        err.message
      );


      socket.emit(
        "drive-list",
        {

          deviceId:
            AGENT_ID,

          userId:
            payload.userId || null,

          requestId:
            payload.requestId || null,

          drives: [],

          error:
            err.message,

          timestamp:
            new Date().toISOString(),

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


    /*
     * Basic validation
     */

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

          jobId: null,

          error:
            "Missing wipe job ID",

        }
      );

      return;
    }


    /*
     * Make sure agent identity is attached
     */

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
      job.jobId || "unknown"
    );

    console.log(
      " Operation ID:",
      job.operationId || "unknown"
    );

    console.log(
      " Case ID:",
      job.caseId || "unknown"
    );

    console.log(
      " Evidence:",
      job.fileName || "unknown"
    );

    console.log(
      " Disk:",
      job.devicePath || job.disk || "unknown"
    );

    console.log(
      " Agent:",
      AGENT_ID
    );


    /* -------------------------------------------------
       VALIDATE JOB
    ------------------------------------------------- */

    if (!job.jobId) {

      console.error(
        "❌ Forensic request rejected:"
        + " missing jobId"
      );

      socket.emit(
        "forensic-error",
        {

          deviceId:
            AGENT_ID,

          jobId: null,

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


    if (!job.caseId) {

      console.error(
        "❌ Forensic request rejected:"
        + " missing caseId"
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


    /*
     * A physical disk path should be provided
     * by the backend after drive discovery.
     */

    if (
      !job.devicePath &&
      !job.disk
    ) {

      console.error(
        "❌ Forensic request rejected:"
        + " missing disk/devicePath"
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
       ATTACH AGENT ID
    ------------------------------------------------- */

    const forensicTask = {

      ...job,

      agentId:
        AGENT_ID,

      operation:
        "FORENSIC_SCAN",

    };


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
        "❌ Cancel forensic rejected:"
        + " missing job ID"
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