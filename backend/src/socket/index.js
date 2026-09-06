// backend/src/socket/index.js

import { Server } from "socket.io";

import {
  setSocket,
  registerAgent,
  unregisterAgent,
  updateAgentHeartbeat,

  resolveDriveDiscovery,
  resolvePendingDiscovery,

  listAgents,
  getAgent,
  isAgentConnected,

  sendForensicTask,
  sendForensicCancel,

  sendWipeTask,
  sendWipeCancel,
} from "./agentBridge.js";

/* =========================================================
   SOCKET.IO INSTANCE
========================================================= */

let io = null;

/* =========================================================
   INITIALIZE
========================================================= */

export const initAgentClient = (
  httpServer
) => {
  if (!httpServer) {
    throw new Error(
      "HTTP server is required to initialize Socket.IO."
    );
  }

  /*
   * Prevent duplicate Socket.IO servers.
   */
  if (io) {
    console.warn(
      "⚠️ TrustWipe Socket.IO already initialized."
    );

    return io;
  }

  io = new Server(
    httpServer,
    {
      cors: {
        origin: "*",
        methods: [
          "GET",
          "POST",
        ],
      },

      transports: [
        "websocket",
        "polling",
      ],

      pingInterval:
        25000,

      pingTimeout:
        60000,

      maxHttpBufferSize:
        10 * 1024 * 1024,
    }
  );

  /*
   * CRITICAL:
   *
   * Register THIS exact Socket.IO instance
   * in the SAME agentBridge module.
   */
  setSocket(io);

  console.log(
    "=========================================="
  );

  console.log(
    "🔌 TrustWipe Socket.IO Started"
  );

  console.log(
    "=========================================="
  );

  /* =======================================================
     CONNECTION
  ======================================================= */

  io.on(
    "connection",
    (socket) => {

      console.log(
        "🟢 Socket Connected:",
        socket.id
      );

      console.log(
        "   Transport:",
        socket.conn.transport.name
      );

      let registeredAgentId =
        null;

      /* ===================================================
         REGISTER AGENT
      =================================================== */

      socket.on(
        "register-agent",
        (agent = {}) => {

          try {

            const agentId =
              String(
                agent.agentId ||
                agent.deviceId ||
                ""
              ).trim();

            if (!agentId) {

              console.error(
                "❌ Agent registration rejected: missing Agent ID."
              );

              socket.emit(
                "agent-registered",
                {
                  success: false,

                  error:
                    "Missing agentId/deviceId.",
                }
              );

              return;
            }

            /*
             * Register ONLY through agentBridge.
             *
             * No Map is maintained here.
             */
            const registered =
              registerAgent({
                ...agent,

                agentId,

                deviceId:
                  agent.deviceId ||
                  agentId,

                socket,
              });

            registeredAgentId =
              registered.agentId;

            /*
             * Agent-specific room.
             *
             * This is useful for frontend broadcasts,
             * but discovery itself is sent directly
             * to the Agent socket by agentBridge.
             */
            socket.join(
              `agent:${registeredAgentId}`
            );

            console.log(
              "=========================================="
            );

            console.log(
              "✅ TRUSTWIPE AGENT REGISTERED"
            );

            console.log(
              `   Agent ID : ${registeredAgentId}`
            );

            console.log(
              `   Device ID: ${registered.deviceId}`
            );

            console.log(
              `   Socket   : ${socket.id}`
            );

            console.log(
              `   Hostname : ${registered.hostname || "unknown"}`
            );

            console.log(
              `   Platform : ${registered.platform || "unknown"}`
            );

            console.log(
              "=========================================="
            );

            /*
             * Confirm registration to Agent.
             */
            socket.emit(
              "agent-registered",
              {
                success: true,

                agentId:
                  registered.agentId,

                deviceId:
                  registered.deviceId,

                status:
                  "online",
              }
            );

            /*
             * Tell frontend/admin clients.
             */
            io.emit(
              "agent-status",
              {
                agentId:
                  registered.agentId,

                deviceId:
                  registered.deviceId,

                hostname:
                  registered.hostname,

                platform:
                  registered.platform,

                arch:
                  registered.arch,

                username:
                  registered.username,

                capabilities:
                  registered.capabilities,

                status:
                  "online",

                connected:
                  true,

                socketId:
                  registered.socketId,

                timestamp:
                  new Date().toISOString(),
              }
            );

          } catch (error) {

            console.error(
              "❌ Agent registration error:",
              error
            );

            socket.emit(
              "agent-registered",
              {
                success: false,

                error:
                  error.message,
              }
            );
          }
        }
      );

      /* ===================================================
         HEARTBEAT
      =================================================== */

      socket.on(
        "heartbeat",
        (data = {}) => {

          try {

            const agentId =
              String(
                data.agentId ||
                data.deviceId ||
                registeredAgentId ||
                ""
              ).trim();

            if (!agentId) {
              return;
            }

            /*
             * Prevent an old socket from updating
             * a newer Agent connection.
             */
            const updated =
              updateAgentHeartbeat(
                agentId,
                {
                  ...data,
                  socketId:
                    socket.id,
                }
              );

            if (!updated) {

              console.warn(
                `⚠️ Heartbeat rejected for Agent: ${agentId}`
              );

              return;
            }

            io.emit(
              "agent-status",
              {
                agentId,
                deviceId:
                  data.deviceId ||
                  agentId,

                status:
                  "online",

                connected:
                  true,

                timestamp:
                  new Date().toISOString(),
              }
            );

          } catch (error) {

            console.error(
              "❌ Heartbeat error:",
              error.message
            );
          }
        }
      );

      /* ===================================================
         DRIVE LIST FROM AGENT
      =================================================== */

      socket.on(
        "drive-list",
        (data = {}) => {

          try {

            const agentId =
              String(
                data.agentId ||
                data.deviceId ||
                registeredAgentId ||
                ""
              ).trim();

            /*
             * Security / consistency:
             * ignore a payload that claims to be
             * from another Agent.
             */
            if (
              registeredAgentId &&
              agentId &&
              agentId !==
                registeredAgentId
            ) {

              console.warn(
                `⚠️ Drive list Agent mismatch. Registered=${registeredAgentId}, payload=${agentId}`
              );

              return;
            }

            const payload = {
              ...data,

              agentId:
                agentId ||
                registeredAgentId,

              deviceId:
                data.deviceId ||
                agentId ||
                registeredAgentId,

              drives:
                Array.isArray(
                  data.drives
                )
                  ? data.drives
                  : [],

              timestamp:
                data.timestamp ||
                new Date().toISOString(),
            };

            console.log(
              "=========================================="
            );

            console.log(
              "📀 DRIVE LIST RECEIVED"
            );

            console.log(
              `   Agent: ${payload.agentId}`
            );

            console.log(
              `   Request: ${payload.requestId || "legacy"}`
            );

            console.log(
              `   Drives: ${payload.drives.length}`
            );

            console.log(
              "=========================================="
            );

            /*
             * New request-ID system.
             */
            if (payload.requestId) {

              resolveDriveDiscovery(
                payload.requestId,
                payload
              );
            }

            /*
             * Legacy user-ID system.
             */
            if (payload.userId) {

              resolvePendingDiscovery(
                payload.userId,
                payload
              );
            }

            /*
             * Forward to frontend.
             */
            io.emit(
              "drive-list",
              payload
            );

          } catch (error) {

            console.error(
              "❌ drive-list handler error:",
              error.message
            );
          }
        }
      );

      /* ===================================================
         FORENSIC PROGRESS
      =================================================== */

      socket.on(
        "forensic-progress",
        (data = {}) => {

          console.log(
            "🔎 Forensic progress:",
            data.jobId ||
              data.commandId ||
              "unknown",
            data.progress ??
              data.percent ??
              0
          );

          io.emit(
            "forensic-progress",
            {
              ...data,

              agentId:
                data.agentId ||
                registeredAgentId,

              timestamp:
                new Date().toISOString(),
            }
          );
        }
      );

      /* ===================================================
         FORENSIC RESULT
      =================================================== */

      socket.on(
        "forensic-result",
        (data = {}) => {

          console.log(
            "✅ Forensic result received:",
            data.jobId ||
              data.commandId ||
              "unknown"
          );

          io.emit(
            "forensic-result",
            {
              ...data,

              agentId:
                data.agentId ||
                registeredAgentId,

              timestamp:
                new Date().toISOString(),
            }
          );
        }
      );

      /* ===================================================
         FORENSIC COMPLETE
      =================================================== */

      socket.on(
        "forensic-complete",
        (data = {}) => {

          console.log(
            "🏁 Forensic operation completed:",
            data.jobId ||
              data.commandId ||
              "unknown"
          );

          io.emit(
            "forensic-complete",
            {
              ...data,

              agentId:
                data.agentId ||
                registeredAgentId,

              timestamp:
                new Date().toISOString(),
            }
          );
        }
      );

      /* ===================================================
         FORENSIC ERROR
      =================================================== */

      socket.on(
        "forensic-error",
        (data = {}) => {

          console.error(
            "❌ Forensic Agent error:",
            data.message ||
              data.error ||
              "Unknown forensic error"
          );

          io.emit(
            "forensic-error",
            {
              ...data,

              agentId:
                data.agentId ||
                registeredAgentId,

              timestamp:
                new Date().toISOString(),
            }
          );
        }
      );

      /* ===================================================
         WIPE PROGRESS
      =================================================== */

      socket.on(
        "wipe-progress",
        (data = {}) => {

          console.log(
            "🧹 Wipe progress:",
            data.jobId ||
              data.commandId ||
              "unknown",
            data.progress ??
              0
          );

          io.emit(
            "wipe-progress",
            {
              ...data,

              agentId:
                data.agentId ||
                registeredAgentId,

              timestamp:
                new Date().toISOString(),
            }
          );
        }
      );

      /* ===================================================
         WIPE COMPLETE
      =================================================== */

      socket.on(
        "wipe-complete",
        (data = {}) => {

          console.log(
            "🏁 Wipe completed:",
            data.jobId ||
              data.commandId ||
              "unknown"
          );

          io.emit(
            "wipe-complete",
            {
              ...data,

              agentId:
                data.agentId ||
                registeredAgentId,

              timestamp:
                new Date().toISOString(),
            }
          );
        }
      );

      /* ===================================================
         WIPE ERROR
      =================================================== */

      socket.on(
        "wipe-error",
        (data = {}) => {

          console.error(
            "❌ Wipe Agent error:",
            data.message ||
              data.error ||
              "Unknown wipe error"
          );

          io.emit(
            "wipe-error",
            {
              ...data,

              agentId:
                data.agentId ||
                registeredAgentId,

              timestamp:
                new Date().toISOString(),
            }
          );
        }
      );

      /* ===================================================
         GENERIC AGENT ERROR
      =================================================== */

      socket.on(
        "agent-error",
        (data = {}) => {

          console.error(
            "❌ Agent error:",
            data
          );

          io.emit(
            "agent-error",
            {
              ...data,

              agentId:
                data.agentId ||
                registeredAgentId,

              timestamp:
                new Date().toISOString(),
            }
          );
        }
      );

      /* ===================================================
         DISCONNECT
      =================================================== */

      socket.on(
        "disconnect",
        (reason) => {

          console.log(
            "🔴 Socket disconnected:",
            socket.id
          );

          console.log(
            "   Reason:",
            reason
          );

          /*
           * Only remove the Agent if this socket
           * is still the currently registered socket.
           */
          if (
            registeredAgentId
          ) {

            const removed =
              unregisterAgent(
                registeredAgentId,
                socket.id
              );

            if (removed) {

              io.emit(
                "agent-status",
                {
                  agentId:
                    registeredAgentId,

                  deviceId:
                    registeredAgentId,

                  status:
                    "offline",

                  connected:
                    false,

                  timestamp:
                    new Date().toISOString(),
                }
              );
            }
          }
        }
      );
    }
  );

  return io;
};

/* =========================================================
   GET SOCKET
========================================================= */

export const getIO = () => {

  if (!io) {
    throw new Error(
      "TrustWipe Socket.IO is not initialized."
    );
  }

  return io;
};

/* =========================================================
   COMPATIBILITY HELPERS
========================================================= */

/*
 * IMPORTANT:
 *
 * These functions DO NOT maintain their own Agent Map.
 * They simply read agentBridge.
 */

export const getConnectedAgents = () => {
  return listAgents();
};

export const getAgentById = (
  agentId
) => {
  return getAgent(agentId);
};

export const isAgentOnline = (
  agentId
) => {
  return isAgentConnected(
    agentId
  );
};

/* =========================================================
   DEFAULT EXPORT
========================================================= */

export default {
  initAgentClient,

  getIO,

  getConnectedAgents,

  getAgentById,

  isAgentOnline,

  sendForensicTask,
  sendForensicCancel,

  sendWipeTask,
  sendWipeCancel,
};