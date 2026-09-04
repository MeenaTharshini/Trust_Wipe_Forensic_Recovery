/* ==========================================
   backend/src/socket/index.js
========================================== */

import { Server } from "socket.io";

import {
  setSocket,
  registerAgent,
  unregisterAgent,
  updateAgentHeartbeat,
  resolvePendingDiscovery,
  getAgent as getBridgeAgent,
  listAgents,
  isAgentConnected,
} from "./agentBridge.js";

import WipeJob from "../models/WipeJob.js";
import Device from "../models/Device.js";
import Certificate from "../models/Certificate.js";

import {
  generateCertificate,
} from "../certificateEngine/generateCertificate.js";


/* =====================================================
   SOCKET INSTANCE
===================================================== */

let io = null;


/* =====================================================
   INITIALIZE SOCKET.IO
===================================================== */

export const initAgentClient = (
  httpServer
) => {

  if (!httpServer) {

    throw new Error(
      "HTTP server is required to initialize Socket.IO."
    );

  }


  /*
   * Prevent accidental duplicate initialization.
   */

  if (io) {

    console.warn(
      "⚠️ Socket.IO is already initialized."
    );

    return io;

  }


  /* ---------------------------------------------------
     CREATE SOCKET.IO SERVER
  --------------------------------------------------- */

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

      pingInterval: 25000,

      pingTimeout: 60000,
    }
  );


  /*
   * Store Socket.IO instance in agentBridge.
   */

  setSocket(io);


  console.log(
    "================================="
  );

  console.log(
    " TrustWipe Socket.IO Started"
  );

  console.log(
    "=================================");


  /* ===================================================
     CONNECTION
  =================================================== */

  io.on(
    "connection",
    (socket) => {

      console.log(
        "🟢 Socket Connected:",
        socket.id
      );


      /* ===============================================
         REGISTER AGENT
      =============================================== */

      socket.on(
        "register-agent",
        (agent = {}) => {

          try {

            /*
             * Your current agent sends deviceId.
             * Newer code may send agentId.
             *
             * Support both.
             */

            const deviceId =
              String(
                agent.deviceId ||
                agent.agentId ||
                ""
              ).trim();


            if (!deviceId) {

              console.error(
                "❌ Agent registration rejected:"
                + " missing deviceId."
              );


              socket.emit(
                "agent-registered",
                {
                  success: false,

                  error:
                    "Missing deviceId/agentId.",
                }
              );


              return;

            }


            /*
             * Register through agentBridge.
             *
             * IMPORTANT:
             * Do not maintain another Map here.
             */

            const registeredAgent =
              registerAgent({

                ...agent,

                agentId:
                  deviceId,

                deviceId,

                socket,

              });


            /*
             * Join agent-specific room.
             */

            socket.join(
              `agent:${deviceId}`
            );


            console.log(
              "✅ Agent Registered:",
              deviceId
            );


            /*
             * Notify the registering agent.
             */

            socket.emit(
              "agent-registered",
              {

                success: true,

                agentId:
                  deviceId,

                deviceId,

                status:
                  "online",

              }
            );


            /*
             * Notify frontend/admin clients.
             */

            io.emit(
              "agent-status",
              {

                deviceId,

                agentId:
                  deviceId,

                status:
                  "online",

                hostname:
                  registeredAgent.hostname,

                platform:
                  registeredAgent.platform,

                capabilities:
                  registeredAgent.capabilities,

              }
            );

          }
          catch (err) {

            console.error(
              "❌ Agent registration error:",
              err.message
            );


            socket.emit(
              "agent-registered",
              {

                success: false,

                error:
                  err.message,

              }
            );

          }

        }
      );


      /* ===============================================
         HEARTBEAT
      =============================================== */

      socket.on(
        "heartbeat",
        (data = {}) => {

          const deviceId =
            String(
              data.deviceId ||
              data.agentId ||
              ""
            ).trim();


          if (!deviceId) {
            return;
          }


          const updated =
            updateAgentHeartbeat(
              deviceId,
              data
            );


          if (!updated) {

            console.warn(
              `⚠️ Heartbeat from unknown agent: ${deviceId}`
            );

            return;

          }


          /*
           * Optional status broadcast.
           */

          io.emit(
            "agent-status",
            {

              deviceId,

              agentId:
                deviceId,

              status:
                "online",

            }
          );

        }
      );


      /* ===============================================
         DRIVE DISCOVERY
      =============================================== */

      socket.on(
        "drive-list",
        (data = {}) => {

          console.log(
            "📀 Drive list received from agent:",
            data.deviceId ||
            data.agentId ||
            "unknown"
          );


          /*
           * Resolve the pending HTTP request.
           */

          if (data.userId) {

            resolvePendingDiscovery(
              data.userId,
              data
            );

          }


          /*
           * Also broadcast to dashboard clients.
           */

          io.emit(
            "drive-list",
            data
          );

        }
      );


      /* ===============================================
         WIPE PROGRESS
      =============================================== */

      socket.on(
        "wipe-progress",
        async (data = {}) => {

          try {

            const jobId =
              data.commandId ||
              data.jobId;


            if (!jobId) {

              console.warn(
                "⚠️ wipe-progress missing jobId."
              );

              return;

            }


            const update = {

              progress:
                Number(
                  data.progress || 0
                ),

              status:
                "running",

              $push: {

                events: {

                  message:
                    data.message ||
                    "Wipe progress updated.",

                  timestamp:
                    new Date(),

                },

              },

            };


            const job =
              await WipeJob.findByIdAndUpdate(
                jobId,
                update,
                {
                  new: true,
                }
              );


            /*
             * Send progress to frontend.
             */

            io.emit(
              "wipe-progress",
              job || data
            );

          }
          catch (err) {

            console.error(
              "❌ wipe-progress error:",
              err.message
            );

          }

        }
      );


      /* ===============================================
         WIPE COMPLETE
      =============================================== */

      socket.on(
        "wipe-complete",
        async (data = {}) => {

          try {

            const jobId =
              data.commandId ||
              data.jobId;


            if (!jobId) {

              console.error(
                "❌ wipe-complete missing job ID."
              );

              return;

            }


            const job =
              await WipeJob.findByIdAndUpdate(

                jobId,

                {

                  progress:
                    100,

                  status:
                    data.status ||
                    "completed",

                  completedAt:
                    new Date(),

                  wipedFiles:
                    data.wipedFiles,

                  verifiedFiles:
                    data.verifiedFiles,

                  verificationFailures:
                    data.verificationFailures,

                  verificationHash:
                    data.verificationHash,

                  verificationEvidenceHash:
                    data.verificationEvidenceHash,

                  $push: {

                    events: {

                      message:
                        `Job ${
                          data.status ||
                          "completed"
                        }`,

                      timestamp:
                        new Date(),

                    },

                  },

                },

                {
                  new: true,
                }

              );


            if (!job) {

              console.log(
                "⚠️ Wipe job not found:",
                jobId
              );

              return;

            }


            /* -------------------------------------------
               UPDATE DEVICE
            ------------------------------------------- */

            const deviceStatus =
              data.status === "completed"
                ? "Completed"
                : data.status === "failed"
                ? "Failed"
                : "Pending";


            await Device.findByIdAndUpdate(

              job.deviceId,

              {

                status:
                  deviceStatus,

                currentJobId:
                  null,

                lastJobId:
                  job._id,

              },

              {
                new: true,
              }

            );


            /* -------------------------------------------
               GENERATE CERTIFICATE
            ------------------------------------------- */

            if (
              data.status === "completed"
            ) {

              try {

                const device =
                  await Device.findById(
                    job.deviceId
                  );


                if (!device) {

                  throw new Error(
                    "Device not found."
                  );

                }


                /*
                 * Create certificate.
                 */

                const certificate =
                  await Certificate.create({

                    certificateId:
                      `TW-${Date.now()}`,

                    deviceId:
                      device._id,

                    jobId:
                      job._id,

                    manufacturer:
                      device.manufacturer ||
                      "",

                    modelNumber:
                      device.modelNumber ||
                      "",

                    owner:
                      device.owner,

                    location:
                      device.location ||
                      "",

                    deviceType:
                      device.storageType ||
                      "",

                    storagePath:
                      device.storagePath ||
                      "",

                    sanitizationStandard:
                      "NIST SP 800-88 Rev.1",

                    algorithm:
                      job.algorithm,

                    verificationMethod:
                      job.verificationMethod,

                    verificationHash:
                      job.verificationHash,

                    verificationEvidenceHash:
                      job.verificationEvidenceHash,

                    verificationStatus:
                      "VERIFIED",

                    wipedFiles:
                      job.wipedFiles,

                    verifiedFiles:
                      job.verifiedFiles,

                    verificationFailures:
                      job.verificationFailures,

                    wipeCompletedAt:
                      job.completedAt,

                    signature:
                      "TrustWipe Digital Signature",

                  });


                /*
                 * Generate PDF certificate.
                 */

                const pdfPath =
                  await generateCertificate(
                    certificate,
                    device
                  );


                /*
                 * Save generated PDF path.
                 */

                certificate.pdfUrl =
                  pdfPath;


                await certificate.save();


                /*
                 * Link certificate to wipe job.
                 */

                job.certificateId =
                  certificate.certificateId;


                await job.save();


                console.log(
                  "📜 Certificate Generated:",
                  certificate.certificateId
                );

              }
              catch (err) {

                /*
                 * Certificate generation failure
                 * should not change the already completed
                 * wipe operation.
                 */

                console.error(
                  "❌ Certificate Generation Failed:",
                  err.message
                );

              }

            }


            /* -------------------------------------------
               NOTIFY FRONTEND
            ------------------------------------------- */

            io.emit(
              "wipe-complete",
              job
            );


            io.emit(
              "device-updated",
              {

                deviceId:
                  job.deviceId,

                status:
                  deviceStatus,

                jobId:
                  job._id,

              }
            );

          }
          catch (err) {

            console.error(
              "❌ wipe-complete error:",
              err.message
            );

          }

        }
      );


      /* ===============================================
         FORENSIC PROGRESS
      =============================================== */

      socket.on(
        "forensic-progress",
        async (data = {}) => {

          try {

            const jobId =
              data.jobId ||
              data.commandId;


            if (!jobId) {

              console.warn(
                "⚠️ forensic-progress missing jobId."
              );

              return;

            }


            console.log(
              "🔎 Forensic progress:",
              jobId,
              `${data.progress || 0}%`
            );


            /*
             * Store progress in the ForensicJob model
             * if it exists.
             *
             * Dynamic import is avoided here.
             * The model should be imported at the top
             * if your project contains it.
             *
             * For compatibility, we broadcast the
             * progress immediately.
             */


            io.emit(
              "forensic-progress",
              {

                ...data,

                jobId,

                timestamp:
                  new Date().toISOString(),

              }
            );

          }
          catch (err) {

            console.error(
              "❌ forensic-progress error:",
              err.message
            );

          }

        }
      );


      /* ===============================================
         FORENSIC COMPLETE
      =============================================== */

      socket.on(
        "forensic-complete",
        async (data = {}) => {

          try {

            const jobId =
              data.jobId ||
              data.commandId;


            if (!jobId) {

              console.warn(
                "⚠️ forensic-complete missing jobId."
              );

              return;

            }


            console.log(
              "✅ Forensic job completed:",
              jobId
            );


            /*
             * Broadcast complete forensic result.
             */

            io.emit(
              "forensic-complete",
              {

                ...data,

                jobId,

                status:
                  data.status ||
                  "completed",

                timestamp:
                  new Date().toISOString(),

              }
            );

          }
          catch (err) {

            console.error(
              "❌ forensic-complete error:",
              err.message
            );

          }

        }
      );


      /* ===============================================
         FORENSIC ERROR
      =============================================== */

      socket.on(
        "forensic-error",
        async (data = {}) => {

          try {

            const jobId =
              data.jobId ||
              data.commandId ||
              null;


            console.error(
              "❌ Forensic agent error:",
              data.error ||
              "Unknown error"
            );


            /*
             * Broadcast error to frontend.
             */

            io.emit(
              "forensic-error",
              {

                ...data,

                jobId,

                status:
                  "failed",

                timestamp:
                  new Date().toISOString(),

              }
            );

          }
          catch (err) {

            console.error(
              "❌ forensic-error handler failed:",
              err.message
            );

          }

        }
      );


      /* ===============================================
         AGENT STATUS REQUEST
      =============================================== */

      socket.on(
        "get-agent-status",
        () => {

          try {

            socket.emit(
              "agent-list",
              listAgents()
            );

          }
          catch (err) {

            console.error(
              "❌ Agent status request failed:",
              err.message
            );

          }

        }
      );


      /* ===============================================
         DISCONNECT
      =============================================== */

      socket.on(
        "disconnect",
        (reason) => {

          console.log(
            "🔴 Socket Disconnected:",
            socket.id
          );

          console.log(
            "   Reason:",
            reason
          );


          /*
           * Find which registered agent owns this
           * socket and remove only that connection.
           */

          const agents =
            listAgents();


          for (
            const agent
            of agents
          ) {

            if (
              agent.socketId ===
              socket.id
            ) {

              const removed =
                unregisterAgent(
                  agent.agentId,
                  socket.id
                );


              if (removed) {

                console.log(
                  "🔴 Agent Disconnected:",
                  agent.agentId
                );


                /*
                 * Notify frontend.
                 */

                io.emit(
                  "agent-status",
                  {

                    deviceId:
                      agent.agentId,

                    agentId:
                      agent.agentId,

                    status:
                      "offline",

                  }
                );

              }


              break;

            }

          }

        }
      );

    }
  );


  return io;

};


/* =====================================================
   GET SOCKET.IO INSTANCE
===================================================== */

export const getIO = () => {

  if (!io) {

    throw new Error(
      "Socket.IO has not been initialized."
    );

  }


  return io;

};


/* =====================================================
   GET CONNECTED AGENTS
===================================================== */

/**
 * Returns sanitized agent information.
 *
 * No raw Socket.IO socket objects are returned.
 */

export const getConnectedAgents = () => {

  return listAgents();

};


/* =====================================================
   GET SINGLE AGENT
===================================================== */

export const getAgent = (
  deviceId
) => {

  return getBridgeAgent(
    deviceId
  );

};


/* =====================================================
   CHECK AGENT ONLINE
===================================================== */

export const isAgentOnline = (
  deviceId
) => {

  return isAgentConnected(
    deviceId
  );

};


/* =====================================================
   DEFAULT EXPORT
===================================================== */

export default {
  initAgentClient,
  getIO,
  getConnectedAgents,
  getAgent,
  isAgentOnline,
};