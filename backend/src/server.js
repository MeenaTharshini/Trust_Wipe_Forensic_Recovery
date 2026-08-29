
// backend/src/server.js

import express from "express";
import cors from "cors";
import http from "http";
import dotenv from "dotenv";
import mongoose from "mongoose";
import path from "path";
import { fileURLToPath } from "url";

// ------------------------------------------------------------
// ROUTES
// ------------------------------------------------------------

import authRoutes from "./routes/authRoutes.js";
import deviceRoutes from "./routes/deviceRoutes.js";
import wipeRoutes from "./routes/wipeRoutes.js";
import verificationRoutes from "./routes/verificationRoutes.js";
import certificateRoutes from "./routes/certificateRoutes.js";
import reportRoutes from "./routes/reportRoutes.js";
import forensicRoutes from "./routes/forensic.js";

// ------------------------------------------------------------
// SOCKET
// ------------------------------------------------------------

import { initAgentClient } from "./socket/index.js";

// ------------------------------------------------------------
// PATH CONFIGURATION
// ------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ------------------------------------------------------------
// ENVIRONMENT
// ------------------------------------------------------------

dotenv.config({
  path: path.join(__dirname, "../.env"),
});

const app = express();
const server = http.createServer(app);

// ------------------------------------------------------------
// CORS
// ------------------------------------------------------------

const allowedOrigins = [
  process.env.FRONTEND_URL,
  process.env.FRONTEND_ORIGIN,
].filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      // Allow server-to-server / Postman / curl requests
      if (!origin) {
        return callback(null, true);
      }

      // If no frontend origin is configured,
      // allow the request.
      if (allowedOrigins.length === 0) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      console.warn(
        `⚠️ CORS blocked origin: ${origin}`
      );

      return callback(
        new Error("Not allowed by CORS")
      );
    },

    credentials: true,

    methods: [
      "GET",
      "POST",
      "PUT",
      "PATCH",
      "DELETE",
      "OPTIONS",
    ],

    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "Accept",
      "X-Forensic-Api-Key",
    ],
  })
);

// ------------------------------------------------------------
// BODY PARSING
// ------------------------------------------------------------

app.use(
  express.json({
    limit: "10mb",
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "10mb",
  })
);

// ------------------------------------------------------------
// REQUEST LOGGING
// ------------------------------------------------------------

if (process.env.NODE_ENV !== "production") {
  app.use((req, res, next) => {
    console.log(
      `[API] ${req.method} ${req.originalUrl}`
    );

    next();
  });
}

// ------------------------------------------------------------
// SOCKET.IO / AGENT
// ------------------------------------------------------------

initAgentClient(server);

// ------------------------------------------------------------
// API ROUTES
// ------------------------------------------------------------

app.use(
  "/api/auth",
  authRoutes
);

app.use(
  "/api/devices",
  deviceRoutes
);

app.use(
  "/api/wipe",
  wipeRoutes
);

app.use(
  "/api/verification",
  verificationRoutes
);

app.use(
  "/api/certificate",
  certificateRoutes
);

app.use(
  "/api/reports",
  reportRoutes
);

// ------------------------------------------------------------
// FORENSICS
// ------------------------------------------------------------
//
// This mounts:
//
// GET  /api/forensic/test
// GET  /api/forensic/status
// GET  /api/forensic/evidence
// POST /api/forensic/upload
// POST /api/forensic/hash
// POST /api/forensic/verify-integrity
// POST /api/forensic/scan
// POST /api/forensic/report
//
// etc.
//
// The actual forensic Python engine lives at:
//
// backend/forensic_recovery/
//

app.use(
  "/api/forensic",
  forensicRoutes
);

// ------------------------------------------------------------
// DOWNLOADS
// ------------------------------------------------------------

const downloadsDirectory = path.join(
  __dirname,
  "../downloads"
);

app.use(
  "/downloads",
  express.static(downloadsDirectory)
);

// ------------------------------------------------------------
// HEALTH CHECK
// ------------------------------------------------------------

app.get(
  "/api/health",
  (_req, res) => {
    res.status(200).json({
      success: true,
      status: "OK",
      application: "TrustWipe Enterprise API",
      version: "1.0.0",
      forensic: true,
    });
  }
);

// ------------------------------------------------------------
// FORENSIC HEALTH / DEBUG ENDPOINT
// ------------------------------------------------------------
//
// This makes it very easy to test whether the
// forensic router is actually mounted.
//
// Open:
//
// /api/forensic/test
//
// Expected:
//
// {
//   success: true,
//   message: "Forensic router is working"
// }

app.get(
  "/api/forensic-health",
  (_req, res) => {
    res.status(200).json({
      success: true,
      service: "TrustWipe Digital Forensics",
      mounted: true,
      endpoint: "/api/forensic",
    });
  }
);

// ------------------------------------------------------------
// ROOT
// ------------------------------------------------------------

app.get(
  "/",
  (_req, res) => {
    res.status(200).json({
      success: true,
      application: "TrustWipe Enterprise API",
      version: "1.0.0",
      services: {
        api: true,
        forensic: true,
        socket: true,
      },
    });
  }
);

// ------------------------------------------------------------
// 404 HANDLER
// ------------------------------------------------------------

app.use(
  (req, res) => {
    console.warn(
      `⚠️ 404 NOT FOUND: ${req.method} ${req.originalUrl}`
    );

    res.status(404).json({
      success: false,
      code: "ROUTE_NOT_FOUND",
      message: "Route not found",
      path: req.originalUrl,
    });
  }
);

// ------------------------------------------------------------
// GLOBAL ERROR HANDLER
// ------------------------------------------------------------

app.use(
  (err, req, res, next) => {
    console.error(
      "❌ SERVER ERROR:",
      err
    );

    if (res.headersSent) {
      return next(err);
    }

    res.status(
      err.status || 500
    ).json({
      success: false,
      message:
        process.env.NODE_ENV === "production"
          ? "Internal Server Error"
          : err.message ||
            "Internal Server Error",
    });
  }
);

// ------------------------------------------------------------
// DATABASE + SERVER START
// ------------------------------------------------------------

const PORT =
  Number(process.env.PORT) || 5000;

const MONGO_URI =
  process.env.MONGO_URI;

if (!MONGO_URI) {
  console.error(
    "❌ MONGO_URI is not configured."
  );

  process.exit(1);
}

mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log(
      "✅ MongoDB Connected"
    );

    server.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `🚀 TrustWipe Server Running on port ${PORT}`
        );

        console.log(
          `🔗 Health: http://localhost:${PORT}/api/health`
        );

        console.log(
          `🔬 Forensics: http://localhost:${PORT}/api/forensic/test`
        );

        console.log(
          `🛡️ Forensic Health: http://localhost:${PORT}/api/forensic-health`
        );
      }
    );
  })
  .catch((err) => {
    console.error(
      "❌ MongoDB Connection Error:",
      err.message
    );

    process.exit(1);
  });
