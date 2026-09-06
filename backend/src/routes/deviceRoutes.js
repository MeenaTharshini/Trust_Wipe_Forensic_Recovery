import express from "express";
import {
  autoDiscoverDevices,
  getDevices,
  createDevice,
  deleteDevice,
} from "../controllers/deviceController.js";
import { discoverDrives } from "../services/driveDiscovery.js";

import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();

router.get(
    "/discover",
    authMiddleware,
    discoverDrives
);

router.post(
  "/",
  authMiddleware,
  createDevice
);

router.delete(
  "/:id",
  authMiddleware,
  deleteDevice
);

router.get(
  "/",
  authMiddleware,
  getDevices
);
router.get(
  "/:agentId/drives",
  authMiddleware,
  async (req, res) => {
    try {
      const agentId = String(
        req.params.agentId || ""
      ).trim();

      if (!agentId) {
        return res.status(400).json({
          success: false,
          message: "Agent ID is required.",
        });
      }

      const agentBridge =
        req.app.get("agentBridge");

      if (
        !agentBridge ||
        typeof agentBridge.requestDriveList !==
          "function"
      ) {
        return res.status(503).json({
          success: false,
          message:
            "TrustWipe Agent bridge is unavailable.",
        });
      }

      const data =
        await agentBridge.requestDriveList(
          agentId,
          req.user?.id || null
        );

      return res.json({
        success: true,
        agentId,
        drives: data.drives || [],
      });
    } catch (error) {
      console.error(
        "❌ Drive discovery error:",
        error
      );

      const status =
        error.code === "AGENT_NOT_FOUND"
          ? 404
          : error.code === "AGENT_OFFLINE"
          ? 503
          : error.code ===
            "DRIVE_DISCOVERY_TIMEOUT"
          ? 504
          : 500;

      return res.status(status).json({
        success: false,
        code: error.code || "DRIVE_DISCOVERY_ERROR",
        message: error.message,
      });
    }
  }
);
export default router;