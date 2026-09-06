
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

/*
|--------------------------------------------------------------------------
| TEST ROUTE
|--------------------------------------------------------------------------
| Temporary route to verify that deviceRoutes.js is correctly mounted
| on the Render backend.
|
| URL:
| GET /api/devices/test-drive-route
|
| Remove this route after deployment testing.
|--------------------------------------------------------------------------
*/
router.get("/test-drive-route", (_req, res) => {
  return res.json({
    success: true,
    message: "Device route is mounted correctly",
  });
});

/*
|--------------------------------------------------------------------------
| AUTO DISCOVER DEVICES
|--------------------------------------------------------------------------
| Discovers available devices through the TrustWipe Agent.
|
| GET /api/devices/discover
|--------------------------------------------------------------------------
*/
router.get(
  "/discover",
  authMiddleware,
  discoverDrives
);

/*
|--------------------------------------------------------------------------
| CREATE DEVICE
|--------------------------------------------------------------------------
| Creates/registers a device in the database.
|
| POST /api/devices
|--------------------------------------------------------------------------
*/
router.post(
  "/",
  authMiddleware,
  createDevice
);

/*
|--------------------------------------------------------------------------
| DELETE DEVICE
|--------------------------------------------------------------------------
| Deletes a registered device.
|
| DELETE /api/devices/:id
|--------------------------------------------------------------------------
*/
router.delete(
  "/:id",
  authMiddleware,
  deleteDevice
);

/*
|--------------------------------------------------------------------------
| GET ALL DEVICES
|--------------------------------------------------------------------------
| Returns all devices available to the authenticated user.
|
| GET /api/devices
|--------------------------------------------------------------------------
*/
router.get(
  "/",
  authMiddleware,
  getDevices
);
router.get("/test-drive-route", (_req, res) => {
  return res.json({
    success: true,
    message: "Device route is mounted correctly",
  });
});
/*
|--------------------------------------------------------------------------
| GET DRIVES FROM SPECIFIC AGENT
|--------------------------------------------------------------------------
| Requests the connected TrustWipe Agent to discover physical drives.
|
| GET /api/devices/:agentId/drives
|
| Example:
| /api/devices/MahalakshmiSreenivasan/drives
|--------------------------------------------------------------------------
*/
router.get(
  "/:agentId/drives",
  authMiddleware,
  async (req, res) => {
    try {
      const agentId = String(
        req.params.agentId || ""
      ).trim();

      // Validate Agent ID
      if (!agentId) {
        return res.status(400).json({
          success: false,
          code: "AGENT_ID_REQUIRED",
          message: "Agent ID is required.",
        });
      }

      console.log(
        `📀 Drive discovery requested for Agent: ${agentId}`
      );

      /*
      |--------------------------------------------------------------------------
      | Get Agent Bridge
      |--------------------------------------------------------------------------
      | server.js should contain:
      |
      | app.set("agentBridge", agentBridge);
      |--------------------------------------------------------------------------
      */
      const agentBridge = req.app.get("agentBridge");

      if (
        !agentBridge ||
        typeof agentBridge.requestDriveList !== "function"
      ) {
        console.error(
          "❌ Agent bridge unavailable"
        );

        return res.status(503).json({
          success: false,
          code: "AGENT_BRIDGE_UNAVAILABLE",
          message:
            "TrustWipe Agent bridge is unavailable.",
        });
      }

      /*
      |--------------------------------------------------------------------------
      | Request drive list from Agent
      |--------------------------------------------------------------------------
      */
      const data =
        await agentBridge.requestDriveList(
          agentId,
          req.user?.id || null
        );

      console.log(
        `✅ Drive list received for Agent: ${agentId}`
      );

      const drives = Array.isArray(data?.drives)
        ? data.drives
        : [];

      return res.status(200).json({
        success: true,
        agentId,
        drives,
      });

    } catch (error) {
      console.error(
        "❌ Drive discovery error:",
        error
      );

      /*
      |--------------------------------------------------------------------------
      | Error mapping
      |--------------------------------------------------------------------------
      */
      let status = 500;

      if (error.code === "AGENT_NOT_FOUND") {
        status = 404;
      } else if (
        error.code === "AGENT_OFFLINE"
      ) {
        status = 503;
      } else if (
        error.code === "DRIVE_DISCOVERY_TIMEOUT"
      ) {
        status = 504;
      }

      return res.status(status).json({
        success: false,
        code:
          error.code ||
          "DRIVE_DISCOVERY_ERROR",
        message:
          error.message ||
          "Unable to discover drives.",
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| EXPORT ROUTER
|--------------------------------------------------------------------------
*/
export default router;