import { Router } from "express";
import {
  loginHandler,
  logoutHandler,
  sessionHandler,
  seedHandler,
  verifyDeviceHandler,
  heartbeatHandler,
} from "../controllers/authController.js";

const router = Router();

router.post("/login", loginHandler);
// Second step of a new-device login: redeem the emailed code.
router.post("/verify-device", verifyDeviceHandler);
// Keeps the session's lastSeenAt fresh so concurrent use is measurable.
router.post("/heartbeat", heartbeatHandler);
router.post("/logout", logoutHandler);
router.get("/session", sessionHandler);
router.post("/seed", seedHandler);

export default router;