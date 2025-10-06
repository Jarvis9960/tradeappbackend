import { Router } from "express";
import {
  blockUserHandler,
  createUserHandler,
  getAdminStatsHandler,
  listSecurityEventsHandler,
  listSessionsHandler,
  listUsersHandler,
  revokeSessionHandler,
  unblockUserHandler,
  updateCreditsHandler,
} from "../controllers/adminController.js";
import {
  adminLoginHandler,
  adminLogoutHandler,
  adminSessionHandler,
} from "../controllers/adminAuthController.js";
import { requireAdminAuth } from "../middleware/adminAuth.js";

const router = Router();

router.post("/auth/login", adminLoginHandler);
router.post("/auth/logout", adminLogoutHandler);
router.get("/auth/session", adminSessionHandler);

router.use(requireAdminAuth);

router.get("/stats", getAdminStatsHandler);
router.get("/users", listUsersHandler);
router.post("/users", createUserHandler);
router.post("/users/:id/block", blockUserHandler);
router.post("/users/:id/unblock", unblockUserHandler);
router.post("/users/:id/credits", updateCreditsHandler);
router.get("/sessions", listSessionsHandler);
router.post("/sessions/:id/revoke", revokeSessionHandler);
router.get("/security-events", listSecurityEventsHandler);

export default router;
