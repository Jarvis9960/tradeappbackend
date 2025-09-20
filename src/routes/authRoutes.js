import { Router } from "express";
import { loginHandler, logoutHandler, sessionHandler, seedHandler } from "../controllers/authController.js";

const router = Router();

router.post("/login", loginHandler);
router.post("/logout", logoutHandler);
router.get("/session", sessionHandler);
router.post("/seed", seedHandler);

export default router;