import { Router } from "express";
import { securityEventHandler } from "../controllers/securityController.js";

const router = Router();

router.post("/event", securityEventHandler);

export default router;