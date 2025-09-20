import { Router } from "express";
import authRoutes from "./authRoutes.js";
import securityRoutes from "./securityRoutes.js";

const router = Router();

router.use("/auth", authRoutes);
router.use("/security", securityRoutes);

export default router;