import { Router } from "express";
import authRoutes from "./authRoutes.js";
import securityRoutes from "./securityRoutes.js";
import adminRoutes from "./adminRoutes.js";

const router = Router();

router.use("/auth", authRoutes);
router.use("/security", securityRoutes);
router.use("/admin", adminRoutes);

export default router;
