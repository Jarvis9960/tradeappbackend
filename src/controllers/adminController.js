import { z } from "zod";
import { asyncHandler } from "../utils/asyncHandler.js";
import {
  blockUserForAdmin,
  createUserForAdmin,
  getAdminStats,
  listSecurityEventsForAdmin,
  listSessionsForAdmin,
  listUsersForAdmin,
  revokeSessionForAdmin,
  unblockUserForAdmin,
  updateCreditsForAdmin,
} from "../services/adminService.js";

const createUserSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  credits: z.number().int().min(0).optional(),
});

const reasonSchema = z.object({
  reason: z.string().max(500).optional(),
});

const creditsSchema = z.object({
  credits: z.number().int().min(0),
});

export const getAdminStatsHandler = asyncHandler(async (_req, res) => {
  const stats = await getAdminStats();
  res.json(stats);
});

export const listUsersHandler = asyncHandler(async (_req, res) => {
  const users = await listUsersForAdmin();
  res.json(users);
});

export const createUserHandler = asyncHandler(async (req, res) => {
  const payload = createUserSchema.parse(req.body);
  const user = await createUserForAdmin(payload);
  res.status(201).json(user);
});

export const blockUserHandler = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const payload = reasonSchema.parse(req.body ?? {});
  const user = await blockUserForAdmin(id, payload.reason);
  res.json({ ok: true, user });
});

export const unblockUserHandler = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const payload = reasonSchema.parse(req.body ?? {});
  const user = await unblockUserForAdmin(id, payload.reason);
  res.json({ ok: true, user });
});

export const updateCreditsHandler = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const payload = creditsSchema.parse(req.body);
  const user = await updateCreditsForAdmin(id, payload.credits);
  res.json({ ok: true, user });
});

export const listSessionsHandler = asyncHandler(async (req, res) => {
  const includeParam = Array.isArray(req.query.includeRevoked)
    ? req.query.includeRevoked[0]
    : req.query.includeRevoked;
  const includeRevoked = includeParam !== "false";
  const limitParam = Array.isArray(req.query.limit) ? req.query.limit[0] : req.query.limit;
  const limit = Number.parseInt(limitParam ?? "", 10);
  const sessions = await listSessionsForAdmin({
    includeRevoked,
    limit: Number.isNaN(limit) ? 100 : limit,
  });
  res.json(sessions);
});

export const revokeSessionHandler = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const payload = reasonSchema.parse(req.body ?? {});
  await revokeSessionForAdmin(id, payload.reason);
  res.json({ ok: true });
});

export const listSecurityEventsHandler = asyncHandler(async (req, res) => {
  const limitParam = Array.isArray(req.query.limit) ? req.query.limit[0] : req.query.limit;
  const limit = Number.parseInt(limitParam ?? "", 10);
  const events = await listSecurityEventsForAdmin(Number.isNaN(limit) ? 50 : limit);
  res.json(events);
});
