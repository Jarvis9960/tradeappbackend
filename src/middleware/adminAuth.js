import { asyncHandler } from "../utils/asyncHandler.js";
import { getSessionFromToken } from "../services/authService.js";

const extractBearerToken = (req) => {
  const header = req.headers.authorization ?? req.headers.Authorization;
  if (typeof header === "string" && header.toLowerCase().startsWith("bearer ")) {
    return header.slice(7).trim();
  }
  return undefined;
};

export const requireAdminAuth = asyncHandler(async (req, res, next) => {
  const token = extractBearerToken(req);
  if (!token) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  try {
    const result = await getSessionFromToken(token);
    if (!result || !result.user.isAdmin) {
      res.status(403).json({ error: "Forbidden" });
      return;
    }

    req.adminUser = result.user;
    req.adminSession = result.session;
    req.adminToken = token;
    next();
  } catch (error) {
    if (error instanceof Error && error.message === "ACCOUNT_BLOCKED") {
      res.status(423).json({ error: "Account blocked" });
      return;
    }
    res.status(401).json({ error: "Invalid session" });
  }
});
