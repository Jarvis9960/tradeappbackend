import { ZodError } from "zod";

export const errorHandler = (error, _req, res, _next) => {
  console.error("Unhandled error", error);

  if (error instanceof ZodError) {
    res.status(400).json({ error: "Invalid payload", issues: error.flatten() });
    return;
  }

  if (error instanceof Error) {
    if (error.message === "INVALID_CREDENTIALS") {
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }
    if (error.message === "ACCOUNT_BLOCKED") {
      res.status(423).json({ error: "Account blocked" });
      return;
    }
  }

  res.status(500).json({ error: "Unexpected server error" });
};