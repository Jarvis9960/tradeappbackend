import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import morgan from "morgan";
import routes from "./routes/index.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { config } from "./config.js";

export const createApp = () => {
  const app = express();

  app.disable("x-powered-by");
  app.use(morgan(config.nodeEnv === "production" ? "combined" : "dev"));
  app.use(cors({
    origin: true, // Allow all origins for now, we'll validate in the handlers
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
    exposedHeaders: ['Set-Cookie'],
  }));
  app.use(express.json({ limit: "1mb" }));
  app.use(cookieParser());

  app.get("/health", (_req, res) => {
    res.json({ ok: true, status: "healthy" });
  });

  app.use("/api/v1", routes);

  app.use(errorHandler);

  return app;
};