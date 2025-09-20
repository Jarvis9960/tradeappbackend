import "dotenv/config";

const requiredEnv = ["MONGODB_URI", "JWT_SECRET", "PORT"];

if (process.env.NODE_ENV === "production") {
  requiredEnv.push("CORS_ORIGIN");
}

requiredEnv.forEach((key) => {
  if (!process.env[key]) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
});

export const config = {
  mongodbUri: process.env.MONGODB_URI,
  jwtSecret: process.env.JWT_SECRET,
  port: Number(process.env.PORT ?? 4000),
  nodeEnv: process.env.NODE_ENV ?? "development",
  corsOrigin: process.env.CORS_ORIGIN?.split(",").map((value) => value.trim()).filter(Boolean) ?? ["http://localhost:3000"],
  sessionTtlMinutes: Number(process.env.SESSION_TTL_MINUTES ?? 480),
  cookieDomain: process.env.COOKIE_DOMAIN,
};