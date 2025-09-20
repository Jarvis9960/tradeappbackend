import { createServer } from "node:http";
import { createApp } from "./app.js";
import { connectDatabase } from "./database.js";
import { config } from "./config.js";
import { seedDefaultUser } from "./services/authService.js";

const bootstrap = async () => {
  await connectDatabase();
  await seedDefaultUser();

  const app = createApp();
  const server = createServer(app);

  server.listen(config.port, () => {
    console.log(`Auth server listening on port ${config.port}`);
  });
};

bootstrap().catch((error) => {
  console.error("Failed to bootstrap server", error);
  process.exit(1);
});