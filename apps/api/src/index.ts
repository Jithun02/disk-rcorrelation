import express from "express";
import cors from "cors";
import { initializeDatabase } from "./db";
import apiRouter from "./server";

const app = express();
const PORT = process.env.PORT || 5001;

app.use(cors());
app.use(express.json());

// API Routes
app.use("/api", apiRouter);

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

// Bootstrapper
async function bootstrap() {
  try {
    console.log("[DB] Initializing SQLite database...");
    await initializeDatabase();
    console.log("[DB] SQLite database initialized successfully.");

    app.listen(PORT, () => {
      console.log(`[API] ForensiCore Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error("[Boot Error] Failed to start API Server:", err);
    process.exit(1);
  }
}

bootstrap();
