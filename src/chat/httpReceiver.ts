import express, { type Express } from "express";
import { createHttpHandler, type OnMessage } from "../transport/index.js";

/**
 * The chat demo's express app: the library's dependency-free DIDComm
 * receiver on `POST /`, which the `serve` command extends with its web UI
 * and API routes. express is a dev dependency used only by this demo.
 */
export function createHttpReceiver(onMessage: OnMessage): Express {
  const app = express();
  app.post("/", createHttpHandler(onMessage));
  return app;
}
