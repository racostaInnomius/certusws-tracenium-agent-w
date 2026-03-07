// src/queue/index.ts
import { SqliteOutbox } from "./sqlite-outbox";

export const outbox = new SqliteOutbox();