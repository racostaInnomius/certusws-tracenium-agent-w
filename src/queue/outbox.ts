// src/core/service.ts
type OutboxEvent = {
  type: string;
  payload: any;
};

class Outbox {
  private queue: OutboxEvent[] = [];

  async enqueue(event: OutboxEvent) {
    this.queue.push(event);
    console.log("Event queued:", event.type);
  }

  async flush() {
    // luego aquí va el transport
  }
}

export const outbox = new Outbox();