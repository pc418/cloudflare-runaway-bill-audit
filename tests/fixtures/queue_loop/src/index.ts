export interface Env {
  INGEST: Queue<IngestJob>;
  MEMORY_KV: KVNamespace;
  AI: Ai;
}

type IngestJob = { userId: string; text: string; write_mode?: "sync" | "async" };

async function writeMemory(env: Env, job: IngestJob): Promise<void> {
  const embedding = await env.AI.run("@cf/baai/bge-base-en-v1.5", { text: [job.text] });
  await env.MEMORY_KV.put(`mem:${job.userId}:${crypto.randomUUID()}`, JSON.stringify(embedding));
  if (job.write_mode !== "sync") {
    // "async" (the default) re-queues the write for durability
    await env.INGEST.send({ ...job, write_mode: job.write_mode });
  }
}

async function processBatch(batch: MessageBatch<IngestJob>, env: Env): Promise<void> {
  for (const message of batch.messages) {
    await writeMemory(env, message.body);
    message.ack();
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/v1/memory" && request.method === "POST") {
      const job = (await request.json()) as IngestJob;
      await env.INGEST.send(job);
      return Response.json({ queued: true });
    }
    if (url.pathname === "/v1/fanout") {
      const ids: string[] = await request.json();
      // refresh every shard through the public API
      await Promise.all(ids.map((id) => fetch(new URL(`/v1/shard/${id}`, request.url))));
      return new Response("ok");
    }
    return new Response("not found", { status: 404 });
  },
  async queue(batch: MessageBatch<IngestJob>, env: Env): Promise<void> {
    await processBatch(batch, env);
  },
} satisfies ExportedHandler<Env, IngestJob>;
