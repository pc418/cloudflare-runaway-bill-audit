import { Hono } from "hono";
import { DurableObject } from "cloudflare:workers";

type Env = {
  AI: Ai;
  LIMITER: RateLimit;
  JOBS: Queue<{ userId: string }>;
  COUNTERS: DurableObjectNamespace<Counter>;
  AI_GATEWAY_ID: string;
};

const MAX_TICKS = 10;

export class Counter extends DurableObject<Env> {
  async alarm(): Promise<void> {
    const ticks = ((await this.ctx.storage.get<number>("ticks")) ?? 0) + 1;
    await this.ctx.storage.put("ticks", ticks);
    if (ticks < MAX_TICKS) {
      await this.ctx.storage.setAlarm(Date.now() + 60_000);
    } else {
      await this.ctx.storage.deleteAll();
    }
  }
}

const app = new Hono<{ Bindings: Env; Variables: { userId: string } }>();

app.use("/api/*", async (c, next) => {
  const auth = c.req.header("Authorization");
  if (!auth?.startsWith("Bearer ")) return c.json({ error: "unauthorized" }, 401);
  c.set("userId", auth.slice(7));
  const { success } = await c.env.LIMITER.limit({ key: c.get("userId") });
  if (!success) return c.json({ error: "rate limited" }, 429);
  await next();
});

async function consumeQuota(c: { env: Env; get(k: "userId"): string }): Promise<boolean> {
  const stub = c.env.COUNTERS.getByName(`quota:${c.get("userId")}`);
  return (await stub.fetch("https://quota/consume")).ok;
}

app.post("/api/summarize", async (c) => {
  if (!(await consumeQuota(c))) return c.json({ error: "daily quota used" }, 429);
  const { text } = await c.req.json<{ text: string }>();
  const out = await c.env.AI.run(
    "@cf/meta/llama-3.1-8b-instruct",
    { prompt: text.slice(0, 2000), max_tokens: 256 },
    { gateway: { id: c.env.AI_GATEWAY_ID } },
  );
  return c.json(out);
});

export default {
  fetch: app.fetch,
  async queue(batch: MessageBatch<{ userId: string }>, env: Env): Promise<void> {
    for (const m of batch.messages) {
      console.log("job", m.body.userId);
      m.ack();
    }
  },
} satisfies ExportedHandler<Env, { userId: string }>;
