import { getSandbox, proxyToSandbox, type Sandbox } from "@cloudflare/sandbox";
import { Hono } from "hono";

export { Sandbox } from "@cloudflare/sandbox";

type Env = { Sandbox: DurableObjectNamespace<Sandbox>; MODEL: string };

const app = new Hono<{ Bindings: Env }>();

// Every request (including /favicon.ico and /apple-touch-icon.png) lands here.
app.all("*", async (c) => {
  const sandbox = getSandbox(c.env.Sandbox, "moltbot", { keepAlive: true });
  await sandbox.startProcess("node gateway.js");
  const proxied = await proxyToSandbox(c.req.raw, c.env);
  if (proxied) return proxied;
  return sandbox.containerFetch(c.req.raw, 18789);
});

export default app;
