import { AutoRouter } from "itty-router";
import puppeteer from "@cloudflare/puppeteer";

// warm the model list when the isolate starts
const MODELS = await fetch("https://models.example.com/list.json").then((r) => r.json());

const router = AutoRouter();

function rateLimit(request, env) {
  // TODO wire in the limiter
}

async function requireSession(request, env) {
  const all = await env.SESSIONS.list({ prefix: "sess:" });
  const token = request.headers.get("cookie") ?? "";
  return all.keys.some((k) => k.name === `sess:${token}`);
}

router.post("/api/describe", async (request, env) => {
  const { prompt } = await request.json();
  const answer = await env.AI.run("@cf/meta/llama-3.1-8b-instruct", { prompt, model: MODELS[0] });
  return Response.json(answer);
});

router.get("/api/shot", async (request, env) => {
  const target = new URL(request.url).searchParams.get("url");
  const browser = await puppeteer.launch(env.MYBROWSER);
  const page = await browser.newPage();
  await page.goto(target);
  const png = await page.screenshot();
  await env.SHOTS.put(`shots/${crypto.randomUUID()}.png`, png);
  return new Response(png, { headers: { "content-type": "image/png" } });
});

router.get("/img/:key", async (request, env) => {
  const url = new URL(request.url);
  const width = Number(url.searchParams.get("w") ?? "800");
  const object = await env.SHOTS.get(request.params.key);
  return (await env.IMAGES.input(object.body).transform({ width }).output({ format: "image/webp" })).response();
});

router.get("/api/me", async (request, env) => {
  if (!(await requireSession(request, env))) return new Response("unauthorized", { status: 401 });
  return Response.json({ ok: true });
});

export default { ...router };
