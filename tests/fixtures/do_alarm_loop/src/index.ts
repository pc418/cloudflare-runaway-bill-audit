import { DurableObject } from "cloudflare:workers";

export interface Env {
  ROOMS: DurableObjectNamespace<Room>;
  SYNCER: DurableObjectNamespace<Syncer>;
}

export class Room extends DurableObject<Env> {
  async fetch(request: Request): Promise<Response> {
    await this.ctx.storage.setAlarm(Date.now() + 1000);
    return new Response("ok");
  }

  // Heartbeat: flush presence every 500 ms "until the room is empty".
  async alarm(): Promise<void> {
    const members = (await this.ctx.storage.get<string[]>("members")) ?? [];
    await this.ctx.storage.put("lastFlush", Date.now());
    console.log("flushed", members.length);
    await this.ctx.storage.setAlarm(Date.now() + 500);
  }
}

export class Syncer extends DurableObject<Env> {
  async alarm(alarmInfo?: AlarmInvocationInfo): Promise<void> {
    try {
      await this.pushUpstream();
    } catch (err) {
      // retry later
      await this.scheduleRetry();
    }
  }

  private async pushUpstream(): Promise<void> {
    const res = await fetch("https://upstream.example.com/sync", { method: "POST" });
    if (!res.ok) throw new Error(`upstream ${res.status}`);
  }

  private async scheduleRetry(): Promise<void> {
    await this.ctx.storage.setAlarm(Date.now() + 30_000);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const id = env.ROOMS.idFromName(new URL(request.url).pathname);
    return env.ROOMS.get(id).fetch(request);
  },
} satisfies ExportedHandler<Env>;
