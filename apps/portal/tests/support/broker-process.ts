// Starts a Broker for a fixture whose configuration names the Broker's own
// origin, so its port must be chosen before the Broker starts. The port is
// found free and released for the Broker to bind, and another process can
// take it in between; only that failure is retried.
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { once } from "node:events";
import { createServer, type AddressInfo } from "node:net";
import { setTimeout as delay } from "node:timers/promises";

export interface StartedBroker {
  child: ChildProcessWithoutNullStreams;
  port: number;
  baseUrl: string;
}

export interface BrokerStart {
  binary: string;
  /** Writes the configuration of a Broker served at `baseUrl` on `port` and returns its path. */
  configure(port: number, baseUrl: string): Promise<string>;
  cwd: string;
  env?: NodeJS.ProcessEnv;
  /** Receives everything the Broker writes, across attempts. */
  onOutput?(text: string): void;
  /** Headers for each readiness request. */
  readinessHeaders?(): Record<string, string>;
  timeoutMs: number;
  /** Startups to try in all; only address-in-use failures are retried. */
  attempts?: number;
}

/** A Broker that exited before readiness, with what it wrote. */
export class BrokerExitedError extends Error {
  constructor(readonly output: string) {
    super(`broker exited before readiness\n${output}`);
  }
}

/** A loopback port that was free when it was chosen. */
export async function freeLoopbackPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.address() as AddressInfo;
  await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  return port;
}

/**
 * True when the Broker's own `broker_start_failed` event reports that its
 * listen address was in use.
 */
export function failedWithAddressInUse(output: string): boolean {
  return output.split("\n").some((line) => {
    let event: unknown;
    try {
      event = JSON.parse(line);
    } catch {
      return false;
    }
    const { event: name, error } = (event ?? {}) as { event?: unknown; error?: unknown };
    return name === "broker_start_failed" && typeof error === "string" && /^Address already in use \(os error \d+\)$/.test(error);
  });
}

/**
 * Starts the Broker on a fresh loopback port and waits until `/v1/healthz`
 * answers. A Broker that exits first fails the start at once, unless its own
 * startup event shows that another process took the port; that startup is
 * retried on a new port, up to `attempts` startups in all. `timeoutMs`
 * bounds every start together, and a Broker that does not become ready is
 * stopped.
 */
export async function startBroker(options: BrokerStart): Promise<StartedBroker> {
  const attempts = options.attempts ?? 3;
  const deadline = Date.now() + options.timeoutMs;
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await startOnce(options, await freeLoopbackPort(), deadline);
    } catch (error) {
      if (!(error instanceof BrokerExitedError) || attempt >= attempts || Date.now() >= deadline
          || !failedWithAddressInUse(error.output)) throw error;
    }
  }
}

async function startOnce(options: BrokerStart, port: number, deadline: number): Promise<StartedBroker> {
  const baseUrl = `http://127.0.0.1:${port}`;
  const config = await options.configure(port, baseUrl);
  const output: string[] = [];
  const record = (text: string) => {
    output.push(text);
    options.onOutput?.(text);
  };
  const child = spawn(options.binary, ["--config", config, "serve", "--listen", `127.0.0.1:${port}`], {
    cwd: options.cwd,
    env: options.env ?? process.env
  });
  const closed = once(child, "close").catch(() => undefined);
  // Ends any readiness request or pause once the Broker exits or fails to
  // spawn, so a listener that accepts without answering, such as another
  // process holding the port, cannot hide the Broker's exit.
  const ended = new AbortController();
  child.once("exit", () => ended.abort());
  child.stdout.on("data", (chunk: Buffer) => record(String(chunk)));
  child.stderr.on("data", (chunk: Buffer) => record(String(chunk)));
  const failure: { spawn?: Error } = {};
  child.on("error", (error) => {
    failure.spawn = error;
    record(error.message);
    ended.abort();
  });
  try {
    for (;;) {
      if (failure.spawn) throw failure.spawn;
      if (child.exitCode !== null || child.signalCode !== null) {
        await closed;
        throw new BrokerExitedError(output.join(""));
      }
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error(`broker did not become ready\n${output.join("")}`);
      const headers = options.readinessHeaders?.() ?? {};
      try {
        const response = await fetch(`${baseUrl}/v1/healthz`, {
          headers,
          signal: AbortSignal.any([ended.signal, AbortSignal.timeout(remaining)])
        });
        await response.body?.cancel();
        if (response.ok) return { child, port, baseUrl };
      } catch {
        // Retry while the broker starts; the checks above end the wait.
      }
      await delay(Math.min(250, Math.max(0, deadline - Date.now())), undefined, { signal: ended.signal }).catch(() => undefined);
    }
  } catch (error) {
    await stopBroker(child);
    throw error;
  }
}

/** Stops the Broker with SIGTERM, then SIGKILL after five seconds. */
async function stopBroker(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (child.pid === undefined || child.exitCode !== null || child.signalCode !== null) return;
  const exited = once(child, "exit");
  child.kill("SIGTERM");
  const timer = setTimeout(() => child.kill("SIGKILL"), 5_000);
  await exited;
  clearTimeout(timer);
}
