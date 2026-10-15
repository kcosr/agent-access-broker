// Serves the built portal (`portalDist`) for specs that answer every API call
// with explicit fixtures instead of a Broker.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { portalDist } from "./binaries";

export type PortalAssets = { baseUrl: string; close: () => Promise<void> };

export async function servePortalAssets(): Promise<PortalAssets> {
  const server = createServer(async (request, response) => {
    const pathname = new URL(request.url!, "http://localhost").pathname;
    const asset = pathname.startsWith("/ui/assets/") ? pathname.slice(4) : "index.html";
    try {
      response.setHeader("content-type", asset.endsWith(".js") ? "text/javascript" : asset.endsWith(".css") ? "text/css" : "text/html");
      response.end(await readFile(path.join(portalDist, asset)));
    } catch {
      response.writeHead(404).end();
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    close: () => new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())))
  };
}
