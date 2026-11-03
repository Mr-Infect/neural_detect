import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "dist");
const mime = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".ico": "image/x-icon", ".json": "application/json" };
const headers = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
};

const server = http.createServer(async (request, response) => {
  if (request.url === "/health") {
    response.writeHead(200, { ...headers, "Content-Type": "application/json" });
    response.end('{"status":"ok"}');
    return;
  }
  if (request.url?.startsWith("/api/")) {
    const upstream = http.request({ hostname: "api", port: 8000, method: request.method, path: request.url, headers: { ...request.headers, host: "api:8000" } }, (result) => {
      response.writeHead(result.statusCode ?? 502, { ...result.headers, ...headers });
      result.pipe(response);
    });
    upstream.on("error", () => { if (!response.headersSent) response.writeHead(502, headers); response.end(); });
    request.pipe(upstream);
    return;
  }

  let requested;
  try { requested = decodeURIComponent(new URL(request.url ?? "/", "http://localhost").pathname); }
  catch { response.writeHead(400, headers); response.end("Bad request"); return; }
  const candidate = path.resolve(root, `.${requested}`);
  if (candidate !== root && !candidate.startsWith(root + path.sep)) { response.writeHead(400, headers); response.end("Bad request"); return; }
  let file = candidate;
  try { if ((await fs.stat(file)).isDirectory()) file = path.join(file, "index.html"); await fs.access(file); }
  catch { file = path.join(root, "index.html"); }
  try {
    const body = await fs.readFile(file);
    response.writeHead(200, { ...headers, "Content-Type": mime[path.extname(file)] ?? "application/octet-stream", "Cache-Control": file.endsWith("index.html") ? "no-cache" : "public, max-age=31536000, immutable" });
    response.end(body);
  } catch { response.writeHead(404, headers); response.end("Not found"); }
});
server.listen(Number(process.env.PORT ?? 8080), "0.0.0.0");
