# Frontend

## Purpose and architecture

This React and TypeScript application provides the authenticated NEURAL DETECT console. The development image runs Vite with an `/api` proxy. The production image builds static assets and serves them from the small Node HTTP server in `server.mjs`; API requests are forwarded to the Compose `api` service.

## Dependencies and configuration

Node.js 22.13.1 and the exact package versions in `package-lock.json` are used. No frontend secrets belong in browser configuration. Authentication uses short-lived API bearer tokens in browser local storage; use HTTPS at the external reverse proxy in deployed environments.

## Usage and build

From this directory run `npm ci` and `npm run build`. For a production-style local container run Compose with `-f docker-compose.yml -f infrastructure/docker-compose.prod.yml` from the repository root. The production container health endpoint is `/health`.

## Tests and limitations

The production TypeScript/Vite build and CI dependency audit are required checks. The production static server is tested through the image health endpoint and browser verification. There is no independent frontend component test framework yet. The reverse-proxy TLS certificate and external domain are deployment responsibilities.
