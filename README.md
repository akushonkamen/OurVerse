# OurVerse Mini Program Stack

This repo now ships the OurVerse backend together with a WeChat Mini Program scaffold. Behaviour of the original API is preserved; only the project layout has changed to make mini program development and deployment easier.

## Project Layout

- `backend/` – Node.js API previously served at the project root. All existing endpoints and business logic are intact; run `npm install` inside this folder (or use the root scripts) to get started. Static uploads continue to live under `backend/uploads/`.
- `miniprogram/` – Fresh WeChat Mini Program project shell with a sample index page that pings `/health`. Hook this up to real pages and components as you iterate.
- `infra/` – Deployment assets (Docker Compose, Railway config, helper scripts) updated to point at the new backend location.
- `server.js` – Compatibility shim that keeps `node server.js` working after the move.

## Quick Start

```bash
# Install backend dependencies
npm install --prefix backend

# Run the API locally (from repo root)
npm run dev

# Alternatively, run commands directly inside backend/
cd backend && npm run dev
```

Mini program assets can be imported into WeChat DevTools by opening the `miniprogram/` directory. Remember to update `miniprogram/config/index.js` with the reachable backend domain and to configure legal request domains inside the WeChat console.

For temporary public URLs during development you can run `npm run tunnel`, which triggers the ngrok helper under `backend/scripts/` (requires `ngrok` CLI and GitHub credentials in `.env`).

## Deployment Notes

Use the scripts in `infra/` for container-based deployments. The backend Dockerfile now lives under `backend/`, and `infra/docker-compose.yml`/`infra/deploy.sh` reference the new paths. Existing environment variables (`MONGODB_URI`, `JWT_SECRET`, etc.) remain unchanged.

For more detailed platform instructions (Railway, ngrok testing), check the docs inside `infra/` and the scripts shipped in `backend/scripts/`.
