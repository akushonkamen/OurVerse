# OurVerse Backend + iOS Stack

This repository now pairs the OurVerse backend with a native SwiftUI iOS client. The API behaviour remains unchanged; only the project layout has shifted to make iOS development and deployment straightforward.

## Project Layout

- `backend/` – Node.js API served previously from the project root. All endpoints and business logic stay intact; install dependencies inside this folder (or via the root scripts). Static uploads continue to live under `backend/uploads/`.
- `ios/OurVerse/` – SwiftUI iOS app that pings the same backend `/health` endpoint and can be expanded into the full mobile experience. Update `Resources/BackendConfig.plist` with your reachable backend domain.
- `infra/` – Deployment assets (Docker Compose, Railway config, helper scripts) already wired to the backend location.
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

### iOS App
1. Ensure the backend is running and reachable from your simulator or device.
2. Update `ios/OurVerse/Resources/BackendConfig.plist` with the correct base URL (defaults to `http://localhost:3000`).
3. Open `ios/OurVerse/OurVerse.xcodeproj` in Xcode 15 or newer, select the `OurVerse` target, and build & run.

## Deployment Notes

Use the scripts in `infra/` for container-based deployments. The backend Dockerfile lives under `backend/`, and `infra/docker-compose.yml`/`infra/deploy.sh` reference the new paths. Existing environment variables (`MONGODB_URI`, `JWT_SECRET`, etc.) remain unchanged.

For temporary public URLs during development you can run `npm run tunnel`, which triggers the ngrok helper under `backend/scripts/` (requires `ngrok` CLI and GitHub credentials in `.env`).
