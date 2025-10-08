# Repository Guidelines

## Project Structure & Module Organization
- `backend/` hosts the Node/Express API (`src/app.js` entry chain) with config in `src/config`, request handling in `controllers`, `routes`, and persistence in `models`. Static files sit in `public/`, runtime logs in `logs/`, and user uploads in `uploads/`.
- `ios/OurVerse/` contains the SwiftUI status app, split into `App/`, `ViewModels/`, `Services/`, and `Models/`, with reusable assets under `Resources/` and unit/UI suites in `Tests/`.
- `infra/` provides deployment scaffolding: `docker-compose.yml` for MongoDB + API, `mongo-init/` seed scripts, and `nginx.conf` for edge routing. Root-level `ourverse.sh` automates restart tasks on production hosts.

## Build, Test & Development Commands
- `cd backend && npm install` installs backend dependencies (Node ≥16).
- `npm run dev` serves the API with nodemon on port 8444; `npm start` runs the same server without auto-reload.
- `npm run normalize:uploads` reconciles file metadata in `uploads/` after manual edits.
- `cd infra && docker-compose up --build` brings up MongoDB and the API using `.env` values.
- iOS: open `ios/OurVerse/OurVerse.xcodeproj` in Xcode, or run `xcodebuild -project ios/OurVerse/OurVerse.xcodeproj -scheme OurVerse -destination 'platform=iOS Simulator,name=iPhone 15' test` for CI-friendly validation.

## Coding Style & Naming Conventions
- JavaScript uses 2-space indentation, single quotes, and semicolons; expose modules via `module.exports` and prefer async/await over raw promises.
- Keep business logic in `services/` and `utils/` while controllers stay thin. New environment keys must be registered in `backend/src/config/env.js`.
- Swift code uses 4-space indentation, SwiftUI naming (`HealthStatusViewModel.swift`), and organizes test doubles alongside the feature under test.

## Testing Guidelines
- Backend lacks a bundled test runner; add Jest-based suites under `backend/tests/` mirroring route or service names and include `npm test` scripts when you introduce them. Until then, document manual checks (e.g., `curl http://localhost:8444/api/health`) in PRs.
- iOS already ships with `OurVerseTests` and `OurVerseUITests`; extend these when adding API clients or UI flows, and keep async tests using XCTest expectations.

## Commit & Pull Request Guidelines
- Follow the existing history: capitalized, present-tense summaries that explain the “what” and “why” (“Refactor GitHub authentication URL handling…”). Reference issue IDs or tickets where applicable.
- PRs should outline the change, list automated/manual test evidence, flag environment or schema updates, and attach screenshots or simulator recordings for UI updates.
- Request reviews from both backend and iOS maintainers when touching shared contracts such as health endpoints or auth payloads to avoid regressions.
