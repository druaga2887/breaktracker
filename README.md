# Break Tracker

Break Tracker is an internal web application for managing employee breaks. The project is split into two packages:

- **backend/** — Express API with SQLite persistence and an integrated smoke test suite.
- **frontend/** — React (Vite) single-page app served by the backend in production.

## Prerequisites
- Node.js 20+
- npm 10+

## Installing dependencies
Each package is self-contained. Install dependencies once per package:

```sh
npm --prefix backend ci
npm --prefix frontend ci
```

The backend test runner automatically prepares dependencies on demand, so installing ahead of time is optional.

## Automated checks
Run the backend smoke suite and compile the frontend bundle to verify core workflows before shipping changes.

```sh
npm --prefix backend test
npm --prefix frontend run build
```

The backend test boots the API against an isolated SQLite database and walks through:

- initial admin login and forced password reset
- role-aware access control
- break start/stop lifecycle
- live status and summary reporting

## Manual verification
1. Start the API: `npm --prefix backend start`
2. In another terminal, serve the built frontend: `npm --prefix frontend run preview -- --host`
3. Sign in with the seeded admin user (`admin` / `admin123`), follow the password reset prompt, and explore the dashboard.

During manual testing, confirm:

- live dashboard filters update counts as breaks start and stop
- reports respect date and team/department filters
- admin tables allow creating and editing entities with status toggles

## Continuous integration
GitHub Actions installs dependencies, runs the backend smoke tests, and verifies a production build of the frontend. Keep these commands green locally to ensure the pipeline succeeds.
