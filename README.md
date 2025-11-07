# Break Tracker

Break Tracker is an internal web application for managing employee breaks. The project is split into two packages:

- **backend/** — Dependency-free Node HTTP API with JSON persistence and an integrated smoke test suite.
- **frontend/** — React (Vite) single-page app served by the backend in production.

## Prerequisites
- Node.js 20+
- npm 10+

## Installing dependencies
Each package is self-contained. Install dependencies once per package:

```sh
npm --prefix frontend ci
```

The backend ships without third-party dependencies, so no install step is required there.

## Automated checks
Run the backend smoke suite and compile the frontend bundle to verify core workflows before shipping changes.

```sh
npm --prefix backend test
npm --prefix frontend run build
```

The backend test boots the API against an isolated JSON database and walks through:

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

## Resolving merge conflicts

Need to clear the "This branch has conflicts" banner on GitHub? Follow the hands-on walkthrough in
[`docs/merge-conflicts.md`](docs/merge-conflicts.md). It breaks the process into seven short steps with
examples of the conflict markers you will see and the exact commands to run.

At a glance, the flow is:

1. Fetch the latest code from `main`.
2. Merge it into your branch.
3. Edit any files that show conflict markers, deleting the `<<<<<<<`, `=======`, and `>>>>>>>` lines.
4. Mark each fixed file with `git add`.
5. Re-run the project tests to ensure everything still passes.
6. Commit the merge and push your branch back to GitHub.

The detailed guide includes optional shortcuts (like keeping either version of a file) and tips for using a
visual editor if you get stuck.
