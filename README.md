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
If GitHub shows "This branch has conflicts" when you open a pull request, sync your branch with the latest `main` changes and resolve the edits locally:

1. Fetch the newest commits: `git fetch origin`
2. Switch to your feature branch (for example `work`): `git checkout work`
3. Merge the updated main branch: `git merge origin/main`
4. For each file listed with conflicts, open it and remove the `<<<<<<<`, `=======`, and `>>>>>>>` markers, keeping the intended final content.
5. Once every conflict is resolved, mark the files as ready: `git add <file>`
6. Verify the project still works by running:
   ```sh
   npm --prefix backend test
   npm --prefix frontend run build
   ```
7. Commit the merge: `git commit`
8. Push the resolved branch back to GitHub: `git push origin work`

After these steps, the pull request will update automatically and the "conflicts" banner will disappear.
