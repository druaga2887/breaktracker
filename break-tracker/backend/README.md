# Break Tracker Backend (Starter)

## Quick start (local)
```bash
cd backend
npm install
PORT=3001 JWT_SECRET=devsecret node server.js
# open http://localhost:3001/api/health
# default admin: admin / admin123 (you'll be asked to change it)
```

## API (high level)
- POST /api/auth/login
- POST /api/auth/change-password
- GET /api/departments
- POST /api/departments
- PUT /api/departments/:id
- DELETE /api/departments/:id (soft)
- POST /api/teams  (auto-picks first active department if none sent)
- PUT /api/teams/:id
- DELETE /api/teams/:id (soft)
- POST /api/break-types
- PUT /api/break-types/:id
- DELETE /api/break-types/:id (soft)
- POST /api/users
- PUT /api/users/:id
- PUT /api/employees/:id
- POST /api/breaks/start
- POST /api/breaks/stop
```

It uses SQLite at `backend/data.sqlite` by default.
