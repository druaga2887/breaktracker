// backend/serveStaticUI.js
const path = require('path');
const fs = require('fs');
const express = require('express');

/**
 * Mounts the built React/Vite UI (copied by CI into backend/public).
 * Must be called AFTER your /api/* routes and BEFORE any 404/error handlers.
 */
module.exports = function mountStaticUI(app) {
  const publicDir = path.resolve(__dirname, 'public');

  if (fs.existsSync(publicDir)) {
    // Serve static files (index.html by default)
    app.use(express.static(publicDir, { index: 'index.html', maxAge: '15m' }));

    // SPA fallback for any non-API route
    app.get(/^\/(?!api).*/, (_req, res) => {
      res.sendFile(path.join(publicDir, 'index.html'));
    });
  } else {
    console.warn('[serveStaticUI] Static UI directory not found:', publicDir);
  }
};
