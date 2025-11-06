#!/usr/bin/env node
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const backendDir = path.join(__dirname, '..');

function hasModule(name) {
  try {
    require.resolve(name, { paths: [backendDir] });
    return true;
  } catch (err) {
    return false;
  }
}

if (hasModule('express')) {
  process.exit(0);
}

console.log('Backend dependencies missing. Installing project packages...');

try {
  fs.rmSync(path.join(backendDir, 'node_modules'), { recursive: true, force: true });
} catch (err) {
  console.warn(`Failed to clean node_modules: ${err.message}`);
}

const hasLockFile = fs.existsSync(path.join(backendDir, 'package-lock.json'));
const installArgs = hasLockFile
  ? ['ci', '--no-audit', '--no-fund']
  : ['install', '--no-audit', '--no-fund'];

const result = spawnSync('npm', installArgs, {
  cwd: backendDir,
  stdio: 'inherit',
});

if (result.status !== 0) {
  console.error('Failed to install backend dependencies.');
  process.exit(result.status || 1);
}
