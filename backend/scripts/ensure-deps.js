#!/usr/bin/env node
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const backendDir = path.join(__dirname, '..');
const packageJson = require(path.join(backendDir, 'package.json'));

function hasModule(name) {
  try {
    require.resolve(name, { paths: [backendDir] });
    return true;
  } catch (err) {
    return false;
  }
}

const dependencies = Object.keys(packageJson.dependencies || {});
const missingDeps = dependencies.filter((dep) => !hasModule(dep));

if (missingDeps.length === 0) {
  process.exit(0);
}

console.log('Backend dependencies missing. Installing project packages...');
console.log(`Missing modules: ${missingDeps.join(', ')}`);

try {
  fs.rmSync(path.join(backendDir, 'node_modules'), { recursive: true, force: true });
} catch (err) {
  console.warn(`Failed to clean node_modules: ${err.message}`);
}

const hasLockFile = fs.existsSync(path.join(backendDir, 'package-lock.json'));
const installArgs = hasLockFile
  ? ['ci', '--no-audit', '--no-fund']
  : ['install', '--no-audit', '--no-fund'];

const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const result = spawnSync(npmCommand, installArgs, {
  cwd: backendDir,
  stdio: 'inherit',
});

if (result.error) {
  console.error(`Failed to execute npm: ${result.error.message}`);
  process.exit(result.status || 1);
}

if (result.status !== 0) {
  console.error('Failed to install backend dependencies.');
  process.exit(result.status || 1);
}

const stillMissing = dependencies.filter((dep) => !hasModule(dep));
if (stillMissing.length > 0) {
  console.error(`Dependencies are still missing after installation: ${stillMissing.join(', ')}`);
  process.exit(1);
}
