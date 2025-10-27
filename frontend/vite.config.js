import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// the plugin is optional; if you prefer, omit it and the import.
// if you omit, also remove it from devDependencies and package.json
export default defineConfig({
  plugins: [react()],
});
