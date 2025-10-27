import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.jsx'; // <-- exact casing

createRoot(document.getElementById('root')).render(<App />);
