require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { initDb } = require('./db/database');

const app = express();
const PORT = process.env.PORT || 4000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Routes
app.use('/agent', require('./routes/agent'));
app.use('/permissions', require('./routes/permissions'));
app.use('/audit-log', require('./routes/audit'));
app.use('/delegation', require('./routes/delegation'));

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'ScopeGuard',
    version: '1.0.0',
    auth0Domain: process.env.AUTH0_DOMAIN,
    timestamp: new Date().toISOString()
  });
});

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Initialize DB then start server
initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`\n  ScopeGuard running at http://localhost:${PORT}\n`);
    });
  })
  .catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });
