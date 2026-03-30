require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { auth, requiresAuth } = require('express-openid-connect');
const { initDb } = require('./db/database');

const app = express();
const PORT = process.env.PORT || 4000;

// Middleware
app.use(cors());
app.use(express.json());

// Auth0 OpenID Connect middleware
app.use(auth({
  authRequired: false,
  auth0Logout: true,
  secret: process.env.AUTH0_SECRET,
  baseURL: `http://localhost:${PORT}`,
  clientID: process.env.AUTH0_CLIENT_ID,
  clientSecret: process.env.AUTH0_CLIENT_SECRET,
  issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}`,
  routes: {
    login: '/login',
    logout: '/logout',
    callback: '/callback'
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

// Auth state endpoint — returns user info if logged in
app.get('/api/me', (req, res) => {
  if (req.oidc.isAuthenticated()) {
    res.json({
      authenticated: true,
      user: req.oidc.user
    });
  } else {
    res.json({ authenticated: false });
  }
});

// Connect GitHub — triggers Auth0 login with GitHub social connection
app.get('/connect-github', requiresAuth(), (req, res) => {
  res.oidc.login({
    authorizationParams: {
      connection: 'github',
      connection_scope: 'repo,read:user,user:email'
    },
    returnTo: '/'
  });
});

// Protected API routes
app.use('/agent', requiresAuth(), require('./routes/agent'));
app.use('/permissions', requiresAuth(), require('./routes/permissions'));
app.use('/audit-log', requiresAuth(), require('./routes/audit'));
app.use('/delegation', requiresAuth(), require('./routes/delegation'));

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
