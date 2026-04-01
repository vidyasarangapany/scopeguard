require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { auth, requiresAuth } = require('express-openid-connect');
const { initDb, logAction } = require('./db/database');

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
  baseURL: process.env.BASE_URL || `http://localhost:${PORT}`,
  clientID: process.env.AUTH0_CLIENT_ID,
  clientSecret: process.env.AUTH0_CLIENT_SECRET,
  issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}`,
  routes: {
    login: '/login',
    logout: '/logout',
    callback: '/callback'
  },
  afterCallback: async (req, res, session, decodedState) => {
    let userId = 'unknown';
    try { userId = session.claims?.sub || 'unknown'; } catch {}
    const returnTo = decodedState?.returnTo || '/';

    try {
      if (returnTo.includes('github_connected=1')) {
        logAction({
          action: 'GitHub account connected',
          api: 'Auth0',
          scope_used: 'repo,read:user,user:email',
          risk_level: 'low',
          status: 'success',
          user_id: userId,
          details: 'GitHub social connection linked via Auth0 Token Vault'
        });
      } else {
        logAction({
          action: 'User login',
          api: 'Auth0',
          scope_used: 'openid profile email',
          risk_level: 'low',
          status: 'success',
          user_id: userId,
          details: 'Login via Auth0 Universal Login'
        });
      }
    } catch (logErr) {
      console.error('Audit log error in afterCallback:', logErr.message);
    }

    return session;
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
  logAction({
    action: 'GitHub connection initiated',
    api: 'Auth0',
    scope_used: 'repo,read:user,user:email',
    risk_level: 'low',
    status: 'pending',
    user_id: req.oidc.user.sub,
    details: 'User initiated GitHub OAuth connection via Auth0'
  });

  res.oidc.login({
    authorizationParams: {
      connection: 'github',
      connection_scope: 'repo,read:user,user:email'
    },
    returnTo: '/?github_connected=1'
  });
});

// Logout with audit logging
app.get('/api/logout', (req, res) => {
  if (req.oidc.isAuthenticated()) {
    logAction({
      action: 'User logout',
      api: 'Auth0',
      scope_used: 'session',
      risk_level: 'low',
      status: 'success',
      user_id: req.oidc.user.sub,
      details: 'User logged out'
    });
  }
  res.redirect('/logout');
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
