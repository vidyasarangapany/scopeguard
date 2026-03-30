const express = require('express');
const router = express.Router();
const { ManagementClient } = require('auth0');

const management = new ManagementClient({
  domain: process.env.AUTH0_DOMAIN,
  clientId: process.env.AUTH0_AGENT_CLIENT_ID,
  clientSecret: process.env.AUTH0_AGENT_CLIENT_SECRET
});

// Demo-mode scope state (revoke/restore toggles this locally)
let scopeOverride = null; // null = use real state, 'revoked' or 'active'

router.get('/', async (req, res) => {
  const userId = req.oidc.user.sub;

  try {
    const user = await management.users.get({ id: userId });
    const identities = user.data?.identities || user.identities || [];
    const githubIdentity = identities.find(i => i.provider === 'github');

    const githubConnected = !!githubIdentity;
    const isActive = scopeOverride !== 'revoked' && githubConnected;

    const accounts = githubConnected ? [{
      id: 'github-1',
      provider: 'GitHub',
      icon: 'github',
      connectionId: process.env.AUTH0_GITHUB_CONNECTION_ID || 'con_YVcyx2rHTVQHGsDj',
      scopes: isActive ? ['repo:read', 'repo:write', 'issues:write', 'user:read'] : [],
      status: isActive ? 'active' : 'revoked',
      githubUsername: githubIdentity.profileData?.nickname || githubIdentity.profileData?.name || null,
      lastUsed: new Date().toISOString(),
      connectedAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString()
    }] : [];

    res.json({
      accounts,
      githubConnected,
      tokenVault: {
        provider: 'Auth0 Token Vault',
        status: githubConnected ? 'connected' : 'awaiting_connection',
        domain: process.env.AUTH0_DOMAIN
      }
    });
  } catch (err) {
    console.error('Failed to fetch user identities:', err.message);
    // Fallback — return empty state so frontend can show Connect GitHub
    res.json({
      accounts: [],
      githubConnected: false,
      tokenVault: {
        provider: 'Auth0 Token Vault',
        status: 'error',
        domain: process.env.AUTH0_DOMAIN
      }
    });
  }
});

router.post('/revoke/:accountId', (req, res) => {
  scopeOverride = 'revoked';
  res.json({
    message: 'Access revoked for GitHub (demo mode — Auth0 connection remains intact)',
    account: { id: req.params.accountId, status: 'revoked', scopes: [] }
  });
});

router.post('/restore/:accountId', (req, res) => {
  scopeOverride = null;
  res.json({
    message: 'Access restored for GitHub',
    account: {
      id: req.params.accountId,
      status: 'active',
      scopes: ['repo:read', 'repo:write', 'issues:write', 'user:read']
    }
  });
});

module.exports = router;
