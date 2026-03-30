const express = require('express');
const router = express.Router();

// Simulated permission state (in production, this would come from Auth0 Token Vault)
let connectedAccounts = [
  {
    id: 'github-1',
    provider: 'GitHub',
    icon: 'github',
    connectionId: process.env.AUTH0_GITHUB_CONNECTION_ID || 'con_YVcyx2rHTVQHGsDj',
    scopes: ['repo:read', 'repo:write', 'issues:write', 'user:read'],
    status: 'active',
    lastUsed: new Date().toISOString(),
    connectedAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString()
  }
];

router.get('/', (req, res) => {
  res.json({
    accounts: connectedAccounts,
    tokenVault: {
      provider: 'Auth0 Token Vault',
      status: 'connected',
      domain: process.env.AUTH0_DOMAIN
    }
  });
});

router.post('/revoke/:accountId', (req, res) => {
  const { accountId } = req.params;
  const account = connectedAccounts.find(a => a.id === accountId);

  if (!account) {
    return res.status(404).json({ error: 'Account not found' });
  }

  account.status = 'revoked';
  account.scopes = [];
  account.lastUsed = new Date().toISOString();

  res.json({
    message: `Access revoked for ${account.provider}`,
    account
  });
});

router.post('/restore/:accountId', (req, res) => {
  const { accountId } = req.params;
  const account = connectedAccounts.find(a => a.id === accountId);

  if (!account) {
    return res.status(404).json({ error: 'Account not found' });
  }

  account.status = 'active';
  account.scopes = ['repo:read', 'repo:write', 'issues:write', 'user:read'];
  account.lastUsed = new Date().toISOString();

  res.json({
    message: `Access restored for ${account.provider}`,
    account
  });
});

module.exports = router;
