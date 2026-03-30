const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  const delegation = {
    parentAgent: {
      name: 'ScopeGuard Primary Agent',
      type: 'primary',
      scopes: [
        { name: 'repo:read', status: 'granted', description: 'Read repository data' },
        { name: 'repo:write', status: 'granted', description: 'Write to repositories' },
        { name: 'issues:write', status: 'granted', description: 'Create and edit issues' }
      ],
      riskLevel: 'medium',
      tokenSource: 'Auth0 Token Vault',
      model: 'Claude Sonnet'
    },
    subAgent: {
      name: 'ScopeGuard Sub-Agent',
      type: 'sub-agent',
      delegatedBy: 'ScopeGuard Primary Agent',
      scopes: [
        { name: 'repo:read', status: 'inherited', description: 'Read repository data' },
        { name: 'repo:write', status: 'blocked', description: 'Write to repositories' },
        { name: 'issues:write', status: 'blocked', description: 'Create and edit issues' }
      ],
      riskLevel: 'low',
      restriction: 'Downward scoping only - cannot exceed parent permissions'
    },
    policy: {
      rule: 'least-privilege',
      description: 'Sub-agents cannot exceed parent agent permissions. Scope escalation is blocked and logged.',
      enforcement: 'automatic'
    }
  };

  res.json(delegation);
});

module.exports = router;
