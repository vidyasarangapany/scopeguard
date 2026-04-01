const express = require('express');
const router = express.Router();
const Anthropic = require('@anthropic-ai/sdk');
const fetch = require('node-fetch');
const { ManagementClient } = require('auth0');
const { logAction } = require('../db/database');

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const management = new ManagementClient({
  domain: process.env.AUTH0_DOMAIN,
  clientId: process.env.AUTH0_MANAGEMENT_CLIENT_ID || process.env.AUTH0_AGENT_CLIENT_ID,
  clientSecret: process.env.AUTH0_MANAGEMENT_CLIENT_SECRET || process.env.AUTH0_AGENT_CLIENT_SECRET
});

// Sub-agent allowed actions — read only, no write
const SUB_AGENT_ALLOWED = ['list_repos', 'list_issues', 'get_user'];

async function classifyWithClaude(query) {
  const message = await anthropic.messages.create({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 1024,
    messages: [
      {
        role: 'user',
        content: `You are a security-focused AI that classifies GitHub actions by risk level.

Classify the following user request into exactly one risk level and extract the intended action:

Risk levels:
- LOW: Read-only operations (list repos, view profile, list issues, get user info)
- MEDIUM: Limited write operations (create issue, add comment, create gist)
- HIGH: Destructive/admin operations (delete repo, transfer repo, change visibility, remove collaborator)

User request: "${query}"

Respond in JSON format only, no markdown:
{"risk": "low|medium|high", "action": "brief action description", "github_action": "list_repos|create_issue|get_user|list_issues|delete_repo|other", "requires_repo": false, "repo_name": null, "issue_title": null, "issue_body": null}`
      }
    ]
  });

  try {
    const text = message.content[0].text;
    return JSON.parse(text);
  } catch {
    return { risk: 'medium', action: query, github_action: 'other', requires_repo: false };
  }
}

async function getGitHubToken(userId) {
  try {
    const user = await management.users.get({ id: userId });
    const identities = user.data?.identities || user.identities || [];
    const githubIdentity = identities.find(i => i.provider === 'github');

    if (githubIdentity && githubIdentity.access_token) {
      logAction({
        action: 'Token exchange',
        api: 'Auth0 Token Vault',
        scope_used: 'read:user_idp_tokens',
        risk_level: 'low',
        status: 'success',
        user_id: userId,
        details: 'GitHub OAuth token retrieved from Auth0 Token Vault identity'
      });
      return githubIdentity.access_token;
    }

    const fallbackToken = process.env.GITHUB_TOKEN || null;
    logAction({
      action: 'Token exchange',
      api: 'Auth0 Token Vault',
      scope_used: 'read:user_idp_tokens',
      risk_level: 'low',
      status: fallbackToken ? 'success' : 'error',
      user_id: userId,
      details: fallbackToken
        ? 'No GitHub identity in Token Vault — fell back to GITHUB_TOKEN PAT'
        : 'No GitHub identity in Token Vault and no PAT fallback available'
    });
    return fallbackToken;
  } catch (err) {
    const fallbackToken = process.env.GITHUB_TOKEN || null;
    logAction({
      action: 'Token exchange',
      api: 'Auth0 Token Vault',
      scope_used: 'read:user_idp_tokens',
      risk_level: 'low',
      status: fallbackToken ? 'success' : 'error',
      user_id: userId,
      details: `Token Vault retrieval failed: ${err.message}` + (fallbackToken ? ' — fell back to GITHUB_TOKEN PAT' : '')
    });
    return fallbackToken;
  }
}

async function executeGitHubAction(classification, githubToken) {
  const headers = {
    'Authorization': `token ${githubToken}`,
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'ScopeGuard-Agent'
  };

  const { github_action, repo_name, issue_title, issue_body } = classification;

  switch (github_action) {
    case 'list_repos': {
      // FIXED: visibility=public enforces least-privilege
      const res = await fetch('https://api.github.com/user/repos?sort=updated&per_page=10&visibility=public&affiliation=owner', { headers });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`GitHub API error ${res.status}: ${errText}`);
      }
      const repos = await res.json();
      return {
        type: 'repos',
        data: repos.map(r => ({
          name: r.full_name,
          description: r.description,
          stars: r.stargazers_count,
          language: r.language,
          updated: r.updated_at,
          private: r.private,
          url: r.html_url
        }))
      };
    }

    case 'list_issues': {
      const url = repo_name
        ? `https://api.github.com/repos/${repo_name}/issues?per_page=10`
        : 'https://api.github.com/issues?per_page=10';
      const res = await fetch(url, { headers });
      if (!res.ok) throw new Error(`GitHub API error ${res.status}`);
      const issues = await res.json();
      return {
        type: 'issues',
        data: issues.map(i => ({
          title: i.title,
          number: i.number,
          state: i.state,
          repo: i.repository?.full_name || repo_name,
          url: i.html_url
        }))
      };
    }

    case 'create_issue': {
      if (!repo_name) throw new Error('Repository name required to create an issue');
      const res = await fetch(`https://api.github.com/repos/${repo_name}/issues`, {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: issue_title || 'New issue from ScopeGuard Agent',
          body: issue_body || 'This issue was created by ScopeGuard AI Agent.'
        })
      });
      if (!res.ok) throw new Error(`GitHub API error ${res.status}`);
      const issue = await res.json();
      return {
        type: 'issue_created',
        data: { number: issue.number, title: issue.title, url: issue.html_url }
      };
    }

    case 'get_user': {
      const res = await fetch('https://api.github.com/user', { headers });
      if (!res.ok) throw new Error(`GitHub API error ${res.status}`);
      const user = await res.json();
      return {
        type: 'user',
        data: { login: user.login, name: user.name, public_repos: user.public_repos, url: user.html_url }
      };
    }

    default:
      return { type: 'unsupported', data: { message: `Action "${github_action}" is not supported yet.` } };
  }
}

// ===== PRIMARY AGENT =====
router.post('/', async (req, res) => {
  const { query } = req.body;
  const userId = req.oidc.user.sub;

  if (!query) return res.status(400).json({ error: 'Query is required' });

  try {
    const classification = await classifyWithClaude(query);

    if (classification.risk === 'high') {
      logAction({
        action: classification.action,
        api: 'GitHub',
        scope_used: 'admin',
        risk_level: 'high',
        status: 'pending',
        user_id: userId,
        details: 'Step-up authorization required — Primary Agent'
      });

      return res.json({
        stepUpRequired: true,
        risk: 'high',
        action: classification.action,
        message: 'This action requires re-authorization. High-risk operations need explicit approval.',
        classification,
        agent: 'primary'
      });
    }

    const githubToken = await getGitHubToken(userId);
    if (!githubToken) {
      return res.status(500).json({ error: 'Unable to obtain GitHub access token', risk: classification.risk, action: classification.action });
    }

    const result = await executeGitHubAction(classification, githubToken);

    logAction({
      action: classification.action,
      api: 'GitHub',
      scope_used: classification.risk === 'low' ? 'repo:read' : 'issues:write',
      risk_level: classification.risk,
      status: 'success',
      user_id: userId,
      details: `[Primary Agent] ${JSON.stringify(result.data).substring(0, 400)}`
    });

    return res.json({
      stepUpRequired: false,
      risk: classification.risk,
      action: classification.action,
      result,
      classification,
      agent: 'primary'
    });

  } catch (err) {
    console.error('Primary agent error:', err);
    logAction({ action: query, api: 'GitHub', scope_used: 'unknown', risk_level: 'medium', status: 'error', user_id: userId, details: err.message });
    return res.status(500).json({ error: err.message });
  }
});

// ===== SUB-AGENT =====
// Enforces downward scoping: only list_repos, list_issues, get_user allowed
router.post('/sub', async (req, res) => {
  const { query } = req.body;
  const userId = req.oidc.user.sub;

  if (!query) return res.status(400).json({ error: 'Query is required' });

  try {
    const classification = await classifyWithClaude(query);

    // Sub-agent scope enforcement — block anything not in allowed list
    const isAllowed = SUB_AGENT_ALLOWED.includes(classification.github_action);

    if (!isAllowed) {
      logAction({
        action: classification.action,
        api: 'GitHub',
        scope_used: classification.risk === 'high' ? 'admin' : 'issues:write',
        risk_level: classification.risk,
        status: 'blocked',
        user_id: userId,
        details: `[Sub-Agent] Scope escalation blocked — action "${classification.github_action}" exceeds delegated permissions (repo:read only)`
      });

      return res.json({
        stepUpRequired: false,
        risk: classification.risk,
        action: classification.action,
        blocked: true,
        agent: 'sub',
        result: {
          type: 'scope_blocked',
          data: {
            message: `Sub-Agent blocked: "${classification.action}" requires write permissions not granted to this agent. Sub-Agent is limited to read:repo and read:issues only. Scope escalation logged.`
          }
        }
      });
    }

    // Allowed — execute with Token Vault token (same token, enforced by action whitelist)
    const githubToken = await getGitHubToken(userId);
    if (!githubToken) {
      return res.status(500).json({ error: 'Unable to obtain GitHub access token' });
    }

    const result = await executeGitHubAction(classification, githubToken);

    logAction({
      action: classification.action,
      api: 'GitHub',
      scope_used: 'repo:read',
      risk_level: 'low',
      status: 'success',
      user_id: userId,
      details: `[Sub-Agent] ${JSON.stringify(result.data).substring(0, 400)}`
    });

    return res.json({
      stepUpRequired: false,
      risk: 'low',
      action: classification.action,
      result,
      classification,
      agent: 'sub'
    });

  } catch (err) {
    console.error('Sub-agent error:', err);
    logAction({ action: query, api: 'GitHub', scope_used: 'repo:read', risk_level: 'low', status: 'error', user_id: userId, details: `[Sub-Agent] ${err.message}` });
    return res.status(500).json({ error: err.message });
  }
});

// ===== STEP-UP CONFIRMATION =====
router.post('/confirm', async (req, res) => {
  const { action, approved } = req.body;
  const userId = req.oidc.user.sub;

  if (!approved) {
    logAction({ action: action || 'unknown', api: 'GitHub', scope_used: 'admin', risk_level: 'high', status: 'denied', user_id: userId, details: 'User denied step-up authorization' });
    return res.json({ status: 'denied', message: 'High-risk action was denied by the user.' });
  }

  logAction({ action: action || 'unknown', api: 'GitHub', scope_used: 'admin', risk_level: 'high', status: 'blocked', user_id: userId, details: 'Step-up granted but action blocked in demo mode for safety' });

  return res.json({
    status: 'blocked',
    message: 'Step-up authorization verified. Destructive action blocked for safety in demo mode.',
    result: {
      type: 'high_risk_blocked',
      data: { message: `Step-up authorization required — deletion blocked for safety in demo mode. The attempt has been logged.` }
    }
  });
});

module.exports = router;
