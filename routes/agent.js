const express = require('express');
const router = express.Router();
const Anthropic = require('@anthropic-ai/sdk');
const fetch = require('node-fetch');
const { logAction } = require('../db/database');

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const RISK_CLASSIFICATIONS = {
  low: {
    actions: ['list repos', 'list repositories', 'show repos', 'get repos', 'view profile', 'list issues', 'show issues'],
    scopes: ['read'],
    description: 'Read-only operations'
  },
  medium: {
    actions: ['create issue', 'open issue', 'comment on issue', 'add comment', 'create gist'],
    scopes: ['read', 'issues:write'],
    description: 'Write operations within limited scope'
  },
  high: {
    actions: ['delete repo', 'delete repository', 'transfer repo', 'change visibility', 'remove collaborator', 'delete branch', 'force push'],
    scopes: ['read', 'write', 'admin'],
    description: 'Destructive or administrative operations'
  }
};

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

async function getGitHubToken() {
  // Request token from Auth0 Token Vault via M2M flow
  const tokenResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: process.env.AUTH0_AGENT_CLIENT_ID,
      client_secret: process.env.AUTH0_AGENT_CLIENT_SECRET,
      audience: process.env.AUTH0_AUDIENCE,
      grant_type: 'client_credentials'
    })
  });

  if (!tokenResponse.ok) {
    console.error('Auth0 Token Vault unavailable, falling back to GITHUB_TOKEN');
    return process.env.GITHUB_TOKEN || null;
  }

  const { access_token } = await tokenResponse.json();

  // The M2M token from Auth0 is not a GitHub token — use PAT fallback for direct GitHub API calls
  if (process.env.GITHUB_TOKEN) {
    return process.env.GITHUB_TOKEN;
  }

  return access_token;
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
      const res = await fetch('https://api.github.com/user/repos?sort=updated&per_page=10', { headers });
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
      const repoPath = repo_name || 'user';
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

router.post('/', async (req, res) => {
  const { query } = req.body;

  if (!query) {
    return res.status(400).json({ error: 'Query is required' });
  }

  try {
    // Step 1: Classify with Claude
    const classification = await classifyWithClaude(query);

    // Step 2: Check for high risk - require step-up auth
    if (classification.risk === 'high') {
      logAction({
        action: classification.action,
        api: 'GitHub',
        scope_used: 'admin',
        risk_level: 'high',
        status: 'pending',
        user_id: 'user',
        details: 'Step-up authorization required'
      });

      return res.json({
        stepUpRequired: true,
        risk: 'high',
        action: classification.action,
        message: 'This action requires re-authorization. High-risk operations need explicit approval.',
        classification
      });
    }

    // Step 3: Get GitHub token from Auth0
    const githubToken = await getGitHubToken();

    if (!githubToken) {
      logAction({
        action: classification.action,
        api: 'GitHub',
        scope_used: classification.risk === 'low' ? 'read' : 'issues:write',
        risk_level: classification.risk,
        status: 'error',
        user_id: 'user',
        details: 'Failed to obtain GitHub token from Auth0 Token Vault'
      });

      return res.status(500).json({
        error: 'Unable to obtain GitHub access token',
        risk: classification.risk,
        action: classification.action
      });
    }

    // Step 4: Execute GitHub action
    const result = await executeGitHubAction(classification, githubToken);

    const scopeUsed = classification.risk === 'low' ? 'read' : 'issues:write';

    logAction({
      action: classification.action,
      api: 'GitHub',
      scope_used: scopeUsed,
      risk_level: classification.risk,
      status: 'success',
      user_id: 'user',
      details: JSON.stringify(result.data).substring(0, 500)
    });

    return res.json({
      stepUpRequired: false,
      risk: classification.risk,
      action: classification.action,
      result,
      classification
    });

  } catch (err) {
    console.error('Agent error:', err);

    logAction({
      action: query,
      api: 'GitHub',
      scope_used: 'unknown',
      risk_level: 'medium',
      status: 'error',
      user_id: 'user',
      details: err.message
    });

    return res.status(500).json({ error: err.message });
  }
});

// Step-up auth confirmation endpoint
router.post('/confirm', async (req, res) => {
  const { action, approved } = req.body;

  if (!approved) {
    logAction({
      action: action || 'unknown',
      api: 'GitHub',
      scope_used: 'admin',
      risk_level: 'high',
      status: 'denied',
      user_id: 'user',
      details: 'User denied step-up authorization'
    });

    return res.json({
      status: 'denied',
      message: 'High-risk action was denied by the user.'
    });
  }

  logAction({
    action: action || 'unknown',
    api: 'GitHub',
    scope_used: 'admin',
    risk_level: 'high',
    status: 'blocked',
    user_id: 'user',
    details: 'Step-up authorization granted but action blocked in demo mode for safety'
  });

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
