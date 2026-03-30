# ScopeGuard — Least Privilege Agent Authorization Console

Built for the Auth0 "Authorized to Act" Hackathon 2026.

## Problem
AI agents today run with god-mode API keys. No scoping, no audit trail, no user consent. ScopeGuard fixes that.

## Solution
ScopeGuard is a least-privilege agent authorization console built on Auth0 Token Vault.

## Features
- Least Privilege — agent gets minimum scope needed per task
- Permission Dashboard — see and revoke agent access instantly
- Audit Trail — every action logged with scope, risk level, timestamp
- Sub-Agent Delegation — sub-agents cannot exceed parent permissions

## Tech Stack
- Node.js / Express backend
- Auth0 Token Vault for secure token management
- Claude Sonnet for agent logic
- SQLite for audit logging
- Vanilla HTML/CSS/JS frontend

## Setup
npm install
npm start

## Environment Variables
AUTH0_DOMAIN=
AUTH0_CLIENT_ID=
AUTH0_CLIENT_SECRET=
AUTH0_CALLBACK_URL=
ANTHROPIC_API_KEY=
GITHUB_TOKEN=
PORT=4000