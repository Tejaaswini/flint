#!/usr/bin/env node
// vulnerable-mcp.mjs — minimal MCP server over stdio for the Flint exfil demo.
//
// NO npm dependencies. Uses only Node built-ins: readline, process.stdin/stdout.
//
// Tools exposed:
//   read_config(name: string) — returns prod_settings with a synthetic API key
//                               when name === "prod_settings"; harmless config otherwise.
//   post_webhook(url: string, body: string) — acknowledges the call without
//                               making a real HTTP request. In enforce mode, the
//                               gateway intercepts before this server sees it.
//
// Wire format: JSON-RPC 2.0 over newline-delimited stdio.

import { createInterface } from 'node:readline';

const send = (obj) => {
  process.stdout.write(JSON.stringify(obj) + '\n');
};

// read_config tool — returns synthetic credentials for "prod_settings"
function handleReadConfig(args) {
  const name = args?.name ?? '';
  if (name === 'prod_settings') {
    return {
      content: [{
        type: 'text',
        // Synthetic key: matches fingerprint.go regex  sk[-_][A-Za-z0-9]{20,}
        // and credential_exfil.go regex sk-(?:proj-)?[A-Za-z0-9_\-]{32,}
        // NEVER a real key — 40 placeholder chars after "sk-"
        text: '# Production settings\nAPI_KEY=sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA9876\nDB_HOST=db.internal\nLOG_LEVEL=info',
      }],
    };
  }
  return {
    content: [{
      type: 'text',
      text: `# Config for ${name}\nFEATURE_X=on`,
    }],
  };
}

// post_webhook tool — acknowledges without making a real HTTP request.
// In enforce mode the gateway intercepts the request before it reaches here.
function handlePostWebhook(args) {
  const url = args?.url ?? '(no url)';
  return {
    content: [{
      type: 'text',
      text: `posted to ${url}`,
    }],
  };
}

// Tool schemas
const toolSchemas = [
  {
    name: 'read_config',
    description: 'Read a named configuration block.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Config block name' },
      },
      required: ['name'],
    },
  },
  {
    name: 'post_webhook',
    description: 'Post data to a webhook URL.',
    inputSchema: {
      type: 'object',
      properties: {
        url:  { type: 'string', description: 'Destination URL' },
        body: { type: 'string', description: 'Request body' },
      },
      required: ['url'],
    },
  },
];

// Handle a single JSON-RPC request. Returns a response object, or null for
// notifications (which must not be replied to).
function dispatch(req) {
  const { id, method, params } = req;

  // Notifications (no id) — no response
  if (id === undefined || id === null) {
    if (method === 'notifications/initialized') {
      // nothing to do
    }
    return null;
  }

  switch (method) {
    case 'initialize':
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'flint-vulnerable-mcp', version: '0.1.0' },
        },
      };

    case 'tools/list':
      return {
        jsonrpc: '2.0',
        id,
        result: { tools: toolSchemas },
      };

    case 'tools/call': {
      const name = params?.name;
      let result;
      if (name === 'read_config') {
        result = handleReadConfig(params?.arguments);
      } else if (name === 'post_webhook') {
        result = handlePostWebhook(params?.arguments);
      } else {
        return {
          jsonrpc: '2.0',
          id,
          error: { code: -32601, message: `Method not found: unknown tool ${name}` },
        };
      }
      return { jsonrpc: '2.0', id, result };
    }

    default:
      return {
        jsonrpc: '2.0',
        id,
        error: { code: -32601, message: `Method not found: ${method}` },
      };
  }
}

// Read newline-delimited JSON from stdin
const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });

rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  let req;
  try {
    req = JSON.parse(trimmed);
  } catch (e) {
    send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }

  const resp = dispatch(req);
  if (resp !== null) {
    send(resp);
  }
});

rl.on('close', () => {
  process.exit(0);
});
