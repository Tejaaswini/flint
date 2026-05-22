#!/usr/bin/env node
// sample_agent.mjs — pipes scripted JSON-RPC into the gateway's stdin to drive the demo.
//
// The gateway is launched as `node sample_agent.mjs | flint-gateway ... -- npx server-everything`.
// This script's stdout is the gateway's agent-side stdin.
//
// It fires a mix of allowed and denied calls, paced so the live UI feed has steady,
// readable activity.

import { setTimeout as sleep } from 'node:timers/promises';

const send = (obj) => {
  process.stdout.write(JSON.stringify(obj) + '\n');
};

const log = (...args) => {
  process.stderr.write('[sample-agent] ' + args.join(' ') + '\n');
};

// ----------------------------------------------------------------------------
// Sequence
// ----------------------------------------------------------------------------

let id = 1;
const next = () => id++;

// 1. MCP handshake
send({
  jsonrpc: '2.0',
  id: next(),
  method: 'initialize',
  params: {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'flint-demo', version: '0.1.0' },
  },
});
await sleep(1500);

send({ jsonrpc: '2.0', method: 'notifications/initialized' });
await sleep(500);

// 2. List tools — the gateway filters this to what the agent can discover
send({ jsonrpc: '2.0', id: next(), method: 'tools/list' });
await sleep(2000);

log('handshake complete; starting tool calls');

// 3. Sequence of calls covering: allow, allow, deny (printEnv), allow, deny (sampleLLM), allow ...
const sequence = [
  { name: 'echo', arguments: { message: 'hello flint' } },
  { name: 'add', arguments: { a: 7, b: 35 } },
  { name: 'printEnv', arguments: {} },                          // deny — explicit_deny
  { name: 'getTinyImage', arguments: {} },
  { name: 'echo', arguments: { message: 'second tick' } },
  { name: 'sampleLLM', arguments: { prompt: 'one liner about cats' } }, // deny — explicit_deny
  { name: 'longRunningOperation', arguments: { duration: 2, steps: 3 } },
  { name: 'annotatedMessage', arguments: { messageType: 'success', includeImage: false } },
  { name: 'add', arguments: { a: 11, b: 13 } },
  { name: 'echo', arguments: { message: 'third tick' } },
  { name: 'getResourceReference', arguments: { resourceId: 42 } },
  { name: 'unknownDangerousTool', arguments: { recklessness: 'high' } }, // deny — no_matching_rule
];

for (const call of sequence) {
  send({
    jsonrpc: '2.0',
    id: next(),
    method: 'tools/call',
    params: call,
  });
  await sleep(2500);
}

// 4. Steady-state loop so the live feed keeps moving
log('entering steady-state loop');
const steady = [
  { name: 'echo', arguments: { message: 'tick' } },
  { name: 'add', arguments: { a: 1, b: 1 } },
  { name: 'getTinyImage', arguments: {} },
  { name: 'printEnv', arguments: {} }, // will be denied each time
];

let i = 0;
while (true) {
  const call = steady[i % steady.length];
  send({
    jsonrpc: '2.0',
    id: next(),
    method: 'tools/call',
    params: call,
  });
  i++;
  await sleep(4000);
}
