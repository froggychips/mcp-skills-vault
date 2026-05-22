#!/usr/bin/env node
/**
 * Minimal fake MCP server for testing mcp_eval.cjs.
 *
 * Speaks newline-delimited JSON-RPC 2.0 on stdin/stdout.
 *
 * Configurable via env vars:
 *   FAKE_TOOLS_JSON   JSON-encoded array of tools to return from tools/list
 *                     (default: empty array)
 *   FAKE_BOOT_DELAY_MS  Delay before responding to the initialize request,
 *                       used to drive the timeout test case
 *   FAKE_FAIL         If "exit" → exit 1 before responding; if "error" →
 *                     respond to initialize with a JSON-RPC error.
 *
 * Intentionally simple — no MCP SDK, no real capability negotiation,
 * just enough to drive the eval handshake.
 */

'use strict';

const FAKE_TOOLS_JSON   = process.env.FAKE_TOOLS_JSON   || '[]';
const FAKE_BOOT_DELAY_MS = parseInt(process.env.FAKE_BOOT_DELAY_MS || '0', 10);
const FAKE_FAIL         = process.env.FAKE_FAIL         || '';

if (FAKE_FAIL === 'exit') {
  // Simulate a server that crashes before responding to initialize.
  process.stderr.write('fake server crashed during boot\n');
  process.exit(1);
}

let tools = [];
try {
  tools = JSON.parse(FAKE_TOOLS_JSON);
  if (!Array.isArray(tools)) tools = [];
} catch {
  tools = [];
}

let buffer = '';

function send(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

process.stdin.on('data', (chunk) => {
  buffer += chunk.toString('utf8');
  let nl;
  while ((nl = buffer.indexOf('\n')) !== -1) {
    const line = buffer.slice(0, nl).trim();
    buffer = buffer.slice(nl + 1);
    if (!line) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    handle(msg);
  }
});

process.stdin.on('end', () => process.exit(0));

function handle(msg) {
  if (msg.method === 'initialize') {
    const respond = () => {
      if (FAKE_FAIL === 'error') {
        send({ jsonrpc: '2.0', id: msg.id, error: { code: -32603, message: 'fake initialize failure' } });
        return;
      }
      send({
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          protocolVersion: '2025-06-18',
          capabilities: { tools: {} },
          serverInfo: { name: 'fake-mcp-server', version: '0.0.0' },
        },
      });
    };
    if (FAKE_BOOT_DELAY_MS > 0) setTimeout(respond, FAKE_BOOT_DELAY_MS);
    else respond();
    return;
  }

  if (msg.method === 'notifications/initialized') {
    // No response for notifications.
    return;
  }

  if (msg.method === 'tools/list') {
    send({ jsonrpc: '2.0', id: msg.id, result: { tools } });
    return;
  }

  // Unknown method → respond with method-not-found.
  if (typeof msg.id !== 'undefined') {
    send({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: `unknown method ${msg.method}` } });
  }
}
