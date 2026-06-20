#!/usr/bin/env node
/**
 * AgentSentinel — MCP Prompt Injection Runtime Guard
 * 
 * A transparent MCP proxy that intercepts all tool responses and scans them
 * for prompt injection attacks before they reach the model's context window.
 * 
 * Usage:
 *   TARGET_MCP_CMD="npx @some/mcp-server" node server.js
 *   TARGET_MCP_CMD="npx @some/mcp-server" SENTINEL_BLOCK=true node server.js
 */

const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { z } = require('zod');
const fs = require('fs');
const path = require('path');

// ── Config ────────────────────────────────────────────────────────────────────
const TARGET_MCP_CMD  = process.env.TARGET_MCP_CMD;
const SENTINEL_BLOCK  = process.env.SENTINEL_BLOCK === 'true';
const LOG_FILE        = path.join(process.env.SENTINEL_LOG_DIR || __dirname, 'sentinel.log');

if (!TARGET_MCP_CMD) {
  console.error('[AgentSentinel] ERROR: TARGET_MCP_CMD not set.');
  process.exit(1);
}

// ── Injection Patterns ────────────────────────────────────────────────────────
const PATTERNS = [
  /ignore\s+(?:all\s+)?previous\s+(?:instructions?|prompts?)/i,
  /disregard\s+(?:all\s+)?(?:prior|previous)\s+(?:instructions?|context)/i,
  /forget\s+(?:your|all|everything|the\s+above)/i,
  /new\s+instructions?:/i,
  /you\s+are\s+now\s+(?:a|an|the)\s+/i,
  /override\s+your\s+(?:system|instructions?|constraints?)/i,
  /\[system\]/i,
  /act\s+as\s+(?:if\s+you\s+(?:are|were)|a\s+)/i,
];

function scanText(text) {
  if (!text || typeof text !== 'string') return { level: null, matched: [], snippet: '' };

  const matched = PATTERNS.filter(p => p.test(text)).map(p => p.source);
  if (!matched.length) return { level: null, matched: [], snippet: '' };

  const level = matched.length >= 3 ? 'HIGH' : matched.length >= 2 ? 'MEDIUM' : 'LOW';
  const firstMatch = text.search(PATTERNS.find(p => p.test(text)));
  const start = Math.max(0, firstMatch - 40);
  const end   = Math.min(text.length, firstMatch + 120);
  const snippet = (start > 0 ? '…' : '') + text.slice(start, end) + (end < text.length ? '…' : '');
  return { level, matched, snippet };
}

function logThreat(entry) {
  try {
    fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + '\n');
  } catch (e) {
    console.error('[AgentSentinel] Log write failed:', e.message);
  }
  console.error(`[AgentSentinel] ⚠️  ${entry.level} injection detected in tool "${entry.tool}" — patterns: ${entry.matched.join(', ')}`);
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  // 1. Build target client transport (spawns the real MCP server)
  const [cmd, ...args] = TARGET_MCP_CMD.split(/\s+/);
  const clientTransport = new StdioClientTransport({ command: cmd, args });

  const targetClient = new Client(
    { name: 'agent-sentinel-client', version: '1.0.0' },
    { capabilities: { tools: {} } }
  );
  await targetClient.connect(clientTransport);

  // 2. Discover tools from target
  const { tools: targetTools } = await targetClient.listTools();
  console.error(`[AgentSentinel] Proxying ${targetTools.length} tools from "${TARGET_MCP_CMD}"`);
  console.error(`[AgentSentinel] Block mode: ${SENTINEL_BLOCK} | Log: ${LOG_FILE}`);

  // 3. Create proxy server
  const proxyServer = new McpServer({
    name:    'agent-sentinel',
    version: '1.0.0',
  });

  // 4. Register each target tool with injection scanning
  for (const tool of targetTools) {
    // Build a zod schema from the JSON Schema input schema
    const inputSchema = {};
    if (tool.inputSchema?.properties) {
      for (const [key, val] of Object.entries(tool.inputSchema.properties)) {
        // Map common JSON Schema types → zod; default to z.any()
        if (val.type === 'string')  inputSchema[key] = z.string().optional();
        else if (val.type === 'number') inputSchema[key] = z.number().optional();
        else if (val.type === 'boolean') inputSchema[key] = z.boolean().optional();
        else inputSchema[key] = z.any().optional();
      }
    }

    proxyServer.tool(
      tool.name,
      tool.description || '',
      inputSchema,
      async (args) => {
        // Forward call to real target
        const result = await targetClient.callTool({ name: tool.name, arguments: args });

        // Scan all text content in response
        const allText = (result.content || [])
          .filter(c => c.type === 'text')
          .map(c => c.text)
          .join('\n');

        const { level, matched, snippet } = scanText(allText);

        if (level) {
          const entry = {
            ts:      new Date().toISOString(),
            tool:    tool.name,
            level,
            matched,
            snippet,
          };
          logThreat(entry);

          if (SENTINEL_BLOCK && level === 'HIGH') {
            return {
              content: [{
                type: 'text',
                text: `[AgentSentinel BLOCKED] This tool response was quarantined due to detected prompt injection (${matched.length} patterns matched). Threat level: HIGH.`,
              }],
              isError: true,
            };
          }
        }

        return result;
      }
    );
  }

  // 5. Connect proxy server to stdio (agent talks to us via stdin/stdout)
  const serverTransport = new StdioServerTransport();
  await proxyServer.connect(serverTransport);

  // Graceful shutdown
  const shutdown = async (sig) => {
    console.error(`[AgentSentinel] Received ${sig}, shutting down…`);
    await targetClient.close();
    process.exit(0);
  };
  process.on('SIGINT',  () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch(err => {
  console.error('[AgentSentinel] Fatal error:', err);
  process.exit(1);
});
