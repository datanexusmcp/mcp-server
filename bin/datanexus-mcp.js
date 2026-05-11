#!/usr/bin/env node
/**
 * DataNexus MCP — stdio proxy for Glama and local MCP clients.
 *
 * Bridges stdio ↔ the live remote server at https://datanexusmcp.com/mcp
 * using mcp-remote. No Python, no Redis, no PostgreSQL required.
 *
 * Usage:
 *   npx -y @datanexusmcp/mcp-server
 *
 * Claude Desktop claude_desktop_config.json:
 *   {
 *     "mcpServers": {
 *       "datanexus": {
 *         "command": "npx",
 *         "args": ["-y", "@datanexusmcp/mcp-server"]
 *       }
 *     }
 *   }
 */

const { spawn } = require("child_process");

const REMOTE_URL = "https://datanexusmcp.com/mcp";

let proxyBin;
try {
  proxyBin = require.resolve("mcp-remote/dist/proxy.js");
} catch (_) {
  console.error("[DataNexus MCP] mcp-remote not found — reinstall: npm install @datanexusmcp/mcp-server");
  process.exit(1);
}

const child = spawn(process.execPath, [proxyBin, REMOTE_URL], {
  stdio: "inherit",
});

child.on("error", (err) => {
  console.error(`[DataNexus MCP] Failed to start proxy: ${err.message}`);
  process.exit(1);
});

child.on("exit", (code) => process.exit(code ?? 0));
