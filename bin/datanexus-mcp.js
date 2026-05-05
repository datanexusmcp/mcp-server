#!/usr/bin/env node
/**
 * DataNexus MCP — npm launcher.
 *
 * Requires Python 3.12+ and the datanexus-mcp Python package:
 *   pip install datanexus-mcp
 *
 * Then run via npx:
 *   npx -y @datanexus/mcp-server
 *
 * Or add to Claude Desktop claude_desktop_config.json:
 *   {
 *     "mcpServers": {
 *       "datanexus": {
 *         "command": "npx",
 *         "args": ["-y", "@datanexus/mcp-server"]
 *       }
 *     }
 *   }
 */

const { spawn } = require("child_process");
const path = require("path");

const python = process.env.DATANEXUS_PYTHON || "python3";

const child = spawn(python, ["-m", "datanexus.main"], {
  stdio: "inherit",
  env: {
    ...process.env,
  },
});

child.on("error", (err) => {
  if (err.code === "ENOENT") {
    console.error(
      `[DataNexus MCP] Python interpreter not found: '${python}'\n` +
      `Install Python 3.12+ and run: pip install datanexus-mcp\n` +
      `Or set DATANEXUS_PYTHON=/path/to/python3`
    );
  } else {
    console.error(`[DataNexus MCP] Failed to start server: ${err.message}`);
  }
  process.exit(1);
});

child.on("exit", (code) => {
  process.exit(code ?? 0);
});
