# Security Policy

## Supported Versions
Only the latest published version of @datanexusmcp/mcp-server 
receives security fixes.

## Reporting a Vulnerability
Email: security@datanexusmcp.com
Response time: 48 hours
Please do not open public GitHub issues for security vulnerabilities.
We will acknowledge receipt, investigate, and coordinate disclosure.

## Package Behavior

`@datanexusmcp/mcp-server` is a stdio proxy that connects MCP clients
(Claude Desktop, Cursor, Windsurf) to the DataNexus remote server at
`https://datanexusmcp.com/mcp` via mcp-remote. No user data is
processed locally. This is the standard pattern for remote MCP servers.
Source: https://github.com/datanexusmcp/mcp-server
