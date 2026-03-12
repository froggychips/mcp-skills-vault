#!/usr/bin/env node
/**
 * MCP Wrapper Template – server.js
 *
 * This file is the entry-point for a minimal Model Context Protocol (MCP) server
 * that exposes one or more tools to an AI agent via the stdio transport.
 *
 * Replace every occurrence of {{name}} / {{tool}} with your actual tool name before
 * publishing.  The tool definitions go in the ListTools handler and the execution
 * logic goes in the CallTool handler.
 *
 * Architecture overview:
 *   stdin  → StdioServerTransport → Server → handler → result → stdout
 *
 * See https://modelcontextprotocol.io for the full protocol specification.
 */

const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const { StdioServerTransport } = require("@modelcontextprotocol/sdk/server/stdio.js");
const {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} = require("@modelcontextprotocol/sdk/types.js");

// ---------------------------------------------------------------------------
// Server initialisation
// ---------------------------------------------------------------------------

const server = new Server(
  {
    // Replace {{name}} with your MCP server name (e.g. "my-cli-mcp")
    name: "{{name}}",
    version: "0.1.0",
  },
  {
    capabilities: {
      // Declare that this server exposes tools.
      // Add "resources: {}" and/or "prompts: {}" here if needed.
      tools: {},
    },
  }
);

// ---------------------------------------------------------------------------
// Tool listing
// ---------------------------------------------------------------------------

/**
 * ListTools handler – called by the client to discover available tools.
 * Return every tool your server supports here so agents can choose the right one.
 */
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      // -----------------------------------------------------------------------
      // Example tool definition – replace or extend as needed.
      // -----------------------------------------------------------------------
      // {
      //   name: "do_something",
      //   description: "One-sentence description of what this tool does.",
      //   inputSchema: {
      //     type: "object",
      //     properties: {
      //       param1: {
      //         type: "string",
      //         description: "Description of param1.",
      //       },
      //       param2: {
      //         type: "number",
      //         description: "Description of param2.",
      //       },
      //     },
      //     required: ["param1"],
      //   },
      // },
    ],
  };
});

// ---------------------------------------------------------------------------
// Tool execution
// ---------------------------------------------------------------------------

/**
 * CallTool handler – called whenever the client invokes a tool.
 *
 * Best practices:
 *  - Validate required arguments before executing.
 *  - Return structured content (preferably { type: "text", text: "..." }).
 *  - Use isError: true on the response for expected/handled failures so the
 *    agent can try to recover rather than crashing.
 *  - Let unexpected errors propagate as thrown exceptions (the SDK will
 *    convert them to protocol-level errors automatically).
 */
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    // -----------------------------------------------------------------------
    // Add a case for each tool declared in ListToolsRequestSchema above.
    // -----------------------------------------------------------------------
    // case "do_something": {
    //   const { param1, param2 } = args ?? {};
    //   if (!param1) {
    //     return {
    //       isError: true,
    //       content: [{ type: "text", text: "param1 is required." }],
    //     };
    //   }
    //   const result = await doSomething(param1, param2);
    //   return { content: [{ type: "text", text: JSON.stringify(result) }] };
    // }

    default:
      // Returning an error response (rather than throwing) lets the agent
      // handle unknown-tool situations gracefully.
      return {
        isError: true,
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
      };
  }
});

// ---------------------------------------------------------------------------
// Transport & startup
// ---------------------------------------------------------------------------

/**
 * Graceful shutdown: flush any in-flight responses before exiting so that
 * the parent process receives complete data.
 */
async function shutdown() {
  try {
    await server.close();
  } catch {
    // Ignore close errors during shutdown
  }
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

// Connect the server to the stdio transport and start listening.
const transport = new StdioServerTransport();
server.connect(transport).catch((err) => {
  console.error("Fatal: failed to connect MCP transport:", err);
  process.exit(1);
});
