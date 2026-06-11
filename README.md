# RMS MCP Server

An [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server that exposes **Runtime Mobile Security (RMS)** capabilities as tools for AI assistants such as Claude Code.

With this server, an AI assistant can attach Frida to a mobile app, hook methods, search the heap, run arbitrary Frida scripts, and read real-time console output — all without leaving the chat interface.

---

## Prerequisites

- **RMS running** — start it with `rms` or `node rms.js` (default: `http://127.0.0.1:5491`)
- **Python 3.10+**
- Required Python packages:

```bash
pip install mcp httpx python-socketio[client]
```

---

## Configuration file — `.mcp.json`

Place `.mcp.json` in the project root (or any parent directory that Claude Code scans):

```json
{
  "mcpServers": {
    "rms": {
      "command": "python3",
      "args": [
        "/home/afnscbrl/Claude/RMS-Runtime-Mobile-Security/mcp_rms_server.py"
      ],
      "env": {
        "RMS_URL": "http://127.0.0.1:5491",
        "RMS_MCP_BUFFER": "500"
      }
    }
  }
}
```

| Field | Description |
|---|---|
| `command` | Python interpreter to use |
| `args` | Absolute path to `mcp_rms_server.py` |
| `RMS_URL` | Base URL of the running RMS instance |
| `RMS_MCP_BUFFER` | Max lines buffered per real-time channel (default: 500) |

> Adjust `args[0]` if you cloned the repo to a different path.

---

## How it works

The MCP server runs as a stdio process managed by Claude Code. On startup it:

1. Connects to RMS over **Socket.io** (background thread) to buffer real-time events.
2. Exposes all RMS operations as **MCP tools** callable by the AI.
3. Forwards tool calls to the RMS HTTP API and returns results as text.

Real-time output (hooks, heap search, API monitor, etc.) is captured into in-memory ring buffers (one per channel, `RMS_MCP_BUFFER` lines each) and retrieved on demand via `rms_get_console`.

---

## Available tools

### Session & device

| Tool | Description |
|---|---|
| `rms_status` | Check HTTP reachability and Socket.io connection status |
| `rms_get_device_info` | List installed apps and basic device info |
| `rms_start_session` | Attach Frida to a target app (`target_package`, `os`) |

### Class & method inspection

| Tool | Description |
|---|---|
| `rms_dump_classes` | List all loaded Java/ObjC classes (optional `filter`) |
| `rms_get_methods` | List all methods of a class (`class_name`) |
| `rms_diff_classes` | Snapshot/diff loaded classes to find what an action loads |

### Dynamic instrumentation

| Tool | Description |
|---|---|
| `rms_hook_method` | Hook a method and log args/return values |
| `rms_heap_search` | Find live instances of a class and call a method on them |
| `rms_run_frida_script` | Execute arbitrary Frida JavaScript in the attached app |

### API Monitor

| Tool | Description |
|---|---|
| `rms_list_api_monitor_categories` | List all monitorable API categories (Crypto, Network, SMS…) |
| `rms_api_monitor_start` | Start the API Monitor for selected (or all) categories |

### Custom scripts

| Tool | Description |
|---|---|
| `rms_list_custom_scripts` | List bundled Frida scripts for Android and iOS |
| `rms_get_custom_script` | Read the source of a custom script (`os`, `script_name`) |

### Console & utilities

| Tool | Description |
|---|---|
| `rms_get_console` | Read buffered output from a channel: `call_stack`, `hook_stack`, `heap_search`, `api_monitor`, `static_analysis`, `global_stack`, or `all` |
| `rms_reset_console` | Clear all console buffers |
| `rms_save_logs` | Save current console output to disk |
| `rms_file_manager` | Browse (`list`) or read (`read`) files on the device |
| `rms_static_analysis` | Run static analysis on the attached iOS app |

---

## Typical workflow

```
1. Start RMS:           node rms.js
2. Open Claude Code in the project directory (picks up .mcp.json automatically)
3. Check connection:    rms_status
4. List apps:          rms_get_device_info
5. Attach to app:      rms_start_session  { target_package: "com.example.app", os: "Android" }
6. Explore classes:    rms_dump_classes   { filter: "crypto" }
7. List methods:       rms_get_methods    { class_name: "javax.crypto.Cipher" }
8. Hook a method:      rms_hook_method    { class_name: "...", method_name: "...", method_signature: "..." }
9. Watch output:       rms_get_console    { channel: "hook_stack" }
```

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `RMS_URL` | `http://127.0.0.1:5491` | RMS server base URL |
| `RMS_MCP_BUFFER` | `500` | Ring-buffer size per real-time channel |

---

## Troubleshooting

**`Cannot reach RMS at …`** — RMS is not running. Start it with `node rms.js` first.

**`socketio_connected: false`** — RMS is reachable over HTTP but the WebSocket handshake failed. Check for firewall rules or proxy interference on port 5491.

**Empty console channels** — Attach to an app first (`rms_start_session`), interact with it, then read the channel. Buffers only fill after Socket.io connects.

**`FRIDA_CRASH`** — Frida encountered an error while attaching. Verify `frida-server` is running on the device and the package name is correct.
