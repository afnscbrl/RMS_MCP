#!/usr/bin/env python3
"""
MCP Server for RMS - Runtime Mobile Security
Connects to a running RMS instance (default: http://127.0.0.1:5491)
and exposes its capabilities as MCP tools.
"""

import asyncio
import json
import os
import threading
from collections import deque
from datetime import datetime
from typing import Any

import httpx
import socketio
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    TextContent,
    Tool,
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
RMS_BASE_URL = os.environ.get("RMS_URL", "http://127.0.0.1:5491")
MAX_BUFFER = int(os.environ.get("RMS_MCP_BUFFER", "500"))  # lines per channel

# ---------------------------------------------------------------------------
# Real-time Socket.io buffer
# ---------------------------------------------------------------------------
# Maps MCP channel name → Socket.io event name emitted by rms.js
_CHANNEL_EVENT = {
    "call_stack":      "call_stack",
    "hook_stack":      "hook_stack",
    "heap_search":     "heap_search",
    "api_monitor":     "api_monitor",
    "static_analysis": "static_analysis",
    "global_stack":    "global_console",   # rms.js emits 'global_console' not 'global_stack'
}

_buffers: dict[str, deque] = {ch: deque(maxlen=MAX_BUFFER) for ch in _CHANNEL_EVENT}
_sio = socketio.Client(reconnection=True, reconnection_attempts=0, logger=False)
_sio_connected = False


def _start_socketio():
    """Connect to RMS Socket.io in a background thread."""
    global _sio_connected

    @_sio.on("connect")
    def _on_connect():
        global _sio_connected
        _sio_connected = True

    @_sio.on("disconnect")
    def _on_disconnect():
        global _sio_connected
        _sio_connected = False

    for channel, event in _CHANNEL_EVENT.items():
        def _make_handler(ch):
            @_sio.on(_CHANNEL_EVENT[ch])
            def _handler(data):
                text = data.get("data", "") if isinstance(data, dict) else str(data)
                _buffers[ch].append(f"[{datetime.now().strftime('%H:%M:%S')}] {text}")
            return _handler
        _make_handler(channel)

    try:
        _sio.connect(RMS_BASE_URL, transports=["websocket", "polling"])
        _sio.wait()
    except Exception:
        pass  # RMS not running yet – tools will show a helpful error


threading.Thread(target=_start_socketio, daemon=True).start()

# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------
server = Server("rms-mcp")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _buf(channel: str) -> str:
    lines = list(_buffers.get(channel, []))
    if not lines:
        return "(empty – no events received yet)"
    return "\n".join(lines)


async def _get(path: str, params: dict | None = None) -> str:
    async with httpx.AsyncClient(base_url=RMS_BASE_URL, timeout=15) as c:
        r = await c.get(path, params=params)
        r.raise_for_status()
        return r.text


async def _post_multi(path: str, pairs: list) -> str:
    """POST with repeated keys (list of (key, value) tuples)."""
    async with httpx.AsyncClient(base_url=RMS_BASE_URL, timeout=30, follow_redirects=True) as c:
        r = await c.post(path, data=pairs)
        r.raise_for_status()
        return r.text


async def _post(path: str, data: dict) -> str:
    async with httpx.AsyncClient(base_url=RMS_BASE_URL, timeout=30, follow_redirects=True) as c:
        r = await c.post(path, data=data)
        r.raise_for_status()
        # Surface frida crash errors via the final URL
        if "frida_crash=True" in str(r.url):
            import urllib.parse
            qs = urllib.parse.parse_qs(str(r.url).split("?", 1)[-1])
            msg = qs.get("frida_crash_message", ["unknown error"])[0]
            return f"FRIDA_CRASH: {msg}"
        return r.text


def _json_or_text(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return text


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="rms_status",
            description=(
                "Check whether the RMS server is reachable and whether the "
                "Socket.io real-time connection is active."
            ),
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="rms_get_device_info",
            description=(
                "Return the list of apps installed on the connected mobile device "
                "and basic device information (name, id, mode)."
            ),
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="rms_start_session",
            description=(
                "Attach Frida to a target app on the device. "
                "Requires the app package/bundle ID and the OS type."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target_package": {
                        "type": "string",
                        "description": "App package name (Android) or bundle ID (iOS).",
                    },
                    "os": {
                        "type": "string",
                        "enum": ["Android", "iOS"],
                        "description": "Mobile OS of the target app.",
                    },
                    "system_package": {
                        "type": "string",
                        "description": "System package to monitor alongside the app (optional).",
                    },
                    "no_system_package": {
                        "type": "boolean",
                        "description": "Set to true to skip monitoring any system package.",
                    },
                },
                "required": ["target_package", "os"],
            },
        ),
        Tool(
            name="rms_get_console",
            description=(
                "Return buffered real-time output from one or more RMS console channels. "
                "Channels: call_stack, hook_stack, heap_search, api_monitor, "
                "static_analysis, global_stack, all."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "channel": {
                        "type": "string",
                        "enum": [
                            "call_stack", "hook_stack", "heap_search",
                            "api_monitor", "static_analysis", "global_stack", "all",
                        ],
                        "description": "Which channel to read. Use 'all' for everything.",
                    }
                },
                "required": ["channel"],
            },
        ),
        Tool(
            name="rms_reset_console",
            description="Clear all RMS console buffers (both local and on the server).",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="rms_save_logs",
            description="Tell RMS to save the current console output to files on disk.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="rms_dump_classes",
            description=(
                "List all Java/ObjC classes currently loaded in the target app. "
                "Optionally filter by a substring."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "filter": {
                        "type": "string",
                        "description": "Case-insensitive substring filter (optional).",
                    }
                },
                "required": [],
            },
        ),
        Tool(
            name="rms_get_methods",
            description="List all methods of a specific class in the target app.",
            inputSchema={
                "type": "object",
                "properties": {
                    "class_name": {
                        "type": "string",
                        "description": "Fully-qualified class name.",
                    }
                },
                "required": ["class_name"],
            },
        ),
        Tool(
            name="rms_hook_method",
            description=(
                "Hook a specific method in the target app. "
                "Returns hook output via the hook_stack and call_stack channels."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "class_name": {
                        "type": "string",
                        "description": "Fully-qualified class name.",
                    },
                    "method_name": {
                        "type": "string",
                        "description": "Method name to hook.",
                    },
                    "method_signature": {
                        "type": "string",
                        "description": "Method signature (as shown in the RMS UI).",
                    },
                    "overload": {
                        "type": "string",
                        "description": "Overload string if needed (optional).",
                    },
                    "args": {
                        "type": "string",
                        "description": "Comma-separated arg names matching the overload (optional).",
                    },
                    "print_stack_trace": {
                        "type": "boolean",
                        "description": "Include stack trace in hook output.",
                    },
                },
                "required": ["class_name", "method_name", "method_signature"],
            },
        ),
        Tool(
            name="rms_heap_search",
            description=(
                "Search the heap for live instances of a class and call a method on them."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "class_name": {
                        "type": "string",
                        "description": "Fully-qualified class name.",
                    },
                    "method_name": {
                        "type": "string",
                        "description": "Method to call on found instances.",
                    },
                    "method_signature": {
                        "type": "string",
                        "description": "Method signature.",
                    },
                },
                "required": ["class_name", "method_name", "method_signature"],
            },
        ),
        Tool(
            name="rms_api_monitor_start",
            description=(
                "Start the API Monitor on the target app. "
                "Monitors sensitive Android API categories (Crypto, Network, SMS, etc.)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "categories": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "List of category names to monitor. "
                            "E.g. ['Crypto', 'Network', 'SMS']. "
                            "Leave empty to use all categories."
                        ),
                    }
                },
                "required": [],
            },
        ),
        Tool(
            name="rms_list_api_monitor_categories",
            description="Return all available API Monitor categories and their hooks.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="rms_list_custom_scripts",
            description="List all available custom Frida scripts bundled with RMS.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="rms_get_custom_script",
            description="Return the source code of a custom Frida script.",
            inputSchema={
                "type": "object",
                "properties": {
                    "os": {
                        "type": "string",
                        "enum": ["Android", "iOS"],
                        "description": "Target OS of the script.",
                    },
                    "script_name": {
                        "type": "string",
                        "description": "File name of the script (e.g. 'root_detection_bypass.js').",
                    },
                },
                "required": ["os", "script_name"],
            },
        ),
        Tool(
            name="rms_run_frida_script",
            description=(
                "Load and execute an arbitrary Frida/JavaScript snippet "
                "inside the currently attached app."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "script": {
                        "type": "string",
                        "description": "Frida JavaScript code to evaluate.",
                    }
                },
                "required": ["script"],
            },
        ),
        Tool(
            name="rms_file_manager",
            description=(
                "Browse or read files on the device through the RMS file manager. "
                "Action 'list' returns directory contents; 'read' returns file contents."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["list", "read"],
                        "description": "Operation to perform.",
                    },
                    "path": {
                        "type": "string",
                        "description": "Absolute path on the device.",
                    },
                },
                "required": ["action", "path"],
            },
        ),
        Tool(
            name="rms_static_analysis",
            description=(
                "Run static analysis on the target iOS app (strings, classes, methods). "
                "Output appears in the static_analysis console channel."
            ),
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="rms_diff_classes",
            description=(
                "Compare two class snapshots to find classes loaded after a specific action. "
                "Use action='snapshot' to take the first snapshot, then 'diff' to compare."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["snapshot", "diff"],
                        "description": "'snapshot' saves current classes; 'diff' shows new ones.",
                    }
                },
                "required": ["action"],
            },
        ),
    ]


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        result = await _dispatch(name, arguments)
    except httpx.ConnectError:
        result = (
            f"Cannot reach RMS at {RMS_BASE_URL}. "
            "Make sure RMS is running (`rms` or `node rms.js`)."
        )
    except httpx.HTTPStatusError as e:
        result = f"RMS returned HTTP {e.response.status_code}: {e.response.text[:500]}"
    except Exception as e:
        result = f"Error: {e}"

    if not isinstance(result, str):
        result = json.dumps(result, indent=2, ensure_ascii=False, default=str)

    return [TextContent(type="text", text=result)]


async def _dispatch(name: str, args: dict) -> Any:
    # ------------------------------------------------------------------ status
    if name == "rms_status":
        try:
            await _get("/")
            reachable = True
        except Exception:
            reachable = False
        return {
            "rms_url": RMS_BASE_URL,
            "http_reachable": reachable,
            "socketio_connected": _sio_connected,
            "buffer_sizes": {k: len(v) for k, v in _buffers.items()},
        }

    # ----------------------------------------------------------- device info
    if name == "rms_get_device_info":
        # The / endpoint returns HTML; we parse what we can from the JSON the
        # template receives. The easiest approach is to POST to get JSON.
        # RMS doesn't have a pure JSON API, so we query the page and extract.
        html = await _get("/")
        # Heuristic: grab device_info from the rendered page
        import re
        m = re.search(r'id="device_info"[^>]*>([^<]+)<', html)
        device_info = m.group(1).strip() if m else "(parse error – read HTML)"
        # Extract app list
        apps = re.findall(r'"identifier"\s*:\s*"([^"]+)"', html)
        if not apps:
            # newer nunjucks template
            apps = re.findall(r'value="([a-zA-Z][a-zA-Z0-9_.]+)"', html)
        return {
            "device_info": device_info,
            "installed_apps": sorted(set(apps)),
            "note": "Visit http://127.0.0.1:5491/ for the full interactive UI.",
        }

    # ---------------------------------------------------------- start session
    if name == "rms_start_session":
        # GET / first so rms.js populates the app_list global before POST uses it
        await _get("/")
        data = {
            "target_package": args["target_package"],
            "mobile_OS": args["os"],
            "package": args["target_package"],
            "system_package": args.get("system_package", ""),
            "no_system_package": "true" if args.get("no_system_package") else "false",
            "mode": "Attach",
        }
        html = await _post("/", data)
        if html.startswith("FRIDA_CRASH:"):
            return f"RMS error while attaching: {html}"
        return (
            f"Frida session started for {args['target_package']} on {args['os']}. "
            "Use rms_get_console to read output."
        )

    # ---------------------------------------------------------- console output
    if name == "rms_get_console":
        channel = args["channel"]
        if channel == "all":
            parts = []
            for ch in _buffers:
                content = _buf(ch)
                parts.append(f"=== {ch.upper()} ===\n{content}")
            return "\n\n".join(parts)
        return _buf(channel)

    # --------------------------------------------------------- reset console
    if name == "rms_reset_console":
        for buf in _buffers.values():
            buf.clear()
        try:
            await _get("/reset_console_logs", {"redirect": "/"})
        except Exception:
            pass
        return "All console buffers cleared."

    # ----------------------------------------------------------- save logs
    if name == "rms_save_logs":
        result = await _get("/save_console_logs")
        return result

    # --------------------------------------------------------- dump classes
    if name == "rms_dump_classes":
        html = await _get("/dump", {"choice": "1"})
        import re
        classes = re.findall(r'<td>\s*([A-Za-z][A-Za-z0-9_.$/\\]+)\s*</td>', html)
        classes = sorted(set(c.strip() for c in classes if "." in c))
        flt = args.get("filter", "").lower()
        if flt:
            classes = [c for c in classes if flt in c.lower()]
        return {
            "total": len(classes),
            "classes": classes,
        }

    # --------------------------------------------------------- get methods
    if name == "rms_get_methods":
        class_name = args["class_name"]
        html = await _get("/dump", {"class": class_name})
        import re
        methods = re.findall(r'<option[^>]*value="([^"]+)"[^>]*>([^<]+)</option>', html)
        method_list = [{"value": v, "label": l.strip()} for v, l in methods]
        return {
            "class": class_name,
            "methods": method_list,
        }

    # ---------------------------------------------------------- hook method
    if name == "rms_hook_method":
        data = {
            "class_name": args["class_name"],
            "class_method": args["method_name"],
            "method_signature": args["method_signature"],
            "overload": args.get("overload", ""),
            "args": args.get("args", ""),
            "print_stack_trace": "true" if args.get("print_stack_trace") else "false",
        }
        result = await _post("/dump", data)
        return (
            f"Hook set on {args['class_name']}.{args['method_name']}. "
            "Use rms_get_console with channel='hook_stack' to see output."
        )

    # --------------------------------------------------------- heap search
    if name == "rms_heap_search":
        data = {
            "class_name": args["class_name"],
            "class_method": args["method_name"],
            "method_signature": args["method_signature"],
        }
        await _post("/heap_search", data)
        return (
            "Heap search triggered. "
            "Use rms_get_console with channel='heap_search' to see results."
        )

    # ------------------------------------------------- api monitor categories
    if name == "rms_list_api_monitor_categories":
        config_path = os.path.join(
            os.path.dirname(__file__), "config", "api_monitor.json"
        )
        with open(config_path) as f:
            data = json.load(f)
        summary = [
            {
                "category": entry["Category"],
                "type": entry["HookType"],
                "hook_count": len(entry["hooks"]),
                "hooks": [f"{h['clazz']}.{h['method']}" for h in entry["hooks"]],
            }
            for entry in data
        ]
        return summary

    # ---------------------------------------------------- api monitor start
    if name == "rms_api_monitor_start":
        categories = args.get("categories", [])
        config_path = os.path.join(
            os.path.dirname(__file__), "config", "api_monitor.json"
        )
        with open(config_path) as f:
            all_cats = json.load(f)

        if categories:
            selected = [e for e in all_cats if e["Category"] in categories]
        else:
            selected = all_cats

        # Send one api_selected value per category (mirrors the web UI checkboxes)
        cat_names = [e["Category"] for e in selected]
        await _post_multi("/api_monitor", [("api_selected", n) for n in cat_names])
        cat_names = [e["Category"] for e in selected]
        return (
            f"API Monitor started for {len(selected)} categories: {cat_names}. "
            "Use rms_get_console with channel='api_monitor' to see output."
        )

    # ------------------------------------------------- list custom scripts
    if name == "rms_list_custom_scripts":
        base = os.path.join(os.path.dirname(__file__), "custom_scripts")
        result: dict[str, list[str]] = {}
        for os_dir in ["Android", "iOS"]:
            path = os.path.join(base, os_dir)
            if os.path.isdir(path):
                result[os_dir] = sorted(
                    f for f in os.listdir(path) if f.endswith(".js")
                )
        return result

    # --------------------------------------------------- get custom script
    if name == "rms_get_custom_script":
        result = await _get(
            "/get_frida_custom_script",
            {"os": args["os"], "cs": args["script_name"]},
        )
        return result

    # --------------------------------------------------- run frida script
    if name == "rms_run_frida_script":
        data = {"frida_custom_script": args["script"], "redirect": "/console_output"}
        await _post("/eval_script_and_redirect", data)
        return (
            "Script submitted. "
            "Use rms_get_console with channel='global_stack' to see output."
        )

    # ---------------------------------------------------- file manager
    if name == "rms_file_manager":
        action = args["action"]
        path = args["path"]
        if action == "list":
            data = {"path": path, "action": "list"}
        else:
            data = {"path": path, "action": "read"}
        result = await _post("/file_manager", data)
        return _json_or_text(result)

    # ------------------------------------------------- static analysis
    if name == "rms_static_analysis":
        html = await _get("/static_analysis")
        return (
            "Static analysis triggered. "
            "Use rms_get_console with channel='static_analysis' to see results."
        )

    # ------------------------------------------------- diff classes
    if name == "rms_diff_classes":
        action = args["action"]
        if action == "snapshot":
            html = await _get("/diff_classes", {"action": "snapshot"})
            return "Class snapshot taken. Now trigger an action in the app, then call diff."
        else:
            html = await _get("/diff_classes", {"action": "diff"})
            import re
            classes = re.findall(r'<li[^>]*>([^<]+)</li>', html)
            return {
                "new_classes_loaded": classes,
                "count": len(classes),
            }

    return f"Unknown tool: {name}"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
