#!/usr/bin/env python3
"""
COMYC Telemetry Sidecar & Dashboard Server
- Collects UDP telemetry heartbeats from nodes running with --demo
- Maintains in-memory state of active nodes and circuits with TTL pruning
- Serves the frontend web dashboard on HTTP 0.0.0.0:8080
- Broadcasts real-time topology updates over Server-Sent Events (SSE) and WebSocket
- Supports a standalone --mock mode for quick frontend testing without C++ nodes
"""

import argparse
import asyncio
import json
import logging
import os
import random
import sys
import time
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler
from typing import Dict, Any, Set

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")
logger = logging.getLogger("demo_server")

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist")


class TopologyState:
    def __init__(self, ttl_seconds: float = 8.0):
        self.ttl = ttl_seconds
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.subscribers: Set[asyncio.Queue] = set()

    def update_node(self, data: Dict[str, Any], sender_addr):
        node_id = data.get("node_id")
        if not node_id:
            return

        ip = sender_addr[0]
        port = data.get("port") or sender_addr[1]
        role = data.get("role", "unknown")
        circuits = data.get("circuits", [])

        self.nodes[node_id] = {
            "node_id": node_id,
            "role": role,
            "ip": ip,
            "port": port,
            "circuits": circuits,
            "last_seen": time.time()
        }
        self.notify_subscribers()

    def prune_stale(self) -> bool:
        now = time.time()
        stale = [nid for nid, n in self.nodes.items() if now - n["last_seen"] > self.ttl]
        if stale:
            for nid in stale:
                logger.info(f"Pruning stale node: {nid}")
                del self.nodes[nid]
            self.notify_subscribers()
            return True
        return False

    def get_snapshot(self) -> Dict[str, Any]:
        nodes_list = []
        circuits_list = []
        
        for n in self.nodes.values():
            nodes_list.append({
                "id": n["node_id"],
                "role": n["role"],
                "ip": n["ip"],
                "port": n["port"],
                "label": f"{n['node_id']} ({n['ip']}:{n['port']})"
            })
            for c in n.get("circuits", []):
                circuits_list.append({
                    "cid": c.get("cid"),
                    "client": n["node_id"],
                    "relays": c.get("relays", []),
                    "exit": c.get("exit"),
                    "dest": c.get("dest", "")
                })

        return {
            "nodes": nodes_list,
            "circuits": circuits_list,
            "timestamp": time.time()
        }

    def notify_subscribers(self):
        snapshot = self.get_snapshot()
        raw = json.dumps(snapshot)
        for q in list(self.subscribers):
            try:
                q.put_nowait(raw)
            except Exception:
                pass


class TelemetryProtocol(asyncio.DatagramProtocol):
    def __init__(self, state: TopologyState):
        self.state = state

    def datagram_received(self, data: bytes, addr):
        try:
            payload = json.loads(data.decode("utf-8"))
            self.state.update_node(payload, addr)
        except Exception as e:
            logger.debug(f"Invalid telemetry datagram from {addr}: {e}")


async def handle_events(reader, writer, state: TopologyState):
    """Serve Server-Sent Events stream for live graph updates."""
    writer.write(b"HTTP/1.1 200 OK\r\n")
    writer.write(b"Content-Type: text/event-stream\r\n")
    writer.write(b"Cache-Control: no-cache\r\n")
    writer.write(b"Connection: keep-alive\r\n")
    writer.write(b"Access-Control-Allow-Origin: *\r\n\r\n")
    await writer.drain()

    queue = asyncio.Queue(maxsize=32)
    state.subscribers.add(queue)

    # Initial snapshot
    initial_raw = json.dumps(state.get_snapshot())
    writer.write(f"data: {initial_raw}\n\n".encode("utf-8"))
    await writer.drain()

    try:
        while True:
            raw = await queue.get()
            writer.write(f"data: {raw}\n\n".encode("utf-8"))
            await writer.drain()
    except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        state.subscribers.discard(queue)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def handle_snapshot_api(writer, state: TopologyState):
    snapshot = json.dumps(state.get_snapshot())
    body = snapshot.encode("utf-8")
    writer.write(b"HTTP/1.1 200 OK\r\n")
    writer.write(b"Content-Type: application/json\r\n")
    writer.write(b"Access-Control-Allow-Origin: *\r\n")
    writer.write(f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8"))
    writer.write(body)
    await writer.drain()
    writer.close()


def get_mime_type(path: str) -> str:
    if path.endswith(".html"): return "text/html"
    if path.endswith(".js") or path.endswith(".mjs"): return "application/javascript"
    if path.endswith(".css"): return "text/css"
    if path.endswith(".svg"): return "image/svg+xml"
    if path.endswith(".json"): return "application/json"
    if path.endswith(".png"): return "image/png"
    return "application/octet-stream"


async def handle_static(path: str, writer):
    clean_path = path.split("?")[0].lstrip("/")
    if not clean_path:
        clean_path = "index.html"
    file_path = os.path.join(STATIC_DIR, clean_path)

    # Fallback to index.html for SPA routing
    if not os.path.exists(file_path):
        file_path = os.path.join(STATIC_DIR, "index.html")

    if not os.path.exists(file_path):
        msg = b"<h1>Dashboard static files not built yet. Please run build step in src/gui</h1>"
        writer.write(b"HTTP/1.1 404 Not Found\r\n")
        writer.write(b"Content-Type: text/html\r\n")
        writer.write(f"Content-Length: {len(msg)}\r\n\r\n".encode("utf-8"))
        writer.write(msg)
        await writer.drain()
        writer.close()
        return

    try:
        with open(file_path, "rb") as f:
            content = f.read()
        mime = get_mime_type(file_path)
        writer.write(b"HTTP/1.1 200 OK\r\n")
        writer.write(f"Content-Type: {mime}\r\n".encode("utf-8"))
        writer.write(b"Access-Control-Allow-Origin: *\r\n")
        writer.write(f"Content-Length: {len(content)}\r\n\r\n".encode("utf-8"))
        writer.write(content)
        await writer.drain()
    except Exception as e:
        logger.error(f"Error serving {file_path}: {e}")
    finally:
        writer.close()


async def http_handler(reader, writer, state: TopologyState):
    try:
        line = await reader.readline()
        if not line:
            writer.close()
            return
        parts = line.decode("utf-8").split()
        if len(parts) < 2:
            writer.close()
            return
        method, path = parts[0], parts[1]

        # Drain remaining headers
        while True:
            h = await reader.readline()
            if not h or h == b"\r\n":
                break

        if path == "/events" or path == "/sse":
            await handle_events(reader, writer, state)
        elif path == "/api/topology":
            await handle_snapshot_api(writer, state)
        else:
            await handle_static(path, writer)
    except Exception as e:
        logger.debug(f"HTTP connection error: {e}")
        writer.close()


async def mock_generator(state: TopologyState, num_clients=3, num_relays=4, num_exits=2):
    """Simulates active nodes and moving circuits for testing the visualizer without C++ nodes."""
    logger.info(f"Starting mock generator with {num_clients} clients, {num_relays} relays, {num_exits} exits")

    relays = [f"10.0.0.{10+i}:6969" for i in range(num_relays)]
    exits = [f"10.0.0.{50+i}:6969" for i in range(num_exits)]

    # Register Relays & Exits
    for i, r in enumerate(relays):
        ip, port = r.split(":")
        state.update_node({
            "node_id": f"relay-{i+1}",
            "role": "relay",
            "port": int(port),
            "circuits": []
        }, (ip, int(port)))

    for i, e in enumerate(exits):
        ip, port = e.split(":")
        state.update_node({
            "node_id": f"exit-{i+1}",
            "role": "exit",
            "port": int(port),
            "circuits": []
        }, (ip, int(port)))

    cid_counter = 1000
    while True:
        await asyncio.sleep(2.0)
        # Refresh relays & exits
        for i, r in enumerate(relays):
            ip, port = r.split(":")
            state.update_node({
                "node_id": f"relay-{i+1}",
                "role": "relay",
                "port": int(port),
                "circuits": []
            }, (ip, int(port)))

        for i, e in enumerate(exits):
            ip, port = e.split(":")
            state.update_node({
                "node_id": f"exit-{i+1}",
                "role": "exit",
                "port": int(port),
                "circuits": []
            }, (ip, int(port)))

        # Update clients with random active circuits
        for i in range(num_clients):
            cid_counter += 1
            # Pick 1 to 2 random relays for the path
            hop_count = random.randint(1, min(2, len(relays)))
            r_path = random.sample(relays, hop_count)
            e = random.choice(exits)
            dest = f"142.250.190.{random.randint(10, 200)}:443"
            client_id = f"client-{i+1}"
            client_ip = f"10.0.0.{100+i}"

            circuits = [
                {"cid": cid_counter, "relays": r_path, "exit": e, "dest": dest}
            ]
            if random.random() > 0.5:
                circuits.append({
                    "cid": cid_counter + 50,
                    "relays": random.sample(relays, random.randint(1, min(2, len(relays)))),
                    "exit": random.choice(exits),
                    "dest": "default (vpn)"
                })

            state.update_node({
                "node_id": client_id,
                "role": "client",
                "port": 5000 + i,
                "circuits": circuits
            }, (client_ip, 5000 + i))


async def pruner_task(state: TopologyState):
    while True:
        await asyncio.sleep(1.0)
        state.prune_stale()


async def main():
    parser = argparse.ArgumentParser(description="COMYC Telemetry & Dashboard Server")
    parser.add_argument("--udp-port", type=int, default=8008, help="UDP telemetry port (default: 8008)")
    parser.add_argument("--http-port", type=int, default=8080, help="HTTP dashboard port (default: 8080)")
    parser.add_argument("--ttl", type=float, default=6.0, help="Node heartbeat TTL in seconds (default: 6.0)")
    parser.add_argument("--mock", action="store_true", help="Run with simulated mock nodes and rotating circuits")
    parser.add_argument("--mock-clients", type=int, default=3, help="Number of mock clients")
    parser.add_argument("--mock-relays", type=int, default=4, help="Number of mock relays")
    parser.add_argument("--mock-exits", type=int, default=2, help="Number of mock exits")
    args = parser.parse_args()

    state = TopologyState(ttl_seconds=args.ttl)
    loop = asyncio.get_running_loop()

    # Start UDP telemetry server
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: TelemetryProtocol(state),
        local_addr=("0.0.0.0", args.udp_port)
    )
    logger.info(f"UDP Telemetry Receiver listening on 0.0.0.0:{args.udp_port}")

    # Start HTTP server (SSE + static files)
    http_server = await asyncio.start_server(
        lambda r, w: http_handler(r, w, state),
        "0.0.0.0",
        args.http_port
    )
    logger.info(f"HTTP Dashboard Server running at http://localhost:{args.http_port}")

    asyncio.create_task(pruner_task(state))

    if args.mock:
        asyncio.create_task(mock_generator(state, args.mock_clients, args.mock_relays, args.mock_exits))

    async with http_server:
        await http_server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Exiting...")
