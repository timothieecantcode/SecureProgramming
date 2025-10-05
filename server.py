# server.py
import asyncio
import json
import uuid


class Server:
    def __init__(self, host="127.0.0.1", port=0, introducer_host="127.0.0.1", introducer_port=8000):
        self.server_id = str(uuid.uuid4())
        self.host = host
        self.port = port
        self.introducer_host = introducer_host
        self.introducer_port = introducer_port

        self.peers = {}                # server_id -> {"host":..., "port":...}
        self.active_peer_writers = {}  # server_id -> writer
        self.active_clients = {}       # client_id -> writer

    # Register with introducer to get current server list
    async def register_with_introducer(self):
        try:
            reader, writer = await asyncio.open_connection(self.introducer_host, self.introducer_port)
            join_message = {
                "type": "SERVER_JOIN",
                "payload": {
                    "server_id": self.server_id,
                    "host": self.host,
                    "port": self.port,
                    "pubkey": "FAKE_PUBLIC_KEY"
                }
            }
            writer.write(json.dumps(join_message).encode())
            await writer.drain()

            data = await reader.read(4096)
            response = json.loads(data.decode())
            print(f"[Introducer] Server list received: {response}")
            self.peers = response.get("servers", {})

            writer.close()
            await writer.wait_closed()
        except Exception as e:
            print(f"[Error] Failed to register with introducer: {e}")

    # Handle incoming connections (clients or servers)
    async def handle_connection(self, reader, writer):
        peer_name = writer.get_extra_info('peername')
        print(f"[Connection] New connection from {peer_name}")

        while True:
            try:
                data = await reader.read(4096)
                if not data:
                    print(f"[Connection] {peer_name} disconnected")
                    break

                message = json.loads(data.decode())
                msg_type = message.get("type", "")
                sender = message.get("from")
                recipient = message.get("to")
                visited = set(message.get("visited_servers", []))

                print(f"[Received] {msg_type} from {sender}, to {recipient}, visited: {visited}")

                # --- CLIENT HELLO ---
                if msg_type == "USER_HELLO":
                    self.active_clients[sender] = writer
                    ack = {"type": "USER_HELLO_ACK", "from": self.server_id, "to": sender, "payload": {}}
                    writer.write(json.dumps(ack).encode())
                    await writer.drain()
                    print(f"[Hello] Registered client {sender}")

                # --- DIRECT MESSAGE ---
                elif msg_type == "MSG_DIRECT":
                    if recipient in self.active_clients:
                        # Deliver locally
                        recipient_writer = self.active_clients[recipient]
                        recipient_writer.write(json.dumps(message).encode())
                        await recipient_writer.drain()
                        print(f"[Delivered] Direct message from {sender} delivered to local client {recipient}")

                        # Optional ACK to sender
                        sender_writer = self.active_clients.get(sender)
                        if sender_writer:
                            ack = {"type": "MSG_ACK", "from": self.server_id, "to": sender, "payload": {}}
                            sender_writer.write(json.dumps(ack).encode())
                            await sender_writer.drain()
                    else:
                        # Forward to all peers not yet visited
                        visited.add(self.server_id)
                        message["visited_servers"] = list(visited)
                        for peer_id, peer_writer in self.active_peer_writers.items():
                            if peer_id not in visited:
                                try:
                                    peer_writer.write(json.dumps(message).encode())
                                    await peer_writer.drain()
                                    print(f"[Forwarded] Direct message from {sender} forwarded to peer {peer_id}")
                                except Exception as e:
                                    print(f"[Error] Failed forwarding to peer {peer_id}: {e}")

                # --- BROADCAST MESSAGE ---
                elif msg_type == "MSG_BROADCAST":
                    sender_id = message["from"]

                    # Deliver to all local clients except sender
                    for client_id, client_writer in self.active_clients.items():
                        if client_id != sender_id:
                            client_writer.write(json.dumps(message).encode())
                            await client_writer.drain()
                            print(f"[Broadcast] Delivered message from {sender_id} to local client {client_id}")

                    # Forward to all peers that haven't seen this message
                    if self.server_id not in visited:
                        visited.add(self.server_id)
                        message["visited_servers"] = list(visited)

                    for peer_id, peer_writer in self.active_peer_writers.items():
                        if peer_id not in visited:
                            try:
                                peer_writer.write(json.dumps(message).encode())
                                await peer_writer.drain()
                                print(f"[Broadcast] Forwarded message from {sender_id} to peer {peer_id}")
                            except Exception as e:
                                print(f"[Error] Failed to forward broadcast to {peer_id}: {e}")

                # --- SERVER ANNOUNCE ---
                elif msg_type == "SERVER_ANNOUNCE":
                    peer_id = sender
                    if peer_id not in self.active_peer_writers and peer_id != self.server_id:
                        try:
                            peer_host = message["payload"]["host"]
                            peer_port = message["payload"]["port"]
                            peer_reader, peer_writer = await asyncio.open_connection(peer_host, peer_port)
                            self.active_peer_writers[peer_id] = peer_writer
                            print(f"[Peer] Connected back to announcing server {peer_id}")
                        except Exception as e:
                            print(f"[Error] Failed to connect back to announcing server {peer_id}: {e}")

            except Exception as e:
                print(f"[Error] Connection error with {peer_name}: {e}")
                break

        # --- CLEANUP ---
        for cid, w in list(self.active_clients.items()):
            if w == writer:
                del self.active_clients[cid]
                print(f"[Cleanup] Removed client {cid}")
        writer.close()
        await writer.wait_closed()

    # Send SERVER_ANNOUNCE to peer
    async def send_announce(self, writer):
        announce_msg = {
            "type": "SERVER_ANNOUNCE",
            "from": self.server_id,
            "to": "*",
            "payload": {"host": self.host, "port": self.port, "pubkey": "FAKE_PUBLIC_KEY"},
            "sig": "..."
        }
        writer.write(json.dumps(announce_msg).encode())
        await writer.drain()
        print(f"[Announce] Sent SERVER_ANNOUNCE to peer")

    # Connect to peers from introducer list
    async def connect_to_peers(self):
        for server_id, info in self.peers.items():
            if server_id == self.server_id:
                continue
            if server_id not in self.active_peer_writers:
                try:
                    reader, writer = await asyncio.open_connection(info['host'], info['port'])
                    self.active_peer_writers[server_id] = writer
                    print(f"[Peer] Connected to peer server {server_id} at {info['host']}:{info['port']}")
                    await self.send_announce(writer)
                except Exception as e:
                    print(f"[Error] Failed to connect to peer {server_id}: {e}")

    # Start the asyncio server
    async def run_server(self):
        server = await asyncio.start_server(self.handle_connection, self.host, self.port)
        addr = server.sockets[0].getsockname()
        self.host, self.port = addr[0], addr[1]
        print(f"[Server] Running on {self.host}:{self.port}")
        return server

    # Main run loop
    async def run(self):
        server = await self.run_server()
        await self.register_with_introducer()
        await self.connect_to_peers()
        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    srv = Server()
    asyncio.run(srv.run())
