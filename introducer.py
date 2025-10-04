# introducer.py
import asyncio
import json
import uuid

class Introducer:
    def __init__(self, host="127.0.0.1", port=8000):
        self.host = host
        self.port = port
        self.servers = {}  # server_id -> {"host":..., "port":..., "pubkey":...}

    async def handle_connection(self, reader, writer):
        data = await reader.read(4096)
        message = json.loads(data.decode())
        print(f"Received: {message}")

        if message.get("type") == "SERVER_JOIN":
            server_id = message['payload']['server_id']
            self.servers[server_id] = {
                "host": message["payload"]["host"],
                "port": message["payload"]["port"],
                "pubkey": message["payload"]["pubkey"]
            }
            # Send current server list back
            response = {
                "type": "SERVER_LIST",
                "servers": self.servers
            }
            writer.write(json.dumps(response).encode())
            await writer.drain()

        writer.close()
        await writer.wait_closed()

    async def run(self):
        server = await asyncio.start_server(
            self.handle_connection, self.host, self.port
        )
        print(f"Introducer running on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    introducer = Introducer()
    asyncio.run(introducer.run())
