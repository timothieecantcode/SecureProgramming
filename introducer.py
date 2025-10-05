import asyncio
import json
import time

class Introducer:
    def __init__(self, host="127.0.0.1", port=8000):
        self.host = host
        self.port = port
        self.servers = {}  # server_id -> {"host":..., "port":..., "pubkey":...}
        self.clients = {}  # user_id -> {"server_id":..., "meta":...}

    async def handle_connection(self, reader, writer):
        data = await reader.read(65536)
        if not data:
            writer.close()
            await writer.wait_closed()
            return

        message = json.loads(data.decode())
        print(f"[Introducer] Received: {message}")

        response = None

        # ----------------- SERVER JOIN -----------------
        if message.get("type") == "SERVER_JOIN":
            server_id = message["payload"]["server_id"]
            self.servers[server_id] = {
                "host": message["payload"]["host"],
                "port": message["payload"]["port"],
                "pubkey": message["payload"]["pubkey"]
            }

            # SERVER_WELCOME includes current users and servers
            clients_list = [
                {
                    "user_id": uid,
                    "host": self.servers.get(info["server_id"], {}).get("host", ""),
                    "port": self.servers.get(info["server_id"], {}).get("port", 0),
                    "pubkey": info.get("meta", {}).get("pubkey", "")
                }
                for uid, info in self.clients.items()
            ]

            response = {
                "type": "SERVER_WELCOME",
                "from": "introducer",
                "to": server_id,
                "ts": int(time.time() * 1000),
                "payload": {
                    "assigned_id": server_id,
                    "servers": self.servers,
                    "clients": clients_list
                },
                "sig": "..."
            }

        # ----------------- USER ADVERTISE -----------------
        elif message.get("type") == "USER_ADVERTISE":
            user_id = message["payload"]["user_id"]
            self.clients[user_id] = {
                "server_id": message["payload"]["server_id"],
                "meta": message["payload"].get("meta", {})
            }
            # Respond with ACK including current users
            response = {
                "type": "USER_ADVERTISE_ACK",
                "from": "introducer",
                "to": message.get("from"),
                "ts": int(time.time() * 1000),
                "payload": {
                    "user_id": user_id,
                    "servers": self.servers,
                    "clients": [
                        {
                            "user_id": uid,
                            "host": self.servers.get(info["server_id"], {}).get("host", ""),
                            "port": self.servers.get(info["server_id"], {}).get("port", 0),
                            "pubkey": info.get("meta", {}).get("pubkey", "")
                        }
                        for uid, info in self.clients.items()
                    ]
                },
                "sig": "..."
            }

        # ----------------- SEND RESPONSE -----------------
        if response:
            writer.write(json.dumps(response).encode())
            await writer.drain()
            print(f"[Introducer] Sent response: {response}")

        writer.close()
        await writer.wait_closed()

    async def run(self):
        server = await asyncio.start_server(
            self.handle_connection, self.host, self.port
        )
        print(f"[Introducer] Running on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    introducer = Introducer()
    asyncio.run(introducer.run())
