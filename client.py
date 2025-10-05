import asyncio
import json
import uuid


class Client:
    def __init__(self, server_host="127.0.0.1", server_port=9000):
        self.client_id = str(uuid.uuid4())
        self.server_host = server_host
        self.server_port = server_port

    async def listen_server(self, reader):
        while True:
            try:
                data = await reader.read(4096)
                if not data:
                    print("[Connection] Server disconnected.")
                    break
                message = json.loads(data.decode())
                msg_type = message.get("type", "")
                sender = message.get("from", "")
                if msg_type == "MSG_DIRECT":
                    text = message.get("payload", {}).get("text", "")
                    print(f"\n[Message from {sender}]: {text}")
                else:
                    print(f"\n[Server message]: {message}")
            except Exception as e:
                print(f"[Error] Reading from server: {e}")
                break

    async def send_hello(self, writer):
        hello_message = {
            "type": "USER_HELLO",
            "from": self.client_id,
            "to": "server_id",
            "ts": 0,
            "payload": {
                "client": "cli-v1",
                "pubkey": "FAKE_CLIENT_PUBKEY",
                "enc_pubkey": "FAKE_CLIENT_PUBKEY"
            },
            "sig": ""
        }
        writer.write(json.dumps(hello_message).encode())
        await writer.drain()
        print(f"[Hello] Sent USER_HELLO to server")

    async def chat_loop(self, writer):
        while True:
            msg = await asyncio.to_thread(input, "Enter message (recipient_id|message or broadcast|text): ")
            if "|" not in msg:
                print("[Input] Invalid format. Use recipient_id|message or broadcast|text")
                continue
            to_id, text = msg.split("|", 1)
            to_id = to_id.strip()
            message = {
                "from": self.client_id,
                "ts": 0,
                "payload": {"text": text.strip()},
                "sig": "",
                "visited_servers": []
            }

            if to_id.lower() == "broadcast":
                message["type"] = "MSG_BROADCAST"
                message["to"] = "*"
            else:
                message["type"] = "MSG_DIRECT"
                message["to"] = to_id

            writer.write(json.dumps(message).encode())
            await writer.drain()
            print(f"[Sent] {message['type']} to {message['to']}")

    async def run(self):
        reader, writer = await asyncio.open_connection(self.server_host, self.server_port)
        asyncio.create_task(self.listen_server(reader))
        await self.send_hello(writer)
        await self.chat_loop(writer)


if __name__ == "__main__":
    port = int(input("Server port: "))
    client = Client(server_host="127.0.0.1", server_port=port)
    asyncio.run(client.run())
