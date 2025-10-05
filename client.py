import asyncio
import json
import uuid
import time
import base64
import os
import hashlib


class Client:
    def __init__(self, server_host="127.0.0.1", server_port=9000):
        self.client_id = str(uuid.uuid4())
        self.server_host = server_host
        self.server_port = server_port
        self.users = {}  # user_id -> server_id
        self.active_files = {}  # file_id -> {"name": str, "chunks": []}
        self.incoming_files = {}  # file_id -> {"name": str, "size": int, "sha": str, "chunks": []}

    # -------------------- SERVER LISTENER --------------------
    async def listen_server(self, reader):
        while True:
            try:
                line = await reader.readline()
                if not line:
                    print("[Connection] Server disconnected.")
                    break

                message = json.loads(line.decode().strip())
                msg_type = message.get("type", "")
                sender = message.get("from", "")

                # --- Incoming chat ---
                if msg_type == "MSG_DIRECT":
                    text = message.get("payload", {}).get("text", "")
                    print(f"\n[Message from {sender}]: {text}")

                elif msg_type == "USER_ADVERTISE":
                    user_id = message["payload"]["user_id"]
                    server_id = message["payload"]["server_id"]
                    self.users[user_id] = server_id
                    print(f"\n[Network Update] User {user_id} on server {server_id}")

                # --- File transfer messages ---
                elif msg_type == "FILE_START":
                    payload = message["payload"]
                    file_id = payload["file_id"]
                    filename = payload["name"]
                    filesize = payload.get("size", 0)
                    filehash = payload.get("sha256", "")
                    self.incoming_files[file_id] = {
                        "name": filename,
                        "size": filesize,
                        "sha": filehash,
                        "chunks": []
                    }
                    print(f"\n[File] Incoming file '{filename}' ({filesize} bytes, sha256={filehash}) from {sender}")

                elif msg_type == "FILE_CHUNK":
                    payload = message["payload"]
                    file_id = payload["file_id"]
                    chunk_data = base64.urlsafe_b64decode(payload["ciphertext"])
                    idx = payload["index"]
                    if file_id in self.incoming_files:
                        self.incoming_files[file_id]["chunks"].append((idx, chunk_data))
                        print(f"[File] Received chunk {idx} for file {file_id}")

                elif msg_type == "FILE_END":
                    payload = message["payload"]
                    file_id = payload["file_id"]
                    if file_id not in self.incoming_files:
                        continue
                    info = self.incoming_files[file_id]
                    ordered = [c for _, c in sorted(info["chunks"], key=lambda x: x[0])]
                    data = b"".join(ordered)
                    dest = f"received_{info['name']}"
                    with open(dest, "wb") as f:
                        f.write(data)
                    sha = hashlib.sha256(data).hexdigest()
                    if sha == info["sha"]:
                        print(f"[File] ✅ Received and verified {dest} ({len(data)} bytes)")
                    else:
                        print(f"[File] ⚠️ Hash mismatch for {dest} (expected {info['sha']}, got {sha})")
                    del self.incoming_files[file_id]

                else:
                    print(f"\n[Server message]: {message}")

            except Exception as e:
                print(f"[Error] Reading from server: {e}")
                break

    # -------------------- HELLO MESSAGE --------------------
    async def send_hello(self, writer):
        hello_message = {
            "type": "USER_HELLO",
            "from": self.client_id,
            "to": "*",
            "ts": int(time.time() * 1000),
            "payload": {
                "client": "cli-v1",
                "pubkey": "FAKE_CLIENT_PUBKEY",
                "enc_pubkey": "FAKE_CLIENT_PUBKEY"
            },
            "sig": ""
        }
        writer.write((json.dumps(hello_message) + "\n").encode("utf-8"))
        await writer.drain()
        print(f"[Hello] Sent USER_HELLO to server")

    # -------------------- FILE SEND --------------------
    async def send_file(self, writer, recipient_id, file_path):
        if not os.path.exists(file_path):
            print("[File] Error: File not found.")
            return

        file_id = str(uuid.uuid4())
        filesize = os.path.getsize(file_path)
        sha256_hash = hashlib.sha256(open(file_path, "rb").read()).hexdigest()

        # FILE_START
        start_msg = {
            "type": "FILE_START",
            "from": self.client_id,
            "to": recipient_id,
            "ts": int(time.time() * 1000),
            "payload": {
                "file_id": file_id,
                "name": os.path.basename(file_path),
                "size": filesize,
                "sha256": sha256_hash,
                "mode": "dm"
            },
            "sig": ""
        }
        writer.write((json.dumps(start_msg) + "\n").encode("utf-8"))
        await writer.drain()
        print(f"[File] 📤 Starting file transfer '{file_path}' ({filesize} bytes)")

        # FILE_CHUNK
        CHUNK_SIZE = 32 * 1024
        with open(file_path, "rb") as f:
            index = 0
            sent = 0
            while chunk := f.read(CHUNK_SIZE):
                encoded = base64.urlsafe_b64encode(chunk).decode()
                chunk_msg = {
                    "type": "FILE_CHUNK",
                    "from": self.client_id,
                    "to": recipient_id,
                    "ts": int(time.time() * 1000),
                    "payload": {"file_id": file_id, "index": index, "ciphertext": encoded},
                    "sig": ""
                }
                writer.write((json.dumps(chunk_msg) + "\n").encode("utf-8"))
                await writer.drain()
                index += 1
                sent += len(chunk)
                percent = (sent / filesize) * 100
                print(f"[File] Sent chunk {index} ({percent:.1f}%)", end="\r")
        print()

        # FILE_END
        end_msg = {
            "type": "FILE_END",
            "from": self.client_id,
            "to": recipient_id,
            "ts": int(time.time() * 1000),
            "payload": {"file_id": file_id},
            "sig": ""
        }
        writer.write((json.dumps(end_msg) + "\n").encode("utf-8"))
        await writer.drain()
        print(f"[File] ✅ Finished sending {file_path}")

    # -------------------- CHAT LOOP --------------------
    async def chat_loop(self, writer):
        while True:
            msg = await asyncio.to_thread(input, "Enter message (id|text) or file|id|path or broadcast|text: ")

            if msg.startswith("file|"):
                try:
                    _, to_id, path = msg.split("|", 2)
                    await self.send_file(writer, to_id.strip(), path.strip())
                except ValueError:
                    print("[Input] Invalid format. Use: file|recipient_id|path")
                continue

            if "|" not in msg:
                print("[Input] Invalid format.")
                continue

            to_id, text = msg.split("|", 1)
            message = {
                "from": self.client_id,
                "ts": int(time.time() * 1000),
                "payload": {"text": text.strip()},
                "sig": "",
                "visited_servers": []
            }

            if to_id.lower() == "broadcast":
                message["type"] = "MSG_BROADCAST"
                message["to"] = "*"
            else:
                message["type"] = "MSG_DIRECT"
                message["to"] = to_id.strip()

            writer.write((json.dumps(message) + "\n").encode("utf-8"))
            await writer.drain()
            print(f"[Sent] {message['type']} to {message['to']}")

    # -------------------- MAIN RUN LOOP --------------------
    async def run(self):
        reader, writer = await asyncio.open_connection(self.server_host, self.server_port)
        asyncio.create_task(self.listen_server(reader))
        await self.send_hello(writer)

        await asyncio.sleep(0.5)
        if self.users:
            print("\n[Network Users] Known users in the network:")
            for uid, sid in self.users.items():
                print(f"  {uid} -> Server {sid}")

        await self.chat_loop(writer)


if __name__ == "__main__":
    port = int(input("Server port: "))
    client = Client(server_host="127.0.0.1", server_port=port)
    asyncio.run(client.run())
