from SOCP.client.crypto_file import gen_file_key32, make_file_chunk_payload, open_file_chunk_payload
import os

key = gen_file_key32()
file_id = "53d3c204-6689-4834-b74a-8d62b0b19a62"

# make two chunks
p0 = make_file_chunk_payload(key, file_id, 0, b"A" * 1024)
p1 = make_file_chunk_payload(key, file_id, 1, b"B" * 1024)

# good path
print("chunk0:", len(open_file_chunk_payload(key, p0)))
print("chunk1:", len(open_file_chunk_payload(key, p1)))

# reorder attack should fail (AAD ties index)
try:
    open_file_chunk_payload(key, {"file_id": file_id, "index": 0, **p1})
except Exception as e:
    print("reorder caught:", type(e).__name__)

# Wrong file id caught
bad = dict(p0)
bad["file_id"] = "other-id"
try:
    open_file_chunk_payload(key, bad)
except Exception as e:
    print("Wrong file_id caught:", type(e).__name__)

# Reorder caught
try:
    bad = dict(p1)          # p1 is index=1
    bad["index"] = 0        # lie about the index
    open_file_chunk_payload(key, bad)
    print("reorder NOT caught")
except Exception as e:
    print("reorder caught:", type(e).__name__)
