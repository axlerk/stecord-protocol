"""Small helpers shared by make_vectors.py (the emitter) and verify_test_vectors.py (the checker)."""
import hashlib

PASSWORDS = {"main": "correct horse battery staple", "other": "Tr0ub4dor&3"}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def salt_for(name):
    """Fixed 16-byte salt of a vector, derived from its name (a shipping encoder uses a random one)."""
    return hashlib.sha256(b"stecord-vector-salt|" + name.encode()).digest()[:16]


def rows_digest(cap, rows):
    """SHA-256 of the file bit position (file offset * 8 + bit index from the MSB) of every row of a set, as 8-byte
    big-endian integers, in set order."""
    h = hashlib.sha256()
    for r in rows:
        bit = 7 - (cap.mask[r].bit_length() - 1)
        h.update((cap.file_off[r] * 8 + bit).to_bytes(8, "big"))
    return h.hexdigest()


def read_file(path):
    with open(path, "rb") as f:
        return f.read()
