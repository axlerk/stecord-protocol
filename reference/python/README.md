# Reference implementation (Python)

| File | What |
|---|---|
| `stecord_decode.py` | The decoder of stealth-v1 and open-v1 (normative path). CLI: `python3 -I stecord_decode.py clip.mov --password P` or `--open` |
| `stecord_carrier.py` | The carrier layer: container, parse, rows, usable rule, level sets, clip nonce |
| `stecord_encode.py` | An informative encoder (the format defines only the decode path). CLI: `python3 -I stecord_encode.py cover.mov stego.mov --password P --text hello` |
| `bitio.py`, `mp4.py`, `h264x.py` | The CAVLC parser, copied from the research code ([`NOTICE-PARSER.md`](NOTICE-PARSER.md)) |
| `cavlc_tables.py`, `gen_tables_from_swift.py` | The CAVLC code tables of ITU-T H.264 and their generator, which reads the app's Swift tables ([`NOTICE-PARSER.md`](NOTICE-PARSER.md)) |
| `make_covers.py` | The recipe of the cover clips of `../../test-vectors/` |
| `make_vectors.py`, `vectorlib.py` | Emits `../../test-vectors/` (deterministic) |
| `verify_test_vectors.py` | Checks every vector, every read, every primitive |
| `tests/` | `unittest` suite |

**Dependencies: the Python standard library and one package, `cryptography` (PyCA), for AES-256-GCM** (the same author's other
reference decoders use it for the same reason). PBKDF2, HMAC and SHA-256 are the standard library's;
HKDF (RFC 5869) is written here and checked against the `cryptography` package's HKDF and RFC 5869 test case 3. Python 3.14.8 was
used; nothing in the code needs a feature newer than 3.9 (**inferred**, not run on an older Python). `numpy` is not needed.

```
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python3 -I verify_test_vectors.py ../../test-vectors          # about a minute: the pure-Python parser is slow
python3 -I -m unittest discover -s tests                 # the same, as a test suite (+ unit tests)
```

Use `-I` (isolated mode): the scripts add their own directory to `sys.path`. The parser is a **reference, not an engine**: it takes
2 to 4 s per 100 000 rows (a 0.1 MB test clip) and 3 to 86 s for a 4 MB phone clip on the Mac. A Swift port of the same parser
reads such clips in 0.1 to 0.8 s on an iPhone 12 mini (Release build, 2026-11-09).

## Independence

`stecord_decode.py` and `stecord_encode.py` share their key derivation and syndrome code, so a mistake there would not be caught
by this pair. The independent check is the app's Swift engine: its tests read every vector, compare the covers' rows, level sets and nonces, and
reproduce the stego vectors byte for byte with the vectors' salts. It does not yet write vectors of its own for this decoder
([`../../test-vectors/README.md`](../../test-vectors/README.md), "Next"). The other checks: the HKDF here against the
`cryptography` package and RFC 5869; AES-GCM and PBKDF2 are the libraries' own; the level sets and the row positions against the
research code (a test in `tests/test_stecord.py` that is skipped when the research code is not next to this directory, as in the public mirror).
