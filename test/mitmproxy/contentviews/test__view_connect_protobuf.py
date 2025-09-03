import gzip
from pathlib import Path

from mitmproxy.contentviews import Metadata
from mitmproxy.contentviews._view_connect_protobuf import connect_protobuf


def _encode_varint(x: int) -> bytes:
    out = bytearray()
    while True:
        b = x & 0x7F
        x >>= 7
        if x:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _pb_varint(field_no: int, value: int) -> bytes:
    # key = (field_no << 3) | 0 (varint)
    key = (field_no << 3) | 0
    return bytes([key]) + _encode_varint(value)


def _pb_len_delimited(field_no: int, data: bytes) -> bytes:
    # key = (field_no << 3) | 2 (len_delimited)
    key = (field_no << 3) | 2
    length = len(data)
    return bytes([key]) + _encode_varint(length) + data


def _frame(flags: int, payload: bytes) -> bytes:
    return bytes([flags]) + len(payload).to_bytes(4, "big") + payload


def _gzip(data: bytes) -> bytes:
    return gzip.compress(data, mtime=0)


def _meta() -> Metadata:
    # hint so that protobuf subview has non-negative priority if selected via registry
    return Metadata(content_type="application/connect+proto")


def test_connect_protobuf_uncompressed_data():
    # message: field 1 = 7 (varint), field 2 = "hello" (len-delimited)
    msg = _pb_varint(1, 7) + _pb_len_delimited(2, b"hello")
    data = _frame(0x00, msg)

    text = connect_protobuf.prettify(data, _meta())
    assert "frame 1: data, compressed=False" in text
    assert "field_tag: 1" in text and "varint: 7" in text
    assert "field_tag: 2" in text and "utf8: hello" in text


def test_connect_protobuf_compressed_and_trailer():
    # frame 1: compressed data frame
    msg1 = _pb_varint(1, 1)
    f1 = _frame(0x01, _gzip(msg1))

    # frame 2: uncompressed trailer
    trailer = b"grpc-status: 0\r\ngrpc-message: OK"
    f2 = _frame(0x80, trailer)

    text = connect_protobuf.prettify(f1 + f2, _meta())
    assert "frame 1: data, compressed=True" in text
    assert "varint: 1" in text
    assert "frame 2: trailer, compressed=False" in text
    assert "grpc-status" in text and "grpc-message" in text


def test_connect_protobuf_real_files_smoke():
    # Ensure we can parse provided binary captures without raising and produce some frame output.
    root = Path(__file__).resolve().parents[4]
    c = (root / "testdata" / "86_c.txt").read_bytes()
    s = (root / "testdata" / "86_s.txt").read_bytes()

    for blob in (c, s):
        out = connect_protobuf.prettify(blob, _meta())
        assert "frame 1:" in out
        assert out  # non-empty
