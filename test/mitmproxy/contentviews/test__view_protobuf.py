import pytest

from mitmproxy.contentviews import Metadata
from mitmproxy.contentviews._view_protobuf import protobuf


def _pb_varint(field_no: int, value: int) -> bytes:
    # key = (field_no << 3) | 0 (varint)
    key = (field_no << 3) | 0
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
    return bytes([key]) + _encode_varint(value)


def _pb_len_delimited(field_no: int, data: bytes) -> bytes:
    # key = (field_no << 3) | 2 (len_delimited)
    key = (field_no << 3) | 2
    length = len(data)
    # simple length varint (length expected to be small in tests)
    if length < 0x80:
        return bytes([key, length]) + data
    raise AssertionError("test only supports small payloads")


def test_protobuf_varint_and_string():
    # message: field 1 = 42 (varint), field 2 = "abc" (len-delimited)
    msg = _pb_varint(1, 42) + _pb_len_delimited(2, b"abc")
    text = protobuf.prettify(msg, Metadata(content_type="application/x-protobuf"))
    assert "field_tag: 1" in text
    assert "varint: 42" in text
    assert "field_tag: 2" in text
    assert "utf8: abc" in text


def test_render_priority():
    good = _pb_varint(1, 1)
    bad = b"\x00\x01\x02"
    assert protobuf.render_priority(good, Metadata(content_type="application/x-protobuf")) > 0
    assert protobuf.render_priority(bad, Metadata(content_type="application/x-protobuf")) < 0
