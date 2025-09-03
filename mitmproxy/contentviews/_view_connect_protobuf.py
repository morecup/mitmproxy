from __future__ import annotations

import importlib
import json
from typing import List, Tuple

from mitmproxy.contentviews._api import Contentview, Metadata
from mitmproxy.contentviews._utils import merge_repeated_keys, yaml_dumps
from mitmproxy.net import encoding


class ConnectProtobufContentview(Contentview):
    """
    Decode Connect/gRPC-framed protobuf payloads with per-frame compression.

    Wire format (compatible with gRPC/gRPC-web/Connect framing):
      - 1 byte flags
          * bit 0: 1 if payload is compressed, 0 otherwise
          * bit 1: 1 if end-stream frame (Connect), 0 otherwise
          * bit 7: 1 if trailer frame (gRPC-Web/gRPC), 0 otherwise
      - 4 byte big-endian unsigned length
      - payload bytes of given length

    This view unwraps all frames in sequence. For data frames it optionally
    gunzips the payload and then delegates pretty-printing to the best matching
    contentview (preferring the protobuf view if available). For trailer frames,
    it renders the payload as text (gunzipped if flagged).
    """

    syntax_highlight = "none"

    CT_HINTS = (
        "application/grpc",
        "application/grpc+proto",
        "application/grpc-web",
        "application/grpc-web+proto",
        "application/connect",
        "application/connect+proto",
        "application/protobuf",
        "application/x-protobuf",
        "+proto",
        "/proto",
    )

    @staticmethod
    def _looks_like_connect(data: bytes) -> bool:
        if len(data) < 5:
            return False
        flag = data[0]
        length = int.from_bytes(data[1:5], "big")
        if length < 0 or 5 + length > len(data):
            return False
        # Accept common flag patterns: 0x00/0x01 (data, uncompressed/compressed),
        # 0x02 (end-stream for Connect), and 0x80/0x81 (trailers in gRPC-web-like protocols).
        if (flag & 0x7F) in (0x00, 0x01, 0x02):
            return True
        if (flag & 0x80) != 0:
            return True
        return False

    @classmethod
    def _parse_frames(cls, data: bytes) -> List[Tuple[int, int, bytes]]:
        frames: List[Tuple[int, int, bytes]] = []
        pos = 0
        n = len(data)
        while pos + 5 <= n:
            flag = data[pos]
            length = int.from_bytes(data[pos + 1 : pos + 5], "big")
            pos += 5
            if length < 0 or pos + length > n:
                break
            payload = data[pos : pos + length]
            pos += length
            frames.append((flag, length, payload))
        if not frames:
            raise ValueError("Not a Connect/gRPC framed message.")
        return frames

    @staticmethod
    def _preferred_algorithms(metadata: Metadata) -> list[str]:
        """
        Determine preferred per-message compression algorithms from HTTP headers.
        We consult common header names across gRPC/Connect implementations.
        The returned list is ordered by preference and only contains algorithms we support.
        """
        algos: list[str] = []
        msg = metadata.http_message
        if msg is not None:
            headers = msg.headers
            # Common across ecosystems:
            #  - gRPC: "grpc-encoding" header
            #  - Connect: "connect-encoding" or "connect-content-encoding" (implementations vary)
            #  - Fallback: "content-encoding" (rare for framed bodies; included defensively)
            for name in (
                "grpc-encoding",
                "connect-encoding",
                "connect-content-encoding",
                "content-encoding",
            ):
                val = headers.get(name)
                if val:
                    # Could be a comma-separated list, keep ordering.
                    for part in (x.strip() for x in val.split(",")):
                        if part and part.lower() not in algos:
                            algos.append(part.lower())
        # Supported decoders in mitmproxy
        supported = {"gzip", "deflate", "br", "zstd", "identity"}
        ret = [a for a in algos if a in supported]
        if not ret:
            # Conservative default order if headers are missing or unknown.
            ret = ["gzip", "br", "zstd", "deflate"]
        return ret

    @staticmethod
    def _decompress_with_algorithms(data: bytes, algorithms: list[str]) -> bytes:
        """
        Try to decompress using the provided list of algorithms.
        Returns the first successful result; if all fail, re-raise the last error.
        """
        last_err: Exception | None = None
        for algo in algorithms:
            try:
                if algo == "identity":
                    return data
                if algo == "gzip":
                    return encoding.decode_gzip(data)
                if algo == "deflate":
                    return encoding.decode_deflate(data)
                if algo == "br":
                    return encoding.decode_brotli(data)
                if algo == "zstd":
                    return encoding.decode_zstd(data)
            except Exception as e:  # try the next one
                last_err = e
                continue
        if last_err:
            raise last_err
        return data

    @staticmethod
    def _parse_trailer_headers(text: str) -> str:
        """
        Parse trailer or end-stream block into a human-friendly format.
        First try JSON pretty-print; if that fails, try header parsing
        (key: value per line) and render as YAML. If both fail, return raw text.
        """
        # Try JSON first (Connect end-stream with +json)
        t = text.strip()
        if (t.startswith("{") and t.endswith("}")) or (t.startswith("[") and t.endswith("]")):
            try:
                obj = json.loads(t)
                return yaml_dumps(obj)
            except Exception:
                pass

        # Fallback: header-like parsing
        lines = [ln.strip("\r") for ln in text.split("\n") if ln.strip()]
        pairs: list[tuple[str, str]] = []
        for ln in lines:
            if ":" in ln:
                k, v = ln.split(":", 1)
                pairs.append((k.strip(), v.lstrip()))
            else:
                # Not header-like, bail out to raw text rendering.
                return text
        merged = merge_repeated_keys(pairs)
        return yaml_dumps(merged)

    @staticmethod
    def _is_connect_ct(metadata: Metadata) -> bool:
        ct = (metadata.content_type or "").lower()
        return "application/connect" in ct

    def _ct_hint(self, metadata: Metadata) -> bool:
        ct = (metadata.content_type or "").lower()
        return any(h in ct for h in self.CT_HINTS)

    def render_priority(self, data: bytes, metadata: Metadata) -> float:
        if not data:
            return -1
        if not self._looks_like_connect(data):
            return -1
        # Prefer this view when content-type hints at grpc/connect/proto.
        return 1.2 if self._ct_hint(metadata) else 0.8

    def prettify(self, data: bytes, metadata: Metadata) -> str:
        frames = self._parse_frames(data)
        # Lazy import to avoid circular imports during registry bootstrap.
        cv = importlib.import_module("mitmproxy.contentviews")

        parts: list[str] = []
        # Pre-compute preferred compression algorithms once per message
        preferred_algos = self._preferred_algorithms(metadata)

        for i, (flag, length, payload) in enumerate(frames, start=1):
            # End/trailer detection differs between gRPC-Web (bit7) and Connect (bit1)
            is_connect = self._is_connect_ct(metadata)
            is_trailer = ((flag & 0x80) != 0) if not is_connect else ((flag & 0x02) != 0)
            is_compressed = (flag & 0x01) != 0

            label = "endstream" if (is_connect and is_trailer) else ("trailer" if is_trailer else "data")
            header_prefix = (
                f"frame {i}: {label}, "
                f"flags=0x{flag:02x}, compressed={is_compressed}, length={length}"
            )

            if is_trailer:
                body = payload
                if is_compressed:
                    try:
                        body = self._decompress_with_algorithms(body, preferred_algos)
                    except Exception:
                        # If decompression fails, keep raw bytes and show as-is.
                        pass
                # Render trailers as structured headers if possible.
                trailer_text = body.decode("utf-8", "backslashreplace")
                structured = self._parse_trailer_headers(trailer_text)
                parts.append(header_prefix + "\n" + structured)
                continue

            content_bytes = payload
            if is_compressed:
                try:
                    content_bytes = self._decompress_with_algorithms(
                        content_bytes, preferred_algos
                    )
                except Exception:
                    # Leave as-is if we cannot decompress; downstream may still handle it.
                    pass

            header = header_prefix + f", uncompressed_length={len(content_bytes)}"

            # Prefer protobuf view if available, else fall back to auto detection.
            try:
                subview = cv.registry["protobuf"]
            except KeyError:
                subview = cv.registry.get_view(content_bytes, metadata)
            # Make per-frame rendering resilient: if protobuf view fails, try auto.
            try:
                rendered = subview.prettify(content_bytes, metadata)
            except Exception:
                try:
                    fallback_view = cv.registry.get_view(content_bytes, metadata)
                    rendered = fallback_view.prettify(content_bytes, metadata)
                except Exception:
                    # Last resort: show a small hex preview to avoid losing data entirely.
                    preview = content_bytes[:64].hex()
                    suffix = "..." if len(content_bytes) > 64 else ""
                    rendered = f"bytes_hex_preview: {preview}{suffix}"
            parts.append(header + "\n" + rendered)

        # Separate frames visually.
        sep = "\n\n" + ("-" * 40) + "\n\n"
        return sep.join(parts)


connect_protobuf = ConnectProtobufContentview()
