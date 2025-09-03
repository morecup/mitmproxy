from __future__ import annotations

import io
from typing import Any
import struct

from kaitaistruct import KaitaiStream

from mitmproxy.contentviews._api import Contentview, Metadata
from mitmproxy.contentviews._utils import yaml_dumps
from mitmproxy.contrib.kaitaistruct.google_protobuf import GoogleProtobuf


class ProtobufContentview(Contentview):
    syntax_highlight = "yaml"
    # 安全阈值，避免对任意大/深的字节尝试递归解析导致性能问题
    MAX_NESTED_DEPTH = 10
    MAX_NESTED_BYTES = 512 * 1024  # 单个嵌套字段建议上限（保守启发）
    HARD_NESTED_BYTES_LIMIT = 8 * 1024 * 1024  # 绝对安全上限（8MB），超过则不尝试递归

    CT_HINTS = (
        "application/protobuf",
        "application/x-protobuf",
        "application/grpc+proto",
        "application/connect+proto",
        "+proto",
        "/proto",
    )

    def _ct_hint(self, metadata: Metadata) -> bool:
        ct = (metadata.content_type or "").lower()
        return bool(ct and any(h in ct for h in self.CT_HINTS)) or bool(
            metadata.protobuf_definitions
        )

    def _looks_like_protobuf(self, data: bytes) -> bool:
        """
        保守的启发式：只有在解析成功且至少存在一个合理的字段号时，才认为像嵌套的 protobuf。
        这样可以减少将任意字节误判为消息的概率。
        """
        if not data or len(data) < 2:
            return False
        try:
            ks = KaitaiStream(io.BytesIO(data))
            msg = GoogleProtobuf(ks)
        except Exception:
            return False
        pairs = getattr(msg, "pairs", None)
        if not pairs:
            return False
        # 经验阈值：存在至少一个较小、常见范围内的字段号
        small_tags = sum(1 for p in pairs if getattr(p, "field_tag", 0) <= 16384)
        return small_tags >= 1

    def _decode_likely_text(self, body: bytes) -> str | None:
        """
        尝试将长度字段作为文本解码：
        - 先尝试 UTF-8 解码。
        - 使用可打印占比与常见文本特征（JSON/JWT/换行等）进行判定。
        判定为文本时，返回解码后的字符串；否则返回 None。
        """
        if not body:
            return ""
        try:
            s = body.decode("utf-8")
        except Exception:
            return None
        # 可打印占比
        printable_ratio = (sum(1 for c in s if c.isprintable()) / max(len(s), 1))
        if printable_ratio >= 0.85:
            return s
        t = s.strip()
        # JSON 的简单特征
        if (t.startswith("{") and t.endswith("}")) or (t.startswith("[") and t.endswith("]")):
            return s
        # 多行文本/富文本
        if "\n" in s or "\r" in s:
            return s
        # 简单 JWT 识别（base64url 三段式）
        if s.count(".") == 2:
            parts = s.split(".")
            if all(part and all(ch.isalnum() or ch in "-_" for ch in part) for part in parts):
                return s
        return None

    def _parse_message(self, data: bytes, depth: int = 0) -> list[dict[str, Any]]:
        ks = KaitaiStream(io.BytesIO(data))
        msg = GoogleProtobuf(ks)
        out: list[dict[str, Any]] = []
        for p in msg.pairs:
            item: dict[str, Any] = {
                "field_tag": p.field_tag,
                "wire_type": p.wire_type.name,
            }
            if p.wire_type.name == "varint":
                u = int(p.value.value)
                item["varint"] = u
                # 附带 ZigZag 反解，便于识别 sint32/sint64
                sint = (u >> 1) ^ -(u & 1)
                item["sint"] = int(sint)
            elif p.wire_type.name == "bit_32":
                u32 = int(p.value)
                item["u32"] = u32
                # 有符号视图与 float32 视图
                s32 = struct.unpack("<i", struct.pack("<I", u32))[0]
                f32 = struct.unpack("<f", struct.pack("<I", u32))[0]
                item["s32"] = int(s32)
                item["float32"] = float(f32)
            elif p.wire_type.name == "bit_64":
                u64 = int(p.value)
                item["u64"] = u64
                s64 = struct.unpack("<q", struct.pack("<Q", u64))[0]
                f64 = struct.unpack("<d", struct.pack("<Q", u64))[0]
                item["s64"] = int(s64)
                item["float64"] = float(f64)
            elif p.wire_type.name == "len_delimited":
                body = bytes(p.value.body)
                item["length"] = len(body)
                # 优先：若像文本，则直接作为 UTF-8 呈现以提升可读性
                s = self._decode_likely_text(body)
                if s is not None:
                    item["utf8"] = s
                else:
                    # 其次：尝试将其作为嵌套 protobuf 递归解析
                    # 放宽长度限制：在一个更大的绝对上限内（HARD_NESTED_BYTES_LIMIT）基于结构判断是否像 protobuf，
                    # 以避免正当的大消息（如 repeated ChatMessage）被误判为二进制。
                    can_try_nested = (
                        depth < self.MAX_NESTED_DEPTH
                        and 0 < len(body) <= self.HARD_NESTED_BYTES_LIMIT
                    )
                    if can_try_nested and self._looks_like_protobuf(body):
                        try:
                            item["message"] = {"fields": self._parse_message(body, depth + 1)}
                        except Exception:
                            # 递归失败则回退到十六进制预览（避免 !!binary）
                            pass
                    if "message" not in item:
                        item["bytes_hex_preview"] = body[:64].hex() + (
                            "..." if len(body) > 64 else ""
                        )
            out.append(item)
        return out

    def _parse(self, data: bytes) -> list[dict[str, Any]]:
        # 对顶层消息也使用支持递归的解析器
        return self._parse_message(data, 0)

    def render_priority(self, data: bytes, metadata: Metadata) -> float:
        if not data:
            return -1
        if not self._ct_hint(metadata):
            return -1
        # Heuristic: attempt to parse; if it fails, it's not protobuf.
        try:
            _ = self._parse(data)
            return 0.7
        except Exception:
            return -1

    def prettify(self, data: bytes, metadata: Metadata) -> str:
        items = self._parse(data)
        meta: dict[str, Any] = {}
        if metadata.protobuf_definitions:
            # Placeholder: we currently do not resolve field names, but expose the path
            # so users can see which .proto is configured.
            meta["protobuf_definitions"] = str(metadata.protobuf_definitions)
        doc: dict[str, Any] = {k: v for k, v in meta.items()}
        doc["fields"] = items
        return yaml_dumps(doc)


protobuf = ProtobufContentview()
