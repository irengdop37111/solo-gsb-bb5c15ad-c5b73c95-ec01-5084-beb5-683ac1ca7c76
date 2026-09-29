"""Chunked, bounded-memory parsing of newline-delimited JSON (NDJSON).

The input is an arbitrary-length byte stream made of physical lines:

* lines are terminated by ``LF`` (``\\n``); a single preceding ``CR``
  (``\\r\\n`` / CRLF) is stripped as part of the terminator;
* a final line without any trailing newline is still delivered;
* empty lines (zero bytes after removing the terminator) are delivered like
  any other so the caller can count their physical line numbers, then skip
  them.

Memory stays bounded independently of the total stream size: the in-progress
line never exceeds ``max_line_bytes + 1`` bytes and the chunk handed in by the
caller is never copied wholesale for longer than a line lives. A line whose
raw bytes (excluding the terminator) exceed the cap is reported **once** as
:data:`LINE_TOO_LONG`; every remaining byte of that physical line up to and
including its next ``LF`` is discarded without buffering.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import AsyncIterator, List, Optional

from starlette.responses import StreamingResponse

# One raw line may carry at most this many bytes, excluding its terminator.
MAX_LINE_BYTES = 1024 * 1024  # 1 MiB

# Per-line error codes echoed in the NDJSON response.
LINE_TOO_LONG = "line_too_long"
INVALID_JSON = "invalid_json"
INVALID_UTF8 = "invalid_utf8"

NDJSON_MEDIA_TYPE = "application/x-ndjson"


@dataclass(frozen=True)
class LineEvent:
    """One physical line pulled from the stream.

    For an oversized line ``error`` is :data:`LINE_TOO_LONG` and ``raw`` is
    empty; every byte belonging to that physical line has already been
    consumed, so processing resumes at the following physical line.
    """

    line_no: int
    raw: bytes
    error: Optional[str] = None


class NdjsonLineSplitter:
    """State machine turning arbitrary byte chunks into physical lines.

    Incoming chunks may split lines anywhere, including across the CR/LF of a
    CRLF terminator. The physical line counter advances exactly once per LF
    and, at end of stream, once for a non-empty unterminated tail.
    """

    def __init__(self, max_line_bytes: int = MAX_LINE_BYTES) -> None:
        self._max = max_line_bytes
        # One byte of slack lets an exactly-max-length line followed by CRLF
        # be buffered (its CR is terminator, not content) while a max+1-byte
        # line is still caught.
        self._cap = max_line_bytes + 1
        self._buf = b""
        # Set once the in-progress (still unterminated) line is known to be
        # overlong; its remaining bytes are then dropped until its LF.
        self._overlong = False
        self._line_no = 0

    def feed(self, chunk: bytes) -> List[LineEvent]:
        """Absorb one chunk; return every physical line it completes."""
        events: List[LineEvent] = []
        pos = 0
        size = len(chunk)
        while pos < size:
            nl = chunk.find(b"\n", pos)
            if nl < 0:
                self._absorb(chunk[pos:])
                break

            self._line_no += 1
            line_no = self._line_no
            total = len(self._buf) + (nl - pos)
            if self._overlong or total > self._cap:
                # Already known overlong, or the terminator arrived in the
                # same chunk with strictly more content bytes than we may
                # hold (strictly greater than the cap stays overlong even
                # after stripping a possible CR).
                events.append(LineEvent(line_no, b"", LINE_TOO_LONG))
            else:
                raw = self._buf + chunk[pos:nl]
                if raw.endswith(b"\r"):
                    raw = raw[:-1]
                if len(raw) > self._max:
                    events.append(LineEvent(line_no, b"", LINE_TOO_LONG))
                else:
                    events.append(LineEvent(line_no, raw))

            self._buf = b""
            self._overlong = False
            pos = nl + 1
        return events

    def finish(self) -> List[LineEvent]:
        """Flush the final physical line when the stream had no trailing LF."""
        if self._overlong:
            self._line_no += 1
            return [LineEvent(self._line_no, b"", LINE_TOO_LONG)]
        if not self._buf:
            # Trailing LF (or an empty stream): no extra physical line.
            return []
        self._line_no += 1
        raw = self._buf
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if len(raw) > self._max:
            return [LineEvent(self._line_no, b"", LINE_TOO_LONG)]
        return [LineEvent(self._line_no, raw)]

    def _absorb(self, tail: bytes) -> None:
        """Retain bytes after the last LF until more data arrives."""
        if self._overlong:
            # Still draining an overlong line; drop without buffering.
            return
        if len(self._buf) + len(tail) > self._cap:
            # More content (excluding any LF) than can ever be accepted:
            # report at the terminator / EOF, meanwhile keep nothing.
            self._overlong = True
            self._buf = b""
        else:
            self._buf += tail


async def iter_ndjson_lines(
    chunks: AsyncIterator[bytes],
    max_line_bytes: Optional[int] = None,
) -> AsyncIterator[LineEvent]:
    """Yield :class:`LineEvent` objects from an async stream of byte chunks."""
    if max_line_bytes is None:
        # Read at call time so tests (or future config) can override the cap.
        max_line_bytes = MAX_LINE_BYTES
    splitter = NdjsonLineSplitter(max_line_bytes=max_line_bytes)
    async for chunk in chunks:
        for event in splitter.feed(chunk):
            yield event
    for event in splitter.finish():
        yield event


def encode_line(obj: dict) -> bytes:
    """Serialize one response object as a self-delimiting NDJSON record."""
    # ensure_ascii=False keeps non-ASCII redacted output verbatim (UTF-8).
    return (
        json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        .encode("utf-8")
        + b"\n"
    )


class NdjsonStreamingResponse(StreamingResponse):
    """``StreamingResponse`` that never polls ``receive()`` for disconnects.

    Starlette's stock :class:`~starlette.responses.StreamingResponse` runs a
    background task that keeps calling the ASGI ``receive()`` so it can abort
    when the client goes away. Our generator also consumes ``receive()`` (the
    request body stream), and some ASGI test transports serialise ``receive``
    in a way that the two concurrent consumers deadlock. A client disconnect
    is surfaced to us anyway on the next ``send()``, so proactively polling
    for it adds nothing here -- stream start/body/end directly instead.
    """

    async def __call__(self, scope, receive, send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": self.status_code,
                "headers": self.raw_headers,
            }
        )
        async for chunk in self.body_iterator:
            if not isinstance(chunk, (bytes, memoryview)):
                chunk = chunk.encode(self.charset)
            await send({"type": "http.response.body", "body": chunk, "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})
