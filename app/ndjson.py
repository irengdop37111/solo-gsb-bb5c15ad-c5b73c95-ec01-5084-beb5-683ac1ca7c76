"""Chunked NDJSON framing with memory bounded independently of file size.

The request body is consumed as an async stream of arbitrary-sized chunks and
split into *physical* lines. Only the current (unterminated) line is ever held
in memory, so peak buffering is O(longest line + chunk size) no matter how
large the whole upload is.

Line semantics
--------------
* Both ``LF`` (``\\n``) and ``CRLF`` (``\\r\\n``) terminate a line; the CR of a
  CRLF pair -- including one split across two chunks -- is stripped, while a
  dangling CR at end of file is ordinary content.
* A file without a trailing newline still yields its final line.
* Physical lines are numbered from 1. Blank (zero-byte) lines produce no
  event but still consume a number, so subsequent numbers stay physical.
* A line longer than ``max_bytes`` (excluding its terminator) emits a single
  ``too_long`` event; its remaining bytes are then discarded up to and
  including the next newline so processing resumes on the following line.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import AsyncIterator, Optional

# Per-line ceiling: 1 MiB of content, not counting the LF / CRLF terminator.
DEFAULT_MAX_LINE_BYTES = 1024 * 1024


@dataclass(frozen=True)
class LineEvent:
    """One physical input line.

    ``kind == "line"``: ``payload`` holds the raw line bytes with the
    terminator (and the CR of CRLF) removed.
    ``kind == "too_long"``: the line exceeded the size limit; ``payload`` is
    ``None`` and the remainder of the physical line has already been drained.
    """

    line_no: int
    kind: str
    payload: Optional[bytes] = None


async def iter_ndjson_lines(
    chunks: AsyncIterator[bytes],
    max_bytes: int = DEFAULT_MAX_LINE_BYTES,
) -> AsyncIterator[LineEvent]:
    """Yield one :class:`LineEvent` per non-blank / overlong physical line.

    ``chunks`` is an async iterator of raw body bytes; chunk boundaries are
    arbitrary and may split terminators or lines.
    """
    buf = bytearray()
    # Discarding the tail of a line already reported as too long.
    draining = False
    # Number of physical lines already terminated by a newline.
    terminated = 0

    async for chunk in chunks:
        view = memoryview(chunk)
        pos = 0
        while True:
            nl = chunk.find(b"\n", pos)
            has_nl = nl != -1
            end = nl if has_nl else len(chunk)

            if draining:
                # Everything up to (and including) this newline belongs to
                # the discarded line.
                if has_nl:
                    draining = False
                    terminated += 1
            elif has_nl:
                line_no = terminated + 1
                buf.extend(view[pos:end])
                # Strip exactly one CR -- the CR of a CRLF terminator. At this
                # point it must immediately precede LF, even if the pair was
                # split across chunks.
                data = bytes(buf[:-1]) if buf.endswith(b"\r") else bytes(buf)
                buf.clear()
                terminated += 1
                if len(data) > max_bytes:
                    yield LineEvent(line_no, "too_long")
                elif data:
                    yield LineEvent(line_no, "line", data)
                # Zero bytes: blank line -- skipped, but its number is spent.
            else:
                # Continuation of the still-unterminated current line.
                line_no = terminated + 1
                buf.extend(view[pos:end])
                # Tolerate one extra byte only when it is a CR that might be
                # the first half of a CRLF arriving in the next chunk; any
                # other buffer longer than max_bytes is certainly over limit.
                limit = max_bytes + 1 if buf.endswith(b"\r") else max_bytes
                if len(buf) > limit:
                    yield LineEvent(line_no, "too_long")
                    buf.clear()
                    draining = True

            if not has_nl:
                break
            pos = nl + 1

    # Flush the final line when the file has no trailing newline. A dangling
    # CR here is content, not a terminator, so it is left intact.
    if not draining and buf:
        line_no = terminated + 1
        if len(buf) > max_bytes:
            yield LineEvent(line_no, "too_long")
        else:
            yield LineEvent(line_no, "line", bytes(buf))
