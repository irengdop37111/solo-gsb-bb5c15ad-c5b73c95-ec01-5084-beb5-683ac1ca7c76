"""Unit tests for the bounded chunked NDJSON line splitter."""

from __future__ import annotations

import pytest

from app.ndjson import LINE_TOO_LONG, NdjsonLineSplitter


def _split(data: bytes, chunk_size: int = 3, limit: int = 1024 * 1024):
    """Feed ``data`` in small chunks; return (events, final_events)."""
    sp = NdjsonLineSplitter(max_line_bytes=limit)
    events = []
    for i in range(0, len(data), chunk_size):
        events.extend(sp.feed(data[i : i + chunk_size]))
    events.extend(sp.finish())
    return events


def test_lf_crlf_and_no_final_newline():
    events = _split(b"a\nb\r\nc")
    assert [(e.line_no, e.raw, e.error) for e in events] == [
        (1, b"a", None),
        (2, b"b", None),
        (3, b"c", None),
    ]


def test_blank_lines_keep_physical_numbering():
    events = _split(b"\n\nx\n\n")
    out = [(e.line_no, e.raw) for e in events]
    # Blank lines are still delivered; callers skip them, line numbers stay real.
    assert out == [(1, b""), (2, b""), (3, b"x"), (4, b"")]


def test_crlf_split_across_chunks():
    # CR and LF delivered in different chunks.
    events = _split(b"ab\r\ncd\n", chunk_size=2)
    assert [(e.line_no, e.raw) for e in events] == [(1, b"ab"), (2, b"cd")]


def test_empty_input_yields_nothing():
    assert _split(b"") == []
    events = _split(b"\n")
    assert [(e.line_no, e.raw) for e in events] == [(1, b"")]
    sp = NdjsonLineSplitter()
    assert sp.feed(b"\n")[0].line_no == 1
    assert sp.finish() == []


def test_exact_limit_line_is_accepted():
    limit = 8
    events = _split(b"x" * limit + b"\n", chunk_size=3, limit=limit)
    assert len(events) == 1
    assert events[0].raw == b"x" * limit
    assert events[0].error is None


def test_exact_limit_with_crlf_is_accepted():
    limit = 8
    events = _split(b"x" * limit + b"\r\n", chunk_size=3, limit=limit)
    assert len(events) == 1
    assert events[0].raw == b"x" * limit
    assert events[0].error is None


def test_line_one_byte_over_limit_reported_once():
    limit = 8
    events = _split(b"x" * (limit + 1) + b"\nok\n", chunk_size=3, limit=limit)
    assert [(e.line_no, e.error) for e in events] == [
        (1, LINE_TOO_LONG),
        (2, None),
    ]
    assert events[1].raw == b"ok"


def test_huge_overlong_line_reports_only_once_and_resyncs():
    limit = 16
    body = b"y" * (100 * limit)  # no newline inside
    events = _split(body + b"\nafter\r\n", chunk_size=7, limit=limit)
    assert [(e.line_no, e.error, e.raw) for e in events] == [
        (1, LINE_TOO_LONG, b""),
        (2, None, b"after"),
    ]


def test_unterminated_overlong_line_at_eof():
    limit = 4
    events = _split(b"z" * 100, chunk_size=5, limit=limit)
    assert [(e.line_no, e.error) for e in events] == [(1, LINE_TOO_LONG)]


def test_unterminated_normal_line_at_eof():
    limit = 4
    events = _split(b"zz", chunk_size=1, limit=limit)
    assert [(e.line_no, e.raw) for e in events] == [(1, b"zz")]


def test_overlong_line_terminator_in_same_chunk_as_overflow():
    limit = 4
    sp = NdjsonLineSplitter(max_line_bytes=limit)
    # Single chunk already contains both the overflowing content and its LF.
    events = sp.feed(b"abcde\nok\n")
    events.extend(sp.finish())
    assert [(e.line_no, e.error, e.raw) for e in events] == [
        (1, LINE_TOO_LONG, b""),
        (2, None, b"ok"),
    ]


def test_overlong_detection_when_overflow_arrives_after_pause():
    limit = 4
    sp = NdjsonLineSplitter(max_line_bytes=limit)
    events = sp.feed(b"abcd")
    assert events == []
    # Exact length is still fine until a 5th content byte arrives.
    events = sp.feed(b"e\n")
    events.extend(sp.finish())
    assert [(e.line_no, e.error) for e in events] == [(1, LINE_TOO_LONG)]


def test_many_small_lines_chunk_boundary_regression():
    lines = [str(i).encode() for i in range(50)]
    data = b"\n".join(lines) + b"\n"
    for chunk_size in (1, 2, 7, 64, 1000):
        events = _split(data, chunk_size=chunk_size)
        assert [e.raw for e in events] == lines
        assert [e.line_no for e in events] == list(range(1, 51))
