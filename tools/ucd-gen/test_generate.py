"""Guards on the UCD fetch (docs/09 §7.1; G16 part C).

These tables decide every blind index value both cores produce, and there is
no published digest to check the source files against. So the only things
standing between a bad fetch and a silent cross-implementation lookup miss are
the transport and the URL -- and until 2026-08-25 neither was checked: `urllib`
followed redirects and protocol downgrades by default, and the fetch logged the
URL it asked for rather than the one that answered.

Runs without pytest and without the network:

    python tools/ucd-gen/test_generate.py

Pytest can also collect it, since every check is a `test_*` function.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import generate  # noqa: E402


# --------------------------------------------------------------------------
# doubles: an opener whose response reports whatever served URL we want
# --------------------------------------------------------------------------

class _Response:
    def __init__(self, url: str, body: bytes) -> None:
        self.url = url
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *exc) -> bool:
        return False


class _Opener:
    """Answers every request from `served`, which may differ from the request."""

    def __init__(self, served=None, body: bytes = b"# UCD\n") -> None:
        self._served = served
        self._body = body
        self.requested: list[str] = []

    def open(self, url: str, timeout=None) -> _Response:
        self.requested.append(url)
        return _Response(self._served or url, self._body)


def _tmpdir() -> str:
    return tempfile.mkdtemp(prefix="ucd-gen-test-")


def _expect_unsafe(fn, *needles: str) -> str:
    try:
        fn()
    except generate.UnsafeFetch as exc:
        message = str(exc)
        for needle in needles:
            assert needle in message, "expected %r in %r" % (needle, message)
        return message
    raise AssertionError("expected UnsafeFetch, nothing was raised")


# --------------------------------------------------------------------------
# the guards
# --------------------------------------------------------------------------

def test_pinned_url_is_https() -> None:
    """The template itself must not be the thing that downgrades."""
    assert generate.UCD_URL.startswith("https://")
    for name in generate.UCD_FILES:
        assert (generate.UCD_URL % (generate.VERSION, name)).startswith("https://")


def test_redirect_is_refused() -> None:
    """The real defect: `Public/<unreleased>/ucd/` 302s to the moving draft.

    Reproduces the shape measured on 2026-08-25 -- a redirect to a plaintext
    draft URL -- through the handler that now refuses it.
    """
    opener = generate._refuse_redirects()
    # `build_opener` drops the stock handler in favour of a subclass, so the
    # one redirect handler on the opener should be the refusing one.
    redirectors = [h for h in opener.handlers
                   if isinstance(h, urllib.request.HTTPRedirectHandler)]
    assert len(redirectors) == 1, "expected exactly one redirect handler, got %d" % len(redirectors)
    handler = redirectors[0]
    assert type(handler) is not urllib.request.HTTPRedirectHandler, \
        "the stock handler is installed; redirects would be followed"

    class _Req:
        full_url = "https://www.unicode.org/Public/18.0.0/ucd/UnicodeData.txt"

    message = _expect_unsafe(
        lambda: handler.redirect_request(
            _Req(), None, 302, "Found", {},
            "http://www.unicode.org/Public/draft/ucd/UnicodeData.txt"),
        "302",
        "draft",
        generate.VERSION,
    )
    # The message has to say *why*, not just that it failed: whoever hits this
    # is mid-bump and needs to learn the version is not released.
    assert "not published yet" in message or "has not released" in message


def test_served_url_mismatch_is_refused() -> None:
    """A redirect that reached us some other way still cannot produce tables."""
    dest = _tmpdir()
    try:
        opener = _Opener(served="http://www.unicode.org/Public/draft/ucd/CaseFolding.txt")
        _expect_unsafe(
            lambda: generate.download(dest, opener=opener),
            "asked for",
            "draft",
        )
    finally:
        shutil.rmtree(dest, ignore_errors=True)


def test_plaintext_http_is_refused() -> None:
    """Even with redirects handled, an http:// pin must not fetch."""
    original = generate.UCD_URL
    generate.UCD_URL = "http://www.unicode.org/Public/%s/ucd/%s"
    dest = _tmpdir()
    try:
        _expect_unsafe(
            lambda: generate.download(dest, opener=_Opener()),
            "HTTPS",
        )
    finally:
        generate.UCD_URL = original
        shutil.rmtree(dest, ignore_errors=True)


def test_clean_fetch_writes_every_file() -> None:
    """The guards must not have broken the path they guard."""
    dest = _tmpdir()
    try:
        opener = _Opener(body=b"# 0000..0001; stub\n")
        generate.download(dest, opener=opener)
        for name in generate.UCD_FILES:
            path = os.path.join(dest, name)
            assert os.path.exists(path), "%s was not written" % name
            with open(path, "rb") as fh:
                assert fh.read() == b"# 0000..0001; stub\n"
        assert len(opener.requested) == len(generate.UCD_FILES)
        for url in opener.requested:
            assert generate.VERSION in url, url
    finally:
        shutil.rmtree(dest, ignore_errors=True)


def main() -> int:
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith("test_") and callable(o)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - a test runner reports, it does not raise
            failed += 1
            print("FAIL %s: %s: %s" % (name, type(exc).__name__, exc))
        else:
            print("ok   %s" % name)
    print("\n%d passed, %d failed" % (len(tests) - failed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
