"""Presidio's email recognizer calls tldextract's module-level extractor,
which by default fetches the Public Suffix List on a cache miss."""

from __future__ import annotations

import socket

import pytest

tld = pytest.importorskip("tldextract.tldextract")


def test_the_module_extractor_reads_only_the_bundled_snapshot(monkeypatch):
    from forgd_verdict.detectors.mlpii import _offline_suffix_list

    monkeypatch.setattr(tld, "TLD_EXTRACTOR", tld.TLD_EXTRACTOR)

    def no_network(*args, **kwargs):
        raise AssertionError("tldextract reached the network")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    _offline_suffix_list()
    assert tld.TLD_EXTRACTOR.suffix_list_urls == ()
    import tldextract

    assert tldextract.extract("someone@mail.example.co.uk").suffix == "co.uk"
