import socket

import pandas as pd
import pytest

from phishing_url.collection_audit import audit
from phishing_url.legitimate_collection import public_addresses, read_candidates, suitable_url


def test_url_policy_rejects_cross_domain_credentials_and_tokens():
    assert suitable_url("https://www.example.com/about", "example.com")[0]
    assert not suitable_url("https://other.test/about", "example.com")[0]
    assert suitable_url("https://user@example.com/", "example.com")[1] == "credentials_in_url"
    assert suitable_url("https://example.com/?sessionid=secret", "example.com")[1] == "sensitive_query_key"


def test_public_address_guard_rejects_private_resolution(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: [(socket.AF_INET, 1, 6, "", ("127.0.0.1", 0))])
    with pytest.raises(ValueError, match="non-public"):
        public_addresses("example.com")


def test_suitability_gate_rejects_too_small_collection(tmp_path):
    observations=tmp_path/"observations.csv"; failures=tmp_path/"failures.csv"
    pd.DataFrame([{"candidate_rank":1,"candidate_domain":"example.com","url_raw":"https://example.com/about","url_clean":"https://example.com/about","observed_from":"homepage_link","evidence_url":"https://example.com/","retrieved_utc":"2026-01-01T00:00:00Z","same_domain":True,"label_basis":"assumed"}]).to_csv(observations,index=False)
    pd.DataFrame([{"candidate_rank":2,"candidate_domain":"bad.test","stage":"homepage_https","reason":"timeout"}]).to_csv(failures,index=False)
    result=audit(observations,failures,tmp_path/"audit")
    assert result["decision"] == "unsuitable"
    assert (tmp_path/"audit/manual_review_queue.csv").is_file()


def test_seeded_candidate_sampling_is_reproducible(tmp_path):
    source=tmp_path/"tranco.csv"
    source.write_text("".join(f"{rank},site{rank}.example\n" for rank in range(1,31)))
    first=read_candidates(source,5,25,10,20250926)
    assert first == read_candidates(source,5,25,10,20250926)
    assert len(first) == len(set(first)) == 10
