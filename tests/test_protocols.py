"""Correctness: every protocol must return EXACTLY the true breached subset
(client credentials that are in the breach corpus), and nothing else."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import protocols as P
import pytest

BREACH = {f"breached_pw_{i}" for i in range(200)} | {"password123", "qwerty", "letmein"}
CLIENT = ["password123", "qwerty", "unique_safe_1", "unique_safe_2",
          "breached_pw_5", "breached_pw_199", "totally_unbreached"]
TRUE_BREACHED = {"password123", "qwerty", "breached_pw_5", "breached_pw_199"}


@pytest.mark.parametrize("name", list(P.PROTOCOLS.keys()))
def test_protocol_correct(name):
    proto = P.PROTOCOLS[name]
    state = proto.server_setup(BREACH)
    breached, metrics = proto.check(CLIENT, state)
    assert breached == TRUE_BREACHED, f"{name}: got {breached}"
    assert metrics["comm_bytes"] > 0


def test_dh_psi_hides_nonmembers():
    """DH-PSI must not flag any safe credential."""
    proto = P.PROTOCOLS["dh_psi"]
    state = proto.server_setup(BREACH)
    breached, _ = proto.check(["unique_safe_1", "unique_safe_2"], state)
    assert breached == set()


def test_k_anonymity_reports_bucket_sizes():
    proto = P.PROTOCOLS["k_anonymity"]
    state = proto.server_setup(BREACH)
    _, m = proto.check(CLIENT, state)
    assert "mean_k_anonymity" in m and m["mean_k_anonymity"] >= 0
