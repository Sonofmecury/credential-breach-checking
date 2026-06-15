"""
protocols.py -- three credential-breach-checking protocols with a uniform
interface, for a privacy/performance comparison.

A client holds candidate credentials (passwords). A server holds a breach corpus
(known-compromised passwords). The client wants to learn which of its credentials
are breached while revealing as little as possible to the server.

Protocols:
  NaiveHashLookup   client sends full SHA-256 hash; server replies present/absent.
                    Baseline: NO query privacy (server learns the exact hash).
  KAnonymity        HIBP model: SHA-1 hash, send the 5-hex-char prefix; server
                    returns all suffixes in that bucket; client matches locally.
                    Server learns only the prefix (a k-anonymity set).
  DhPsi             Diffie-Hellman Private Set Intersection over a safe-prime
                    group. Server learns nothing about which credentials the
                    client checks (only the query-set cardinality); client learns
                    only the intersection. Cryptographic privacy.

Each protocol exposes:
  server_setup(breach_set)           -> server state
  check(client_set, server_state)    -> (breached_subset, metrics)
where metrics includes communication bytes and a leakage descriptor.
"""
from __future__ import annotations

import hashlib
import secrets

try:
    import gmpy2
    def _powmod(b, e, m):
        return int(gmpy2.powmod(int(b), int(e), int(m)))
    _BACKEND = "gmpy2"
except Exception:  # pragma: no cover
    def _powmod(b, e, m):
        return pow(b, e, m)
    _BACKEND = "python"

# ---- RFC 3526 2048-bit MODP safe prime (group 14). p = 2q+1, q prime. ----
P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
P = int(P_HEX, 16)
Q = (P - 1) // 2  # prime order of the QR subgroup


def _sha256_int(s: str) -> int:
    return int.from_bytes(hashlib.sha256(s.encode()).digest(), "big")


# ---------------------------------------------------------------------------
class NaiveHashLookup:
    name = "naive_hash"
    leakage = "Server learns the exact SHA-256 hash of every queried credential (no query privacy)."

    def server_setup(self, breach_set):
        return {hashlib.sha256(p.encode()).hexdigest() for p in breach_set}

    def check(self, client_set, server_state):
        sent = [hashlib.sha256(p.encode()).hexdigest() for p in client_set]
        breached = {p for p, h in zip(client_set, sent) if h in server_state}
        # communication: client sends 32-byte hashes; server replies 1 bit each
        comm = len(sent) * 32 + len(sent) * 1
        return breached, {"comm_bytes": comm, "server_learns_exact_hash": True}


# ---------------------------------------------------------------------------
class KAnonymity:
    name = "k_anonymity"
    PREFIX = 5  # hex chars of SHA-1 (HIBP uses 5) -> 2^20 buckets
    leakage = "Server learns the SHA-1 prefix (a k-anonymity bucket) of each query, not the full hash."

    def server_setup(self, breach_set):
        buckets = {}
        for p in breach_set:
            h = hashlib.sha1(p.encode()).hexdigest().upper()
            buckets.setdefault(h[: self.PREFIX], []).append(h[self.PREFIX:])
        return buckets

    def check(self, client_set, server_state):
        breached = set(); comm = 0; bucket_sizes = []
        for p in client_set:
            h = hashlib.sha1(p.encode()).hexdigest().upper()
            pref, suf = h[: self.PREFIX], h[self.PREFIX:]
            comm += self.PREFIX  # client uploads the prefix
            bucket = server_state.get(pref, [])
            bucket_sizes.append(len(bucket))
            comm += sum(len(s) for s in bucket)  # server returns the bucket suffixes
            if suf in bucket:
                breached.add(p)
        return breached, {"comm_bytes": comm, "bucket_sizes": bucket_sizes,
                          "mean_k_anonymity": (sum(bucket_sizes) / len(bucket_sizes)) if bucket_sizes else 0}


# ---------------------------------------------------------------------------
class DhPsi:
    name = "dh_psi"
    leakage = "Server learns nothing about which credentials are queried (only the query-set size); client learns only the intersection."

    def _hash_to_group(self, s: str) -> int:
        # land in the QR subgroup of order q: square the hash mod p
        return _powmod(_sha256_int(s) % P, 2, P)

    def server_setup(self, breach_set):
        beta = secrets.randbelow(Q - 2) + 2
        # server publishes H(y)^beta for each breach entry (its blinded set)
        blinded = {_powmod(self._hash_to_group(y), beta, P) for y in breach_set}
        return {"beta": beta, "blinded_server_set": blinded}

    def check(self, client_set, server_state):
        beta = server_state["beta"]; server_blinded = server_state["blinded_server_set"]
        alpha = secrets.randbelow(Q - 2) + 2
        # round 1: client -> server  H(x)^alpha
        client_blinded = [(p, _powmod(self._hash_to_group(p), alpha, P)) for p in client_set]
        # round 2: server -> client  (H(x)^alpha)^beta  = H(x)^{alpha beta}
        double = [(p, _powmod(a, beta, P)) for p, a in client_blinded]
        # client raises server's blinded set to alpha: H(y)^{beta alpha}
        server_double = {_powmod(b, alpha, P) for b in server_blinded}
        breached = {p for p, d in double if d in server_double}
        elem = (P.bit_length() + 7) // 8  # bytes per group element
        comm = len(client_set) * elem        # round 1 upload
        comm += len(client_set) * elem       # round 2 download
        comm += len(server_blinded) * elem   # server set transfer (one-time)
        return breached, {"comm_bytes": comm, "server_learns_queries": False,
                          "group_bits": P.bit_length()}


PROTOCOLS = {p.name: p for p in [NaiveHashLookup(), KAnonymity(), DhPsi()]}
