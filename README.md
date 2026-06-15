# Privacy vs Cost in Credential Breach Checking: k-Anonymity vs Private Set Intersection

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20703640.svg)](https://doi.org/10.5281/zenodo.20703640)

**Paper 3 of the "Secure Systems in the Quantum Era" portfolio.** An applied-
cryptography comparison of how breach-checking services trade privacy against
cost. Builds on the author's password-auditor project.

## Status

- Implementation complete, tested (5 tests), and benchmarked.
- Manuscript: `paper/Credential_Breach_Checking_Preprint.pdf` (7 pp).

## The three protocols

- **naive hash** -- send full SHA-256 hash (baseline; no query privacy).
- **k-anonymity (HIBP)** -- SHA-1, send 5-hex prefix, download bucket, match locally.
- **DH-PSI** -- Diffie-Hellman Private Set Intersection over the RFC 3526 2048-bit
  safe prime (gmpy2-backed); server learns nothing about queries.

## Headline findings

- **Cost:** k-anonymity is ~tens of bytes and sub-ms per query; DH-PSI is 100-1000x
  more communication and ~10^4x more computation, both linear in breach-DB size.
- **Privacy:** at a 1,000,000-entry DB the k-anonymity set has **median 1, mean 1.55,
  max 8** -- a prefix usually maps to a single hash, so an honest-but-curious server
  effectively learns the credential. PSI privacy is cryptographic and DB-size-independent.
- **Takeaway:** k-anonymity is safe only at very large DB scale; for small/targeted
  breach corpora its privacy collapses and PSI is the right choice.

## Run

```bash
pip install -r requirements.txt   # numpy/matplotlib/pytest/gmpy2
python3 src/benchmark.py          # checkpointed; rerun until complete
python3 src/plots.py
pytest -q
```

Outputs: `results/benchmark.csv`, `results/kanon_buckets.json`,
`results/privacy_curve.json`, `results/figures/`.

## License
MIT.
