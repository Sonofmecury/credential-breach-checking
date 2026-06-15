"""
benchmark.py -- measure the three protocols' cost vs breach-DB size.

For each protocol and DB size N (fixed client batch M), records server-setup time,
query time, total communication bytes, and the recovered breached count. DH-PSI
is modexp-bound so it is measured at smaller N (and the linear O(N) trend is the
point); naive and k-anonymity scale to large N cheaply.

Also records the k-anonymity bucket-size distribution (its privacy parameter) at
the largest DB size.

Checkpointed: appends each (protocol, N) to results/benchmark.csv; rerun to finish.
Outputs: results/benchmark.csv, results/kanon_buckets.json, results/run_meta.json
"""
from __future__ import annotations
import csv, json, os, sys, time, secrets
sys.path.insert(0, os.path.dirname(__file__))
import protocols as P

RES = os.path.join(os.path.dirname(__file__), "..", "results")
M = 100            # client batch size
OVERLAP = 0.5      # fraction of client creds that are actually breached
N_CHEAP = [1000, 10000, 100000, 1000000]
N_PSI = [1000, 2000, 4000]
PLAN = {"naive_hash": N_CHEAP, "k_anonymity": N_CHEAP, "dh_psi": N_PSI}


def corpus(n):
    return {f"pw_{i}_{secrets.token_hex(4)}" for i in range(n)}


def client_from(breach, m, overlap):
    bl = list(breach)
    n_hit = int(m * overlap)
    hits = bl[:n_hit]
    safe = [f"safe_{i}_{secrets.token_hex(4)}" for i in range(m - n_hit)]
    return hits + safe, set(hits)


def main():
    os.makedirs(RES, exist_ok=True)
    out = os.path.join(RES, "benchmark.csv")
    fields = ["protocol", "db_size", "client_batch", "setup_ms", "query_ms",
              "comm_bytes", "comm_per_query_bytes", "breached_found"]
    done = set(); rows = []
    if os.path.exists(out):
        rows = list(csv.DictReader(open(out)))
        done = {(r["protocol"], int(r["db_size"])) for r in rows}

    for pname, nlist in PLAN.items():
        proto = P.PROTOCOLS[pname]
        for n in nlist:
            if (pname, n) in done:
                continue
            breach = corpus(n)
            client, truth = client_from(breach, M, OVERLAP)
            t0 = time.perf_counter(); state = proto.server_setup(breach); setup = (time.perf_counter()-t0)*1000
            t0 = time.perf_counter(); breached, met = proto.check(client, state); q = (time.perf_counter()-t0)*1000
            row = {"protocol": pname, "db_size": n, "client_batch": M,
                   "setup_ms": round(setup, 2), "query_ms": round(q, 2),
                   "comm_bytes": met["comm_bytes"], "comm_per_query_bytes": round(met["comm_bytes"]/M, 1),
                   "breached_found": len(breached)}
            rows.append(row); done.add((pname, n))
            with open(out, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
                for rr in rows: w.writerow({k: rr.get(k) for k in fields})
            print("{:<12} N={:<8} setup={:>8}ms query={:>8}ms comm={:>10}B found={}".format(
                pname, n, row["setup_ms"], row["query_ms"], row["comm_bytes"], len(breached)), flush=True)

    total = sum(len(v) for v in PLAN.values())
    if len(rows) < total:
        print(f"PARTIAL {len(rows)}/{total}; rerun."); return 0

    # k-anonymity bucket-size distribution at largest N (privacy metric)
    import statistics
    breach = corpus(1000000)
    st = P.PROTOCOLS["k_anonymity"].server_setup(breach)
    sizes = [len(v) for v in st.values()]
    ka = {"db_size": 1000000, "n_nonempty_buckets": len(sizes),
          "mean_bucket": round(statistics.mean(sizes), 2), "median_bucket": statistics.median(sizes),
          "p95_bucket": sorted(sizes)[int(0.95*len(sizes))], "max_bucket": max(sizes),
          "note": "Each queried prefix reveals a k-anonymity set of this many candidate hashes."}
    json.dump(ka, open(os.path.join(RES, "kanon_buckets.json"), "w"), indent=2)
    json.dump({"client_batch": M, "overlap": OVERLAP, "psi_group_bits": P.P.bit_length(),
               "n_cheap": N_CHEAP, "n_psi": N_PSI},
              open(os.path.join(RES, "run_meta.json"), "w"), indent=2)
    print("k-anon buckets @1M:", ka)
    print("wrote benchmark.csv, kanon_buckets.json, run_meta.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
