"""Figures for the credential-breach-checking comparison.
  fig1_communication.png   comm per query vs DB size (log-log)
  fig2_computation.png     total compute (setup+query) vs DB size (log-log)
  fig3_privacy.png         k-anonymity set size vs DB size (privacy parameter)
"""
import csv, json, os, sys, secrets, statistics
sys.path.insert(0, os.path.dirname(__file__))
import protocols as P
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt

RES=os.path.join(os.path.dirname(__file__),"..","results"); FIG=os.path.join(RES,"figures")
COL={"naive_hash":"#d7301f","k_anonymity":"#2b8cbe","dh_psi":"#33a02c"}
LBL={"naive_hash":"naive hash (no privacy)","k_anonymity":"k-anonymity (HIBP)","dh_psi":"DH-PSI"}

def load():
    rows=list(csv.DictReader(open(os.path.join(RES,"benchmark.csv"))))
    d={}
    for r in rows:
        d.setdefault(r["protocol"],[]).append((int(r["db_size"]),float(r["comm_per_query_bytes"]),
                                               float(r["setup_ms"])+float(r["query_ms"])))
    for k in d: d[k].sort()
    return d

def fig1(d):
    fig,ax=plt.subplots(figsize=(8,5))
    for p,xs in d.items():
        ax.plot([a for a,_,_ in xs],[b for _,b,_ in xs],marker="o",color=COL[p],label=LBL[p])
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("Breach-DB size (entries)"); ax.set_ylabel("Communication per query (bytes, log)")
    ax.set_title("Figure 1. Communication cost per query vs breach-DB size")
    ax.grid(True,which="both",ls=":",alpha=0.4); ax.legend()
    fig.tight_layout(); o=os.path.join(FIG,"fig1_communication.png"); fig.savefig(o,dpi=150); plt.close(fig); return o

def fig2(d):
    fig,ax=plt.subplots(figsize=(8,5))
    for p,xs in d.items():
        ax.plot([a for a,_,_ in xs],[c for _,_,c in xs],marker="o",color=COL[p],label=LBL[p])
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("Breach-DB size (entries)"); ax.set_ylabel("Total compute: setup+query (ms, log)")
    ax.set_title("Figure 2. Computation cost vs breach-DB size")
    ax.grid(True,which="both",ls=":",alpha=0.4); ax.legend()
    fig.tight_layout(); o=os.path.join(FIG,"fig2_computation.png"); fig.savefig(o,dpi=150); plt.close(fig); return o

def fig3():
    # k-anonymity set size (mean over NON-EMPTY buckets) vs DB size; PSI = DB-independent
    Ns=[10000,100000,1000000]; ks=[]
    for n in Ns:
        breach={f"pw_{i}_{secrets.token_hex(3)}" for i in range(n)}
        st=P.PROTOCOLS["k_anonymity"].server_setup(breach)
        sizes=[len(v) for v in st.values()]
        ks.append(statistics.mean(sizes))
    fig,ax=plt.subplots(figsize=(8,5))
    ax.plot(Ns,ks,marker="o",color=COL["k_anonymity"],label="k-anonymity: mean k (anonymity-set size)")
    ax.axhline(1.0,ls="--",color="#999",label="k = 1 (no anonymity: prefix => unique hash)")
    ax.set_xscale("log")
    ax.set_xlabel("Breach-DB size (entries)"); ax.set_ylabel("k-anonymity set size (mean per non-empty bucket)")
    ax.set_title("Figure 3. k-anonymity privacy degrades for smaller breach DBs\n(DH-PSI privacy is cryptographic and DB-size-independent)")
    for x,k in zip(Ns,ks): ax.annotate(f"{k:.2f}",(x,k),textcoords="offset points",xytext=(0,7),ha="center",fontsize=8)
    ax.grid(True,which="both",ls=":",alpha=0.4); ax.legend()
    fig.tight_layout(); o=os.path.join(FIG,"fig3_privacy.png"); fig.savefig(o,dpi=150); plt.close(fig)
    json.dump({"db_sizes":Ns,"mean_k":[round(k,3) for k in ks]},open(os.path.join(RES,"privacy_curve.json"),"w"),indent=2)
    return o

def main():
    os.makedirs(FIG,exist_ok=True); d=load()
    for o in (fig1(d),fig2(d),fig3()): print("Wrote",o)

if __name__=="__main__": main()
