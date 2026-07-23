"""Stability sweep: re-assess every LLM-decided control N times (temp 1.0,
cache disabled, faithful production assess()) and report which controls are
NOT unanimous. Rule-8/no-evidence controls are deterministic and skipped.

USAGE: .venv/Scripts/python.exe scripts/stability_sweep.py [--runs 15] [--workers 5]
"""
from __future__ import annotations
import argparse, json, threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import sys
sys.path.insert(0, str(Path('.').resolve()))
from sqlmodel import Session, select
from cybersecurity_assessor import config as cfg, tls
from cybersecurity_assessor.db import engine
from cybersecurity_assessor.engine.assessor import Assessor
from cybersecurity_assessor.excel.ccis_reader import read_workbook_index
from cybersecurity_assessor.models import Assessment, Objective, Workbook
from cybersecurity_assessor.routes.controls import _build_evidence_block
from cybersecurity_assessor.engine.crm_context import build_crm_context
from cybersecurity_assessor.system_context import build_boundary_brief

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--runs',type=int,default=15)
    ap.add_argument('--workers',type=int,default=5); ap.add_argument('--out',default='scripts/_stability_sweep.json')
    a=ap.parse_args()
    tls.install()
    from openai import OpenAI
    from cybersecurity_assessor.llm.client import OpenAIClient
    base,tok=cfg.resolve_openai_endpoint()
    sdk=OpenAI(base_url=base,api_key=tok,max_retries=3,timeout=240)
    client=OpenAIClient(model='gpt-5.6-sol',_sdk_client=sdk,max_tokens=32000)
    main_s=Session(engine); wb=main_s.get(Workbook,1); idx=read_workbook_index(Path(wb.path)); c2r=idx.by_cci()
    # LLM-decided objective ids
    llm=main_s.exec(select(Assessment,Objective).join(Objective,Objective.id==Assessment.objective_id).where(
        Assessment.verdict_source.in_(('LLM_ACCEPT','LLM_AFTER_RETRY')))).all()
    targets=[(o.objective_id,o.control_id_fk) for _a,o in llm]
    print('sweeping %d LLM controls x %d runs = %d calls'%(len(targets),a.runs,len(targets)*a.runs))
    # prep serially (thread-local session for evidence build)
    tl=threading.local()
    def sess():
        s=getattr(tl,'s',None)
        if s is None: s=Session(engine); tl.s=s
        return s
    preps={}
    for cci,_ in targets:
        s=sess(); o=s.exec(select(Objective).where(Objective.objective_id==cci)).first()
        row=c2r.get(cci)
        if row is None: continue
        ev=_build_evidence_block(objective_pk=o.id,control_id=row.control_id,workbook_id=1,s=s)
        crm=build_crm_context(1,s)
        try: bb=build_boundary_brief(1,s,scope_labels=crm.scope_labels())
        except Exception: bb=None
        preps[cci]=dict(row=row,ev=ev,crm=crm,bb=bb)
    print('prepped %d'%len(preps))
    results={cci:[] for cci in preps}
    def one(cci):
        p=preps[cci]; aor=Assessor(llm=client,cache_session=None)
        try:
            d=aor.assess(p['row'],tagged_evidence=p['ev'].text,evidence_block=p['ev'],crm_context=p['crm'],boundary_brief=p['bb'],workbook_id=None)
            return cci,(d.status.value if d.status else ('NEEDS_REVIEW' if d.needs_review else 'None'))
        except Exception as e: return cci,'ERROR'
    jobs=[cci for cci in preps for _ in range(a.runs)]
    import random; random.Random(7).shuffle(jobs)
    done=0; total=len(jobs)
    with ThreadPoolExecutor(max_workers=a.workers) as pool:
        futs=[pool.submit(one,cci) for cci in jobs]
        for f in as_completed(futs):
            cci,st=f.result(); results[cci].append(st); done+=1
            if done%100==0: print('  %d/%d'%(done,total))
    # analyze
    out={}; wobbly=[]
    for cci,sts in results.items():
        c=Counter(sts); tot=sum(c.values()); minority=tot-max(c.values()) if c else 0
        out[cci]={'dist':dict(c),'minority':minority,'runs':tot}
        if minority>=1: wobbly.append((cci,minority,dict(c)))
    wobbly.sort(key=lambda x:-x[1])
    Path(a.out).write_text(json.dumps({'runs':a.runs,'n':len(preps),'results':out,'wobbly':wobbly},indent=2))
    uni=sum(1 for cci in out if out[cci]['minority']==0)
    print('\n==== STABILITY SWEEP ===='); print('unanimous: %d/%d (%.1f%%)'%(uni,len(out),100*uni/len(out)))
    print('wobbly (any split): %d'%len(wobbly))
    for cci,m,dist in wobbly:
        print('  %-14s minority=%2d  %s'%(cci,m,dist))
    print('wrote',a.out)

if __name__=='__main__': main()
