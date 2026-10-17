"""Repeatable local-only GGUF benchmark. Run during an AI maintenance window.

Example inside Docker:
  python -m scripts.benchmark_local_ai --sweep

The full sweep takes a long time because each llama.cpp configuration reloads the
multi-gigabyte model. Candidate settings are temporary unless --apply-best is used.
No prompt text, response text, keys or Discord credentials are written to the report.
"""
import argparse
import asyncio
import itertools
import json
import statistics
from datetime import datetime, timezone
from pathlib import Path

import httpx

from config.ai import options
from config.runtime_config import update_runtime_config
from config.settings import get_settings
from services.ai_benchmark import measure_configuration, configure_engine


def score(result):
    values=[case.get('first_token_seconds') for case in result['cases'].values()
            if case.get('first_token_seconds') is not None]
    return statistics.median(values) if values else float('inf')


def candidates(base, args):
    sets=[]
    if args.sweep:
        sets.extend([{**base,'threads':x} for x in (4,5,6,8,10,12)])
        sets.extend([{**base,'threads_batch':x} for x in (4,5,6,8,10,12)])
        sets.extend([{**base,'batch_size':b,'ubatch_size':u} for b,u in itertools.product((256,512,1024),(128,256,512)) if u<=b])
        sets.extend([{**base,'kv_cache_type':x} for x in ('f16','q8_0')])
        sets.extend([{**base,'context_size':x} for x in (2048,3072,4096)])
    else:
        threads=args.threads or [base.get('threads',0)]
        batches=args.batch or [base.get('batch_size',512)]
        ubatches=args.ubatch or [base.get('ubatch_size',512)]
        contexts=args.context or [base.get('context_size',4096)]
        kvs=args.kv_cache or [base.get('kv_cache_type','f16')]
        batch_pairs=[(b,u) for b,u in itertools.product(batches,ubatches) if u<=b]
        for t,tb,(b,u),c,kv in itertools.product(threads,args.threads_batch or [base.get('threads_batch',0)],batch_pairs,contexts,kvs):
            sets.append({**base,'threads':t,'threads_batch':tb,'batch_size':b,'ubatch_size':u,'context_size':c,'kv_cache_type':kv})
    unique=[]; seen=set()
    for item in sets:
        key=tuple(sorted(item.items()))
        if key not in seen: seen.add(key); unique.append(item)
    return unique


async def main_async(args):
    cfg=options(); original_options=cfg
    if cfg.provider!='local_gguf': raise SystemExit('Select Local GGUF as default before benchmarking; no external API is used.')
    base=cfg.engine_config()
    # Record live auto-resolved CPU threads and active server choices for an exact rollback.
    async with httpx.AsyncClient(timeout=10,trust_env=False) as client:
        live=(await client.get('http://llm:8081/health')).json()
    for name in ('threads','threads_batch','batch_size','ubatch_size','context_size','kv_cache_type'):
        if live.get(name) is not None: base[name]=live[name]
    candidates_to_test=candidates(base,args)
    if not candidates_to_test: raise SystemExit('No valid configurations selected.')
    report={'created_at':datetime.now(timezone.utc).isoformat(),'provider':'local_gguf','model':'CyberSecurity.gguf',
            'warmup_runs':1,'repetitions_per_case':3,'baseline_config':base,'sweep':bool(args.sweep),'results':[]}
    best=(float('inf'),base,None)
    try:
        for index,candidate in enumerate(candidates_to_test,1):
            print(f'[{index}/{len(candidates_to_test)}] Loading candidate configuration…',flush=True)
            await configure_engine(candidate,persist=False)
            result=await measure_configuration(candidate,repetitions=3)
            row={'config':candidate,'result':result,'median_first_token_seconds':round(score(result),4)}
            report['results'].append(row)
            print(json.dumps(row,sort_keys=True),flush=True)
            if score(result)<best[0]: best=(score(result),candidate,result)
        report['best_config']=best[1]
        report['best_result']=best[2]
        if args.apply_best and best[2] and best[1]!=base:
            cfg=cfg.model_copy(update={k:v for k,v in best[1].items() if k in cfg.engine_config()})
            update_runtime_config({'AI_OPTIONS':cfg.model_dump(),'AI_PROVIDER':cfg.provider,
                                  'AI_MODEL':cfg.providers[cfg.provider].model})
            get_settings.cache_clear()
            await configure_engine(cfg.engine_config(),persist=True)
            report['applied_best']=True
        else:
            await configure_engine(base,persist=True)
            report['applied_best']=False
    except BaseException:
        await configure_engine(base,persist=True)
        update_runtime_config({'AI_OPTIONS':original_options.model_dump(),'AI_PROVIDER':original_options.provider,
                              'AI_MODEL':original_options.providers[original_options.provider].model})
        get_settings.cache_clear()
        raise
    Path(args.output).write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(f"Report saved to {args.output}; best first-token median {best[0]:.3f}s; applied={report['applied_best']}")


def parse_args():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sweep',action='store_true',help='Run the staged threads, batch/ubatch, KV and context sweep (lengthy).')
    parser.add_argument('--apply-best',action='store_true',help='Persist best measured settings only after the entire run succeeds.')
    parser.add_argument('--threads',type=lambda x:[int(v) for v in x.split(',')])
    parser.add_argument('--threads-batch',type=lambda x:[int(v) for v in x.split(',')])
    parser.add_argument('--batch',type=lambda x:[int(v) for v in x.split(',')])
    parser.add_argument('--ubatch',type=lambda x:[int(v) for v in x.split(',')])
    parser.add_argument('--context',type=lambda x:[int(v) for v in x.split(',')])
    parser.add_argument('--kv-cache',type=lambda x:x.split(','))
    parser.add_argument('--output',default='/tmp/hex-alert-local-ai-benchmark.json')
    return parser.parse_args()


if __name__=='__main__': asyncio.run(main_async(parse_args()))
