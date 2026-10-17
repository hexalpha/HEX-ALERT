"""Safe, local-only benchmark helpers for the resident llama.cpp model."""
import asyncio
import statistics
import time

import httpx

from config.ai import options, inference_url
from services.ai_chat import data_context, compact_model_context

QUESTIONS = {
    'simple': 'What is the difference between IDS and IPS?',
    'cyber': 'Explain SQL injection in simple terms.',
    'rag': 'What are the latest critical CVEs in HEX ALERT?',
}
SYSTEM = 'You are HEX ALPHA by HEX SECURITY. Be concise, accurate, and use only supplied current records.'


def _median(values):
    values=[float(x) for x in values if x is not None]
    return round(statistics.median(values),4) if values else None


async def wait_ready(client, timeout=360):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            response=await client.get(inference_url()+'/health',timeout=5)
            if response.status_code==200:
                health=response.json()
                if health.get('status')=='ready': return health
                if health.get('status')=='error': raise RuntimeError('Local model failed to load; current settings will be restored.')
        except httpx.HTTPError: pass
        await asyncio.sleep(2)
    raise TimeoutError('Local model did not finish loading before the benchmark timeout.')


async def _request(client, messages, max_tokens=32):
    started=time.monotonic()
    payload={
        'model':'CyberSecurity.gguf','messages':messages,'max_tokens':max_tokens,
        'temperature':0.2,'top_p':0.9,'stream':True,
        'stream_options':{'include_usage':True}}
    answer_parts=[]; usage={}; timing={}; first_token=None
    async with client.stream('POST',inference_url()+'/v1/chat/completions',json=payload,timeout=600) as response:
        response.raise_for_status()
        async for line in response.aiter_lines():
            if not line.startswith('data:'): continue
            raw=line[5:].strip()
            if raw=='[DONE]': continue
            try: chunk=__import__('json').loads(raw)
            except (ValueError,TypeError): continue
            if isinstance(chunk.get('usage'),dict): usage=chunk['usage']
            if isinstance(chunk.get('timings'),dict): timing=chunk['timings']
            for choice in chunk.get('choices') or []:
                delta=choice.get('delta') or {}
                text=delta.get('content') or ''
                if text:
                    if first_token is None: first_token=time.monotonic()-started
                    answer_parts.append(text)
    answer=''.join(answer_parts)
    if not answer or len(answer.strip())<5: raise RuntimeError('The local model returned an empty benchmark response.')
    total=float(time.monotonic()-started)
    details=usage.get('prompt_tokens_details') or {}
    return {'input_tokens':usage.get('prompt_tokens',timing.get('prompt_n')),
            'prompt_cache_tokens':details.get('cached_tokens',timing.get('cache_n')),
            'prompt_eval_seconds':round((timing.get('prompt_ms') or 0)/1000,4) or None,
            'prompt_eval_tokens_per_second':timing.get('prompt_per_second'),
            'first_token_seconds':round(first_token,4) if first_token is not None else None,
            'generation_tokens_per_second':timing.get('predicted_per_second'),
            'total_seconds':round(total,4),
            'output_tokens':usage.get('completion_tokens',timing.get('predicted_n')),
            'answer_valid':True}


async def measure_configuration(engine_config, repetitions=3):
    """Warm the target engine, then take three samples per fixed test case."""
    async with httpx.AsyncClient(timeout=600,trust_env=False) as client:
        initial=await wait_ready(client)
        warmup_started=time.monotonic()
        await _request(client,[{'role':'system','content':SYSTEM},{'role':'user','content':'Say ready.'}],8)
        warmup_seconds=round(time.monotonic()-warmup_started,4)
        rag_diag={}; rag_started=time.monotonic()
        rag=await data_context(QUESTIONS['rag'],rag_diag,top_k=3)
        rag_retrieval_ms=round((time.monotonic()-rag_started)*1000,2)
        compact=compact_model_context(rag) if rag else ''
        prompts={
            'simple':[{'role':'system','content':SYSTEM},{'role':'user','content':QUESTIONS['simple']}],
            'cyber':[{'role':'system','content':SYSTEM},{'role':'user','content':QUESTIONS['cyber']}],
        }
        if compact and 'No matching current HEX ALERT records' not in compact:
            prompts['rag']=[{'role':'system','content':SYSTEM},{'role':'system','content':compact},
                            {'role':'user','content':QUESTIONS['rag']}]
        results={}; sample_rows=[]; cpu_samples=[]; stop_cpu=asyncio.Event()
        async def sample_cpu():
            while not stop_cpu.is_set():
                try:
                    health=(await client.get(inference_url()+'/health',timeout=5)).json()
                    value=health.get('cpu_percent')
                    if isinstance(value,(int,float)): cpu_samples.append(float(value))
                except (httpx.HTTPError,ValueError): pass
                try: await asyncio.wait_for(stop_cpu.wait(),timeout=0.5)
                except TimeoutError: pass
        cpu_task=asyncio.create_task(sample_cpu())
        for name,messages in prompts.items():
            samples=[]
            for _ in range(repetitions):
                sample=await _request(client,messages,160 if name in ('simple','cyber') else 128)
                samples.append(sample); sample_rows.append(sample)
            results[name]={key:_median([row.get(key) for row in samples])
                           for key in ('input_tokens','prompt_cache_tokens','prompt_eval_seconds',
                                       'prompt_eval_tokens_per_second','first_token_seconds',
                                       'generation_tokens_per_second','total_seconds','output_tokens')}
            results[name]['samples']=len(samples)
        stop_cpu.set(); await asyncio.gather(cpu_task,return_exceptions=True)
        health=await wait_ready(client)
        return {'cases':results,'rag_records_available':'rag' in prompts,
                'rag_retrieval_ms':rag_retrieval_ms,'rag_db_query_ms':rag_diag.get('db_query_ms'),
                'rag_cache_hit':bool(rag_diag.get('rag_cache_hit')),
                'estimated_rag_context_tokens':max(0,(results.get('rag',{}).get('input_tokens') or 0)-
                    (results.get('simple',{}).get('input_tokens') or 0)),
                'ram_bytes':health.get('ram_usage_bytes'),
                'cpu_percent_median':_median(cpu_samples),'cpu_percent_peak':max(cpu_samples) if cpu_samples else None,
                'load_seconds':health.get('load_seconds',initial.get('load_seconds')),
                'warmup_seconds':warmup_seconds,'engine':{k:health.get(k) for k in
                ('threads','threads_batch','batch_size','ubatch_size','context_size','kv_cache_type','acceleration')},
                'repetitions':repetitions,'warmed':True}


async def configure_engine(config, *, persist=False):
    async with httpx.AsyncClient(timeout=600,trust_env=False) as client:
        response=await client.post(inference_url()+'/configure',params={'persist':str(persist).lower()},json=config)
        response.raise_for_status()
        return await wait_ready(client)
