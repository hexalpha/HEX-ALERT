"""Internal-only supervisor. Owns one resident llama.cpp process; never a shell."""
import asyncio
import json
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
import httpx
import psutil
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from gguf_metadata import inspect_gguf

MODEL = os.environ.get('LOCAL_GGUF_MODEL', '/models/CyberSecurity.gguf')
CONFIG = Path('/state/engine.json')
INTERNAL = 'http://127.0.0.1:8082'

class EngineConfig(BaseModel):
    context_size: int = Field(4096, ge=2048, le=16384)
    threads: int = Field(0, ge=0, le=64)
    threads_batch: int = Field(0, ge=0, le=64)
    batch_size: int = Field(256, ge=32, le=1024)
    ubatch_size: int = Field(256, ge=32, le=1024)
    kv_cache_type: Literal['f16','q8_0','q4_0'] = 'f16'
    concurrency: int = Field(1, ge=1, le=2)
    gpu_acceleration: Literal['auto','cpu','cuda'] = 'auto'
    gpu_layers: int = Field(-1, ge=-1, le=200)
    fallback_template: Literal['chatml','qwen3','llama3','gemma','mistral-v3'] = 'chatml'
    reasoning_mode: Literal['fast','reasoning'] = 'fast'

class Engine:
    def __init__(self):
        self.process = None
        self.task = None
        self.config = EngineConfig()
        self.state = {'status':'loading', 'model':'CyberSecurity.gguf', 'backend':'llama.cpp'}
        self.client = None
        self.lock = asyncio.Lock()
        self.monitor_process = None

    async def stop(self):
        if self.task and not self.task.done():
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
        if self.process and self.process.returncode is None:
            self.process.terminate()
            try: await asyncio.wait_for(self.process.wait(), 10)
            except TimeoutError:
                self.process.kill()
                await self.process.wait()

    async def load(self, force_cpu=False):
        started = time.monotonic()
        self.state = {'status':'loading', 'model':'CyberSecurity.gguf', 'backend':'llama.cpp'}
        try:
            metadata = await asyncio.to_thread(inspect_gguf, MODEL)
            self.state['metadata'] = metadata
            # mmap weights still need working RAM plus KV cache; avoid obvious OOM loads.
            available = psutil.virtual_memory().available
            for name in ('memory.max',):
                path = Path('/sys/fs/cgroup') / name
                if path.exists() and path.read_text().strip().isdigit():
                    available = min(available, int(path.read_text()) - int(Path('/sys/fs/cgroup/memory.current').read_text()))
            if available < metadata['size_bytes'] + 512 * 1024**2:
                raise RuntimeError('Insufficient memory for model and context')
            cfg = self.config
            threads = cfg.threads or max(1, min(8, (psutil.cpu_count(logical=False) or os.cpu_count() or 2) - 1))
            threads_batch = cfg.threads_batch or threads
            # CPU image remains the portable default. CUDA build can be selected explicitly.
            probe = await asyncio.create_subprocess_exec('/app/llama-server','--list-devices', stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            devices, _ = await asyncio.wait_for(probe.communicate(), 15)
            cuda = b'CUDA' in devices and cfg.gpu_acceleration != 'cpu' and not force_cpu
            self.state.update(acceleration='CUDA' if cuda else 'CPU', threads=threads, threads_batch=threads_batch,
                              gpu_note='' if cuda or cfg.gpu_acceleration=='cpu' else 'CUDA unavailable in runtime; using CPU',
                              context_size=cfg.context_size, batch_size=cfg.batch_size, ubatch_size=min(cfg.ubatch_size,cfg.batch_size),
                              kv_cache_type=cfg.kv_cache_type, available_ram_bytes=available)
            args = ['/app/llama-server','-m',MODEL,'--host','127.0.0.1','--port','8082',
                    '-c',str(cfg.context_size * cfg.concurrency),'-np',str(cfg.concurrency),
                    '-t',str(threads),'-tb',str(threads_batch),'-b',str(cfg.batch_size),'-ub',str(min(cfg.ubatch_size,cfg.batch_size)),
                    '-ctk',cfg.kv_cache_type,'-ctv',cfg.kv_cache_type,
                    '-ngl',str(cfg.gpu_layers if cuda else 0),
                    '--alias','CyberSecurity.gguf','--reasoning','off' if cfg.reasoning_mode=='fast' else 'on',
                    '--cache-prompt','--log-disable']
            if not metadata.get('chat_template'): args += ['--chat-template',cfg.fallback_template]
            self.process = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            self.monitor_process = psutil.Process(self.process.pid)
            # Prime psutil's interval counter so later health polls report real usage.
            self.monitor_process.cpu_percent(None)
            for _ in range(600):
                if self.process.returncode is not None:
                    if cuda:
                        await self.load(force_cpu=True)
                        return
                    raise RuntimeError('Inference process failed to load model')
                try:
                    response = await self.client.get(INTERNAL+'/health', timeout=2)
                    if response.status_code == 200: break
                except httpx.HTTPError: pass
                await asyncio.sleep(1)
            else: raise RuntimeError('Model loading timed out')
            self.state.update(status='warming_up', load_seconds=round(time.monotonic()-started,3))
            response = await self.client.post(INTERNAL+'/v1/chat/completions', json={'model':'CyberSecurity.gguf','messages':[{'role':'user','content':'Say ready.'}], 'max_tokens':8, 'temperature':0}, timeout=180)
            response.raise_for_status()
            self.state.update(status='ready', warmup_seconds=round(time.monotonic()-started-self.state['load_seconds'],3))
        except asyncio.CancelledError: raise
        except Exception as exc:
            self.state.update(status='error', error=str(exc) if isinstance(exc, (ValueError,RuntimeError)) else 'Model could not be loaded; check file and runtime resources')

engine = Engine()

@asynccontextmanager
async def lifespan(app):
    engine.client = httpx.AsyncClient(timeout=600, limits=httpx.Limits(max_connections=8))
    try:
        if CONFIG.exists(): engine.config = EngineConfig.model_validate_json(CONFIG.read_text())
    except Exception: pass
    engine.task = asyncio.create_task(engine.load())
    async def monitor():
        retries=0
        while True:
            await asyncio.sleep(15)
            if engine.state['status']=='ready' and engine.process and engine.process.returncode is not None and retries<3:
                async with engine.lock:
                    retries+=1
                    await engine.stop()
                    engine.task=asyncio.create_task(engine.load())
    watcher=asyncio.create_task(monitor())
    yield
    watcher.cancel()
    await asyncio.gather(watcher,return_exceptions=True)
    await engine.stop()
    await engine.client.aclose()

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)

@app.get('/health')
async def health():
    state = dict(engine.state)
    if engine.process and engine.process.returncode is not None and state['status']=='ready':
        state.update(status='error', error='Inference process stopped')
    try:
        process=engine.monitor_process if engine.process else None
        state['ram_usage_bytes'] = process.memory_info().rss if process else 0
        state['cpu_percent'] = process.cpu_percent(None) if process else 0
    except psutil.Error: state['ram_usage_bytes'] = 0
    state['vram_usage_bytes'] = None
    return state

@app.post('/configure')
async def configure(config: EngineConfig, persist: bool = True):
    async with engine.lock:
        if config != engine.config or (await health())['status']=='error':
            if persist:
                temp = CONFIG.with_suffix('.tmp')
                temp.write_text(config.model_dump_json())
                temp.replace(CONFIG)
            await engine.stop()
            engine.config = config
            engine.state['status'] = 'loading'
            engine.task = asyncio.create_task(engine.load())
    return await health()

@app.post('/v1/chat/completions')
async def completion(request: Request):
    if (await health())['status'] != 'ready': raise HTTPException(503,'Local model is not ready')
    body = await request.json()
    # Only the bot service can reach this endpoint. No executable tools are accepted.
    if body.get('tools') or body.get('functions'): raise HTTPException(422,'Tools are disabled')
    if body.get('stream'):
        async def stream():
            async with engine.client.stream('POST',INTERNAL+'/v1/chat/completions',json=body) as response:
                response.raise_for_status()
                async for chunk in response.aiter_bytes(): yield chunk
        return StreamingResponse(stream(),media_type='text/event-stream')
    response = await engine.client.post(INTERNAL+'/v1/chat/completions',json=body)
    if response.is_error: raise HTTPException(502,'Local inference failed')
    return response.json()

if __name__ == '__main__':
    uvicorn.run(app,host='0.0.0.0',port=8081,access_log=False)
