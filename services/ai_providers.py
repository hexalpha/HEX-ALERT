"""Shared streaming interface; no provider is selected implicitly on failure."""
import json
from config.ai import KEYS, inference_url
from config.runtime_config import get_runtime_config
from config.settings import get_settings

class AIUnavailable(RuntimeError): pass

class AIProvider:
    def __init__(self, name, config, client):
        self.name, self.config, self.client = name, config, client
        self.usage = {}
        self.performance = {}

    def model_info(self):
        return {'provider':self.name, 'model':self.config.model, 'backend':'llama.cpp' if self.name=='local_gguf' else 'OpenAI-compatible API'}

    def connection(self):
        endpoints = {'local_gguf':inference_url()+'/v1', 'openai':'https://api.openai.com/v1',
                     'groq':'https://api.groq.com/openai/v1',
                     'gemini':'https://generativelanguage.googleapis.com/v1beta/openai'}
        url = endpoints.get(self.name) or self.config.base_url
        if self.name == 'ollama': url = url.rstrip('/') + '/v1'
        key_name = KEYS.get(self.name)
        try:
            stored = get_runtime_config()
            bootstrap = get_settings()
        except Exception:
            stored, bootstrap = {}, None
        key = stored.get(key_name, getattr(bootstrap,key_name.lower(),'') if bootstrap else '') if key_name else ''
        if not self.config.enabled: raise AIUnavailable('This AI provider is disabled.')
        if self.name in ('openai','groq','gemini') and not key: raise AIUnavailable('This AI provider has no configured API key.')
        if not url: raise AIUnavailable('Configure the provider base URL first.')
        return url, {'Authorization':f'Bearer {key}'} if key else {}

    async def health(self):
        try:
            url, headers = self.connection()
            response = await self.client.get(inference_url()+'/health' if self.name=='local_gguf' else url+'/models',headers=headers,timeout=3)
            response.raise_for_status()
            return {**self.model_info(), **(response.json() if self.name=='local_gguf' else {'status':'ready'})}
        except Exception:
            return {**self.model_info(), 'status':'offline'}

    async def stream_chat(self, messages, settings):
        url, headers = self.connection()
        self.usage = {}
        self.performance = {}
        body = {'model':self.config.model,'messages':messages,'max_tokens':settings.max_tokens,
                'temperature':settings.temperature,'top_p':settings.top_p,'stream':settings.streaming}
        if settings.streaming: body['stream_options']={'include_usage':True}
        if self.name in ('local_gguf','ollama'):
            body.update(top_k=settings.top_k,repeat_penalty=settings.repeat_penalty)
        try:
            if not settings.streaming:
                response=await self.client.post(url+'/chat/completions',headers=headers,json=body,timeout=settings.timeout_seconds)
                response.raise_for_status()
                data=response.json(); self.usage=data.get('usage',{})
                yield data['choices'][0]['message']['content']
                return
            async with self.client.stream('POST',url+'/chat/completions',headers=headers,json=body,timeout=settings.timeout_seconds) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if not line.startswith('data:'): continue
                    raw = line[5:].strip()
                    if raw == '[DONE]': break
                    chunk = json.loads(raw)
                    if chunk.get('usage'): self.usage = chunk['usage']
                    if isinstance(chunk.get('timings'),dict): self.performance=chunk['timings']
                    if chunk.get('error'): raise AIUnavailable('The provider could not generate a response.')
                    for choice in chunk.get('choices',[]):
                        content = choice.get('delta',{}).get('content')
                        if content: yield content
        except AIUnavailable: raise
        except Exception: raise AIUnavailable('AI generation failed. Check AI Settings and retry.') from None

    async def chat(self, messages, settings):
        return ''.join([part async for part in self.stream_chat(messages,settings)])

class LocalGGUFProvider(AIProvider): pass
class OpenAIProvider(AIProvider): pass
class GeminiProvider(AIProvider): pass
class GroqProvider(AIProvider): pass
class OllamaProvider(AIProvider): pass
class CustomOpenAIProvider(AIProvider): pass

def make_provider(name, settings, client):
    classes = dict(zip(('local_gguf','openai','gemini','groq','ollama','custom'),
                       (LocalGGUFProvider,OpenAIProvider,GeminiProvider,GroqProvider,OllamaProvider,CustomOpenAIProvider)))
    if name not in classes: raise AIUnavailable('AI chat is disabled.')
    return classes[name](name,settings.providers[name],client)
