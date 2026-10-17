"""Read-only web search and source verification. Web results are untrusted evidence."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from collections import OrderedDict, defaultdict, deque
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import httpx
from bs4 import BeautifulSoup

from collectors.base import PinnedAsyncHTTPTransport, validate_public_url
from config.internet_search import get_search_options
from config.runtime_config import get_runtime_config
from services.time_utils import utc_now, iso_utc

log = logging.getLogger('hexalert.internet_search')

SECRET_KEYS = {
    'google': 'GOOGLE_SEARCH_API_KEY',
    'google_engine_id': 'GOOGLE_SEARCH_ENGINE_ID',
    'tavily': 'TAVILY_API_KEY',
    'serper': 'SERPER_API_KEY',
    'brave': 'BRAVE_SEARCH_API_KEY',
    'bing_compatible': 'BING_SEARCH_API_KEY',
    'custom': 'CUSTOM_SEARCH_API_KEY',
}

TRUSTED_DOMAINS = {
    'cisa.gov': 100, 'nvd.nist.gov': 100, 'nist.gov': 95, 'microsoft.com': 95,
    'msrc.microsoft.com': 100, 'google.com': 90, 'cloud.google.com': 95,
    'aws.amazon.com': 95, 'cisco.com': 90, 'talosintelligence.com': 95,
    'paloaltonetworks.com': 90, 'unit42.paloaltonetworks.com': 95,
    'mandiant.com': 90, 'cloudflare.com': 90, 'github.com': 85,
    'bleepingcomputer.com': 75, 'thehackernews.com': 70,
    'therecord.media': 75, 'darkreading.com': 75, 'securityweek.com': 75,
    'arstechnica.com': 65, 'reuters.com': 75, 'techcrunch.com': 60,
}
REFERENCE_ONLY_DOMAINS = {'linkedin.com', 'naukri.com', 'wellfound.com'}

class InternetSearchError(RuntimeError):
    pass

class SearchNotConfigured(InternetSearchError):
    pass

class SearchRateLimited(InternetSearchError):
    pass

class InternetSearchProvider:
    """Provider contract: return raw API payload plus normalized public results."""
    name=''
    async def search(self, service, query, count, options, credentials):
        raise NotImplementedError

class GoogleSearchProvider(InternetSearchProvider): name='google'
class TavilyProvider(InternetSearchProvider): name='tavily'
class SerperProvider(InternetSearchProvider): name='serper'
class BraveSearchProvider(InternetSearchProvider): name='brave'
class BingCompatibleProvider(InternetSearchProvider): name='bing_compatible'
class CustomSearchProvider(InternetSearchProvider): name='custom'

PROVIDER_ADAPTERS={adapter.name:adapter for adapter in
                    (GoogleSearchProvider,TavilyProvider,SerperProvider,BraveSearchProvider,BingCompatibleProvider,CustomSearchProvider)}

for _adapter in PROVIDER_ADAPTERS.values():
    async def _provider_search(self, service, query, count, options, credentials):
        return await service._fetch_provider_impl(self.name,query,count,options,credentials)
    _adapter.search=_provider_search

class InternetSearchService:
    def __init__(self):
        self.cache = OrderedDict()
        self.rate = defaultdict(deque)
        self.stats = {'queries': 0, 'success': 0, 'failure': 0, 'cache_hits': 0, 'last_status': 'not_configured', 'last_provider': ''}
        self._transport = None
        self._client = None
        self._page_client = None
        self._page_transport = None

    async def close(self):
        for client in (self._client, self._page_client):
            if client and not client.is_closed:
                await client.aclose()
        self._client = self._page_client = None
        self._transport = self._page_transport = None

    def _credentials(self):
        return get_runtime_config()

    def configured_providers(self):
        raw = self._credentials()
        opts = get_search_options()
        return {
            'google': bool(raw.get(SECRET_KEYS['google']) and raw.get(SECRET_KEYS['google_engine_id'])),
            'tavily': bool(raw.get(SECRET_KEYS['tavily'])),
            'serper': bool(raw.get(SECRET_KEYS['serper'])),
            'brave': bool(raw.get(SECRET_KEYS['brave'])),
            'bing_compatible': bool(raw.get(SECRET_KEYS['bing_compatible']) and opts.bing_compatible_endpoint),
            'custom': bool(opts.custom_endpoint),
        }

    def status(self):
        opts = get_search_options()
        configured = self.configured_providers()
        selected = opts.primary_provider
        ready = bool(opts.enabled and configured.get(selected))
        return {
            'enabled': opts.enabled,
            'provider': selected,
            'fallback_provider': opts.fallback_provider,
            'status': 'ready' if ready else ('not_configured' if not configured.get(selected) else 'disabled'),
            'providers': {name: {'configured': value, 'status': 'configured' if value else 'not_configured'} for name, value in configured.items()},
            'google_api_key_configured': configured['google'],
            'google_engine_id_configured': bool(self._credentials().get(SECRET_KEYS['google_engine_id'])),
            'stats': dict(self.stats),
        }

    @staticmethod
    def normalized_query(question: str, *, explicit_provider: str | None = None) -> str:
        text = re.sub(r'<@!?\d+>', ' ', str(question or ''))
        text = re.sub(r'^\s*(?:search\s+(?:google|the\s+web|the\s+internet|online)|google)\s+(?:for\s+)?', '', text, flags=re.I)
        text = re.sub(r'^\s*(?:please\s+)?(?:search\s+(?:the\s+)?(?:web|internet)\s+(?:for\s+)?)', '', text, flags=re.I)
        text = re.sub(r'\s+', ' ', text).strip()
        return text[:300]

    @staticmethod
    def _host(url: str) -> str:
        return (urlsplit(url).hostname or '').lower().rstrip('.')

    @staticmethod
    def _canonical(url: str) -> str:
        parts = urlsplit(url)
        query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
                 if not k.lower().startswith(('utm_', 'ref')) and k.lower() not in {'fbclid', 'gclid'}]
        return urlunsplit((parts.scheme.lower(), (parts.hostname or '').lower(), parts.path.rstrip('/') or '/', urlencode(query), ''))

    @staticmethod
    def _domain_trust(host: str) -> int:
        for domain, score in TRUSTED_DOMAINS.items():
            if host == domain or host.endswith('.' + domain):
                return score
        if host.endswith(('.gov', '.gov.uk', '.gov.in', '.edu')):
            return 70
        return 35

    @staticmethod
    def _query_tokens(query: str):
        return {word for word in re.findall(r'[a-z0-9][a-z0-9.+-]{2,}', query.casefold()) if word not in {'latest', 'current', 'today', 'search', 'google', 'news', 'cybersecurity'}}

    def _is_relevant(self, query: str, item: dict) -> bool:
        tokens = self._query_tokens(query)
        if not tokens:
            return True
        body = (item.get('title', '') + ' ' + item.get('snippet', '')).casefold()
        matched = sum(token in body for token in tokens)
        return matched >= 1 or len(tokens) <= 1

    async def _client_for(self, url: str):
        parts = urlsplit(url)
        if parts.scheme != 'https' or not parts.hostname:
            raise InternetSearchError('Search provider endpoint must use HTTPS.')
        if self._client is None or self._client.is_closed:
            self._transport = PinnedAsyncHTTPTransport(retries=0)
            self._client = httpx.AsyncClient(timeout=15, follow_redirects=False, trust_env=False,
                                             transport=self._transport, headers={'User-Agent': 'HEX-ALPHA/1.0'})
        await self._transport.pin(parts.hostname)
        return self._client

    async def _page_fetch(self, url: str, timeout_seconds: int):
        validate_public_url(url)
        parts = urlsplit(url)
        if parts.scheme != 'https' or not parts.hostname:
            raise ValueError('Only public HTTPS source pages are accepted')
        if self._page_client is None or self._page_client.is_closed:
            self._page_transport = PinnedAsyncHTTPTransport(retries=0)
            self._page_client = httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False, trust_env=False,
                                                  transport=self._page_transport,
                                                  headers={'User-Agent': 'HEX-ALPHA/1.0 (+cybersecurity source verification)',
                                                           'Accept': 'text/html,application/xhtml+xml'})
        await self._page_transport.pin(parts.hostname)
        async with self._page_client.stream('GET', url) as response:
            content_type = response.headers.get('content-type', '').lower()
            if response.status_code != 200 or ('html' not in content_type and 'xhtml' not in content_type):
                return None
            chunks = bytearray()
            async for chunk in response.aiter_bytes():
                chunks.extend(chunk)
                if len(chunks) >= 160_000:
                    break
            return bytes(chunks).decode(response.encoding or 'utf-8', errors='replace')

    @staticmethod
    def _extract_page(html: str):
        soup = BeautifulSoup(html, 'html.parser')
        published = ''
        for attr, value in [('property', 'article:published_time'), ('name', 'datePublished'), ('itemprop', 'datePublished'), ('name', 'pubdate')]:
            node = soup.find('meta', attrs={attr: value})
            if node and node.get('content'):
                published = str(node['content'])[:80]
                break
        for node in soup(['script', 'style', 'noscript', 'svg', 'nav', 'footer', 'header', 'form', 'iframe']):
            node.decompose()
        main = soup.find('article') or soup.find('main') or soup.body or soup
        text = re.sub(r'\s+', ' ', main.get_text(' ', strip=True))
        return text[:3500], published

    async def _fetch_provider_impl(self, provider: str, query: str, count: int, opts, raw):
        credential_key = SECRET_KEYS.get(provider)
        api_key = raw.get(credential_key, '') if credential_key else ''
        if provider == 'google':
            if not api_key or not raw.get(SECRET_KEYS['google_engine_id']):
                raise SearchNotConfigured('Google Search API key and Search Engine ID are not configured.')
            url = 'https://customsearch.googleapis.com/customsearch/v1'
            client = await self._client_for(url)
            response = await client.get(url, params={'key': api_key, 'cx': raw[SECRET_KEYS['google_engine_id']],
                                                      'q': query, 'num': count, 'safe': 'active' if opts.safe_search else 'off'},
                                        timeout=opts.timeout_seconds)
            response.raise_for_status()
            data = response.json()
            source = data.get('items', [])
        elif provider == 'tavily':
            if not api_key: raise SearchNotConfigured('Tavily API key is not configured.')
            url = 'https://api.tavily.com/search'; client = await self._client_for(url)
            response = await client.post(url, headers={'Authorization': f'Bearer {api_key}'},
                                         json={'query': query, 'max_results': count, 'search_depth': 'basic',
                                               'include_answer': False, 'include_raw_content': False}, timeout=opts.timeout_seconds)
            response.raise_for_status(); data = response.json(); source = data.get('results', [])
        elif provider == 'serper':
            if not api_key: raise SearchNotConfigured('Serper API key is not configured.')
            url = 'https://google.serper.dev/search'; client = await self._client_for(url)
            response = await client.post(url, headers={'X-API-KEY': api_key},
                                         json={'q': query, 'num': count, 'safe': 'active' if opts.safe_search else 'off'},
                                         timeout=opts.timeout_seconds)
            response.raise_for_status(); data = response.json(); source = data.get('organic', [])
        elif provider == 'brave':
            if not api_key: raise SearchNotConfigured('Brave Search API key is not configured.')
            url = 'https://api.search.brave.com/res/v1/web/search'; client = await self._client_for(url)
            response = await client.get(url, headers={'X-Subscription-Token': api_key, 'Accept': 'application/json'},
                                        params={'q': query, 'count': count, 'safesearch': 'moderate' if opts.safe_search else 'off'},
                                        timeout=opts.timeout_seconds)
            response.raise_for_status(); data = response.json(); source = data.get('web', {}).get('results', [])
        elif provider in {'bing_compatible', 'custom'}:
            endpoint = opts.bing_compatible_endpoint if provider == 'bing_compatible' else opts.custom_endpoint
            if not endpoint: raise SearchNotConfigured(f'{provider} HTTPS endpoint is not configured.')
            if provider == 'bing_compatible' and not api_key: raise SearchNotConfigured('Bing-compatible API key is not configured.')
            client = await self._client_for(endpoint)
            headers = {'Ocp-Apim-Subscription-Key': api_key} if provider == 'bing_compatible' and api_key else {}
            if provider == 'custom' and api_key: headers['Authorization'] = f'Bearer {api_key}'
            payload = {'q': query, 'query': query, 'count': count, 'max_results': count,
                       'safeSearch': 'Moderate' if opts.safe_search else 'Off', 'safe_search': opts.safe_search}
            response = await client.get(endpoint, params=payload, headers=headers, timeout=opts.timeout_seconds)
            response.raise_for_status(); data = response.json()
            source = data.get('webPages', {}).get('value') or data.get('results') or data.get('items') or []
        else:
            raise SearchNotConfigured('Select a supported internet search provider.')

        normalized=[]; seen=set(); now=iso_utc(utc_now())
        for row in source or []:
            if not isinstance(row, dict): continue
            url=str(row.get('link') or row.get('url') or row.get('href') or '').strip()
            try:
                validate_public_url(url)
                if urlsplit(url).scheme != 'https': continue
            except (ValueError, TypeError): continue
            host=self._host(url)
            if host in {'google.com', 'www.google.com', 'search.yahoo.com'}: continue
            canonical=self._canonical(url)
            if canonical in seen: continue
            seen.add(canonical)
            title=re.sub(r'\s+', ' ', str(row.get('title') or row.get('name') or ''))[:240]
            snippet=re.sub(r'\s+', ' ', str(row.get('snippet') or row.get('description') or row.get('content') or ''))[:700]
            if not title or not snippet: continue
            normalized.append({'title': title, 'url': url, 'domain': host, 'snippet': snippet,
                               'published_date': str(row.get('published_date') or row.get('published') or row.get('date') or row.get('datePublished') or '')[:80],
                               'provider': provider, 'retrieved_at': now, 'trust_score': self._domain_trust(host),
                               'verified_page': False, 'page_text': '', 'reference_only': any(host == d or host.endswith('.' + d) for d in REFERENCE_ONLY_DOMAINS)})
        normalized=[row for row in normalized if self._is_relevant(query,row)]
        if opts.trust_domain_filtering:
            normalized.sort(key=lambda r: (r['trust_score'], bool(r['published_date'])), reverse=True)
        return data, normalized[:count]

    async def _fetch_provider(self, provider: str, query: str, count: int, opts, raw):
        adapter=PROVIDER_ADAPTERS.get(provider)
        if adapter is None: raise SearchNotConfigured('Select a supported internet search provider.')
        return await adapter().search(self,query,count,opts,raw)

    def _rate_check(self, requester_id: str, opts):
        now=time.monotonic(); bucket=self.rate[str(requester_id or 'anonymous')]
        while bucket and now-bucket[0]>=60: bucket.popleft()
        if len(bucket)>=opts.requests_per_minute:
            raise SearchRateLimited(f'Live search is limited to {opts.requests_per_minute} requests per minute. Please try again shortly.')
        bucket.append(now)
        if len(self.rate)>5000:
            for key in list(self.rate)[:1000]: self.rate.pop(key,None)

    async def _audit(self, payload):
        try:
            from database.db import SessionLocal
            from database.models import SystemLog
            async with SessionLocal() as session:
                session.add(SystemLog(level='INFO' if payload.get('status')=='success' else 'WARNING',
                                      component='INTERNET_SEARCH', message=json.dumps(payload,separators=(',',':'))))
                await session.commit()
        except Exception:
            log.warning('Internet search metrics could not be persisted')

    async def search(self, query: str, *, requester_id: str, provider_override: str | None = None,
                     allow_fallback: bool = True, bypass_rate_limit: bool = False,
                     exclude_urls=(), exclude_titles=()):
        opts=get_search_options(); raw=self._credentials()
        if not opts.enabled and not bypass_rate_limit:
            raise SearchNotConfigured('Live internet search is disabled in AI Settings.')
        query=self.normalized_query(query)
        if not query: raise InternetSearchError('Enter a search query.')
        provider=provider_override or opts.primary_provider
        if provider not in SECRET_KEYS and provider not in {'custom'}:
            raise SearchNotConfigured('Unsupported search provider.')
        configured=self.configured_providers()
        if not configured.get(provider) and not (allow_fallback and opts.fallback_provider!='disabled' and configured.get(opts.fallback_provider)):
            raise SearchNotConfigured(f'{provider.replace("_", " ").title()} search is not configured.')
        query_hash=hashlib.sha256(query.casefold().encode()).hexdigest()[:16]
        cache_key=(provider,query.casefold(),opts.max_results,opts.safe_search,opts.trust_domain_filtering)
        cached=self.cache.get(cache_key)
        if cached and time.monotonic()-cached[0] < opts.cache_ttl_seconds:
            self.cache.move_to_end(cache_key); self.stats['cache_hits']+=1
            results=[dict(item) for item in cached[1]]
            status='success'; latency=0.0
            self.stats['queries']+=1; self.stats['success']+=1; self.stats['last_status']='ready'; self.stats['last_provider']=provider
            results=self._exclude_duplicates(results,exclude_urls,exclude_titles)
            await self._audit({'status':status,'provider':provider,'latency_ms':0,'result_count':len(results),
                               'domains':sorted({x['domain'] for x in results})[:5],'cache_hit':True,
                               'query_length':len(query),'query_hash':query_hash})
            return {'provider':provider,'query':query,'results':results,'latency_ms':0,'cache_hit':True}
        if not bypass_rate_limit: self._rate_check(requester_id,opts)
        started=time.monotonic(); providers=[provider]
        if allow_fallback and opts.fallback_provider!='disabled' and opts.fallback_provider!=provider:
            providers.append(opts.fallback_provider)
        error=None; selected=provider; results=[]
        for name in providers:
            try:
                if not configured.get(name):
                    if name==provider: raise SearchNotConfigured(f'{name.replace("_", " ").title()} search is not configured.')
                    continue
                selected=name
                _,results=await self._fetch_provider(name,query,opts.max_results,opts,raw)
                if results: break
                error='No relevant search results were returned.'
            except Exception as exc:
                error=type(exc).__name__
                if name==provider and isinstance(exc,SearchNotConfigured) and len(providers)==1: break
        latency=round((time.monotonic()-started)*1000,1)
        if not results:
            self.stats['queries']+=1; self.stats['failure']+=1; self.stats['last_status']='error'; self.stats['last_provider']=selected
            await self._audit({'status':'failure','provider':selected,'latency_ms':latency,'result_count':0,
                               'domains':[],'cache_hit':False,'query_length':len(query),'query_hash':query_hash,
                               'reason':error or 'no_results'})
            if error and error not in {'No relevant search results were returned.', 'SearchNotConfigured'}:
                raise InternetSearchError('Internet search could not complete. Check the provider configuration and try again.')
            raise InternetSearchError('No relevant public web results were found.')

        # Fetch only the top three useful result pages. Search listing text is untrusted evidence too.
        pages=0
        for item in results:
            if pages>=3: break
            if item['reference_only']: continue
            try:
                html=await self._page_fetch(item['url'],opts.timeout_seconds)
                if html:
                    item['page_text'],page_date=self._extract_page(html)
                    item['verified_page']=bool(item['page_text'])
                    if page_date and not item['published_date']: item['published_date']=page_date
                    pages+=1
            except Exception as exc:
                item['page_fetch_error']=type(exc).__name__
        # Keep accessible pages first, but retain result snippets when a publisher blocks fetches.
        results.sort(key=lambda x:(x['verified_page'],x['trust_score']),reverse=True)
        results=results[:3]
        self.cache[cache_key]=(time.monotonic(),[dict(item) for item in results]); self.cache.move_to_end(cache_key)
        while len(self.cache)>1000: self.cache.popitem(last=False)
        self.stats['queries']+=1; self.stats['success']+=1; self.stats['last_status']='ready'; self.stats['last_provider']=selected
        results=self._exclude_duplicates(results,exclude_urls,exclude_titles)
        await self._audit({'status':'success','provider':selected,'latency_ms':latency,'result_count':len(results),
                           'domains':sorted({x['domain'] for x in results})[:5],'verified_pages':sum(x['verified_page'] for x in results),
                           'cache_hit':False,'query_length':len(query),'query_hash':query_hash})
        return {'provider':selected,'query':query,'results':results,'latency_ms':latency,'cache_hit':False}

    @staticmethod
    def _exclude_duplicates(results, urls, titles):
        known_urls={InternetSearchService._canonical(str(x)) for x in urls if x}
        known_titles={re.sub(r'[^a-z0-9]+',' ',str(x).casefold()).strip() for x in titles if x}
        kept=[]; seen=set()
        for item in results:
            canonical=InternetSearchService._canonical(item['url'])
            title=re.sub(r'[^a-z0-9]+',' ',item['title'].casefold()).strip()
            if canonical in known_urls or title in known_titles or canonical in seen: continue
            seen.add(canonical);kept.append(item)
        return kept

    def format_context(self, results):
        rows=[]
        for item in results[:3]:
            rows.append({'title':item['title'],'published':item.get('published_date') or 'Not publicly available',
                         'url':item['url'],'details':(item.get('page_text') or item['snippet'])[:1200],
                         'domain':item['domain'],'provider':item['provider'],'retrieved_at':item['retrieved_at'],
                         'snippet':item['snippet'],'verified_page':item['verified_page'],
                         'reference_only':item['reference_only']})
        return 'HEX ALERT current data facts only:\n'+json.dumps(rows,ensure_ascii=False,separators=(',',':')) if rows else ''

    @staticmethod
    def preview(results):
        if not results: return ''
        blocks=[]
        for item in results[:3]:
            note='Reference only' if item['reference_only'] else ('Page checked' if item['verified_page'] else 'Search result only')
            blocks.append(f"- **{item['title'][:120]}** ({item['domain']}; {note})\n  {item['snippet'][:200]}\n  Source: <{item['url']}>")
        return 'Search results (current; not independently certified):\n'+'\n'.join(blocks)

internet_search = InternetSearchService()
