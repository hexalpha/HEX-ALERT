"""Summary compatibility adapter using the same selected provider as Discord chat."""
import asyncio
from services.ai_chat import chat_service

class AIService:
    async def summarize(self,text:str,max_chars:int=700)->str:
        from config.ai import options
        if not options().summaries_enabled or chat_service.active or chat_service.waiting:
            return self._extractive(text,max_chars)
        if not text.strip(): return self._extractive(text,max_chars)
        try:
            async with asyncio.timeout(20):
                result=await chat_service.ask(('summary',id(asyncio.current_task())),
                    'Summarize only supplied facts in under 90 words. Missing details are Not publicly available.\n'+text[:1800],remember=False,priority=3)
            return result['answer'][:max_chars]
        except Exception: return self._extractive(text,max_chars)

    @staticmethod
    def _extractive(text,max_chars):
        clean=' '.join(text.split())
        return (clean[:max_chars-1].rsplit(' ',1)[0]+'…') if len(clean)>max_chars else clean or 'Not publicly available'
