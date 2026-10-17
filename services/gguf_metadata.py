"""Read bounded GGUF metadata without reading tensor weights or token arrays."""
import struct
from pathlib import Path


def inspect_gguf(path: str) -> dict:
    file = Path(path)
    sizes = {0: ('B', 1), 1: ('b', 1), 2: ('H', 2), 3: ('h', 2),
             4: ('I', 4), 5: ('i', 4), 6: ('f', 4), 7: ('?', 1),
             10: ('Q', 8), 11: ('q', 8), 12: ('d', 8)}
    with file.open('rb') as stream:
        def number(fmt):
            return struct.unpack('<' + fmt, stream.read(struct.calcsize(fmt)))[0]
        def string(keep=True):
            length = number('Q')
            if length > file.stat().st_size - stream.tell():
                raise ValueError('Invalid GGUF string length')
            if not keep:
                stream.seek(length, 1)
                return None
            if length > 1_000_000:
                raise ValueError('GGUF metadata string too large')
            return stream.read(length).decode('utf-8')
        def value(kind, keep=True, depth=0):
            if depth > 4: raise ValueError('Invalid GGUF array nesting')
            if kind == 8: return string(keep)
            if kind == 9:
                subtype, length = number('I'), number('Q')
                if length > 10_000_000: raise ValueError('GGUF array too large')
                if subtype in sizes:
                    stream.seek(sizes[subtype][1] * length, 1)
                else:
                    for _ in range(length): value(subtype, False, depth + 1)
                return None
            if kind not in sizes: raise ValueError('Unknown GGUF metadata type')
            return number(sizes[kind][0])
        if stream.read(4) != b'GGUF': raise ValueError('File is not GGUF')
        version = number('I')
        if version not in (2, 3): raise ValueError('Unsupported GGUF version')
        tensors, count = number('Q'), number('Q')
        if count > 100_000: raise ValueError('Too many GGUF metadata fields')
        metadata = {}
        for _ in range(count):
            key, kind = string(), number('I')
            val = value(kind)
            if val is not None: metadata[key] = val
        arch = metadata.get('general.architecture', 'unknown')
        return {'version': version, 'size_bytes': file.stat().st_size, 'tensors': tensors,
                'architecture': arch, 'context_length': metadata.get(f'{arch}.context_length'),
                'quantization_type': metadata.get('general.file_type'),
                'chat_template': metadata.get('tokenizer.chat_template'),
                'bos_token_id': metadata.get('tokenizer.ggml.bos_token_id'),
                'eos_token_id': metadata.get('tokenizer.ggml.eos_token_id')}
