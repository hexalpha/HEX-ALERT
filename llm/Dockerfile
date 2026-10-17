ARG LLAMA_IMAGE=ghcr.io/ggml-org/llama.cpp@sha256:23fd59bc5e5b06ca68003a5772d441f0411fb723eeaff850b9111bcd2ac4fd33
FROM ${LLAMA_IMAGE}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends python3-venv && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/hex-llm \
    && /opt/hex-llm/bin/pip install --no-cache-dir fastapi==0.142.2 uvicorn==0.54.0 httpx==0.28.1 psutil==7.2.2 \
    && useradd --uid 10001 --create-home inference && mkdir /state && chown inference:inference /state
COPY llm/server.py /opt/hex/server.py
COPY services/gguf_metadata.py /opt/hex/gguf_metadata.py
USER inference
ENV LD_LIBRARY_PATH=/app
WORKDIR /opt/hex
ENTRYPOINT ["/opt/hex-llm/bin/python", "server.py"]
