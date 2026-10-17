FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN addgroup --system app && adduser --system --ingroup app app
RUN mkdir -p /app/backups /app/runtime-config && chown -R app:app /app/backups /app/runtime-config && chmod 700 /app/runtime-config
COPY requirements.lock.txt .
RUN pip install --no-cache-dir --timeout 120 --retries 5 -r requirements.lock.txt
COPY . .
USER app
EXPOSE 8080
CMD ["sh", "-c", "alembic upgrade head && python main.py"]
