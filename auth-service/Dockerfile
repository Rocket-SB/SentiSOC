# Stage 1: Build dependencies
FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Stage 2: Runtime - non-root user, minimal surface
FROM python:3.12-slim AS runtime
WORKDIR /app

RUN addgroup --gid 1000 appgroup && \
    adduser  --uid 1000 --gid 1000 --disabled-password --no-create-home appuser

COPY --from=builder /root/.local /home/appuser/.local
COPY --chown=appuser:appgroup . .

RUN mkdir -p /app/data && chown appuser:appgroup /app/data

ENV PATH=/home/appuser/.local/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 1000
EXPOSE 5001
HEALTHCHECK --interval=30s --timeout=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/health')"

CMD ["python", "app.py"]
