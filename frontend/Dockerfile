FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

FROM python:3.12-slim AS runtime
WORKDIR /app
RUN addgroup --gid 1000 appgroup && \
    adduser  --uid 1000 --gid 1000 --disabled-password --no-create-home appuser
COPY --from=builder /root/.local /home/appuser/.local
COPY --chown=appuser:appgroup . .
ENV PATH=/home/appuser/.local/bin:$PATH PYTHONUNBUFFERED=1
USER 1000
EXPOSE 8080
CMD ["python", "app.py"]
