FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    POLICY_DB=/data/policies.db

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Persistent policy library lives on the mounted Docker volume. Create the
# mount point in the image and hand it to the unprivileged runtime user so
# SQLite (plus its WAL/SHM sidecars) is writable there.
RUN mkdir -p /data && chown nobody:nogroup /data
VOLUME ["/data"]

EXPOSE 8080

USER nobody

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
