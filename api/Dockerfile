FROM python:3.12-slim

WORKDIR /app

# Create a non-root user and group
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R appuser:appgroup /app

EXPOSE 8000

# Entrypoint runs as root to fix volume mount ownership, then drops to appuser
CMD ["sh", "-c", "chown -R appuser:appgroup /app/uploads && exec su -s /bin/sh appuser -c 'uvicorn api:app --host 0.0.0.0 --port 8000'"]
