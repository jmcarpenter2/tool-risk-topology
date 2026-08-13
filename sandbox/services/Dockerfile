# Shared image for the two FastAPI services (internal-api and canary-sink).
# The concrete app is chosen by the compose `command:` (uvicorn <module>:app ...).
FROM python:3.11-slim

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY internal_api.py canary_sink.py ./

# Default; overridden per-service in docker-compose.yml.
CMD ["uvicorn", "internal_api:app", "--host", "0.0.0.0", "--port", "8000"]
