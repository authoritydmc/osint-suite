FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Persisted runtime API keys (/api/settings -> keys.json) + optional key envs.
# All keys optional; every lookup degrades gracefully without them.
RUN mkdir -p /app/data
VOLUME ["/app/data"]
ENV DATA_DIR=/app/data
# ENV NUMVERIFY_KEY=
# ENV ABSTRACT_PHONE_KEY=
# ENV VERIPHONE_KEY=
# ENV IPQS_KEY=
# ENV ABUSEIPDB_KEY=
# ENV SHODAN_KEY=
# ENV HIBP_API_KEY=
# ENV GITHUB_TOKEN=
# ENV TELEGRAM_API_ID=
# ENV TELEGRAM_API_HASH=
# ENV TELEGRAM_SESSION=

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
