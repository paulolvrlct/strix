FROM python:3.12-slim

# System deps for maigret/holehe/whois and exiftool (image metadata)
RUN apt-get update && apt-get install -y --no-install-recommends \
        whois git build-essential libimage-exiftool-perl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user (ANSSI/CIS hardening)
RUN useradd --create-home --shell /usr/sbin/nologin strix
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

# Output is a mounted volume; ensure it's writable by the non-root user
RUN mkdir -p /app/output && chown -R strix:strix /app
USER strix

ENTRYPOINT ["python", "-m", "strix"]
# Default to the interactive menu (run with a TTY, e.g. `docker compose run --rm strix`).
CMD ["menu"]
