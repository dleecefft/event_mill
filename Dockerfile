# Event Mill - Docker Image with ttyd web terminal
# Runs as non-privileged user for security

FROM python:3.11-slim

# Install ttyd from official release
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    ca-certificates \
    && wget -qO /usr/local/bin/ttyd \
       https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.x86_64 \
    && chmod +x /usr/local/bin/ttyd \
    && apt-get purge -y wget \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Create non-privileged user
RUN groupadd --gid 1000 eventmill \
    && useradd --uid 1000 --gid eventmill --shell /bin/bash --create-home eventmill

WORKDIR /app

# Install Python dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=eventmill:eventmill . .

# Create directory for credentials with correct ownership
RUN mkdir -p /app/credentials && chown eventmill:eventmill /app/credentials

# Switch to non-privileged user
USER eventmill

# ttyd options:
#   -W         = writable (allow input)
#   -p 7681    = port
#   -t fontSize=16 = larger font for readability
EXPOSE 7681

#CMD ["ttyd", "-W", "-p", "7681", "-t", "fontSize=16", "python", "conversational_client.py"]
#CMD ["ttyd", "-W", "-p", "7681", "-c", "someuser:somecred", "-t", "fontSize=16", "python", "conversational_client.py"]
CMD ["sh", "-c", "ttyd -W -p 7681 -c ${TTYD_USERNAME}:${TTYD_PASSWORD} -t fontSize=16 python conversational_client.py"]