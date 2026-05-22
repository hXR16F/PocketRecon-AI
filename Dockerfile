FROM python:3.14-slim

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /mcp-server

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    nmap \
    iputils-ping \
    traceroute \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pocket_recon_server.py ./
COPY pocket_recon_mcp.py ./
COPY tools/ ./tools/

EXPOSE 5005
CMD ["python", "pocket_recon_server.py"]
