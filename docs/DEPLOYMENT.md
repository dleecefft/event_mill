# Event Mill Deployment Guide

## Overview
Deploy the Event Mill MCP server on a standalone Linux server (VM) or Google Cloud Run.

## Why Remote Server?
- **API Key Authentication**: Gemini API works properly without Cloud Shell's GCP credential conflicts
- **Clean Environment**: No automatic GCP authentication overriding API keys
- **Production Ready**: Suitable for actual SOC operations
- **Team Access**: Multiple analysts can connect to a shared server

## Prerequisites

### 1. Service Account Setup
```bash
# Create service account in GCP Console
gcloud iam service-accounts create soc-mcp-server \
    --description="SOC MCP Server Service Account" \
    --display-name="SOC MCP Server"

# Grant necessary permissions
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:soc-mcp-server@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/storage.objectViewer"  # Read access to logs

# If you need to write logs (not required for current use case)
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:soc-mcp-server@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/storage.objectViewer"

# Download service account key
gcloud iam service-accounts keys create ~/soc-mcp-key.json \
    --iam-account=soc-mcp-server@YOUR_PROJECT_ID.iam.gserviceaccount.com
```

### 2. Server Setup
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and dependencies
sudo apt install python3 python3-pip python3-venv -y

# Create application directory
sudo mkdir /opt/soc-mcp
sudo chown $USER:$USER /opt/soc-mcp
cd /opt/soc-mcp

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Environment Configuration
Create `.env` file:
```bash
# Gemini API Key (get from https://aistudio.google.com/app/apikey)
GEMINI_API_KEY=your_gemini_api_key_here

# GCS Service Account Key (absolute path)
GOOGLE_APPLICATION_CREDENTIALS=/opt/soc-mcp/soc-mcp-key.json

# Optional: Restrict to specific bucket for security
GCS_LOG_BUCKET=your-log-bucket-name

# Optional: Force stdio transport (default for remote server)
MCP_TRANSPORT=stdio
```

### 4. Deploy Files
```bash
# Copy service account key
cp ~/soc-mcp-key.json /opt/soc-mcp/
chmod 400 /opt/soc-mcp/soc-mcp-key.json

# Copy application files
cp server.py client.py requirements.txt README.md /opt/soc-mcp/
```

## Running the Server

### Method 1: Direct (for testing)
```bash
cd /opt/soc-mcp
source venv/bin/activate
python server.py
```

### Method 2: Systemd Service (production)
Create `/etc/systemd/system/soc-mcp.service`:
```ini
[Unit]
Description=SOC MCP Log Analysis Server
After=network.target

[Service]
Type=simple
User=soc-user
WorkingDirectory=/opt/soc-mcp
Environment=PATH=/opt/soc-mcp/venv/bin
ExecStart=/opt/soc-mcp/venv/bin/python server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Create dedicated user
sudo useradd -r -s /bin/false soc-user
sudo chown -R soc-user:soc-user /opt/soc-mcp

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable soc-mcp
sudo systemctl start soc-mcp

# Check status
sudo systemctl status soc-mcp
```

## Client Usage

### From Remote Server
```bash
cd /opt/soc-mcp
source venv/bin/activate
python client.py
```

### From Other Machines
Copy `client.py` and run it, pointing to your server:
```bash
python client.py --server your-server-ip --port 8080
```

## Security Considerations

### 1. Service Account Permissions
- Use **minimum required permissions** (`roles/storage.objectViewer`)
- **Never** grant `roles/storage.admin` unless absolutely necessary
- Consider **bucket-level permissions** instead of project-level

### 2. API Key Security
- Store API key in `.env` file with **restricted permissions** (600)
- Consider using **Gemini API quotas** to prevent abuse
- Monitor API usage in Google Cloud Console

### 3. Network Security
- Use **VPN** or **private network** for server access
- Consider **firewall rules** to restrict access to specific IPs
- Use **SSH key authentication** for server management

## Troubleshooting

### GCS Access Issues
```bash
# Test GCS access manually
gcloud auth activate-service-account --key-file=/opt/soc-mcp/soc-mcp-key.json
gsutil ls gs://your-bucket-name
```

### Gemini API Issues
```bash
# Test API key
curl -H "Content-Type: application/json" \
     -H "x-goog-api-key: YOUR_API_KEY" \
     -X POST \
     -d '{"contents":[{"parts":[{"text":"Hello"}]}]}' \
     "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
```

### Service Issues
```bash
# Check logs
sudo journalctl -u soc-mcp -f

# Test manually
cd /opt/soc-mcp
source venv/bin/activate
python server.py
```

## Performance Optimization

### 1. Large Log Files
- Consider **increasing memory** on the server for large log processing
- Use **GCS streaming** (already implemented) to avoid loading entire files

### 2. Concurrent Users
- For multiple analysts, consider **load balancing**
- Monitor **CPU and memory usage** during peak operations

### 3. API Rate Limits
- Monitor **Gemini API usage** in Google Cloud Console
- Consider **caching** frequent analyses
- Implement **rate limiting** if needed
