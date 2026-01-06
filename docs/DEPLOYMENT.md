# Event Mill Deployment Guide

## Overview
Deploy the Event Mill MCP server on a standalone Linux server (VM) or Google Cloud Run with ttyd web terminal.

## Deployment Options

| Method | Access | Best For |
|--------|--------|----------|
| Local Docker + ttyd | HTTP :7681 | Development, local testing |
| Cloud Run + ttyd | HTTPS :443 | Production, team access |
| VM + systemd | SSH | Traditional server deployment |

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

---

## Cloud Run Deployment (ttyd Web Terminal)

Deploy Event Mill as a web-accessible terminal via HTTPS on port 443.

### Quick Deploy

```bash
# Set environment variables
export GOOGLE_CLOUD_PROJECT=your-project-id
export GEMINI_API_KEY=your-gemini-api-key
export GCS_LOG_BUCKET=your-log-bucket  # Optional

# Deploy
./deploy-cloudrun.sh
```

### Manual Deployment

#### 1. Build and Push Image

```bash
# Build using Cloud Build
gcloud builds submit \
    --project="${GOOGLE_CLOUD_PROJECT}" \
    --tag="gcr.io/${GOOGLE_CLOUD_PROJECT}/event-mill" \
    --dockerfile=Dockerfile.cloudrun \
    .
```

#### 2. Deploy to Cloud Run

```bash
gcloud run deploy event-mill \
    --project="${GOOGLE_CLOUD_PROJECT}" \
    --region=us-central1 \
    --image="gcr.io/${GOOGLE_CLOUD_PROJECT}/event-mill" \
    --platform=managed \
    --port=8080 \
    --memory=512Mi \
    --cpu=1 \
    --timeout=3600 \
    --concurrency=10 \
    --min-instances=0 \
    --max-instances=3 \
    --set-env-vars="GEMINI_API_KEY=${GEMINI_API_KEY}" \
    --set-env-vars="GCS_LOG_BUCKET=${GCS_LOG_BUCKET}" \
    --allow-unauthenticated
```

#### 3. Access the Terminal

Cloud Run provides HTTPS automatically:
```
https://event-mill-XXXXXX-uc.a.run.app
```

The ttyd terminal is accessible directly at this URL via your browser.

### Cloud Run Configuration

| Setting | Value | Reason |
|---------|-------|--------|
| Port | 8080 | Cloud Run routes HTTPS:443 → container:8080 |
| Memory | 512Mi | Sufficient for log analysis |
| CPU | 1 | Single CPU for terminal session |
| Timeout | 3600s | 1 hour max session (Cloud Run limit) |
| Concurrency | 10 | Multiple analyst sessions |
| Min instances | 0 | Scale to zero when idle |
| Max instances | 3 | Limit concurrent sessions |

### Authentication Options

#### Option 1: Public Access (IAM-controlled)
```bash
--allow-unauthenticated
```
Anyone with the URL can access. Use for internal/VPN-protected networks.

#### Option 2: IAM Authentication
```bash
--no-allow-unauthenticated
```
Then grant access to specific users:
```bash
gcloud run services add-iam-policy-binding event-mill \
    --region=us-central1 \
    --member="user:analyst@example.com" \
    --role="roles/run.invoker"
```

#### Option 3: Basic Auth (ttyd built-in)
Update `Dockerfile.cloudrun` CMD to use auth:
```dockerfile
CMD ["sh", "-c", "ttyd -W -p ${PORT} -c ${TTYD_USERNAME}:${TTYD_PASSWORD} -t fontSize=16 python conversational_client.py"]
```

Then deploy with secrets:
```bash
# Create secrets
echo -n "admin" | gcloud secrets create ttyd-username --data-file=-
echo -n "your-secure-password" | gcloud secrets create ttyd-password --data-file=-

# Deploy with secrets
gcloud run deploy event-mill \
    ... \
    --set-secrets="TTYD_USERNAME=ttyd-username:latest,TTYD_PASSWORD=ttyd-password:latest"
```

### GCS Access from Cloud Run

Cloud Run uses the service's identity to access GCS. Grant permissions:

```bash
# Get the Cloud Run service account
SERVICE_ACCOUNT=$(gcloud run services describe event-mill \
    --region=us-central1 \
    --format="value(spec.template.spec.serviceAccountName)")

# Grant GCS read access
gcloud projects add-iam-policy-binding ${GOOGLE_CLOUD_PROJECT} \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="roles/storage.objectViewer"
```

### CI/CD with Cloud Build

Use `cloudbuild.yaml` for automated deployments:

```bash
# Trigger on git push
gcloud builds triggers create github \
    --repo-name=event-mill \
    --repo-owner=your-org \
    --branch-pattern="^main$" \
    --build-config=cloudbuild.yaml
```

### Limitations

- **Session timeout**: Cloud Run has a max timeout of 3600s (1 hour)
- **Cold starts**: First request may take 5-10s if scaled to zero
- **WebSocket**: ttyd uses WebSocket which Cloud Run supports
- **No persistent storage**: Each session starts fresh
