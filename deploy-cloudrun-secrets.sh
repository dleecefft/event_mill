#!/bin/bash
# Event Mill - Cloud Run Deployment with Secret Manager
# Uses pre-created secrets: aisbx-gemini-api and aisbx-mcp-sa

set -e

# Configuration
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-your-project-id}"
REGION="northamerica-northeast2"
SERVICE_NAME="event-mill"
IMAGE_NAME="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"

# GCS bucket for log analysis
GCS_LOG_BUCKET="digevtrecintake"

# Secret names (pre-created in GCP Console)
SECRET_GEMINI_API="aisbx-gemini-api"
SECRET_GCS_SA="aisbx-mcp-sa"
SECRET_TTYD_USER="aisbx-ttyd-user"
SECRET_TTYD_CRED="aisbx-ttyd-cred"

echo "🏭 Event Mill - Cloud Run Deployment (with Secret Manager)"
echo "==========================================================="
echo "Project:  ${PROJECT_ID}"
echo "Region:   ${REGION}"
echo "Service:  ${SERVICE_NAME}"
echo ""
echo "🔐 Using secrets:"
echo "   - ${SECRET_GEMINI_API} (Gemini API Key)"
echo "   - ${SECRET_GCS_SA} (GCS Service Account)"
echo "   - ${SECRET_TTYD_USER} (ttyd username)"
echo "   - ${SECRET_TTYD_CRED} (ttyd password)"
echo ""
echo "📦 GCS Bucket: ${GCS_LOG_BUCKET}"
echo ""

# =============================================================================
# Step 1: Enable APIs
# =============================================================================
echo "📡 Enabling required APIs..."
gcloud services enable secretmanager.googleapis.com --project="${PROJECT_ID}"
gcloud services enable run.googleapis.com --project="${PROJECT_ID}"
gcloud services enable cloudbuild.googleapis.com --project="${PROJECT_ID}"

# =============================================================================
# Step 2: Grant Cloud Run access to secrets
# =============================================================================
echo ""
echo "🔑 Granting Cloud Run access to secrets..."

PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)")
SERVICE_ACCOUNT="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

grant_secret_access() {
    local secret_name=$1
    gcloud secrets add-iam-policy-binding "${secret_name}" \
        --project="${PROJECT_ID}" \
        --member="serviceAccount:${SERVICE_ACCOUNT}" \
        --role="roles/secretmanager.secretAccessor" \
        --quiet 2>/dev/null || true
    echo "   ✓ Granted access to '${secret_name}'"
}

grant_secret_access "${SECRET_GEMINI_API}"
grant_secret_access "${SECRET_GCS_SA}"
grant_secret_access "${SECRET_TTYD_USER}"
grant_secret_access "${SECRET_TTYD_CRED}"

# =============================================================================
# Step 3: Build the container image
# =============================================================================
echo ""
echo "📦 Building container image..."
gcloud builds submit \
    --project="${PROJECT_ID}" \
    --tag="${IMAGE_NAME}" \
    --dockerfile=Dockerfile.cloudrun \
    .

# =============================================================================
# Step 4: Deploy to Cloud Run with secrets
# =============================================================================
echo ""
echo "🚀 Deploying to Cloud Run..."

gcloud run deploy "${SERVICE_NAME}" \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --image="${IMAGE_NAME}" \
    --platform=managed \
    --port=8080 \
    --memory=512Mi \
    --cpu=1 \
    --min-instances=0 \
    --max-instances=3 \
    --timeout=3600 \
    --concurrency=10 \
    --set-secrets="GEMINI_API_KEY=${SECRET_GEMINI_API}:latest,/app/credentials/sa-key.json=${SECRET_GCS_SA}:latest,TTYD_USERNAME=${SECRET_TTYD_USER}:latest,TTYD_PASSWORD=${SECRET_TTYD_CRED}:latest" \
    --set-env-vars="GOOGLE_APPLICATION_CREDENTIALS=/app/credentials/sa-key.json,GCS_LOG_BUCKET=${GCS_LOG_BUCKET}" \
    --allow-unauthenticated

# =============================================================================
# Step 5: Display results
# =============================================================================
echo ""
echo "✅ Deployment complete!"
echo ""

SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --format="value(status.url)")

echo "🌐 Event Mill is available at:"
echo "   ${SERVICE_URL}"
echo ""
echo "🔐 Secrets configured:"
echo "   - GEMINI_API_KEY ← ${SECRET_GEMINI_API}"
echo "   - /app/credentials/sa-key.json ← ${SECRET_GCS_SA}"
echo "   - TTYD_USERNAME ← ${SECRET_TTYD_USER}"
echo "   - TTYD_PASSWORD ← ${SECRET_TTYD_CRED}"
echo ""
echo "🔒 Basic auth enabled (ttyd -c user:pass)"
echo ""
echo "📦 Environment:"
echo "   - GCS_LOG_BUCKET = ${GCS_LOG_BUCKET}"
echo "   - Region = ${REGION}"
echo ""
echo "📋 To update a secret:"
echo "   gcloud secrets versions add ${SECRET_GEMINI_API} --data-file=- <<< 'new-key'"
echo "   gcloud secrets versions add ${SECRET_GCS_SA} --data-file=/path/to/new-sa.json"
