#!/bin/bash
# Event Mill - Cloud Run Deployment Script
# Deploys ttyd web terminal accessible via HTTPS on port 443

set -e

# Configuration - Update these values
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-your-project-id}"
REGION="${CLOUD_RUN_REGION:-us-central1}"
SERVICE_NAME="event-mill"
IMAGE_NAME="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"

# Optional: Basic auth credentials (stored in Secret Manager)
# TTYD_USERNAME and TTYD_PASSWORD should be created as secrets

echo "🏭 Event Mill - Cloud Run Deployment"
echo "====================================="
echo "Project:  ${PROJECT_ID}"
echo "Region:   ${REGION}"
echo "Service:  ${SERVICE_NAME}"
echo ""

# Step 1: Build the container image
echo "📦 Building container image..."
gcloud builds submit \
    --project="${PROJECT_ID}" \
    --tag="${IMAGE_NAME}" \
    --dockerfile=Dockerfile.cloudrun \
    .

# Step 2: Deploy to Cloud Run
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
    --set-env-vars="GEMINI_API_KEY=${GEMINI_API_KEY:-}" \
    --set-env-vars="GCS_LOG_BUCKET=${GCS_LOG_BUCKET:-}" \
    --allow-unauthenticated

# Note: For authenticated access, remove --allow-unauthenticated and use:
#   --no-allow-unauthenticated
# Then grant access via IAM:
#   gcloud run services add-iam-policy-binding event-mill \
#       --member="user:you@example.com" \
#       --role="roles/run.invoker"

# Step 3: Get the service URL
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
echo "   Cloud Run automatically provides HTTPS on port 443"
echo "   The ttyd terminal is accessible directly at the URL above"
echo ""

# Optional: Add basic auth using Secret Manager
# echo "To add basic auth:"
# echo "  1. Create secrets:"
# echo "     gcloud secrets create ttyd-username --data-file=- <<< 'admin'"
# echo "     gcloud secrets create ttyd-password --data-file=- <<< 'your-password'"
# echo "  2. Update the CMD in Dockerfile.cloudrun to use auth"
# echo "  3. Redeploy with --set-secrets"
