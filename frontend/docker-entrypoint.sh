#!/bin/sh
set -e

# Default backend host if not set
export BACKEND_HOST=${BACKEND_HOST:-"localhost:8000"}
# Default to HTTPS for external URLs (*.railway.app), HTTP for internal
export BACKEND_PROTOCOL=${BACKEND_PROTOCOL:-"https"}

echo "Starting NiksES Frontend"
echo "Backend Host: $BACKEND_HOST"
echo "Backend Protocol: $BACKEND_PROTOCOL"

# Substitute environment variables in nginx config
envsubst '${BACKEND_HOST} ${BACKEND_PROTOCOL}' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

# Start nginx
exec nginx -g 'daemon off;'
