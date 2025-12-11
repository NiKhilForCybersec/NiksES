#!/bin/sh
set -e

# Default backend host if not set
export BACKEND_HOST=${BACKEND_HOST:-"localhost:8000"}

echo "Starting NiksES Frontend"
echo "Backend Host: $BACKEND_HOST"

# Substitute environment variables in nginx config
envsubst '${BACKEND_HOST}' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

# Start nginx
exec nginx -g 'daemon off;'
