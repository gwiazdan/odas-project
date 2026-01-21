#!/bin/bash
set -e

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/nginx-selfsigned.key \
  -out /etc/nginx/ssl/nginx-selfsigned.crt \
  -subj "/C=PL/ST=State/L=City/O=Organization/OU=IT/CN=localhost"

echo "Self-signed certificate generated at:"
echo "  /etc/nginx/ssl/nginx-selfsigned.crt"
echo "  /etc/nginx/ssl/nginx-selfsigned.key"
