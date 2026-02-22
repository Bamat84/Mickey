#!/bin/bash
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://askmickey.io/health" 2>/dev/null)
echo "[$(date)] Health check: $HTTP_CODE"
